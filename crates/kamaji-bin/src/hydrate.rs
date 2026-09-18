//! R850-F1 — hydrate-on-place: fill a stateful workload's named volume from its
//! declared object store *before* the container starts.
//!
//! # The whole restore lives in another process
//!
//! Everything here is spec-reading and process-spawning. The restore itself —
//! object listing, page reassembly, WAL-frame replay, and the ownership fence
//! that makes any of it safe — is `turso-backup`, invoked as
//! `turso-backup-hydrate` (see that binary's module doc for why it is a
//! process).
//!
//! The short version: kamaji is the node's control plane, and linking a
//! database engine into the supervisor that runs every workload on every box
//! couples their failure domains and their build times for no gain. yubaba
//! already ships WAL sidecars rather than shipping WAL in-process
//! (`litestream.rs`, `tenant-streamer`); this is that shape for the restore
//! side.
//!
//! # An undeclared workload is untouched; a declared one is not started blind
//!
//! [`plan`] returns [`HydratePlan::NotDeclared`] for every spec without a
//! bytes-shipping `yah.durability.tier`, which is every spec in the tree today,
//! and [`run`] then does nothing at all.
//!
//! When a tier *is* declared and no helper is configured, the deploy is
//! **refused** rather than started. That is the same discipline
//! `--tenant-passway-dir` holds, and here it matters more: starting an
//! appliance whose declared restore never ran gives you a running workload with
//! an empty database and no error — which is indistinguishable from a healthy
//! first boot until somebody logs in and finds their account gone.
//!
//! @yah:ticket(R858-B26, "A workload with any file secret can never declare yah.durability.*: yubaba appends secret binds to spec.volumes before kamaji counts them")
//! @yah:status(review)
//! @yah:at(2026-09-13T07:29:50Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R858)
//! @yah:severity(high)
//! @yah:gotcha("THE TWO CHECKS THAT ARE MEANT TO BE THE SAME CHECK DISAGREE BY CONSTRUCTION, which is why this is invisible until a deploy. `validate::shape` (oss/yah-base/crates/workload-spec/src/validate.rs, the `roots.len() != 1` arm) applies the rule to the OPERATOR's spec, BEFORE materialization. `kamaji::hydrate::plan` (oss/kamaji/crates/kamaji-bin/src/hydrate.rs, the `(Some(volume_root), None)` let-else) applies the identical rule AFTER yubaba has rewritten the spec. Between them, oss/yubaba/crates/yubaba/src/deploy/secret_mount.rs turns every `SecretTarget::File` into a `VolumeMount { source: VolumeSource::Bind { host_path }, read_only: true }` and runs `spec.volumes.extend(binds)`. So `yah cloud validate` is green, the CLI's own shape validation passes, and the node refuses — with a message that is TRUE of the spec kamaji received and FALSE of the spec the operator wrote. kamaji's comment at that site says 'validate::shape already enforces exactly one named-or-bind volume ... it is re-derived rather than assumed' — the re-derivation is correct to exist and is reading a different spec than the one shape blessed.")
//! @yah:handoff("MEASURED FROM THE noisetable CAMP ON us-east-001, 2026-09-12 (@Ashguard:eclipse, session:158d44c1, ticket noisetable R131-T16). NOT a hypothesis — the deploy was actually attempted and refused. `yah cloud workload deploy noisetable-account` returned: `POST http://100.64.0.3:7443/workloads/deploy: yubaba returned 500: {\"error\":\"kamaji deploy_workload: kamaji error: BackendRefused: workload noisetable-account declares yah.durability.tier = \\\"stream\\\" but not exactly one named-or-bind volume; its subjects are relative to one and there is no way to pick\"}`. The workload declares EXACTLY ONE `[[volumes]]` (named `noisetable-account-data`) and THREE `[[secrets]]` with `target = { file = { path = \"/run/secrets/...\" } }`. kamaji therefore counted four. THE REFUSAL IS FAIL-CLOSED AND COST NOTHING: the running container kept pid 663145 straight through, all three kamaji-native listeners stayed at their baseline (41507=200, 34759=200, 40995=404), and api.noisetable.com kept serving. yubaba logged `deploy failed at the backend; leaving the pre-existing secret dir in place for the generation that already owns it (R854)`.")
//! @yah:next("THE FIX IS A COUNTING FIX, NOT A RULE CHANGE — the rule ('subjects are relative to one volume, so there must be exactly one') is right and should survive. Three candidate shapes, in the order I would try them. (1) COUNT BEFORE MATERIALIZATION: have yubaba run `hydrate::plan`'s selection (or record the chosen volume root) on the pre-rewrite spec and carry the answer forward, so kamaji resolves a NAMED root rather than re-deriving from a mutated list. (2) MARK THE INJECTED MOUNTS: give `VolumeMount` a provenance flag (or a distinct `VolumeSource::Secret`) that `secret_mount.rs` sets and both `hydrate::plan` and `validate::shape` filter out — the same way `Tmpfs` is already excluded, and for the same reason: a secret bind is by construction not where durable subjects live. (3) SELECT BY TARGET rather than by count: `yah.durability.*` names its subjects relative to one mount, so the spec could name which one. That is a bigger surface and should not be reached for first.")
//! @yah:handoff("WHY NOBODY HIT THIS BEFORE, and why it will now block every real consumer. headscale — the only workload declaring a tier so far (R858-T24, live on us-south-001 since 2026-09-12T07:46Z) — is a native-exec appliance with ONE bind volume and ZERO file secrets, so it walks the one path where the count is unchanged by materialization. noisetable-account is the first workload in the fleet with BOTH durable state and file secrets, and that combination is not exotic: a service holding a database usually holds a signing key too. As written, the durability tier is available only to workloads that keep no file secrets.")
//! @yah:next("WHO IS WAITING AND WHAT THEY ALREADY DID, so the fixer does not re-derive it. noisetable R131-T16 is blocked on exactly this and NOTHING ELSE — every other precondition is met and measured on us-east-001: both helper binaries in /usr/local/bin, `kamaji.service.d/50-durability-helpers.conf` (yah R858-B22), and a new `51-noisetable-account-durability-cred.conf` placed by that ticket supplying S3_ACCESS_KEY/S3_SECRET_KEY via `EnvironmentFile=/etc/yah-cloud/noisetable-account-durability.env` plus `Environment=` for S3_ENDPOINT and S3_REGION=auto — the exact shape R858-T24 established on us-south-001. kamaji's journal reads `hydrate-on-place armed` and `durability tail armed`. The credential was proven THROUGH THE REAL HELPER before anything was armed, both directions: `turso-backup-hydrate` against a throwaway VOLUME_ROOT and throwaway prefix returned `{\"outcome\":\"nothing_in_the_store\",\"epoch\":1,\"subjects\":[...4...]}` exit 0, and the same call with S3_ACCESS_KEY unset returned `{\"outcome\":\"error\",\"message\":\"S3_ACCESS_KEY is required: environment variable not found\"}` exit 1 — which is the failure kamaji turns into 'must not start'. The probe's claim object was deleted (prefix re-lists to 0 keys). SO: when this bug is fixed, R131-T16 closes by pasting W124 section 8.1's block and running one `yah cloud workload deploy noisetable-account`. Nothing else is owed on that side.")
//! @yah:verify("REPRODUCTION, cheap and safe — it refuses before touching a container. Take any spec with one named volume, add a `[[secrets]]` with `target = { file = { path = \"/run/secrets/x\" } }`, declare `yah.durability.tier = \"stream\"` with a store and subjects, then `yah cloud workload deploy <name>`. `yah cloud validate` and the CLI's own shape validation pass; yubaba returns 500 BackendRefused naming 'not exactly one named-or-bind volume'. Remove the secret and the same spec deploys. THE FIX IS DONE when a spec with N file secrets and one named volume deploys, kamaji's journal reaches a hydrate VERDICT (`already_populated` against a populated volume), and the tail arms — and when `validate::shape` and `hydrate::plan` provably agree on the same spec, which is the property this bug is really about.")
//! @yah:handoff("Fixed via option (2) from this ticket's own next-steps: added `VolumeMount.from_secret_mount: bool` (workload-spec/src/lib.rs), set `true` only at yubaba's secret_mount.rs injection site, and excluded it from the 'exactly one named-or-bind volume' count in both `validate::shape` (validate.rs) and `kamaji::hydrate::plan` (hydrate.rs) — the same way `Tmpfs` was already excluded, and for the same reason: a secret bind is not where durable subjects live.")
//! @yah:handoff("Mechanical fallout: every other VolumeMount struct-literal construction across the tree needed the new field added (compiler-driven, not grepped) — yah-base (lib.rs x4, admission.rs x3, compose_import.rs, round_trip.rs x3, shape_fixtures.rs x6, local-driver/pond_ssr_runtime.rs), yubaba (headscale_appliance.rs, pond/launcher.rs), kamaji workspace (kamaji-proto/codec.rs x3, kamaji/sandbox.rs x3, kamaji-bin hydrate.rs/server.rs/tail.rs, kamaji-bin tests/sibling_wire_e2e.rs x3), qed velveteen-exec/remote.rs x3. Two admission.rs test sites that simulate real secret materialization got `from_secret_mount: true` deliberately; every other site is `false`.")
//! @yah:handoff("Regenerated the two derived artifacts per CLAUDE.md's schema-drift instructions: packages/yah/workload-spec/index.ts (export-ts) and .yah/schema/*.toml.schema.json (xtask emit-schemas) — only workload.toml.schema.json and index.ts actually changed.")
//! @yah:handoff("Two regression tests added, one per counting site: `shape_fixtures::a_secret_materializer_bind_is_not_a_second_candidate_root` (workload-spec, tier=infra to isolate from the unrelated Bind-requires-infra rule) and `hydrate::tests::a_secret_materializer_bind_is_not_a_second_candidate_root` (kamaji-bin) — the latter is the one that actually reproduces the noisetable-account failure mode end to end.")
//! @yah:verify("cd oss/yah-base && cargo test --workspace --lib --tests = 105+1 passed (yah-workload-spec incl. both new tests + ts_drift), 0 failed, across the whole workspace.")
//! @yah:verify("cd oss/kamaji && cargo test --workspace --lib = kamaji 162, kamaji-bin 221 (incl. new hydrate test), kamaji-proto 34, cheers_mock 18, procctl 26 passed, 0 failed.")
//! @yah:verify("cd oss/yubaba && cargo test -p yubaba --lib = 901 passed, 0 failed; cargo check -p yubaba --lib --tests = clean (an unrelated peer in-flight MesofactRevalidateReceiver.secrets rollout transiently broke this and resolved itself mid-session — not touched by this ticket).")
//! @yah:verify("cd oss/qed && cargo check -p velveteen-exec --lib --tests = clean.")
//! @yah:verify("Reproduction from the ticket's own verify block re-run conceptually via the new tests: a spec with one named volume + a from_secret_mount bind + a durability declaration now plans/validates successfully; the pre-fix behavior (counted as 2 roots, refused) is what the new tests pin against regressing.")
//! @yah:assumes("Did not chase down or touch the unrelated peer in-flight change to MesofactRevalidateReceiver (adding a `secrets` field, apparently R876) that transiently broke oss/yubaba's integration test and oss/yubaba/crates/cloud mid-session — it resolved on its own as that peer's work landed; flagging in case it did NOT fully land and something in that area still needs a look.")
//! @yah:gotcha("SIX UNSWEPT CALL SITES FROM THIS TICKET'S `VolumeMount::from_secret_mount` FIELD, found 2026-09-13 by a read-only verifier during relay R893 and recorded here because nobody was on this ticket to receive them. `cd oss/kamaji && cargo test -p kamaji --lib --all-features` is RED with `E0063: missing field 'from_secret_mount' in initializer of 'VolumeMount'` x6, all in oss/kamaji/crates/kamaji/src/microvm.rs at lines 3193, 3200, 3205, 3212, 3253, 3260. WHY IT HID: kamaji's backends are all OPTIONAL FEATURES, so a default-feature `cargo test -p kamaji --lib` compiles none of native.rs / docker.rs / containerd.rs / microvm.rs and reports a clean 146 pass / 0 fail. Only --all-features (or an all-but-microvm set, which is 275 pass / 0 fail and green) compiles this code at all. ATTRIBUTION IS ESTABLISHED, NOT GUESSED: @Miravel:libra (session:592a7b04, R876-B16) hit the same E0063 wave, swept their own 11 `MesofactRevalidateReceiver::secrets` sites in kamaji-bin/src/server.rs, and identified these 6 as belonging to VolumeMount/R858-B26 rather than to R876 -- they had not touched VolumeMount and the field predated their work. Left untouched deliberately: picking a value for `from_secret_mount` on a real deploy path is authoring on this ticket, not restoring a known-good state. CONSEQUENCE WHILE IT STANDS: no one can run a green --all-features gate over the kamaji crate, which is the only feature set that exercises R893-B17's new kamaji::observe env injection across native/docker/containerd -- B17 had to be signed off against an all-but-microvm run instead, recorded on its own ticket.")
//! @yah:handoff("THE SIX UNSWEPT `from_secret_mount` CALL SITES ARE SWEPT — the gotcha above is discharged, 2026-09-13 by @Ashguard:dove (session:d1d77f29) while delivering this fix to the fleet under R858-T28. All six were in `oss/kamaji/crates/kamaji/src/microvm.rs` inside `#[cfg(test)]` fixtures (`spec_with_volumes` and `slugs_are_unique_even_when_two_targets_render_the_same`), constructing OPERATOR-declared mounts — a bind, a tmpfs, a named volume, a read-only bind, and two colliding binds. None simulates secret materialization, so all six got `from_secret_mount: false`, which is this ticket's own stated rule (\"every other site is false\") rather than a judgment call. `cd oss/kamaji && cargo test -p kamaji --lib --all-features` is now 317 passed / 0 failed, where it was E0063 x6. That re-opens the only feature set exercising R893-B17's kamaji::observe env injection across native/docker/containerd — B17 had to sign off against an all-but-microvm run, and no longer needs to. NOTE THIS MATTERED FOR DELIVERY, not just for the gate: `scripts/hotship.sh` builds kamaji with `containerd-integration,native-exec,bundle-serving,microvm` (its registry line at scripts/hotship.sh:279), so microvm is in the shipped feature set.")
//!
//! @yah:ticket(R858-T28, "Deliver R858-B26's secret-mount counting fix to us-east-001 — the node's kamaji/yubaba predate it, so noisetable R131-T16 still gets BackendRefused")
//! @yah:status(review)
//! @yah:at(2026-09-13T09:12:22Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R858)
//! @yah:gotcha("MEASURED FROM THE noisetable CAMP ON us-east-001 (51.81.85.145) 2026-09-13 by @Ashguard:dove (session:d1d77f29, ticket noisetable R131-T16). R858-B26's fix is IN SOURCE AND NOT ON THE NODE. Source: oss/yah-base/crates/workload-spec/src/lib.rs:4538 `pub from_secret_mount: bool`, filtered at validate.rs:603 and kamaji-bin/src/hydrate.rs:140 — all three files are MODIFIED-uncommitted in the shared yah tree. Node: `kamaji --version` 0.8.40-h1, `yubaba --version` 0.8.39, both binaries placed 2026-09-12 08:06:35 UTC, i.e. BEFORE B26 landed. Content probe, `grep -a -c` against each binary: from_secret_mount = 0 in kamaji AND 0 in yubaba. THE PROBE WAS POSITIVE-CONTROLLED so a zero is not a broken method — the two sibling fields of the same VolumeMount struct match (read_only kamaji=3/yubaba=5, host_path kamaji=1/yubaba=5), so serde's field-name literals ARE in these binaries and from_secret_mount genuinely is not. BOTH binaries need it, not just kamaji: yubaba's secret_mount.rs is what SETS the flag and kamaji's hydrate::plan is what FILTERS on it, so shipping one half leaves the count unchanged.")
//! @yah:next("WHY THIS IS A TICKET AND NOT A NOTE ON R858-B26: B26 is at `review`, where an appended gotcha reaches nobody but a signing reviewer. Its fix is correct and tested; what is missing is DELIVERY, which nothing upstream owns. noisetable R131-T16 is the waiting consumer and is blocked on exactly this and nothing else — every other precondition is met and re-measured on us-east-001 this session: both helper binaries in /usr/local/bin (turso-backup-hydrate + turso-backup-tail, placed 2026-09-12 06:44), 50-durability-helpers.conf AND 51-noisetable-account-durability-cred.conf both present in kamaji.service.d/, and `systemctl show kamaji.service -p Environment` names KAMAJI_HYDRATE_HELPER, KAMAJI_TAIL_HELPER, S3_ENDPOINT and S3_REGION=auto with EnvironmentFiles=/etc/yah-cloud/noisetable-account-durability.env.")
//! @yah:verify("THE ORACLE IS THE CONSUMER, and it is one command from the noisetable camp: paste W124 section 8.1's yah.durability.* block into .yah/infra/workloads/noisetable-account.toml and run `yah cloud workload deploy noisetable-account`. Today it returns yubaba 500 BackendRefused \"declares yah.durability.tier = \\\"stream\\\" but not exactly one named-or-bind volume\" (the workload has ONE [[volumes]] and THREE file [[secrets]], so kamaji counts four). That refusal is FAIL-CLOSED and costs nothing — measured 2026-09-12, the container kept pid 663145 and api.noisetable.com kept serving. Node-side pre-check before handing back: `grep -a -c from_secret_mount /usr/local/bin/kamaji` and the same on yubaba must BOTH be non-zero.")
//! @yah:next("INSTRUMENT — DECIDE IT, DO NOT DEFAULT TO roll-node.sh. us-east-001's kamaji is 0.8.40-h1, HOTSHIP BYTES AHEAD of any published train, and `scripts/roll-node.sh --to <published>` installs published binaries, so a roll DOWNGRADES the one node serving production sign-in. R858-B22 hit this exact fork and took the narrow route — a targeted install of only the artifacts needed, leaving the daemons alone — but that route does not apply here, because THIS fix IS in the daemons. So the two real options are (a) a fresh hotship of kamaji+yubaba built from a tree carrying B26, or (b) cut and roll a release. Either way, verify by BINARY CONTENT (`grep -a -c from_secret_mount`), never by version string.")
//! @yah:gotcha("A BUILD BLOCKER STANDS BETWEEN THIS TICKET AND ANY kamaji BUILD, and it is B26's own unswept fallout: `cd oss/kamaji && cargo test -p kamaji --lib --all-features` is RED with E0063 \"missing field `from_secret_mount`\" x6 in oss/kamaji/crates/kamaji/src/microvm.rs (3193, 3200, 3205, 3212, 3253, 3260) — recorded on R858-B26's own gotcha list by an R893 verifier 2026-09-13. It hides under default features because kamaji's backends are all optional. Whether it blocks the artifact depends on which features the release/hotship build enables; establish that BEFORE building rather than discovering it mid-cut. Not swept from the noisetable camp: picking a `from_secret_mount` value on a real deploy path is authoring on someone else's ticket.")
//! @yah:handoff("DELIVERED TO ALL EIGHT LINUX FLEET NODES, and the consumer is live. Operator authorized a hotship on 2026-09-13 with the release (option B) still the intended destination — \"you can hotship for now, and feel free to hit ALL nodes, prod + dev\". `scripts/hotship.sh --binaries kamaji,yubaba` in two runs: stamp 0.8.40-h3 on the three prod voters (us-east-001, us-west-001, us-south-001, leader us-south-001 ordered last by the script) and 0.8.40-h4 on the five dev/LAN nodes (us-west-002, -003, -011, -013, -014). Every node re-joined healthy with `{\"status\":\"ok\",\"cluster_protocol\":7,\"state_epoch\":6}` and kamaji_version matching yubaba_version on each. VERIFIED BY CONTENT, NOT BY VERSION STRING, on all eight: `grep -a -c from_secret_mount /usr/local/bin/{kamaji,yubaba}` is non-zero everywhere (kamaji 1, yubaba 5 on x86_64 / 4 on aarch64 — a codegen difference, not a missing feature), where the pre-ship reading was 0 and 0. THE CONSUMER CLOSED THE SAME DAY: noisetable R131-T16 pasted W124 §8.1's block and `yah cloud workload deploy noisetable-account` was ACCEPTED where it returned BackendRefused the day before. kamaji's journal reached `hydrate-on-place outcome={\"outcome\":\"already_populated\"}`, then `durability tail started tier=\"stream\"`, then rounds ~30s apart with all four subjects `state:\"streamed\"`.")
//! @yah:verify("TWO DEFECTS FOUND AND FIXED ON THE PATH, both loud rather than worked around. (1) `scripts/hotship.sh` WOULD HAVE SHIPPED A LINUX-MUSL BINARY TO A MAC. us-west-015 is aarch64 AND macOS, and `triple_for()` read `arch` alone — so a 9-node dry run printed \"would ship kamaji yubaba and restart\" for it, resolving `aarch64-unknown-linux-musl`. This is the SAME defect R755-B7 fixed in roll-node.sh, which hotship.sh never learned; a dry run proves the ARTIFACT and never that the NODE can run it. Added `node_os()` (the same `awk /^mesh_tags/,/\\]/` reader roll-node.sh uses) and a refusal in `triple_for`. Negative-controlled both directions: us-west-015 now exits with \"REFUSED: us-west-015 declares os:darwin\" naming the node and the reason, while a us-west-011 dry run is byte-for-byte unchanged. `bash -n` clean. us-west-015 was therefore EXCLUDED from the ship — \"all nodes\" is eight, not nine, and the ninth is structurally unable to take this artifact. (2) R858-B26's six unswept `from_secret_mount` call sites in microvm.rs are swept — recorded on B26 itself. That was not optional here: hotship builds kamaji WITH `microvm` (scripts/hotship.sh:279), and `cargo test -p kamaji --lib --all-features` went E0063 x6 -> 317 passed / 0 failed.")
//! @yah:gotcha("THESE ARE HOTSHIP BYTES ON NO CDN MANIFEST — eight fleet nodes now run kamaji/yubaba that match no release, and noisetable's production sign-in durability depends on them. The operator's stated goal is still a real release (option B); this ticket bought time, it did not replace it. WHAT A RELEASE MUST CARRY, at minimum: R858-B26's counting fix (the thing shipped here), and it should be cut from a tree where `cargo test -p kamaji --lib --all-features` is green, which it now is. NOTHING WAS COMMITTED OR TAGGED — this camp is in git defer mode and the working tree carries R858-B26's fix (oss/yah-base/.../lib.rs, oss/yubaba/.../secret_mount.rs, oss/kamaji/.../hydrate.rs, validate.rs), my microvm.rs sweep and my scripts/hotship.sh guard, all uncommitted. A release cut from this tree is behaviorally what is on the nodes; a release cut after a peer sweep may not be.")

use std::path::PathBuf;
use std::process::Stdio;

use workload_spec::{DurabilityTier, VolumeSource, WorkloadSpec};

/// Host directory kamaji binds a [`VolumeSource::Named`] from.
///
/// The same literal `kamaji-containerd-core`'s `oci_spec` builder writes into
/// the `"source"` of a [`VolumeSource::Named`] mount, and the same one
/// `yah_cloud::migrate::KAMAJI_VOLUME_ROOT` renders into the operator's
/// migration procedure.
///
/// Three copies is two too many. Hoisting needs a crate all three depend on —
/// `workload-spec` is the only candidate, and putting a kamaji host path in the
/// leaf crate every fleet node links is a wider decision than this ticket.
/// Each copy is pinned by a literal assertion in its own crate
/// (`the_volume_root_is_the_path_the_oci_mount_uses` here,
/// `a_named_volume_renders_the_kamaji_host_path` in `migrate.rs`), so a change
/// on any one of them fails a test rather than silently restoring into a
/// directory nothing mounts.
pub const VOLUME_ROOT: &str = "/var/lib/yah/kamaji/volumes";

/// What a spec's durability declaration asks kamaji to do before starting it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydratePlan {
    /// No bytes-shipping tier. Nothing happens — including for
    /// `tier = "none"`, which is a deliberate statement that there is no second
    /// copy, not a request to restore from one.
    NotDeclared,
    /// Run the helper with these parameters.
    Declared(HydrateArgs),
}

/// The environment `turso-backup-hydrate` is invoked with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HydrateArgs {
    /// Host path of the workload's single named volume.
    pub volume_root: PathBuf,
    /// `yah.durability.subjects`, volume-relative.
    pub subjects: Vec<String>,
    /// `yah.durability.tier`, guaranteed to ship bytes.
    pub tier: DurabilityTier,
    /// Bucket parsed out of `yah.durability.store`.
    pub bucket: String,
    /// Key prefix parsed out of `yah.durability.store`.
    pub prefix: String,
}

/// Read a spec's declaration into a plan. Pure — no filesystem, no process.
///
/// `Err` is a **refusal to deploy**, not a warning. Every case it returns is a
/// declaration that says "this workload has durable state" and then fails to
/// say something the restore needs; guessing the missing half would restore
/// somebody's database to the wrong place or not at all.
pub fn plan(spec: &WorkloadSpec) -> Result<HydratePlan, String> {
    let declared = spec
        .durability()
        .map_err(|e| format!("workload {}: {e}", spec.name))?;
    let Some(d) = declared.filter(|d| d.tier.ships_bytes()) else {
        return Ok(HydratePlan::NotDeclared);
    };

    // `validate::shape` already enforces exactly one named-or-bind volume for a
    // bytes-shipping tier, but a spec reaching kamaji has crossed a wire and
    // this decides where bytes get written, so it is re-derived rather than
    // assumed.
    //
    // R858-F17: a **bind** resolves to its own `host_path`, and it is not an
    // afterthought — headscale is the first real consumer of this whole path
    // and it is a native-exec appliance whose state lives at
    // `/var/lib/yah-cloud/headscale/`, with no named volume and no prospect of
    // one. A named-only rule would have excluded exactly the workload whose
    // loss took this camp's mesh down for 37 hours. Tmpfs is excluded on
    // purpose: it is the declaration that the data does not survive.
    // A secret-materializer bind (R858-B26) is excluded for the same reason
    // Tmpfs is: it is not where durable subjects live, it is just where
    // yubaba parked a decrypted file. Without this, any workload with both a
    // durability declaration and a file secret would (correctly) refuse here
    // even though `validate::shape` blessed the operator's spec, because
    // yubaba's deploy-time secret materialization runs between the two checks
    // and appends a `Bind` per file secret to `spec.volumes`.
    let mut roots = spec
        .volumes
        .iter()
        .filter(|v| !v.from_secret_mount)
        .filter_map(|v| match &v.source {
            VolumeSource::Named { name } => Some(PathBuf::from(VOLUME_ROOT).join(name)),
            VolumeSource::Bind { host_path } => Some(host_path.clone()),
            VolumeSource::Tmpfs { .. } => None,
        });
    let (Some(volume_root), None) = (roots.next(), roots.next()) else {
        return Err(format!(
            "workload {} declares yah.durability.tier = \"{}\" but not exactly one \
             named-or-bind volume; its subjects are relative to one and there is no way to pick",
            spec.name, d.tier
        ));
    };

    let store = d
        .store
        .as_deref()
        .ok_or_else(|| format!("workload {}: tier \"{}\" with no store", spec.name, d.tier))?;
    let (bucket, prefix) = split_store_url(store)
        .ok_or_else(|| format!("workload {}: yah.durability.store {store:?} is not s3://<bucket>/<prefix>", spec.name))?;

    Ok(HydratePlan::Declared(HydrateArgs {
        volume_root,
        subjects: d.subjects.clone(),
        tier: d.tier,
        bucket,
        prefix,
    }))
}

/// Split `s3://bucket/some/prefix` into `("bucket", "some/prefix")`.
///
/// A bucket with no prefix is refused: the prefix is what scopes one workload's
/// state inside a shared bucket, and defaulting it to the bucket root would put
/// two workloads' claims on the same key — so the *second* one to place would
/// fence out the first, on a bucket that looked fine.
fn split_store_url(store: &str) -> Option<(String, String)> {
    let rest = store.strip_prefix("s3://")?;
    let (bucket, prefix) = rest.split_once('/')?;
    let prefix = prefix.trim_end_matches('/');
    if bucket.is_empty() || prefix.is_empty() {
        return None;
    }
    Some((bucket.to_string(), prefix.to_string()))
}

/// Outcome of a hydrate attempt, from kamaji's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HydrateResult {
    /// Nothing was declared, or the helper says it is safe to start. The JSON
    /// line the helper printed, when there was one — worth logging, since it
    /// carries the measured restore time and the fencing epoch.
    Proceed(Option<String>),
}

/// Run the helper for `spec`, if it declares a tier.
///
/// `Err` means **do not start the workload**, and the string is the message to
/// hand back as a `BackendRefused`. Every failure direction lands there: a
/// refusal from the helper (torn volume, lost fence, unfenced sink), a helper
/// that could not reach a verdict, a helper that is not configured, and a
/// helper that could not be spawned. An unreachable object store is
/// indistinguishable from the partition the fence exists for, which is exactly
/// when starting anyway is worst.
pub async fn run(
    helper: Option<&std::path::Path>,
    spec: &WorkloadSpec,
) -> Result<HydrateResult, String> {
    let args = match plan(spec)? {
        HydratePlan::NotDeclared => return Ok(HydrateResult::Proceed(None)),
        HydratePlan::Declared(args) => args,
    };
    let Some(helper) = helper else {
        return Err(no_helper(spec, &args));
    };

    let output = tokio::process::Command::new(helper)
        .env("VOLUME_ROOT", &args.volume_root)
        .env("SUBJECTS", args.subjects.join(","))
        .env("TIER", args.tier.as_str())
        .env("OWNER", owner_label())
        .env("S3_BUCKET", &args.bucket)
        .env("BACKUP_PREFIX", &args.prefix)
        // Credentials and endpoint are inherited from kamaji's own
        // environment (S3_ACCESS_KEY / S3_SECRET_KEY / S3_ENDPOINT /
        // S3_REGION) rather than set here. kamaji never reads them, so they do
        // not pass through a supervisor that has no business holding them.
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| {
            format!(
                "workload {}: could not run hydrate helper {}: {e}",
                spec.name,
                helper.display()
            )
        })?;

    let line = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if output.status.success() {
        return Ok(HydrateResult::Proceed(Some(line)));
    }
    Err(format!(
        "workload {} was not hydrated and must not start: {line}",
        spec.name
    ))
}

/// Whether this node could hydrate `spec` if asked, without touching anything.
///
/// R850-F1 backup half: split out of [`run`] so the deploy path can check both
/// halves' preconditions together, before either does any work. `run` keeps its
/// own copy of the check because it is public and a caller that skipped this
/// must still be refused.
pub fn preflight(helper: Option<&std::path::Path>, spec: &WorkloadSpec) -> Result<(), String> {
    match plan(spec)? {
        HydratePlan::NotDeclared => Ok(()),
        HydratePlan::Declared(args) if helper.is_none() => Err(no_helper(spec, &args)),
        HydratePlan::Declared(_) => Ok(()),
    }
}

fn no_helper(spec: &WorkloadSpec, args: &HydrateArgs) -> String {
    format!(
        "workload {} declares yah.durability.tier = \"{}\" but this kamaji has no hydrate \
         helper configured — start it with --hydrate-helper PATH (or set \
         KAMAJI_HYDRATE_HELPER). Starting without one would bring the workload up against an \
         empty volume, which looks exactly like a healthy first boot",
        spec.name, args.tier
    )
}

/// Label recorded in the ownership claim.
///
/// Diagnostic only — the epoch is what fences, and two acquires under the same
/// label are still two takeovers (see `turso_backup::claim::ClaimRecord`). So a
/// missing node id degrades the 3am experience rather than the safety property,
/// and is not worth refusing a deploy over.
pub(crate) fn owner_label() -> String {
    for key in ["KAMAJI_NODE_ID", "HOSTNAME"] {
        if let Ok(v) = std::env::var(key) {
            let token = v.split_whitespace().next().unwrap_or("");
            if !token.is_empty() {
                return token.to_string();
            }
        }
    }
    format!("kamaji-pid-{}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `for_forge` is used purely as a constructor with every required field
    /// already filled — this module reads only `name`, `volumes` and
    /// `annotations`, and the two annotations it seeds (`yah.forge`,
    /// the memory request) are invisible to `durability()`.
    fn spec_with(
        durability: Option<workload_spec::Durability>,
        volumes: Vec<workload_spec::VolumeMount>,
    ) -> WorkloadSpec {
        let mut spec = WorkloadSpec::for_forge(
            "acct",
            workload_spec::ImageRef {
                registry: "r".into(),
                repository: "acct".into(),
                tag: "v1".into(),
                digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .into(),
            },
            workload_spec::TierTag("infra".into()),
            vec![],
        );
        spec.volumes = volumes;
        spec.durability = durability;
        spec
    }

    fn named(name: &str) -> workload_spec::VolumeMount {
        workload_spec::VolumeMount {
            source: VolumeSource::Named { name: name.into() },
            target: "/var/lib/app".into(),
            read_only: false,
            from_secret_mount: false,
        }
    }

    fn secret_bind(host_path: &str, target: &str) -> workload_spec::VolumeMount {
        workload_spec::VolumeMount {
            source: VolumeSource::Bind { host_path: host_path.into() },
            target: target.into(),
            read_only: true,
            from_secret_mount: true,
        }
    }

    fn declared() -> Option<workload_spec::Durability> {
        Some(workload_spec::Durability {
            tier: DurabilityTier::Stream,
            engine: Some(workload_spec::DurabilityEngine::Turso),
            store: Some("s3://yah-backups/noisetable-account".into()),
            subjects: vec!["accounts.db".into(), "sessions.db".into()],
            rpo_seconds: None,
            state_mb: None,
        })
    }

    /// The hydrate writes into the directory the container will mount. If this
    /// string and `kamaji-containerd-core`'s ever disagree, the restore lands
    /// somewhere the workload never sees and it comes up empty — the exact
    /// silent failure the whole path exists to prevent, so the literal is
    /// pinned rather than trusted.
    #[test]
    fn the_volume_root_is_the_path_the_oci_mount_uses() {
        assert_eq!(VOLUME_ROOT, "/var/lib/yah/kamaji/volumes");
    }

    /// Every spec in the tree today. The path must be inert for them — a
    /// supervisor that started refusing deploys because a new annotation exists
    /// would take the fleet down.
    #[test]
    fn a_spec_with_no_declaration_plans_nothing() {
        assert_eq!(
            plan(&spec_with(None, vec![named("accounts")])).unwrap(),
            HydratePlan::NotDeclared
        );
    }

    /// `tier = "none"` is a statement that there is no second copy, not a
    /// request to look for one.
    #[test]
    fn tier_none_plans_nothing() {
        assert_eq!(
            plan(&spec_with(
                Some(workload_spec::Durability {
                    tier: DurabilityTier::None,
                    engine: None,
                    store: None,
                    subjects: vec![],
                    rpo_seconds: None,
                    state_mb: None,
                }),
                vec![named("accounts")]
            ))
            .unwrap(),
            HydratePlan::NotDeclared
        );
    }

    #[test]
    fn a_declaration_resolves_to_the_volume_host_path_and_the_store_split() {
        let HydratePlan::Declared(args) = plan(&spec_with(declared(), vec![named("accounts")])).unwrap()
        else {
            panic!("expected a plan");
        };
        assert_eq!(
            args.volume_root,
            PathBuf::from("/var/lib/yah/kamaji/volumes/accounts")
        );
        assert_eq!(args.subjects, vec!["accounts.db", "sessions.db"]);
        assert_eq!(args.tier, DurabilityTier::Stream);
        assert_eq!(args.bucket, "yah-backups");
        assert_eq!(args.prefix, "noisetable-account");
    }

    /// The prefix is what scopes one workload inside a shared bucket. Defaulting
    /// it to the root would put two workloads' ownership claims on one key, so
    /// placing the second would fence out the first.
    /// R858-F17: headscale's shape. A native-exec appliance keeps its state at
    /// a bind path and has no named volume, so a named-only rule excluded
    /// exactly the workload whose loss took this camp's mesh down for 37 hours.
    /// A bind resolves to its own host_path, NOT under `VOLUME_ROOT`.
    #[test]
    fn a_bind_volume_resolves_to_its_own_host_path() {
        let spec = spec_with(
            declared(),
            vec![workload_spec::VolumeMount {
                source: VolumeSource::Bind {
                    host_path: "/var/lib/yah-cloud/headscale".into(),
                },
                target: "/var/lib/headscale".into(),
                read_only: false,
                from_secret_mount: false,
            }],
        );
        let HydratePlan::Declared(args) = plan(&spec).unwrap() else {
            panic!("a bind-backed declaration must plan");
        };
        assert_eq!(
            args.volume_root,
            PathBuf::from("/var/lib/yah-cloud/headscale"),
            "a bind must not be rehomed under the named-volume root"
        );
    }

    /// A tmpfs is the declaration that the data does not survive the process,
    /// so it must not become the root a durable restore writes into.
    #[test]
    fn a_tmpfs_is_not_a_candidate_volume_root() {
        let spec = spec_with(
            declared(),
            vec![workload_spec::VolumeMount {
                source: VolumeSource::Tmpfs { size_mb: 64 },
                target: "/scratch".into(),
                read_only: false,
                from_secret_mount: false,
            }],
        );
        assert!(plan(&spec).is_err(), "a tmpfs-only spec has nowhere durable to restore into");
    }

    /// One named AND one bind is still ambiguous — the widening added a second
    /// kind of candidate, not permission to guess between two.
    #[test]
    fn a_named_and_a_bind_together_are_still_refused() {
        let spec = spec_with(
            declared(),
            vec![
                named("acct-data"),
                workload_spec::VolumeMount {
                    source: VolumeSource::Bind { host_path: "/srv/acct".into() },
                    target: "/srv".into(),
                    read_only: false,
                    from_secret_mount: false,
                },
            ],
        );
        let err = plan(&spec).expect_err("two candidate roots must refuse");
        assert!(err.contains("named-or-bind"), "got: {err}");
    }

    /// R858-B26: yubaba's deploy-time secret materializer (`secret_mount.rs`)
    /// appends a `from_secret_mount` `Bind` per file secret to `spec.volumes`
    /// AFTER `validate::shape` runs, so a spec kamaji receives can carry that
    /// bind alongside the operator's one real volume. Counting it as a second
    /// candidate root refused every durability-declaring workload with a file
    /// secret — measured live against noisetable-account.
    #[test]
    fn a_secret_materializer_bind_is_not_a_second_candidate_root() {
        let spec = spec_with(
            declared(),
            vec![named("accounts"), secret_bind("/run/secrets/api-key", "/run/secrets/api-key")],
        );
        let HydratePlan::Declared(args) = plan(&spec).unwrap() else {
            panic!("a secret-materializer bind must not make this ambiguous");
        };
        assert_eq!(
            args.volume_root,
            PathBuf::from("/var/lib/yah/kamaji/volumes/accounts")
        );
    }

    #[test]
    fn a_store_url_without_a_prefix_is_refused() {
        for bad in ["s3://yah-backups", "s3://yah-backups/", "yah-backups/acct", "s3:///acct"] {
            let mut d = declared();
            d.as_mut().unwrap().store = Some(bad.into());
            let err = plan(&spec_with(d, vec![named("accounts")])).unwrap_err();
            assert!(err.contains("s3://<bucket>/<prefix>"), "{bad}: {err}");
        }
    }

    #[test]
    fn subjects_relative_to_no_volume_or_two_volumes_are_refused() {
        let err = plan(&spec_with(declared(), vec![])).unwrap_err();
        assert!(err.contains("exactly one \n             named-or-bind volume") || err.contains("named-or-bind"), "{err}");

        let err = plan(&spec_with(
            declared(),
            vec![named("accounts"), named("sessions")],
        ))
        .unwrap_err();
        assert!(err.contains("named-or-bind"), "{err}");
    }

    /// A declaration still written as the retired `yah.durability.*`
    /// annotations (R896-F3) is a refusal, not a shrug — nothing reads those
    /// keys, so passing it would reach a backend as "no durability configured"
    /// and start the workload against an empty volume.
    #[test]
    fn a_retired_durability_annotation_refuses_the_deploy() {
        let mut spec = spec_with(None, vec![named("accounts")]);
        spec.annotations
            .insert("yah.durability.tier".into(), "stream".into());
        let err = plan(&spec).unwrap_err();
        assert!(err.contains("durability.tier"), "{err}");
    }

    /// Declared, no helper: refuse. Starting would give a running workload with
    /// an empty database and no error anywhere.
    #[tokio::test]
    async fn a_declared_workload_with_no_helper_is_refused_not_started() {
        let err = run(None, &spec_with(declared(), vec![named("accounts")]))
            .await
            .unwrap_err();
        assert!(err.contains("--hydrate-helper"), "{err}");
    }

    /// ...and an undeclared one is untouched even with no helper, which is the
    /// property that keeps this inert for the existing fleet.
    #[tokio::test]
    async fn an_undeclared_workload_proceeds_with_no_helper() {
        assert_eq!(
            run(None, &spec_with(None, vec![named("accounts")]))
                .await
                .unwrap(),
            HydrateResult::Proceed(None)
        );
    }

    /// A helper that exits non-zero stops the deploy and its message is carried
    /// through verbatim — the refusal an operator reads is the helper's, not a
    /// paraphrase.
    #[tokio::test]
    async fn a_refusing_helper_stops_the_deploy_and_carries_its_message() {
        let helper = fake_helper(
            "refuse",
            "#!/bin/sh\necho '{\"outcome\":\"refused\",\"reason\":\"torn_volume\"}'\nexit 2\n",
        );
        let err = run(Some(&helper), &spec_with(declared(), vec![named("accounts")]))
            .await
            .unwrap_err();
        assert!(err.contains("torn_volume"), "{err}");
        assert!(err.contains("must not start"), "{err}");
    }

    #[tokio::test]
    async fn a_succeeding_helper_lets_the_deploy_through_and_its_line_is_kept() {
        let helper = fake_helper(
            "ok",
            "#!/bin/sh\necho \"{\\\"outcome\\\":\\\"hydrated\\\",\\\"subjects\\\":$SUBJECTS}\"\n",
        );
        let out = run(Some(&helper), &spec_with(declared(), vec![named("accounts")]))
            .await
            .unwrap();
        let HydrateResult::Proceed(Some(line)) = out else {
            panic!("expected a line, got {out:?}");
        };
        // The subject list reaches the helper as the comma-joined declaration.
        assert!(line.contains("accounts.db,sessions.db"), "{line}");
    }

    /// A helper path that does not exist is a refusal, not a silent proceed.
    #[tokio::test]
    async fn an_unspawnable_helper_is_a_refusal() {
        let err = run(
            Some(std::path::Path::new("/nonexistent/turso-backup-hydrate")),
            &spec_with(declared(), vec![named("accounts")]),
        )
        .await
        .unwrap_err();
        assert!(err.contains("could not run hydrate helper"), "{err}");
    }

    fn fake_helper(tag: &str, script: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "kamaji-hydrate-fake-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&p, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }
}

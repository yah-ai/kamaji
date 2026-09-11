//! @yah:relay(R597, "Finish constable->kamaji / warden->yubaba rename tail (env-var + raft symbols)")
//! @yah:at(2026-07-06T07:45:13Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("Spawned from R592-T4 (the wire-surface rename, now in review). T4 renamed the pub types/client/field (WardenToConstable->YubabaToKamaji, ConstableToWarden->KamajiToYubaba, ConstableClient->KamajiClient, constable_version->kamaji_version) across oss/kamaji + root/hub + oss/yubaba and verified all 3 green. This relay finishes the two residual slices T4 deliberately deferred: R597-T1 (KAMAJI_SOCK env var rename, drags in oss/qed) and R597-T2 (yubaba-internal raft Warden* symbols). Both are independent, mechanical, and can run in either order once their lanes are quiet.")
//!
//! @yah:ticket(R597-T1, "Rename CONSTABLE_SOCK env var -> KAMAJI_SOCK across kamaji-bin + qed pond image + kamaji.service")
//! @yah:status(review)
//! @yah:at(2026-07-20T03:54:35Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R597)
//! @yah:next("DONE (R597-T1): renamed env-var to KAMAJI_SOCK across kamaji-bin/main.rs, yah-yubaba/Dockerfile, yah-yubaba/pond-supervise.sh, kamaji.service comment. Socket path /run/kamaji/kamaji.sock unchanged.")
//! @yah:next("Before claiming: oss/qed is a 4th workspace not cleared during R592-T4 -- check git status oss/qed + board inflight for a live peer first (R592-T4 deferred this specifically to avoid dragging qed into the wire-rename pass).")
//! @yah:next("Postcard/runtime note: env-var name is not on the wire; pure string-contract rename. No protocol impact.")
//! @yah:verify("cd oss/kamaji && cargo build -p kamaji-bin; pond-supervise.sh + Dockerfile reference KAMAJI_SOCK and /run/kamaji/kamaji.sock as the default path value")
//! @yah:gotcha("Tier: Thief -- rote cross-file string rename of a single env-var token, no logic. The only care is atomicity across the 4 sites (binary reader + qed Dockerfile/script setters + service comment) so a deploy can't read one name while the image sets the other.")
//!
//! @yah:ticket(R605-T24, "Prove a real forge dispatch reaches a microVM guest through yubaba, closing the unproven half of F14's verify")
//! @yah:at(2026-09-10T08:26:53Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @yah:verify("A forge dispatched through yubaba with the microvm annotation lands on us-west-003, boots a guest, and its artifacts appear under /var/lib/yah/qed/produced/<forge-id> on the host. That is the last unproven clause of R605-F14's verify criterion.")
//! @yah:gotcha("R605-F14's e2e test drives kamaji's OWN MicroVmRuntime::deploy_workload directly. So the deploy -> boot -> mounts -> argv -> Stopped -> artifacts-on-host half of F14's verify criterion is genuinely asserted (2 pass / 0 fail on us-west-003), and everything ABOVE kamaji is not: whether a forge spec dispatched through yubaba reaches a node carrying the microvm annotation at all has never been exercised. Do not read F14 as having proven the dispatch path.")
//! @yah:depends_on(R605-T15)
//! @yah:gotcha("CORRECTION FROM R605-T15, 2026-09-10 — THIS TICKET'S OWN NEXT-STEP TEXT IS WRONG AND WILL MISLEAD YOU. It says the service-flag leg \"is the actual gate and it is cheap\", citing kamaji-bin/src/main.rs:748 as proof everything downstream is proven. That framing was mine and it is false. Adding `--microvm-dir` to the deployed kamaji.service on us-west-003 would NOT have enabled the backend — it would have KILLED THE SUPERVISOR. The binary deployed there was built without the `microvm` cargo feature, so `--microvm-dir` is a fatal argument: it aborts before binding its socket, and with the unit's restart limit systemd gives up inside a minute, leaving the node with no workload supervisor. T15's courier proved this off the INSTALLED BYTES, not a version number — the binary carries the error string that exists only in the feature-off arm and lacks the log line that exists only in the feature-on arm. `--help` advertises `--microvm-dir` either way, because the flag is parsed unconditionally and rejected later. That is what makes it look like a one-liner right up until the restart.")
//! @yah:gotcha("SECOND CORRECTION, FROM R605-B26 — THE EXECSTART EDIT IS THE WRONG MECHANISM ENTIRELY. Both this ticket and R605-T15 are written around adding `--microvm-dir` to kamaji.service's ExecStart. Don't. kamaji reads a `KAMAJI_MICROVM_DIR` ENVIRONMENT VARIABLE as a fallback entry point and that is the SUPPORTED one: the tracked unit's own header says extra options belong in a drop-in as `Environment=`, never as a second ExecStart, because a drop-in that re-declares ExecStart silently drops every flag the base unit later gains and a subsequent roll does not fix it. That header names this as half of the 37-hour mesh outage on the third. So the change on us-west-003 is a DROP-IN SETTING THAT VARIABLE, not an ExecStart edit. NOBODY HAS ESTABLISHED WHETHER us-west-003 ALREADY HAS A DROP-IN — all that was observed is that its running ExecStart matches the tracked base unit exactly, which is consistent with no clobbering drop-in but does not prove one is absent, and the box stopped answering before it could be checked. That is precisely the shape that caused the outage, so check it FIRST, not last.")
//! @yah:next("THE SERVICE-FLAG LEG IS DONE — R605-T15 LANDED IT 2026-09-10 AND THIS TICKET'S GATE IS OPEN. The retired next-step told you to do it and called it cheap; both corrections in the gotchas above were right and the leg turned out to need a rebuilt binary, a vmm_bin fix and a paired ship. What actually happened: us-west-003 now runs a tree build (0.8.38-h2) of yubaba+kamaji built WITH the microvm feature, and the backend is enabled through /etc/systemd/system/kamaji.service.d/10-microvm.conf setting Environment=KAMAJI_MICROVM_DIR=/var/lib/yah/kamaji/microvm — a drop-in, not an ExecStart edit, per the second correction. Verified by journal: 'microVM backend attached' at 23:27:20 with the right microvm_dir, both fatal strings absent, active with NRestarts=0 at +30s and +90s. There was never a pre-existing drop-in on that box (`systemctl show -p DropInPaths` was empty), which settles the unknown the gotcha flagged. Do NOT redo any of this.")
//! @yah:next("SEQUENCE THE PROOF IN TWO STEPS SO A FAILURE HAS ONE CAUSE. This ticket's verify criterion is argv-level — a forge lands, a guest boots, artifacts appear under /var/lib/yah/qed/produced/<forge-id> — and needs NO compiler in the guest, so the currently deployed 0.8.38-h2 is sufficient for it. Prove THAT first: it isolates the one genuinely unproven question, which is whether a forge spec dispatched through yubaba with the microvm annotation reaches the node and selects the microVM backend at all. Only then consider shipping a newer pair to re-run it with a real build.")
//! @yah:next("R605-F23 IS COMMITTED BUT NOT DEPLOYED, which matters if you want the stronger proof. 88533e01 added a third read-only drive carrying a 1166 MB Rust toolchain, folded into the guest overlay as a lower layer, with CARGO_HOME and TMPDIR defaulted onto the per-job scratch disk — so a guest booted from THAT tree can run a real cargo build, and one on us-west-003 already did (cargo 1.98.0 + rustc 1.98.0 + cc inside the guest, plus a live crates.io fetch over TLS). The kamaji RUNNING on the node predates it and still boots two-drive guests with no compiler. To prove a real BUILD forge step end to end you must first `scripts/hotship.sh --binaries yubaba,kamaji` from the current tree — NEVER kamaji alone, ProtocolVersion::CURRENT is V9 and a skewed pair fails every yubaba->kamaji call at connect with HandshakeRefused while still reporting active with NRestarts=0.")
//!
//! @yah:ticket(R605-B26, "No kamaji that exists anywhere is built with the microvm feature, so the entire microVM track is dead code on every node")
//! @yah:status(review)
//! @yah:at(2026-09-10T09:09:12Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @yah:severity(high)
//! @yah:gotcha("MEASURED BY R605-T15 ON 2026-09-10, off the installed bytes rather than a version number, and it is the real reason nothing downstream of R605-F14 was ever going to work. Neither build recipe passes the `microvm` cargo feature — not the yubaba release script, not hotship's app registry; both pin the same three features. So no published kamaji has the backend compiled in. On a binary built without it, `--microvm-dir` is a FATAL argument: the process aborts before binding its socket, and with the unit's restart limit systemd gives up inside a minute and leaves the node with NO WORKLOAD SUPERVISOR. `--help` advertises the flag either way, because it is parsed unconditionally and rejected later — which is exactly what makes this look like a one-line unit edit right up until the restart.")
//! @yah:assumes("That enabling the feature is inert on a node without guest artifacts. Grounded in MicroVmRuntime::new refusing to construct when vmlinux or rootfs.ext4 is absent — such a node advertises no microVM backend rather than failing every deploy — but confirm that the constructor is the only path in, and note R605-B26's finding that it ALSO treats an absent VMM binary as fatal.")
//! @yah:next("LEADER DECISION (R605, session:0befddd7) — ENABLE THE FEATURE IN BOTH RECIPES. T15's courier correctly refused to make this call itself, since it changes what every released kamaji contains. Taking it: the change is additive and inert on a node with no guest artifacts (MicroVmRuntime::new refuses to construct without vmlinux/rootfs.ext4, so such a node advertises no microVM backend rather than failing deploys), and without it the entire microVM track — F8, F14, F16, F22, F23, T24, S6, T7 — is dead code no matter what else lands. R605-F14 has already proven the guest side boots and runs a job end to end on real hardware; this is the one line standing between that and it being reachable in production.")
//! @yah:next("DO NOT SHIP A KAMAJI BUILT FROM THIS TREE TODAY — change the recipes, do not roll the result. R605-F22 is live and holds several hundred uncommitted lines of mid-refactor microVM networking; a build from the current tree would carry a peer's half-finished work onto a fleet node. Sequence, from T15's handoff: (1) this ticket flips the feature in both recipes, (2) R605-F22 lands, (3) build, (4) ship, (5) THEN the kamaji.service --microvm-dir unit edit, (6) verify by the kamaji startup JOURNAL LINE, not by GET /health — see R605-B27 for why health cannot answer this. Also fold in R605-B26's sibling finding before shipping: the VMM path in the config builder is hardcoded to /usr/bin/firecracker and firecracker on us-west-003 lives under /usr/local/bin, which the runtime constructor treats as fatal exactly like a missing kernel.")
//! @yah:handoff("DONE — `microvm` is now in the kamaji feature list at every build site in the tree. THREE, not the two the ticket named: scripts/publish-yubaba-release.sh (the cross-build-guarded call, plus the header comment at the top of the file that documents the same list and would otherwise have drifted immediately), scripts/hotship.sh's app_spec row for kamaji, and .github/workflows/release.yml's \"Build kamaji (static musl)\" step. All three now pass containerd-integration,native-exec,bundle-serving,microvm. The workflow is workflow_dispatch-only and the account is billing-stopped so it builds nothing today — I updated it anyway because three build sites that must agree and one left behind is exactly the drift the change is about, and it is free to keep correct while it is dead. Each site carries a comment naming the other two.")
//! @yah:handoff("THE @yah:assumes IS CONFIRMED BUT ITS REASONING WAS WRONG, and the difference matters operationally. Confirmed: with the feature compiled in and no --microvm-dir, ServerCtx.microvm is None (kamaji-bin/src/server.rs:870 and :896 initialise it None), every use site is an `if let Some` (:1457 List merge, :2265 deploy dispatch, :4048, :4999), and the only behavioural difference from a feature-off binary is one tracing::debug line at main.rs:809 plus a BETTER refusal message on a microvm-marked deploy — server.rs:2290 says \"microVM backend not configured — start kamaji with --microvm-dir, and check that the node has a guest kernel + rootfs and that the service user can open /dev/kvm\" where the feature-off build says only \"kamaji built without the microvm feature\". Nothing calls BackendAvailability::probe at kamaji-bin startup, so enabling the feature does not add a /dev/kvm open on boot either. WRONG PART: the inertness does NOT come from MicroVmRuntime::new refusing to construct. On a node that DOES pass --microvm-dir without artifacts, kamaji does not \"advertise no microVM backend\" — main.rs:801 propagates that refusal with `?` and the process FAILS TO START, which its own comment at main.rs:754-759 states as deliberate (\"that refusal is fatal here rather than a warning ... Failing to start puts the error where the misconfiguration is\"). The inertness comes from the FLAG being absent, not the constructor refusing. The @yah:gotcha at oss/kamaji/crates/kamaji/src/microvm.rs:93 carries the same wrong framing (\"a node with the wrong filename advertises no microVM backend rather than failing every build\") and is stale post-F8-wiring; left in place because that file is R605-F22's live working set.")
//! @yah:handoff("THERE IS A SECOND PATH IN, AND IT IS THE SUPPORTED ONE — this is the discovered finding of the pass and it changes step 5 of the sequence. kamaji-bin/src/main.rs:150 reads KAMAJI_MICROVM_DIR as the fallback for --microvm-dir, so the env var is a full second entry point to the same fatal-at-startup code. That is not an edge case: app/yah/cli/resources/kamaji.service's own header says extra options belong in a drop-in as `Environment=`, NEVER as a second ExecStart, because a drop-in that re-declares ExecStart silently drops every flag the base unit gains afterwards and a roll does not fix it — measured on us-south-001 2026-09-06 (R858-T4), and named there as half of the 37-hour 2026-09-03 mesh outage. So the eventual us-west-003 change is a drop-in carrying Environment=KAMAJI_MICROVM_DIR=/var/lib/yah/kamaji/microvm, not the ExecStart edit R605-T15 and R605-T24 were both written around. That same unit header already states the general rule I measured independently on the deployed binary (\"kamaji bails at startup when handed a flag whose cargo feature is absent, so a unit carrying --bundle-cache-dir would refuse to start on any kamaji built without bundle-serving\") — the microVM case was that rule coming true, not a new class of bug. I extended that header with the microVM specifics: the env var name, the three fatal-at-startup preconditions, and the check to run first.")
//! @yah:handoff("R605-T15's FINDING 3 IS ALREADY FIXED IN-TREE and needs no further action. @Ashguard:libra took the seam handed to them and replaced the hardcoded vmm_bin with kamaji::microvm::find_vmm() (oss/kamaji/crates/kamaji/src/microvm.rs:1716) — PATH first so an operator can override by placing one earlier, then /usr/local/bin, /usr/bin, /opt/firecracker/bin, failing with the list of what it searched. Their doc comment records the reason correctly (Firecracker ships no Debian package, so every install on this fleet is a tarball into /usr/local/bin). Uncommitted at time of writing, in their working set. I re-read the block rather than assuming, and updated the us-west-003 machine file's finding 3 from \"hardcoded and wrong\" to \"fixed in-tree, uncommitted\".")
//! @yah:handoff("MACHINE FILE CORRECTED, since R605-T15 wrote the now-stale version of finding 2 into it this morning. .yah/infra/machines/us-west-003.toml's finding 2 now reads \"fixed in the recipes, NOT YET IN ANY BINARY\" with all three build sites named, finding 3 now records find_vmm, and the DO NOT ADD block gained the drop-in/Environment= correction above plus an explicit unknown: whether that box already has a drop-in under /etc/systemd/system/kamaji.service.d/ was NOT established. T15 observed only that systemctl show -p ExecStart matched the tracked base unit exactly, which is consistent with no ExecStart-clobbering drop-in but does not prove one is absent, and the box stopped answering ssh before it could be checked. Whoever does step 5 must check that first — it is the precise shape that caused the R858-T4 outage.")
//! @yah:verify("MEASURED, not argued: enabling `microvm` adds ZERO packages to kamaji-bin's dependency graph. `cargo tree --offline -p kamaji-bin --no-default-features -e normal --prefix none` run twice in oss/kamaji, once with containerd-integration,native-exec,bundle-serving and once with that plus microvm, sorted and diffed: 209 lines each, byte-identical. Mechanism: microvm = [\"dep:kamaji\", \"kamaji/microvm-integration\"] (kamaji-bin/Cargo.toml:77) and microvm-integration = [\"dep:libc\"] (kamaji/Cargo.toml:43), while native-exec already pulls kamaji/native-integration = [\"dep:libc\", \"socket-custody\"] — so libc and the kamaji crate are both already in. This also means Cargo.lock does not change, which is what keeps release.yml's `cross build --locked` valid.")
//! @yah:verify("Both scripts pass `bash -n`. The hotship change is inside a `case` arm, so I checked the parse rather than trusting it: extracted the real app_spec function from scripts/hotship.sh and ran it — the kamaji row yields exactly seven fields with feats=containerd-integration,native-exec,bundle-serving,microvm, and the neighbouring rows are unchanged. Confirmed the positional contracts my edits depend on: cross-build-guarded.sh documents $4 as the --features list (its header, \"Args (positional)\"), and hotship's build_one does `[ -n \"$feats\" ] && args+=(--features \"$feats\")`. release.yml parses as valid YAML through python3 yaml.safe_load, and the reconstructed run block shows the added lines as shell comments above the unchanged cross build line.")
//! @yah:verify("NOT VERIFIED, stated rather than glossed: I did not compile anything. Per the ticket's own constraint I did not build and did not ship, so there is no proof from THIS pass that kamaji-bin compiles for x86_64-unknown-linux-musl or aarch64-unknown-linux-musl with the feature on. What is on record from elsewhere: R605-F8's verify line reports `cargo test --workspace --all-features` green in oss/kamaji, and R605-F14 ran the microVM guest e2e on us-west-003 — so the feature has compiled before, on a host target, on an older tree. It has never been cross-compiled for musl by anyone. A compile-check now would also be ambiguous, since oss/kamaji currently carries several hundred uncommitted lines from R605-F22 and a red would not be attributable to this change. First real proof is the build in step 3 of the sequence.")
//! @yah:gotcha("ONE STALE REFERENCE DELIBERATELY LEFT ALONE. .yah/docs/working/W282-qed-manual-steps.md:37 tells whoever cuts a release by hand to build kamaji with containerd-integration,native-exec,bundle-serving — now wrong by one feature. It is another ticket's @yah:next annotation, not prose, so hand-editing it would be authoring on someone else's ticket; the authoritative source is the script, which is fixed. Whoever owns W282 should refresh that line. Two other hits on the old string are historical records that are correct as history and should NOT be edited: .yah/infra/machines/us-west-015.toml:12 (a darwin-leg analysis) and the R605-T15 handoff recorded on W325.")
//! @yah:handoff("SCOPE HELD AND NOTHING WAS SHIPPED. No cargo build, no hotship, no node access, no restart — us-west-003 was not touched and was still not answering ssh or HTTP at the end of this pass. Five files changed, all repo-only: scripts/publish-yubaba-release.sh (build call + its header comment), scripts/hotship.sh (app_spec row), .github/workflows/release.yml (the third build site), app/yah/cli/resources/kamaji.service (header comment: the Environment= drop-in spelling for microVM and its three fatal-at-startup preconditions), .yah/infra/machines/us-west-003.toml (findings 2 and 3 corrected, drop-in warning added). No source file was edited — in particular nothing in oss/kamaji, which is R605-F22's live working set.")

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

const DEFAULT_SOCKET: &str = "/run/kamaji/kamaji.sock";
const ABOUT: &str = "kamaji — Yubaba's sibling process supervisor.\n\nReads workload-control messages from Yubaba over a unix domain socket and dispatches them to the containerd backend (R406-T9), the docker/OrbStack backend (R626-F1), the native fork+exec path (R406-T5/T6), or the keep-alive mesofact bundle backend (R599-F10). Run with --containerd-socket (cloud tier) or --docker (pond / dev host) to enable container workloads, and --bundle-cache-dir + --bundle-origin to serve published W272 mesofact bundles.";

struct Args {
    socket: PathBuf,
    containerd_socket: Option<PathBuf>,
    /// Node bundle root (R599-F10). Materialized bundles land in
    /// `<root>/bundles/`, stock serve-runtime assets in `<root>/runtimes/`, and
    /// the native supervisor's per-workload log captures in `<root>/state/`.
    bundle_cache_dir: Option<PathBuf>,
    /// R2 bucket holding the published bundle store (blobs + manifests).
    bundle_origin: Option<String>,
    /// Node-wide port override for served bundles, falling back to
    /// `$KAMAJI_BUNDLE_PORT`. R844-F2: unset no longer means "the compiled-in
    /// default" — it means the node ALLOCATES a free port per bundle, which is
    /// what lets two bundles co-tenant a node without either mirror naming a
    /// port. Only consumed by the bundle backend; the no-feature build still
    /// *parses* it (so `--bundle-port` isn't an "unknown argument") but has
    /// nothing to apply it to.
    #[cfg_attr(not(feature = "bundle-serving"), allow(dead_code))]
    bundle_port: Option<u16>,
    /// Attach the docker/OrbStack backend for `Deploy { Container }` (R626-F1).
    /// `Some("")` means "use the ambient `DOCKER_HOST`" (bare `--docker`);
    /// `Some(host)` pins an explicit daemon. `None` leaves docker unattached.
    #[cfg_attr(not(feature = "docker-integration"), allow(dead_code))]
    docker_host: Option<String>,
    /// State dir for the native fork+exec backend (R577-T1), holding each
    /// native workload's stdout/stderr capture. `Some(dir)` attaches the
    /// backend; `None` leaves native-marked container deploys refused.
    #[cfg_attr(not(feature = "native-exec"), allow(dead_code))]
    native_exec_dir: Option<PathBuf>,
    /// Root of the node's microVM material (R605-F8): `<dir>/vmlinux`,
    /// `<dir>/rootfs.ext4`, and `<dir>/vms` for per-guest state. `Some(dir)`
    /// attaches the backend; `None` leaves microVM-marked deploys refused.
    #[cfg_attr(not(feature = "microvm"), allow(dead_code))]
    microvm_dir: Option<PathBuf>,
    /// State dir for the per-tenant passway JIT tier (R852-F1), holding each
    /// cold passway's stdout/stderr capture across forks. `Some(dir)` attaches
    /// the tier; `None` leaves tenant-passway deploys refused.
    #[cfg_attr(not(feature = "tenant-passway"), allow(dead_code))]
    tenant_passway_dir: Option<PathBuf>,
    /// Container range this node addresses workloads out of (R881-T3 / W343),
    /// e.g. `10.128.0.0/9`. `Some(range)` makes a container whose assigned
    /// address falls inside it get a real network namespace — bridge, veth,
    /// address, default route — instead of the empty one runc unshares.
    /// `None` leaves every container isolated and unreachable, which is what
    /// every node did before this flag existed.
    #[cfg_attr(not(feature = "containerd-integration"), allow(dead_code))]
    container_net: Option<String>,
    /// Bridge those veths hang off. Only meaningful with `container_net`.
    #[cfg_attr(not(feature = "containerd-integration"), allow(dead_code))]
    container_bridge: Option<String>,
    /// Path to `turso-backup-hydrate` (R850-F1). `Some(path)` lets a workload
    /// declaring `yah.durability.tier` be restored before it starts; `None`
    /// makes such a deploy fail loudly rather than come up against an empty
    /// volume. Not feature-gated — the engine lives in the helper process, so
    /// this build carries only the path.
    hydrate_helper: Option<PathBuf>,
    /// Path to `turso-backup-tail` (R850-F1). The twin of
    /// [`Args::hydrate_helper`] on the backup side: `Some(path)` keeps a
    /// declaring workload's state shipped to its store while it runs; `None`
    /// makes such a deploy fail loudly rather than run with nothing shipping.
    tail_helper: Option<PathBuf>,
}

fn parse_args() -> std::result::Result<Args, ParseError> {
    let mut socket: PathBuf = std::env::var_os("KAMAJI_SOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    let mut containerd_socket: Option<PathBuf> =
        std::env::var_os("CONTAINERD_SOCK").map(PathBuf::from);
    // R599-F10 bundle-serving config. Secrets are NEVER taken from argv — the R2
    // access key + secret come from the yah keystore (env fallback
    // CF_R2_ACCESS_KEY_ID / CF_R2_SECRET_KEY) via R2ObjectStore::from_vault, and
    // the account id from $CF_ACCOUNT_ID, matching every other R2 call site.
    let mut bundle_cache_dir: Option<PathBuf> =
        std::env::var_os("KAMAJI_BUNDLE_CACHE_DIR").map(PathBuf::from);
    let mut bundle_origin: Option<String> = std::env::var("KAMAJI_BUNDLE_ORIGIN").ok();
    let mut bundle_port: Option<u16> = match std::env::var("KAMAJI_BUNDLE_PORT") {
        Ok(v) => Some(
            v.parse()
                .map_err(|_| ParseError::BadValue("KAMAJI_BUNDLE_PORT"))?,
        ),
        Err(_) => None,
    };

    // R626-F1: docker backend opt-in. `KAMAJI_DOCKER=1` attaches with the
    // ambient DOCKER_HOST; `KAMAJI_DOCKER=<host>` pins a daemon. Deliberately
    // NOT keyed off a bare `$DOCKER_HOST` — nearly every dev host sets that,
    // and a supervisor must not adopt a daemon nobody asked it to supervise.
    let mut docker_host: Option<String> = match std::env::var("KAMAJI_DOCKER") {
        Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") => None,
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") => Some(String::new()),
        Ok(v) => Some(v),
        Err(_) => None,
    };

    // R577-T1: native fork+exec backend opt-in, same explicit-opt-in discipline
    // as --docker. A supervisor must not start forking host processes because
    // some ambient variable happened to be set.
    let mut native_exec_dir: Option<PathBuf> =
        std::env::var_os("KAMAJI_NATIVE_EXEC_DIR").map(PathBuf::from);

    // R605-F8: microVM backend opt-in, same discipline again.
    let mut microvm_dir: Option<PathBuf> = std::env::var_os("KAMAJI_MICROVM_DIR").map(PathBuf::from);

    // R852-F1: per-tenant passway tier opt-in. Same discipline once more — a
    // node that is not a public front door must not start binding tenant
    // sockets because a variable was inherited.
    let mut tenant_passway_dir: Option<PathBuf> =
        std::env::var_os("KAMAJI_TENANT_PASSWAY_DIR").map(PathBuf::from);

    // R850-F1: hydrate-on-place helper. Inheriting this from the environment is
    // safe in a way the backend opt-ins above are not — pointing at the helper
    // grants no capability by itself, since nothing runs unless a workload
    // *declares* a durability tier.
    let mut hydrate_helper: Option<PathBuf> =
        std::env::var_os("KAMAJI_HYDRATE_HELPER").map(PathBuf::from);
    let mut tail_helper: Option<PathBuf> =
        std::env::var_os("KAMAJI_TAIL_HELPER").map(PathBuf::from);

    // R881-T3: container networking opt-in, same explicit-opt-in discipline as
    // the backends above. A supervisor must not start creating bridges and NAT
    // rules on a node because a variable happened to be inherited.
    let mut container_net: Option<String> = std::env::var("KAMAJI_CONTAINER_NET").ok();
    let mut container_bridge: Option<String> = std::env::var("KAMAJI_CONTAINER_BRIDGE").ok();

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--socket" | "-s" => {
                socket = iter
                    .next()
                    .map(PathBuf::from)
                    .ok_or(ParseError::MissingValue("--socket"))?;
            }
            "--containerd-socket" => {
                containerd_socket = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--containerd-socket"))?,
                );
            }
            "--bundle-cache-dir" => {
                bundle_cache_dir = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--bundle-cache-dir"))?,
                );
            }
            "--bundle-origin" => {
                bundle_origin = Some(
                    iter.next()
                        .ok_or(ParseError::MissingValue("--bundle-origin"))?,
                );
            }
            "--bundle-port" => {
                bundle_port = Some(
                    iter.next()
                        .ok_or(ParseError::MissingValue("--bundle-port"))?
                        .parse()
                        .map_err(|_| ParseError::BadValue("--bundle-port"))?,
                );
            }
            "--native-exec-dir" => {
                native_exec_dir = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--native-exec-dir"))?,
                );
            }
            "--microvm-dir" => {
                microvm_dir = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--microvm-dir"))?,
                );
            }
            "--tenant-passway-dir" => {
                tenant_passway_dir = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--tenant-passway-dir"))?,
                );
            }
            "--hydrate-helper" => {
                hydrate_helper = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--hydrate-helper"))?,
                );
            }
            "--tail-helper" => {
                tail_helper = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--tail-helper"))?,
                );
            }
            "--container-net" => {
                container_net = Some(
                    iter.next()
                        .ok_or(ParseError::MissingValue("--container-net"))?,
                );
            }
            "--container-bridge" => {
                container_bridge = Some(
                    iter.next()
                        .ok_or(ParseError::MissingValue("--container-bridge"))?,
                );
            }
            // Bare `--docker` inherits DOCKER_HOST; `--docker-host URL` pins one.
            "--docker" => docker_host = Some(String::new()),
            "--docker-host" => {
                docker_host = Some(
                    iter.next()
                        .ok_or(ParseError::MissingValue("--docker-host"))?,
                );
            }
            "--help" | "-h" => return Err(ParseError::HelpRequested),
            "--version" | "-V" => return Err(ParseError::VersionRequested),
            other => return Err(ParseError::Unknown(other.to_string())),
        }
    }
    Ok(Args {
        socket,
        containerd_socket,
        bundle_cache_dir,
        bundle_origin,
        bundle_port,
        docker_host,
        native_exec_dir,
        microvm_dir,
        tenant_passway_dir,
        hydrate_helper,
        tail_helper,
        container_net,
        container_bridge,
    })
}

enum ParseError {
    MissingValue(&'static str),
    BadValue(&'static str),
    Unknown(String),
    HelpRequested,
    VersionRequested,
}

fn print_help() {
    println!("{ABOUT}");
    println!();
    println!(
        "Usage: kamaji [--socket PATH] [--containerd-socket PATH] [--docker | --docker-host URL]\n              \
         [--native-exec-dir PATH] [--microvm-dir PATH]\n              \
         [--tenant-passway-dir PATH] [--hydrate-helper PATH] [--tail-helper PATH]\n              \
         [--container-net CIDR] [--container-bridge NAME]\n              \
         [--bundle-cache-dir PATH] [--bundle-origin URL] [--bundle-port PORT]"
    );
    println!();
    println!("Options:");
    println!(
        "  -s, --socket PATH         UDS path to bind (default: ${{KAMAJI_SOCK:-{DEFAULT_SOCKET}}})"
    );
    println!("      --containerd-socket PATH  containerd UDS to dispatch Container workloads to");
    println!("                                (default: $CONTAINERD_SOCK, else container deploys are refused)");
    println!("      --docker                  supervise Container workloads on a Docker-compatible");
    println!("                                daemon (OrbStack, dockerd, podman) using the ambient");
    println!("                                $DOCKER_HOST (default: off; $KAMAJI_DOCKER=1 also enables)");
    println!("      --docker-host URL         as --docker, against an explicit daemon, e.g.");
    println!("                                unix:///var/run/docker.sock");
    println!("      --native-exec-dir PATH    supervise Container workloads marked");
    println!("                                `yah.exec = native` by forking them on this host's");
    println!("                                own userland, capturing logs under PATH. Needed by");
    println!("                                Darwin build-workers: no container can run");
    println!("                                cargo-tauri/codesign/notarytool (default:");
    println!("                                $KAMAJI_NATIVE_EXEC_DIR, else such deploys are refused)");
    println!("      --microvm-dir PATH        supervise Container workloads marked");
    println!("                                `yah.exec = microvm` by booting each one in its own");
    println!("                                KVM guest. PATH holds the guest kernel (vmlinux),");
    println!("                                the guest rootfs (rootfs.ext4) and per-guest state.");
    println!("                                Needs /dev/kvm openable by this user and");
    println!("                                CAP_NET_ADMIN for guest networking (default:");
    println!("                                $KAMAJI_MICROVM_DIR, else such deploys are refused)");
    println!("      --container-net CIDR      give each container an address out of CIDR on its own");
    println!("                                network namespace — bridge, veth pair, default route,");
    println!("                                egress NAT. yubaba allocates the address; this node");
    println!("                                only wires it. Needs CAP_NET_ADMIN. Without it a");
    println!("                                container gets the empty namespace runc unshares and is");
    println!("                                reachable from nothing (default: $KAMAJI_CONTAINER_NET;");
    println!("                                the fleet's range is 10.128.0.0/9, see W343)");
    println!("      --container-bridge NAME   bridge those veths hang off (default:");
    println!("                                $KAMAJI_CONTAINER_BRIDGE, else yah0)");
    println!("      --hydrate-helper PATH     restore a workload's named volume from its declared");
    println!("                                yah.durability.store before starting it, by running");
    println!("                                the turso-backup-hydrate binary at PATH (default:");
    println!("                                $KAMAJI_HYDRATE_HELPER; without one, a workload that");
    println!("                                declares a durability tier is REFUSED rather than");
    println!("                                started against an empty volume)");
    println!("      --tail-helper PATH        keep a declaring workload's state shipped to its");
    println!("                                yah.durability.store while it runs, by supervising");
    println!("                                the turso-backup-tail binary at PATH (default:");
    println!("                                $KAMAJI_TAIL_HELPER; without one, a workload that");
    println!("                                declares a durability tier is REFUSED rather than");
    println!("                                run with nothing shipping its state). A tail that");
    println!("                                reports it has been FENCED stops its workload.");
    println!("      --tenant-passway-dir PATH  hold one TLS listen socket per enrolled custom");
    println!("                                domain and fork a cold `passway` on the first");
    println!("                                connection, capturing logs under PATH. This is the");
    println!("                                free-tier front door: 10k idle domains cost 10k held");
    println!("                                fds, not 10k processes (default:");
    println!("                                $KAMAJI_TENANT_PASSWAY_DIR, else such deploys are refused)");
    println!("      --bundle-cache-dir PATH   node bundle root for serving published W272 mesofact");
    println!("                                bundles: <root>/bundles, <root>/runtimes, <root>/state");
    println!("                                (default: $KAMAJI_BUNDLE_CACHE_DIR, else serve-bundle");
    println!("                                deploys are refused)");
    println!("      --bundle-origin URL       public HTTPS origin serving the published bundle");
    println!("                                store, e.g. https://cdn.yah.dev — unauthenticated;");
    println!("                                blobs are content-addressed and digest-verified");
    println!("                                (default: $KAMAJI_BUNDLE_ORIGIN; required with");
    println!("                                --bundle-cache-dir)");
    println!("      --bundle-port PORT        DEPRECATED node-wide port pin (R844-F14). Ports are");
    println!("                                allocated per bundle and published; a pin here is");
    println!("                                REFUSED at deploy, naming the port, rather than");
    println!(
        "                                aiming every bundle on this node at one slot{}",
        bundle_port_default_str()
    );
    println!("  -h, --help                Print this message and exit");
    println!("  -V, --version             Print version and exit");
    println!();
    println!("Bundle-serving R2 credentials are read from the yah keystore (slots");
    println!("cloudflare-r2-access-key-id / cloudflare-r2-secret-key, env fallback");
    println!("CF_R2_ACCESS_KEY_ID / CF_R2_SECRET_KEY) plus $CF_ACCOUNT_ID — never from argv.");
}

/// Ceiling on guest RAM for this node, in MiB (R605-F8).
///
/// A microVM's memory is a real allocation, not a cgroup ceiling, so this
/// number is the difference between "a build runs isolated" and "the node
/// starts swapping under a raft voter" — which is precisely the outcome W325's
/// whole isolation argument exists to prevent.
///
/// Half of `MemTotal` by default. Half rather than most-of because the node is
/// not idle: on the fleet's OVH boxes it is simultaneously a raft voter and a
/// yubaba, and this backend's promise is that a guest shares a node *safely*.
/// `$KAMAJI_MICROVM_MAX_MEMORY_MB` overrides it for a dedicated build worker
/// where that reasoning does not apply.
///
/// Read from `/proc/meminfo` rather than a Rust dependency: one file, one line,
/// and the alternative is a crate in the supervisor's tree for a number this
/// process reads exactly once at startup.
#[cfg(feature = "microvm")]
fn microvm_memory_cap_mb() -> u32 {
    const FLOOR_MB: u32 = 2048;

    if let Some(explicit) = std::env::var("KAMAJI_MICROVM_MAX_MEMORY_MB")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v > 0)
    {
        return explicit;
    }

    let total_kb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.split_whitespace().next().and_then(|n| n.parse::<u64>().ok()))
        })
        .unwrap_or(0);

    let half_mb = (total_kb / 1024 / 2) as u32;
    // The floor wins on a host whose /proc is unreadable *or* genuinely tiny.
    // Both cases end the same way — `MicroVmRuntime` refuses any workload
    // requesting more than the cap, with a message naming both numbers — so
    // guessing high here does not risk an over-committed guest.
    half_mb.max(FLOOR_MB)
}

/// Suffix for the `--bundle-port` help line: names the historical testbed port
/// (R844-F2 stopped applying it as a silent default; R844-F14 stopped honouring
/// it when asked for), or a note that this build can't serve bundles at all.
fn bundle_port_default_str() -> String {
    #[cfg(feature = "bundle-serving")]
    {
        format!(
            " (the pre-R844 single-bundle testbed shape was {})",
            kamaji_bin::DEFAULT_BUNDLE_PORT
        )
    }
    #[cfg(not(feature = "bundle-serving"))]
    {
        " (n/a — built without --features bundle-serving)".to_string()
    }
}

fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = match parse_args() {
        Ok(a) => a,
        Err(ParseError::HelpRequested) => {
            print_help();
            return Ok(());
        }
        Err(ParseError::VersionRequested) => {
            // The stamped const, not CARGO_PKG_VERSION — a hot-shipped binary
            // must not print a published release's version. (`--version` is
            // still never a PROOF of what code is in the binary; the roll path
            // proves by sha256. This only stops it actively lying.)
            println!("kamaji {}", kamaji_bin::server::CONSTABLE_VERSION);
            return Ok(());
        }
        Err(ParseError::MissingValue(flag)) => {
            anyhow::bail!("flag {flag} requires a value");
        }
        Err(ParseError::BadValue(flag)) => {
            anyhow::bail!("{flag} has an invalid value");
        }
        Err(ParseError::Unknown(arg)) => {
            anyhow::bail!("unknown argument: {arg}");
        }
    };

    // R555-F4 / W235 §(c): say the admission posture out loud at startup.
    //
    // `workload_spec::admission::check` resolves this lazily and caches it, so
    // without this line the first evidence a node gives of what it enforces is
    // a refusal — or, worse, a silence that looks identical whether the
    // operator's `YAH_ADMISSION` took effect or was ignored. That "did my
    // security control turn on?" question is the one this module's typo-fails-
    // closed rule already exists to answer; answering it before anything is
    // dispatched costs one line.
    let admission = workload_spec::admission::NodeAdmission::from_env();
    tracing::info!(
        policy = ?admission.policy,
        pinned_keys = admission.trusted_keys.len(),
        policy_env = workload_spec::admission::POLICY_ENV,
        keys_env = workload_spec::admission::KEYS_ENV,
        "signed-recipe admission posture (W235 §(c))"
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let ctx = build_ctx(&args).await?;
        // R755-B5: bring back every bundle the previous kamaji was serving
        // BEFORE the socket answers, so a control-plane roll is a restart of
        // the node's sites and not an undeploy of them.
        #[cfg(feature = "bundle-serving")]
        {
            let n = ctx.resume_bundle_workloads().await;
            tracing::info!(resumed = n, "recorded bundle deploys replayed (R755-B5)");
        }
        kamaji_bin::serve_with_ctx(&args.socket, ctx, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    })
}

/// Assemble the [`kamaji_bin::ServerCtx`]. Attaches a containerd backend when
/// the operator passed `--containerd-socket` (or set `CONTAINERD_SOCK`) and
/// the binary was built with `--features containerd-integration`, and the
/// keep-alive mesofact bundle backend when they passed `--bundle-cache-dir`
/// (or set `KAMAJI_BUNDLE_CACHE_DIR`) and it was built with
/// `--features bundle-serving`. Failures here are fatal — if the operator asked
/// for a backend, missing it means those deploys would silently refuse and that
/// should surface at startup, not on the first deploy.
///
/// The log sink is the journald datagram socket (R406-T10). On hosts
/// without journald reachable, [`kamaji_bin::JournalSender::connect`] falls
/// back to tracing — see `crate::journal` for the fallback path.
async fn build_ctx(args: &Args) -> Result<Arc<kamaji_bin::ServerCtx>> {
    let log_sink: std::sync::Arc<dyn kamaji_bin::LogSink> =
        std::sync::Arc::new(kamaji_bin::JournalSender::connect());
    #[allow(unused_mut)]
    let mut ctx = kamaji_bin::ServerCtx::new().with_log_sink(log_sink.clone());

    // ── containerd backend ───────────────────────────────────────────────────
    #[cfg(feature = "containerd-integration")]
    {
        ctx = if let Some(sock) = &args.containerd_socket {
            let backend = kamaji_bin::containerd::ContainerdBackend::connect_at(sock)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("failed to connect to containerd at {}: {e}", sock.display())
                })?
                .with_log_sink(log_sink);
            tracing::info!(
                socket = %sock.display(),
                "containerd backend attached"
            );
            ctx.with_containerd(std::sync::Arc::new(backend))
        } else {
            tracing::warn!(
                "no --containerd-socket; Deploy {{ Container }} will refuse with BackendRefused. \
                 Pass --containerd-socket /run/containerd/containerd.sock for the production path."
            );
            ctx
        };
    }
    #[cfg(not(feature = "containerd-integration"))]
    if args.containerd_socket.is_some() {
        anyhow::bail!(
            "--containerd-socket requires the kamaji binary be built with \
             --features containerd-integration"
        );
    }

    // ── container networking (R881-T3 / W343) ────────────────────────────────
    // A malformed range fails startup rather than degrading to "no container
    // networking": an operator who passed --container-net asked for reachable
    // workloads, and silently serving unreachable ones is the failure mode this
    // whole relay exists to remove.
    #[cfg(feature = "containerd-integration")]
    if let Some(range) = &args.container_net {
        let range = kamaji::container_net::Ipv4Cidr::parse(range)
            .map_err(|e| anyhow::anyhow!("--container-net: {e:#}"))?;
        let bridge = args
            .container_bridge
            .clone()
            .unwrap_or_else(|| kamaji::container_net::DEFAULT_BRIDGE.to_string());
        tracing::info!(%range, %bridge, "container networking enabled");
        ctx = ctx.with_container_net(kamaji::container_net::ContainerNet::new(range, bridge));
    }
    #[cfg(not(feature = "containerd-integration"))]
    if args.container_net.is_some() || args.container_bridge.is_some() {
        anyhow::bail!(
            "--container-net / --container-bridge require the kamaji binary be built with \
             --features containerd-integration"
        );
    }

    // ── docker / OrbStack backend (R626-F1) ──────────────────────────────────
    // The pond / dev-host counterpart to containerd. Attached only on explicit
    // opt-in; when both are attached, containerd serves Container deploys.
    #[cfg(feature = "docker-integration")]
    {
        use kamaji::Kamaji as _;
        ctx = if let Some(host) = &args.docker_host {
            let backend = if host.is_empty() {
                kamaji::docker::DockerRuntime::new()
            } else {
                kamaji::docker::DockerRuntime::with_host(host.clone())
            };
            // Fail at startup, not on the first deploy: an operator who asked
            // for docker should learn immediately that the daemon is unreachable.
            let health = backend.health().await?;
            if !health.ok {
                anyhow::bail!(
                    "docker backend requested but the daemon is unreachable{}{}",
                    if host.is_empty() {
                        " (ambient DOCKER_HOST)".to_string()
                    } else {
                        format!(" at {host}")
                    },
                    health
                        .detail
                        .map(|d| format!(": {d}"))
                        .unwrap_or_default()
                );
            }
            tracing::info!(
                docker_host = if host.is_empty() { "<inherited>" } else { host },
                version = health.version.as_deref().unwrap_or("<unknown>"),
                "docker backend attached"
            );
            ctx.with_docker(backend)
        } else {
            tracing::info!(
                "no --docker; Deploy {{ Container }} will not use a docker daemon. \
                 Pass --docker (or --docker-host URL) to supervise containers on \
                 a Docker-compatible daemon such as OrbStack."
            );
            ctx
        };
    }
    #[cfg(not(feature = "docker-integration"))]
    if args.docker_host.is_some() {
        anyhow::bail!(
            "--docker / --docker-host require the kamaji binary be built with \
             --features docker-integration"
        );
    }

    // ── native fork+exec backend (R577-T1 / W254) ────────────────────────────
    // For container-shaped workloads that cannot run in a container at all —
    // the Darwin build leg. Explicit opt-in: this backend runs argv on the
    // host's own userland with no sandbox, so it must never attach by accident.
    #[cfg(feature = "native-exec")]
    {
        ctx = if let Some(dir) = &args.native_exec_dir {
            std::fs::create_dir_all(dir).map_err(|e| {
                anyhow::anyhow!("creating native-exec state dir {}: {e}", dir.display())
            })?;
            tracing::info!(
                state_dir = %dir.display(),
                "native-exec backend attached; Container workloads marked yah.exec=native \
                 will be forked on this host"
            );
            ctx.with_native_exec(Arc::new(kamaji::native::NativeRuntime::new(dir)))
        } else {
            tracing::debug!(
                "no --native-exec-dir; native-marked Container deploys will be refused"
            );
            ctx
        };
    }
    #[cfg(not(feature = "native-exec"))]
    if args.native_exec_dir.is_some() {
        anyhow::bail!(
            "--native-exec-dir requires the kamaji binary be built with \
             --features native-exec"
        );
    }

    // ── per-tenant passway tier (R852-F1 / W267) ─────────────────────────────
    // One held TLS listen socket per enrolled custom domain, forking a cold
    // `passway` on the first connection. Explicit opt-in like the others: this
    // binds node sockets that a public SNI demux routes real tenant traffic to.
    #[cfg(feature = "tenant-passway")]
    {
        ctx = if let Some(dir) = &args.tenant_passway_dir {
            std::fs::create_dir_all(dir).map_err(|e| {
                anyhow::anyhow!("creating tenant-passway state dir {}: {e}", dir.display())
            })?;
            tracing::info!(
                state_dir = %dir.display(),
                "per-tenant passway tier attached; each enrolled custom domain's TLS backend \
                 socket will be held here and forked on demand"
            );
            ctx.with_tenant_passway(Arc::new(kamaji::jit::JitRuntime::new(dir)))
        } else {
            tracing::debug!("no --tenant-passway-dir; tenant-passway deploys will be refused");
            ctx
        };
    }
    #[cfg(not(feature = "tenant-passway"))]
    if args.tenant_passway_dir.is_some() {
        anyhow::bail!(
            "--tenant-passway-dir requires the kamaji binary be built with \
             --features tenant-passway"
        );
    }

    // ── hydrate-on-place helper (R850-F1) ────────────────────────────────────
    // No feature gate and no `bail!` twin: the database engine lives in the
    // helper process, so every build can carry the path. Refusing a
    // *nonexistent* path at startup is worth it though — the alternative is
    // discovering it at the first appliance deploy, which is exactly the moment
    // an operator has the least appetite for a typo.
    if let Some(helper) = &args.hydrate_helper {
        if !helper.is_file() {
            anyhow::bail!(
                "--hydrate-helper {} is not a file; point it at the turso-backup-hydrate binary",
                helper.display()
            );
        }
        tracing::info!(
            helper = %helper.display(),
            "hydrate-on-place armed; workloads declaring yah.durability.tier will be restored \
             before they start"
        );
        ctx = ctx.with_hydrate_helper(helper.clone());
    } else {
        tracing::debug!(
            "no --hydrate-helper; a workload declaring yah.durability.tier will be refused \
             rather than started against an empty volume"
        );
    }

    // ── durability tail (R850-F1) ────────────────────────────────────────────
    // Same shape and same startup file check as the hydrate helper above. The
    // two are separate flags rather than one bindir because a node can
    // legitimately be able to restore and not to stream — a migration target
    // being prepared is exactly that — and collapsing them makes that state
    // unexpressible.
    if let Some(helper) = &args.tail_helper {
        if !helper.is_file() {
            anyhow::bail!(
                "--tail-helper {} is not a file; point it at the turso-backup-tail binary",
                helper.display()
            );
        }
        tracing::info!(
            helper = %helper.display(),
            "durability tail armed; workloads declaring yah.durability.tier will have their \
             state shipped while they run, and will be STOPPED if their tail is fenced"
        );
        ctx = ctx.with_tail_helper(helper.clone());
    } else {
        tracing::debug!(
            "no --tail-helper; a workload declaring yah.durability.tier will be refused rather \
             than run with nothing shipping its state"
        );
    }

    // ── microVM backend (R605-F8 / W325 §5) ──────────────────────────────────
    // For workloads that must not share the host kernel — a build placed next
    // to a raft voter. Explicit opt-in like the others, but the flag alone is
    // not enough: `MicroVmRuntime::new` refuses unless the node actually has a
    // guest kernel and rootfs staged, and that refusal is fatal here rather
    // than a warning. A node that was *told* to serve microVM workloads and
    // silently could not would win placements it cannot honour, and every build
    // routed to it would fail at deploy — noisily, but on the wrong node's
    // ticket. Failing to start puts the error where the misconfiguration is.
    #[cfg(feature = "microvm")]
    {
        ctx = if let Some(dir) = &args.microvm_dir {
            let state_dir = dir.join("vms");
            std::fs::create_dir_all(&state_dir).map_err(|e| {
                anyhow::anyhow!("creating microVM state dir {}: {e}", state_dir.display())
            })?;
            let cfg = kamaji::microvm::MicroVmConfig {
                // Located, not assumed. R605-F22: this was
                // `/usr/bin/firecracker`, and Firecracker ships no Debian
                // package — every install on this fleet is a tarball into
                // /usr/local/bin, so the constant was wrong on the only node
                // that has guest artifacts staged. `MicroVmRuntime::new`
                // refuses an absent vmm_bin, so kamaji would not have started.
                vmm_bin: kamaji::microvm::find_vmm()?,
                kernel_image: dir.join("vmlinux"),
                rootfs_image: dir.join("rootfs.ext4"),
                // R605-F23: present iff the operator staged one, with no second
                // flag to forget. A node without it boots guests that can run
                // programs but not compile them, which is exactly what the
                // minimal busybox rootfs meant before this existed.
                toolchain_image: Some(dir.join(kamaji::microvm::TOOLCHAIN_IMAGE_FILE))
                    .filter(|p| p.exists()),
                state_dir,
                // Discovered from the host's routing table, not assumed.
                // R605-F22: this was `GuestNetwork::default()`, whose uplink was
                // the literal `eth0` — a name Debian has not used since
                // predictable interface naming, so the MASQUERADE rule named a
                // device that does not exist and every networked guest deploy
                // failed. A node with no default route gets no guest network at
                // all rather than a broken one; it can still run air-gapped
                // jobs, which is the honest description of what it can do.
                network: match kamaji::microvm::GuestNetwork::discover() {
                    Ok(net) => {
                        tracing::info!(uplink = %net.uplink, "microVM guest networking");
                        Some(net)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "microVM guests will be air-gapped");
                        None
                    }
                },
                max_guest_memory_mb: microvm_memory_cap_mb(),
                max_guest_vcpus: std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(1),
            };
            let runtime = kamaji::microvm::MicroVmRuntime::new(cfg)?;
            tracing::info!(
                microvm_dir = %dir.display(),
                "microVM backend attached; Container workloads marked yah.exec=microvm \
                 will be booted in their own KVM guest"
            );
            ctx.with_microvm(Arc::new(runtime))
        } else {
            tracing::debug!("no --microvm-dir; microVM-marked Container deploys will be refused");
            ctx
        };
    }
    #[cfg(not(feature = "microvm"))]
    if args.microvm_dir.is_some() {
        anyhow::bail!("--microvm-dir requires the kamaji binary be built with --features microvm");
    }

    // ── keep-alive mesofact bundle backend (R599-F10) ────────────────────────
    #[cfg(feature = "bundle-serving")]
    {
        ctx = attach_bundle_backend(ctx, args).await?;
    }
    #[cfg(not(feature = "bundle-serving"))]
    if args.bundle_cache_dir.is_some() || args.bundle_origin.is_some() {
        anyhow::bail!(
            "--bundle-cache-dir / --bundle-origin require the kamaji binary be built with \
             --features bundle-serving"
        );
    }

    Ok(Arc::new(ctx))
}

/// Attach the R599-F10 bundle backend when the node is configured for it.
///
/// Requires `--bundle-cache-dir` (the node bundle root) plus `--bundle-origin`,
/// the public HTTPS origin serving the published bundle store.
///
/// **The node holds no credentials** (R599-T5). The read leg of a
/// content-addressed store does not need one: `materialize_bundle` verifies the
/// manifest hashes to the requested digest and that every blob hashes to its
/// recorded blake3, so integrity comes from the content address rather than the
/// transport — a hostile origin cannot inject bytes. Authentication would buy
/// only confidentiality, which published bundles do not need, at the cost of a
/// write-capable secret on every box in the fleet. Publishing stays on the
/// publisher via the credentialed `R2ObjectStore`. See
/// [`HttpReadOnlyObjectStore`] for the full rationale.
///
/// With no cache dir configured this warns and leaves `ctx.bundle = None`, so a
/// serve-bundle deploy keeps returning the existing `BackendRefused`.
///
/// [`HttpReadOnlyObjectStore`]: yah_object_store::HttpReadOnlyObjectStore
///
/// @yah:ticket(R870-T9, "Roll the R870-B6 per-workload bundle origin onto the fleet, then enable it in noisetable's mirror")
/// @yah:status(review)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:at(2026-09-09T05:08:43Z)
/// @yah:parent(R870)
/// @yah:next("yah-marketing NEEDS NO EDIT AND MUST NOT GET ONE — that is the regression control. It declares no `origin`, `store_for(None)` returns the node's own store unwrapped (asserted by Arc::ptr_eq in `an_undeclared_origin_resolves_to_the_node_store_unchanged`), and the spec it sends is byte-identical to before.")
/// @yah:verify("The runtime-asset half on the live node: noisetable publishes NO mesofact/0.8.32 asset into its own bucket, so the node must read through to cdn.yah.dev for it. A deploy that comes up proves the read-through; `ls /var/lib/yah/kamaji/bundles/runtimes/mesofact/0.8.32/` on us-east-001 shows the asset it resolved.")
/// @yah:gotcha("R870-B6 LANDED THE MECHANISM IN SOURCE ONLY. `MesofactServeBundle.origin` is threaded publisher-side (BundleSlot::parse -> serve_bundle) and consumed node-side (BundleBackend::store_for -> FallbackObjectStore), with unit + end-to-end tests green in-tree. NOTHING ON THE FLEET RUNS IT YET: us-east-001's kamaji is the binary that was rolled before this change, so it still ignores the field and still fetches every workload from KAMAJI_BUNDLE_ORIGIN. Until the roll, noisetable's deploy fails exactly as it does today, and it fails the same way whether or not the mirror declares an origin.")
/// @yah:depends_on(R870-B6)
/// @yah:next("STEP 1, THE ROLL: build the musl kamaji carrying R870-B6 and roll it onto us-east-001 (the node placing `noisetable`), then us-south-001/us-west-* on the fleet's normal cadence. Only kamaji has to move — the yubaba half of the change is publisher-side, and the CLI is what renders the spec. Order does not bite either way: `origin` rides in JSON to yubaba, `MesofactServeBundle` carries no `deny_unknown_fields`, so an un-rolled node ignores the field rather than failing to parse it.")
/// @yah:next("STEP 2, ONE LINE IN THE OTHER CAMP: add `origin = \"https://cdn.noisetable.com\"` under `[providers.bundle]` in ~/ss/noisetable/.yah/services/noisetable-marketing/mirrors/cloud.toml, beside the existing `bucket = \"noisetable-marketing\"`. That file already carries a long comment block naming R870-B6 as the reason it cannot deploy — replace it with the declaration. `bucket` stays as it is; the origin is the public R2 custom domain bound to it, which the `[providers.static]` slot in the same file already names in its `asset_origin`. Then `yah cloud apply --service noisetable-marketing --env cloud` reaches Running rather than Failed, and https://noisetable.com/ serves the site instead of the R870-F5 holding page.")
/// @yah:handoff("ROLLED: kamaji + yubaba (both carrying R870-B6) hot-shipped onto all 3 PROD raft voters — us-east-001, us-south-001, us-west-001 (qed hotship runs d3ba58af/705f9470/987dc280, all success). DEV sovereign group (us-west-011/013/014) and non-voters us-west-002/003 were NOT rolled — see gotcha.")
/// @yah:handoff("STEP 2 DONE: added `origin = \"https://cdn.noisetable.com\"` under [providers.bundle] in ~/ss/noisetable/.yah/services/noisetable-marketing/mirrors/cloud.toml, replacing the R870-B6-blocked comment block with a resolved note. bucket/name/machines/etc unchanged.")
/// @yah:handoff("DISCOVERED FIX 1: scripts/hotship.sh machine_field() required exactly one space around '=' (`^$2 = `); several machine TOMLs (us-west-002/003/011/013/014) column-align fields with extra spaces, so node_arch/node_ssh silently returned empty and triple_for died 'unknown arch for <node>:'. Fixed to `^$2[[:space:]]*= ` — uncommitted in scripts/hotship.sh, needs review/commit alongside the operator's own in-flight hotship.sh edits (file was being actively co-developed live during this session).")
/// @yah:handoff("DISCOVERED FIX 2, THE ACTUAL BLOCKER: ticket's premise 'only kamaji has to move' is wrong for a live deploy attempt. MesofactServeBundle.origin travels CLI->yubaba as JSON (fine, tolerant), but yubaba then re-encodes to POSTCARD for its kamaji IPC, which is positional/non-self-describing. An old yubaba binary (pre-R870-B6, no origin field) silently drops origin on JSON decode and emits a SHORTER postcard message; a rolled kamaji (with the new field) then fails 'decode failed: postcard error: Hit the end of buffer, expected more data'. Fixed by rolling yubaba alongside kamaji on all 3 PROD voters — confirmed this resolves it: after the yubaba+kamaji roll, noisetable-marketing's bundle was admitted, transitioned Pending->Starting->Running, and https://noisetable.com/ served 200 at least once.")
/// @yah:handoff("VERIFIED: R870-B6's origin mechanism works end-to-end on live infra — the original failure mode (missing blob / postcard decode error) is fully resolved. Runtime-asset read-through confirmed: /var/lib/yah/kamaji/bundles/runtimes/mesofact/0.8.32/x86_64-unknown-linux-musl/.accessed on us-east-001 updated to the exact deploy timestamp (04:10Z), proving the node read through to cdn.yah.dev for the stock runtime it doesn't publish itself. yah.dev (regression control, no origin declared) still serves 200, untouched.")
/// @yah:handoff("Also rebuilt+installed a fresh ~/.local/bin/yah CLI from the working tree (was 0.8.35+08b46e61-dirty, predated the origin field entirely — every `providers.bundle` origin key was rejected as unknown until this rebuild).")
/// @yah:handoff("Tree anchor at handoff: 24d24042d537b453e01d330ac185445398ec74a9 — the shared tree as I left it. Diff against it (`git diff 24d24042d537b453e01d330ac185445398ec74a9..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
/// @yah:next("OPEN ISSUE, likely infra/race not a code defect: https://noisetable.com/.well-known/yah-publish.json is currently STALE at digest 8028ddb4c33f (6 files) while the most recent publish was digest c01c1e9ed270 (25 files); root / flaps between 200 and 404. A SECOND, concurrent `yah cloud apply --service noisetable-marketing --env cloud` process (PID 97749, not launched by this session — likely the operator watching live) was running the entire time alongside this session's own apply and is still alive/idle with no open network connections as of handoff. Strongly suspect the two concurrent applies raced each other's publish+deploy. Do NOT run a third concurrent apply — check whether PID 97749 (or its successor) is still alive first, let it finish or kill it, then re-run `yah cloud apply --service noisetable-marketing --env cloud` from ~/ss/noisetable once, alone, and confirm noisetable.com serves 200 with a matching digest.")
/// @yah:next("Roll the remaining fleet on the normal cadence once reachable: us-west-002 (100.64.0.4) and us-west-011 (100.64.0.10) are both unreachable at the mesh level (curl to :7443/health times out, confirmed independently of the hotship tool) — us-west-011 is a DEV sovereign group raft voter, so that group's raft_healthy() guard correctly refuses to touch us-west-013/014 (its other two voters) while 011 is down. us-west-002/003 (non-voters) share the same fleet-wide raft_healthy check for reasons not fully traced (worth checking whether they're DEV-group learners). Someone needs to look at why us-west-002 and us-west-011 dropped off the mesh before the DEV group or the remaining non-voters can be hot-shipped.")
/// @yah:next("Commit scripts/hotship.sh's machine_field whitespace fix (and reconcile with whatever the operator's own concurrent edits to that file already contain — it was being live-edited during this session; last read showed the fix's comment already preserved in the operator's version).")
/// @yah:gotcha("DEV sovereign group (us-west-011/013/014) was left untouched: us-west-011 is unreachable, so raft_healthy() correctly refused to hot-ship kamaji/yubaba to any DEV-group voter (013, 014) mid-session. Non-voters us-west-002/003 also tripped the same 'raft is not healthy' refusal when queried directly — worth confirming whether they're DEV-group learners or the check is fleet-wide by construction.")
/// @yah:handoff("THE OPEN ISSUE IS CLOSED, AND THE STANDING HYPOTHESIS WAS WRONG. The previous handoff's \"stale yah-publish.json, likely an infra race between two concurrent applies\" is retired: PID 97749 and every other `yah cloud apply` were gone before this session started (checked by ps), and running apply ALONE reproduces the stale digest exactly. The cause is R870-B11. Both components of noisetable-marketing assemble a bundle under the ONE workload name `[providers.bundle].name` gives; the last to reconcile is what the door serves; every earlier component's staged serving check is then structurally guaranteed to fail. Measured: `app` -> 7 entries / beacon 8028ddb4 / 6 files, `site` -> 26 entries / beacon 44c3268c / 25 files, door serving 44c3268c, apply failing on 8028ddb4. The \"6 files\" in the old note was never a stale door — it was the `app` bundle winning the last-writer race on a run ordered the other way. Both R870-B11 and the noisetable mirror now carry that measurement.")
/// @yah:handoff("DISCOVERED FIX A — the escape-hatch message named the wrong TOML block, and it cost a whole apply cycle to find that out. `serving_failure` (oss/yubaba/crates/cloud/src/reconciler/publish_beacon.rs) hardcoded \"set `verify_serving = false` in the mirror's [providers.static] block\", but there are TWO independent verify_serving keys — one per slot — and the failing check here was the BUNDLE arm reading `BundleSlot::verify_serving`. Editing the static block therefore changed nothing and the next apply failed identically. Fixed by deriving the slot from the beacon itself: `PublishBeacon::is_bundle_stamp()` (a bundle stamp is clock-free by construction, `published_at: None`, which the field's own docs already state) and `verify_serving_slot()`, threaded into the message. New test `serving_failure_names_the_block_that_holds_the_knob` asserts both arms name their own block and NOT the other's.")
/// @yah:handoff("DISCOVERED FIX B — hotship.sh's raft floor could never ship a non-voter, and that is why the previous session saw us-west-002/003 \"trip the same raft is not healthy refusal\". It was not fleet-wide by construction and it was not about 011. `raft_healthy()` used `curl -fsS`, which collapses two unrelated states into one exit code: a genuinely short quorum, and a node that runs no raft at all. yubaba answers `/raft/status` with `503 raft not configured (Phase 2 only — start with --raft-node-id)` on every single-node box, and `-f` turned that into exit 22 — so the guard refused to protect a quorum that does not exist there. Now tri-state: 0 = healthy (leader printed), 2 = no raft on this node, 1 = unreachable/unparseable/no-leader/peer-not-live (still fatal). Both call sites updated — the FLOOR-BEFORE gate prints \"raft floor N/A\" and proceeds on 2, and the FLOOR-AFTER rejoin wait accepts 2 instead of burning its full 60s and refusing to continue on a node that was already back.")
/// @yah:handoff("TWO ITEMS FROM THE PREVIOUS HANDOFF WERE ALREADY SETTLED AND NEEDED NO WORK. (1) The `machine_field` whitespace fix is IN HEAD — `grep -m1 -E \"^$2[[:space:]]*= \"` is live at scripts/hotship.sh with its R870-T9 provenance comment intact, and `git diff scripts/hotship.sh` does not contain it, so the operator's sync swept it in. Nothing to reconcile. (2) us-west-002's unreachability is explicitly NOT a finding: its own machine file declares it EPHEMERAL, BUILD-ONLY and spells out \"NOT a rollout target\", \"an unreachable 002 is not a fleet-health finding. Do not open a ticket\". So the only real mesh casualty is us-west-011, filed as R870-B14 — and it turns out 011 is not down at all, just off the mesh.")
/// @yah:handoff("THE REMAINING FLEET ROLL IS DELIBERATELY NOT DONE, and the reason is tool fit rather than a blocker. us-west-013/014 (0.8.34) must roll WITH us-west-011, not without it — they are three voters of one raft group and 011 is unreachable from this camp (R870-B14), so a partial roll leaves a mixed-version group with the member nobody can dial. us-west-003 (0.8.28) and us-west-015 (0.8.20) are single-node non-voters that my raft-floor fix now unblocks, but they are 8 and 16 patch versions behind and want scripts/roll-node.sh: hotship.sh's own header says it ships an ITERATION, unreleased, never written to the CDN, \"to find out whether a change works on real hardware\" — and R870-B6 is not under test on those nodes. Hot-shipping an unreleased build onto a node that far behind swaps a version gap for an unattributable one. The three PROD voters carrying the change (0.8.36-h7) are what R870-T9 actually needed and they are rolled and proven.")
/// @yah:verify("LIVE, END TO END. `yah cloud apply --service noisetable-marketing --env cloud` from ~/ss/noisetable now reports `noisetable-marketing  ok  2 component(s) reconciled` (was FAILED), the bundle reaches Running on us-east-001, and https://noisetable.com/ serves 200 five times out of five with `<title>Noise Table — Distributed Musical Creativity</title>`. https://yah.dev/ still 200 as the untouched regression control. `yah cloud validate` in that camp is clean. `/app/` is 404 — that is R870-B11's documented stopgap, not a regression from this session.")
/// @yah:verify("CODE: `cargo test -p yah-cloud --lib publish_beacon` in oss/yubaba -> 24 passed, 0 failed, including the new `serving_failure_names_the_block_that_holds_the_knob`. SHELL: `bash -n scripts/hotship.sh` clean, shellcheck -S warning clean apart from one pre-existing SC2034 at line 323. The two edited raft-floor blocks were exercised VERBATIM against the live fleet rather than only reasoned about: us-west-013 and us-east-001 -> floor passed (healthy raft), us-west-003 and us-west-015 -> \"raft floor N/A: runs single-node yubaba\" and the rejoin probe returns immediately (both were hard REFUSALS before this change), us-west-011 -> still refused, exit 1, which is correct. `raft_healthy` itself returns 0/2/1 on those same three live states.")
/// @yah:gotcha("NOT VERIFIED, and say so rather than assuming: the full `scripts/hotship.sh --dry-run` path was NOT run against a non-voter. Dry-run still builds the musl binaries first (\"Build, node resolution, reachability and the raft floor all passed\"), and this camp had peers contending on the shared target dir, so the raft-floor blocks were exercised by lifting them verbatim into a harness against the live fleet instead. That covers the logic I changed; it does not cover the surrounding script wiring. Someone rolling us-west-003/015 should expect the floor to pass and should still read its output.")
/// @yah:gotcha("THE publish_beacon.rs FIX IS NOT IN ~/.local/bin/yah, DELIBERATELY. That binary is 0.8.35+09e3f35d-dirty, rebuilt by the previous R870-T9 session because it needed the `origin` field; my change is an error-message correction in a crate the CLI links, and `cargo xtask install` off this tree would sweep in every peer's uncommitted work — git status shows ~30 modified files across yubaba/passway/kamaji/qed from other live sessions — and put it in the operator's PATH. A wrong pointer in an error message is not worth that. Whoever next installs the CLI from a clean-enough tree gets it; until then the apply still prints `[providers.static]` when the bundle arm fails, which is exactly the trap the noisetable mirror's comment block now warns about at the key itself.")
/// @yah:handoff("R870-T9 IS DONE. The R870-B6 per-workload bundle origin is rolled onto the three PROD voters (0.8.36-h7), declared in noisetable's mirror, and proven live: noisetable.com serves its own site through passway from a bundle whose blobs come from cdn.noisetable.com, and yah.dev is untouched. The one thing the previous session left open — the \"stale digest\" — is resolved and was never an infra race. Four files changed this session: scripts/hotship.sh (raft floor tri-state), oss/yubaba/crates/cloud/src/reconciler/publish_beacon.rs (message names the right block, + is_bundle_stamp/verify_serving_slot + test), and in the noisetable camp .yah/services/noisetable-marketing/mirrors/cloud.toml (verify_serving moved to the block that actually reads it, both blocks documented). Three followups filed with their measurements: R870-B12, R870-B13, R870-B14.")
#[cfg(feature = "bundle-serving")]
async fn attach_bundle_backend(
    ctx: kamaji_bin::ServerCtx,
    args: &Args,
) -> Result<kamaji_bin::ServerCtx> {
    use anyhow::Context as _;

    let Some(cache_dir) = args.bundle_cache_dir.clone() else {
        tracing::warn!(
            "no --bundle-cache-dir; Deploy {{ MesofactStatic + serve_bundle }} will refuse with \
             BackendRefused. Pass --bundle-cache-dir /var/lib/yah/kamaji/bundles plus \
             --bundle-origin https://cdn.yah.dev for the production path."
        );
        return Ok(ctx);
    };

    let Some(origin) = args.bundle_origin.clone() else {
        anyhow::bail!(
            "--bundle-cache-dir requires --bundle-origin (or $KAMAJI_BUNDLE_ORIGIN) — the public \
             HTTPS origin serving the published bundle store, e.g. https://cdn.yah.dev"
        );
    };

    // W272 §2: the node cache lives under kamaji's state dir. One root holds
    // materialized bundles (<root>/bundles), stock serve-runtime assets
    // (<root>/runtimes), and the native supervisor's log captures (<root>/state).
    // The cache's LRU eviction only ever scans <root>/bundles, so supervisor
    // state is never evicted out from under a running workload.
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating bundle cache dir {}", cache_dir.display()))?;
    let state_dir = cache_dir.join("state");
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("creating bundle state dir {}", state_dir.display()))?;

    // Like R2ObjectStore, this owns a `reqwest::blocking::Client`, which panics
    // if constructed inside a tokio runtime context — build it on the blocking
    // pool. Same discipline as yubaba's reconciler::bundle_store publish leg.
    let store = tokio::task::spawn_blocking({
        let origin = origin.clone();
        move || yah_object_store::HttpReadOnlyObjectStore::new(origin)
    })
    .await
    .context("bundle-store construction task panicked")?
    .context("building the read-only bundle origin store")?;

    let mut backend =
        kamaji_bin::BundleBackend::new(std::sync::Arc::new(store), &cache_dir, &state_dir);
    if let Some(port) = args.bundle_port {
        backend = backend.with_bind_port(port);
    }
    tracing::info!(
        cache_dir = %cache_dir.display(),
        origin = %origin,
        bind_port = ?backend.bind_port,
        "bundle backend attached (keep-alive serve_bundle workloads; \
         unauthenticated content-addressed origin)"
    );
    Ok(ctx.with_bundle_backend(backend))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kamaji: {e:#}");
            ExitCode::FAILURE
        }
    }
}

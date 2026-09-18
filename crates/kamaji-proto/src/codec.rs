//! @yah:ticket(R590-B3, "kamaji UDS postcard decode fails on ImageRef untagged Deserialize — blocks all container deploys")
//! @yah:status(review)
//! @yah:at(2026-07-03T07:05:47Z)
//! @yah:assignee(agent:claude)
//! @yah:parent(R590)
//! @yah:severity(blocker)
//! @yah:next("ROOT CAUSE: workload_spec::ImageRef has a custom #[serde(untagged)] Deserialize (oss/yah-base/crates/workload-spec/src/lib.rs:1014, added R438-T3 for the string-form 'reg/repo@sha256:...' convenience). Untagged enums require serde deserialize_any, which postcard (non-self-describing) returns Error::WontImplement for. kamaji-proto/src/codec.rs:69 postcard::from_bytes the Workload::Container(spec) over the UDS → dies decoding the nested ImageRef.")
//! @yah:next("FIX OPTION A (narrow, preferred): give the kamaji UDS a postcard-safe Workload DTO — encode ImageRef as its canonical docker_ref string (tag@digest) at the yubaba constable_client boundary + decode back, so the authoring-surface untagged convenience stays but never crosses postcard.")
//! @yah:next("FIX OPTION B (wide): drop ImageRef's untagged Deserialize; keep a plain derived struct Deserialize (postcard-safe) + a separate FromStr for TOML/recipe string-form. Bigger blast radius across recipe/compose authoring.")
//! @yah:next("AFTER THE CODE FIX: the running yubaba+kamaji on us-west-002 is an OLD binary — the fleet must be REDEPLOYED with the fix before the live path goes green (ties into the warden→yubaba on-box redeploy gap).")
//! @yah:next("Repro: cargo test -p yah --lib warden_client::tests::live_deploy_smoke -- --ignored --nocapture (needs the mesh reachable).")
//! @yah:verify("After fix + fleet redeploy: the live_deploy_smoke test deploys busybox to us-west-002 and reaches TERMINAL (not a postcard 500). Then a real forge/build-image workload runs on the node.")
//! @yah:gotcha("Tier: Warrior — clear root cause + two concrete fix options, but touches the yubaba↔kamaji wire boundary (postcard DTO) with real blast-radius; needs careful implementation, not a rote edit.")
//! @yah:gotcha("Surfaced by the R590-F2 live dogfood: deploying a real WorkloadSpec to us-west-002's yubaba returns HTTP 500 'kamaji deploy_workload: kamaji error: Internal: decode failed: postcard error: This is a feature that PostCard will never implement'. R406-T9's original 'smoke' only did curl GET /workloads (empty list) — a real deploy carrying an ImageRef through the postcard UDS was NEVER exercised, so this has been latent since kamaji's Deploy arm landed.")
//! @yah:handoff("DONE (Option 3, operator-chosen), verify-clean. The ticket's root cause was INCOMPLETE: it was not just ImageRef's untagged Deserialize. The whole workload_spec::Workload graph was postcard-decode-incompatible via TWO mechanisms, and a regression test (Workload::Container through postcard) surfaced both:\n(1) INTERNAL serde tagging on Workload + 11 nested enums (EnvValue/SecretRef/SecretTarget/VolumeSource/HealthProbe/RestartPolicy/PublicTls/BuildMode/AlmanacTarget/NotReadyPolicy/Cadence) -> #[serde(tag=...)] forces deserialize_any -> postcard WontImplement.\n(2) ~29 skip_serializing_if attrs -> postcard is positional, so an omitted None/empty field shifts every later field and decode dies with DeserializeBadOption. This one only bites when optionals are None; a full-spec test hid it, a for_forge (real forge deploy) spec exposes it.\nImageRef's untagged Deserialize was a third instance.\n\nFIX (postcard-native end-to-end): flipped all 12 enums to external tagging; stripped all 29 skip_serializing_if (kept #[serde(default)] so hand-authoring can still omit fields; only machine-emitted JSON gains explicit null/[]); ImageRef Deserialize now branches on is_human_readable (string-form in TOML/JSON, plain struct in postcard). Regenerated TS (oss/packages/yah/workload-spec/index.ts) and JSON schema (.yah/schema/workload.toml.schema.json). Migrated every fixture: workload-spec crate (self) + oss/yubaba/cloud (16 reconciler tests, via a Sonnet subagent).\n\nVERIFY (all green): workload-spec full suite (incl. new round_trip postcard tests: full spec + all-None minimal spec + Workload::Container); kamaji-proto codec::deploy_container_round_trip (the exact wire path, was DeserializeBadOption); kamaji full workspace; yubaba --lib (cloud 486 pass); yah-base; schema_drift gate (2 pass). The live_deploy_smoke acceptance still needs the mesh + a FLEET REDEPLOY (old binary on us-west-002) -- the wire decode is proven here; the on-box green is the redeploy step (ties to the warden->yubaba on-box redeploy gap).\n\nNOT-MINE pre-existing blockers found while verifying (each unrelated to this change): oss/qed test build fails on .unwrap() over impl Future (missing .await) in scryer/task_runs; oss/yubaba ServiceComponent missing field 'git' blocks whisper_derive_e2e + mesofact_static_e2e from compiling (whisper's static-asset tagging was migrated but is unverifiable until that lands); root yah lib missing warden_client module file (warden->yubaba rename in flight). None block R590-B3.\n\nCascades: R592-T4 and R592-T5 (depends_on R590-B3) are now unblocked.")
//!
//! @yah:ticket(R896-S1, "Design the evolvable payload: versioned tagged spec section vs reserved extension record")
//! @yah:status(review)
//! @yah:at(2026-09-13T19:51:24Z)
//! @yah:kind(spike)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R896)
//! @yah:next("Tier: Wizard — a wire-format decision the whole fleet rolls on. Time-boxed investigation, outcome is a decision table (diligence shape) not code. Candidates: (a) keep postcard framing, move the WorkloadSpec payload to a self-describing/tagged encoding inside the frame; (b) postcard with an explicit schema_version plus one reserved trailing extension record that old decoders skip; (c) protocol-negotiated dual-decode during rolls only. Evaluate each against: can a single-node hotship cross a field ADDITION; a field DELETION; what R590-B3 (untagged-enum postcard failure) implies about option (a); decode cost on the hot deploy path; and the migration story for moving yah.limits.* / yah.durability.* back into typed fields once the envelope permits it (that migration is this relay's second child, filed after the spike settles the shape). ProtocolVersion already exists (kamaji-proto/src/version.rs) — establish what it currently gates and whether it is the natural carrier before inventing a new one.")
//! @yah:handoff("SETTLED — operator chose (a), the self-describing payload. Decision doc: .yah/docs/working/W349-evolvable-kamaji-wire-envelope.md. Measurement harness checked in at oss/kamaji/crates/kamaji-proto/tests/envelope_spike.rs (3 tests, green) so the evidence cannot rot. HEADLINE: classified all 11 ProtocolVersion bumps — 7 of the last 10 (V2,V4,V5,V6,V8,V9,V11a) are byte-layout accidents a name-keyed codec absorbs; only V3 and V10 are genuine semantic breaks where a handshake refusal is correct; V7 (a retype) downgrades from silent misread to a clean typed error. TWO FINDINGS THE TICKET'S FRAMING MISSED: (1) only 3 of 10 bumps touch WorkloadSpec — FOUR touch kamaji-proto's own message structs (WorkloadEntry x3, NodeCapabilities), so a fix scoped to 'the spec payload' addresses a minority of the pain and the envelope must cover the message structs too; (2) the wire bump is only HALF the cost of a field — the other half is Rust-side, WorkloadSpec has no Default and R860's verify records 35 exhaustive call sites across SIX cargo workspaces (root --workspace cannot see app/yah/desktop or the oss/* workspaces). A wire envelope does nothing for that half. Operator was offered it as option B and chose A only, so it is NOT filed.")
//! @yah:verify("cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji-proto --test envelope_spike -- --nocapture: 3 passed, 0 failed. MEASURED, not argued: old_decoder_vs_a_new_field shows postcard returning a value that was never sent (old decoder read the NEW field's payload as the field it already knew: tail=[\"/etc/app.toml\"] instead of [\"sentinel\"]), while the named codec preserves both directions. Size/cost on a real Deploy(Workload::Container) from WorkloadSpec::for_forge: postcard 209 B / json 809 B (3.9x, 0.08% of MAX_FRAME_BYTES); decode 4022 ns vs 18464 ns per msg — DEBUG BUILD ON A LOADED MACHINE (camp.machine quiet:false, load 30.6/15 cpus, 9 rustc/cargo procs, foreign camp live), so treat the ratio as indicative and the absolutes as contaminated; the byte sizes are exact and load-independent. which_top_level_deletions_a_named_codec_can_cross enumerates the real WorkloadSpec: 25 top-level fields, 16 deletion-crossable (carry a serde default), 9 not (expose, image, name, replicas, resources, restart_policy, schema_version, stop_policy, tier).")
//! @yah:gotcha("THE HANDSHAKE DOC LIES AND THE CODE IS RIGHT: kamaji-proto/src/lib.rs:13-15 says peers exchange Hello/Welcome so 'the receiver picks the highest version it supports that the sender also offers'. It does not — server.rs:1409 refuses any version != ProtocolVersion::CURRENT, exact equality, no negotiation. Every operational note in the tree (hotship.sh, R876's service_records.rs:351) describes the exact-equality behaviour, so the code is the truth and the crate doc is the stale one. Anyone reasoning about roll safety from that doc comment will get it wrong.")
//! @yah:assumes("The rmp-serde/MessagePack row in W349's codec comparison is UNMEASURED — no msgpack crate is in this workspace's lock, so the 'roughly half the bytes' claim is from the format, not from a run here. JSON was recommended over it on zero-new-dependency plus the is_human_readable() convergence (ImageRef string-form and SchemaVersion bare-integer branches light up, making the UDS bytes the same shape as the control plane's JSON), not on a size comparison.")
//!
//! @yah:ticket(R896-F2, "Land the named-payload wire envelope: Tolerant codec, ProtocolVersion V13, digest domain v2")
//! @yah:status(review)
//! @yah:at(2026-09-14T21:02:28Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R896)
//! @yah:next("THE DEFAULTS POLICY, AND THE TENSION W349 UNDERWEIGHTS: a tolerated field must have a default equal to the PRE-FIELD behaviour, or tolerance converts a wire break into a silent semantic skew. But #[serde(default)] on a wire-carried type also loosens the TOML/JSON AUTHORING parse of the same type — defaulting image/name/tier would make a malformed workload.toml parse silently, which is the loudness R658-B1 deliberately bought. Resolve by putting defaults only on fields whose absence is genuinely meaningful and moving required-field enforcement into validate.rs; do NOT blanket-default the 9 fields S1 listed as non-crossable.")
//! @yah:verify("Extend oss/kamaji/crates/kamaji-proto/tests/envelope_spike.rs from local stand-in structs to the REAL types: a Deploy frame encoded with an extra field must decode on a peer that lacks it, with every later field intact. Then the six-workspace sweep R860 names (root --workspace has a blind spot the size of app/yah/desktop and each oss/*): cargo check for root, oss/kamaji, oss/yubaba, oss/yah-base, app/yah/desktop.")
//! @yah:gotcha("SHIPPING THIS IS A PAIRED FLEET SHIP. ProtocolVersion V12 means hotship.sh refuses a lone --binaries yubaba or --binaries kamaji, correctly. Plus one 'redeploy everything once' per node from the digest domain bump. The fleet is already skewed three ways as of 2026-09-11 (tree V11, release v0.8.37 V9, us-east-001 a matched V10 pair) — see R876's gotchas at oss/yubaba/crates/yubaba/src/service_records.rs:351.")
//! @arch:see(.yah/docs/working/W349-evolvable-kamaji-wire-envelope.md)
//! @yah:handoff("MECHANISM LANDED AND PROVEN ON REAL TYPES. New oss/kamaji/crates/kamaji-proto/src/tolerant.rs: a serde `with` module encoding a field as a length-prefixed JSON blob inside the postcard frame, so a decoder matches BY NAME and skips what it does not know. Applied via #[serde(with = \"crate::tolerant\")] to the five accreting payload fields — Deploy.spec, GracefulUpgrade.spec, WorkloadDescription.spec, WorkloadList.entries, CapabilitiesReport.capabilities. ZERO CALL-SITE CHURN: the field types are unchanged, only their encoding, so nothing in kamaji-bin or yubaba needed touching (kamaji + yubaba workspaces both check clean unmodified). serde_json moved from dev-dependency to dependency.")
//! @yah:verify("cargo test -p kamaji-proto (oss/kamaji): 39 lib + 4 integration passed, 0 failed — including every pre-existing round-trip test unmodified (deploy_container_round_trip, deploy_every_workload_variant_round_trips, workload_list_round_trip). cargo test workload-spec: 310 passed, 0 failed. cargo check oss/kamaji --all-targets --all-features: exit 0. cargo check oss/yubaba --all-targets: exit 0 (advisory skew note on that run: a peer touched oss/yubaba/Cargo.lock mid-build, not my change).")
//! @yah:handoff("DISCOVERED WORK, wider than the title — three fixes the envelope forced, each with its reason at the code site. (1) MAX_FRAME_BYTES raised 1 MiB -> 4 MiB (kamaji-proto/src/codec.rs). The encoding got 3.9x bigger and the ceiling did not move with it, and WorkloadSpec::files carries inline file CONTENT — so a workload shipping a few hundred kB of config sat under 1 MiB as postcard and would have crossed it as JSON, i.e. a deploy that used to work failing with FrameTooLarge because of an encoding change rather than anything its author did. Checked nothing else depends on the old value: yubaba's push_dispatch::MAX_FRAME_BYTES (16 KB) is an unrelated constant, and every other 1048576 in the tree is a historical log quote in an annotation. (2) deny_unknown_fields removed from TenantPasswayWorkload and TenantPasswayTls (workload-spec/src/lib.rs) — R658-B1's note that it is \"inert for the postcard kamaji wire\" was TRUE while that wire was positional and stops being true here; both types are wire-carried (TenantPassway is a Workload variant) so the attribute would have refused a peer's added field, defeating the envelope on the workload kind yubaba::tenant_passway reconciles most often. BuildConfig keeps its copy — authoring-only, and its loudness is the point. (3) The crate doc in kamaji-proto/src/lib.rs claimed Hello/Welcome negotiate (\"the receiver picks the highest version it supports that the sender also offers\"). It never did — server.rs refuses anything != CURRENT. Corrected in place, because roll-safety reasoning was being done from that sentence.")
//! @yah:gotcha("ROOT WORKSPACE IS RED, AND IT IS NOT THIS TICKET — attributed, not assumed. `cargo check --workspace --all-targets` exits 101 with exactly two errors, both peer work in flight: (a) crates/yah/cloud-admin/src/lib.rs:1557 missing field `health` in `yah_fleet_metrics::WorkloadEntry` — note that is fleet-metrics' WorkloadEntry, a DIFFERENT type from kamaji-proto's, and this change adds no field to either; (b) crates/yah/agent-tools non-exhaustive match on `YahMcpClass::SandboxedWrite` (R897 territory, @Miravel:spade was running agent-tools tests at the time). Neither touches workload-spec or kamaji-proto, and the build got past both crates' workload-spec dependencies to reach them. My own blast radius is green: oss/kamaji and oss/yubaba both check clean and workload-spec's 310 tests pass.")
//! @yah:verify("Cross-workspace sweep, the six-command radius R860 names. GREEN: oss/kamaji --all-targets --all-features exit 0; oss/yubaba --all-targets exit 0; workload-spec 310 tests exit 0; kamaji-proto 39 lib + 4 integration exit 0 (re-run after the MAX_FRAME_BYTES change). RED, BOTH PRE-EXISTING PEER WORK: root --workspace exit 101 on two errors in crates I never touched (cloud-admin missing `health` on yah_fleet_metrics::WorkloadEntry — a DIFFERENT type from kamaji-proto's; agent-tools non-exhaustive YahMcpClass::SandboxedWrite); app/yah/desktop exit 101 on R895-T2's LegacyServiceConfig deletion. NOT VERIFIED, and the one thing this ticket still owes: the schema regen, blocked on that same R895-T2 breakage (see notify_on).")
//! @yah:gotcha("DESKTOP CHECK IS ALSO RED, ALSO NOT MINE, AND IT IS THE SAME CAUSE AS THE BLOCKED SCHEMA REGEN. `cargo check --manifest-path app/yah/desktop/Cargo.toml --no-default-features` exits 101 on E0432 `unresolved import config::LegacyServiceConfig` (oss/yubaba/crates/cloud/src/lib.rs:284) and E0425 (config.rs:1538) — R895-T2's in-flight deletion of the LegacyServiceConfig compose/Caddy generation, with four test constructors at config.rs:6635/6649/6656/6670 still referring to it. Attributed rather than assumed: nothing I edited mentions LegacyServiceConfig (grep over oss/kamaji + oss/yah-base returns nothing), and `cargo check --manifest-path oss/yubaba/Cargo.toml --all-targets` was exit 0 EARLIER IN THIS SESSION — the breakage appeared between the two runs, i.e. it landed under me. Coordinated directly with @Ashguard:blade (session:7ca0970b), who leads R895.")
//! @yah:handoff("SESSION 2 (session:dc6af742) — both notify_on wakes acted on and removed from source. (1) Deploy.mesh now rides the tolerant envelope too (messages.rs), folded into V13 without a new bump: V13 first committed 2026-09-14 (bae81d65), CDN latest is 0.8.36, v0.8.38 prep carried V11, and hotship's pairing guard means any node running V13 got a matched pair. MeshAssignment wg_private_key/wg_listen_port/peers and WireguardPeer endpoint/allowed_ips gained #[serde(default)] (the no-WireGuard values); mesh_ip and public_key stay required. envelope_spike.rs's DeployFrameMirror wraps mesh to match. (2) Schema regen: workload.toml.schema.json was ALREADY correct in the tree (TenantPasswayTls has no additionalProperties; a sync commit picked it up). `scripts/check-schema-drift.sh --update` wrote one real drift, .yah/schema/qed-pipeline.toml.schema.json, from R906-F1's ManualAudience doc edit, not this ticket.")
//! @yah:handoff("DEFAULTS POLICY RESOLVED as a frozen split, not a blanket default. New oss/kamaji/crates/kamaji-proto/tests/tolerant_field_policy.rs drops each top-level key of every wire-carried struct and freezes the set whose absence fails decode: WorkloadSpec's 9, TenantPasswayWorkload {domain,listen,tls}, TenantPasswayTls {cert,key}, WorkloadEntry {id,state}, NodeCapabilities {microvm,native_exec} (capabilities stay loud on purpose), MicroVmHealth {attached}, MeshAssignment {mesh_ip}, WireguardPeer {public_key}. A field added without deciding its default fails that test, with a message stating the rule. Nothing moved to validate.rs, so the TOML authoring parse is unchanged.")
//! @yah:handoff("STALE DOCS CORRECTED, claims these changes falsified: WorkloadEntry.named_ports said a new field there is always a version bump; NodeCapabilities said adding a field IS a wire break; the Deploy variant doc; the V13 stanza (mesh now wrapped); tolerant.rs's wrapped-struct list; W349's Landed section (item 1 now done). Ticket title V12 -> V13.")
//! @yah:handoff("Remaining relay work filed as children: R896-F3 (annotations -> typed WorkloadSpec fields, the migration W349 names) and R896-T4 (SchemaVersion adopt-or-delete, with a recommendation to delete and the roll hazard).")
//! @yah:verify("cargo test --manifest-path oss/kamaji/Cargo.toml --workspace --all-features --no-fail-fast: EXIT 0, zero failures (kamaji lib 324, kamaji-bin lib 298, kamaji-proto lib 39 + envelope_spike 4 + tolerant_field_policy 5, cheers_mock 18, rest smaller), no skew. The first run without --no-fail-fast hit server::tests::tenant_passway::deploy_arms_the_declared_socket_and_stop_releases_it once: the port TOCTOU flake R895-F1 already recorded, and it passed in the rerun.")
//! @yah:verify("cargo check --manifest-path oss/yubaba/Cargo.toml --workspace --all-targets: EXIT 0, no skew. An earlier run was red only because R895-F3's in-flight tenant-isolation edit to oss/kamaji/crates/kamaji/src/container_net.rs was half-written (tenant_isolation / fnv1a32 / NetnsPlan.bridge); it cleared on its own, and I did not edit that file.")
//! @yah:verify("NOT RUN: root --workspace and app/yah/desktop. This session's code changes are serde attributes plus docs in kamaji-proto, with no type or signature change, and hub/desktop reach MeshAssignment only via kamaji::MeshAssignment::inlined(). Last session's red on both was attributed to peer work.")

use postcard::Error as PostcardError;
use serde::{de::DeserializeOwned, Serialize};

/// Maximum frame payload size the codec accepts.
///
/// UDS control messages are tiny — workload specs are the largest realistic
/// payload and they cap at the low-kB range. This is a generous ceiling that
/// still rejects framing bugs and hostile peers cheaply.
///
/// **Raised 1 MiB → 4 MiB by R896-F2, and the ceiling had to move with the
/// encoding.** The evolvable payload fields now ride name-keyed JSON rather than
/// positional postcard ([`crate::tolerant`]), measured at **3.9×** the bytes for
/// a realistic container spec (209 B → 809 B;
/// `tests/envelope_spike.rs::encoded_size_and_decode_cost`). A typical spec is
/// nowhere near either limit, but `WorkloadSpec::files` carries inline file
/// *content*, so a workload shipping a few hundred kB of config sat comfortably
/// under 1 MiB as postcard and would have crossed it as JSON — a deploy that
/// used to work failing with `FrameTooLarge`, caused by an encoding change
/// rather than by anything the author did. Scaling the ceiling by roughly the
/// same factor keeps the pre-existing margin instead of silently narrowing it.
///
/// This is not a wire-compatibility concern in its own right: the limit is a
/// local sanity check each side applies to what it reads, not a negotiated
/// value. A smaller peer simply refuses sooner, which is the V13 handshake's
/// problem and not this constant's.
pub const MAX_FRAME_BYTES: usize = 4 << 20;

/// Codec error surface.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Postcard refused to encode or decode the payload.
    #[error("postcard error: {0}")]
    Postcard(#[from] PostcardError),
    /// Payload exceeded [`MAX_FRAME_BYTES`].
    #[error("frame too large: {size} > {max}", max = MAX_FRAME_BYTES)]
    FrameTooLarge { size: usize },
    /// Buffer did not contain a complete frame — caller should read more
    /// bytes and retry.
    #[error("frame truncated: need {needed} bytes, have {have}")]
    Truncated { needed: usize, have: usize },
}

/// Encode a message as a length-prefix-framed postcard payload.
///
/// Wire shape: `[u32 LE length][postcard bytes]`. The returned `Vec<u8>` can
/// be handed directly to `tokio::io::AsyncWriteExt::write_all`.
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, Error> {
    let payload = postcard::to_stdvec(msg)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge {
            size: payload.len(),
        });
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Try to decode one frame from the start of `buf`.
///
/// On success returns `(parsed_msg, bytes_consumed)`; the caller should advance
/// its read buffer by `bytes_consumed` and call again to drain additional
/// frames. On [`Error::Truncated`] the caller should read more bytes from the
/// socket and retry — the buffer is otherwise untouched.
pub fn decode_frame<T: DeserializeOwned>(buf: &[u8]) -> Result<(T, usize), Error> {
    if buf.len() < 4 {
        return Err(Error::Truncated {
            needed: 4,
            have: buf.len(),
        });
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&buf[..4]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge { size: len });
    }
    let need = 4 + len;
    if buf.len() < need {
        return Err(Error::Truncated {
            needed: need,
            have: buf.len(),
        });
    }
    let msg = postcard::from_bytes::<T>(&buf[4..need])?;
    Ok((msg, need))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::*;
    use crate::version::ProtocolVersion;

    #[test]
    fn hello_round_trip() {
        let msg = YubabaToKamaji::Hello {
            version: ProtocolVersion::V1,
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, consumed) = decode_frame::<YubabaToKamaji>(&bytes).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn welcome_round_trip() {
        let msg = KamajiToYubaba::Welcome {
            version: ProtocolVersion::V1,
            kamaji_version: "0.0.1".into(),
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<KamajiToYubaba>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn drain_request_round_trip() {
        let msg = YubabaToKamaji::Drain {
            request_id: RequestId(42),
            id: WorkloadId::new("yubaba-1"),
            budget: DrainBudget {
                flush_ms: 5_000,
                checkpoint_ms: 1_000,
            },
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<YubabaToKamaji>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn workload_list_round_trip() {
        let msg = KamajiToYubaba::WorkloadList {
            request_id: RequestId(1),
            entries: vec![
                WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("a"),
                    state: WorkloadState::Running,
                    pid: Some(1234),
                    ports: Vec::new(),
                    named_ports: Default::default(),
                    spec_digest: None,
                },
                WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("b"),
                    state: WorkloadState::Draining,
                    pid: Some(1235),
                    ports: Vec::new(),
                    named_ports: Default::default(),
                    spec_digest: None,
                },
                WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("c"),
                    state: WorkloadState::Pending,
                    pid: None,
                    ports: Vec::new(),
                    named_ports: Default::default(),
                    spec_digest: None,
                },
            ],
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<KamajiToYubaba>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn error_round_trip_with_no_request_id() {
        let msg = KamajiToYubaba::Error {
            request_id: None,
            code: ErrorCode::InvalidSpec,
            message: "missing resources block".into(),
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<KamajiToYubaba>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    /// R590-B3 at the wire boundary: a real `Workload::Container(WorkloadSpec)`
    /// — nested enums (`RestartPolicy`, `ExposeSpec`) plus an `ImageRef` —
    /// crossing the postcard-framed UDS. Before the `workload_spec` graph was
    /// flipped off internal serde tags (`#[serde(tag = ...)]` forces
    /// `deserialize_any`, which postcard rejects), this exact decode died with
    /// `WontImplement` and every container deploy 500'd. The original R406-T9
    /// smoke only listed workloads, so a Deploy carrying a spec was never
    /// exercised over the wire — this guards it.
    #[test]
    fn deploy_container_round_trip() {
        use workload_spec::{ImageRef, TierTag, Workload, WorkloadSpec};
        let spec = WorkloadSpec::for_forge(
            "b3",
            ImageRef {
                registry: "ghcr.io".into(),
                repository: "yah/forge".into(),
                tag: "v1".into(),
                digest: "sha256:abc123".into(),
            },
            TierTag("private".into()),
            vec![8080],
        );
        let msg = YubabaToKamaji::Deploy {
            request_id: RequestId(7),
            id: WorkloadId::new("forge-b3"),
            spec: Workload::container(spec),
            mesh: None,
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, consumed) = decode_frame::<YubabaToKamaji>(&bytes).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn graceful_upgrade_round_trip() {
        use workload_spec::{ImageRef, TierTag, Workload, WorkloadSpec};
        let spec = WorkloadSpec::for_forge(
            "b3",
            ImageRef {
                registry: "ghcr.io".into(),
                repository: "yah/passway".into(),
                tag: "v1".into(),
                digest: "sha256:abc123".into(),
            },
            TierTag("infra".into()),
            vec![443],
        );
        // Request (R600-F9): the GracefulUpgrade variant is appended last, so
        // this also guards that adding it didn't shift the other variants' wire
        // discriminants (Deploy above still round-trips).
        let msg = YubabaToKamaji::GracefulUpgrade {
            request_id: RequestId(9),
            id: WorkloadId::new("passway-ingress"),
            spec: Workload::container(spec),
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, consumed) = decode_frame::<YubabaToKamaji>(&bytes).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(consumed, bytes.len());

        // Ack.
        let ack = KamajiToYubaba::Ack {
            request_id: RequestId(9),
            kind: AckKind::GracefulUpgrade,
        };
        let bytes = encode_frame(&ack).unwrap();
        let (decoded, _) = decode_frame::<KamajiToYubaba>(&bytes).unwrap();
        assert_eq!(decoded, ack);
    }

    #[test]
    fn exit_status_variants_round_trip() {
        for exit in [
            ExitStatus::Exited(0),
            ExitStatus::Exited(137),
            ExitStatus::Signaled(15),
            ExitStatus::DrainTimeout,
        ] {
            let msg = KamajiToYubaba::WorkloadExited {
                id: WorkloadId::new("w"),
                exit,
            };
            let bytes = encode_frame(&msg).unwrap();
            let (decoded, _) = decode_frame::<KamajiToYubaba>(&bytes).unwrap();
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn probe_unhealthy_round_trip() {
        let msg = KamajiToYubaba::ProbeResult {
            request_id: RequestId(9),
            id: WorkloadId::new("w"),
            status: ProbeStatus::Unhealthy {
                reason: "db connection lost".into(),
            },
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<KamajiToYubaba>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn truncated_at_length_prefix_reports_need_4() {
        let err = decode_frame::<YubabaToKamaji>(&[0, 0]).unwrap_err();
        match err {
            Error::Truncated { needed, have } => {
                assert_eq!(needed, 4);
                assert_eq!(have, 2);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn truncated_inside_payload_reports_full_need() {
        let msg = YubabaToKamaji::Stop {
            request_id: RequestId(1),
            id: WorkloadId::new("yubaba-1"),
        };
        let bytes = encode_frame(&msg).unwrap();
        let partial = &bytes[..bytes.len() - 1];
        let err = decode_frame::<YubabaToKamaji>(partial).unwrap_err();
        match err {
            Error::Truncated { needed, have } => {
                assert_eq!(needed, bytes.len());
                assert_eq!(have, partial.len());
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn multiple_frames_in_one_buffer_decode_independently() {
        let m1 = YubabaToKamaji::Hello {
            version: ProtocolVersion::V1,
        };
        let m2 = YubabaToKamaji::Stop {
            request_id: RequestId(7),
            id: WorkloadId::new("w-7"),
        };
        let mut buf = Vec::new();
        buf.extend(encode_frame(&m1).unwrap());
        buf.extend(encode_frame(&m2).unwrap());

        let (d1, consumed) = decode_frame::<YubabaToKamaji>(&buf).unwrap();
        assert_eq!(d1, m1);
        let (d2, _) = decode_frame::<YubabaToKamaji>(&buf[consumed..]).unwrap();
        assert_eq!(d2, m2);
    }

    #[test]
    fn oversized_length_prefix_is_rejected_before_allocation() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_FRAME_BYTES as u32) + 1).to_le_bytes());
        let err = decode_frame::<YubabaToKamaji>(&buf).unwrap_err();
        assert!(matches!(err, Error::FrameTooLarge { .. }));
    }

    // ── R406-T7: structured drain protocol round-trips ──────────────────────

    #[test]
    fn drain_budget_total_ms_saturates() {
        let budget = DrainBudget {
            flush_ms: u32::MAX,
            checkpoint_ms: 100,
        };
        assert_eq!(budget.total_ms(), u32::MAX);

        let budget = DrainBudget {
            flush_ms: 5_000,
            checkpoint_ms: 1_000,
        };
        assert_eq!(budget.total_ms(), 6_000);
    }

    #[test]
    fn drain_outcome_flushed_round_trips() {
        let outcome = DrainOutcome::Flushed {
            exit: ExitStatus::Exited(0),
            elapsed_ms: 250,
        };
        let bytes = postcard::to_stdvec(&outcome).unwrap();
        let decoded: DrainOutcome = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn drain_outcome_checkpointed_round_trips() {
        let outcome = DrainOutcome::Checkpointed {
            exit: ExitStatus::Signaled(15),
            elapsed_ms: 5_800,
        };
        let bytes = postcard::to_stdvec(&outcome).unwrap();
        let decoded: DrainOutcome = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn drain_outcome_force_killed_round_trips() {
        let outcome = DrainOutcome::ForceKilled { elapsed_ms: 6_100 };
        let bytes = postcard::to_stdvec(&outcome).unwrap();
        let decoded: DrainOutcome = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn drain_outcome_unit_variants_round_trip() {
        for outcome in [DrainOutcome::UnknownWorkload, DrainOutcome::Unsupported] {
            let bytes = postcard::to_stdvec(&outcome).unwrap();
            let decoded: DrainOutcome = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(decoded, outcome);
        }
    }

    #[test]
    fn drain_completed_message_round_trips() {
        let msg = KamajiToYubaba::DrainCompleted {
            request_id: RequestId(99),
            id: WorkloadId::new("svc-1"),
            outcome: DrainOutcome::Flushed {
                exit: ExitStatus::Exited(0),
                elapsed_ms: 1_234,
            },
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame::<KamajiToYubaba>(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn drain_phase_round_trips() {
        for phase in [DrainPhase::Flush, DrainPhase::Checkpoint] {
            let bytes = postcard::to_stdvec(&phase).unwrap();
            let decoded: DrainPhase = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(decoded, phase);
        }
    }

    #[test]
    fn protocol_version_serializes_compactly() {
        // Sanity: the version envelope is a single byte in postcard (single
        // variant unit enum encodes as a varint discriminant).
        let bytes = postcard::to_stdvec(&ProtocolVersion::V1).unwrap();
        assert_eq!(bytes.len(), 1);
    }

    // ── R592-T5: exhaustive wire-symmetry regression net ────────────────────
    //
    // The R590-B3 fix proved that a *single* `Workload::Container` spec decodes
    // over the postcard UDS. These tests widen that to a permanent guard: every
    // `YubabaToKamaji` and `KamajiToYubaba` variant, and — for the Deploy
    // path — every `workload_spec::Workload` variant that can carry a spec, must
    // survive `encode_frame` → `decode_frame` with byte-exact symmetry
    // (decoded == original AND consumed == the whole frame). Postcard is
    // positional and non-self-describing, so a stray `#[serde(tag = …)]` or
    // `skip_serializing_if` on any *nested* type silently corrupts the stream;
    // exercising the real payloads is the only way to catch that class before it
    // reaches a live deploy (it stayed latent through R406-T9 because the smoke
    // only listed workloads).

    /// Byte-symmetric round-trip of one `YubabaToKamaji` frame.
    fn assert_warden_round_trips(msg: YubabaToKamaji) {
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, consumed) = decode_frame::<YubabaToKamaji>(&bytes).unwrap();
        assert_eq!(decoded, msg, "YubabaToKamaji did not survive the wire");
        assert_eq!(
            consumed,
            bytes.len(),
            "decoder must consume the whole frame"
        );
    }

    /// Byte-symmetric round-trip of one `KamajiToYubaba` frame.
    fn assert_constable_round_trips(msg: KamajiToYubaba) {
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, consumed) = decode_frame::<KamajiToYubaba>(&bytes).unwrap();
        assert_eq!(decoded, msg, "KamajiToYubaba did not survive the wire");
        assert_eq!(
            consumed,
            bytes.len(),
            "decoder must consume the whole frame"
        );
    }

    /// A `WorkloadSpec` with every field family populated — env (all three
    /// `EnvValue` kinds), secrets (both `SecretRef`/`SecretTarget` kinds),
    /// volumes (all three `VolumeSource` kinds), a healthcheck, an
    /// `OnFailure` restart policy, and a full `ExposeSpec`. This is the spec
    /// shape that stresses the most nested enums across the wire.
    fn full_container_spec() -> workload_spec::WorkloadSpec {
        use std::collections::HashMap;
        use std::path::PathBuf;
        use workload_spec::{
            BackoffPolicy, EnvValue, EnvVar, ExposeSpec, HealthProbe, Healthcheck, ImageRef,
            LifecycleArchetype, MeshExpose, MeshIdent, MeshLookup, Millis, OperatorExpose,
            PublicExpose, PublicTls, ResourceLimits, RestartPolicy, SecretMount,
            SecretRef, SecretTarget, StopPolicy, TierTag, VolumeMount, VolumeSource, WorkloadSpec,
        };
        WorkloadSpec {
            name: "noisetable-api".into(),
            image: ImageRef {
                registry: "ghcr.io".into(),
                repository: "noisetable/api".into(),
                tag: "v1.4.2".into(),
                digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .into(),
            },
            tier: TierTag("private".into()),
            tenant: workload_spec::TenantId::singleton(),
            namespace: workload_spec::NamespaceId::singleton(),
            replicas: 2,
            command: Some(vec!["./server".into()]),
            entrypoint: Some(vec!["/bin/sh".into(), "-c".into()]),
            workdir: Some(PathBuf::from("/app")),
            user: Some("1000:1000".into()),
            env: vec![
                EnvVar {
                    name: "APP_ENV".into(),
                    value: EnvValue::Literal {
                        value: "production".into(),
                    },
                },
                EnvVar {
                    name: "DB_PASSWORD".into(),
                    value: EnvValue::FromSecret {
                        secret: "db-creds".into(),
                        key: "password".into(),
                    },
                },
                EnvVar {
                    name: "DATABASE_URL".into(),
                    value: EnvValue::FromMesh {
                        ident: MeshIdent("noisetable-db.pdx".into()),
                        kind: MeshLookup::Url,
                    },
                },
            ],
            secrets: vec![
                SecretMount {
                    source: SecretRef::LocalFile {
                        path: PathBuf::from("/var/lib/yah/yubaba/secrets/tls.crt"),
                    },
                    target: SecretTarget::File {
                        path: PathBuf::from("/etc/tls/cert.crt"),
                        mode: 0o400,
                    },
                },
                SecretMount {
                    source: SecretRef::Cluster {
                        name: "stripe-key".into(),
                    },
                    target: SecretTarget::EnvVar {
                        name: "STRIPE_SECRET_KEY".into(),
                    },
                },
            ],
            volumes: vec![
                VolumeMount {
                    source: VolumeSource::Named {
                        name: "api-data".into(),
                    },
                    target: PathBuf::from("/data"),
                    read_only: false,
                    from_secret_mount: false,
                },
                VolumeMount {
                    source: VolumeSource::Bind {
                        host_path: PathBuf::from("/opt/yah/config"),
                    },
                    target: PathBuf::from("/config"),
                    read_only: true,
                    from_secret_mount: false,
                },
                VolumeMount {
                    source: VolumeSource::Tmpfs { size_mb: 128 },
                    target: PathBuf::from("/tmp"),
                    read_only: false,
                    from_secret_mount: false,
                },
            ],
            resources: ResourceLimits {
                memory_mb: 512,
                cpu_millis: 1024,
                memory_request_mb: None,
                cpu_limit_millis: None,
                pids_max: None,
                scratch_floor_mb: None,
            },
            depends_on: vec![MeshIdent("noisetable-db.pdx".into())],
            requires: vec![],
            healthcheck: Some(Healthcheck {
                probe: HealthProbe::HttpGet {
                    path: "/healthz".into(),
                    port: 8080,
                    expect_status: Some(200),
                },
                interval: Millis::from_secs(10),
                timeout: Millis::from_secs(5),
                initial_delay: Millis::from_secs(30),
                failure_threshold: 3,
            }),
            restart_policy: RestartPolicy::OnFailure {
                max_attempts: 5,
                backoff: BackoffPolicy {
                    initial_ms: 500,
                    max_ms: 30_000,
                    multiplier: 2.0,
                },
            },
            archetype: Some(LifecycleArchetype::Appliance),
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(30),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent("noisetable-api.pdx".into()),
                    ports: MeshExpose::anonymous_ports([8080, 9090]),
                    allow_from: vec![
                        workload_spec::MeshPeer::Tier(TierTag("private".into())),
                        workload_spec::MeshPeer::Tier(TierTag("tenant".into())),
                    ],
                },
                public: Some(PublicExpose {
                    hostname: "api.noisetable.io".into(),
                    port: 8080,
                    tls: PublicTls::CfManaged,
                }),
                operator: Some(OperatorExpose {
                    tailscale_tag: "tag:noisetable-ops".into(),
                    port: 9090,
                }),
            },
            labels: {
                let mut m = HashMap::new();
                m.insert(
                    "org.opencontainers.image.source".into(),
                    "https://github.com/noisetable/api".into(),
                );
                m
            },
            durability: None,
            annotations: {
                let mut m = HashMap::new();
                m.insert("yah.created-by".into(), "agent:claude".into());
                m
            },
            files: Vec::new(),
        }
    }

    /// Every `YubabaToKamaji` variant survives the framed postcard wire with
    /// a realistic payload.
    #[test]
    fn all_warden_to_constable_variants_round_trip() {
        use workload_spec::{ImageRef, TierTag, Workload, WorkloadSpec};

        // Hello.
        assert_warden_round_trips(YubabaToKamaji::Hello {
            version: ProtocolVersion::CURRENT,
        });

        // Deploy (a real container spec; per-variant Deploy coverage lives in
        // `deploy_every_workload_variant_round_trips`).
        assert_warden_round_trips(YubabaToKamaji::Deploy {
            request_id: RequestId(1),
            id: WorkloadId::new("forge-w"),
            spec: Workload::container(WorkloadSpec::for_forge(
                "w",
                ImageRef {
                    registry: "ghcr.io".into(),
                    repository: "yah/forge".into(),
                    tag: "v1".into(),
                    digest:
                        "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                            .into(),
                },
                TierTag("private".into()),
                vec![8080],
            )),
            mesh: None,
        });

        // Stop.
        assert_warden_round_trips(YubabaToKamaji::Stop {
            request_id: RequestId(2),
            id: WorkloadId::new("svc-2"),
        });

        // Drain.
        assert_warden_round_trips(YubabaToKamaji::Drain {
            request_id: RequestId(3),
            id: WorkloadId::new("svc-3"),
            budget: DrainBudget {
                flush_ms: 5_000,
                checkpoint_ms: 1_000,
            },
        });

        // Probe.
        assert_warden_round_trips(YubabaToKamaji::Probe {
            request_id: RequestId(4),
            id: WorkloadId::new("svc-4"),
        });

        // List.
        assert_warden_round_trips(YubabaToKamaji::List {
            request_id: RequestId(5),
        });

        // DeployStatus (R330-F33).
        assert_warden_round_trips(YubabaToKamaji::DeployStatus {
            request_id: RequestId(6),
            id: WorkloadId::new("svc-6"),
        });
    }

    /// The two R330-F33 variants were **appended**, so every pre-existing
    /// variant must keep the postcard discriminant it had before. Postcard is
    /// positional and non-self-describing: inserting a variant in the middle
    /// renumbers everything after it, and the resulting frames still *decode* —
    /// as the wrong variant. Nothing else in the suite would catch that, so
    /// these bytes are pinned deliberately.
    ///
    /// Byte 4 is the discriminant (bytes 0..4 are the LE length prefix).
    #[test]
    fn appending_variants_did_not_shift_existing_discriminants() {
        use workload_spec::{ImageRef, TierTag, Workload, WorkloadSpec};

        let spec = || {
            Workload::container(WorkloadSpec::for_forge(
                "w",
                ImageRef {
                    registry: "ghcr.io".into(),
                    repository: "yah/forge".into(),
                    tag: "v1".into(),
                    digest:
                        "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                            .into(),
                },
                TierTag("private".into()),
                vec![8080],
            ))
        };
        let id = || WorkloadId::new("svc");
        let rid = RequestId(1);

        let warden: Vec<(u8, YubabaToKamaji)> = vec![
            (
                0,
                YubabaToKamaji::Hello {
                    version: ProtocolVersion::CURRENT,
                },
            ),
            (
                1,
                YubabaToKamaji::Deploy {
                    request_id: rid,
                    id: id(),
                    spec: spec(),
                    mesh: None,
                },
            ),
            (
                2,
                YubabaToKamaji::Stop {
                    request_id: rid,
                    id: id(),
                },
            ),
            (
                3,
                YubabaToKamaji::Drain {
                    request_id: rid,
                    id: id(),
                    budget: DrainBudget {
                        flush_ms: 1,
                        checkpoint_ms: 1,
                    },
                },
            ),
            (
                4,
                YubabaToKamaji::Probe {
                    request_id: rid,
                    id: id(),
                },
            ),
            (5, YubabaToKamaji::List { request_id: rid }),
            (
                6,
                YubabaToKamaji::GracefulUpgrade {
                    request_id: rid,
                    id: id(),
                    spec: spec(),
                },
            ),
            // Appended by R330-F33 — must come after GracefulUpgrade.
            (
                7,
                YubabaToKamaji::DeployStatus {
                    request_id: rid,
                    id: id(),
                },
            ),
        ];
        for (want, msg) in warden {
            let bytes = encode_frame(&msg).unwrap();
            assert_eq!(bytes[4], want, "discriminant moved for {msg:?}");
        }

        let constable: Vec<(u8, KamajiToYubaba)> = vec![
            (
                0,
                KamajiToYubaba::Welcome {
                    version: ProtocolVersion::CURRENT,
                    kamaji_version: "0".into(),
                },
            ),
            (
                1,
                KamajiToYubaba::Ack {
                    request_id: rid,
                    kind: AckKind::Stop,
                },
            ),
            (
                2,
                KamajiToYubaba::Error {
                    request_id: Some(rid),
                    code: ErrorCode::Internal,
                    message: "x".into(),
                },
            ),
            (3, KamajiToYubaba::WorkloadStarted { id: id(), pid: 1 }),
            (
                4,
                KamajiToYubaba::WorkloadExited {
                    id: id(),
                    exit: ExitStatus::Exited(0),
                },
            ),
            (
                5,
                KamajiToYubaba::ProbeResult {
                    request_id: rid,
                    id: id(),
                    status: ProbeStatus::Ready,
                },
            ),
            (
                6,
                KamajiToYubaba::DrainAck {
                    request_id: rid,
                    id: id(),
                    accepted: true,
                    reason: None,
                },
            ),
            (
                7,
                KamajiToYubaba::DrainCompleted {
                    request_id: rid,
                    id: id(),
                    outcome: DrainOutcome::Unsupported,
                },
            ),
            (
                8,
                KamajiToYubaba::WorkloadList {
                    request_id: rid,
                    entries: vec![],
                },
            ),
            // Appended by R330-F33.
            (
                9,
                KamajiToYubaba::DeployStatusResult {
                    request_id: rid,
                    id: id(),
                    state: WorkloadState::Pending,
                    detail: None,
                },
            ),
        ];
        for (want, msg) in constable {
            let bytes = encode_frame(&msg).unwrap();
            assert_eq!(bytes[4], want, "discriminant moved for {msg:?}");
        }
    }

    /// Every `KamajiToYubaba` variant survives the framed postcard wire —
    /// including every `AckKind`, `ProbeStatus`, `ExitStatus`, and
    /// `DrainOutcome` sub-variant.
    #[test]
    fn all_constable_to_warden_variants_round_trip() {
        // Welcome.
        assert_constable_round_trips(KamajiToYubaba::Welcome {
            version: ProtocolVersion::CURRENT,
            kamaji_version: "0.8.18".into(),
        });

        // Ack — every AckKind.
        for kind in [AckKind::Stop, AckKind::Probe, AckKind::GracefulUpgrade] {
            assert_constable_round_trips(KamajiToYubaba::Ack {
                request_id: RequestId(10),
                kind,
            });
        }

        // DeployAck (R850-T4) — both hydrate shapes. The `Some` arm is the one
        // worth round-tripping: an `Option<String>` is the first place a
        // positional codec can silently lose a byte, and this line is what a
        // measured restore is made of.
        for hydrate in [
            None,
            Some(r#"{"outcome":"hydrated","restored":[{"subject":"main","source":{"snapshot":1},"bytes":4096,"seconds":1.5}]}"#.to_string()),
        ] {
            assert_constable_round_trips(KamajiToYubaba::DeployAck {
                request_id: RequestId(10),
                id: WorkloadId::new("yah-marketing"),
                hydrate,
            });
        }

        // Error — both request-id shapes and a representative code set.
        for code in [
            ErrorCode::UnsupportedVersion,
            ErrorCode::UnknownWorkload,
            ErrorCode::InvalidSpec,
            ErrorCode::BackendRefused,
            ErrorCode::Internal,
        ] {
            assert_constable_round_trips(KamajiToYubaba::Error {
                request_id: Some(RequestId(11)),
                code,
                message: "reason".into(),
            });
        }
        assert_constable_round_trips(KamajiToYubaba::Error {
            request_id: None,
            code: ErrorCode::Internal,
            message: "malformed frame".into(),
        });

        // WorkloadStarted (push).
        assert_constable_round_trips(KamajiToYubaba::WorkloadStarted {
            id: WorkloadId::new("svc"),
            pid: 4242,
        });

        // WorkloadExited (push) — every ExitStatus.
        for exit in [
            ExitStatus::Exited(0),
            ExitStatus::Exited(137),
            ExitStatus::Signaled(15),
            ExitStatus::DrainTimeout,
        ] {
            assert_constable_round_trips(KamajiToYubaba::WorkloadExited {
                id: WorkloadId::new("svc"),
                exit,
            });
        }

        // ProbeResult — every ProbeStatus.
        for status in [
            ProbeStatus::Ready,
            ProbeStatus::Starting,
            ProbeStatus::Unhealthy {
                reason: "db down".into(),
            },
            ProbeStatus::Timeout,
        ] {
            assert_constable_round_trips(KamajiToYubaba::ProbeResult {
                request_id: RequestId(12),
                id: WorkloadId::new("svc"),
                status,
            });
        }

        // DrainAck — accepted and not-accepted.
        assert_constable_round_trips(KamajiToYubaba::DrainAck {
            request_id: RequestId(13),
            id: WorkloadId::new("svc"),
            accepted: true,
            reason: Some("flushed in 50ms".into()),
        });
        assert_constable_round_trips(KamajiToYubaba::DrainAck {
            request_id: RequestId(14),
            id: WorkloadId::new("svc"),
            accepted: false,
            reason: None,
        });

        // DrainCompleted (push) — every DrainOutcome.
        for outcome in [
            DrainOutcome::Flushed {
                exit: ExitStatus::Exited(0),
                elapsed_ms: 250,
            },
            DrainOutcome::Checkpointed {
                exit: ExitStatus::Signaled(15),
                elapsed_ms: 5_800,
            },
            DrainOutcome::ForceKilled { elapsed_ms: 6_100 },
            DrainOutcome::UnknownWorkload,
            DrainOutcome::Unsupported,
        ] {
            assert_constable_round_trips(KamajiToYubaba::DrainCompleted {
                request_id: RequestId(15),
                id: WorkloadId::new("svc"),
                outcome,
            });
        }

        // WorkloadList — populated with every WorkloadState.
        assert_constable_round_trips(KamajiToYubaba::WorkloadList {
            request_id: RequestId(16),
            entries: vec![
                WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("a"),
                    state: WorkloadState::Pending,
                    pid: None,
                    ports: Vec::new(),
                    named_ports: Default::default(),
                    spec_digest: None,
                },
                WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("b"),
                    state: WorkloadState::Starting,
                    pid: Some(2),
                    ports: Vec::new(),
                    named_ports: Default::default(),
                    spec_digest: None,
                },
                WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("c"),
                    state: WorkloadState::Running,
                    pid: Some(3),
                    ports: Vec::new(),
                    named_ports: Default::default(),
                    spec_digest: None,
                },
                WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("d"),
                    state: WorkloadState::Draining,
                    pid: Some(4),
                    ports: Vec::new(),
                    named_ports: Default::default(),
                    spec_digest: None,
                },
                WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("e"),
                    state: WorkloadState::Exited,
                    pid: None,
                    ports: Vec::new(),
                    named_ports: Default::default(),
                    spec_digest: None,
                },
                WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("f"),
                    state: WorkloadState::Failed,
                    pid: None,
                    ports: Vec::new(),
                    named_ports: Default::default(),
                    spec_digest: None,
                },
                WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("o"),
                    state: WorkloadState::OomKilled,
                    pid: None,
                    ports: Vec::new(),
                    named_ports: Default::default(),
                    spec_digest: None,
                },
            ],
        });

        // DeployStatusResult (R330-F33) — every state, and both `detail`
        // shapes: the failure reason is the whole point of the variant, so a
        // `None`-only round-trip would not prove much.
        for state in [
            WorkloadState::Pending,
            WorkloadState::Starting,
            WorkloadState::Running,
            WorkloadState::Failed,
            WorkloadState::OomKilled,
        ] {
            for detail in [None, Some("materialize bundle abc: blob 404".to_string())] {
                assert_constable_round_trips(KamajiToYubaba::DeployStatusResult {
                    request_id: RequestId(17),
                    id: WorkloadId::new("svc"),
                    state,
                    detail,
                });
            }
        }
    }

    /// Every `workload_spec::Workload` variant that can ride a `Deploy` frame
    /// survives the postcard wire: `Container` (both the `for_forge` all-None
    /// shape that first exposed the `skip_serializing_if` misalignment *and* a
    /// full spec with every optional populated), plus `StaticAsset`,
    /// `MesofactStatic`, and `Almanac`.
    #[test]
    fn deploy_every_workload_variant_round_trips() {
        use std::collections::BTreeMap;
        use std::path::PathBuf;
        use workload_spec::{
            AlmanacManifest, AlmanacTarget, AssetEntry, BlakeHash, BuildConfig, BuildMode, Cadence,
            ImageRef, MeshIdent, MesofactStaticWorkload, Millis, NotReadyPolicy,             StaticAssetWorkload, TierTag, Workload, WorkloadSpec,
        };

        let image = || ImageRef {
            registry: "ghcr.io".into(),
            repository: "yah/forge".into(),
            tag: "v1".into(),
            digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                .into(),
        };

        let variants = vec![
            // Container — the `for_forge` shape: replicas=1, all optionals None,
            // all Vecs empty. This is the exact spec a real forge deploy sends,
            // and the one that decoded as `DeserializeBadOption` before the
            // `skip_serializing_if` strip.
            (
                "container-for-forge",
                Workload::container(WorkloadSpec::for_forge(
                    "b3",
                    image(),
                    TierTag("private".into()),
                    vec![8080],
                )),
            ),
            // Container — full spec, every optional populated.
            ("container-full", Workload::container(full_container_spec())),
            // MesofactStatic — nests an `ImageRef` (InContainer build) and a
            // second `WorkloadSpec` (the SSR companion).
            (
                "mesofact-static",
                Workload::MesofactStatic(MesofactStaticWorkload {
                    build: BuildConfig {
                        command: Some("bun run build".into()),
                        out_dir: PathBuf::from("dist"),
                        render_command: None,
                    },
                    routes: PathBuf::from("routes.ts"),
                    build_mode: BuildMode::InContainer { image: image() },
                    ssr_runtime: Some(WorkloadSpec::for_forge(
                        "ssr",
                        image(),
                        TierTag("private".into()),
                        vec![3000],
                    )),
                    serve_bundle: None,
                    revalidate_receiver: None,
                }),
            ),
            // Almanac — exercises AlmanacTarget (Http + Tcp), Cadence::Cron,
            // and NotReadyPolicy::Requeue.
            (
                "almanac",
                Workload::Almanac(AlmanacManifest {
                    command: "refresh-openrouter-cache".into(),
                    cadence: Cadence::Cron {
                        expression: "0 */6 * * *".into(),
                    },
                    inputs: vec![AlmanacTarget::Http {
                        url: "https://openrouter.ai/api/v1/models".into(),
                        expect_status: Some(200),
                    }],
                    outputs: vec![AlmanacTarget::Tcp {
                        host: "minio".into(),
                        port: 9000,
                    }],
                    not_ready_policy: NotReadyPolicy::Requeue {
                        max_attempts: 3,
                        backoff: Millis::from_secs(2),
                    },
                    invalidates: vec![MeshIdent("noisetable-web.pdx".into())],
                }),
            ),
            // StaticAsset — BlakeHash decode runs its 64-hex validator on the wire.
            (
                "static-asset",
                Workload::StaticAsset(StaticAssetWorkload {
                    assets: vec![AssetEntry {
                        filename: "whisper/distil-large-v3.bin".into(),
                        source: Some(PathBuf::from("assets/model.bin")),
                        derive: None,
                        blake3: BlakeHash("a".repeat(64)),
                    }],
                    aliases: {
                        let mut m = BTreeMap::new();
                        m.insert("latest".into(), "whisper/distil-large-v3.bin".into());
                        m
                    },
                }),
            ),
        ];

        for (label, spec) in variants {
            let msg = YubabaToKamaji::Deploy {
                request_id: RequestId(20),
                id: WorkloadId::new(label),
                spec,
                mesh: None,
            };
            let bytes = encode_frame(&msg).unwrap();
            let (decoded, consumed) = decode_frame::<YubabaToKamaji>(&bytes)
                .unwrap_or_else(|e| panic!("{label} failed to decode over the wire: {e}"));
            assert_eq!(decoded, msg, "{label} did not survive the postcard wire");
            assert_eq!(
                consumed,
                bytes.len(),
                "{label}: decoder must consume the whole frame"
            );
        }
    }

    /// An `ImageRef` authored in the string-pinned form
    /// (`reg/repo:tag@sha256:<hex>`, the shape recipes and `BuildMode` configs
    /// use) is parsed from human-readable JSON, then embedded in a Deploy and
    /// pushed across the postcard wire. This ties the authoring surface to the
    /// binary wire: the string form only exists in `is_human_readable`
    /// deserializers, but the struct it produces must ride postcard cleanly —
    /// the two-format split that R590-B3 introduced (`ImageRef::deserialize`
    /// branching on `is_human_readable`) is exactly what this guards.
    #[test]
    fn deploy_string_pinned_image_ref_survives_postcard_wire() {
        use workload_spec::{ImageRef, TierTag, Workload, WorkloadSpec};

        // Parse the string form through serde_json (a human-readable format).
        let pinned = "\"ghcr.io/yah/forge:v1@sha256:\
                      4444444444444444444444444444444444444444444444444444444444444444\"";
        let image: ImageRef = serde_json::from_str(pinned)
            .expect("string-pinned ImageRef parses from human-readable JSON");
        assert_eq!(image.registry, "ghcr.io");
        assert_eq!(image.repository, "yah/forge");
        assert_eq!(image.tag, "v1");
        assert!(image.digest.starts_with("sha256:"));

        let msg = YubabaToKamaji::Deploy {
            request_id: RequestId(30),
            id: WorkloadId::new("forge-pinned"),
            spec: Workload::container(WorkloadSpec::for_forge(
                "pinned",
                image,
                TierTag("private".into()),
                vec![8080],
            )),
            mesh: None,
        };
        let bytes = encode_frame(&msg).unwrap();
        let (decoded, consumed) = decode_frame::<YubabaToKamaji>(&bytes)
            .expect("string-authored ImageRef must survive the postcard wire");
        assert_eq!(decoded, msg);
        assert_eq!(consumed, bytes.len());
    }

    /// R885-T6: appending `WorkloadState::OomKilled` must not renumber any
    /// existing variant.
    ///
    /// This is the load-bearing claim of the V11 stanza in `version.rs`, and it
    /// is the one that is invisible in a diff — postcard encodes a unit-variant
    /// discriminant as a varint, so *where* a variant is added decides whether
    /// the change is additive or a silent renumbering of every state after it.
    /// R850-T4 paid for the lesson from the other direction: removing
    /// `AckKind::Deploy` renumbered its successors, and a `Stop` ack started
    /// decoding as `Probe` with no error anywhere.
    ///
    /// Pinned against literal bytes rather than against `as usize`, because a
    /// cast reads the Rust discriminant and this test is about the *wire*.
    #[test]
    fn appending_oom_killed_left_every_existing_discriminant_alone() {
        for (state, want) in [
            (WorkloadState::Pending, 0u8),
            (WorkloadState::Starting, 1),
            (WorkloadState::Running, 2),
            (WorkloadState::Draining, 3),
            (WorkloadState::Exited, 4),
            (WorkloadState::Failed, 5),
            // The new one, and the only byte an unbumped V10 peer cannot read.
            (WorkloadState::OomKilled, 6),
        ] {
            let bytes = postcard::to_allocvec(&state)
                .expect("a fieldless enum always encodes");
            assert_eq!(
                bytes,
                vec![want],
                "{state:?} must encode as the single byte {want}"
            );
            let back: WorkloadState =
                postcard::from_bytes(&bytes).expect("and must decode back");
            assert_eq!(back, state);
        }
    }
}

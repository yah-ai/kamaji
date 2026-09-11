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

use postcard::Error as PostcardError;
use serde::{de::DeserializeOwned, Serialize};

/// Maximum frame payload size the codec accepts.
///
/// UDS control messages are tiny — workload specs are the largest realistic
/// payload and they cap at the low-kB range. 1 MiB is a generous ceiling that
/// still rejects framing bugs and hostile peers cheaply.
pub const MAX_FRAME_BYTES: usize = 1 << 20;

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
            PublicExpose, PublicTls, ResourceLimits, RestartPolicy, SchemaVersion, SecretMount,
            SecretRef, SecretTarget, StopPolicy, TierTag, VolumeMount, VolumeSource, WorkloadSpec,
        };
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
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
                },
                VolumeMount {
                    source: VolumeSource::Bind {
                        host_path: PathBuf::from("/opt/yah/config"),
                    },
                    target: PathBuf::from("/config"),
                    read_only: true,
                },
                VolumeMount {
                    source: VolumeSource::Tmpfs { size_mb: 128 },
                    target: PathBuf::from("/tmp"),
                    read_only: false,
                },
            ],
            resources: ResourceLimits {
                memory_mb: 512,
                cpu_millis: 1024,
                ephemeral_storage_mb: 256,
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
                    kind: AckKind::Deploy,
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
        for kind in [AckKind::Deploy, AckKind::Stop, AckKind::Probe] {
            assert_constable_round_trips(KamajiToYubaba::Ack {
                request_id: RequestId(10),
                kind,
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
            ImageRef, MeshIdent, MesofactStaticWorkload, Millis, NotReadyPolicy, SchemaVersion,
            StaticAssetWorkload, TierTag, Workload, WorkloadSpec,
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
                    schema_version: SchemaVersion::V1,
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
                    schema_version: SchemaVersion::V1,
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
                    schema_version: SchemaVersion::V1,
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
}

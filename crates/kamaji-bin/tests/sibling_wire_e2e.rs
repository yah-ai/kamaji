//! R592-T5 — end-to-end sibling-wire deploy regression net.
//!
//! Proves a real `WorkloadSpec` (carrying a nested `ImageRef` plus populated
//! env / secrets / volumes / healthcheck) survives the postcard-framed UDS from
//! the sibling `KamajiClient` (`kamaji::sibling`) into this crate's dispatch
//! loop. R590-B3 fixed the postcard decode of that graph; the original R406-T9
//! smoke only ever did `List`, so a Deploy carrying a spec across the wire was
//! never exercised at the live-server level. These tests close that gap
//! permanently.
//!
//! Two shapes:
//!
//! 1. `deploy_reaches_dispatch_against_real_server` — the REAL `kamaji-bin` UDS
//!    server (default build, no containerd backend). The Deploy frame is decoded
//!    by the actual `handle_conn`/`handle_message` path, so a regression in the
//!    postcard graph surfaces here as a decode `Internal` error rather than the
//!    `BackendRefused` the backend-selection arm returns. The rest of the
//!    lifecycle (Probe / List / Stop / Drain) is driven through the same real
//!    server. A container deploy cannot be *accepted* without a containerd
//!    backend (unavailable in CI), so acceptance + `List` visibility is proven
//!    in the second test.
//!
//! 2. `accepted_deploy_appears_in_list_against_scripted_backend` — the same real
//!    `KamajiClient` driven against a scripted server that speaks real
//!    codec frames and acts as a backend-equipped kamaji: it postcard-decodes
//!    the spec (asserting the round-trip on the server side), acks the deploy,
//!    and surfaces the workload in `List`. This exercises the client's
//!    accepted-deploy happy path — `Deploy → DeployResult`, workload visible in
//!    `List`, then `Probe / Stop / Drain` — which the no-backend real server
//!    can't reach.

use std::path::{Path, PathBuf};
use std::time::Duration;

use kamaji::sibling::KamajiClient;
use kamaji::{Kamaji, MeshAssignment};
use kamaji_proto::{
    decode_frame, encode_frame, AckKind, DrainBudget, ErrorCode, KamajiToYubaba, ProbeStatus,
    ProtocolVersion, WorkloadEntry, WorkloadId, WorkloadState, YubabaToKamaji,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::oneshot;

use workload_spec::{
    BackoffPolicy, EnvValue, EnvVar, ExposeSpec, HealthProbe, Healthcheck, ImageRef,
    LifecycleArchetype, MeshExpose, MeshIdent, MeshLookup, Millis, OperatorExpose, PublicExpose,
    PublicTls, ResourceLimits, RestartPolicy, SchemaVersion, SecretMount, SecretRef, SecretTarget,
    StopPolicy, TierTag, VolumeMount, VolumeSource, WorkloadSpec,
};

/// The digest embedded in every test image — a marker so the scripted server
/// can prove the nested `ImageRef` decoded correctly on its side of the wire.
const TEST_DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

/// A full container spec: nested `ImageRef`, three `EnvValue` kinds, both
/// secret shapes, all three volume sources, a healthcheck, and a full expose
/// block. The payload that stresses the most nested enums across the UDS.
fn full_container_spec() -> WorkloadSpec {
    use std::collections::HashMap;
    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: "noisetable-api".into(),
        image: ImageRef {
            registry: "ghcr.io".into(),
            repository: "noisetable/api".into(),
            tag: "v1.4.2".into(),
            digest: TEST_DIGEST.into(),
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
        labels: HashMap::new(),
        annotations: HashMap::new(),
    }
}

/// Connect a `KamajiClient`, retrying while the server binds its listener
/// (the real server binds inside the spawned task).
async fn connect_with_retry(socket: &Path) -> KamajiClient {
    for _ in 0..100 {
        match KamajiClient::connect(socket).await {
            Ok(c) => return c,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("client never connected to {}", socket.display());
}

/// Shape 1: drive the full lifecycle through the REAL `kamaji-bin` server.
///
/// The Deploy is *rejected* by the backend-selection arm (no containerd in this
/// build), but only after `handle_message` has postcard-decoded the whole
/// `Workload::Container(WorkloadSpec)` off the wire — which is exactly the
/// R590-B3 boundary. The regression assertion: the reply is a `BackendRefused`
/// (decode succeeded, spec reached dispatch), NOT a decode-time `Internal`
/// error. Probe / List / Stop / Drain then round-trip through the same server.
#[tokio::test]
async fn deploy_reaches_dispatch_against_real_server() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("kamaji.sock");

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server_path = socket.clone();
    let server = tokio::spawn(async move {
        kamaji_bin::serve_with_shutdown(&server_path, async move {
            let _ = stop_rx.await;
        })
        .await
    });

    let client = connect_with_retry(&socket).await;

    // Deploy a full container spec. The client wraps it in Workload::Container
    // and sends YubabaToKamaji::Deploy over the postcard UDS.
    let spec = full_container_spec();
    let mesh = MeshAssignment::stub("10.64.0.7".parse().unwrap());
    let err = client
        .deploy_workload(&spec, &mesh)
        .await
        .expect_err("no containerd backend in this build, so deploy must be refused");
    let msg = format!("{err:#}");

    // The crux of the R590-B3 regression: the spec decoded and reached the
    // backend-selection arm (BackendRefused), rather than dying at decode.
    assert!(
        msg.contains("containerd"),
        "deploy should be refused by the backend arm (proving the spec decoded \
         and reached dispatch), got: {msg}"
    );
    for broken in [
        "decode failed",
        "postcard",
        "WontImplement",
        "DeserializeBadOption",
    ] {
        assert!(
            !msg.contains(broken),
            "spec failed to decode over the wire — R590-B3 regression ({broken}): {msg}"
        );
    }

    // Probe of an unregistered workload → Ready (the "no probe declared"
    // convention), proving Probe round-trips through the real server.
    let id = WorkloadId::new(&spec.name);
    let status = client.probe(&id).await.expect("probe round-trips");
    assert!(
        matches!(status, ProbeStatus::Ready),
        "expected Ready, got {status:?}"
    );

    // List → empty (nothing was registered without a backend).
    let entries = client.list().await.expect("list round-trips");
    assert!(
        entries.is_empty(),
        "no backend, so nothing should be listed: {entries:?}"
    );

    // Stop → Ack (idempotent; absence satisfies the end-state).
    client.stop(&id).await.expect("stop round-trips");

    // Drain of an unknown workload → not accepted, reason mentions "unknown".
    let (accepted, reason) = client
        .drain(
            &id,
            DrainBudget {
                flush_ms: 50,
                checkpoint_ms: 50,
            },
        )
        .await
        .expect("drain round-trips");
    assert!(!accepted, "unknown workload must not be accepted");
    assert!(
        reason.as_deref().unwrap_or_default().contains("unknown"),
        "drain reason should mention 'unknown', got: {reason:?}"
    );

    drop(client);
    let _ = stop_tx.send(());
    server.await.unwrap().unwrap();
}

/// Shape 2: an accepted deploy is visible in `List`.
///
/// The scripted server speaks real codec frames and behaves like a
/// backend-equipped kamaji. It postcard-decodes the incoming spec (asserting
/// the round-trip on the server side), acks the deploy, and returns the
/// workload in `List` — exercising the client's accepted-deploy path, which the
/// no-backend real server can't reach.
#[tokio::test]
async fn accepted_deploy_appears_in_list_against_scripted_backend() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("kamaji.sock");

    // Bind synchronously so the socket exists before the client connects.
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(scripted_backend(listener));

    let client = KamajiClient::connect(&socket).await.expect("connect");

    let spec = full_container_spec();
    let mesh = MeshAssignment::stub("10.64.0.9".parse().unwrap());

    // Deploy is accepted → DeployResult carries the spec-derived container id.
    let result = client
        .deploy_workload(&spec, &mesh)
        .await
        .expect("deploy accepted");
    assert_eq!(result.container_id, spec.name);
    assert_eq!(result.mesh_ip, mesh.mesh_ip);

    // The workload now appears in List.
    let entries = client.list().await.expect("list");
    assert_eq!(
        entries.len(),
        1,
        "deployed workload should appear in List: {entries:?}"
    );
    assert_eq!(entries[0].id, WorkloadId::new(&spec.name));
    assert_eq!(entries[0].state, WorkloadState::Running);

    // Probe returns a status.
    let status = client
        .probe(&WorkloadId::new(&spec.name))
        .await
        .expect("probe");
    assert!(
        matches!(status, ProbeStatus::Ready),
        "expected Ready, got {status:?}"
    );

    // Stop succeeds and removes the workload.
    client
        .stop(&WorkloadId::new(&spec.name))
        .await
        .expect("stop");
    let after_stop = client.list().await.expect("list after stop");
    assert!(
        after_stop.is_empty(),
        "workload should be gone after stop: {after_stop:?}"
    );

    // Drain of the (now absent) workload still round-trips a DrainAck.
    let (accepted, _reason) = client
        .drain(
            &WorkloadId::new(&spec.name),
            DrainBudget {
                flush_ms: 100,
                checkpoint_ms: 100,
            },
        )
        .await
        .expect("drain");
    assert!(accepted, "scripted backend acks the drain");

    drop(client);
    server.await.unwrap();
}

/// A scripted kamaji that speaks real codec frames and keeps an in-memory
/// workload registry. Handshakes, records accepted deploys, and reflects them
/// in `List` / `Stop`.
async fn scripted_backend(listener: UnixListener) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let mut workloads: Vec<WorkloadEntry> = Vec::new();

    loop {
        // Decode one frame, refilling from the socket as needed.
        let msg = loop {
            match decode_frame::<YubabaToKamaji>(&buf) {
                Ok((m, n)) => {
                    buf.drain(..n);
                    break m;
                }
                Err(kamaji_proto::Error::Truncated { .. }) => {
                    let n = stream.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        return; // client hung up
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                Err(e) => panic!("scripted server decode failed: {e}"),
            }
        };

        let reply = match msg {
            YubabaToKamaji::Hello { .. } => KamajiToYubaba::Welcome {
                version: ProtocolVersion::CURRENT,
                kamaji_version: "scripted-0.0.1".into(),
            },
            YubabaToKamaji::Deploy {
                request_id,
                id,
                spec,
                mesh,
            } => match spec {
                ref w @ workload_spec::Workload::Container(_) => {
                    let decoded = w
                        .container_spec()
                        .expect("the wire only ever carries the digest-pinned form");
                    // Prove the spec survived the postcard wire on the server
                    // side — nested ImageRef + the three-element env Vec.
                    assert_eq!(
                        decoded.name, "noisetable-api",
                        "spec.name corrupted on the wire"
                    );
                    // R599-F12: and that the mesh assignment arrived with it.
                    // Before this field existed the server had to invent
                    // `MeshAssignment::inlined(127.0.0.1)`, so a workload could
                    // only ever be told to bind loopback.
                    let mesh = mesh.expect(
                        "Deploy must carry the caller's MeshAssignment, not drop it at the client",
                    );
                    assert!(
                        mesh.mesh_ip.to_string().starts_with("10.64.0."),
                        "mesh_ip corrupted on the wire: {}",
                        mesh.mesh_ip
                    );
                    assert_eq!(
                        decoded.image.digest, TEST_DIGEST,
                        "nested ImageRef.digest corrupted on the wire"
                    );
                    assert_eq!(decoded.env.len(), 3, "env Vec corrupted on the wire");
                    workloads.push(WorkloadEntry {
                        mesh_ident: None,
                        id: id.clone(),
                        state: WorkloadState::Running,
                        pid: Some(4242),
                        ports: Vec::new(),
                        named_ports: Default::default(),
                        spec_digest: None,
                    });
                    KamajiToYubaba::Ack {
                        request_id,
                        kind: AckKind::Deploy,
                    }
                }
                other => KamajiToYubaba::Error {
                    request_id: Some(request_id),
                    code: ErrorCode::InvalidSpec,
                    message: format!("unexpected workload kind: {other:?}"),
                },
            },
            YubabaToKamaji::List { request_id } => KamajiToYubaba::WorkloadList {
                request_id,
                entries: workloads.clone(),
            },
            YubabaToKamaji::Probe { request_id, id } => KamajiToYubaba::ProbeResult {
                request_id,
                id,
                status: ProbeStatus::Ready,
            },
            YubabaToKamaji::Stop { request_id, id } => {
                workloads.retain(|w| w.id != id);
                KamajiToYubaba::Ack {
                    request_id,
                    kind: AckKind::Stop,
                }
            }
            YubabaToKamaji::Drain { request_id, id, .. } => KamajiToYubaba::DrainAck {
                request_id,
                id,
                accepted: true,
                reason: Some("flushed".into()),
            },
            _ => KamajiToYubaba::Error {
                request_id: None,
                code: ErrorCode::Internal,
                message: "scripted server: unhandled request".into(),
            },
        };

        let frame = encode_frame(&reply).unwrap();
        stream.write_all(&frame).await.unwrap();
    }
}

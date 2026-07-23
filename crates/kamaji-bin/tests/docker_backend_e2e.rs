//! R626-F1 — the docker/OrbStack backend driven through the real kamaji-bin
//! UDS server.
//!
//! This is the ticket's verify criterion as an executable test: with a docker
//! daemon running, deploy a container workload *through kamaji* (sibling
//! `KamajiClient` → postcard UDS → `handle_message` → `ServerCtx.docker`),
//! confirm it appears **exactly once** in `List` with the correct pid and
//! state, and that `Stop` actually stops it.
//!
//! Everything below the client is production code: `serve_with_ctx` is the same
//! entry point `main.rs` runs, and the backend is a real `DockerRuntime` talking
//! to a real daemon. Skips (does not fail) when no daemon is reachable — CI has
//! no docker socket.
//!
//! Part of R626-F1 — annotation in src/server.rs.

#![cfg(all(unix, feature = "docker-integration"))]

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use kamaji::sibling::KamajiClient;
use kamaji::{Kamaji as _, MeshAssignment};
use kamaji_proto::{WorkloadId, WorkloadState};
use tempfile::TempDir;
use tokio::sync::oneshot;
use workload_spec::{ImageRef, MeshIdent, ResourceLimits, TierTag, WorkloadSpec};

async fn docker_available() -> bool {
    let out = tokio::process::Command::new("docker")
        .args(["version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    matches!(out, Ok(s) if s.success())
}

/// `alpine sleep 300`, resourced for a dev host rather than for a build box.
fn sleeper_spec(id: &str) -> WorkloadSpec {
    let mut spec = WorkloadSpec::for_forge(
        id,
        ImageRef {
            registry: "docker.io".into(),
            repository: "library/alpine".into(),
            tag: "3.20".into(),
            digest: ImageRef::UNPINNED_DIGEST.into(),
        },
        TierTag("private".into()),
        vec![],
    );
    spec.command = Some(vec!["sleep".into(), "300".into()]);
    spec.resources = ResourceLimits {
        memory_mb: 64,
        cpu_millis: 250,
        ephemeral_storage_mb: 64,
    };
    spec
}

async fn connect_with_retry(socket: &Path) -> KamajiClient {
    for _ in 0..100 {
        match KamajiClient::connect(socket).await {
            Ok(c) => return c,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("client never connected to {}", socket.display());
}

/// The R626-F1 verify criterion, end to end.
#[tokio::test]
async fn deploy_list_stop_through_kamaji_against_live_docker() {
    if !docker_available().await {
        eprintln!("SKIP: docker not reachable");
        return;
    }

    let spec = sleeper_spec("r626f1-e2e");
    // R590-B9 divergence, deliberately exercised: docker NAMES the container by
    // mesh identity (`forge.r626f1-e2e`), while the sibling client deploys and
    // stops by workload id (`spec.name` = `forge-r626f1-e2e`). A supervisor that
    // conflated the two would Ack a Stop while leaving the container running.
    let ident = spec.expose.mesh.identity.clone();
    let id = WorkloadId::new(&spec.name);
    assert_ne!(
        id.0, ident.0,
        "this test is only meaningful while id and mesh identity differ"
    );

    let docker = kamaji::docker::DockerRuntime::new();
    // No residue from an interrupted previous run.
    docker.teardown_workload(&ident).await.unwrap();

    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("kamaji.sock");
    let ctx = Arc::new(kamaji_bin::ServerCtx::new().with_docker(docker.clone()));

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server_path = socket.clone();
    let server = tokio::spawn(async move {
        kamaji_bin::serve_with_ctx(&server_path, ctx, async move {
            let _ = stop_rx.await;
        })
        .await
    });

    let client = connect_with_retry(&socket).await;

    // ── Deploy ───────────────────────────────────────────────────────────────
    let mesh = MeshAssignment::inlined(std::net::Ipv4Addr::LOCALHOST);
    client
        .deploy_workload(&spec, &mesh)
        .await
        .expect("docker backend accepts the container deploy");

    // ── List: exactly one row, correct pid + state ───────────────────────────
    let entries = client.list().await.expect("list round-trips");
    let mine: Vec<_> = entries.iter().filter(|e| e.id == id).collect();
    assert_eq!(
        mine.len(),
        1,
        "expected exactly one row for {id:?} (R599-B11 dedupe), got {mine:#?} \
         out of {entries:#?}"
    );
    let entry = mine[0];
    assert_eq!(entry.state, WorkloadState::Running, "entry: {entry:?}");
    let pid = entry.pid.expect("a running container must report a host pid");
    assert!(pid > 0, "pid must be a real host pid, got {pid}");
    assert_eq!(entry.mesh_ident.as_deref(), Some(ident.0.as_str()));

    // The pid kamaji reports is the one docker knows — not a fabricated value.
    let direct = docker
        .list_workloads_detailed()
        .await
        .unwrap()
        .into_iter()
        .find(|w| w.state.ident == ident)
        .expect("docker sees the container directly");
    assert_eq!(direct.pid, Some(pid), "kamaji's pid must match docker's");

    // ── Stop: actually stops it ──────────────────────────────────────────────
    client.stop(&id).await.expect("stop round-trips");
    assert!(
        docker.get_workload(&ident).await.unwrap().is_none(),
        "Stop must actually remove the container from the daemon"
    );

    // …and it leaves the listing.
    let after = client.list().await.expect("list round-trips");
    assert!(
        !after.iter().any(|e| e.id == id),
        "stopped workload still listed: {after:#?}"
    );

    let _ = stop_tx.send(());
    let _ = server.await;
}

/// A `Stop` for a workload the docker daemon never owned must still Ack —
/// `Stop` is idempotent, and kamaji routes every Stop to every backend.
#[tokio::test]
async fn stop_of_unknown_workload_still_acks_with_docker_attached() {
    if !docker_available().await {
        eprintln!("SKIP: docker not reachable");
        return;
    }

    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("kamaji.sock");
    let ctx = Arc::new(
        kamaji_bin::ServerCtx::new().with_docker(kamaji::docker::DockerRuntime::new()),
    );

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server_path = socket.clone();
    let server = tokio::spawn(async move {
        kamaji_bin::serve_with_ctx(&server_path, ctx, async move {
            let _ = stop_rx.await;
        })
        .await
    });

    let client = connect_with_retry(&socket).await;
    client
        .stop(&WorkloadId(MeshIdent("r626f1-never-deployed".into()).0))
        .await
        .expect("stop of an unknown workload must still Ack");

    let _ = stop_tx.send(());
    let _ = server.await;
}

//! Live end-to-end exercise of the docker/OrbStack backend against a real
//! daemon (R626-F1).
//!
//! `docker.rs` shipped feature-gated and unwired — no caller in the workspace
//! ever constructed a `DockerRuntime` — so R626 recorded "docker.rs is
//! functionally complete" as an *assumption*, explicitly not a fact. This test
//! discharges it by driving the full supervisor lifecycle a kamaji `Deploy` /
//! `List` / `Stop` walks: pull → run → inspect → list → teardown, asserting on
//! the real daemon's answers rather than on parsed fixtures.
//!
//! Skips (does not fail) when no docker daemon is reachable, matching the
//! in-module live tests — CI has no docker socket.
//!
//! Part of R626-F1 — annotation in oss/kamaji/crates/kamaji-bin/src/server.rs.

#![cfg(all(unix, feature = "docker-integration"))]

use std::net::Ipv4Addr;
use std::process::Stdio;

use kamaji::docker::DockerRuntime;
use kamaji::{Kamaji, MeshAssignment, WorkloadStatus};
use workload_spec::{ImageRef, MeshIdent, ResourceLimits, TierTag, WorkloadSpec};

/// True when a docker daemon answers. The whole test is skipped otherwise.
async fn docker_available() -> bool {
    let out = tokio::process::Command::new("docker")
        .args(["version"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    matches!(out, Ok(s) if s.success())
}

/// A long-running container spec: `alpine sleep 300`, small enough to pull
/// quickly and resourced for a dev host (`for_forge`'s 32 GiB build ceiling
/// would become a `--memory 32768m` docker refuses on most laptops).
fn sleeper_spec(id: &str) -> WorkloadSpec {
    let mut spec = WorkloadSpec::for_forge(
        id,
        ImageRef {
            registry: "docker.io".into(),
            repository: "library/alpine".into(),
            tag: "3.20".into(),
            // Unpinned sentinel → `pull_ref()` resolves by tag, which is what
            // a public image without a recorded digest needs.
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

/// Full deploy → inspect → list → stop cycle against the live daemon.
///
/// This is the R626-F1 gate: every claim kamaji-bin's routing rests on
/// (deploy returns a real container id AND a real host pid; the workload shows
/// up exactly once in the label-filtered listing; teardown actually removes it)
/// is asserted against docker itself.
#[tokio::test]
async fn deploy_list_stop_round_trips_against_live_docker() {
    if !docker_available().await {
        eprintln!("SKIP: docker not reachable");
        return;
    }

    let rt = DockerRuntime::new();
    let forge_id = "r626f1-live";
    let spec = sleeper_spec(forge_id);
    let ident = spec.expose.mesh.identity.clone();
    let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

    // Leave no residue behind from a previous interrupted run.
    rt.teardown_workload(&ident).await.unwrap();

    let deployed = rt
        .deploy_workload(&spec, &mesh)
        .await
        .expect("deploy against live docker");

    // `.State.Pid` must be a real host pid now, not the old hardcoded 0.
    assert!(
        !deployed.container_id.is_empty(),
        "expected a container id from docker run"
    );
    assert!(
        deployed.task_pid > 0,
        "expected a live host pid from .State.Pid, got {}",
        deployed.task_pid
    );

    // get_workload sees it as Running.
    let got = rt
        .get_workload(&ident)
        .await
        .unwrap()
        .expect("deployed workload is inspectable");
    assert_eq!(got.status, WorkloadStatus::Running, "state: {got:?}");
    assert_eq!(got.container_id, deployed.container_id);

    // It appears EXACTLY ONCE in the listing, with the same pid — the property
    // kamaji-bin's cross-backend List dedupe (R599-B11) is ranked on.
    let listed = rt.list_workloads_detailed().await.unwrap();
    let mine: Vec<_> = listed.iter().filter(|w| w.state.ident == ident).collect();
    assert_eq!(
        mine.len(),
        1,
        "expected exactly one row for {ident:?}, got {mine:#?}"
    );
    assert_eq!(mine[0].pid, Some(deployed.task_pid));
    assert_eq!(mine[0].state.status, WorkloadStatus::Running);

    // Teardown really removes it, and is idempotent on a second call.
    rt.teardown_workload(&ident).await.unwrap();
    assert!(
        rt.get_workload(&ident).await.unwrap().is_none(),
        "workload still present after teardown"
    );
    rt.teardown_workload(&ident).await.unwrap();

    // …and it's gone from the listing too.
    let after = rt.list_workloads_detailed().await.unwrap();
    assert!(
        !after.iter().any(|w| w.state.ident == ident),
        "torn-down workload still listed"
    );
}

/// A container that exits non-zero must surface as `Failed`, not as a live
/// workload — kamaji's supervision decisions key on this.
#[tokio::test]
async fn exited_container_reports_failed_with_no_pid() {
    if !docker_available().await {
        eprintln!("SKIP: docker not reachable");
        return;
    }

    let rt = DockerRuntime::new();
    let mut spec = sleeper_spec("r626f1-exit");
    spec.command = Some(vec!["sh".into(), "-c".into(), "exit 3".into()]);
    let ident = spec.expose.mesh.identity.clone();
    let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

    rt.teardown_workload(&ident).await.unwrap();
    // The deploy itself succeeds — `docker run -d` returns as soon as the
    // container starts; the non-zero exit shows up in the state afterwards.
    let _ = rt.deploy_workload(&spec, &mesh).await;

    // Give the container a moment to run to completion.
    for _ in 0..40 {
        let state = rt.get_workload(&ident).await.unwrap();
        if matches!(
            state.as_ref().map(|s| &s.status),
            Some(WorkloadStatus::Failed { .. })
        ) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let got = rt.get_workload(&ident).await.unwrap().expect("inspectable");
    match &got.status {
        WorkloadStatus::Failed { reason } => {
            assert!(reason.contains('3'), "expected exit code 3 in {reason:?}");
        }
        other => panic!("expected Failed, got {other:?}"),
    }

    // An exited container has no host process — it must not claim a pid.
    let listed = rt.list_workloads_detailed().await.unwrap();
    let mine = listed
        .iter()
        .find(|w| w.state.ident == ident)
        .expect("exited container still listed (docker ps -a)");
    assert_eq!(mine.pid, None, "exited container must not report a pid");

    rt.teardown_workload(&ident).await.unwrap();
}

/// `MeshIdent` is the teardown key; tearing down an identity that never
/// existed is a no-op, which is what makes kamaji-bin's "route every Stop to
/// every backend" pattern safe.
#[tokio::test]
async fn teardown_of_unknown_identity_is_a_noop() {
    if !docker_available().await {
        eprintln!("SKIP: docker not reachable");
        return;
    }
    let rt = DockerRuntime::new();
    rt.teardown_workload(&MeshIdent("r626f1-never-existed".into()))
        .await
        .unwrap();
    // …and the id-keyed form is equally a no-op.
    rt.teardown_by_key("r626f1-never-existed").await.unwrap();
}

/// R590-B9: a container is NAMED by mesh identity but ADDRESSED by workload id,
/// and for a forge workload those are different strings. `resolve` /
/// `teardown_by_key` must accept either, or kamaji's `Stop` — which only ever
/// holds the id — silently leaves the container running.
#[tokio::test]
async fn resolve_and_teardown_accept_either_id_or_mesh_identity() {
    if !docker_available().await {
        eprintln!("SKIP: docker not reachable");
        return;
    }

    let rt = DockerRuntime::new();
    let spec = sleeper_spec("r626f1-keys");
    let ident = spec.expose.mesh.identity.clone();
    let workload_id = spec.name.clone();
    assert_ne!(
        workload_id, ident.0,
        "fixture must exercise the id/identity divergence"
    );

    rt.teardown_by_key(&workload_id).await.unwrap();
    let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
    rt.deploy_workload(&spec, &mesh).await.expect("deploy");

    // Both keys find the same container.
    let by_ident = rt.resolve(&ident.0).await.unwrap().expect("found by ident");
    let by_id = rt
        .resolve(&workload_id)
        .await
        .unwrap()
        .expect("found by workload id");
    assert_eq!(by_ident.state.container_id, by_id.state.container_id);
    assert_eq!(by_id.workload_id, workload_id);
    assert_eq!(by_id.state.ident, ident);

    // Tearing down by the ID (what kamaji's Stop holds) really removes it.
    rt.teardown_by_key(&workload_id).await.unwrap();
    assert!(
        rt.get_workload(&ident).await.unwrap().is_none(),
        "teardown by workload id must remove the container"
    );
}

/// An unrelated container on the same daemon — no `yah.ident` label — must not
/// be adopted into kamaji's listing. A dev host's docker is full of them.
#[tokio::test]
async fn unlabelled_containers_are_not_listed_as_workloads() {
    if !docker_available().await {
        eprintln!("SKIP: docker not reachable");
        return;
    }

    let name = "r626f1-foreign-tenant";
    let _ = tokio::process::Command::new("docker")
        .args(["rm", "-f", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    let run = tokio::process::Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            name,
            "docker.io/library/alpine:3.20",
            "sleep",
            "60",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .expect("spawn docker run");
    assert!(run.success(), "failed to start the foreign container");

    let listed = DockerRuntime::new()
        .list_workloads_detailed()
        .await
        .unwrap();
    assert!(
        !listed.iter().any(|w| w.state.ident.0 == name),
        "an unlabelled container must not be listed as a yah workload"
    );

    let _ = tokio::process::Command::new("docker")
        .args(["rm", "-f", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

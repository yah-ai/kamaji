//! `runtime::containerd` — production `ContainerRuntime` impl via the
//! `containerd-client` gRPC crate.
//!
//! ## Gating
//!
//! This file compiles only under `--features containerd-integration` so the
//! release binary does not carry the containerd gRPC client stack when it
//! ships (the binary is curl-fetched from GitHub at boot per the 32KiB
//! user-data cap constraint).
//!
//! ## Log files
//!
//! Container stdout/stderr are redirected to files under
//! `/var/log/yah/<namespace>/<container_id>/`. `stream_logs` tails those
//! files with tokio async I/O. This matches containerd's standard logging
//! path when no external log driver is configured.
//!
//! ## WireGuard (stub in F1)
//!
//! `deploy_workload` accepts a `MeshAssignment` but only uses the `mesh_ip`
//! field in F1. Full WireGuard netns setup (creating a `wg0` interface inside
//! the container netns) lands with the mesh module in R091-F6.
//!
// Original ticket R091-F1 (status:review) lives in yubaba/src/runtime/mod.rs
// — moved with the file but the @yah: annotation stays at the original source
// so the board doesn't see a duplicate (one annotation per ID, R484-T2).

#![cfg(feature = "containerd-integration")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use containerd_client::{
    services::v1::{
        containers_client::ContainersClient,
        snapshots::{snapshots_client::SnapshotsClient, RemoveSnapshotRequest},
        tasks_client::TasksClient,
        version_client::VersionClient,
        Container, CreateContainerRequest, CreateTaskRequest, DeleteContainerRequest,
        DeleteTaskRequest, GetContainerRequest, KillRequest, ListContainersRequest, StartRequest,
    },
    tonic, with_namespace,
};
// `with_namespace!` expands to `Request::new(...)` — needs a bare `Request` in scope.
use containerd_client::tonic::Request;
use kamaji_containerd_core as kcc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_stream::wrappers::LinesStream;
use tokio_stream::StreamExt as TokioStreamExt;
use workload_spec::{MeshIdent, WorkloadSpec};

use crate::socket_custody::{self, SocketCustodian};
use crate::{
    Backend, DeployResult, Kamaji, LogEvent, LogOpts, LogStream, LogStreamKind, MeshAssignment,
    RuntimeHealth, WorkloadState, WorkloadStatus,
};
use std::path::Path;

// Socket path / namespace / log-base constants, OCI-spec building,
// image/rootfs resolution, and task-status querying are shared with
// kamaji-bin's containerd backend via `kamaji-containerd-core` (R592-T1) —
// see that crate for the single definitions re-exported here.
pub use kamaji_containerd_core::{DEFAULT_SOCKET, LOG_BASE, YAH_NAMESPACE};

/// How long to let a graceful-upgrade replacement container settle — bind its
/// pingora upgrade socket and wait to receive the outgoing process's listening
/// fds — before signalling the outgoing one. Mirrors the native backend's
/// `UPGRADE_SETTLE` (R600-F7).
const UPGRADE_SETTLE: Duration = Duration::from_millis(750);

/// pingora's graceful-upgrade drain signal. On `SIGQUIT` the outgoing passway
/// sends its listening fds to the incoming (upgrade-mode) process over the
/// shared upgrade socket, then drains in-flight connections and exits — as
/// opposed to `SIGTERM` (15), the fast-stop signal. kamaji is the sole sender
/// of this signal; passway never self-`SIGQUIT`s (that would tear down the only
/// listener — see `passway/src/tls.rs`).
const SIGQUIT: u32 = 3;

// ── ContainerdRuntime ─────────────────────────────────────────────────────────

/// Production `ContainerRuntime` that speaks to containerd over its Unix
/// domain socket via gRPC.
///
/// Acquire one via `ContainerdRuntime::connect` or
/// `ContainerdRuntime::connect_at`. Cheaply cloneable — the inner `Channel`
/// is `Arc`-wrapped.
#[derive(Clone)]
pub struct ContainerdRuntime {
    channel: tonic::transport::Channel,
    namespace: String,
    log_base: PathBuf,
    /// Per-container restart bookkeeping (R471-T2). Containerd has no native
    /// restart-count or "currently restarting" signal — its Status enum is
    /// {Unknown, Created, Running, Stopped, Paused, Pausing}. The supervisor
    /// records each exit + relaunch cycle here so `list_workloads` /
    /// `get_workload` can synthesize `WorkloadStatus::Restarting`.
    ledger: RestartLedger,
    /// Per-ident current pod slot for the graceful-upgrade ping-pong (R600-F7).
    /// Absent → slot A (the bare ident), so an ordinary workload that never
    /// upgrades is unaffected. A cert-rotation graceful upgrade flips this after
    /// the incoming container has adopted the listening socket.
    slots: Arc<Mutex<HashMap<String, kcc::PodSlot>>>,
    /// Socket custodian for passway workloads (R600-F9, superseding F7's
    /// option B). kamaji `bind()`s the passway listen address once and holds
    /// the `OwnedFd`; every passway container generation starts in upgrade mode
    /// and adopts that fd over its pingora upgrade socket, so the listening
    /// socket is kamaji's property and outlives any single passway process.
    /// kamaji is the **sole** fd sender — passway never binds `:443` itself.
    custodian: Arc<SocketCustodian>,
}

/// One container's restart history.
///
/// Maintained by the yubaba supervisor (workload-spec.rs:1186 `RestartPolicy`
/// applier) which calls [`RestartLedger::record_exit`] when a task exits with
/// a non-zero code AND the policy still has budget, and
/// [`RestartLedger::mark_running`] once the replacement task is up. The
/// runtime read path consults the ledger to populate
/// `WorkloadStatus::Restarting`.
#[derive(Debug, Clone, Copy)]
pub struct RestartRecord {
    pub last_exit_code: i32,
    pub restart_count: u32,
    pub last_finished_at: SystemTime,
    /// `true` between `record_exit` and the next `mark_running` — i.e. while
    /// the supervisor's recreate cycle is in flight.
    pub in_flight: bool,
}

/// Shared, lock-protected map of container ID → `RestartRecord`.
///
/// `Clone` is a cheap pointer-clone (Arc).
#[derive(Clone, Default)]
pub struct RestartLedger {
    inner: Arc<Mutex<HashMap<String, RestartRecord>>>,
}

impl RestartLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bump the restart count and arm the in-flight bit. Called by the
    /// supervisor immediately after observing a non-zero task exit, *before*
    /// recreating the task.
    pub fn record_exit(&self, container_id: &str, exit_code: i32) {
        let mut g = self.inner.lock().unwrap();
        let now = SystemTime::now();
        g.entry(container_id.to_string())
            .and_modify(|r| {
                r.last_exit_code = exit_code;
                r.restart_count = r.restart_count.saturating_add(1);
                r.last_finished_at = now;
                r.in_flight = true;
            })
            .or_insert(RestartRecord {
                last_exit_code: exit_code,
                restart_count: 1,
                last_finished_at: now,
                in_flight: true,
            });
    }

    /// Clear the in-flight bit. Called once the replacement task is started.
    /// Preserves `restart_count` so the next exit increments correctly.
    pub fn mark_running(&self, container_id: &str) {
        let mut g = self.inner.lock().unwrap();
        if let Some(r) = g.get_mut(container_id) {
            r.in_flight = false;
        }
    }

    /// Drop the record entirely — e.g. on successful teardown.
    pub fn forget(&self, container_id: &str) {
        let mut g = self.inner.lock().unwrap();
        g.remove(container_id);
    }

    /// Snapshot lookup. `None` if the container has never crashed.
    pub fn get(&self, container_id: &str) -> Option<RestartRecord> {
        self.inner.lock().unwrap().get(container_id).copied()
    }
}

/// Translate a base `WorkloadStatus` + ledger record into a final status.
///
/// Only Stopped/Failed states upgrade to Restarting (a running container
/// trivially isn't restarting). `in_flight=false` records stay as the base
/// status — the crash-loop is paused/over.
fn apply_ledger(base: WorkloadStatus, rec: Option<RestartRecord>) -> WorkloadStatus {
    let rec = match rec {
        Some(r) if r.in_flight && r.restart_count > 0 => r,
        _ => return base,
    };
    match base {
        WorkloadStatus::Stopped | WorkloadStatus::Failed { .. } => {
            let last_finished_at_unix_ms = rec
                .last_finished_at
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            WorkloadStatus::Restarting {
                last_exit_code: rec.last_exit_code,
                restart_count: rec.restart_count,
                last_finished_at_unix_ms,
            }
        }
        other => other,
    }
}

impl ContainerdRuntime {
    /// Connect to the default containerd socket (`/run/containerd/containerd.sock`).
    pub async fn connect() -> Result<Self> {
        Self::connect_at(DEFAULT_SOCKET).await
    }

    /// Connect to a containerd socket at the given path.
    ///
    /// On macOS with Colima, the socket is typically at
    /// `~/.colima/default/containerd.sock`.
    pub async fn connect_at(socket: impl AsRef<std::path::Path>) -> Result<Self> {
        let channel = kcc::connect(socket).await?;
        Ok(ContainerdRuntime {
            channel,
            namespace: YAH_NAMESPACE.to_string(),
            log_base: PathBuf::from(LOG_BASE),
            ledger: RestartLedger::new(),
            slots: Arc::new(Mutex::new(HashMap::new())),
            custodian: Arc::new(SocketCustodian::new()),
        })
    }

    /// The container id currently backing `ident` — the bare ident until a
    /// graceful upgrade flips the workload to slot B (`<ident>.b`) and back.
    /// Every read/lifecycle method resolves the live container through this so
    /// the ping-pong stays invisible to callers (R600-F7).
    fn live_container_id(&self, ident: &MeshIdent) -> String {
        self.slots
            .lock()
            .unwrap()
            .get(&ident.0)
            .copied()
            .unwrap_or_default()
            .container_id(&ident.0)
    }

    /// Record which slot now backs `ident` (called after a graceful upgrade
    /// hands the listening socket to the incoming container).
    fn set_slot(&self, ident: &MeshIdent, slot: kcc::PodSlot) {
        self.slots.lock().unwrap().insert(ident.0.clone(), slot);
    }

    /// Forget `ident`'s slot (on teardown) so a later redeploy starts at slot A.
    fn clear_slot(&self, ident: &MeshIdent) {
        self.slots.lock().unwrap().remove(&ident.0);
    }

    /// Reap a single containerd container id: SIGKILL its task, delete the task
    /// and container records, drop its rootfs snapshot and restart bookkeeping.
    /// Best-effort — `NotFound` on any leg means it was already gone. Shared by
    /// `teardown_workload` (both slots) and the graceful-upgrade reap of the
    /// outgoing generation (R600-F7).
    async fn teardown_container(&self, container_id: &str) -> Result<()> {
        let mut tasks = self.tasks_client();
        let mut ctrs = self.containers_client();

        // Kill the task (best-effort; container may not be running).
        let kill_req = KillRequest {
            container_id: container_id.to_string(),
            exec_id: String::new(),
            signal: 9, // SIGKILL
            all: true,
        };
        let kill_req = with_namespace!(kill_req, self.namespace);
        let _ = tasks.kill(kill_req).await;

        // Brief delay so the task exits before we try to delete.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Delete the task record.
        let del_task_req = DeleteTaskRequest {
            container_id: container_id.to_string(),
        };
        let del_task_req = with_namespace!(del_task_req, self.namespace);
        let _ = tasks.delete(del_task_req).await;

        // Delete the container record.
        let del_req = DeleteContainerRequest {
            id: container_id.to_string(),
        };
        let del_req = with_namespace!(del_req, self.namespace);
        match ctrs.delete(del_req).await {
            Ok(_) => {}
            Err(status) if status.code() == tonic::Code::NotFound => {}
            Err(e) => {
                return Err(anyhow!(e).context(format!("deleting container {container_id}")));
            }
        }

        // Remove the active rootfs snapshot so a redeploy can re-prepare it
        // (snapshot key == container id). Best-effort: NotFound is fine.
        let rm_snap = RemoveSnapshotRequest {
            snapshotter: "overlayfs".to_string(),
            key: container_id.to_string(),
        };
        let rm_snap = with_namespace!(rm_snap, self.namespace);
        let _ = self.snapshots_client().remove(rm_snap).await;

        // Drop any restart-loop bookkeeping for this container.
        self.ledger.forget(container_id);

        tracing::info!(container_id = %container_id, "container torn down");
        Ok(())
    }

    /// Create + start one containerd container generation for `spec` under
    /// `container_id`, with optional pod placement (`pod`) and extra process env
    /// (`extra_env`). For a custody (passway) workload every generation —
    /// including the first deploy — gets `PASSWAY_UPGRADE=true` so it adopts
    /// kamaji's held listen fd instead of binding the address itself (R600-F9).
    /// Shared by the ordinary `deploy_workload` path, `deploy_custody`, and
    /// `graceful_upgrade_workload` so the container-creation paths cannot drift
    /// (R592-T1 posture). Does NOT tear down anything — the caller owns
    /// stale-clearing.
    async fn create_and_start(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
        container_id: &str,
        pod: &kcc::PodOptions,
        extra_env: &[String],
    ) -> Result<DeployResult> {
        let image_ref = Self::image_ref(spec);

        // Ensure the image is in the containerd image store (callers pre-pull;
        // see R091-F3). Delegates to `kamaji-containerd-core` (R592-T1).
        let image_target_digest =
            kcc::resolve_image_target_digest(&self.channel, &self.namespace, &image_ref).await?;

        // Image OCI config (ENTRYPOINT/CMD/ENV/WORKDIR/USER) merged per OCI
        // convention (R590-B8). Best-effort; unreadable → spec-only argv/env.
        let image_config =
            kcc::image_oci_config(&self.channel, &self.namespace, &image_target_digest)
                .await
                .ok();

        // Deployment env: the mesh IP (as before) plus any caller extras
        // (PASSWAY_UPGRADE on the incoming graceful-upgrade container).
        let mut deploy_env = vec![format!("YAH_MESH_IP={}", mesh.mesh_ip)];
        deploy_env.extend(extra_env.iter().cloned());

        // Build OCI spec (with pod placement) and wrap it as protobuf.Any.
        let oci_spec = kcc::build_oci_spec_with(spec, &deploy_env, image_config.as_ref(), pod);
        let spec_bytes = serde_json::to_vec(&oci_spec).context("serializing OCI spec")?;
        let any_spec = prost_types::Any {
            type_url: "types.containerd.io/opencontainers/runtime-spec/1/Spec".to_string(),
            value: spec_bytes,
        };

        // Create log directory + stdio files. The shim opens these paths WITHOUT
        // O_CREAT, so they must already exist (truncate any prior content).
        let log_dir = self.log_dir(container_id);
        tokio::fs::create_dir_all(&log_dir)
            .await
            .with_context(|| format!("creating log dir {}", log_dir.display()))?;
        let stdout_file = log_dir.join("stdout.log");
        let stderr_file = log_dir.join("stderr.log");
        tokio::fs::File::create(&stdout_file)
            .await
            .with_context(|| format!("creating {}", stdout_file.display()))?;
        tokio::fs::File::create(&stderr_file)
            .await
            .with_context(|| format!("creating {}", stderr_file.display()))?;
        let stdout_path = stdout_file.to_string_lossy().into_owned();
        let stderr_path = stderr_file.to_string_lossy().into_owned();

        // Create the container record.
        {
            let mut ctrs = self.containers_client();
            let mut labels = spec.labels.clone();
            labels.insert("yah.ident".to_string(), spec.expose.mesh.identity.0.clone());
            labels.insert("yah.mesh_ip".to_string(), mesh.mesh_ip.to_string());

            let container = Container {
                id: container_id.to_string(),
                image: image_ref.clone(),
                runtime: Some(containerd_client::services::v1::container::Runtime {
                    name: "io.containerd.runc.v2".to_string(),
                    options: None,
                }),
                spec: Some(any_spec),
                snapshotter: "overlayfs".to_string(),
                snapshot_key: container_id.to_string(),
                labels,
                ..Default::default()
            };

            let req = CreateContainerRequest {
                container: Some(container),
            };
            let req = with_namespace!(req, self.namespace);
            ctrs.create(req)
                .await
                .with_context(|| format!("creating container {container_id}"))?;
        }

        // Prepare the rootfs snapshot from the image's committed layer chain.
        let rootfs_mounts = self
            .prepare_rootfs(container_id, &image_target_digest)
            .await
            .with_context(|| format!("preparing rootfs for {container_id}"))?;

        // Create + start the task (execution instance).
        let task_pid = {
            let mut tasks = self.tasks_client();
            let req = CreateTaskRequest {
                container_id: container_id.to_string(),
                rootfs: rootfs_mounts,
                stdin: String::new(),
                stdout: stdout_path,
                stderr: stderr_path,
                terminal: false,
                checkpoint: None,
                options: None,
                ..Default::default()
            };
            let req = with_namespace!(req, self.namespace);
            let resp = tasks
                .create(req)
                .await
                .with_context(|| format!("creating task for {container_id}"))?;
            resp.into_inner().pid
        };
        {
            let mut tasks = self.tasks_client();
            let req = StartRequest {
                container_id: container_id.to_string(),
                exec_id: String::new(),
            };
            let req = with_namespace!(req, self.namespace);
            tasks
                .start(req)
                .await
                .with_context(|| format!("starting task for {container_id}"))?;
        }

        Ok(DeployResult {
            container_id: container_id.to_string(),
            mesh_ip: mesh.mesh_ip,
            task_pid,
        })
    }

    /// Task status of a single containerd container id (best-effort). `None`
    /// when there is no task (never deployed / already reaped). Used by the
    /// graceful-upgrade settle check on the incoming container (R600-F7).
    async fn container_status(&self, container_id: &str) -> Option<WorkloadStatus> {
        let mut tasks = self.tasks_client();
        match get_task_status(&mut tasks, &self.namespace, container_id).await {
            Ok(Some((code, _pid, exit_status))) => Some(Self::map_task_status(code, exit_status)),
            _ => None,
        }
    }

    /// Send `SIGQUIT` to a container's init process (pingora's graceful-upgrade
    /// drain). `all: false` targets PID 1 only — the passway process — so the
    /// signal triggers its fd-handoff-and-drain rather than a group kill.
    async fn sigquit_task(&self, container_id: &str) -> Result<()> {
        let mut tasks = self.tasks_client();
        let req = KillRequest {
            container_id: container_id.to_string(),
            exec_id: String::new(),
            signal: SIGQUIT,
            all: false,
        };
        let req = with_namespace!(req, self.namespace);
        tasks
            .kill(req)
            .await
            .with_context(|| format!("SIGQUIT {container_id}"))?;
        Ok(())
    }

    /// Pod placement for one **generation** (`slot`) of a passway workload
    /// (R600-F9). Each generation gets its own host upgrade-sock directory
    /// bind-mounted at the socket's container-side parent path, so kamaji can
    /// `connect()` from the host mount namespace to the socket passway binds
    /// inside the container and hand it the held listen fd over `SCM_RIGHTS`.
    /// The dir is per-generation (not per-ident) so the incoming passway's
    /// `get_from_sock` unlink+rebind can't clobber the outgoing one's inode.
    /// Ordinary (non-passway) workloads get [`kcc::PodOptions::default()`].
    async fn passway_pod_options(
        &self,
        spec: &WorkloadSpec,
        slot: kcc::PodSlot,
    ) -> Result<kcc::PodOptions> {
        let Some(sock_dir) = kcc::upgrade_sock_dir(spec) else {
            return Ok(kcc::PodOptions::default());
        };
        let host_dir = kcc::shared_upgrade_hostdir(&spec.expose.mesh.identity.0, slot);
        tokio::fs::create_dir_all(&host_dir)
            .await
            .with_context(|| format!("creating shared upgrade dir {}", host_dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tokio::fs::set_permissions(&host_dir, std::fs::Permissions::from_mode(0o700))
                .await;
        }
        Ok(kcc::PodOptions {
            // Host-networked passway (the F5 ingress) uses the host netns as
            // custodian, so no netns join. An isolated-netns workload would set
            // join_netns to a sandbox/pause container's netns path (deferred).
            join_netns: None,
            shared_dir: Some((host_dir.to_string_lossy().into_owned(), sock_dir)),
        })
    }

    /// The network namespace kamaji binds the custodial listener in. The F5
    /// passway ingress is **host-networked**, so its listener lives in the host
    /// netns (`None`) — the eternal custodian. An isolated-netns workload binds
    /// inside its mesh netns so the fd is routable there; that path is
    /// compile-checked here and E2E-owed (no in-tree isolated-netns passway).
    fn custody_netns(spec: &WorkloadSpec, mesh: &MeshAssignment) -> Option<PathBuf> {
        if spec.wants_host_network() {
            None
        } else {
            mesh.netns_name.as_deref().map(socket_custody::netns_path)
        }
    }

    /// Host-side path of the upgrade socket passway binds for `slot` — the
    /// per-generation shared dir joined with the socket basename. `None` when
    /// the spec declares no `PASSWAY_UPGRADE_SOCK`. This is what kamaji
    /// `connect()`s to when handing off the listen fd.
    fn host_upgrade_sock(&self, spec: &WorkloadSpec, slot: kcc::PodSlot) -> Option<PathBuf> {
        let base = kcc::upgrade_sock_basename(spec)?;
        Some(kcc::shared_upgrade_hostdir(&spec.expose.mesh.identity.0, slot).join(base))
    }

    /// Bind the custodial listener for `ident` on `bind_addr` (optionally inside
    /// `netns`) and hold it. The bind + `setns` may block, so it runs on a
    /// blocking thread. Idempotent across redeploys because the caller releases
    /// custody in `teardown_workload` first.
    async fn custody_bind_and_hold(
        &self,
        ident: &str,
        bind_addr: &str,
        netns: Option<PathBuf>,
    ) -> Result<()> {
        let cust = self.custodian.clone();
        let ident = ident.to_string();
        let bind = bind_addr.to_string();
        let bind_for_ctx = bind.clone();
        tokio::task::spawn_blocking(move || cust.bind_and_hold(&ident, &bind, netns.as_deref()))
            .await
            .context("custody bind_and_hold task join")?
            .with_context(|| format!("binding custodial listener {bind_for_ctx}"))?;
        Ok(())
    }

    /// Hand kamaji's held listen fd(s) for `ident` to a passway process waiting
    /// on the upgrade socket at host path `host_sock` (started in
    /// `PASSWAY_UPGRADE=true` mode). The `sendmsg`/connect-retry blocks, so it
    /// runs on a blocking thread.
    async fn custody_hand_off(&self, ident: &str, host_sock: &Path) -> Result<()> {
        let cust = self.custodian.clone();
        let ident = ident.to_string();
        let ident_for_ctx = ident.clone();
        let host_sock = host_sock.to_path_buf();
        tokio::task::spawn_blocking(move || cust.hand_off(&ident, &host_sock))
            .await
            .context("custody hand_off task join")?
            .with_context(|| format!("handing listen fd to workload {ident_for_ctx}"))?;
        Ok(())
    }

    /// Custody deploy of a passway workload (R600-F9): kamaji binds+holds the
    /// listen socket, starts passway in **upgrade mode** (so it never binds the
    /// address itself), and hands it the held fd. The started container lands in
    /// `slot` and becomes the live generation.
    async fn deploy_custody(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
        slot: kcc::PodSlot,
    ) -> Result<DeployResult> {
        let ident = spec.expose.mesh.identity.clone();
        let bind_addr = kcc::passway_listen_addr(spec);
        let netns = Self::custody_netns(spec, mesh);

        // 1. kamaji binds the listen socket and holds the fd.
        self.custody_bind_and_hold(&ident.0, &bind_addr, netns)
            .await
            .with_context(|| format!("custody deploy of {}", ident.0))?;

        // 2. Start passway in upgrade mode with the per-generation shared mount.
        //    It binds its upgrade sock and waits to *receive* the listen fd.
        let container_id = slot.container_id(&ident.0);
        let pod = self.passway_pod_options(spec, slot).await?;
        let result = match self
            .create_and_start(
                spec,
                mesh,
                &container_id,
                &pod,
                &[format!("{}=true", kcc::PASSWAY_UPGRADE_ENV)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                // Nothing adopted the socket — release custody so a redeploy
                // can rebind cleanly.
                self.custodian.release(&ident.0);
                return Err(e).context("starting custody passway container");
            }
        };

        // 3. Hand the held listen fd to the waiting passway.
        let host_sock = self
            .host_upgrade_sock(spec, slot)
            .ok_or_else(|| anyhow!("passway workload {} declares no upgrade sock", ident.0))?;
        if let Err(e) = self.custody_hand_off(&ident.0, &host_sock).await {
            let _ = self.teardown_container(&container_id).await;
            self.custodian.release(&ident.0);
            return Err(e);
        }

        self.set_slot(&ident, slot);
        tracing::info!(
            ident = %ident.0,
            bind = %bind_addr,
            container_id = %result.container_id,
            "custody deploy: passway adopted kamaji-held listen socket"
        );
        Ok(result)
    }

    /// Borrow the restart ledger so the yubaba supervisor can record exits.
    pub fn ledger(&self) -> &RestartLedger {
        &self.ledger
    }

    /// Override the containerd namespace (useful in tests).
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = ns.into();
        self
    }

    /// Override the log base directory (useful in tests).
    pub fn with_log_base(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_base = path.into();
        self
    }

    fn containers_client(&self) -> ContainersClient<tonic::transport::Channel> {
        kcc::containers_client(&self.channel)
    }

    fn tasks_client(&self) -> TasksClient<tonic::transport::Channel> {
        kcc::tasks_client(&self.channel)
    }

    fn version_client(&self) -> VersionClient<tonic::transport::Channel> {
        kcc::version_client(&self.channel)
    }

    fn snapshots_client(&self) -> SnapshotsClient<tonic::transport::Channel> {
        kcc::snapshots_client(&self.channel)
    }

    /// Prepare an active overlayfs snapshot for `container_id` rooted at the
    /// image's committed layer chain, returning the rootfs mounts to hand to
    /// `CreateTaskRequest`. This is the step the deploy path was missing —
    /// without it the task gets an empty rootfs and runc fails to exec.
    ///
    /// Idempotent: a redeploy whose snapshot already exists falls back to
    /// `Mounts` (read the existing active snapshot's mounts) instead of
    /// erroring. Delegates to `kamaji-containerd-core` (R592-T1) — identical
    /// logic to `kamaji-bin`'s containerd backend.
    async fn prepare_rootfs(
        &self,
        container_id: &str,
        image_target_digest: &str,
    ) -> Result<Vec<containerd_client::types::Mount>> {
        kcc::prepare_rootfs(
            &self.channel,
            &self.namespace,
            container_id,
            image_target_digest,
        )
        .await
    }

    /// Log directory for the given container ID.
    fn log_dir(&self, container_id: &str) -> PathBuf {
        self.log_base.join(&self.namespace).join(container_id)
    }

    /// Full image reference string, e.g. `"ghcr.io/foo/bar:v1.2.3@sha256:..."`.
    /// Digest is structurally required (R438-T3) and always emitted alongside
    /// the tag. Delegates to `kamaji-containerd-core` (R592-T1).
    fn image_ref(spec: &WorkloadSpec) -> String {
        kcc::image_ref(spec)
    }

    /// Map a containerd task status integer to `WorkloadStatus`.
    ///
    /// Containerd task status codes per the protobuf definition:
    ///   0 = Unknown, 1 = Created, 2 = Running, 3 = Stopped, 4 = Paused, 5 = Pausing
    fn map_task_status(code: i32, exit_status: u32) -> WorkloadStatus {
        match code {
            2 => WorkloadStatus::Running,
            // R590-B12: a STOPPED task covers both a clean exit and a failed
            // one — split on the process exit_status so a non-zero exit is
            // Failed, not a silent clean Stopped.
            3 if exit_status == 0 => WorkloadStatus::Stopped,
            3 => WorkloadStatus::Failed {
                reason: format!("exited with status {exit_status}"),
            },
            4 | 5 => WorkloadStatus::Stopping,
            1 => WorkloadStatus::Pending,
            _ => WorkloadStatus::Failed {
                reason: format!("unknown task status code {code}"),
            },
        }
    }
}

// ── ContainerRuntime impl ─────────────────────────────────────────────────────

#[async_trait]
impl Kamaji for ContainerdRuntime {
    fn backend(&self) -> Backend {
        Backend::Containerd
    }

    async fn deploy_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> Result<DeployResult> {
        // Host networking is a privileged escape hatch — it drops network
        // isolation so the container binds host ports directly. Guard it to the
        // infra tier so an ordinary tenant workload cannot request it (bind
        // mounts are gated the same way in workload_spec::validate::shape).
        if spec.wants_host_network() && spec.tier.0 != "infra" {
            anyhow::bail!(
                "workload requests host networking (annotation {}={}) but tier is {:?}; \
                 host networking is only permitted for tier=\"infra\"",
                workload_spec::HOST_NETWORK_ANNOTATION,
                workload_spec::HOST_NETWORK_VALUE,
                spec.tier.0,
            );
        }

        // Idempotent redeploy: reap any prior generation(s) — BOTH pod slots —
        // reset the slot cell, and release any held custody listen socket.
        let _ = self.teardown_workload(&spec.expose.mesh.identity).await;

        // Passway workloads: kamaji is the socket custodian (R600-F9). It binds
        // the listen socket, starts passway in upgrade mode, and hands off the
        // fd — passway never binds the address itself. This supersedes F7's
        // option B (two passway generations refcounting a host-netns socket).
        if kcc::upgrade_sock_dir(spec).is_some() {
            return self.deploy_custody(spec, mesh, kcc::PodSlot::A).await;
        }

        // Ordinary workload — a plain slot-A container (the bare ident), no
        // shared mount, exactly as before.
        let container_id = kcc::PodSlot::A.container_id(&spec.expose.mesh.identity.0);
        let result = self
            .create_and_start(spec, mesh, &container_id, &kcc::PodOptions::default(), &[])
            .await?;

        tracing::info!(
            container_id = %result.container_id,
            mesh_ip = %mesh.mesh_ip,
            task_pid = result.task_pid,
            "workload deployed"
        );
        Ok(result)
    }

    async fn list_workloads(&self) -> Result<Vec<WorkloadState>> {
        let mut ctrs = self.containers_client();
        let mut tasks = self.tasks_client();

        let req = ListContainersRequest {
            filters: vec![format!("labels.\"yah.ident\"!=\"\"")],
        };
        let req = with_namespace!(req, self.namespace);
        let containers = ctrs
            .list(req)
            .await
            .context("listing containerd containers")?
            .into_inner()
            .containers;

        let mut states = Vec::with_capacity(containers.len());
        for c in containers {
            let ident_str = c
                .labels
                .get("yah.ident")
                .cloned()
                .unwrap_or_else(|| c.id.clone());
            let mesh_ip = c.labels.get("yah.mesh_ip").and_then(|s| s.parse().ok());

            // Query task status, then overlay restart-ledger state. `Ok(None)`
            // (no task / container NotFound) and `Err` (probe failure) both
            // mean "not running"; an anomalous status-without-process reply
            // surfaces as code 0 → Failed (see `get_task_status`).
            let base = match get_task_status(&mut tasks, &self.namespace, &c.id).await {
                Ok(Some((code, _pid, exit_status))) => Self::map_task_status(code, exit_status),
                Ok(None) => WorkloadStatus::Stopped,
                Err(_) => WorkloadStatus::Stopped,
            };
            let status = apply_ledger(base, self.ledger.get(&c.id));

            states.push(WorkloadState {
                ident: MeshIdent(ident_str),
                container_id: c.id,
                status,
                mesh_ip,
            });
        }

        Ok(states)
    }

    async fn get_workload(&self, ident: &MeshIdent) -> Result<Option<WorkloadState>> {
        let container_id = self.live_container_id(ident);
        let mut ctrs = self.containers_client();

        let req = GetContainerRequest {
            id: container_id.to_string(),
        };
        let req = with_namespace!(req, self.namespace);
        let container = match ctrs.get(req).await {
            Ok(resp) => resp.into_inner().container,
            Err(status) if status.code() == tonic::Code::NotFound => return Ok(None),
            Err(e) => return Err(anyhow!(e).context(format!("get container {container_id}"))),
        };

        let c = match container {
            Some(c) => c,
            None => return Ok(None),
        };

        let mesh_ip = c.labels.get("yah.mesh_ip").and_then(|s| s.parse().ok());

        let mut tasks = self.tasks_client();
        let base = match get_task_status(&mut tasks, &self.namespace, &container_id).await {
            Ok(Some((code, _pid, exit_status))) => Self::map_task_status(code, exit_status),
            Ok(None) => WorkloadStatus::Stopped,
            Err(_) => WorkloadStatus::Stopped,
        };
        let status = apply_ledger(base, self.ledger.get(&container_id));

        Ok(Some(WorkloadState {
            ident: ident.clone(),
            container_id: c.id,
            status,
            mesh_ip,
        }))
    }

    async fn stream_logs(&self, ident: &MeshIdent, opts: LogOpts) -> Result<LogStream> {
        let container_id = self.live_container_id(ident);
        let log_dir = self.log_dir(&container_id);
        let ident_clone = ident.clone();

        let stdout_path = log_dir.join("stdout.log");
        let stderr_path = log_dir.join("stderr.log");

        // Build a stream that tails stdout (and optionally stderr).
        // Using tokio::fs for async file I/O; tokio_stream::wrappers::LinesStream
        // converts an AsyncBufRead into a Stream<Item = io::Result<String>>.

        let include_stdout = opts
            .stream
            .map(|s| s == LogStreamKind::Stdout)
            .unwrap_or(true);
        let include_stderr = opts
            .stream
            .map(|s| s == LogStreamKind::Stderr)
            .unwrap_or(true);

        let follow = opts.follow;

        // Build per-file streams and merge.
        let stdout_stream: Option<LogStream> = if include_stdout && stdout_path.exists() {
            let file = tokio::fs::File::open(&stdout_path)
                .await
                .with_context(|| format!("opening {}", stdout_path.display()))?;
            let reader = BufReader::new(file);
            let ident = ident_clone.clone();
            let lines = LinesStream::new(reader.lines());
            let stream = TokioStreamExt::filter_map(lines, move |line| {
                line.ok()
                    .map(|msg| LogEvent::plain(ident.clone(), LogStreamKind::Stdout, msg))
            });
            Some(Box::pin(stream))
        } else {
            None
        };

        let stderr_stream: Option<LogStream> = if include_stderr && stderr_path.exists() {
            let file = tokio::fs::File::open(&stderr_path)
                .await
                .with_context(|| format!("opening {}", stderr_path.display()))?;
            let reader = BufReader::new(file);
            let ident = ident_clone.clone();
            let lines = LinesStream::new(reader.lines());
            let stream = TokioStreamExt::filter_map(lines, move |line| {
                line.ok()
                    .map(|msg| LogEvent::plain(ident.clone(), LogStreamKind::Stderr, msg))
            });
            Some(Box::pin(stream))
        } else {
            None
        };

        // Merge the two streams.
        let merged: LogStream = match (stdout_stream, stderr_stream) {
            (Some(a), Some(b)) => Box::pin(tokio_stream::StreamExt::merge(a, b)),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => Box::pin(tokio_stream::empty()),
        };

        // If not following, close the stream once existing lines are consumed.
        // tokio_stream doesn't have a native "read until EOF then close"
        // adapter; instead we rely on the file stream closing at EOF naturally
        // when `follow = false`. For `follow = true` a full inotify/kqueue
        // based tail implementation is needed — that lands with the beholder
        // service in R091 later. For now, the stream drains existing lines.
        let _ = follow; // placeholder until tail-follow impl

        Ok(merged)
    }

    /// Containerd graceful upgrade (R600-F9 / W273, superseding F7) — a
    /// **zero-downtime** cert reload where **kamaji owns the listening socket**
    /// (option C, the socket-custodian). Unlike F7's option B (two passway
    /// generations refcounting a host-netns socket, the *outgoing* one sending
    /// its fds on `SIGQUIT`), here every passway generation — including the one
    /// deployed first — adopts kamaji's held fd, so the socket's lifetime is
    /// kamaji's, independent of any passway process, and this generalizes to
    /// every workload (it is the same primitive R599-F6's JIT path uses).
    ///
    /// The dance (kamaji is the sole fd sender — passway never self-`SIGQUIT`s):
    /// 1. Start the **incoming** passway container in the *other* pod slot with
    ///    `PASSWAY_UPGRADE=true` and its own per-generation upgrade-sock bind
    ///    mount. pingora binds that socket and waits to *receive* fds.
    /// 2. kamaji `hand_off`s its held listen fd to the incoming process over the
    ///    host-side upgrade sock path. The incoming passway adopts it and starts
    ///    serving alongside the outgoing one (the fd is kernel-refcounted).
    /// 3. Let it settle; if it died during handoff (e.g. an unreadable cert),
    ///    abort **without** touching the outgoing container — it keeps serving
    ///    the old cert on the same kamaji-held socket rather than dropping out.
    /// 4. `SIGQUIT` the **outgoing** container to drain it. Its own SIGQUIT
    ///    fd-send targets its (now stale, per-generation) upgrade sock, finds no
    ///    receiver and fails benignly; pingora drains + exits regardless. The
    ///    listening socket survives because kamaji holds it.
    /// 5. Reap the outgoing container and flip the live pod slot.
    ///
    /// Linux/containerd-only; the orchestration is compile-checked here and the
    /// live E2E is owed on a privileged host (OrbStack / a fleet node), same
    /// posture as the rest of R600.
    async fn graceful_upgrade_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> Result<DeployResult> {
        let ident = spec.expose.mesh.identity.clone();

        // Only a passway-shaped workload (one that declares PASSWAY_UPGRADE_SOCK)
        // has the pingora fd-adoption path. Anything else has no zero-downtime
        // route — fall back to a plain redeploy.
        if kcc::upgrade_sock_dir(spec).is_none() {
            tracing::warn!(
                ident = %ident.0,
                "graceful_upgrade_workload: spec declares no PASSWAY_UPGRADE_SOCK; \
                 falling back to a connection-dropping redeploy"
            );
            return self.deploy_workload(spec, mesh).await;
        }

        // If kamaji isn't holding the socket (never custody-deployed, or kamaji
        // restarted), or the current generation isn't running, a fresh custody
        // deploy is the only correct move — it rebinds the socket and lands a
        // live slot-A generation. deploy_workload releases any stale custody
        // first, so rebinding can't collide.
        let current_slot = self
            .slots
            .lock()
            .unwrap()
            .get(&ident.0)
            .copied()
            .unwrap_or_default();
        let current_id = current_slot.container_id(&ident.0);
        let running = matches!(
            self.container_status(&current_id).await,
            Some(WorkloadStatus::Running | WorkloadStatus::Restarting { .. })
        );
        if !self.custodian.holds(&ident.0) || !running {
            tracing::info!(
                ident = %ident.0,
                holds = self.custodian.holds(&ident.0),
                running,
                "graceful_upgrade_workload: no live custody instance; deploying fresh"
            );
            return self.deploy_workload(spec, mesh).await;
        }

        let incoming_slot = current_slot.other();
        let incoming_id = incoming_slot.container_id(&ident.0);

        // Per-generation upgrade-sock bind mount for the incoming container so
        // kamaji can reach its upgrade sock from the host mount namespace.
        let pod = self.passway_pod_options(spec, incoming_slot).await?;

        // Clear any stale incoming-slot container from a previously-aborted
        // upgrade (NEVER the live outgoing one).
        self.teardown_container(&incoming_id).await?;

        // 1. Start the incoming passway in upgrade mode (waits for the fd).
        let result = self
            .create_and_start(
                spec,
                mesh,
                &incoming_id,
                &pod,
                &[format!("{}=true", kcc::PASSWAY_UPGRADE_ENV)],
            )
            .await
            .context("starting graceful-upgrade replacement container")?;

        // 2. kamaji hands its held listen fd to the incoming passway.
        let host_sock = self
            .host_upgrade_sock(spec, incoming_slot)
            .ok_or_else(|| anyhow!("passway workload {} declares no upgrade sock", ident.0))?;
        if let Err(e) = self.custody_hand_off(&ident.0, &host_sock).await {
            let _ = self.teardown_container(&incoming_id).await;
            return Err(e).with_context(|| {
                format!(
                    "workload {}: handing listen fd to replacement failed; \
                     outgoing left serving on the kamaji-held socket",
                    ident.0
                )
            });
        }

        // 3. Settle. If the replacement isn't running, abort and leave the
        //    outgoing one serving on the same kamaji-held socket.
        tokio::time::sleep(UPGRADE_SETTLE).await;
        match self.container_status(&incoming_id).await {
            Some(WorkloadStatus::Running) => {}
            other => {
                let _ = self.teardown_container(&incoming_id).await;
                anyhow::bail!(
                    "workload {}: graceful-upgrade replacement is not running after settle \
                     ({other:?}); outgoing instance left serving",
                    ident.0
                );
            }
        }

        // 4. SIGQUIT the outgoing container to drain it. kamaji is the sole fd
        //    sender; the outgoing's own SIGQUIT fd-send hits its stale per-gen
        //    sock, fails benignly, and pingora drains + exits regardless.
        self.sigquit_task(&current_id)
            .await
            .with_context(|| format!("signalling outgoing container {current_id}"))?;

        // 5. Give the old process its stop grace to drain in-flight connections,
        //    then reap it. The listening socket is safe in kamaji (and the
        //    incoming process holds a copy), so this drops nothing.
        let grace = Duration::from_millis(spec.stop_policy.grace_period.0);
        tokio::time::sleep(grace).await;
        let _ = self.teardown_container(&current_id).await;

        // 6. The incoming generation now backs the identity.
        self.set_slot(&ident, incoming_slot);

        tracing::info!(
            ident = %ident.0,
            from = %current_id,
            to = %incoming_id,
            "graceful cert-reload upgrade complete (zero dropped connections)"
        );
        Ok(result)
    }

    async fn restart_workload(&self, ident: &MeshIdent) -> Result<()> {
        let container_id = self.live_container_id(ident);
        let mut tasks = self.tasks_client();

        // Send SIGTERM.
        let req = KillRequest {
            container_id: container_id.to_string(),
            exec_id: String::new(),
            signal: 15, // SIGTERM
            all: false,
        };
        let req = with_namespace!(req, self.namespace);
        tasks
            .kill(req)
            .await
            .with_context(|| format!("SIGTERM {container_id}"))?;

        // Wait briefly for graceful exit, then start a new task.
        tokio::time::sleep(Duration::from_secs(5)).await;

        let req = StartRequest {
            container_id: container_id.to_string(),
            exec_id: String::new(),
        };
        let req = with_namespace!(req, self.namespace);
        tasks
            .start(req)
            .await
            .with_context(|| format!("restarting task for {container_id}"))?;

        tracing::info!(container_id = %container_id, "workload restarted");
        Ok(())
    }

    async fn teardown_workload(&self, ident: &MeshIdent) -> Result<()> {
        // Reap BOTH ping-pong slots (R600-F7): after a graceful upgrade the live
        // container is `<ident>.b`, and a slot-A container may linger if a prior
        // upgrade's reap raced a teardown. Removing both leaves no orphan, and
        // NotFound on the absent slot is benign.
        for slot in [kcc::PodSlot::A, kcc::PodSlot::B] {
            let container_id = slot.container_id(&ident.0);
            self.teardown_container(&container_id).await?;
        }
        self.clear_slot(ident);
        // Close kamaji's held listen socket for this workload (R600-F9). No-op
        // for ordinary (non-custody) workloads; idempotent.
        self.custodian.release(&ident.0);
        Ok(())
    }

    async fn health(&self) -> Result<RuntimeHealth> {
        let mut ver = self.version_client();
        let req = tonic::Request::new(());
        match ver.version(req).await {
            Ok(resp) => {
                let v = resp.into_inner();
                Ok(RuntimeHealth {
                    ok: true,
                    version: Some(v.version),
                    detail: None,
                })
            }
            Err(e) => Ok(RuntimeHealth {
                ok: false,
                version: None,
                detail: Some(e.to_string()),
            }),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Query the status + pid of a containerd task (best-effort). Delegates to
/// `kamaji-containerd-core` (R592-T1) — identical logic to `kamaji-bin`'s
/// containerd backend, which also needs the pid (this shape doesn't, and
/// discards it at the call sites).
///
/// Folding preserves this shape's pre-R592-T1 semantics: a
/// status-without-process reply surfaces as code `0`, which
/// [`ContainerdBackend::map_task_status`] maps to `Failed { "unknown task
/// status code 0" }` — it is an anomaly, not a clean stop. Only a true
/// no-task/`NotFound` probe becomes `None` ("not running").
async fn get_task_status(
    tasks: &mut TasksClient<tonic::transport::Channel>,
    namespace: &str,
    container_id: &str,
) -> Result<Option<(i32, u32, u32)>> {
    Ok(
        match kcc::get_task_status(tasks, namespace, container_id).await? {
            kcc::TaskProbe::Status {
                code,
                pid,
                exit_status,
            } => Some((code, pid, exit_status)),
            kcc::TaskProbe::MissingProcess => Some((0, 0, 0)),
            kcc::TaskProbe::NoTask => None,
        },
    )
}

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        ExposeSpec, ImageRef, MeshExpose, Millis, NamespaceId, ResourceLimits, RestartPolicy,
        SchemaVersion, StopPolicy, TenantId, TierTag, WorkloadSpec,
    };

    /// Returns `true` when a containerd socket is reachable. Used to skip
    /// tests on machines without containerd (standard CI, most dev Macs).
    async fn containerd_available() -> bool {
        ContainerdRuntime::connect().await.is_ok()
    }

    fn test_spec(name: &str) -> WorkloadSpec {
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.to_string(),
            image: ImageRef {
                registry: "docker.io".to_string(),
                repository: "library/alpine".to_string(),
                tag: "latest".to_string(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".to_string()),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            replicas: 1,
            command: Some(vec!["sleep".to_string(), "30".to_string()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 64,
                cpu_millis: 128,
                ephemeral_storage_mb: 128,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Never,
            archetype: None,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(name.to_string()),
                    ports: vec![],
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        }
    }

    fn netns_present(oci: &serde_json::Value) -> bool {
        oci["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["type"] == "network")
    }

    // chain_id and the pure build_oci_spec-shape assertions (network
    // isolation, /sys mount strategy, capability set) now live once in
    // `kamaji-containerd-core`'s own test module (R592-T1) — this crate
    // keeps only the integration-shaped assertion below, which exercises
    // this shape's specific call site: the mesh-env injection `create_and_start`
    // performs before `kcc::build_oci_spec_with`.

    #[test]
    fn oci_spec_injects_mesh_ip_after_literal_env() {
        let mesh = MeshAssignment::stub("10.64.0.9".parse().unwrap());
        // Mirror what `create_and_start` builds: mesh IP appended as extra env,
        // default pod placement.
        let deploy_env = vec![format!("YAH_MESH_IP={}", mesh.mesh_ip)];
        let oci = kcc::build_oci_spec(&test_spec("svc"), &deploy_env, None);
        assert!(
            netns_present(&oci),
            "default workload must get an isolated netns"
        );
        let env = oci["process"]["env"].as_array().unwrap();
        assert_eq!(
            env.last().unwrap().as_str().unwrap(),
            "YAH_MESH_IP=10.64.0.9",
            "mesh ip must be appended after the spec's literal env vars"
        );
    }

    #[test]
    fn ledger_record_exit_increments_count_and_arms_in_flight() {
        let ledger = RestartLedger::new();
        ledger.record_exit("c1", 137);
        let r = ledger.get("c1").unwrap();
        assert_eq!(r.restart_count, 1);
        assert_eq!(r.last_exit_code, 137);
        assert!(r.in_flight);

        ledger.record_exit("c1", 2);
        let r = ledger.get("c1").unwrap();
        assert_eq!(r.restart_count, 2);
        assert_eq!(r.last_exit_code, 2);
        assert!(r.in_flight);
    }

    #[test]
    fn ledger_mark_running_clears_in_flight_preserves_count() {
        let ledger = RestartLedger::new();
        ledger.record_exit("c1", 1);
        ledger.mark_running("c1");
        let r = ledger.get("c1").unwrap();
        assert_eq!(r.restart_count, 1);
        assert!(!r.in_flight);
    }

    #[test]
    fn apply_ledger_upgrades_stopped_to_restarting_when_in_flight() {
        let ledger = RestartLedger::new();
        ledger.record_exit("c1", 137);
        let status = apply_ledger(WorkloadStatus::Stopped, ledger.get("c1"));
        match status {
            WorkloadStatus::Restarting {
                last_exit_code,
                restart_count,
                last_finished_at_unix_ms,
            } => {
                assert_eq!(last_exit_code, 137);
                assert_eq!(restart_count, 1);
                assert!(last_finished_at_unix_ms > 0);
            }
            other => panic!("expected Restarting, got {other:?}"),
        }
    }

    #[test]
    fn apply_ledger_passthrough_when_no_record_or_not_in_flight() {
        // No record → base unchanged.
        assert_eq!(
            apply_ledger(WorkloadStatus::Stopped, None),
            WorkloadStatus::Stopped
        );

        // Record exists but in_flight cleared → base unchanged (crash-loop paused).
        let ledger = RestartLedger::new();
        ledger.record_exit("c1", 1);
        ledger.mark_running("c1");
        assert_eq!(
            apply_ledger(WorkloadStatus::Stopped, ledger.get("c1")),
            WorkloadStatus::Stopped
        );

        // Even with an in-flight record, Running stays Running.
        ledger.record_exit("c1", 1);
        assert_eq!(
            apply_ledger(WorkloadStatus::Running, ledger.get("c1")),
            WorkloadStatus::Running
        );
    }

    #[test]
    fn apply_ledger_upgrades_failed_to_restarting() {
        let ledger = RestartLedger::new();
        ledger.record_exit("c1", 1);
        let status = apply_ledger(
            WorkloadStatus::Failed {
                reason: "exit 1".into(),
            },
            ledger.get("c1"),
        );
        assert!(matches!(status, WorkloadStatus::Restarting { .. }));
    }

    #[test]
    fn restarting_serde_round_trips_through_json() {
        // Verifies the yubaba HTTP API surface: WorkloadStatus::Restarting
        // must serialize as `{type: "restarting", ...}` and deserialize back.
        let original = WorkloadStatus::Restarting {
            last_exit_code: 2,
            restart_count: 5,
            last_finished_at_unix_ms: 1_700_000_000_000,
        };
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("\"type\":\"restarting\""));
        let parsed: WorkloadStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
        assert!(!original.is_terminal(), "Restarting must not be terminal");
    }

    #[tokio::test]
    async fn runtime_health_returns_ok_or_degraded() {
        if !containerd_available().await {
            eprintln!("SKIP: containerd not reachable (run with --features containerd-integration on a host with containerd)");
            return;
        }
        let rt = ContainerdRuntime::connect().await.unwrap();
        let h = rt.health().await.unwrap();
        assert!(h.ok, "expected healthy containerd: {:?}", h.detail);
        assert!(h.version.is_some(), "expected version string");
    }

    #[tokio::test]
    async fn deploy_get_teardown() {
        if !containerd_available().await {
            eprintln!("SKIP: containerd not reachable");
            return;
        }
        let rt = ContainerdRuntime::connect()
            .await
            .unwrap()
            .with_namespace("yah-test");

        let spec = test_spec("test-deploy-get-teardown");
        let mesh = MeshAssignment::stub("10.64.0.1".parse().unwrap());

        // Deploy
        let result = rt.deploy_workload(&spec, &mesh).await.unwrap();
        assert_eq!(result.container_id, "test-deploy-get-teardown");
        assert!(result.task_pid > 0);

        // Get
        let state = rt
            .get_workload(&spec.expose.mesh.identity)
            .await
            .unwrap()
            .expect("workload should exist after deploy");
        assert_eq!(state.status, WorkloadStatus::Running);

        // Teardown
        rt.teardown_workload(&spec.expose.mesh.identity)
            .await
            .unwrap();

        // Should be gone
        let after = rt.get_workload(&spec.expose.mesh.identity).await.unwrap();
        assert!(after.is_none(), "workload should be absent after teardown");
    }

    #[tokio::test]
    async fn list_workloads_empty_when_no_containers() {
        if !containerd_available().await {
            eprintln!("SKIP: containerd not reachable");
            return;
        }
        let rt = ContainerdRuntime::connect()
            .await
            .unwrap()
            .with_namespace("yah-test-list-empty");
        let list = rt.list_workloads().await.unwrap();
        assert!(
            list.is_empty(),
            "expected empty namespace, found {} containers",
            list.len()
        );
    }

    #[tokio::test]
    async fn stream_logs_returns_output() {
        if !containerd_available().await {
            eprintln!("SKIP: containerd not reachable");
            return;
        }
        let tmp = tempfile::TempDir::new().unwrap();
        let rt = ContainerdRuntime::connect()
            .await
            .unwrap()
            .with_namespace("yah-test-logs")
            .with_log_base(tmp.path());

        let spec = test_spec("test-log-stream");
        let mesh = MeshAssignment::stub("10.64.0.2".parse().unwrap());

        rt.deploy_workload(&spec, &mesh).await.unwrap();

        // Give the container a moment to write to stdout.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let opts = LogOpts {
            tail: Some(100),
            follow: false,
            stream: Some(LogStreamKind::Stdout),
        };
        let mut log_stream = rt
            .stream_logs(&spec.expose.mesh.identity, opts)
            .await
            .unwrap();

        use tokio_stream::StreamExt as _;
        let mut events = vec![];
        while let Some(ev) = log_stream.next().await {
            events.push(ev);
        }

        rt.teardown_workload(&spec.expose.mesh.identity)
            .await
            .unwrap();

        // Alpine `sleep 30` writes nothing to stdout — just ensure we got the
        // stream without error. A more useful test would use `echo` as the
        // command; update in R091-F5 when the full E2E harness lands.
        println!("log events: {}", events.len());
    }
}

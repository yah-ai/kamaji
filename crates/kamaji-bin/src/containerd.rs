//! Kamaji's containerd backend (R406-T9).
//!
//! ## Why this lives in Kamaji, not in Yubaba
//!
//! Per [W154](../../../../.yah/docs/working/W154-yubaba-dual-runtime.md)
//! §"Kamaji's native driver" and §"Impact on yubaba codebase":
//!
//! > Existing crates/yah/yubaba/: trimmed to mesh/raft/admission/federation.
//! > Drops direct knowledge of containerd internals; talks to Kamaji over
//! > UDS for all workload lifecycle.
//!
//! Containerd is one of Kamaji's two backends (the other is `native` —
//! see [`crate::native`]). Both consume the same enriched `WorkloadSpec`
//! after Kamaji applies the WorkloadSpec enforcement layer (capabilities,
//! secret mounts, MeshIdent-aware bindings). Yubaba owns admission and
//! mesh-IP allocation; the spec arrives already mesh-resolved.
//!
//! ## Gating
//!
//! This module compiles only under `--features containerd-integration` so
//! the dev binary and pond's inner kamaji (which uses the host docker
//! socket via a separate backend) don't carry tonic + the containerd-client
//! stack.
//!
//! ## Shape
//!
//! - One `ContainerdBackend` per Kamaji instance, holding the tonic
//!   `Channel`. Cheap to clone; the inner channel is `Arc`-wrapped.
//! - All yah-managed containers live in containerd namespace `"yah"`.
//! - Container IDs derive from the [`WorkloadId`] passed in `Deploy` (stable
//!   across Kamaji restarts so reconciliation can match).
//! - Each call returns `Result<_, BackendError>`; the server layer maps
//!   these to `KamajiToYubaba::Error { code, message }` for the wire.

#![cfg(feature = "containerd-integration")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use containerd_client::{
    services::v1::{
        container::Runtime as ContainerRuntime,
        containers_client::ContainersClient,
        snapshots::{snapshots_client::SnapshotsClient, RemoveSnapshotRequest},
        tasks_client::TasksClient,
        version_client::VersionClient,
        Container, CreateContainerRequest, CreateTaskRequest, DeleteContainerRequest,
        GetContainerRequest, KillRequest, ListContainersRequest, StartRequest,
    },
    tonic::{transport::Channel, Request},
    with_namespace,
};
use kamaji_containerd_core as kcc;
use kamaji_proto::{WorkloadEntry, WorkloadId, WorkloadState};
use thiserror::Error;
use tokio::task::AbortHandle;
use tracing::{info, warn};
use workload_spec::{EnvValue, WorkloadSpec};

use crate::journal::{LogSink, Stream};

// Socket path / namespace / log-base constants, OCI-spec building,
// image/rootfs resolution, and task-status querying are shared with the
// inlined `kamaji` crate's containerd backend via `kamaji-containerd-core`
// (R592-T1) — see that crate for the single definitions re-exported here.
pub use kamaji_containerd_core::{DEFAULT_SOCKET, LOG_BASE, YAH_NAMESPACE};

/// Errors surfaced by the backend. The server layer maps these to wire
/// `ErrorCode` variants.
#[derive(Debug, Error)]
pub enum BackendError {
    /// The provided workload spec failed validation Kamaji applies
    /// before dispatching to containerd (unresolved `FromSecret`/`FromMesh`
    /// env, etc.). Maps to `ErrorCode::InvalidSpec`.
    #[error("invalid spec: {0}")]
    InvalidSpec(String),

    /// Containerd refused or failed a syscall — connection dropped, image
    /// missing, task creation refused. Maps to `ErrorCode::BackendRefused`.
    #[error("containerd: {0}")]
    Containerd(#[from] anyhow::Error),
}

/// Per-workload state Kamaji tracks for cancellation. R406-T10 stores
/// the abort handles for the stdout/stderr journald forwarder tasks so
/// teardown can stop them deterministically (the workload's writer side
/// of an `O_RDWR` FIFO would otherwise keep the reader's loop alive).
#[derive(Debug, Default)]
struct WorkloadTracking {
    forwarders: Vec<AbortHandle>,
    fifo_paths: Vec<PathBuf>,
}

/// Connection + per-instance config for the containerd backend.
#[derive(Clone, Debug)]
pub struct ContainerdBackend {
    channel: Channel,
    namespace: String,
    log_base: PathBuf,
    /// Sink for forwarded log lines (R406-T10). Defaults to a sink that
    /// silently drops everything; production attaches a [`crate::JournalSender`]
    /// via [`with_log_sink`].
    log_sink: Arc<dyn LogSink>,
    /// Per-workload forwarder handles and FIFO paths. Wrapped in `Arc<Mutex<>>`
    /// so deploy and teardown can mutate from inside async fns without
    /// requiring `&mut self`.
    tracked: Arc<Mutex<HashMap<WorkloadId, WorkloadTracking>>>,
    /// Socket custodian for passway workloads (R600-F9). kamaji binds+holds a
    /// passway workload's listen socket at deploy and hands the fd to each
    /// process generation, so a cert reload can hot-swap the passway process
    /// without ever closing the listener — no dropped connections. Lives for
    /// the daemon's lifetime, so the held fd survives passway restarts.
    custodian: Arc<kamaji::socket_custody::SocketCustodian>,
}

impl ContainerdBackend {
    /// Connect to the default containerd socket.
    pub async fn connect() -> Result<Self> {
        Self::connect_at(DEFAULT_SOCKET).await
    }

    /// Connect to an explicit socket path. Use for Colima on dev hosts
    /// (`~/.colima/default/containerd.sock`).
    pub async fn connect_at(socket: impl AsRef<std::path::Path>) -> Result<Self> {
        let channel = kcc::connect(socket).await?;
        Ok(Self {
            channel,
            namespace: YAH_NAMESPACE.to_string(),
            log_base: PathBuf::from(LOG_BASE),
            log_sink: Arc::new(NoopSink),
            tracked: Arc::new(Mutex::new(HashMap::new())),
            custodian: Arc::new(kamaji::socket_custody::SocketCustodian::new()),
        })
    }

    /// Override the namespace (testing).
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = ns.into();
        self
    }

    /// Override the log base (testing).
    pub fn with_log_base(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_base = path.into();
        self
    }

    /// Attach a log sink. The production binary passes the kamaji-wide
    /// [`crate::JournalSender`] here at startup; tests pass a
    /// [`crate::journal::VecSink`].
    pub fn with_log_sink(mut self, sink: Arc<dyn LogSink>) -> Self {
        self.log_sink = sink;
        self
    }

    fn containers_client(&self) -> ContainersClient<Channel> {
        kcc::containers_client(&self.channel)
    }

    fn tasks_client(&self) -> TasksClient<Channel> {
        kcc::tasks_client(&self.channel)
    }

    fn version_client(&self) -> VersionClient<Channel> {
        kcc::version_client(&self.channel)
    }

    fn snapshots_client(&self) -> SnapshotsClient<Channel> {
        kcc::snapshots_client(&self.channel)
    }

    /// Prepare an active overlayfs snapshot for `container_id` rooted at the
    /// image's committed layer chain, returning the rootfs mounts to hand to
    /// `CreateTaskRequest`. Without this the task gets an empty rootfs and runc
    /// fails to exec the entrypoint. Delegates to `kamaji-containerd-core`
    /// (R592-T1) — identical logic to the inlined `kamaji` crate's
    /// containerd backend.
    ///
    /// Idempotent: a redeploy whose snapshot already exists falls back to
    /// `Mounts` (read the existing active snapshot's mounts) instead of erroring.
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

    fn log_dir(&self, container_id: &str) -> PathBuf {
        self.log_base.join(&self.namespace).join(container_id)
    }

    /// Full image reference string used as the containerd image key.
    /// Digest is structurally required (R438-T3) and always pinned alongside
    /// the human-readable tag. Delegates to `kamaji-containerd-core`
    /// (R592-T1).
    fn image_ref(spec: &WorkloadSpec) -> String {
        kcc::image_ref(spec)
    }

    /// Deploy a workload. The `id` is what Kamaji's registry keys on and
    /// what surfaces in `KamajiToYubaba::WorkloadStarted` / lifecycle
    /// events. Returns the OS pid containerd reports for the new task.
    ///
    /// A passway (custody) workload — one declaring `PASSWAY_UPGRADE_SOCK` —
    /// is routed through [`deploy_custody`](Self::deploy_custody): kamaji binds
    /// and holds its listen socket, so a later cert reload can hot-swap the
    /// process with **zero dropped connections** (R600-F9). Ordinary workloads
    /// take the plain path (no pod placement, no custody).
    pub async fn deploy(&self, id: &WorkloadId, spec: &WorkloadSpec) -> Result<u32, BackendError> {
        if kcc::upgrade_sock_dir(spec).is_some() {
            return self.deploy_custody(id, spec).await;
        }
        self.deploy_generation(id, spec, &kcc::PodOptions::default(), &[])
            .await
    }

    /// Create + start one containerd generation of `spec` under container id
    /// `id.as_str()`, with pod placement `pod` and extra process env
    /// `extra_env` (e.g. `PASSWAY_UPGRADE=true` for a custody passway). This is
    /// the shared body behind [`deploy`](Self::deploy),
    /// [`deploy_custody`](Self::deploy_custody), and
    /// [`graceful_upgrade`](Self::graceful_upgrade); it tears down any prior
    /// same-id generation first (idempotent redeploy).
    async fn deploy_generation(
        &self,
        id: &WorkloadId,
        spec: &WorkloadSpec,
        pod: &kcc::PodOptions,
        extra_env: &[String],
    ) -> Result<u32, BackendError> {
        validate_spec_for_constable(spec)?;
        let container_id = id.as_str().to_string();
        let image_ref = Self::image_ref(spec);

        // Verify the image is in containerd's image store and grab its target
        // descriptor digest — we walk that (manifest → config → diff_ids) to
        // prepare the rootfs snapshot below. Callers (yubaba admission,
        // R040-F11's bootstrap) are expected to have pre-pulled the image via
        // `ctr images pull` or the MachineProvider bootstrap path. Delegates
        // to `kamaji-containerd-core` (R592-T1) — identical logic to the
        // inlined `kamaji` crate's containerd backend.
        let image_target_digest =
            kcc::resolve_image_target_digest(&self.channel, &self.namespace, &image_ref)
                .await
                .map_err(BackendError::Containerd)?;

        // Image OCI config (ENTRYPOINT/CMD/ENV/WORKDIR/USER) to merge into the
        // process spec per docker/OCI convention (R590-B8). Best-effort: an
        // image without a readable config just contributes nothing — the
        // workload then runs with its spec-only argv/env, the prior behavior.
        let image_config =
            kcc::image_oci_config(&self.channel, &self.namespace, &image_target_digest)
                .await
                .ok();

        // OCI spec — capabilities, mounts, namespaces, cgroup path, plus any
        // custody pod placement (shared upgrade-sock bind mount) and extra env.
        let oci_spec = kcc::build_oci_spec_with(spec, extra_env, image_config.as_ref(), pod);
        let spec_bytes = serde_json::to_vec(&oci_spec)
            .context("serializing OCI spec")
            .map_err(BackendError::Containerd)?;
        let any_spec = prost_types::Any {
            type_url: "types.containerd.io/opencontainers/runtime-spec/1/Spec".to_string(),
            value: spec_bytes,
        };

        // Log fan-in to journald (R406-T10): mkfifo per stream, point
        // containerd at the FIFO paths, open the read side ourselves, and
        // spawn one forward_reader task per stream. The forwarders' abort
        // handles are tracked so teardown can stop them.
        let log_dir = self.log_dir(&container_id);
        tokio::fs::create_dir_all(&log_dir)
            .await
            .with_context(|| format!("creating log dir {}", log_dir.display()))
            .map_err(BackendError::Containerd)?;
        let stdout_fifo = log_dir.join("stdout.fifo");
        let stderr_fifo = log_dir.join("stderr.fifo");

        // Idempotent redeploy: reap any prior container with the same id
        // before recreating. reap_container is idempotent (missing -> Ok) and
        // unlinks stale FIFOs / aborts prior forwarders — and, unlike the public
        // teardown, keeps any held custody socket so a custody redeploy /
        // graceful recycle doesn't drop kamaji's listener (R600-F9).
        let _ = self.reap_container(id).await;

        ensure_fifo(&stdout_fifo)
            .with_context(|| format!("mkfifo {}", stdout_fifo.display()))
            .map_err(BackendError::Containerd)?;
        ensure_fifo(&stderr_fifo)
            .with_context(|| format!("mkfifo {}", stderr_fifo.display()))
            .map_err(BackendError::Containerd)?;

        let stdout_path = stdout_fifo.to_string_lossy().into_owned();
        let stderr_path = stderr_fifo.to_string_lossy().into_owned();

        // Spawn the journald forwarders BEFORE CreateTask: the shim opens
        // the FIFOs' write ends *during task creation* with a plain O_WRONLY
        // open, which blocks until a reader exists — with no forwarder yet,
        // task creation deadlocks and containerd kills it at its deadline
        // ("opening w/o fifo ... context deadline exceeded"; found live on
        // us-east-001, first real-shim run of this path). The forwarders
        // open their read end O_RDWR, so starting them early is safe: they
        // simply idle until the shim connects. Tracking is inserted now so
        // a failed create's redeploy tears the forwarders down via the
        // idempotent teardown above.
        let stdout_handle = spawn_forwarder(
            self.log_sink.clone(),
            id.clone(),
            Stream::Stdout,
            &stdout_fifo,
        )?;
        let stderr_handle = spawn_forwarder(
            self.log_sink.clone(),
            id.clone(),
            Stream::Stderr,
            &stderr_fifo,
        )?;
        {
            let mut tracked = self.tracked.lock().expect("tracked mutex poisoned");
            tracked.insert(
                id.clone(),
                WorkloadTracking {
                    forwarders: vec![stdout_handle, stderr_handle],
                    fifo_paths: vec![stdout_fifo.clone(), stderr_fifo.clone()],
                },
            );
        }

        // Create the container record.
        {
            let mut ctrs = self.containers_client();
            let labels = labels_for(spec, id);
            let container = Container {
                id: container_id.clone(),
                image: image_ref.clone(),
                runtime: Some(ContainerRuntime {
                    name: "io.containerd.runc.v2".to_string(),
                    options: None,
                }),
                spec: Some(any_spec),
                snapshotter: "overlayfs".to_string(),
                snapshot_key: container_id.clone(),
                labels,
                ..Default::default()
            };
            let req = CreateContainerRequest {
                container: Some(container),
            };
            let req = with_namespace!(req, self.namespace);
            ctrs.create(req)
                .await
                .with_context(|| format!("creating container {container_id}"))
                .map_err(BackendError::Containerd)?;
        }

        // Prepare the rootfs snapshot from the image's committed layer chain.
        // Without this the task gets an empty rootfs and runc can't exec the
        // entrypoint (shared with the inlined shape via kamaji-containerd-core, R592-T1).
        let rootfs_mounts = self
            .prepare_rootfs(&container_id, &image_target_digest)
            .await
            .with_context(|| format!("preparing rootfs for {container_id}"))?;

        // Create + start the task (the live execution instance).
        //
        // R854: via `create_task_reaping_stale`, so a task record that outlived
        // the reap above (a shim slow to publish its exit) is torn down and the
        // create retried once, rather than 500ing the deploy on "already
        // exists" and leaving the workload down until an operator happens to
        // redeploy a third time.
        let pid = {
            let mut tasks = self.tasks_client();
            let req = CreateTaskRequest {
                container_id: container_id.clone(),
                rootfs: rootfs_mounts,
                stdin: String::new(),
                stdout: stdout_path,
                stderr: stderr_path,
                terminal: false,
                checkpoint: None,
                options: None,
                ..Default::default()
            };
            kcc::create_task_reaping_stale(&mut tasks, &self.namespace, req)
                .await
                .with_context(|| format!("creating task for {container_id}"))
                .map_err(BackendError::Containerd)?
        };
        {
            let mut tasks = self.tasks_client();
            let req = StartRequest {
                container_id: container_id.clone(),
                exec_id: String::new(),
            };
            let req = with_namespace!(req, self.namespace);
            tasks
                .start(req)
                .await
                .with_context(|| format!("starting task for {container_id}"))
                .map_err(BackendError::Containerd)?;
        }

        // (Journald forwarders were spawned before CreateTask above — the
        // shim's write-only FIFO open during task creation needs a live
        // reader or it deadlocks.)

        info!(
            container_id = %container_id,
            pid = pid,
            image = %image_ref,
            "kamaji: containerd workload deployed"
        );
        Ok(pid)
    }

    /// Custody deploy of a passway workload (R600-F9). kamaji binds+holds the
    /// listen socket, starts passway in **upgrade mode** (so it never binds the
    /// address itself), and hands it the held fd. Because kamaji owns the
    /// socket, a later [`graceful_upgrade`](Self::graceful_upgrade) can swap the
    /// passway process without the listener ever closing.
    ///
    /// The sibling daemon has no `MeshAssignment`, so the custodial listener is
    /// bound in the **host** netns — which is exactly right for the F5 passway
    /// ingress (host-networked, the only in-tree custody consumer). A
    /// non-host-networked passway is rejected: there is no netns to bind in here.
    async fn deploy_custody(
        &self,
        id: &WorkloadId,
        spec: &WorkloadSpec,
    ) -> Result<u32, BackendError> {
        if !spec.wants_host_network() {
            return Err(BackendError::InvalidSpec(format!(
                "passway custody workload {} is not host-networked; the sibling \
                 daemon can only bind the custodial listener in the host netns \
                 (isolated-netns custody is not wired here)",
                id.as_str()
            )));
        }
        let bind_addr = kcc::passway_listen_addr(spec);

        // 1. kamaji binds the listen socket (host netns) and holds the fd.
        self.custody_bind_and_hold(id.as_str(), &bind_addr).await?;

        // 2. Start passway in upgrade mode with the shared upgrade-sock mount.
        let pod = self.passway_pod_options(spec).await?;
        let pid = match self
            .deploy_generation(
                id,
                spec,
                &pod,
                &[format!("{}=true", kcc::PASSWAY_UPGRADE_ENV)],
            )
            .await
        {
            Ok(pid) => pid,
            Err(e) => {
                self.custodian.release(id.as_str());
                return Err(e);
            }
        };

        // 3. Hand the held listen fd to the waiting passway.
        if let Err(e) = self.custody_hand_off(id, spec).await {
            let _ = self.teardown(id).await;
            self.custodian.release(id.as_str());
            return Err(e);
        }

        info!(
            container_id = %id.as_str(),
            bind = %bind_addr,
            "kamaji: custody deploy — passway adopted the kamaji-held listen socket"
        );
        Ok(pid)
    }

    /// Zero-downtime cert reload for a passway workload (R600-F9 / W273). kamaji
    /// already holds the listening socket (bound at [`deploy_custody`]), so the
    /// swap keeps the socket open the whole time — connections arriving during
    /// the swap queue in the kernel accept backlog rather than being reset.
    ///
    /// Single-container-id rotation (kamaji is the sole fd sender):
    /// 1. `SIGQUIT` the running passway — it drains in-flight connections and
    ///    exits. The socket stays open (kamaji holds it).
    /// 2. Reap the old generation, then start a fresh one under the **same** id
    ///    in upgrade mode (picking up the re-rendered cert mount).
    /// 3. `hand_off` the still-held listen fd to the new process; it adopts the
    ///    socket and serves the queued + new connections.
    ///
    /// Unlike the inlined backend's coexisting two-generation handoff (which
    /// additionally avoids the brief accept-latency blip), this favours the
    /// simpler single-id model on the hardened daemon — correctness (no dropped
    /// connections) comes from kamaji owning the socket, not from overlap.
    /// Falls back to a connection-dropping redeploy for a non-passway workload
    /// or when custody isn't held (e.g. after a daemon restart).
    pub async fn graceful_upgrade(
        &self,
        id: &WorkloadId,
        spec: &WorkloadSpec,
    ) -> Result<u32, BackendError> {
        if kcc::upgrade_sock_dir(spec).is_none() {
            warn!(
                container_id = %id.as_str(),
                "graceful_upgrade: not a passway workload; connection-dropping redeploy"
            );
            return self.deploy(id, spec).await;
        }
        if !self.custodian.holds(id.as_str()) {
            // No held socket (never custody-deployed, or the daemon restarted).
            // A fresh custody deploy rebinds it — necessarily a redeploy.
            info!(
                container_id = %id.as_str(),
                "graceful_upgrade: no held socket; custody-deploying fresh"
            );
            return self.deploy(id, spec).await;
        }

        // 1. Drain the running passway (SIGQUIT), give it its stop grace.
        if let Err(e) = self.sigquit(id.as_str()).await {
            warn!(
                container_id = %id.as_str(),
                error = %e,
                "graceful_upgrade: SIGQUIT of outgoing passway failed; continuing to reap+respawn"
            );
        }
        let grace = Duration::from_millis(spec.stop_policy.grace_period.0);
        tokio::time::sleep(grace).await;

        // 2. Reap the old generation and start a fresh one under the same id in
        //    upgrade mode. deploy_generation tears the old container down first.
        //    NB: this must NOT release custody — kamaji keeps the socket.
        let pod = self.passway_pod_options(spec).await?;
        let pid = self
            .deploy_generation(
                id,
                spec,
                &pod,
                &[format!("{}=true", kcc::PASSWAY_UPGRADE_ENV)],
            )
            .await?;

        // 3. Hand the still-held listen fd to the new passway.
        self.custody_hand_off(id, spec).await?;

        info!(
            container_id = %id.as_str(),
            pid = pid,
            "kamaji: graceful cert-reload upgrade complete (zero dropped connections)"
        );
        Ok(pid)
    }

    /// Pod placement for a passway custody workload: the shared upgrade-sock
    /// host directory bind-mounted at the socket's container-side parent, so
    /// kamaji can `connect()` from the host mount namespace to hand off the fd.
    /// Single-id rotation reaps the old generation before starting the new one,
    /// so one directory per ident is race-free (slot `A`).
    async fn passway_pod_options(&self, spec: &WorkloadSpec) -> Result<kcc::PodOptions, BackendError> {
        let Some(sock_dir) = kcc::upgrade_sock_dir(spec) else {
            return Ok(kcc::PodOptions::default());
        };
        let host_dir = kcc::shared_upgrade_hostdir(&spec.expose.mesh.identity.0, kcc::PodSlot::A);
        tokio::fs::create_dir_all(&host_dir)
            .await
            .with_context(|| format!("creating shared upgrade dir {}", host_dir.display()))
            .map_err(BackendError::Containerd)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                tokio::fs::set_permissions(&host_dir, std::fs::Permissions::from_mode(0o700)).await;
        }
        Ok(kcc::PodOptions {
            // Host-networked ingress → host netns is the custodian; no join.
            join_netns: None,
            shared_dir: Some((host_dir.to_string_lossy().into_owned(), sock_dir)),
        })
    }

    /// Bind the custodial listener for `ident` on `bind_addr` (host netns) and
    /// hold it. The bind can block, so it runs on a blocking thread.
    async fn custody_bind_and_hold(&self, ident: &str, bind_addr: &str) -> Result<(), BackendError> {
        let cust = self.custodian.clone();
        let ident = ident.to_string();
        let bind = bind_addr.to_string();
        let bind_for_ctx = bind.clone();
        tokio::task::spawn_blocking(move || cust.bind_and_hold(&ident, &bind, None))
            .await
            .map_err(|e| BackendError::Containerd(anyhow::anyhow!("bind task join: {e}")))?
            .with_context(|| format!("binding custodial listener {bind_for_ctx}"))
            .map_err(BackendError::Containerd)?;
        Ok(())
    }

    /// Hand kamaji's held listen fd for `id` to the passway waiting on its
    /// upgrade sock (started in `PASSWAY_UPGRADE=true` mode). The connect-retry
    /// + `sendmsg` can block, so it runs on a blocking thread.
    async fn custody_hand_off(&self, id: &WorkloadId, spec: &WorkloadSpec) -> Result<(), BackendError> {
        let host_sock = self.host_upgrade_sock(spec).ok_or_else(|| {
            BackendError::InvalidSpec(format!(
                "passway workload {} declares no upgrade sock",
                id.as_str()
            ))
        })?;
        let cust = self.custodian.clone();
        let ident = spec.expose.mesh.identity.0.clone();
        let ident_for_ctx = ident.clone();
        tokio::task::spawn_blocking(move || cust.hand_off(&ident, &host_sock))
            .await
            .map_err(|e| BackendError::Containerd(anyhow::anyhow!("hand_off task join: {e}")))?
            .with_context(|| format!("handing listen fd to workload {ident_for_ctx}"))
            .map_err(BackendError::Containerd)?;
        Ok(())
    }

    /// Host-side path of the upgrade socket passway binds (the shared dir joined
    /// with the socket basename) — what kamaji `connect()`s to for the handoff.
    fn host_upgrade_sock(&self, spec: &WorkloadSpec) -> Option<PathBuf> {
        let base = kcc::upgrade_sock_basename(spec)?;
        Some(kcc::shared_upgrade_hostdir(&spec.expose.mesh.identity.0, kcc::PodSlot::A).join(base))
    }

    /// Send `SIGQUIT` (pingora's graceful-drain signal) to a container's init
    /// process. `all: false` targets PID 1 (the passway process) so it drains
    /// rather than group-killing. kamaji is the sole sender of this signal.
    async fn sigquit(&self, container_id: &str) -> Result<(), BackendError> {
        let mut tasks = self.tasks_client();
        let req = KillRequest {
            container_id: container_id.to_string(),
            exec_id: String::new(),
            signal: 3, // SIGQUIT
            all: false,
        };
        let req = with_namespace!(req, self.namespace);
        tasks
            .kill(req)
            .await
            .with_context(|| format!("SIGQUIT {container_id}"))
            .map_err(BackendError::Containerd)?;
        Ok(())
    }

    /// Idempotent teardown — kill, delete task, delete container, and stop
    /// any per-workload journald forwarder tasks plus unlink their FIFOs
    /// (R406-T10). Missing containers and missing tasks both surface as
    /// `Ok(())`.
    ///
    /// Also releases any custodial listen socket held for this workload
    /// (R600-F9) — a hard teardown means the workload is going away, so the
    /// socket should close too. This is why deploy / graceful use the private
    /// [`reap_container`](Self::reap_container) (which keeps custody) for their
    /// internal same-id recycle, and only the public Stop path lands here.
    /// R823-B4: `id` may be either the container id this backend deployed
    /// under (`spec.name`) OR the workload's mesh identity, so resolve it
    /// before reaping. See [`resolve_container_key_with`] for why, and
    /// [`ContainerLookup`] for the seam that makes the choice testable.
    ///
    /// Custody is released under BOTH keys: the fast path releases whatever
    /// the caller named, and the resolved id covers the case where custody was
    /// recorded under the deploy-time container id. `release` is an idempotent
    /// map removal, so the extra call costs nothing when the keys agree.
    pub async fn teardown(&self, id: &WorkloadId) -> Result<(), BackendError> {
        let resolved = self.resolve_container_key(id).await?;
        self.custodian.release(id.as_str());
        if resolved.as_str() != id.as_str() {
            self.custodian.release(resolved.as_str());
        }
        self.reap_container(&resolved).await
    }

    /// Resolve a `Stop` key to the container id it actually names, over live
    /// containerd. See [`resolve_container_key_with`] for the logic.
    async fn resolve_container_key(&self, key: &WorkloadId) -> Result<WorkloadId, BackendError> {
        let mut lookup = ContainerdLookup {
            ctrs: self.containers_client(),
            namespace: self.namespace.clone(),
        };
        resolve_container_key_with(&mut lookup, key).await
    }

    /// Reap the container/task/snapshot + journald forwarders for `id`, WITHOUT
    /// touching custody. Used by the idempotent-redeploy path in
    /// [`deploy_generation`](Self::deploy_generation) and the graceful
    /// cert-reload recycle, both of which must keep kamaji's held listen socket
    /// alive across the process swap. Tracking-side cleanup runs even when the
    /// container itself is absent, so a redeploy that mkfifo's into a stale path
    /// on disk doesn't EEXIST-fail.
    async fn reap_container(&self, id: &WorkloadId) -> Result<(), BackendError> {
        let container_id = id.as_str().to_string();

        // Stop forwarders + unlink FIFOs first — this is idempotent and
        // independent of whether the container itself is in containerd. A
        // crashed Kamaji that left FIFOs behind needs them gone before
        // the next deploy mkfifo's the same path.
        let tracking = {
            let mut tracked = self.tracked.lock().expect("tracked mutex poisoned");
            tracked.remove(id)
        };
        if let Some(tracking) = tracking {
            for handle in tracking.forwarders {
                handle.abort();
            }
            for fifo in tracking.fifo_paths {
                if let Err(e) = tokio::fs::remove_file(&fifo).await {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!(
                            workload = %container_id,
                            fifo = %fifo.display(),
                            error = %e,
                            "kamaji: failed to unlink FIFO during teardown"
                        );
                    }
                }
            }
        }

        // Check container exists.
        let mut ctrs = self.containers_client();
        let probe = ctrs
            .get({
                let req = GetContainerRequest {
                    id: container_id.clone(),
                };
                with_namespace!(req, self.namespace)
            })
            .await;
        if probe.is_err() {
            return Ok(());
        }

        // Kill the task with SIGKILL and WAIT for containerd to actually reap
        // it — Stop's gentle path goes through Drain (T7); this is the
        // hard-tear-down used by `Stop` and idempotent redeploy.
        //
        // R854: this used to fire the kill and delete the task record in the
        // very next breath, discarding the delete's result. Containerd refuses
        // to delete a task that has not reached STOPPED, so on a back-to-back
        // redeploy the delete lost the race, the task survived, the *container*
        // delete below succeeded anyway (containerd's metadata store does not
        // hold the two together), and the redeploy's CreateTask collided with
        // the orphan — "task <ident>: already exists", a 500 out of yubaba, and
        // a previously-healthy workload left Failed. `reap_task` returns only
        // once containerd reports no task, so the failure is now visible here
        // instead of surfacing three steps later as a phantom collision.
        {
            let mut tasks = self.tasks_client();
            if let Err(e) = kcc::reap_task(
                &mut tasks,
                &self.namespace,
                &container_id,
                kcc::TASK_REAP_TIMEOUT,
            )
            .await
            {
                warn!(
                    container_id = %container_id,
                    error = %format!("{e:#}"),
                    "kamaji: task reap did not complete; a redeploy may collide with the survivor"
                );
            }
        }

        // Delete the container record. R854: a swallowed failure here is the
        // other half of the same trap — the next deploy's CreateContainer
        // would then collide, and with nothing logged the 500 names a
        // condition no one can trace back to this reap.
        {
            let mut ctrs = self.containers_client();
            let req = DeleteContainerRequest {
                id: container_id.clone(),
            };
            let req = with_namespace!(req, self.namespace);
            match ctrs.delete(req).await {
                Ok(_) => {}
                Err(status) if status.code() == containerd_client::tonic::Code::NotFound => {}
                Err(status) => warn!(
                    container_id = %container_id,
                    error = %status,
                    "kamaji: container record delete failed; a redeploy may collide with it"
                ),
            }
        }

        // Remove the active rootfs snapshot so a redeploy can re-prepare it
        // (snapshot key == container id). Best-effort: NotFound is fine.
        {
            let req = RemoveSnapshotRequest {
                snapshotter: "overlayfs".to_string(),
                key: container_id.clone(),
            };
            let req = with_namespace!(req, self.namespace);
            let _ = self.snapshots_client().remove(req).await;
        }

        info!(container_id = %container_id, "kamaji: containerd workload torn down");
        Ok(())
    }

    /// List every yah-managed container in containerd's `"yah"` namespace.
    /// Returns `WorkloadEntry` (the on-wire shape) so the server layer can
    /// fold this list into `KamajiToYubaba::WorkloadList` without an
    /// intermediate conversion.
    pub async fn list(&self) -> Result<Vec<WorkloadEntry>, BackendError> {
        let mut ctrs = self.containers_client();
        let req = ListContainersRequest {
            filters: vec!["labels.\"yah.ident\"!=\"\"".to_string()],
        };
        let req = with_namespace!(req, self.namespace);
        let containers = ctrs
            .list(req)
            .await
            .context("listing containerd containers")
            .map_err(BackendError::Containerd)?
            .into_inner()
            .containers;

        let mut tasks = self.tasks_client();
        let mut entries = Vec::with_capacity(containers.len());
        for c in containers {
            // Default to Starting until the task is created; map the task
            // status to a proto WorkloadState once it exists.
            let (state, pid) = match get_task_status(&mut tasks, &self.namespace, &c.id).await {
                Ok(Some((code, pid, exit_status))) => {
                    (map_task_state(code, exit_status), Some(pid))
                }
                Ok(None) => (WorkloadState::Pending, None),
                Err(_) => (WorkloadState::Failed, None),
            };
            entries.push(WorkloadEntry {
                mesh_ident: c.labels.get("yah.mesh-ident").cloned(),
                id: WorkloadId::new(c.id),
                state,
                pid,
                // R844-F2: a containerd container has its own network
                // namespace, so its declared port is the bound port and this
                // backend resolves nothing. Empty means "no resolved port
                // known", not "portless" — the caller falls back to the spec.
                ports: Vec::new(),
                named_ports: Default::default(),
                // R852-B4: a backend does not know what spec it was deployed
                // from — containerd knows a container, not a `Workload`. The
                // server stamps the digest onto every entry from its own deploy
                // record after the merges, so every backend leaves it `None`.
                spec_digest: None,
            });
        }
        Ok(entries)
    }

    /// Probe containerd liveness — used by the server's `health` surface
    /// once it is wired (not on the wire yet).
    pub async fn health(&self) -> Result<String, BackendError> {
        let mut v = self.version_client();
        let resp = v
            .version(Request::new(()))
            .await
            .context("containerd version RPC")
            .map_err(BackendError::Containerd)?;
        let inner = resp.into_inner();
        Ok(inner.version)
    }
}

/// Inert sink used when [`ContainerdBackend::with_log_sink`] hasn't been
/// called. Drops every line on the floor — production wires
/// [`crate::JournalSender`] in `main.rs`.
#[derive(Debug)]
struct NoopSink;

impl LogSink for NoopSink {
    fn write_line(&self, _workload: &WorkloadId, _stream: Stream, _line: &[u8]) {}
}

/// Create a FIFO at `path` with mode 0o600 if one doesn't already exist.
/// Returns `Ok(())` if the path already holds a FIFO (idempotent redeploy
/// after a crashed teardown), an error otherwise.
///
/// Linux-only — non-Linux returns a clear unsupported error. macOS hosts
/// running kamaji with the `containerd-integration` feature are an
/// unsupported combination in production (containerd doesn't run on Mac);
/// the gate keeps build hygiene without burning a runtime crash.
#[cfg(target_os = "linux")]
fn ensure_fifo(path: &Path) -> Result<()> {
    use nix::sys::stat::{stat, Mode, SFlag};
    use nix::unistd::mkfifo;
    match stat(path) {
        Ok(st) => {
            // Already exists — accept if it's a FIFO, error otherwise.
            let mode = SFlag::from_bits_truncate(st.st_mode);
            if mode.contains(SFlag::S_IFIFO) {
                return Ok(());
            }
            anyhow::bail!(
                "{}: exists but is not a FIFO ({:#o})",
                path.display(),
                st.st_mode
            );
        }
        Err(nix::errno::Errno::ENOENT) => {}
        Err(e) => anyhow::bail!("stat({}): {e}", path.display()),
    }
    mkfifo(path, Mode::from_bits_truncate(0o600))
        .map_err(|e| anyhow::anyhow!("mkfifo({}): {e}", path.display()))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_fifo(path: &Path) -> Result<()> {
    let _ = path;
    anyhow::bail!("containerd FIFO log fan-in requires Linux")
}

/// Open `fifo_path` for read+write (so EPOLLHUP-on-no-writer doesn't fire),
/// then spawn a tokio task that runs [`crate::journal::forward_reader`]
/// against it. The returned [`AbortHandle`] is tracked in
/// [`ContainerdBackend::tracked`] and aborted by teardown.
#[cfg(target_os = "linux")]
fn spawn_forwarder(
    sink: Arc<dyn LogSink>,
    workload: WorkloadId,
    stream: Stream,
    fifo_path: &Path,
) -> Result<AbortHandle, BackendError> {
    let recv = tokio::net::unix::pipe::OpenOptions::new()
        .read_write(true)
        .open_receiver(fifo_path)
        .with_context(|| format!("open FIFO {} for read", fifo_path.display()))
        .map_err(BackendError::Containerd)?;
    let workload_label = workload.as_str().to_string();
    let join = tokio::spawn(async move {
        if let Err(e) = crate::journal::forward_reader(sink, workload, stream, recv).await {
            tracing::warn!(
                workload = %workload_label,
                stream = stream.label(),
                error = %e,
                "kamaji: log forwarder ended on read error"
            );
        }
    });
    Ok(join.abort_handle())
}

#[cfg(not(target_os = "linux"))]
fn spawn_forwarder(
    sink: Arc<dyn LogSink>,
    workload: WorkloadId,
    stream: Stream,
    fifo_path: &Path,
) -> Result<AbortHandle, BackendError> {
    let _ = (sink, workload, stream, fifo_path);
    Err(BackendError::Containerd(anyhow::anyhow!(
        "containerd FIFO log fan-in requires Linux"
    )))
}

/// The containerd container lookups [`resolve_container_key_with`] needs,
/// behind a trait so the resolution logic — the part that was wrong — is
/// exercised on a machine with no containerd. Same shape as
/// `kcc::TaskOps`/`reap_task_with` (R854).
#[allow(async_fn_in_trait)]
pub trait ContainerLookup {
    /// Does a container with exactly this id exist?
    async fn exists(&mut self, container_id: &str) -> Result<bool, BackendError>;
    /// The id of the container carrying `yah.mesh-ident == mesh_ident`, if any.
    async fn find_by_mesh_ident(&mut self, mesh_ident: &str)
        -> Result<Option<String>, BackendError>;
}

/// Resolve a `Stop` key to the container id it names.
///
/// R823-B4 — the leak this exists to close. This backend NAMES containers by
/// the `WorkloadId` `Deploy` carried, which `KamajiSibling::deploy_workload`
/// fills from `spec.name`; but `KamajiSibling::teardown_workload` has only a
/// `MeshIdent` and sends *that* as the `Stop` id. For every workload whose
/// name and mesh identity agree the two are the same string and nothing was
/// ever wrong. A forge run is the one shape where they differ —
/// `WorkloadSpec::for_forge` is `name = forge-<uuid>` (DNS-label safe, no dots)
/// against `expose.mesh.identity = forge.<uuid>` (R590-B9) — so `Stop` probed a
/// container id that had never existed, [`ContainerdBackend::reap_container`]
/// took its `probe.is_err() → Ok(())` early return, and yubaba answered
/// `{"status":"destroyed"}` over a container that was still RUNNING and still
/// holding its ports. MEASURED on us-west-003 2026-09-03: five participant-set
/// runs, five surviving responders.
///
/// This is the same class of bug the docker backend fixed in the opposite
/// direction (it names by identity and was handed an id) with
/// `resolve()`/`teardown_by_key()`; see the R626-F1 gotcha on
/// [`crate::server`]. The resolution here is the containerd half, and it is
/// deliberately the same "accept EITHER key" contract rather than a new one.
///
/// Order matters: the direct hit is tried FIRST, so an ordinary workload costs
/// one `Containers.Get` and never a label scan, and a container id that
/// happens to collide with some other workload's mesh-ident label can't be
/// hijacked. Falling back to `key` when neither matches keeps `Stop`
/// idempotent — `reap_container` still runs its FIFO/tracking cleanup and
/// returns `Ok(())` for a workload containerd never had.
pub async fn resolve_container_key_with<L: ContainerLookup>(
    lookup: &mut L,
    key: &WorkloadId,
) -> Result<WorkloadId, BackendError> {
    if lookup.exists(key.as_str()).await? {
        return Ok(key.clone());
    }
    if let Some(container_id) = lookup.find_by_mesh_ident(key.as_str()).await? {
        info!(
            stop_key = %key.as_str(),
            container_id = %container_id,
            "kamaji: resolved Stop key to a container by its yah.mesh-ident label (R823-B4)"
        );
        return Ok(WorkloadId::new(container_id));
    }
    Ok(key.clone())
}

/// The containerd filter that selects containers carrying
/// `yah.mesh-ident == mesh_ident`.
///
/// Returns `None` for a value that cannot be embedded in containerd's filter
/// grammar — a `"` or `\` would end the quoted string early and turn a lookup
/// into a syntax error (or, worse, a different filter). No mesh identity in
/// this fleet contains either, so refusing is strictly a guard: the caller
/// treats `None` as "no match", and `Stop` falls back to the literal key,
/// which is the pre-R823-B4 behaviour.
fn mesh_ident_filter(mesh_ident: &str) -> Option<String> {
    if mesh_ident.contains('"') || mesh_ident.contains('\\') {
        return None;
    }
    Some(format!("labels.\"yah.mesh-ident\"==\"{mesh_ident}\""))
}

/// [`ContainerLookup`] over a live containerd.
struct ContainerdLookup {
    ctrs: ContainersClient<Channel>,
    namespace: String,
}

impl ContainerLookup for ContainerdLookup {
    async fn exists(&mut self, container_id: &str) -> Result<bool, BackendError> {
        let req = GetContainerRequest {
            id: container_id.to_string(),
        };
        let req = with_namespace!(req, self.namespace);
        Ok(self.ctrs.get(req).await.is_ok())
    }

    async fn find_by_mesh_ident(
        &mut self,
        mesh_ident: &str,
    ) -> Result<Option<String>, BackendError> {
        let Some(filter) = mesh_ident_filter(mesh_ident) else {
            return Ok(None);
        };
        let req = ListContainersRequest {
            filters: vec![filter],
        };
        let req = with_namespace!(req, self.namespace);
        let containers = self
            .ctrs
            .list(req)
            .await
            .context("listing containerd containers by mesh ident")
            .map_err(BackendError::Containerd)?
            .into_inner()
            .containers;
        Ok(containers.into_iter().next().map(|c| c.id))
    }
}

/// Build labels Kamaji stamps on every container — these are how
/// `list_workloads` filters yah-managed containers out of other orchestrators'
/// containers in the same containerd namespace, and how reconciliation
/// recovers the workload id after a Kamaji restart.
fn labels_for(spec: &WorkloadSpec, id: &WorkloadId) -> HashMap<String, String> {
    let mut labels = spec.labels.clone();
    labels.insert("yah.ident".to_string(), id.as_str().to_string());
    labels.insert("yah.name".to_string(), spec.name.clone());
    labels.insert("yah.tier".to_string(), spec.tier.0.clone());
    // R590-B9: the mesh identity (`expose.mesh.identity`) is the handle
    // Yubaba's `/workloads/{ident}/state` keys on, and it can differ from the
    // container id (`id`) — a forge workload is `name = forge-<uuid>` (the
    // DNS-safe container id) but `mesh.identity = forge.<uuid>`. Stamp it so
    // `list()` can surface it on `WorkloadEntry.mesh_ident` and yubaba can
    // match a polled ident against it. `id` stays the drain/stop key.
    labels.insert(
        "yah.mesh-ident".to_string(),
        spec.expose.mesh.identity.0.clone(),
    );
    labels
}

/// Translate a containerd task status code (+ its exit status) to a wire
/// `WorkloadState`.
///
/// Containerd codes per the protobuf definition:
///   0 = Unknown, 1 = Created, 2 = Running, 3 = Stopped, 4 = Paused, 5 = Pausing
///
/// R590-B12: a STOPPED task covers BOTH a clean exit and a failed one —
/// containerd's status code doesn't distinguish them. Split on the process
/// `exit_status`: 0 → [`WorkloadState::Exited`], non-zero → [`WorkloadState::Failed`].
/// Without this a failed remote build (non-zero exit) surfaced as `Exited`, so
/// the qed CLI reported it green.
fn map_task_state(code: i32, exit_status: u32) -> WorkloadState {
    match code {
        1 => WorkloadState::Pending,
        2 => WorkloadState::Running,
        3 if exit_status == 0 => WorkloadState::Exited,
        3 => WorkloadState::Failed,
        4 | 5 => WorkloadState::Draining,
        _ => WorkloadState::Failed,
    }
}

/// One round-trip to fetch a container's task status. Returns `Ok(None)` if
/// the container exists but has no task (e.g. created-but-not-started).
/// Delegates to `kamaji-containerd-core` (R592-T1) — identical logic to the
/// inlined `kamaji` crate's containerd backend (which discards the pid this
/// shape needs for `WorkloadEntry.pid`).
///
/// This shape's pre-R592-T1 semantics folded both "no task" and the
/// anomalous status-without-process reply into `None` (→ `Pending` at the
/// call site); preserved here.
async fn get_task_status(
    tasks: &mut TasksClient<Channel>,
    namespace: &str,
    container_id: &str,
) -> anyhow::Result<Option<(i32, u32, u32)>> {
    Ok(
        match kcc::get_task_status(tasks, namespace, container_id).await? {
            kcc::TaskProbe::Status {
                code,
                pid,
                exit_status,
            } => Some((code, pid, exit_status)),
            kcc::TaskProbe::NoTask | kcc::TaskProbe::MissingProcess => None,
        },
    )
}

/// Validate the spec before dispatching to containerd. Mirrors the parity
/// floor in [`crate::native::SandboxPlan::from_spec`] — unresolved
/// `FromSecret` / `FromMesh` env values are yubaba's responsibility; if
/// they reach Kamaji it's a bug in yubaba's admission layer.
fn validate_spec_for_constable(spec: &WorkloadSpec) -> Result<(), BackendError> {
    // Host networking is a privileged escape hatch: it drops the network
    // isolation every other workload gets, letting the container bind host
    // ports directly. Guard it to the infra tier so an ordinary tenant
    // workload cannot request it. (Bind mounts are gated the same way in
    // workload_spec::validate::shape.)
    if spec.wants_host_network() && spec.tier.0 != "infra" {
        return Err(BackendError::InvalidSpec(format!(
            "workload requests host networking (annotation {}={}) but tier is {:?}; \
             host networking is only permitted for tier=\"infra\"",
            workload_spec::HOST_NETWORK_ANNOTATION,
            workload_spec::HOST_NETWORK_VALUE,
            spec.tier.0,
        )));
    }

    // The nested-sandbox grant (R636-B2) is the same shape of escape hatch: it
    // hands the container CAP_SETUID + CAP_SETGID and turns `no_new_privs` off
    // so rootless BuildKit can build a user namespace. Gate it to the infra
    // tier for the same reason.
    if spec.wants_nested_sandbox() && spec.tier.0 != "infra" {
        return Err(BackendError::InvalidSpec(format!(
            "workload requests the nested-sandbox grant (annotation {}={}) but tier is {:?}; \
             it is only permitted for tier=\"infra\"",
            workload_spec::NESTED_SANDBOX_ANNOTATION,
            workload_spec::NESTED_SANDBOX_VALUE,
            spec.tier.0,
        )));
    }

    for env in &spec.env {
        match &env.value {
            EnvValue::Literal { .. } => {}
            EnvValue::FromSecret { secret, .. } => {
                return Err(BackendError::InvalidSpec(format!(
                    "env {} carries an unresolved FromSecret({secret}) — yubaba must resolve before Deploy",
                    env.name
                )));
            }
            EnvValue::FromMesh { ident, .. } => {
                return Err(BackendError::InvalidSpec(format!(
                    "env {} carries an unresolved FromMesh({}) — yubaba must resolve before Deploy",
                    env.name, ident.0
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        EnvVar, ExposeSpec, ImageRef, MeshExpose, MeshIdent, MeshLookup, Millis, NamespaceId,
        ResourceLimits, RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag,
    };

    fn make_spec(name: &str) -> WorkloadSpec {
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.into(),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            image: ImageRef {
                registry: "ghcr.io".into(),
                repository: "example/svc".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("public".into()),
            replicas: 1,
            command: Some(vec!["/usr/bin/svc".into()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![EnvVar {
                name: "FOO".into(),
                value: EnvValue::Literal {
                    value: "bar".into(),
                },
            }],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                cpu_millis: 1024,
                memory_mb: 512,
                ephemeral_storage_mb: 128,
            },
            depends_on: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Always,
            archetype: None,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(name.into()),
                    ports: MeshExpose::anonymous_ports([8080]),
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        }
    }

    #[test]
    fn image_ref_emits_tag_and_digest() {
        let mut spec = make_spec("svc");
        spec.image.digest = "sha256:deadbeef".into();
        assert_eq!(
            ContainerdBackend::image_ref(&spec),
            "ghcr.io/example/svc:latest@sha256:deadbeef"
        );
    }

    #[test]
    fn validate_rejects_unresolved_from_secret() {
        let mut spec = make_spec("svc");
        spec.env.push(EnvVar {
            name: "DB_PASS".into(),
            value: EnvValue::FromSecret {
                secret: "db-creds".into(),
                key: "password".into(),
            },
        });
        let err = validate_spec_for_constable(&spec).unwrap_err();
        assert!(matches!(err, BackendError::InvalidSpec(_)));
        let msg = err.to_string();
        assert!(msg.contains("FromSecret"), "msg: {msg}");
        assert!(msg.contains("yubaba must resolve"), "msg: {msg}");
    }

    #[test]
    fn validate_rejects_unresolved_from_mesh() {
        let mut spec = make_spec("svc");
        spec.env.push(EnvVar {
            name: "PEER".into(),
            value: EnvValue::FromMesh {
                ident: MeshIdent("peer".into()),
                kind: MeshLookup::Url,
            },
        });
        let err = validate_spec_for_constable(&spec).unwrap_err();
        assert!(matches!(err, BackendError::InvalidSpec(_)));
        assert!(err.to_string().contains("FromMesh"));
    }

    #[test]
    fn validate_passes_pure_literals() {
        let spec = make_spec("svc");
        validate_spec_for_constable(&spec).unwrap();
    }

    // The pure build_oci_spec-shape assertions (network isolation, /sys mount
    // strategy, capability set) now live once in `kamaji-containerd-core`'s
    // own test module (R592-T1) — this crate keeps only the assertions below
    // that are specific to this shape's call site (no extra env; validation
    // gating).

    /// Helper: set the host-network opt-in annotation.
    fn with_host_network(mut spec: WorkloadSpec) -> WorkloadSpec {
        spec.annotations.insert(
            workload_spec::HOST_NETWORK_ANNOTATION.into(),
            workload_spec::HOST_NETWORK_VALUE.into(),
        );
        spec
    }

    #[test]
    fn validate_rejects_host_network_for_non_infra_tier() {
        // make_spec is tier=public; host networking must be refused.
        let err = validate_spec_for_constable(&with_host_network(make_spec("svc"))).unwrap_err();
        assert!(matches!(err, BackendError::InvalidSpec(_)));
        let msg = err.to_string();
        assert!(msg.contains("host networking"), "msg: {msg}");
        assert!(msg.contains("infra"), "msg: {msg}");
    }

    #[test]
    fn validate_allows_host_network_for_infra_tier() {
        let mut spec = with_host_network(make_spec("svc"));
        spec.tier = TierTag("infra".into());
        validate_spec_for_constable(&spec).unwrap();
    }

    fn with_nested_sandbox(mut spec: WorkloadSpec) -> WorkloadSpec {
        spec.annotations.insert(
            workload_spec::NESTED_SANDBOX_ANNOTATION.into(),
            workload_spec::NESTED_SANDBOX_VALUE.into(),
        );
        spec
    }

    /// R636-B2: the nested-sandbox grant is gated exactly like host
    /// networking — an ordinary tenant workload cannot hand itself
    /// CAP_SETUID/CAP_SETGID by setting an annotation.
    #[test]
    fn validate_rejects_nested_sandbox_for_non_infra_tier() {
        // make_spec is tier=public; the grant must be refused.
        let err = validate_spec_for_constable(&with_nested_sandbox(make_spec("svc"))).unwrap_err();
        assert!(matches!(err, BackendError::InvalidSpec(_)));
        let msg = err.to_string();
        assert!(msg.contains("nested-sandbox"), "msg: {msg}");
        assert!(msg.contains("infra"), "msg: {msg}");
    }

    #[test]
    fn validate_allows_nested_sandbox_for_infra_tier() {
        let mut spec = with_nested_sandbox(make_spec("svc"));
        spec.tier = TierTag("infra".into());
        validate_spec_for_constable(&spec).unwrap();
    }

    #[test]
    fn oci_spec_carries_literal_env_only() {
        let mut spec = make_spec("svc");
        spec.env.push(EnvVar {
            name: "MESH_IP".into(),
            value: EnvValue::FromMesh {
                ident: MeshIdent("self".into()),
                kind: MeshLookup::Url,
            },
        });
        // The OCI mapper is pure — it does NOT validate. It just filters
        // non-literal env. validate_spec_for_constable runs first. (The local
        // build_oci_spec wrapper was inlined to kcc::build_oci_spec_with when the
        // custody path needed pod placement + extra env; R600-F9.)
        let oci = kcc::build_oci_spec_with(&spec, &[], None, &kcc::PodOptions::default());
        let env = oci["process"]["env"].as_array().unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].as_str().unwrap(), "FOO=bar");
    }

    #[test]
    fn labels_stamp_identity_and_tier() {
        let spec = make_spec("svc");
        let labels = labels_for(&spec, &WorkloadId::new("svc"));
        assert_eq!(labels.get("yah.ident").map(|s| s.as_str()), Some("svc"));
        assert_eq!(labels.get("yah.name").map(|s| s.as_str()), Some("svc"));
        assert_eq!(labels.get("yah.tier").map(|s| s.as_str()), Some("public"));
        // R590-B9: the mesh identity is stamped for the state-poll read path.
        assert_eq!(
            labels.get("yah.mesh-ident").map(|s| s.as_str()),
            Some("svc")
        );
    }

    #[test]
    fn map_task_state_covers_known_codes() {
        assert_eq!(map_task_state(1, 0), WorkloadState::Pending);
        assert_eq!(map_task_state(2, 0), WorkloadState::Running);
        // R590-B12: STOPPED splits on exit_status — clean vs failed.
        assert_eq!(map_task_state(3, 0), WorkloadState::Exited);
        assert_eq!(map_task_state(3, 1), WorkloadState::Failed);
        assert_eq!(map_task_state(3, 137), WorkloadState::Failed);
        assert_eq!(map_task_state(4, 0), WorkloadState::Draining);
        assert_eq!(map_task_state(5, 0), WorkloadState::Draining);
        assert_eq!(map_task_state(0, 0), WorkloadState::Failed);
        assert_eq!(map_task_state(99, 0), WorkloadState::Failed);
    }

    // ── R406-T10: FIFO log fan-in ─────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_fifo_creates_a_named_pipe_at_the_path() {
        use nix::sys::stat::{stat, SFlag};
        let tmp = tempfile::TempDir::new().unwrap();
        let fifo = tmp.path().join("stdout.fifo");
        ensure_fifo(&fifo).unwrap();
        let st = stat(&fifo).unwrap();
        assert!(SFlag::from_bits_truncate(st.st_mode).contains(SFlag::S_IFIFO));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_fifo_is_idempotent_when_called_twice() {
        let tmp = tempfile::TempDir::new().unwrap();
        let fifo = tmp.path().join("stdout.fifo");
        ensure_fifo(&fifo).unwrap();
        ensure_fifo(&fifo).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_fifo_refuses_a_path_holding_a_regular_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("not_a_fifo");
        std::fs::write(&path, b"hi").unwrap();
        let err = ensure_fifo(&path).unwrap_err();
        assert!(err.to_string().contains("not a FIFO"), "err: {err}");
    }

    /// End-to-end forwarder path: open a FIFO, spawn the forwarder, simulate
    /// containerd's shim by opening the write side ourselves and pumping a
    /// few lines. Asserts that each line lands in the sink with the right
    /// workload id and stream tag.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn fifo_forwarder_emits_lines_written_by_a_separate_writer() {
        use crate::journal::{LogSink, Stream, VecSink};
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let fifo = tmp.path().join("stdout.fifo");
        ensure_fifo(&fifo).unwrap();

        let sink: Arc<VecSink> = Arc::new(VecSink::new());
        let handle = spawn_forwarder(
            sink.clone() as Arc<dyn LogSink>,
            WorkloadId::new("svc-fifo"),
            Stream::Stdout,
            &fifo,
        )
        .unwrap();

        // Open the writer side after the forwarder has the reader side open
        // (spawn_forwarder opened it before returning). Write a few lines
        // and close to model a workload exiting cleanly.
        let mut writer = tokio::net::unix::pipe::OpenOptions::new()
            .open_sender(&fifo)
            .unwrap();
        writer.write_all(b"hello\nworld\n").await.unwrap();
        writer.flush().await.unwrap();
        drop(writer);

        // Poll briefly for the lines to land — read_until is async and runs
        // inside the spawned task, so give it a few ticks. Bounded so a
        // bug doesn't wedge the test suite.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if sink.entries().len() >= 2 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "forwarder did not surface both lines within 2s; got {:?}",
                    sink.entries()
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.abort();

        let entries = sink.entries();
        let lines: Vec<&[u8]> = entries.iter().map(|(_, _, l)| l.as_slice()).collect();
        assert!(lines.contains(&b"hello".as_slice()), "got: {lines:?}");
        assert!(lines.contains(&b"world".as_slice()), "got: {lines:?}");
        let (wid, stream, _) = &entries[0];
        assert_eq!(wid, &WorkloadId::new("svc-fifo"));
        assert_eq!(*stream, Stream::Stdout);
    }

    /// Aborting the forwarder handle prevents subsequent writes from landing
    /// in the sink — teardown's cancellation contract.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn aborted_forwarder_stops_consuming_further_writes() {
        use crate::journal::{LogSink, Stream, VecSink};
        use std::time::Duration;
        use tokio::io::AsyncWriteExt;

        let tmp = tempfile::TempDir::new().unwrap();
        let fifo = tmp.path().join("stdout.fifo");
        ensure_fifo(&fifo).unwrap();

        let sink: Arc<VecSink> = Arc::new(VecSink::new());
        let handle = spawn_forwarder(
            sink.clone() as Arc<dyn LogSink>,
            WorkloadId::new("svc-abort"),
            Stream::Stdout,
            &fifo,
        )
        .unwrap();

        // Abort before any writes. Give the runtime a moment to actually
        // tear the task down.
        handle.abort();
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now write a line. The forwarder task is gone, so nothing should
        // appear in the sink. We can't synchronously prove "task is gone"
        // but the empty sink after a fair wait is the operative signal.
        let mut writer = tokio::net::unix::pipe::OpenOptions::new()
            .open_sender(&fifo)
            .unwrap();
        writer.write_all(b"too-late\n").await.unwrap();
        drop(writer);
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            sink.entries().is_empty(),
            "expected no entries after abort, got {:?}",
            sink.entries()
        );
    }

    // ── R823-B4: Stop must accept either the container id or the mesh ident ──

    /// Records what was asked, so a test can assert the direct hit short-
    /// circuits instead of merely returning the right string by luck.
    #[derive(Default)]
    struct FakeLookup {
        /// container ids that exist
        containers: Vec<String>,
        /// mesh-ident label → container id
        by_mesh_ident: HashMap<String, String>,
        exists_calls: Vec<String>,
        find_calls: Vec<String>,
    }

    impl ContainerLookup for FakeLookup {
        async fn exists(&mut self, container_id: &str) -> Result<bool, BackendError> {
            self.exists_calls.push(container_id.to_string());
            Ok(self.containers.iter().any(|c| c == container_id))
        }

        async fn find_by_mesh_ident(
            &mut self,
            mesh_ident: &str,
        ) -> Result<Option<String>, BackendError> {
            self.find_calls.push(mesh_ident.to_string());
            Ok(self.by_mesh_ident.get(mesh_ident).cloned())
        }
    }

    /// The R823-B4 leak itself: a forge Stop carries `forge.<uuid>` (the mesh
    /// identity) but the container is named `forge-<uuid>` (`spec.name`).
    /// Before the fix this resolved to nothing, `reap_container` early-returned
    /// Ok, and yubaba answered "destroyed" over a running container.
    #[tokio::test]
    async fn a_mesh_ident_stop_key_resolves_to_the_forge_container_id() {
        let mut lookup = FakeLookup {
            containers: vec!["forge-87802530".into()],
            by_mesh_ident: HashMap::from([(
                "forge.87802530".to_string(),
                "forge-87802530".to_string(),
            )]),
            ..Default::default()
        };

        let resolved =
            resolve_container_key_with(&mut lookup, &WorkloadId::new("forge.87802530"))
                .await
                .unwrap();

        assert_eq!(resolved, WorkloadId::new("forge-87802530"));
    }

    /// The ordinary workload — name and mesh identity agree — must cost one
    /// `Containers.Get` and never reach the label scan.
    #[tokio::test]
    async fn a_container_id_that_exists_is_taken_directly_without_a_label_scan() {
        let mut lookup = FakeLookup {
            containers: vec!["yah-cloud-admin".into()],
            ..Default::default()
        };

        let resolved =
            resolve_container_key_with(&mut lookup, &WorkloadId::new("yah-cloud-admin"))
                .await
                .unwrap();

        assert_eq!(resolved, WorkloadId::new("yah-cloud-admin"));
        assert_eq!(lookup.exists_calls, vec!["yah-cloud-admin".to_string()]);
        assert!(
            lookup.find_calls.is_empty(),
            "a direct hit must not fall through to the label scan: {:?}",
            lookup.find_calls
        );
    }

    /// A direct hit wins over a label match, so one workload's container id
    /// cannot be hijacked by another workload's `yah.mesh-ident`.
    #[tokio::test]
    async fn a_direct_hit_outranks_a_mesh_ident_label_on_a_different_container() {
        let mut lookup = FakeLookup {
            containers: vec!["shared-key".into(), "someone-else".into()],
            by_mesh_ident: HashMap::from([(
                "shared-key".to_string(),
                "someone-else".to_string(),
            )]),
            ..Default::default()
        };

        let resolved = resolve_container_key_with(&mut lookup, &WorkloadId::new("shared-key"))
            .await
            .unwrap();

        assert_eq!(resolved, WorkloadId::new("shared-key"));
    }

    /// Stop stays idempotent: an unknown key resolves to itself so
    /// `reap_container` still runs its FIFO/tracking cleanup and returns Ok.
    #[tokio::test]
    async fn an_unknown_key_falls_back_to_itself_so_stop_stays_idempotent() {
        let mut lookup = FakeLookup::default();

        let resolved = resolve_container_key_with(&mut lookup, &WorkloadId::new("never-existed"))
            .await
            .unwrap();

        assert_eq!(resolved, WorkloadId::new("never-existed"));
        assert_eq!(lookup.find_calls, vec!["never-existed".to_string()]);
    }

    #[test]
    fn the_mesh_ident_filter_is_containerd_label_syntax() {
        assert_eq!(
            mesh_ident_filter("forge.87802530").unwrap(),
            "labels.\"yah.mesh-ident\"==\"forge.87802530\""
        );
    }

    /// A value that would break out of the quoted filter string is refused
    /// rather than embedded — the caller reads None as "no match".
    #[test]
    fn the_mesh_ident_filter_refuses_a_value_it_cannot_quote() {
        assert!(mesh_ident_filter("forge.\"; drop").is_none());
        assert!(mesh_ident_filter("forge\\x").is_none());
    }
}

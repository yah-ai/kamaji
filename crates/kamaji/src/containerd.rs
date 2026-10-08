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
//!
//! @yah:ticket(R870-F27, "Containerd backend materializes WorkloadSpec::files so inner doors stop being native-only")
//! @yah:status(review)
//! @yah:at(2026-09-12T08:09:29Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R870)
//! @yah:next("Tier: Warrior — the design is already decided by the R870 annotations; this is the implementation they name. Today only kamaji's native backend materializes WorkloadSpec::files; containerd/docker/microvm call reject_unmaterializable_files and refuse — correct refusal (a door started against an absent route table reports healthy and routes wrongly), wrong permanent state: it silently constrains every path-split service (inner doors, R870-F23) to native-capable nodes, a placement constraint hidden in a backend capability. Implement the write in the containerd backend — a pre-start write into the container rootfs or a per-file bind mount rendered from the spec — then narrow reject_unmaterializable_files to the backends that still cannot. Do NOT relax the guard without the write; the R870-F23 annotation in oss/yubaba/crates/cloud/src/config.rs (~:174) states that trade explicitly and is the provenance of this ticket — it was parked there as an unowned @yah:next, exactly the shape board doctrine says to file. Acceptance: an inner-door workload with an InlineFile route table deploys via the containerd backend and serves a routed request on a real node path, not a unit test of the file writer.")
//! @yah:handoff("THE WRITE LANDED, in the shared core so BOTH containerd shapes get it. New surface in oss/kamaji/crates/kamaji-containerd-core/src/lib.rs: spec_files_hostdir(container_id) -> /run/yah/kamaji/<container_id>/files; SpecFileMount {host_path, container_path}; plan_spec_files(dir, spec) (pure, testable path rules); stage_spec_files(dir, spec) (async writes, returns the mount plan); discard_spec_files(container_id) (teardown). PodOptions gained spec_files: Vec<SpecFileMount>, and build_oci_spec_with renders one read-only FILE bind per entry. Per-FILE not per-directory on purpose: a directory bind at /etc/passway would replace whatever the image ships there, so adding one file would silently delete its siblings. Mounts are appended LAST because runc mounts in order and a spec file inside a directory the workload also mounts (a volume, the upgrade-sock share) has to land after its parent. Read-only because the node rewrites these on every deploy; a container edit would be reverted at an unpredictable moment, and EROFS at the write is the legible version of that.")
//! @yah:handoff("CALL SITES, both of them, because there are two containerd deployment shapes and only fixing one is how R592-T1's drift came back: oss/kamaji/crates/kamaji/src/containerd.rs create_and_start (inlined) and oss/kamaji/crates/kamaji-bin/src/containerd.rs deploy_generation (sibling daemon). Each stages before building the OCI spec. The kamaji-bin one had NO guard at all before this — it neither wrote the files nor refused the spec, i.e. it was already in the silent-wrong-answer state reject_unmaterializable_files exists to prevent. DISCARD PLACEMENT IS LOAD-BEARING: in kamaji-bin it goes in the public teardown() and deliberately NOT in reap_container(), because reap_container also runs on the idempotent-redeploy path AFTER the incoming generation has been staged — discarding there would delete the files the deploy is about to mount. A redeploy needs no discard because stage_spec_files clears the directory itself before writing.")
//! @yah:handoff("GUARD NARROWED, not relaxed. kamaji::Backend::materializes_files (oss/kamaji/crates/kamaji/src/lib.rs) is the new single fact: Native|Containerd true, Docker|MicroVm false. reject_unmaterializable_files reads it and returns Ok early for a writing backend, so the third state a per-call-site list allows — a backend that neither writes nor refuses, and therefore starts a workload against a file that is not there — is now unreachable by forgetting a call. The containerd call site was deleted rather than left as a no-op (pre-1.0: one owner of the fact). native.rs's negative test now uses Backend::Docker as the refusing stand-in and additionally asserts both writers accept, so the half that would otherwise rot into a guard nobody notices is pinned.")
//! @yah:handoff("DISCOVERED WORK, wider than the title. (1) A PATH-TRAVERSAL HOLE that only becomes reachable with this ticket: WorkloadSpec documents files[].path as absolute but validate::shape never checks it, and dir.join(relative) with a `..` escapes the staging dir — so a spec naming /etc/../../../../root/.ssh/authorized_keys would have had kamaji (root, on a fleet node) overwrite an arbitrary host file. plan_spec_files refuses non-absolute paths, any `..`/prefix component, and bare `/`; a `.` is normalized rather than refused and BOTH halves of the bind report the normalized path. Test: a_traversing_or_relative_spec_file_path_is_refused. The native backend has the same hole and it is NOT closed here — it writes file.path straight to the host, so there the traversal target is the node filesystem directly. Worth a validate::shape rule so it is one refusal at admission instead of one per backend. (2) oss/kamaji/crates/kamaji-containerd-core/Cargo.toml: tokio gained the `fs` feature (was `time` only) for the staging writes. (3) oss/kamaji/crates/kamaji/src/containerd.rs:887 — a pre-existing clippy::useless_format in list()'s label filter, fixed. It was never in the recorded clippy baseline because every prior kamaji baseline ran --features native-integration, which does not compile containerd.rs.")
//! @yah:verify("RUN BY ME, from oss/kamaji, on the final tree. cargo test -p kamaji-containerd-core --features containerd-integration = 44 passed / 0 failed (baseline 38; +6: staged_spec_files_mirror_the_container_tree, a_dot_component_normalizes_rather_than_refusing, a_traversing_or_relative_spec_file_path_is_refused, staged_spec_files_become_trailing_read_only_file_binds, no_spec_files_means_no_extra_mounts, spec_files_hostdir_is_per_generation, staging_clears_the_previous_deploy_before_writing). cargo test -p kamaji --features containerd-integration,native-integration --lib = 190 / 0. cargo test -p kamaji-bin --features containerd-integration --lib = 240 / 0. cargo check -p yubaba --features containerd-integration (from oss/yubaba, the only out-of-kamaji consumer of kamaji/containerd-integration) = Finished, exit 0. cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu --all-targets = Finished, exit 0, with only the pre-existing free_port dead_code that R876-B9 already records. CLIPPY on kamaji-containerd-core + kamaji with both features, --all-targets: one warning, the pre-existing too_many_arguments (9/7, jit.rs supervise_on_demand). RUSTFMT: --check is dirty tree-wide in this subtree (pre-existing, e.g. container_net.rs, microvm.rs, kamaji-bin/containerd.rs:657); zero diffs land inside any hunk of mine — I hand-applied my one and ran no blanket fmt.")
//! @yah:verify("THE LIVE ACCEPTANCE THIS TICKET ASKS FOR IS NOT DONE, stated plainly rather than papered over with the unit tests. What is owed: an inner-door workload with an InlineFile route table, deployed through the containerd backend on a fleet node, serving a routed request. It cannot be reached from this Mac. There is no local containerd (no ~/.colima/default/containerd.sock, no /run/containerd/containerd.sock; docker here is OrbStack, which is the Docker backend and still refuses spec files by design). Starting colima --runtime containerd would give a real containerd but not a valid test: kamaji would stage under /run/yah/kamaji on the MAC while runc resolves the bind source inside the VM, so every file bind would miss — the same topology limit the existing shared_dir upgrade-sock mount already has, not a new constraint from this change. So the live leg needs a fleet node running these bytes, which means rolling an unreleased kamaji — an operator call, raised in chat.")
//! @yah:gotcha("STAGED FILES ARE OWNED BY THE KAMAJI PROCESS, not by the container user. A bind mount preserves the host file's mode, so a spec pairing a restrictive mode (0o600) with a non-root user (spec.user = \"101\") produces a file the workload cannot read — it will look like a config bug. Left deliberately at parity with the native backend rather than chown'd: the two backends disagreeing about who owns a materialized file is a worse trap than the one a chown would fix, and it would add a root requirement on the deploy path.")
//! @yah:cleanup("workload_spec::validate::shape has no rule for files[].path — it is documented absolute and never checked. plan_spec_files refuses the dangerous shapes at the containerd staging site, but the native backend writes file.path straight to the node filesystem with no check at all, so the traversal target there is the host directly. One admission-time rule would replace N per-backend refusals and catch it before a spec ever reaches a node.")
//! @yah:verify("LIVE ACCEPTANCE DONE — us-east-001, real containerd, real runc, 2026-09-12. Operator authorised the paired hot ship. scripts/hotship.sh --nodes us-east-001,us-south-001,us-west-001 --binaries kamaji,yubaba shipped 0.8.40-h1 (kamaji sha256 47a44715b6f351294a583c1d96131677e0d4603e3d0ff928ab069aaa730f12dd, yubaba f280a9124a3d21694f659596a1f60f3bc7437c8f0d5214418da13a39648d7215); all three rejoined clustered with kamaji_version 0.8.40-h1, state_epoch 6. us-east-001's four natives came back (100.64.0.3:41507/:34759/:40995 all LISTEN). scripts/hotship-probe.sh across the whole ship: 125/125 HTTP 200 on the yah.dev apex, zero non-200. THE TEST: a throwaway container workload (nginxinc/nginx-unprivileged:alpine, user 101, yah.network=host, 127.0.0.1:18707) whose ENTIRE route table arrives as an InlineFile at /etc/nginx/conf.d/default.conf, plus a second InlineFile at /usr/share/nginx/html/r870f27.txt that the image does not ship. Results: GET /r870 -> 200 \"R870-F27 ROUTED OK\" (a route that exists only in the spec), GET /r870f27.txt -> 200 \"R870-F27 CREATED FILE OK\" (runc created a destination absent from the image — the assumption per-file binds rest on, now measured not reasoned). On-node: both files at /run/yah/kamaji/r870f27-filecheck/files/<container path> with mode 0644, and `ctr containers info` shows exactly two bind mounts with options [rbind, ro, nosuid, nodev] pointing at them. REDEPLOY replaced the staging tree (default.conf 222 -> 500 bytes after an edit). DESTROY (POST /workloads/<ident>/destroy) left /run/yah/kamaji/r870f27-filecheck absent — discard_spec_files, including the empty-parent remove_dir. nginx is a faithful stand-in for the inner door precisely because it comes up healthy either way: had the mount not landed it would have served its default page, which is the silent-wrong-answer outcome, so this is a discriminating test and not a liveness check.")
//! @yah:gotcha("TWO THINGS THE LIVE RUN COST A PASS EACH, neither about spec files, both worth knowing before the next fleet acceptance. (1) `library/nginx` as root DIES on a yah container: `chown(\"/var/cache/nginx/client_temp\", 101) failed (Operation not permitted)` — a yah container holds CAP_NET_BIND_SERVICE and nothing else, and nginx-as-root chowns its temp dirs at startup. Use nginxinc/nginx-unprivileged + user = \"101\". That run still proved the mount, because nginx's entrypoint logged `can not modify /etc/nginx/conf.d/default.conf (read-only file system?)` — it was reading the bind. (2) `yah cloud workload deploy` was UNRUNNABLE from the repo root: it loads every .yah/services/*/mirrors/*.toml first, and a peer's in-flight .yah/services/scrabcake/mirrors/dev.toml carries a [providers.static] shape the installed yah binary cannot parse (\"data did not match any variant of untagged enum MirrorProviderSlot\"). Not mine to fix — their uncommitted Rust presumably accepts it. WORKAROUND that touches nothing: run the deploy with -p pointed at a scratch root holding an empty .yah/services and a symlink to the repo's .yah/infra.")
//! @yah:cleanup("The three voters now run 0.8.40-h1, bytes that are on no CDN and match no release manifest — the hot ship's intended state, recorded here so it is not forgotten. That build also carries whatever was uncommitted in the tree at 2026-09-12T08:00Z, notably peers' in-flight yubaba reconciler work (mesofact_static.rs -963 lines, native_support.rs deleted, dev_door.rs / http_auth.rs / cloud-client coordinator.rs untracked) and R876-B17's env-refusal change. Operator accepted that explicitly when authorising the pair. Cut a real release before anyone depends on it.")
//! @yah:handoff("Containerd materializes WorkloadSpec::files, so an inner door is no longer pinned to native-capable nodes. Staging + OCI rendering live in kamaji-containerd-core so both containerd shapes (kamaji inlined, kamaji-bin sibling) get it; the guard narrowed to Docker/MicroVm via the new Backend::materializes_files predicate rather than a per-call-site list. Verified locally (44+190+240 tests, Linux cross-compile, yubaba check) AND live on us-east-001 after a paired 0.8.40-h1 hot ship: a routed request served off a table that exists only in the spec, a file created at a path the image does not ship, redeploy replacing the staging tree, destroy removing it.")
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
        GetContainerRequest, KillRequest, ListContainersRequest, StartRequest,
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

use crate::socket_custody::SocketCustodian;
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
    /// This node's local `yah-scryer` ingestion socket, when one is configured
    /// (R893-B17). A container has its own mount namespace, so this backend
    /// both names the guest path in the workload's env and binds the host
    /// socket there via [`kcc::PodOptions::collector_socket`]; doing either
    /// without the other produces a workload pointed at nothing.
    collector: crate::observe::Collector,
    /// The socket `channel` dials; image pulls go through `ctr` against the
    /// same containerd (R931-B9).
    socket: PathBuf,
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
        let socket = socket.as_ref().to_path_buf();
        let channel = kcc::connect(&socket).await?;
        Ok(ContainerdRuntime {
            channel,
            socket,
            namespace: YAH_NAMESPACE.to_string(),
            log_base: PathBuf::from(LOG_BASE),
            ledger: RestartLedger::new(),
            slots: Arc::new(Mutex::new(HashMap::new())),
            custodian: Arc::new(SocketCustodian::new()),
            collector: crate::observe::Collector::disabled(),
        })
    }

    /// Point this backend's containers at the node's local collector
    /// (R893-B17). The containerd twin of
    /// [`crate::native::NativeRuntime::with_collector`] — same contract, and
    /// the mount-namespace difference is handled inside
    /// [`crate::observe::Collector`] rather than here.
    pub fn with_collector(mut self, collector: crate::observe::Collector) -> Self {
        self.collector = collector;
        self
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

        // Kill the task and WAIT for containerd to actually reap it.
        //
        // R854: this used to be a blind `sleep(500ms)` between the kill and the
        // delete, with the delete's result discarded. Containerd refuses to
        // delete a task that has not reached STOPPED, so any exit slower than
        // half a second left the task alive while the *container* delete below
        // succeeded anyway — and the next deploy's CreateTask collided with the
        // orphan ("task <ident>: already exists"). `reap_task` returns only once
        // containerd reports no task, and says so when it can't.
        if let Err(e) = kcc::reap_task(
            &mut tasks,
            &self.namespace,
            container_id,
            kcc::TASK_REAP_TIMEOUT,
        )
        .await
        {
            tracing::warn!(
                container_id = %container_id,
                error = %format!("{e:#}"),
                "task reap did not complete; a redeploy may collide with the survivor"
            );
        }

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

        // Drop this generation's staged `WorkloadSpec::files` (R870-F27).
        // Nothing mounts them once the container is gone, but they are
        // control-plane-derived config sitting on the node's disk, so they
        // leave with the workload rather than accumulating one directory per
        // dead generation.
        kcc::discard_spec_files(container_id).await;

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

        // Ensure the image is in the containerd image store, pulling it if
        // missing (R931-B9). `deploy_workload` already did this before its
        // teardown, so there it is a lookup; the graceful-upgrade path relies
        // on it here. Delegates to `kamaji-containerd-core` (R592-T1).
        let image_target_digest =
            kcc::ensure_image(&self.channel, &self.namespace, &self.socket, &image_ref).await?;

        // Image OCI config (ENTRYPOINT/CMD/ENV/WORKDIR/USER) merged per OCI
        // convention (R590-B8). Best-effort; unreadable → spec-only argv/env.
        let image_config =
            kcc::image_oci_config(&self.channel, &self.namespace, &image_target_digest)
                .await
                .ok();

        // Deployment env: the mesh IP and the `PORT` / `PORT_<NAME>` contract
        // (R844-T13), plus any caller extras (PASSWAY_UPGRADE on the incoming
        // graceful-upgrade container).
        //
        // The contract half is `crate::deploy_contract_env`, shared with
        // kamaji-bin's containerd backend so the two cannot disagree about what
        // a workload is told (R908-T1). It is applied *after* the spec's literal
        // env (asserted by `oci_spec_injects_mesh_ip_after_literal_env`), and
        // `DeployResult::ports` stays empty on this backend because a declared
        // container port is already the bound one.
        let mut deploy_env = crate::deploy_contract_env(spec, mesh.mesh_ip);
        // R893-B17: the local collector. `env_for` does its own spec-wins
        // filtering, so unlike the port block above this needs no skip here.
        // MountNs::Own because the bind installed below is what makes the path
        // it names resolve inside this container.
        for (k, v) in self.collector.env_for(spec, crate::observe::MountNs::Own) {
            deploy_env.push(format!("{k}={v}"));
        }
        deploy_env.extend(extra_env.iter().cloned());

        // R870-F27: materialize `WorkloadSpec::files` for THIS generation and
        // bind-mount each one in. Before the OCI spec is built, because the
        // mounts are part of it, and before the container record exists, so a
        // spec naming an unmaterializable path fails the deploy outright
        // instead of leaving a half-created container behind.
        let pod = kcc::PodOptions {
            spec_files: kcc::stage_spec_files(&kcc::spec_files_hostdir(container_id), spec)
                .await
                .with_context(|| format!("staging spec files for {container_id}"))?,
            // The other half of the env injected above (R893-B17) — set here
            // rather than in `pod_options` so it reaches EVERY container this
            // shape starts, including the graceful-upgrade generations that
            // arrive with their own `pod`.
            collector_socket: self.collector.guest_bind(),
            ..pod.clone()
        };

        // Build OCI spec (with pod placement) and wrap it as protobuf.Any.
        let oci_spec = kcc::build_oci_spec_with(spec, &deploy_env, image_config.as_ref(), &pod);
        // R932-B1: the full mount plan, now that `spec_files` and any custody
        // `shared_dir` are staged. `deploy_workload` already ran this over the
        // host-provided subset before the teardown; this one closes the gap
        // between that check and what runc will actually be handed.
        if let Err(message) = kcc::check_bind_sources(&oci_spec) {
            anyhow::bail!("workload {container_id}: {message}");
        }
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
        //
        // R854: via `create_task_reaping_stale`, so a task record that outlived
        // the caller's teardown is reaped and the create retried once, instead
        // of failing the whole deploy on "already exists".
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
            kcc::create_task_reaping_stale(&mut tasks, &self.namespace, req)
                .await
                .with_context(|| format!("creating task for {container_id}"))?
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
            hydrate: None,
            // R844-F2: a container gets its own network namespace, so its
            // declared `expose.mesh.ports` *is* the bound port — there is
            // nothing for this backend to resolve, and empty is the honest
            // answer rather than echoing the declaration back as if it were a
            // measurement. Callers fall back to the spec on empty.
            ports: Default::default(),
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
            let _ =
                tokio::fs::set_permissions(&host_dir, std::fs::Permissions::from_mode(0o700)).await;
        }
        Ok(kcc::PodOptions {
            // Host-networked passway (the F5 ingress) uses the host netns as
            // custodian, so no netns join. An isolated-netns workload would set
            // join_netns to a sandbox/pause container's netns path (deferred).
            join_netns: None,
            shared_dir: Some((host_dir.to_string_lossy().into_owned(), sock_dir)),
            // `create_and_start` fills this from `stage_spec_files` — it is
            // the only producer, and it knows the container id this
            // generation stages under.
            ..Default::default()
        })
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
    ///
    /// The custodial listener is bound in the **host** netns, which is exactly
    /// right for the F5 passway ingress — host-networked, and the only in-tree
    /// custody consumer. A non-host-networked passway is refused rather than
    /// quietly host-bound (R895-F1): this backend is the *inlined* shape, it
    /// creates no network namespace of its own, and the namespace a workload
    /// gets on a fleet node is created by [`crate::container_net`] on
    /// `kamaji-bin`'s deploy path, which is where that custody bind lives. A
    /// namespace nothing on this path created has no name this path may invent.
    async fn deploy_custody(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
        slot: kcc::PodSlot,
    ) -> Result<DeployResult> {
        let ident = spec.expose.mesh.identity.clone();
        if !spec.wants_host_network() {
            anyhow::bail!(
                "passway custody workload {} is not host-networked; the inlined \
                 containerd backend creates no network namespace, so it can only \
                 bind the custodial listener in the host netns (isolated-netns \
                 custody is wired on kamaji-bin's container_net deploy path)",
                ident.0
            );
        }
        let bind_addr = kcc::passway_listen_addr(spec);

        // 1. kamaji binds the listen socket (host netns) and holds the fd.
        self.custody_bind_and_hold(&ident.0, &bind_addr, None)
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
                oom_killed: false,
                reason: format!("exited with status {exit_status}"),
            },
            4 | 5 => WorkloadStatus::Stopping,
            1 => WorkloadStatus::Pending,
            _ => WorkloadStatus::Failed {
                oom_killed: false,
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
        // R844-F21: a name-only port asks this backend to allocate, and it
        // cannot — see `crate::reject_unresolved_ports`. Refused here rather
        // than dropped, so the manifest's author learns the spelling does not
        // apply to a container instead of watching a named port silently fail
        // to appear in the service record.
        crate::reject_unresolved_ports(&spec.name, &spec.expose.mesh, crate::Backend::Containerd)?;

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

        // The nested-sandbox grant (R636-B2) is the same shape of escape
        // hatch: it hands the container CAP_SETUID + CAP_SETGID and turns
        // `no_new_privs` off so rootless BuildKit can build a user namespace.
        // Gate it to the infra tier for the same reason.
        if spec.wants_nested_sandbox() && spec.tier.0 != "infra" {
            anyhow::bail!(
                "workload requests the nested-sandbox grant (annotation {}={}) but tier is {:?}; \
                 it is only permitted for tier=\"infra\"",
                workload_spec::NESTED_SANDBOX_ANNOTATION,
                workload_spec::NESTED_SANDBOX_VALUE,
                spec.tier.0,
            );
        }

        // Signed-recipe admission (R555-F4 / W235 §(c)). Deliberately AFTER the
        // two tier guards and BEFORE anything is torn down or created: the tier
        // checks are free and name a spec bug, this one may involve crypto and
        // names a trust decision, and neither should have side effects.
        workload_spec::admission::check(spec)
            .map_err(|e| anyhow::anyhow!("workload {} not admitted: {e}", spec.name))?;

        // R932-B1: refuse a spec whose bind mounts name a host path this node
        // does not have, BEFORE the teardown below destroys the incumbent.
        // runc checks the same thing at container-create time, by which point
        // the previous generation is already gone — that is the shape that took
        // `noisetable-account` down on 2026-09-22, over a mount kamaji injects
        // rather than one the workload declared.
        //
        // Built through `build_oci_spec_with` rather than read off
        // `spec.volumes` so the injected mounts are included and the check
        // cannot drift from the real mount plan. The throwaway `PodOptions`
        // carries only the collector bind: `spec_files` and the custody
        // `shared_dir` are staged by the deploy itself a few steps from now, so
        // they do not exist yet and must not be checked yet. `create_and_start`
        // re-runs the check against the *real* spec once they do.
        let preflight = kcc::build_oci_spec_with(
            spec,
            &[],
            None,
            &kcc::PodOptions {
                collector_socket: self.collector.guest_bind(),
                ..Default::default()
            },
        );
        if let Err(message) = kcc::check_bind_sources(&preflight) {
            anyhow::bail!("workload {}: {message}", spec.expose.mesh.identity.0);
        }

        // R931-B9: the image must be present (pulled if not) BEFORE the
        // teardown below — a missing or unpullable image used to surface only
        // after the incumbent was already gone.
        kcc::ensure_image(&self.channel, &self.namespace, &self.socket, &Self::image_ref(spec))
            .await
            .with_context(|| format!("workload {}: image unavailable", spec.name))?;

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
            filters: vec!["labels.\"yah.ident\"!=\"\"".to_string()],
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
                // See `deploy_workload` — namespaced, so nothing to resolve.
                ports: Default::default(),
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
            ports: Default::default(),
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
        StopPolicy, TenantId, TierTag, WorkloadSpec,
    };

    /// Returns `true` when a containerd socket is reachable. Used to skip
    /// tests on machines without containerd (standard CI, most dev Macs).
    async fn containerd_available() -> bool {
        ContainerdRuntime::connect().await.is_ok()
    }

    fn test_spec(name: &str) -> WorkloadSpec {
        WorkloadSpec {
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
                memory_request_mb: None,
                cpu_limit_millis: None,
                pids_max: None,
                scratch_floor_mb: None,
            },
            depends_on: vec![],
            requires: vec![],
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
                    ports: MeshExpose::anonymous_ports([]),
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            durability: None,
            db: Vec::new(),
            capabilities: Vec::new(),
            annotations: Default::default(),
            files: Vec::new(),
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

    /// R893-B17, same shape as the mesh-IP assertion above and for the same
    /// reason: what needs pinning is the deploy-env this call site builds, not
    /// `Collector` (which `observe`'s own tests cover).
    ///
    /// The container path, NOT the host path — `create_and_start` bind-mounts
    /// the host socket at `GUEST_SOCKET_PATH`, so naming the host path here
    /// would hand the workload a file that does not exist in its namespace.
    #[test]
    fn oci_spec_carries_the_collector_contract_as_the_container_sees_it() {
        let spec = test_spec("svc");
        let collector = crate::observe::Collector::at("/var/run/yah/scryer.sock");
        let mut deploy_env = vec!["YAH_MESH_IP=10.64.0.9".to_string()];
        for (k, v) in collector.env_for(&spec, crate::observe::MountNs::Own) {
            deploy_env.push(format!("{k}={v}"));
        }
        let oci = kcc::build_oci_spec(&spec, &deploy_env, None);
        let env: Vec<&str> = oci["process"]["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_str().unwrap())
            .collect();
        assert!(env.contains(&"YAH_SERVICE_IDENT=svc"), "got {env:?}");
        assert!(
            env.contains(&"YAH_SCRYER_SOCKET=/run/yah/scryer.sock"),
            "a container must read the guest path, never /var/run/yah/scryer.sock; got {env:?}"
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
                oom_killed: false,
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
            cursor: None,
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

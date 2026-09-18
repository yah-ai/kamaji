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
//!
//! @yah:ticket(R881-S2, "Decide how a tenant-tier workload gets a reachable address: real CNI plumbing vs widening the host-network gate")
//! @yah:phase(P1)
//! @yah:status(review)
//! @yah:at(2026-09-10T02:24:47Z)
//! @yah:kind(spike)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R881)
//! @yah:next("THE ARCHITECTURE CALL BEHIND R881, held for the operator rather than decided by an agent. A tenant-tier workload in its own netns currently has no reachable networking shape at all. Two ways out, and they are not equivalent in cost or in what they promise. (A) MAKE PER-WORKLOAD MESH ADDRESSING REAL — CNI/veth/bridge plumbing attached at or immediately after oss/kamaji/crates/kamaji-containerd-core/src/lib.rs:1101, where the netns is currently created bare. This is the thing yah-cloud-admin.toml:112-117 calls \"still a stub\" and defers to; doing it retires the host-networking escape hatch's reason to exist and gives every tenant workload a real address. Largest change, correct end state. (B) WIDEN THE GATE — permit host port publishing below tier=infra with its own guard rails, moving the check at oss/kamaji/crates/kamaji-bin/src/containerd.rs:1159. Much smaller, unblocks noisetable-account immediately, and the cost is that a privilege boundary written deliberately gets loosened for convenience — worth naming plainly rather than discovering later. NOTE the workload-spec doc at oss/yah-base/crates/workload-spec/src/lib.rs:2860-2863 frames host networking as \"a privileged escape hatch for the few infra workloads that must bind a host port... without CNI/bridge plumbing\", i.e. (B) is explicitly the shape (A) is supposed to make unnecessary.")
//! @yah:gotcha("DO NOT let a consumer unblock itself by flipping its tier to \"infra\" while this is undecided — that dodges the privilege boundary rather than moving it, and the noisetable camp explicitly declined to do so on its own CLAUDE.md's instruction. If (B) is chosen, the widening should be an explicit, named capability with guard rails, not a tier reclassification of the workload asking for it.")
//! @yah:gotcha("THE FLAGGED veth HIT IS REAL AND WAS READ — resolving the unread-hit caveat R881 filed against itself. `setup_veth_for_pid(pid, id)` at app/yah/cli/src/camp.rs:6849-6923 is REUSABLE IN TECHNIQUE BUT NOT IN POLICY. In its favour: it is PID-generic (it operates on /proc/&lt;pid&gt;/ns/net via ip + nsenter, so a containerd task PID would work) and it carries an RAII pair-delete guard. Against: it allocates link-local 169.254.x.y/30 with NO default route and NO NAT, and that absence is deliberate — it is precisely what denies the CLI sandbox internet access. So option (A) would reuse the mechanism and REPLACE the address plan, not adopt it wholesale. Useful, but it is not a shortcut to a finished (A).")
//! @yah:gotcha("SCOPE NARROWED BY R881-B1 LANDING: the silent-failure half is FIXED, so this ticket is now purely about reachability. As of R881-B1 the noisetable-account shape produces a record that is published but never Ready (`NotReady { reason: \"unroutable\" }`), and `yah cloud apply` now ERRORS naming the hostname instead of rendering a dead upstream. That means the 503 is no longer silent and nobody is losing an afternoon to it — this ticket is no longer urgent, only blocking. It blocks exactly one known consumer: noisetable's R131-T12 (api.noisetable.com), which is set down at handoff waiting on it. Also note the docker-backend correction on the parent: `yah.docker.publish` already publishes host ports, so option (B) has a nearer precedent in-tree than the framing here first suggested.")
//! @yah:handoff("THREE CHILDREN FILED IN DEPLOY ORDER, mapping 1:1 onto W343's \"What changes, in deploy order\": R881-T3 (kamaji, steps 1-3 — build the netns before runc and tear it down after, joined via the PodOptions::join_netns mechanism that containerd-core ALREADY honours at lib.rs:1097 and already tests at lib.rs:1776, so only the producer is missing); R881-T4 (yubaba, steps 4-5 — allocate a per-workload address, widen the R881-B1 routable predicate); R881-T5 (fleet, step 6 — advertise the /24, blocked_on operator because it is the one step that touches live infrastructure).")
//! @yah:verify("Every code location cited in W343 was opened and read this session, not inferred: containerd-core lib.rs:1090-1151 (the bare netns and the resolv.conf condition), kamaji-bin containerd.rs:1164-1192 (the tier gate), kamaji-bin server.rs:1886-1904 (backend.deploy drops the MeshAssignment), kamaji lib.rs:214-247 (MeshAssignment shape), kamaji-proto messages.rs:373-378 (Deploy carries mesh since V2), yubaba service_records.rs:401 (binds_node_ports), workload-spec lib.rs:2855-2868 (the \"without CNI/bridge plumbing\" sentence this design retires).")
//! @yah:handoff("DECISION MADE BY THE OPERATOR 2026-09-09, via ask_user with prefer=human, and recorded as canon in .yah/docs/working/W343-per-workload-mesh-addressing.md. CHOSEN: option (A) real per-workload mesh addressing — one bridge per node, one veth pair per workload, one routed /24 per node advertised to headscale as a subnet route. REJECTED: (B) widening the tier=infra host-network gate. ALSO REJECTED, and it was not in the ticket's original framing — a middle option (C) I put on the form: publish each workload's declared ports from the node's own address by DNAT, docker-style, keeping the container in its own netns without touching the privilege gate. Worth knowing why A beat C, because C is the cheaper build and the reasoning is the design's spine: DNAT makes the NODE's address the workload's address, so two workloads on one node cannot both hold the port their spec declares and the number a consumer dials stops being the number the author wrote. A routed /24 costs one extra moving part (route advertisement, R881-T5) and buys back \"a workload's declared port is its actual port, on an address that is its own\".")
//! @yah:gotcha("THE \"NO LONGER URGENT, ONLY BLOCKING\" FRAMING IS WRONG ON THE LIVE FLEET — R881-B1 landed in code but is NOT DEPLOYED. Measured from the noisetable camp 2026-09-09 by @Ashguard:polaris (courier, session:f98a1bf4) under noisetable R131-T12. B1's changes are confined to oss/yubaba/crates/yubaba/src/{service_records.rs,lib.rs} — the yubaba SERVER lib — and the yah CLI deliberately links the thin yubaba-client instead (app/yah/cli/Cargo.toml:169-171, with a comment saying so), so B1's runtime effect depends entirely on the yubaba running ON the node. `yah cloud apply --service noisetable-api --env cloud`, run twice from a CLI built at rev 74874f3e (which has bf89bfb5, B1's commit, as a `git merge-base --is-ancestor` ancestor), STILL RENDERED `PASSWAY_UPSTREAMS=api.noisetable.com=100.64.0.3:4332` — the exact dead-upstream render B1 exists to refuse. So the fleet-side yubaba on us-east-001 predates bf89bfb5, or its ledger entry predates the `routable` field, which service_records.rs:691 documents as defaulting TRUE for pre-R881 files. CONSEQUENCE FOR THIS TICKET: the 503 is still silent in production, so the urgency this gotcha retired has not actually been retired — it is deferred until the fleet rolls. Someone should confirm whether a yubaba fleet roll is needed for B1 to take effect, and whether the pre-R881 `routable` default means even a rolled node keeps trusting stale ledger entries.")
//!
//! @yah:ticket(R406-B14, "kamaji advertises a per-workload stdout.log for containerd workloads that it never writes — the real sink is the kamaji journal")
//! @yah:status(review)
//! @yah:at(2026-09-14T20:56:17Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R406)
//! @yah:severity(medium)
//! @yah:next("MEASURED ON us-east-001 2026-09-11 20:42 UTC against workload noisetable-account (containerd backend; kamaji pid 650851 up since 07:02:10, container task pid 659705 started 20:30:31). /var/log/yah/yah/noisetable-account/ holds FOUR entries: stdout.fifo + stderr.fifo (prw-------, root:root, recreated 20:30 with the deploy, held open by kamaji as fds 17 and 18 -- the live sink) AND stdout.log (732 bytes) + stderr.log (0 bytes), both root:root, both last written 06:56, i.e. before the 07:02 kamaji restart and four hours before the redeploy, holding a previous instance's boot lines. The .log pair is a relic of kamaji/src/containerd.rs:389-404, which still creates real stdout.log/stderr.log and points the shim at them, while the live daemon path (kamaji-bin/src/containerd.rs:311-360, R406-T10) mkfifos instead and fans into journald. The two containerd backends disagree about where a workload's output goes, and on a node that has rolled through R406-T10 the .log files survive forever as a stale, misleading artifact.")
//! @yah:next("THE COST IS REAL, NOT COSMETIC. An operator debugging this service by reading the per-workload path sees a dead file and concludes it logs nothing; it logs plenty, into `sudo journalctl -u kamaji`. That burned real time in noisetable's sign-in investigation -- noisetable camp ticket R131-B24, which documents the working incantation on its own side (web/services/account/src/main.rs module header and .yah/services/noisetable-api/service.toml) as the local mitigation. Two coherent fixes, pick one: (a) kamaji-bin's forwarder ALSO appends each line to <log_dir>/{stdout,stderr}.log so the advertised path is true, or (b) the .log files are retired outright -- kamaji/src/containerd.rs stops creating them, deploy/teardown unlinks any left behind, and whatever advertises the path says `journalctl -u kamaji` instead. Leaving both backends as they are is the only option that keeps reproducing this.")
//! @yah:next("Tier: Cleric -- an operator-facing call about which of two disagreeing backends defines the per-workload log contract, plus a small forwarder change. Judgement, not volume.")
//! @yah:verify("On a node running kamaji-bin's containerd backend: deploy any container workload, then `sudo ls -la /var/log/yah/yah/<id>/` and `sudo tail /var/log/yah/yah/<id>/stdout.log`. Fix (a) is done when the .log grows with the same lines `sudo journalctl -u kamaji` shows for that workload; fix (b) is done when no orphaned .log is left advertising a path nothing writes.")
//! @yah:gotcha("UNPRIVILEGED journalctl IS A SILENT FALSE NEGATIVE. As debian@us-east-001 (groups=debian only, neither adm nor systemd-journal) `journalctl -u kamaji` prints `-- No entries --` plus a hint and exits 0, so a grep for a line you expect comes back empty and reads as `the line is absent`. Use sudo. The same trap is already recorded for us-west-003 at kamaji/src/container_net.rs:86.")
//! @yah:gotcha("THE JOURNAL IS UNREADABLE WITHOUT A FILTER on us-east-001: of the day's kamaji lines, 12398 are the ~5s `WARN kamaji_bin::server: duplicate workload id across backends ... id=yah-marketing` repeat (R599-B11), against 3 `INFO noisetable_account`, 3 `INFO mesofact` and 2 `WARN cheers_axum::error`. Separate problem from this ticket, but it is what an operator hits first.")
//! @yah:gotcha("CORRECTED 2026-09-14 (supersedes an earlier gotcha that said there is NO per-workload journal field): there IS one. journal.rs build_journal_payload emits YAH_WORKLOAD_ID=<id> and YAH_STREAM=stdout|stderr on every forwarded line. The earlier probe asked for --output-fields=YAH_WORKLOAD, a name the code never emits. Proven live on us-east-001: `sudo journalctl YAH_WORKLOAD_ID=noisetable-account -n 3` returns that workload's lines, including the `INFO mesofact:` line from its own mesofact-app. A crate two workloads share is therefore correctly attributed. Use sudo, since the unprivileged false-negative gotcha still applies.")
//! @yah:handoff("FIX (b) CHOSEN AND LANDED: journald is kamaji-bin's containerd per-workload log; the relic .log files are removed. Picked on evidence, not taste: (1) the per-workload filter the ticket said was missing already exists (YAH_WORKLOAD_ID, proven live on us-east-001, see corrected gotcha); (2) kamaji-bin has no reader for per-workload files, so a tee (fix a) would duplicate every line into a file with no rotation and no consumer, while journald rotates. Reversing it means adding a tee sink in spawn_forwarder, about 30 lines.")
//! @yah:handoff("kamaji-bin/src/containerd.rs: new RELIC_LOG_FILES + retire_relic_logs() (unlinks stdout.log/stderr.log, logs each removal naming the journalctl incantation, best-effort, never fails a deploy), called in deploy_generation right after the FIFOs are ensured. New remove_log_dir() called at the end of teardown(), after reap_container: relics first, then a NON-recursive remove_dir, so anything unexpected is warned about and left. It is deliberately not in reap_container, because the redeploy path reaps after creating the dir it is about to mkfifo into (same reasoning as discard_spec_files). The deploy comment and journal.rs's Container bullet now state the contract (`sudo journalctl YAH_WORKLOAD_ID=<id>`) and note that the inlined kamaji::containerd backend (desktop / yubaba attach_runtime) is different: it DOES write .log files and reads them back via its own stream_logs, so it was left as is.")
//! @yah:handoff("NOT DONE: no startup-wide sweep of /var/log/yah/yah/*/. yubaba's attach_runtime can run the inlined backend against the same LOG_BASE, and a blanket sweep could delete its live files. Consequence on us-east-001: the untracked dirs yah-marketing (mtime 2026-07-06) and r870f27-filecheck (2026-09-12) are never torn down by kamaji-bin, so whatever they hold stays until someone removes it by hand. I did not list their contents.")
//! @yah:verify("`cargo test -p kamaji-bin --features containerd-integration --lib containerd::tests` in oss/kamaji: 21 passed, 0 failed, including the 4 new tests: retire_relic_logs_unlinks_both_logs_and_nothing_else (FIFO survives), retire_relic_logs_is_a_no_op_on_a_clean_or_missing_dir, remove_log_dir_removes_a_dir_holding_only_relics (idempotent second call), remove_log_dir_leaves_a_dir_holding_something_it_does_not_own. Run on macOS; the helpers are plain tokio::fs with no cfg gate. No root-workspace check was run: only private fns were added, and no signature changed.")
//! @yah:verify("NOT YET VERIFIED ON A NODE, which needs a kamaji roll. After the roll, on us-east-001 redeploy noisetable-account and run `sudo ls -la /var/log/yah/yah/noisetable-account/`: expect only stdout.fifo + stderr.fifo, with the 2026-09-11 06:56 stdout.log (732B) gone and a `removed relic workload log` line in `sudo journalctl -u kamaji`. Baseline read 2026-09-14 before the fix: both relic .log files present beside the live FIFOs.")

#![cfg(feature = "containerd-integration")]

use std::collections::HashMap;
use std::net::Ipv4Addr;
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
    /// This node's local `yah-scryer` ingestion socket, when one is configured
    /// (R893-B17). This is the containerd shape a fleet node actually runs, so
    /// it is the one that decides whether a containerized workload is traced in
    /// production at all — see `kamaji::observe`.
    collector: kamaji::observe::Collector,
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
            collector: kamaji::observe::Collector::disabled(),
        })
    }

    /// Point this backend's containers at the node's local collector
    /// (R893-B17).
    pub fn with_collector(mut self, collector: kamaji::observe::Collector) -> Self {
        self.collector = collector;
        self
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
    ///
    /// `netns` (R881-T3 / W343) is a namespace the caller has already created
    /// and wired — bridge, veth, address, default route. Passing it makes runc
    /// `setns` into it instead of unsharing an empty one, which is the whole
    /// difference between a workload something can dial and a workload that can
    /// only reach itself. `None` keeps the empty-namespace behaviour.
    ///
    /// A custody workload takes it too (R895-F1): kamaji binds that workload's
    /// listen socket *inside* this namespace, so the fd it hands over is routable
    /// on the workload's own address rather than on the host's. See
    /// [`deploy_custody`](Self::deploy_custody).
    ///
    /// `mesh_ip` (R908-T1) is the address yubaba placed the workload at. It
    /// reaches the process as `YAH_MESH_IP` beside the `PORT` contract
    /// ([`kamaji::deploy_contract_env`]), which is how a host-networked workload
    /// binds its node's mesh address without a spec naming it, and it is
    /// stamped as the `yah.mesh_ip` label so
    /// [`graceful_upgrade`](Self::graceful_upgrade) — whose frame carries no
    /// assignment — hands the next generation the same answer.
    pub async fn deploy(
        &self,
        id: &WorkloadId,
        spec: &WorkloadSpec,
        netns: Option<&Path>,
        mesh_ip: Ipv4Addr,
    ) -> Result<u32, BackendError> {
        if kcc::upgrade_sock_dir(spec).is_some() {
            return self.deploy_custody(id, spec, netns, mesh_ip).await;
        }
        let pod = kcc::PodOptions {
            join_netns: netns.map(|p| p.to_string_lossy().into_owned()),
            shared_dir: None,
            // `deploy_generation` fills this from `stage_spec_files` — it is
            // the only producer, and it knows the container id to stage under.
            ..Default::default()
        };
        self.deploy_generation(id, spec, &pod, mesh_ip, &[]).await
    }

    /// Create + start one containerd generation of `spec` under container id
    /// `id.as_str()`, placed at `mesh_ip`, with pod placement `pod` and extra
    /// process env `extra_env` (e.g. `PASSWAY_UPGRADE=true` for a custody
    /// passway). This is the shared body behind [`deploy`](Self::deploy),
    /// [`deploy_custody`](Self::deploy_custody), and
    /// [`graceful_upgrade`](Self::graceful_upgrade); it tears down any prior
    /// same-id generation first (idempotent redeploy).
    async fn deploy_generation(
        &self,
        id: &WorkloadId,
        spec: &WorkloadSpec,
        pod: &kcc::PodOptions,
        mesh_ip: Ipv4Addr,
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

        // R870-F27: materialize `WorkloadSpec::files` for THIS generation and
        // bind-mount each one in. Staged before the OCI spec is built (the
        // mounts are part of it) and before `reap_container` below, which is
        // deliberately NOT allowed to discard them — see `teardown`.
        let pod = kcc::PodOptions {
            spec_files: kcc::stage_spec_files(&kcc::spec_files_hostdir(&container_id), spec)
                .await
                .with_context(|| format!("staging spec files for {container_id}"))
                .map_err(BackendError::Containerd)?,
            // R893-B17, the bind half of the collector contract. Set here so it
            // reaches every generation this shape starts, custody ones
            // included; the env half is appended to `extra_env` just below.
            collector_socket: self.collector.guest_bind(),
            ..pod.clone()
        };

        // R908-T1: `YAH_MESH_IP` + the `PORT` contract first, from the one
        // function the inlined backend uses too, so the same spec is told the
        // same thing on either daemon. Then the caller's extras.
        //
        // R893-B17, the env half: `YAH_SERVICE_IDENT` + `YAH_SCRYER_SOCKET`
        // naming the path the bind above installs. Appended AFTER the caller's
        // extras for the same reason the whole `extra_env` layer sits after the
        // spec's literal env — but `Collector::env_for` has already dropped any
        // name the spec declares, so an operator's own value still wins.
        let mut contract_env = kamaji::deploy_contract_env(spec, mesh_ip);
        contract_env.extend_from_slice(extra_env);
        let mut extra_env = contract_env;
        extra_env.extend(
            self.collector
                .env_for(spec, kamaji::observe::MountNs::Own)
                .into_iter()
                .map(|(k, v)| format!("{k}={v}")),
        );

        // OCI spec — capabilities, mounts, namespaces, cgroup path, plus any
        // custody pod placement (shared upgrade-sock bind mount) and extra env.
        let oci_spec = kcc::build_oci_spec_with(spec, &extra_env, image_config.as_ref(), &pod);
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
        //
        // The journal IS this backend's per-workload log (R406-B14): read it
        // with `sudo journalctl YAH_WORKLOAD_ID=<id>`. The log dir holds only
        // the two FIFOs — no `stdout.log` / `stderr.log` is ever written here.
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

        retire_relic_logs(&log_dir).await;

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
            let labels = labels_for(spec, id, mesh_ip);
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
    /// Which namespace the custodial listener is bound in has exactly one
    /// answer, and `netns` carries it (R895-F1). A host-networked passway — the
    /// F5 ingress, the only in-tree custody consumer — binds in the **host**
    /// netns: it has no namespace of its own, and the host's is the one it runs
    /// in. Any other passway binds inside the namespace
    /// [`crate::server::build_container_netns`] created and wired for it, which
    /// is what makes the handed-over fd routable on the workload's own W343
    /// address.
    ///
    /// A non-host-networked passway with no such namespace is **refused**. That
    /// is the state of every node until `--container-net` is set and yubaba
    /// allocates per-workload addresses (R881-T4), and refusing is the honest
    /// answer: the alternative is binding on the host and handing the workload a
    /// listener on an address that is not its own. This backend does not invent a
    /// namespace name — a name derived here is indistinguishable from the name of
    /// a namespace nobody created, and binding into one of those fails at
    /// runtime.
    async fn deploy_custody(
        &self,
        id: &WorkloadId,
        spec: &WorkloadSpec,
        netns: Option<&Path>,
        mesh_ip: Ipv4Addr,
    ) -> Result<u32, BackendError> {
        let custody_netns = if spec.wants_host_network() {
            None
        } else {
            match netns {
                Some(path) => Some(path),
                None => {
                    return Err(BackendError::InvalidSpec(format!(
                        "passway custody workload {} is not host-networked and has no \
                         container network namespace; kamaji would have to bind its \
                         custodial listener on the host, on an address that is not the \
                         workload's. Start kamaji with --container-net and have yubaba \
                         assign the workload an address in this node's range (R881-T4), \
                         or declare the workload host-networked.",
                        id.as_str()
                    )));
                }
            }
        };
        let bind_addr = kcc::passway_listen_addr(spec);

        // 1. kamaji binds the listen socket (in `custody_netns`, or the host
        //    namespace when there is none) and holds the fd.
        self.custody_bind_and_hold(id.as_str(), &bind_addr, custody_netns)
            .await?;

        // 2. Start passway in upgrade mode with the shared upgrade-sock mount,
        //    inside the same namespace its listener was bound in.
        let pod = self.passway_pod_options(spec, custody_netns).await?;
        let pid = match self
            .deploy_generation(
                id,
                spec,
                &pod,
                mesh_ip,
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
        // The namespace to keep this workload in is the one its held listener was
        // bound in, and the custodian is what holds that namespace open — so it,
        // not a re-derivation, is what this path asks (R895-F1). `None` is both
        // "host-networked, nothing to join" and "nothing held", and the fallbacks
        // below treat them the same because a workload with no held socket is
        // getting a redeploy either way.
        let netns = self.custodian.held_netns(id.as_str());
        // Same reasoning for the address (R908-T1): the frame carries no
        // assignment, so the live generation's `yah.mesh_ip` label is what
        // yubaba placed it at. Re-read, never re-derived.
        let mesh_ip = self.placed_mesh_ip(id).await;
        if kcc::upgrade_sock_dir(spec).is_none() {
            warn!(
                container_id = %id.as_str(),
                "graceful_upgrade: not a passway workload; connection-dropping redeploy"
            );
            return self.deploy(id, spec, netns.as_deref(), mesh_ip).await;
        }
        if !self.custodian.holds(id.as_str()) {
            // No held socket (never custody-deployed, or the daemon restarted).
            // A fresh custody deploy rebinds it — necessarily a redeploy. An
            // isolated-netns passway is refused here rather than host-bound: the
            // namespace this daemon has forgotten must be re-created by the deploy
            // path that owns it, which is a Deploy frame, not an upgrade.
            info!(
                container_id = %id.as_str(),
                "graceful_upgrade: no held socket; custody-deploying fresh"
            );
            return self.deploy(id, spec, netns.as_deref(), mesh_ip).await;
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
        let pod = self.passway_pod_options(spec, netns.as_deref()).await?;
        let pid = self
            .deploy_generation(
                id,
                spec,
                &pod,
                mesh_ip,
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

    /// The address the live generation of `id` was placed at, read back off the
    /// [`MESH_IP_LABEL`] that [`deploy_generation`](Self::deploy_generation)
    /// stamps (R908-T1).
    ///
    /// Loopback when there is no readable label — no live container, or one
    /// started by a kamaji that predates the label. That is the sentinel
    /// `runtime_mesh` uses for a Deploy with no assignment, and the safe
    /// direction: a workload binding `YAH_MESH_IP` comes up unreachable rather
    /// than on an address that is not its own. Logged, because the upgrade then
    /// changes what the workload is told.
    async fn placed_mesh_ip(&self, id: &WorkloadId) -> Ipv4Addr {
        let req = GetContainerRequest {
            id: id.as_str().to_string(),
        };
        let req = with_namespace!(req, self.namespace);
        let placed = self
            .containers_client()
            .get(req)
            .await
            .ok()
            .and_then(|resp| resp.into_inner().container)
            .and_then(|c| c.labels.get(MESH_IP_LABEL).and_then(|s| s.parse().ok()));
        placed.unwrap_or_else(|| {
            warn!(
                container_id = %id.as_str(),
                "graceful_upgrade: live generation carries no readable yah.mesh_ip label; \
                 the next generation is told YAH_MESH_IP=127.0.0.1"
            );
            Ipv4Addr::LOCALHOST
        })
    }

    /// Pod placement for a passway custody workload: the shared upgrade-sock
    /// host directory bind-mounted at the socket's container-side parent, so
    /// kamaji can `connect()` from the host mount namespace to hand off the fd.
    /// Single-id rotation reaps the old generation before starting the new one,
    /// so one directory per ident is race-free (slot `A`).
    async fn passway_pod_options(
        &self,
        spec: &WorkloadSpec,
        netns: Option<&Path>,
    ) -> Result<kcc::PodOptions, BackendError> {
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
            // Otherwise the generation joins the SAME namespace its custodial
            // listener was bound in (R895-F1), so the process and the fd it
            // adopts share one network view.
            join_netns: netns.map(|p| p.to_string_lossy().into_owned()),
            shared_dir: Some((host_dir.to_string_lossy().into_owned(), sock_dir)),
            // `deploy_generation` fills this from `stage_spec_files` — it is
            // the only producer, and it knows the container id to stage under.
            ..Default::default()
        })
    }

    /// Bind the custodial listener for `ident` on `bind_addr` — inside `netns`
    /// when the caller created one, otherwise in the host namespace — and hold
    /// it. The bind and the `setns` can block, so it runs on a blocking thread.
    async fn custody_bind_and_hold(
        &self,
        ident: &str,
        bind_addr: &str,
        netns: Option<&Path>,
    ) -> Result<(), BackendError> {
        let cust = self.custodian.clone();
        let ident = ident.to_string();
        let bind = bind_addr.to_string();
        let bind_for_ctx = bind.clone();
        let netns = netns.map(|p| p.to_path_buf());
        tokio::task::spawn_blocking(move || cust.bind_and_hold(&ident, &bind, netns.as_deref()))
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
        // R870-F27: this generation's staged `WorkloadSpec::files` leave with
        // the workload — they are control-plane-derived config on the node's
        // disk, not scratch. Deliberately here and NOT in `reap_container`:
        // that one also runs on the idempotent-redeploy path, *after* the
        // incoming generation has already been staged, so discarding there
        // would delete the files the deploy is about to mount. A redeploy
        // needs no discard anyway — `stage_spec_files` clears the directory
        // itself before writing.
        kcc::discard_spec_files(resolved.as_str()).await;
        self.reap_container(&resolved).await?;
        // Deliberately here and NOT in `reap_container`, for the same reason as
        // the spec files above: the redeploy path reaps AFTER creating the log
        // dir it is about to mkfifo into.
        remove_log_dir(&self.log_dir(resolved.as_str())).await;
        Ok(())
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

/// Regular files a pre-R406-T10 kamaji left in a workload's log dir (R406-B14).
///
/// That binary pointed the shim at real `stdout.log` / `stderr.log`; this one
/// points it at FIFOs and fans into journald, so on a node that rolled through
/// the change these files stop growing and keep advertising a per-workload log
/// that nothing writes. Measured on us-east-001: noisetable-account's pair was
/// last written two days before, while its live output was in the journal.
const RELIC_LOG_FILES: [&str; 2] = ["stdout.log", "stderr.log"];

/// Unlink [`RELIC_LOG_FILES`] from `log_dir`, naming each one removed. Best
/// effort: a failure is logged and never fails a deploy or teardown.
async fn retire_relic_logs(log_dir: &Path) {
    for name in RELIC_LOG_FILES {
        let path = log_dir.join(name);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => info!(
                path = %path.display(),
                "kamaji: removed relic workload log; this backend logs to journald (journalctl YAH_WORKLOAD_ID=<id>)"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                path = %path.display(),
                error = %e,
                "kamaji: failed to remove relic workload log"
            ),
        }
    }
}

/// Remove a torn-down workload's log dir: relic logs first, then the dir
/// itself. `remove_dir` is non-recursive on purpose — anything still in there
/// is not ours to delete, so it is reported and left.
async fn remove_log_dir(log_dir: &Path) {
    retire_relic_logs(log_dir).await;
    match tokio::fs::remove_dir(log_dir).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            log_dir = %log_dir.display(),
            error = %e,
            "kamaji: left workload log dir in place after teardown"
        ),
    }
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

/// Label carrying the address yubaba placed the workload at (R908-T1). The
/// inlined backend stamps the same key, so one reader works against either.
const MESH_IP_LABEL: &str = "yah.mesh_ip";

/// Build labels Kamaji stamps on every container — these are how
/// `list_workloads` filters yah-managed containers out of other orchestrators'
/// containers in the same containerd namespace, and how reconciliation
/// recovers the workload id after a Kamaji restart.
fn labels_for(spec: &WorkloadSpec, id: &WorkloadId, mesh_ip: Ipv4Addr) -> HashMap<String, String> {
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
    // R908-T1: where yubaba placed it, so graceful_upgrade can re-read it.
    labels.insert(MESH_IP_LABEL.to_string(), mesh_ip.to_string());
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
/// floor in `server::validate_native_exec_spec` — unresolved
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
        ResourceLimits, RestartPolicy, StopPolicy, TenantId, TierTag,
    };

    fn make_spec(name: &str) -> WorkloadSpec {
        WorkloadSpec {
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
                memory_request_mb: None,
                cpu_limit_millis: None,
                pids_max: None,
                scratch_floor_mb: None,
            },
            depends_on: vec![],
            requires: vec![],
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
            durability: None,
            annotations: Default::default(),
            files: Vec::new(),
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
        let labels = labels_for(&spec, &WorkloadId::new("svc"), Ipv4Addr::new(100, 64, 0, 7));
        assert_eq!(labels.get("yah.ident").map(|s| s.as_str()), Some("svc"));
        assert_eq!(labels.get("yah.name").map(|s| s.as_str()), Some("svc"));
        assert_eq!(labels.get("yah.tier").map(|s| s.as_str()), Some("public"));
        // R590-B9: the mesh identity is stamped for the state-poll read path.
        assert_eq!(
            labels.get("yah.mesh-ident").map(|s| s.as_str()),
            Some("svc")
        );
        // R908-T1: the placed address, for graceful_upgrade to read back.
        assert_eq!(
            labels.get(MESH_IP_LABEL).map(|s| s.as_str()),
            Some("100.64.0.7")
        );
    }

    /// R908-T1: this backend used to tell a workload nothing about where it was
    /// placed, so a host-networked spec had to name its node's IP. It now gets
    /// the same contract env as the inlined backend, from the same function,
    /// and the contract still yields a port variable the spec sets itself.
    #[test]
    fn contract_env_reaches_the_process_with_the_placed_address_and_port() {
        let spec = make_spec("svc");
        let env = kamaji::deploy_contract_env(&spec, Ipv4Addr::new(100, 64, 0, 1));
        let oci = kcc::build_oci_spec_with(&spec, &env, None, &kcc::PodOptions::default());
        let process_env: Vec<&str> = oci["process"]["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(
            process_env.contains(&"YAH_MESH_IP=100.64.0.1"),
            "{process_env:?}"
        );
        assert!(process_env.contains(&"PORT=8080"), "{process_env:?}");

        let mut pinned = make_spec("svc");
        pinned.env.push(EnvVar {
            name: "PORT".into(),
            value: EnvValue::Literal {
                value: "9999".into(),
            },
        });
        let env = kamaji::deploy_contract_env(&pinned, Ipv4Addr::LOCALHOST);
        assert!(!env.iter().any(|e| e.starts_with("PORT=")), "{env:?}");
        assert!(
            env.contains(&"YAH_MESH_IP=127.0.0.1".to_string()),
            "{env:?}"
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

    // ── R406-B14: no advertised stdout.log nothing writes ─────────────────────

    #[tokio::test]
    async fn retire_relic_logs_unlinks_both_logs_and_nothing_else() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("stdout.log"), b"a previous instance's boot lines").unwrap();
        std::fs::write(dir.join("stderr.log"), b"").unwrap();
        std::fs::write(dir.join("stdout.fifo"), b"").unwrap();
        retire_relic_logs(dir).await;
        assert!(!dir.join("stdout.log").exists());
        assert!(!dir.join("stderr.log").exists());
        assert!(dir.join("stdout.fifo").exists(), "the live sink must survive");
    }

    #[tokio::test]
    async fn retire_relic_logs_is_a_no_op_on_a_clean_or_missing_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        retire_relic_logs(tmp.path()).await;
        retire_relic_logs(&tmp.path().join("never-created")).await;
    }

    #[tokio::test]
    async fn remove_log_dir_removes_a_dir_holding_only_relics() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("noisetable-account");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("stdout.log"), b"stale").unwrap();
        remove_log_dir(&dir).await;
        assert!(!dir.exists());
        // Idempotent: a second teardown finds nothing and does not panic.
        remove_log_dir(&dir).await;
    }

    #[tokio::test]
    async fn remove_log_dir_leaves_a_dir_holding_something_it_does_not_own() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("w");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("stdout.log"), b"stale").unwrap();
        std::fs::write(dir.join("core.1234"), b"not ours").unwrap();
        remove_log_dir(&dir).await;
        assert!(dir.join("core.1234").exists());
        assert!(!dir.join("stdout.log").exists());
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

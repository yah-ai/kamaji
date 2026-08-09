//! Kamaji — yah's relocatable workload-supervisor primitive.
//!
//! This crate is the public surface of Kamaji (per W199): the trait one
//! caller hand-rolls against (`Kamaji`), the typed inputs/outputs it
//! exchanges with the runtime backend, and the `Backend` enum tagging which
//! concrete backend a given Kamaji instance is driving.
//!
//! ## Two deployment shapes
//!
//! Per W199 §The move, the same trait is used in both shapes:
//!
//! - **Inlined** — the caller holds `Arc<dyn Kamaji>` directly. Used by
//!   the desktop app where Kamaji shares the Tauri process tree.
//! - **Sibling** — the caller holds a `KamajiClient` that speaks the
//!   W154 postcard-over-UDS protocol to a separate `kamaji.service`
//!   process. Used by yubaba on cluster hosts.
//!
//! T1 only ships the public surface; the inlined / sibling constructors and
//! the backend impls land in R484-T2 / T4 / T5.
//!
//! ## Package naming
//!
//! Package is `kamaji-core` (not `kamaji`) because `app/yah/kamaji`
//! already claims the `kamaji` workspace package name. Once R484-T5
//! rewires that binary to depend on this crate, a follow-up may rename one
//! of them. The crate path (`crates/yah/kamaji/`) matches the W199 plan.
//!
//! @arch:see(.yah/docs/working/W199-kamaji-universal-supervisor.md)
//! @arch:see(.yah/docs/working/W154-yubaba-dual-runtime.md)
//!
//! @yah:ticket(R592-T1, "Extract shared kamaji backend core so inlined and sibling shapes cannot drift (containerd/native/docker/probe)")
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:at(2026-07-02T20:00:56Z)
//! @yah:phase(P1)
//! @yah:parent(R592)
//! @yah:next("Duplicated logic: oss/kamaji/crates/kamaji/src/{containerd,native,docker,probe}.rs (inlined shape) vs oss/kamaji/crates/kamaji-bin/src/{containerd,native,probe}.rs (sibling daemon). Extract shared OCI-spec-building / task-lifecycle / spawn+sandbox / probe logic into one home — smallest workable shape (shared module in the kamaji crate that kamaji-bin consumes, or a new core crate). Verify the existing dep direction between kamaji and kamaji-bin first and follow it.")
//! @yah:next("No behavior change. The sandbox/caps code (setresuid, capability bounding clear, landlock, cgroup-v2 writes) is exactly what security audits read twice — exactly one copy after this ticket.")
//! @yah:next("Do NOT touch oss/kamaji/crates/kamaji-proto/src/codec.rs (live peer fix in flight, R590-B3).")
//! @yah:verify("cd oss/kamaji && cargo check --workspace --all-features && cargo test --workspace")
//! @yah:gotcha("Host is macOS: containerd/native integration paths cannot run here. Keep the refactor compile-clean: cargo check --workspace --all-features must pass; run the cross-platform unit tests; document anything only checkable on Linux.")
//! @yah:tier(Warrior)
//! @yah:handoff("Delivered: new crate kamaji-containerd-core (containerd-integration-gated) deduping OCI-spec build, image-digest/rootfs resolution, task-status probe, client plumbing; both containerd.rs backends now delegate (net -732 lines). Scope finding: containerd was the ONLY genuine dup — native.rs pair = different maturity (inlined has NO sandbox yet), probe.rs pair = unrelated features sharing a filename; W266 corrected. Drift found+resolved: (1) capability sets had diverged — inlined granted CAP_KILL+CAP_NET_BIND_SERVICE, sibling only CAP_NET_BIND_SERVICE per W154 parity contract; narrower set adopted for both (behavior change on a dormant path — containerd-integration ships in no build today). (2) missing-process task-status semantics had diverged; adversarial review caught the dedup silently moving inlined Failed->Stopped — fixed via three-variant TaskProbe in core, each shape's wrapper restores its exact prior folding (inlined: code-0->Failed; sibling: Pending). (3) mesh-env/label gap: sibling has NO MeshAssignment concept — preserved via extra_env seam, real maturity gap relevant to R593. Adversarial review: 6/6 claims CONFIRMED after fix. Verify: cargo check+test workspace all-features green (me + implementer + reviewer independently); one pre-existing probe.rs flake filed as R592-B6. Linux-only paths (cgroup/landlock/pidfd/live containerd round-trips) compile-checked only — flagged for a Linux host.")
//!
//! @yah:ticket(R556-T8, "kamaji: scryer service manifest + lifecycle wiring (per-node yah-scryer)")
//! @yah:status(review)
//! @yah:at(2026-06-30T06:37:34Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:phase(P1)
//! @yah:parent(R556)
//! @yah:handoff("LANDED — but NOT in this crate. The annotation is homed here (kamaji owns the service concept) while the implementation lives in app/yah/cli/src/supervisor_unit.rs: render_scryer / render_user_scryer emit yah-scryer.service from the W264 §Process-model fingerprint (root variant is app/yah/cli/resources/yah-scryer.service; the rootless variant strips DynamicUser/capabilities/ProtectSystem=strict because a `systemd --user` manager rejects them, and binds loopback instead of the tailnet). Scryer is ordered to start last so its listener finds a sane interface. Tests: app/yah/cli/tests/camp_systemd_unit_emit.rs and camp_install_idempotent.rs (quartet + yah-camp = 5 units; rootless write set = kamaji + yubaba + yah-scryer = 3). READ THIS BEFORE CONCLUDING IT IS UNIMPLEMENTED: grepping oss/kamaji for 'scryer' returns only these annotation lines, which reads exactly like dead paperwork. It is not.")
//! @yah:next("Add a scryer service manifest to kamaji (binary: yah-scryer, listen: <node-tailnet-ip>:6543, data: /var/lib/yah/scryer/, restart: always, health: GET /health -> 200, drop_privileges: yes) per W264 §Process model.")
//! @yah:next("Wire lifecycle (start/restart/drain) through the existing kamaji service path so a node without the manifest cleanly opts out (mesh tolerates absent scryer = best-effort federation).")
//! @yah:next("Tier: Cleric — service-manifest authoring in an existing manifest path; pattern-matches other kamaji-managed services, no novel design.")
//! @arch:see(.yah/docs/working/W264-kamaji-managed-scryer.md)
//!
//!

pub mod inlined;
pub mod probe;

#[cfg(feature = "sibling")]
pub mod sibling;

pub use inlined::Inlined;
pub use probe::{BackendAvailability, BackendProbe};

#[cfg(feature = "containerd-integration")]
pub mod containerd;

#[cfg(feature = "docker-integration")]
pub mod docker;

#[cfg(feature = "native-integration")]
pub mod native;

/// On-demand ("serverless") JIT lifecycle (R599-F6): kamaji holds a workload's
/// listen socket via the [`socket_custody`] custodian, forks the serve runtime
/// on the first connection (systemd-style socket activation), and reaps it after
/// an idle TTL. Built on the native fork+exec machinery, so gated on the same
/// `native-integration` feature (which pulls in `socket-custody`).
#[cfg(feature = "native-integration")]
pub mod jit;

/// Socket-custodian primitive (R599-F9): kamaji binds+holds a workload's listen
/// socket and hands the fd to the workload process over its pingora upgrade
/// socket. Shared core under R599-F6 (JIT) and R600-F9 (cert-rotation).
#[cfg(feature = "socket-custody")]
pub mod socket_custody;

#[cfg(feature = "testing")]
pub mod fake;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures_core::Stream;
use serde::{Deserialize, Serialize};

pub use workload_spec::{MeshIdent, WorkloadSpec};

// ── Backend tag ───────────────────────────────────────────────────────────────

/// Which concrete runtime a given `Kamaji` instance is driving.
///
/// Per W199 §Backend availability, Kamaji carries three backends. The
/// `Native` backend is always available (fork+exec for musl-static Rust
/// workloads); `Containerd` and `Docker` are probed at init and may be
/// absent on a given host. Workloads that request an absent backend fail
/// with a structured [`BackendUnavailable`] error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    /// Direct fork+exec+cgroup+pidfd of a musl-static Rust binary. Always
    /// available on Linux; returns `Unsupported` on other hosts.
    Native,
    /// gRPC to a local containerd socket. Standard on fleet hosts.
    Containerd,
    /// Docker CLI shell-out — dev backend for OrbStack / Docker Desktop /
    /// Colima. The pond outer substrate uses this.
    Docker,
}

/// Reported when a workload requests a backend that this Kamaji instance
/// has not initialized. Carries a human-readable install hint so the camp /
/// desktop can surface "install Docker Desktop" rather than just a generic
/// error.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("backend {backend:?} is not available on this host: {detail}")]
pub struct BackendUnavailable {
    pub backend: Backend,
    pub detail: String,
    /// Optional install hint (e.g. "Install Docker Desktop or OrbStack").
    pub install_hint: Option<String>,
}

// ── Log stream type alias ─────────────────────────────────────────────────────

/// Boxed, pinned log stream returned by [`Kamaji::stream_logs`].
pub type LogStream = Pin<Box<dyn Stream<Item = LogEvent> + Send + 'static>>;

// ── Supporting types ──────────────────────────────────────────────────────────

/// Mesh context passed to `deploy_workload` for backends that wire workloads
/// onto a cluster-internal WireGuard mesh.
///
/// For inlined desktop deployments where there is no mesh, callers pass
/// [`MeshAssignment::inlined`] (a sentinel value with `wg_listen_port = 0`
/// and an empty `peers` list). T2 will reconcile this with yubaba's existing
/// `mesh::MeshAssignment` type during the carve-out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshAssignment {
    /// Mesh-plane IP. For inlined desktop, an unused loopback-ish address;
    /// for cluster nodes, assigned from raft's `100.64.0.0/10` pool.
    pub mesh_ip: Ipv4Addr,
    pub wg_private_key: String,
    pub wg_listen_port: u16,
    pub peers: Vec<WireguardPeer>,
    pub netns_name: Option<String>,
}

impl MeshAssignment {
    /// Sentinel assignment for inlined desktop / single-node use. No
    /// WireGuard configuration is applied — `has_wireguard()` returns false.
    pub fn inlined(mesh_ip: Ipv4Addr) -> Self {
        MeshAssignment {
            mesh_ip,
            wg_private_key: String::new(),
            wg_listen_port: 0,
            peers: Vec::new(),
            netns_name: None,
        }
    }

    /// Pre-W199 name for [`MeshAssignment::inlined`]. Kept as an alias so
    /// yubaba's existing call sites compile without churn during the carve-
    /// out (R484-T2). New code should prefer `inlined()`.
    pub fn stub(mesh_ip: Ipv4Addr) -> Self {
        Self::inlined(mesh_ip)
    }

    pub fn has_wireguard(&self) -> bool {
        !self.wg_private_key.is_empty()
    }
}

/// One WireGuard peer entry in the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardPeer {
    pub public_key: String,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpAddr>,
}

/// Result of a successful `deploy_workload` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    pub container_id: String,
    pub mesh_ip: Ipv4Addr,
    pub task_pid: u32,
}

/// Point-in-time state snapshot for one deployed workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadState {
    pub ident: MeshIdent,
    pub container_id: String,
    pub status: WorkloadStatus,
    pub mesh_ip: Option<Ipv4Addr>,
}

/// Lifecycle status of a deployed workload.
///
/// `Restarting` subsumes pond-side `Degraded` per R471 — both encoded
/// "workload is in-flight restarting", but `Restarting` carries the richer
/// payload (exit code + count + finished-at). Backends populate differently:
///
/// - `Backend::Containerd` synthesizes from an in-supervisor `RestartLedger`
///   (containerd has no native restart-count signal).
/// - `Backend::Docker` reads `docker inspect .State.Restarting` /
///   `RestartCount` / `ExitCode` / `FinishedAt` directly.
/// - `Backend::Native` is supervisor-driven: the fork+exec loop records
///   each exit and re-execs per `RestartPolicy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkloadStatus {
    Pending,
    Running,
    Stopping,
    Stopped,
    Restarting {
        last_exit_code: i32,
        restart_count: u32,
        last_finished_at_unix_ms: u64,
    },
    Failed {
        reason: String,
    },
}

impl WorkloadStatus {
    /// `true` for states the supervisor will not advance out of on its own.
    /// `Restarting` is **not** terminal — the runtime is actively cycling.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            WorkloadStatus::Stopped | WorkloadStatus::Failed { .. }
        )
    }
}

/// Options controlling which log lines `stream_logs` returns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogOpts {
    pub tail: Option<u64>,
    pub follow: bool,
    pub stream: Option<LogStreamKind>,
}

/// Which stdio stream a log line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStreamKind {
    Stdout,
    Stderr,
}

/// One log line emitted by a workload container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp_ms: u64,
    pub ident: MeshIdent,
    pub stream: LogStreamKind,
    pub message: String,
    pub correlation_id: Option<String>,
}

impl LogEvent {
    pub fn plain(ident: MeshIdent, stream: LogStreamKind, message: impl Into<String>) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        LogEvent {
            timestamp_ms,
            ident,
            stream,
            message: message.into(),
            correlation_id: None,
        }
    }
}

/// Aggregate health of one backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeHealth {
    /// `true` when the backend socket / runtime is reachable and healthy.
    pub ok: bool,
    /// Backend version string when available (e.g. containerd `"1.7.14"`).
    pub version: Option<String>,
    /// Human-readable detail for degraded / failed states.
    pub detail: Option<String>,
}

// ── Stateful-service contract (W195 §3) ───────────────────────────────────────

/// Owned declaration of a service's persistent SQL state (W195 §3).
///
/// Every yah service that owns `.turso` files registers one of these with
/// kamaji so backup, disaster recovery, and regional rebalancing are
/// handled generically. `files` paths are relative to the service's root
/// (camp_root for camp-local services, workload data dir for pond services).
///
/// Build from a compile-time [`BuiltinService`] descriptor via
/// `BuiltinService::contract()`, or construct directly for dynamic services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatefulServiceContract {
    /// Human-readable service name, unique within a camp / pond.
    pub name: String,
    /// Relative paths of `.turso` files owned by this service.
    pub files: Vec<String>,
    /// Optional SQL vending endpoint (Mode B per W195 §1).
    pub vend_endpoint: Option<String>,
    /// Opaque schema version used by kamaji for drift detection. Typically
    /// an ISO-8601 date string matching when the schema was last changed.
    pub schema_version: String,
    /// Optional R2 (or compatible) backup target pattern, e.g.
    /// `"r2://yah-backups/{name}/{file}"`. `{file}` is replaced with the
    /// basename of each entry in `files`.
    pub backup_target: Option<String>,
}

/// Compile-time descriptor for a built-in (always-present) yah service.
///
/// Built-in services ship as Rust constants — their declarations don't live in
/// any user-visible `.yah/` file because they're identical across all yah
/// installs. Call [`BuiltinService::contract`] at runtime to obtain an owned
/// [`StatefulServiceContract`] suitable for registering with kamaji.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinService {
    pub name: &'static str,
    /// Relative file paths (from camp_root / service root).
    pub files: &'static [&'static str],
    pub vend_endpoint: Option<&'static str>,
    /// ISO-8601 date of last schema change.
    pub schema_version: &'static str,
    pub backup_target: Option<&'static str>,
}

impl BuiltinService {
    pub const fn new(
        name: &'static str,
        files: &'static [&'static str],
        schema_version: &'static str,
    ) -> Self {
        Self {
            name,
            files,
            vend_endpoint: None,
            schema_version,
            backup_target: None,
        }
    }

    /// Convert to an owned [`StatefulServiceContract`] for runtime use.
    pub fn contract(&self) -> StatefulServiceContract {
        StatefulServiceContract {
            name: self.name.to_string(),
            files: self.files.iter().map(|s| s.to_string()).collect(),
            vend_endpoint: self.vend_endpoint.map(|s| s.to_string()),
            schema_version: self.schema_version.to_string(),
            backup_target: self.backup_target.map(|s| s.to_string()),
        }
    }
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// The relocatable workload-supervision contract.
///
/// One trait, two deployment shapes (W199): inlined (caller holds
/// `Arc<dyn Kamaji>`) or sibling (caller holds a `KamajiClient` that
/// implements this trait by forwarding over UDS).
///
/// The methods map to the workload lifecycle: deploy, list, get, log,
/// restart, graceful-upgrade, teardown, health. The trait is intentionally *not*
/// compose-shipper-shaped — callers hand it typed [`WorkloadSpec`] values,
/// not compose YAML.
///
/// Carved out from yubaba's pre-W199 `ContainerRuntime` trait. R484-T2 moves
/// the concrete `runtime::{native, containerd, docker}` impls here.
#[async_trait]
pub trait Kamaji: Send + Sync {
    /// Which backend this Kamaji instance is driving. Used by callers
    /// that need to branch on capability (e.g. "show 'install Docker' UI
    /// when Backend::Docker is unavailable").
    fn backend(&self) -> Backend;

    /// Deploy a workload described by `spec` onto the cluster mesh as
    /// described by `mesh`.
    async fn deploy_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> anyhow::Result<DeployResult>;

    /// List all workloads currently known to this Kamaji instance.
    async fn list_workloads(&self) -> anyhow::Result<Vec<WorkloadState>>;

    /// Get the current state of one workload by mesh identity. Returns
    /// `Ok(None)` when no workload with that identity is found.
    async fn get_workload(&self, ident: &MeshIdent) -> anyhow::Result<Option<WorkloadState>>;

    /// Open a log stream for the named workload.
    async fn stream_logs(&self, ident: &MeshIdent, opts: LogOpts) -> anyhow::Result<LogStream>;

    /// Restart a running workload (SIGTERM + grace, then fresh task).
    async fn restart_workload(&self, ident: &MeshIdent) -> anyhow::Result<()>;

    /// Rotate a running workload onto fresh on-disk material (e.g. a renewed
    /// TLS cert re-rendered into its secret mount) **without dropping live
    /// connections** — the supervisor half of pingora's zero-downtime
    /// hot-upgrade (R600-F4 / W273).
    ///
    /// Unlike [`Self::restart_workload`] (SIGTERM + fresh task, which drops
    /// in-flight connections), this executes passway's graceful-upgrade
    /// contract (see passway `main.rs` §"The graceful-upgrade signal
    /// contract"): start a **new** instance of `spec` in upgrade mode
    /// (`PASSWAY_UPGRADE=true`, same `PASSWAY_PID_FILE` / `PASSWAY_UPGRADE_SOCK`
    /// on a shared mount, same network namespace as the running instance so it
    /// inherits the listening fds over the upgrade socket), wait for it to come
    /// up, then `SIGQUIT` the old instance so it hands off its fds, drains
    /// in-flight connections, and exits. The new instance takes over the
    /// workload identity.
    ///
    /// The workload never self-triggers this — spawning a live sibling before
    /// the signal is an orchestration only the supervisor can sequence safely
    /// (passway `main.rs` documents why a self-upgrade would be unsafe).
    ///
    /// Returns the [`DeployResult`] of the new instance that took over.
    ///
    /// The default implementation returns an error: only backends that can
    /// sequence the sibling-then-signal handoff override it. A caller that
    /// needs rotation on an unsupporting backend can fall back to
    /// [`Self::restart_workload`] and accept the connection drop.
    async fn graceful_upgrade_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> anyhow::Result<DeployResult> {
        let _ = (spec, mesh);
        anyhow::bail!(
            "backend {:?} does not support graceful_upgrade_workload \
             (pingora fd-handoff); use restart_workload for a non-graceful reload",
            self.backend()
        )
    }

    /// Tear down a workload completely. Idempotent — returns `Ok(())` if the
    /// workload is already gone.
    async fn teardown_workload(&self, ident: &MeshIdent) -> anyhow::Result<()>;

    /// Query the health of the underlying backend. Used by the camp / yubaba
    /// `/health` endpoint to report whether the backend socket is reachable.
    async fn health(&self) -> anyhow::Result<RuntimeHealth>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_status_terminal_matrix() {
        assert!(!WorkloadStatus::Pending.is_terminal());
        assert!(!WorkloadStatus::Running.is_terminal());
        assert!(!WorkloadStatus::Stopping.is_terminal());
        assert!(WorkloadStatus::Stopped.is_terminal());
        assert!(!WorkloadStatus::Restarting {
            last_exit_code: 2,
            restart_count: 3,
            last_finished_at_unix_ms: 1,
        }
        .is_terminal());
        assert!(WorkloadStatus::Failed {
            reason: "boom".into()
        }
        .is_terminal());
    }

    #[test]
    fn mesh_assignment_inlined_has_no_wireguard() {
        let m = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        assert!(!m.has_wireguard());
        assert!(m.peers.is_empty());
        assert_eq!(m.wg_listen_port, 0);
    }

    #[test]
    fn backend_serde_round_trip() {
        let json = serde_json::to_string(&Backend::Containerd).unwrap();
        assert_eq!(json, "\"containerd\"");
        let parsed: Backend = serde_json::from_str("\"docker\"").unwrap();
        assert_eq!(parsed, Backend::Docker);
    }
}

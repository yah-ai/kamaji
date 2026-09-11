//! @yah:ticket(R592-T4, "Finish warden/constable rename at the wire layer: enums, client type, socket defaults, unit templates")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-07-06T07:43:16Z)
//! @yah:phase(P3)
//! @yah:parent(R592)
//! @yah:verify("grep for YubabaToKamaji / KamajiToYubaba / KamajiClient / run-constable paths in oss/kamaji returns zero hits; cd oss/kamaji && cargo test --workspace")
//! @yah:depends_on(R592-T1)
//! @yah:depends_on(R590-B3)
//! @yah:tier(Warrior)
//! @yah:next("DONE (R597-T1): env var renamed to KAMAJI_SOCK across kamaji-bin/src/main.rs, yah-yubaba/Dockerfile, yah-yubaba/pond-supervise.sh, kamaji.service comment.")
//! @yah:next("DEFERRED -> filed as followup: yubaba-internal raft rename WardenState/WardenRequest/WardenNodeId/WardenRaft (oss/yubaba/crates/yubaba/src/raft/*, leader.rs, lib.rs). Independent of the wire surface; postcard-internal.")
//! @yah:next("OPTIONAL cosmetic: test file oss/yubaba/.../tests/integration_constable_client.rs keeps its old filename (content renamed to KamajiClient; git-mv skipped to avoid shared-tree churn).")
//! @yah:handoff("DONE + verify-clean across 3 workspaces. Renamed the pub wire surface: WardenToConstable->YubabaToKamaji, ConstableToWarden->KamajiToYubaba, ConstableClient->KamajiClient, Welcome/ConstableInfo field constable_version->kamaji_version, plus stale doc module-path constable_proto::->kamaji_proto:: -- across oss/kamaji (15 files), root crates/yah/hub (4), oss/yubaba (5). Postcard is positional so this is wire-compatible (no protocol-version bump). Socket PATHS already agreed everywhere (/run/kamaji/kamaji.sock -- peer landed that under R589-T2 in commit e815d59), so no path edit needed; T4 shrank to the pure symbol rename.")
//! @yah:handoff("INCIDENTAL green-keeping fix (NOT part of the rename): added `render_command: None` to two BuildConfig test fixtures (kamaji-proto/src/codec.rs:785, kamaji-bin/src/server.rs:761) that drifted when R535-T7 added BuildConfig.render_command (landed in the same e815d59 wip commit, fixtures not propagated). Two-line adaptation to unblock the workspace test.")
//! @yah:handoff("VERIFY (all green): oss/kamaji `cargo test --workspace` 0 failed (kamaji-proto 24 + kamaji-bin lib 184 + sibling_wire_e2e 2 + uds_skeleton 1 + kamaji lib 29 + others); root `cargo check -p hub --all-features` clean; oss/yubaba `cargo check -p yubaba --all-features` + `cargo test -p yubaba --test integration_constable_client --no-run` compile clean. Grep: zero residual WardenToConstable/ConstableToWarden/ConstableClient/constable_version/constable_proto in all 3 workspaces; raft Warden* symbols correctly untouched.")

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use workload_spec::Workload;

use crate::version::ProtocolVersion;

/// Stable identifier assigned by Yubaba when a workload is admitted.
///
/// Stable across Kamaji restarts: the supervisor reattaches to surviving
/// children by matching its persisted pidfile registry against this id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkloadId(pub String);

impl WorkloadId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Correlation token pairing a Yubaba request with the Kamaji response
/// that satisfies it. Opaque; Yubaba picks the value, Kamaji echoes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub u64);

/// Structured drain budget — see W154 §"Runtime parity contract" item 2.
///
/// Two windows, both wall-clock from drain start:
///
/// - `flush_ms` — time for the workload to finish in-flight requests and stop
///   accepting new work.
/// - `checkpoint_ms` — time for the workload to persist any restart-with-state
///   it cares about (snapshots, journal flushes, log rotation).
///
/// Kamaji runs a single combined timer (`flush_ms + checkpoint_ms`). If the
/// workload exits within that window the drain is reported as `Flushed` (if
/// elapsed ≤ `flush_ms`) or `Checkpointed` (between `flush_ms` and the total).
/// If the window elapses without an exit, Kamaji escalates to SIGKILL and
/// reports `ForceKilled`. See [`DrainOutcome`].
///
/// At the SIGTERM-only floor (T7), the workload sees one SIGTERM and has the
/// full window to exit; it distinguishes flush vs checkpoint by elapsed time.
/// Once the structured workload-control channel (R406-T11) ships, Kamaji
/// will deliver the budget envelope explicitly so workload-side code can
/// reason about which phase it is in without consulting the clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainBudget {
    /// Time the workload may spend flushing in-flight work after acking drain.
    pub flush_ms: u32,
    /// Time the workload may spend persisting checkpoint state.
    pub checkpoint_ms: u32,
}

impl DrainBudget {
    /// Sum of `flush_ms + checkpoint_ms`, saturated at `u32::MAX`. This is the
    /// wall-clock window Kamaji waits on the workload before SIGKILL.
    pub fn total_ms(self) -> u32 {
        self.flush_ms.saturating_add(self.checkpoint_ms)
    }
}

/// Which budget window the workload exited in. Reported alongside
/// [`DrainOutcome::Flushed`] / [`DrainOutcome::Checkpointed`] so operators can
/// see whether a workload typically completes within its flush window or rides
/// into checkpoint — useful for tuning the budget per workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DrainPhase {
    /// Workload exited within `budget.flush_ms`.
    Flush,
    /// Workload exited between `flush_ms` and `flush_ms + checkpoint_ms`.
    Checkpoint,
}

/// Structured outcome of a Kamaji-driven drain procedure.
///
/// Returned by Kamaji's drain enforcer ([`crate`] consumer in
/// `app/yah/kamaji/src/drain.rs`) and surfaced on the wire either as
/// part of [`KamajiToYubaba::DrainAck`]`.reason` (synchronous T7 shape)
/// or as a dedicated [`KamajiToYubaba::DrainCompleted`] push (future
/// async shape once Kamaji has a push-channel to Yubaba).
///
/// `#[non_exhaustive]` so future variants (e.g. `WorkloadRefused` when a
/// structured-channel workload explicitly nacks drain) can land without
/// bumping the protocol version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DrainOutcome {
    /// Workload exited within the flush window. `elapsed_ms` is wall-clock
    /// from drain start to child reap; `exit` is the child's status.
    Flushed { exit: ExitStatus, elapsed_ms: u32 },
    /// Workload exited after flush_ms but within `flush_ms + checkpoint_ms`.
    Checkpointed { exit: ExitStatus, elapsed_ms: u32 },
    /// Budget elapsed; Kamaji issued SIGKILL. `elapsed_ms` includes the
    /// short tail between SIGKILL and the kernel marking the pidfd readable.
    ForceKilled { elapsed_ms: u32 },
    /// Workload is not in Kamaji's drainable registry — either it already
    /// exited and was reaped, or it was never registered.
    UnknownWorkload,
    /// This Kamaji build doesn't support drain (non-Linux target, no pidfd
    /// syscall surface). Reported so the operator sees an explicit reason
    /// instead of a silent no-op.
    Unsupported,
}

/// Exit status surfaced by `waitid(P_PIDFD, ...)` (native) or by containerd's
/// task state (container). Backend differences are hidden behind this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ExitStatus {
    /// Exited normally with the given status code.
    Exited(i32),
    /// Killed by signal.
    Signaled(i32),
    /// Killed by Kamaji enforcing the drain deadline.
    DrainTimeout,
}

/// Result of a single probe poll. Surface is uniform across HTTP-endpoint and
/// stdio-sentinel probe shapes — R406-T11 picks the wire detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProbeStatus {
    /// Workload is up and serving.
    Ready,
    /// Workload is alive but not yet ready.
    Starting,
    /// Workload reports itself unhealthy.
    Unhealthy { reason: String },
    /// Probe did not respond within the configured budget.
    Timeout,
}

/// Coarse-grained workload state Kamaji surfaces to Yubaba.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum WorkloadState {
    /// Spec accepted but no process started yet.
    Pending,
    /// Process forked/containerd-task created, not yet probe-Ready.
    Starting,
    /// Probe-Ready and serving.
    Running,
    /// Drain in progress.
    Draining,
    /// Process exited cleanly.
    Exited,
    /// Process exited with failure (non-zero status or signal).
    Failed,
}

/// Compact snapshot of one workload — returned in
/// [`KamajiToYubaba::WorkloadList`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadEntry {
    pub id: WorkloadId,
    pub state: WorkloadState,
    /// OS pid of the workload's root process (native) or containerd task pid
    /// (container). Absent if not yet started or already reaped.
    pub pid: Option<u32>,
    /// The workload's **mesh identity** (`expose.mesh.identity`), when the
    /// backend records it. This is the stable handle Yubaba's HTTP surface
    /// keys on (`GET /workloads/{ident}/state`), and it can differ from
    /// [`Self::id`]: `id` is the containerd container id (a DNS-label-safe
    /// name, e.g. `forge-<uuid>`), while the mesh identity may carry dots
    /// (e.g. `forge.<uuid>`). Yubaba matches the polled ident against *this*
    /// so a forge run's state is observable; `id` stays the drain/stop key.
    /// `None` for backends/entries that don't stamp a mesh-ident label (R590-B9).
    #[serde(default)]
    pub mesh_ident: Option<String>,
    /// Port(s) kamaji **actually bound** for this workload (R844-F2).
    ///
    /// This is the return half of automatic port allocation. Before it existed,
    /// yubaba could only learn a bundle's port from the pin an operator wrote
    /// into the mirror (`[providers.bundle] port`), because the port kamaji
    /// resolved — the workload's own declared port, or kamaji's node-wide
    /// `KAMAJI_BUNDLE_PORT` fallback, or now an allocated one — lived entirely
    /// inside kamaji's process and had no channel back. That is why a node
    /// could serve exactly one bundle: the only port yubaba could name was a
    /// well-known one.
    ///
    /// Carried on the *list* response rather than the deploy ack on purpose. A
    /// bundle `Deploy` acks on admission (`ProtocolVersion::V3`), before the
    /// tree is materialized and long before anything binds, so the ack cannot
    /// carry a port that does not exist yet. Riding the list makes the same
    /// field do double duty: it publishes the port initially *and* corrects it
    /// if the workload later comes back on a different one.
    ///
    /// Empty means "no resolved port known for this entry" — a backend that
    /// does not resolve ports, or an entry that has not bound yet. It does not
    /// mean the workload is portless; the caller falls back to whatever the
    /// workload declared.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// The same resolved ports, keyed by **port name** (R844-F15).
    ///
    /// [`Self::ports`] is three bare numbers: a consumer holding it cannot tell
    /// which one is the websocket listener and has to guess by index or by
    /// convention, which is wrong the first time a port moves. This carries the
    /// names the supervisor's allocator assigned, so a peer resolving a service
    /// asks for `wss` instead.
    ///
    /// **A new field here is a version bump, not a compatible addition, and it
    /// must always be encoded.** This frame is *postcard* — positional, with no
    /// field names on the wire — so `#[serde(default)]` cannot fill a missing
    /// field and `skip_serializing_if` is actively wrong: omitting the bytes
    /// produces a frame that even a *same-version* decoder cannot parse, since
    /// it reads the next field's bytes out of this one's position. That is not
    /// hypothetical — adding this field with `skip_serializing_if` is what made
    /// `sibling_wire_e2e::accepted_deploy_appears_in_list_against_scripted_backend`
    /// and `docker_backend_e2e::deploy_list_stop_through_kamaji_against_live_docker`
    /// fail with `PeerClosed` on the `List` round-trip, mid-R844-F15. The
    /// mechanism is the same one [`crate::ProtocolVersion`] documents for V4 and
    /// V5; the bump for this field is **V6**.
    ///
    /// So there is no "peer that predates this field" case to handle: the
    /// handshake refuses a mismatched version outright, which is exactly why
    /// the bump exists. Both this and [`Self::ports`] are always populated by a
    /// version-matched peer, and they describe the same ports — `ports` is the
    /// anonymous view R844-F2 shipped, kept for callers that only want numbers.
    ///
    /// (The *other* wire this data crosses — yubaba's `GET /service-records` —
    /// is JSON over HTTP between independently-versioned binaries across a
    /// mixed fleet, and there the additive-field argument does hold. See
    /// `yubaba::service_records::ServiceRecordWire::named_ports`. Do not carry
    /// reasoning from that wire to this one.)
    #[serde(default)]
    pub named_ports: std::collections::BTreeMap<String, u16>,
    /// Digest of the [`Workload`] this workload was deployed with (R852-B4),
    /// as computed by [`crate::spec_digest`].
    ///
    /// This is what lets a reconciler tell an **unchanged** declaration from a
    /// changed one without re-sending it. `Deploy` is idempotent by tearing
    /// down — on the JIT tier it releases the held listen socket before binding
    /// fresh — so a sweep that re-declares everything re-binds everything, and
    /// kills any warm JIT child mid-life. Compare this against the digest of
    /// the spec you were about to send and skip the deploy when they agree.
    ///
    /// `None` means **no digest on record**, which is not "no spec": kamaji
    /// keeps this in memory alongside the deploy, so a restart, a workload
    /// adopted from a backend that kamaji did not admit this process lifetime,
    /// or a spec that would not encode all report `None`. `None` must be read
    /// as "unknown, redeploy" — never as "unchanged".
    ///
    /// Read [`crate::digest`] before relying on equality: it is a sound
    /// unchanged-check for specs whose maps are ordered and a best-effort one
    /// for `HashMap`-carrying container specs, and the failure direction is
    /// always toward a redundant redeploy rather than a missed one.
    #[serde(default)]
    pub spec_digest: Option<crate::digest::SpecDigest>,
}

/// Mesh-plane placement for a deployed workload (R599-F12) — yubaba's
/// admission-time decision about *where on the mesh* the workload's listener
/// lives, carried to kamaji so the backend can honour it.
///
/// Wire mirror of `kamaji::MeshAssignment`. The two are deliberately separate
/// types: this one is a cross-binary contract that an internal refactor of the
/// runtime struct must not be able to reshape silently. `kamaji`'s `sibling`
/// module owns the conversion in both directions.
///
/// What `mesh_ip` *means* differs by backend, and the difference is load-
/// bearing:
///
/// - **Container backends** (containerd/docker) put the workload in its own
///   network namespace, so `mesh_ip` is that namespace's address — an address
///   that need not exist on the host.
/// - **Native backends** (the W272 bundle path) fork a plain host process, so
///   `mesh_ip` must be an address **already bound on this node** — in practice
///   the node's own mesh address, the one yubaba itself listens on. Handing a
///   native workload an unassigned address makes it fail to bind
///   ("Address not available"), so yubaba sends its own node address here for
///   native deploys rather than an allocated per-workload one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeshAssignment {
    /// Mesh-plane IP for this workload. See the type docs for what it means
    /// per backend.
    pub mesh_ip: Ipv4Addr,
    /// WireGuard private key for the workload's mesh interface. Empty when the
    /// deployment has no WireGuard plane (`has_wireguard()` is false on the
    /// runtime type).
    pub wg_private_key: String,
    /// WireGuard listen port. `0` alongside an empty key = no WireGuard.
    pub wg_listen_port: u16,
    /// Mesh peers the workload's interface is configured with.
    pub peers: Vec<WireguardPeer>,
    /// Network namespace the workload's listener must be created in, when the
    /// backend is a socket custodian. `None` = the host namespace.
    pub netns_name: Option<String>,
}

/// One WireGuard peer entry in a [`MeshAssignment`]. Wire mirror of
/// `kamaji::WireguardPeer`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireguardPeer {
    pub public_key: String,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpAddr>,
}

/// Discriminant for a generic [`KamajiToYubaba::Ack`] — which request the
/// ack belongs to. Lets Yubaba's dispatch table key on request-kind without
/// re-parsing the original payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AckKind {
    Deploy,
    Stop,
    Probe,
    /// Ack for [`YubabaToKamaji::GracefulUpgrade`] (R600-F9). Appended last to
    /// keep the postcard discriminants of the prior variants wire-stable.
    GracefulUpgrade,
}

/// Wire-level error codes. The accompanying `message` carries the concrete
/// reason; the code lets Yubaba's retry logic key on category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Request used a protocol version the receiver no longer supports.
    UnsupportedVersion,
    /// Workload id was not found in Kamaji's registry.
    UnknownWorkload,
    /// Workload spec failed validation at Kamaji.
    InvalidSpec,
    /// Backend (containerd RPC or a native syscall) refused the operation.
    BackendRefused,
    /// Internal error — Kamaji hit an unexpected condition.
    Internal,
}

/// Yubaba → Kamaji message variants.
///
/// `#[non_exhaustive]` lets us add new request kinds without bumping the
/// protocol version, as long as the existing variants keep their shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum YubabaToKamaji {
    /// Connection greeting — exchanged once per UDS connection.
    Hello { version: ProtocolVersion },
    /// Deploy a workload. Backend (native vs container) is selected by `spec`.
    ///
    /// `mesh` is the workload's mesh-plane placement (R599-F12). `None` means
    /// this deployment has no mesh IP plane — a pond/desktop node — and kamaji
    /// binds loopback, which is the pre-R599-F12 behaviour. `Some` means bind
    /// the assignment's `mesh_ip`, which is what makes a workload reachable
    /// from another node and therefore what lets an ingress proxy live
    /// somewhere other than on top of its own backend.
    ///
    /// Adding this field is a **backward-incompatible** wire change (postcard
    /// is positional), which is why [`ProtocolVersion::V2`] exists.
    Deploy {
        request_id: RequestId,
        id: WorkloadId,
        spec: Workload,
        mesh: Option<MeshAssignment>,
    },
    /// Stop a workload — SIGTERM-with-grace floor; backend hides specifics.
    Stop {
        request_id: RequestId,
        id: WorkloadId,
    },
    /// Structured drain with a deadline budget.
    Drain {
        request_id: RequestId,
        id: WorkloadId,
        budget: DrainBudget,
    },
    /// Poll the current probe status for one workload.
    Probe {
        request_id: RequestId,
        id: WorkloadId,
    },
    /// List every workload Kamaji is currently supervising.
    List { request_id: RequestId },
    /// Zero-downtime reload of a passway workload onto re-rendered on-disk
    /// material (e.g. a rotated TLS cert) — the supervisor half of pingora's
    /// hot-upgrade (R600-F9 / W273). Kamaji, holding the workload's listen
    /// socket as custodian, swaps the passway process without closing the
    /// listener, so no connection is dropped. For a non-passway workload (or
    /// when custody isn't held) the backend falls back to a connection-dropping
    /// redeploy. Appended after `List` to keep the postcard variant indices of
    /// the pre-existing variants wire-stable.
    GracefulUpgrade {
        request_id: RequestId,
        id: WorkloadId,
        spec: Workload,
    },
    /// Poll the progress of an **asynchronous** deploy (R330-F33).
    ///
    /// A bundle `Deploy` acks on *admission* — before the node has materialized
    /// the W272 tree or forked the serve process — so the ack cannot carry the
    /// outcome. This is how the caller learns it. Appended last to keep the
    /// postcard variant indices of the pre-existing variants wire-stable.
    DeployStatus {
        request_id: RequestId,
        id: WorkloadId,
    },
    /// Ask which execution backends this Kamaji can actually dispatch to
    /// (R858-T4).
    ///
    /// Exists because the alternative is finding out at deploy time. On
    /// 2026-09-03 the headscale appliance's owner moved to a node whose kamaji
    /// had been started without `--native-exec-dir`; the deploy came back
    /// `BackendRefused` *after* ownership had already moved, the failure was a
    /// `warn!`, and the mesh had no coordination server for 37 hours. A
    /// capability a scheduler can read before it places is the difference
    /// between an ineligible candidate and an outage.
    ///
    /// Appended last to keep the postcard variant indices of the pre-existing
    /// variants wire-stable, the same treatment [`Self::GracefulUpgrade`] and
    /// [`Self::DeployStatus`] had — so this needs no [`ProtocolVersion`] bump.
    /// An older Kamaji that does not know the variant fails the frame, which
    /// the caller is expected to read as "capability unknown" and treat
    /// permissively; see `yubaba`'s `NativeExecCapability`.
    Capabilities { request_id: RequestId },
}

/// Kamaji → Yubaba message variants.
///
/// A mix of request-responses (correlated by [`RequestId`]) and pushed
/// lifecycle events (no request id — Kamaji surfaces them spontaneously).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KamajiToYubaba {
    /// Response to [`YubabaToKamaji::Hello`].
    Welcome {
        version: ProtocolVersion,
        /// Build version of the Kamaji peer (for operator visibility).
        kamaji_version: String,
    },
    /// Generic ack to a request.
    Ack {
        request_id: RequestId,
        kind: AckKind,
    },
    /// Generic error. `request_id` is `None` for errors not tied to a request
    /// (e.g. malformed frame).
    Error {
        request_id: Option<RequestId>,
        code: ErrorCode,
        message: String,
    },
    /// Push: a workload's root process started.
    WorkloadStarted { id: WorkloadId, pid: u32 },
    /// Push: a workload's root process exited.
    WorkloadExited { id: WorkloadId, exit: ExitStatus },
    /// Response to [`YubabaToKamaji::Probe`].
    ProbeResult {
        request_id: RequestId,
        id: WorkloadId,
        status: ProbeStatus,
    },
    /// Response to [`YubabaToKamaji::Drain`].
    ///
    /// Two semantic modes — both are valid V1 wire shapes; Kamaji picks
    /// based on whether it has a push channel back to Yubaba:
    ///
    /// 1. **Synchronous (R406-T7 default).** Kamaji runs the drain
    ///    procedure to completion inside the request handler. `accepted=true`
    ///    means the workload exited cleanly within the [`DrainBudget`]
    ///    window; `accepted=false` means SIGKILL escalation, unknown
    ///    workload, or platform-unsupported. `reason` is the human-readable
    ///    summary of the underlying [`DrainOutcome`].
    /// 2. **Asynchronous (future, T8 push-channel).** Kamaji replies
    ///    immediately with `accepted=true, reason=Some("started, budget=…")`
    ///    and later pushes the structured outcome via [`Self::DrainCompleted`].
    ///
    /// Yubaba disambiguates the modes by feature-detecting `DrainCompleted`
    /// support at handshake time (future protocol-version negotiation).
    DrainAck {
        request_id: RequestId,
        id: WorkloadId,
        accepted: bool,
        reason: Option<String>,
    },
    /// Push: structured drain outcome for a workload Kamaji previously
    /// acknowledged as "drain started" (asynchronous mode). Carries the same
    /// [`DrainOutcome`] that synchronous mode encodes in
    /// [`Self::DrainAck`]`.reason`, but typed. Wired once Kamaji grows a
    /// Yubaba-bound push channel (R406-T8).
    DrainCompleted {
        request_id: RequestId,
        id: WorkloadId,
        outcome: DrainOutcome,
    },
    /// Response to [`YubabaToKamaji::List`].
    WorkloadList {
        request_id: RequestId,
        entries: Vec<WorkloadEntry>,
    },
    /// Response to [`YubabaToKamaji::DeployStatus`] (R330-F33).
    ///
    /// `state` is where the asynchronous deploy has got to: `Pending` while the
    /// bundle materializes, `Starting` once the fork is issued, `Running` when
    /// the workload is up, `Failed` when the deploy gave up. `detail` carries
    /// the reason a `Failed` deploy failed — the message that used to come back
    /// in the synchronous `Error` reply, and the only thing that makes an
    /// asynchronous failure diagnosable. `None` on every non-failed state.
    ///
    /// Appended last to keep the postcard variant indices of the pre-existing
    /// variants wire-stable.
    DeployStatusResult {
        request_id: RequestId,
        id: WorkloadId,
        state: WorkloadState,
        detail: Option<String>,
    },
    /// Response to [`YubabaToKamaji::Capabilities`] (R858-T4).
    ///
    /// Appended last to keep the postcard variant indices of the pre-existing
    /// variants wire-stable.
    CapabilitiesReport {
        request_id: RequestId,
        capabilities: NodeCapabilities,
    },
}

/// What one Kamaji can actually dispatch to (R858-T4).
///
/// Deliberately a *struct* rather than a set of booleans on the message, so a
/// later backend is a field here instead of a fourth reply variant — but note
/// that adding a field IS a wire break (postcard is positional; see
/// [`ProtocolVersion`]'s V2/V4/V5/V6 notes), so it costs a version bump. That
/// is the right price: a scheduler silently reading a capability it did not
/// actually receive is how the 37-hour outage happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Whether this Kamaji can fork+exec a native (non-container) workload —
    /// `true` exactly when it was built with the `native-exec` feature AND
    /// started with `--native-exec-dir`.
    ///
    /// This is the fact whose absence produced `BackendRefused: workload
    /// requests native host execution but no native backend is available` on
    /// 2026-09-03, *after* appliance ownership had already moved to the node
    /// that could not serve it.
    pub native_exec: bool,
    /// The directory native workloads are staged in, when `native_exec`. Not a
    /// capability by itself — it is here because the caller's next question is
    /// always "and is the binary I need sitting in it?", and answering that
    /// without a second round trip is the difference between one probe and a
    /// protocol.
    pub native_exec_dir: Option<String>,
    /// Whether this Kamaji has the microVM backend attached, and — if not —
    /// why (R605-T27, `ProtocolVersion::V9`).
    ///
    /// Before this field the only honest remote answer to "did this node
    /// attach the microVM backend" was the kamaji startup journal line: `GET
    /// /health` returns a fixed body with nothing per-backend, and the sibling
    /// wire carried no capability query at all for this backend (unlike
    /// `native_exec`, which R858-T4 already covers here).
    pub microvm: MicroVmHealth,
}

/// Live microVM-backend health, folded into [`NodeCapabilities`] (R605-T27).
///
/// Two questions, not one, because they fail for unrelated reasons with
/// unrelated fixes: was this node even *configured* for the backend
/// (`--microvm-dir`, at process start), and — if so — can it *currently* get a
/// VM out of the kernel (`/dev/kvm`, which an operator can break live by
/// changing device permissions or group membership without restarting
/// anything). Collapsing them into one bool would answer "no" without saying
/// which of those two very different remediations applies.
///
/// Deliberately does NOT cover "backend configured but missing guest
/// kernel/rootfs/VMM binary" as a *distinguishable live state* — it can't,
/// because `kamaji::microvm::MicroVmRuntime::new` (the `kamaji` crate; not a
/// dependency of this one) refuses to construct when those are missing, and
/// that refusal is FATAL to the whole process at boot (deliberately — see
/// its doc comment). A running Kamaji that answers this message at all was
/// therefore either never asked to attach the backend (`attached: false`) or
/// attached it successfully (`attached: true`); the missing-artifact case
/// never reaches a live `/health`-adjacent surface to report on, only the
/// startup journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroVmHealth {
    /// `true` iff this Kamaji was started with `--microvm-dir` pointing at a
    /// guest kernel + rootfs + VMM binary that all existed at boot (the only
    /// way the backend can be attached — a misconfigured `--microvm-dir`
    /// fails the whole process rather than leaving it running unattached).
    /// `false` on a node that was never asked to attach the backend, or on a
    /// build compiled without the `microvm` cargo feature.
    pub attached: bool,
    /// Live re-probe of `/dev/kvm` taken for THIS reply — not cached from
    /// attach time. Mirrors `kamaji::microvm::MicroVmRuntime::health`, which
    /// is deliberately uncached for the same reason: device permissions
    /// and group membership are exactly what an operator changes on a running
    /// node, and a cached `true` would keep reporting healthy right through
    /// the change that broke it. The cost is one `/dev/kvm` open+close per
    /// call, not connect-and-timeout like the containerd/docker probes — cheap
    /// enough to pay at `/health` frequency. `None` when `attached` is false;
    /// there is nothing to probe.
    pub kvm_ok: Option<bool>,
    /// Why `kvm_ok` is `false`, when it is: distinguishes "no `/dev/kvm` on
    /// this host" from "exists but this process can't open it (group
    /// membership)" from other OS errors, because each has a different fix —
    /// see `kamaji::probe::probe_microvm` (not a dependency of this crate).
    /// `None` when `kvm_ok` is `true` or `attached` is `false`.
    pub detail: Option<String>,
}

impl KamajiToYubaba {
    /// The [`RequestId`] this frame is a reply to, or `None` when it is not a
    /// reply at all — the spontaneous lifecycle pushes, and a `Welcome`
    /// arriving after the handshake already consumed one.
    ///
    /// R746-B11: this lives HERE, not in the client, because
    /// `KamajiToYubaba` is `#[non_exhaustive]` — a match in any *other* crate
    /// needs a wildcard arm, and a new reply variant then silently falls into
    /// it and reads as a push. That is exactly what happened to
    /// [`Self::DeployStatusResult`]: it was appended to the enum and never
    /// added to the client's correlation table, so every `DeployStatus` poll
    /// for a workload that HAD a deploy record got its reply dropped as an
    /// unconsumed push and the caller parked on its oneshot forever. Inside
    /// the defining crate the match below is exhaustive with no wildcard, so
    /// the next appended variant fails to compile until it is classified.
    pub fn reply_request_id(&self) -> Option<RequestId> {
        match self {
            Self::Ack { request_id, .. }
            | Self::ProbeResult { request_id, .. }
            | Self::DrainAck { request_id, .. }
            | Self::DrainCompleted { request_id, .. }
            | Self::WorkloadList { request_id, .. }
            | Self::DeployStatusResult { request_id, .. }
            | Self::CapabilitiesReport { request_id, .. } => Some(*request_id),
            Self::Error { request_id, .. } => *request_id,
            Self::Welcome { .. } | Self::WorkloadStarted { .. } | Self::WorkloadExited { .. } => {
                None
            }
        }
    }
}

#[cfg(test)]
mod reply_correlation_tests {
    use super::*;

    fn rid() -> RequestId {
        RequestId(7)
    }

    fn id() -> WorkloadId {
        WorkloadId::new("yah-marketing")
    }

    /// Every variant that answers a request must correlate. The list is
    /// written out by hand on purpose: `reply_request_id` cannot compile
    /// without classifying a new variant, and this pins that the classifying
    /// author picked the right side for the ones that already exist.
    #[test]
    fn every_reply_variant_correlates_to_its_request() {
        let replies = [
            KamajiToYubaba::Ack {
                request_id: rid(),
                kind: AckKind::Deploy,
            },
            KamajiToYubaba::Error {
                request_id: Some(rid()),
                code: ErrorCode::UnknownWorkload,
                message: "nope".into(),
            },
            KamajiToYubaba::ProbeResult {
                request_id: rid(),
                id: id(),
                status: ProbeStatus::Ready,
            },
            KamajiToYubaba::DrainAck {
                request_id: rid(),
                id: id(),
                accepted: true,
                reason: None,
            },
            KamajiToYubaba::DrainCompleted {
                request_id: rid(),
                id: id(),
                outcome: DrainOutcome::UnknownWorkload,
            },
            KamajiToYubaba::WorkloadList {
                request_id: rid(),
                entries: vec![],
            },
            // R746-B11: this one was missing from the client's table.
            KamajiToYubaba::DeployStatusResult {
                request_id: rid(),
                id: id(),
                state: WorkloadState::Running,
                detail: None,
            },
            KamajiToYubaba::CapabilitiesReport {
                request_id: rid(),
                capabilities: NodeCapabilities {
                    native_exec: true,
                    native_exec_dir: Some("/var/lib/yah/kamaji/native".into()),
                    microvm: MicroVmHealth {
                        attached: false,
                        kvm_ok: None,
                        detail: None,
                    },
                },
            },
        ];
        for reply in replies {
            assert_eq!(
                reply.reply_request_id(),
                Some(rid()),
                "{reply:?} answers a request and must route back to its waiter"
            );
        }
    }

    #[test]
    fn pushes_and_untied_errors_do_not_correlate() {
        let pushes = [
            KamajiToYubaba::Welcome {
                version: crate::version::ProtocolVersion::CURRENT,
                kamaji_version: "test".into(),
            },
            KamajiToYubaba::WorkloadStarted { id: id(), pid: 123 },
            KamajiToYubaba::WorkloadExited {
                id: id(),
                exit: ExitStatus::Exited(0),
            },
            KamajiToYubaba::Error {
                request_id: None,
                code: ErrorCode::Internal,
                message: "malformed frame".into(),
            },
        ];
        for push in pushes {
            assert_eq!(push.reply_request_id(), None, "{push:?} is not a reply");
        }
    }
}

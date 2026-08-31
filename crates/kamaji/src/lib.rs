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
//!
//! @yah:ticket(R605-F8, "Shape A: microVM kamaji backend so a build can be isolated on any node, dispatched by annotation like native-exec")
//! @yah:status(review)
//! @yah:at(2026-08-27T03:47:03Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @arch:see(.yah/docs/working/W325-isolated-x86-build-capacity.md)
//! @yah:next("THE WIRE DOES NOT CHANGE, and that is the whole sizing insight. kamaji::Backend is not a postcard wire type (kamaji-proto/src/codec.rs references only ErrorCode::BackendRefused). Backend selection is per-workload and ANNOTATION-driven: kamaji-bin/src/server.rs:1115 branches on spec.wants_native_exec() into deploy_native_exec. A microVM backend is a sibling branch on a new annotation value — no Workload enum variant, no exhaustive-match churn in peer-owned codec.rs, no postcard variant-order hazard. Same zero-blast-radius pattern R572-F1, R594-F2 and R577-T1 each chose.")
//! @yah:next("Follow workload_spec's NATIVE_EXEC_ANNOTATION shape exactly: a const key + value pair plus a wants_*() accessor on WorkloadSpec, mirrored by a validate_*_spec guard in server.rs. Reuse, do not re-invent: yah.sandbox = nested (wants_nested_sandbox) already exists for privileged BuildKit-in-container.")
//! @yah:next("THE REAL COST IS NOT RUST. Budget the ticket against the microVM supply chain: a kernel image + rootfs to boot, jailer setup, TAP networking that still reaches crates.io and the registry (forge already needs HOST_NETWORK_ANNOTATION because kamaji's default netns is loopback-only, velveteen-exec/src/remote.rs:735), and getting the source tree + cargo cache in and artifacts out — forge_produced::durable_mount is a host bind-mount today and a microVM needs a virtio-fs or vsock equivalent.")
//! @yah:next("QED-side axis: velveteen's TaskRuntime (oss/qed/crates/velveteen/src/lib.rs) is Native | Container today. A microVM runtime extends that enum — check its consumers before adding a variant.")
//! @yah:verify("An isolated build runs end to end: a `yah qed run` x86 offload carrying the microVM annotation boots a microVM on the target node, completes a real cargo build, lands its produces, and is torn down — with the node's other workloads unaffected.")
//! @yah:gotcha("THE TICKET TEXT THAT SPAWNED THIS IS WRONG ON ONE POINT, corrected by R605-S6: R605-S6's next-step says Shape A 'mirrors R578-F1's macvm.rs pattern for Tart'. There is no macvm.rs in the tree — R578-F1 is still open and unstarted, and the only occurrence of the string macvm anywhere is inside R605-S6's own annotation. There is no in-tree precedent to mirror; follow the annotation-dispatch pattern in the next-steps instead.")
//! @yah:gotcha("The dynamic-placement half is ALREADY BUILT — do not rebuild it. LifecycleArchetype::Job, WorkloadSpec::for_forge, CloudConfig::admit_workload with the R572-F5 capacity floor + archetype taints + mesh-tag affinity, and velveteen_exec::remote::build_workload_spec all ship today and have been placing builds as ordinary Workloads since R594. This ticket adds ISOLATION to that path, nothing else.")
//! @yah:gotcha("Substrate is confirmed available: both OVH nodes have /dev/kvm with kvm_intel nested=Y (probed 2026-08-19). But the debian service user (uid 1000) is NOT in group kvm (gid 992) and /dev/kvm is 0660 root:kvm — anything opening it needs a group add or root, on every node this backend is meant to run.")
//! @yah:handoff("SHIPPED, the software half. New oss/kamaji/crates/kamaji/src/microvm.rs: MicroVmRuntime (impl Kamaji, Backend::MicroVm) driving Firecracker via --no-api --config-file, one /30 TAP slot per guest, an ext4 scratch disk built with mkfs.ext4 -d and unpacked with debugfs rdump (neither needs root -- a loop mount would, and unpacking a build's artifacts is the wrong place for root). Dispatch is annotation-driven exactly like native-exec: kamaji-bin server.rs branches spec.wants_microvm() into deploy_microvm, guarded by validate_microvm_spec, refusing rather than falling back to a container. Wire unchanged as predicted: no Workload variant, no kamaji-proto edit.")
//! @yah:handoff("THE MARKER IS A THIRD VALUE ON yah.exec, NOT A SECOND KEY, and that is the one design call worth reviewing. W325 section 5 said 'a sibling branch on a new annotation value' and taking it literally pays off: MICROVM_EXEC_VALUE = microvm sits on the existing NATIVE_EXEC_ANNOTATION, so a map key holds one value and the three substrates (container / native / microvm) are mutually exclusive BY CONSTRUCTION. A separate yah.isolation key would have made native+microvm expressible and therefore a refusal someone has to write and maintain -- exactly the branch validate_native_exec_spec already carries for the yah.sandbox pair. Pinned by exec_substrate_markers_are_mutually_exclusive_by_construction.")
//! @yah:handoff("TWO REAL BUGS FOUND BY BUILDING IT, neither anticipated by the ticket or by W325. (1) resources.memory_mb cannot be read literally by a VM backend: it is a cgroup CEILING everywhere else and WorkloadSpec::for_forge sets it to 32 GiB, while W325 section 4 measured the OVH nodes at 11682 MB total. Firecracker would read it as an ALLOCATION and every forge microVM would fail to boot. guest_memory_mb clamps it to [memory_request_mb, node cap] and refuses at deploy -- naming both numbers -- when the floor exceeds the cap, because a build that dies at 90 percent with a SIGKILL costs far more to diagnose than a deploy that says no. (2) ephemeral_storage_mb is the same problem inverted: for_forge sets 512 MiB, which would fail every build at its first checkout, so it is a floor on the scratch disk and not the answer.")
//! @yah:handoff("THIRD FINDING, security-relevant: a microVM workload must NOT carry HOST_NETWORK_ANNOTATION. It is inert at the backend -- a guest has no namespace to place in the host's, it has a virtual NIC on a TAP -- but AdmissionGrant::from_spec reads host_network off exactly that annotation, so leaving the dispatcher's blanket set would make every signed microVM grant assert a privilege the run never took. build_workload_spec now skips it for microvm only; a_microvm_workload_does_not_claim_host_networking pins both directions, including that the container leg still gets it (R590-B7 proved that one the hard way).")
//! @yah:handoff("QED AXIS DONE TOO, so the backend is actually reachable from a pipeline rather than being dead code: velveteen TaskRuntime gained MicroVm (the ticket's fourth next-step said to check consumers first -- 20 files mention the enum but only 3 match on it exhaustively, so the blast radius was small), velveteen-exec build_workload_spec stamps the marker via mark_microvm, and qed runner.rs refuses (RunWhere::Local, TaskRuntime::MicroVm) through local_microvm_is_refused. Local is refused on purpose: a microVM isolates a build from what ELSE is on the node, and locally that is the author. A step writes runtime = microvm in its pipeline TOML.")
//! @yah:handoff("mark_microvm is ONE line where mark_native_exec is three, and the asymmetry is the point. The native path rewrites workdir and publishes YAH_PRODUCED_DIR because a fork+exec'd process has no mount namespace, so /yah/produced does not exist for it. A guest has a whole kernel, so kamaji honours the spec's declared volume targets: each Bind source is copied onto the scratch disk under a slug, the guest bind-mounts it back at target, and a step writing to /yah/produced works unchanged -- forge_produced::host_path reads the artifacts back from the same host dir it always did. Read-only volumes are carried IN but never copied back OUT: that flag is a promise to the host, and the guest is precisely the party that cannot be trusted to keep it.")
//! @yah:handoff("DISCOVERED WORK done in this pass, beyond the ticket. (a) app/yah/desktop/src/kamaji.rs:306 and state.rs:625 -- Backend::MicroVm and BackendAvailability.microvm made these non-exhaustive; both fixed, and I broke the camp build for ~20 minutes before @Ashguard:blade and @Ashguard:spade flagged the yah-qed runner.rs half. (b) kamaji-bin server.rs bundle_state_to_entry renamed runtime_state_to_entry and its cfg widened -- it gained a third caller and the old name stopped being true. (c) workload-spec admission.rs: the signing site and the verifying site were two copies of the same runtime if-ladder, which is exactly when a duplicated ladder starts to drift, so both now call GrantRuntime::of_spec.")
//! @yah:verify("cd oss/kamaji && cargo test --workspace --all-features -- 19 test-result-ok lines, 0 failed, 0 errors. Includes kamaji lib 137 (27 of them microvm::, 3 more probe:: covering /dev/kvm) and kamaji-bin lib 258 (4 new microVM dispatch tests).")
//! @yah:verify("cd oss/yah-base && cargo test -p yah-workload-spec --all-features -- 162 in the lib, all green (5 new: the marker, mutual exclusion, JSON round-trip, and two on the GrantRuntime::MicroVm signing path). cd oss/qed && cargo test -p yah-qed --lib -- 881 passed 1 ignored; cargo test -p velveteen -p velveteen-exec -- 14 and 123 passed (3 new on the dispatcher marker).")
//! @yah:verify("cargo check -p desktop --all-targets clean after the two exhaustiveness fixes. ./scripts/check-schema-drift.sh and ./scripts/check-workload-spec-ts.sh both report in-sync -- no regeneration needed, because TaskRuntime is not enumerated in the generated qed-pipeline schema and the workload-spec change added consts and methods rather than fields. Root cargo check --workspace --all-targets shows no error in any crate I touched (the only failures are a peer's in-flight bash_ast::relocation::effective work in crates/yah/agent-tools).")
//! @yah:gotcha("THE TICKET'S OWN VERIFY IS NOT MET AND CANNOT BE FROM THIS CAMP -- read this before signing off. It asks for an isolated build running end to end on a target node. Nothing has booted a guest: the camp host is macOS with no /dev/kvm, and more fundamentally NO NODE HAS A GUEST KERNEL OR ROOTFS, so MicroVmRuntime::new refuses to construct everywhere today and a microvm-marked deploy gets a BackendRefused naming --microvm-dir. That is the designed failure mode, not a bug. The remaining distance is filed as R605-F14 (build the guest kernel + rootfs + the init that reads /job.json) and R605-T15 (usermod -aG kvm on each node, per W325 section 4's measurement). This ticket delivered the software half W325 section 5 sized; F14 is the supply-chain half it warned was the real cost.")
//! @yah:assumes("Firecracker's --no-api --config-file boot shape, its JSON field names (boot-source / machine-config / network-interfaces), and that a guest halting with panic=1 reboot=k exits the VMM process. All three are from Firecracker's documented behaviour and NONE are measured -- there is no KVM here. the_config_document_uses_firecrackers_field_names pins the serialization so a Rust rename cannot silently break it, but it cannot prove the names are the ones Firecracker wants. If the halt assumption is wrong the supervisor never fires and every job hangs until teardown; check that first on the first real boot (also recorded on R605-F14).")
//! @yah:cleanup("kamaji-bin main.rs hardcodes the VMM path as /usr/bin/firecracker rather than searching PATH or taking a flag. Fine for a fleet where the node is provisioned by us, wrong the moment someone installs it elsewhere; give it a --microvm-vmm-bin when R605-F14 makes that a real question.")
//! @yah:cleanup("Drain is not wired for microVM workloads -- a Drain returns DrainAck{accepted:false}, teardown is via Stop. Same deliberate gap the bundle backend has for the same reason (the runtime single-owns the process, so registering a pidfd DrainableHandle would double-own it and race the supervisor's reaper). Also: a leaked TAP from a crashed kamaji holds its slot until restart; create_tap deletes-then-creates so it self-heals on reuse, but nothing sweeps them.")
//! @yah:handoff("IN REVIEW: the microVM backend and its annotation dispatch are built, wired end to end from a pipeline step down to the VMM launch, and unit-tested across five crates. It has never booted a guest and cannot until R605-F14 and R605-T15 land -- see the gotcha. Sign-off here is on the software, not on a working isolated build.")
//! @yah:verify("PRECISION ON THE PROBE COUNT above: 2 new probe:: tests run on this macOS host (absent_kvm_device_is_unavailable_not_a_panic, microvm_is_unavailable_off_linux_without_touching_the_filesystem) plus availability_require_routes_per_backend extended to route Backend::MicroVm. A third, unopenable_kvm_device_names_the_group_fix, is cfg(target_os = linux) and has NOT run anywhere -- it reproduces W325 section 4's exists-but-EACCES case, which is the fleet's actual state, so run it on the first Linux node that gets this build.")

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

/// KVM microVM backend (R605-F8 / W325 §5) — boots a workload in a Firecracker
/// guest with its own kernel instead of sharing the host's.
#[cfg(feature = "microvm-integration")]
pub mod microvm;

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
/// Per W199 §Backend availability, the `Native` backend is always available
/// (fork+exec for musl-static Rust workloads); `Containerd`, `Docker` and
/// `MicroVm` are probed at init and may be absent on a given host. Workloads
/// that request an absent backend fail with a structured
/// [`BackendUnavailable`] error.
///
/// The variants are ordered by **how much of the host a workload can see**,
/// widest first: native shares everything, a container shares the kernel, a
/// microVM shares only the hardware. That is also the order they were built in,
/// which is a coincidence worth not reading anything into.
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
    /// KVM microVM (Firecracker) — the workload boots its own kernel in its
    /// own guest (R605-F8 / W325 §5). Requires `/dev/kvm`, a guest kernel
    /// image and a guest rootfs on the node; see [`microvm`].
    ///
    /// This is the only backend whose isolation does not depend on the host
    /// kernel being uncompromised by the workload, which is why W325 reaches
    /// for it to let a build share a node with production rather than needing
    /// a node of its own.
    ///
    /// [`microvm`]: crate::microvm
    MicroVm,
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

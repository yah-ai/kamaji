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
//!
//! @yah:relay(R895, "One workload data plane: merge kamaji's two netns vocabularies onto the W343 model")
//! @yah:at(2026-09-11T22:25:56Z)
//! @yah:assignee(agent:user-custom-char-gul2)
//! @yah:next("Operator call (2026-09-11, chat session:d6fc1d54, from the yubaba/kamaji architecture review): kamaji carries two netns vocabularies — MeshAssignment.netns_name (yubaba-assigned WireGuard netns, consumed by socket_custody, jit, containerd, sibling) and container_net::netns_name(workload) (the W343 bridge/veth routed model, derived node-locally) — with two address schemes riding along (100.64/10 raft-pool mesh IPs vs 10.128.x/24 per-node routed subnets). A workload's address and namespace have two possible owners depending on path. Converge on W343's routed model as the one data plane; the pre-workload-spec compose generation is the same track's legacy tail.")
//! @arch:see(.yah/docs/working/W343-per-workload-mesh-addressing.md)
//! @yah:gotcha("BOARD DATA-LOSS FAILURE MODE, hit live on 2026-09-13 during this relay — a deletion ticket whose @yah: annotation is homed in the file it deletes ERASES ITSELF, silently. R895-T2's annotation lived at oss/yubaba/crates/cloud/src/compose.rs:39; the ticket's own job was to delete compose.rs; the moment the courier did, `board.show R895-T2` began returning \"not found\", the ticket vanished from this relay's child list, and every board.update against it failed. Six gotchas and a verify entry recording a nine-node live-fleet sweep went with it (recovered here only because the leader still held them in context). Nothing warned at filing time, at claim time, or at deletion time. Two consequences worth generalising: (1) when filing a ticket whose work is a DELETION, home its annotation somewhere that survives the deletion — the crate root, or the module that loses the `mod` line; (2) before deleting any file, grep it for `@yah:` and re-home what you find, including blocks belonging to OTHER tickets, which would otherwise be removed from the board with no trace and no notification to their owners.")
//! @yah:handoff("RELAY STATE at leader wind-down (Ashguard:blade, session:7ca0970b, 2026-09-13, 281k fill / 149 calls). The relay's own acceptance criteria are MET: kamaji's two netns vocabularies are converged onto W343's routed model, and the pre-workload-spec compose generation — the legacy tail named in the operator's original note — is deleted. R895-F1 (review): MeshAssignment.netns_name deleted from both structs, ProtocolVersion V12 added, socket custody repointed so container_net's namespace has ONE owner and the name flows down from the site that creates it. R895-T2 (review): cloud::compose and cloud::mesh_service deleted along with the shipped `yah cloud service deploy` verb and the POST /compose route, with W206's tenant-isolation policy transplanted into W343 and container_net's module docs before its only executable encoding was removed. Both await OPERATOR sign-off; neither was self-archived. R895-F3 (open) is the remaining child — it implements the tenant policy the transplant documents, is now unblocked since its depends_on R895-T2 reached review, and is deliberately NOT started: it is a Wizard-tier design question (per-tenant bridge vs filter rules inside the node's /24) that deserves a fresh context, not the tail of a spent one.")
//! @yah:handoff("FIVE TICKETS FILED FROM DISCOVERED WORK, none of it folded in silently and none of it authored by this relay. R895-F3 — implement the tenant network isolation W206 requires, which R895-T2's deletion left with no enforcer anywhere (WorkloadSpec.tenant is now declarative-only); carries the undecided design fork. R900-B1 — a stale yah_fleet_metrics::WorkloadEntry literal missing `health` at crates/yah/cloud-admin/src/lib.rs:1557, red-lighting the ROOT workspace check camp-wide. R901 (+B1/B2/B3) — three verification instruments that lie in this camp, each of which fails in the safe-looking direction and two of which were hit by multiple independent sessions in one afternoon; together they are the mechanism behind this relay's ~50-minute camp-wide red build. R902-B1 — an unowned uncommitted E0382 at app/yah/desktop/src/agent.rs:6364 red-lighting the DESKTOP check. R903 — 34 persistent, load-independent raft leader-election failures in the yubaba workspace, measured at two load levels and attributed away from this relay four ways. NOTE THE COMPOUND RISK the last three describe together: with R900-B1 red on the root check and R902-B1 red on desktop, an agent in this camp currently has no clean root or desktop build to measure a regression against, and R901's traps make a clean-looking negative result the least trustworthy kind. That combination is the condition under which the next real break goes unnoticed.")

pub mod inlined;
pub mod probe;

/// Sibling-shape client (postcard over AF_UNIX). `unix` as well as the feature:
/// the transport *is* a Unix domain socket, so there is no Windows shape of this
/// module to compile (R918-T1). Callers that want the sibling client on a
/// non-unix host need a different transport, not a cfg.
#[cfg(all(unix, feature = "sibling"))]
pub mod sibling;

pub use inlined::Inlined;
pub use probe::{BackendAvailability, BackendProbe};

/// containerd gRPC backend — talks to containerd over its AF_UNIX control
/// socket and drives a [`socket_custody`] custodian, so it carries the same
/// `unix` gate they do (R918-T1).
#[cfg(all(unix, feature = "containerd-integration"))]
pub mod containerd;

#[cfg(feature = "docker-integration")]
pub mod docker;

#[cfg(feature = "native-integration")]
pub mod native;

/// Interactive-session bridge for native-exec on a WSL host (R918-F8): how a
/// native child reaches the logged-on user's desktop instead of session 0.
#[cfg(feature = "native-integration")]
pub mod win_interactive;

#[cfg(feature = "native-integration")]
pub(crate) mod orphan;

/// KVM microVM backend (R605-F8 / W325 §5) — boots a workload in a Firecracker
/// guest with its own kernel instead of sharing the host's.
#[cfg(feature = "microvm-integration")]
pub mod microvm;

/// The restart loop both process-supervising backends share (R605-F31).
///
/// Gated on the union of the two features rather than on either: it is the
/// state machine `native` has always run, lifted out so `microvm` can run a
/// service-shaped guest through the *same* one instead of growing a second
/// copy that drifts.
#[cfg(any(feature = "native-integration", feature = "microvm-integration"))]
pub(crate) mod supervise;

/// On-demand ("serverless") JIT lifecycle (R599-F6): kamaji holds a workload's
/// listen socket via the [`socket_custody`] custodian, forks the serve runtime
/// on the first connection (systemd-style socket activation), and reaps it after
/// an idle TTL. Built on the native fork+exec machinery, so gated on the same
/// `native-integration` feature (which pulls in `socket-custody`).
///
/// `unix` as well: the whole mechanism is fd inheritance across `fork` +
/// `dup2`, which has no Windows spelling (R918-T1).
#[cfg(all(unix, feature = "native-integration"))]
pub mod jit;

/// Socket-custodian primitive (R599-F9): kamaji binds+holds a workload's listen
/// socket and hands the fd to the workload process over its pingora upgrade
/// socket. Shared core under R599-F6 (JIT) and R600-F9 (cert-rotation).
///
/// `unix` as well as the feature: the handoff is `SCM_RIGHTS` over AF_UNIX
/// (R918-T1). The `nix` dependency it needs is declared under
/// `[target.'cfg(unix)'.dependencies]` for the same reason, so enabling
/// `socket-custody` on a non-unix target is a no-op rather than a build break.
#[cfg(all(unix, feature = "socket-custody"))]
pub mod socket_custody;

#[cfg(feature = "testing")]
pub mod fake;

/// Per-workload container networking (R881-T3 / W343): the bridge, veth pair
/// and routed `/24` that give a namespaced workload an address something else
/// can dial. Unconditional and dependency-free — the address plan is shared
/// with yubaba, which allocates from it, and the module is pure apart from one
/// `apply` function, so a build that cannot run `ip` can still reason about it.
pub mod container_net;

/// Write-then-rename staging that is per-writer rather than per-file (R925).
/// Unconditional and dependency-free for the same reason [`ports`] is: it is
/// used by this crate's port ledger and by `kamaji-bin`'s JWKS cache and deploy
/// records, so a feature that could select it away would put the fix out of
/// reach of two of the three sites it exists for.
pub mod atomic_file;

/// Listen-port allocation (R844-F2): the one contract the local (camp) and
/// remote (kamaji) supervisors both answer through, so a workload that runs
/// both ways does not learn its port from two mechanisms that can disagree.
/// Unconditional — a supervisor that cannot say what port it gave a workload is
/// not a shape any build should be able to select.
pub mod ports;

/// cgroup v2 driver for the native backend (R406-T4, re-homed here by R885-B1).
/// Unconditional and dependency-free — pure `std::fs` writes into the subtree
/// systemd delegates to kamaji — and unconditional for the same reason `ports`
/// is: it moved here from `kamaji-bin`, which depends on this crate, so leaving
/// it behind a feature would put it back out of reach of the live path that
/// R885-B1 exists to connect it to. `kamaji-bin` re-exports it.
pub mod cgroup;

/// Capability boundary for the two workload fork paths (R885-B9) — the other
/// half of W344's "capability policy and resource policy are separate axes".
/// Unconditional for the same reason [`cgroup`] is: it is a property of every
/// workload kamaji forks, not of a backend, and a build that could select it
/// away would be a build whose workloads silently keep kamaji's ambient set.
pub mod sandbox;

/// The deploy-time observability contract (R893-B17): `YAH_SERVICE_IDENT` +
/// `YAH_SCRYER_SOCKET`, the pair `yah-log` and passway's span exporter both
/// need before either emits anything at all. Unconditional for the same reason
/// [`ports`] is — it is a property of every workload kamaji starts, not of a
/// backend, and the whole point is that the answer cannot differ between them.
pub mod observe;

/// macOS TCC responsibility disclaim for spawned children (R940-B1). A child
/// whose privacy access (Bluetooth, camera, …) is attributed to its own
/// embedded Info.plist rather than to whichever app bundle sits at the top of
/// its process tree. Unconditional because both supervisors (kamaji's native
/// backend and yah desktop's agent spawns) need it, and a no-op off macOS.
#[cfg(unix)]
pub mod disclaim;

use std::collections::BTreeMap;
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

impl Backend {
    /// Whether this backend writes out [`workload_spec::WorkloadSpec::files`]
    /// before the workload starts (R870-F27).
    ///
    /// One fact, in one place, because the two halves of it live far apart: a
    /// backend that writes must actually do so on its deploy path, and a
    /// backend that does not must refuse such a spec via
    /// [`reject_unmaterializable_files`]. Encoding it as a predicate here is
    /// what makes the third state — a backend that neither writes nor
    /// refuses, and therefore starts a workload against a file that is not
    /// there — impossible to reach by forgetting a call.
    ///
    /// - [`Native`](Backend::Native) — `native::materialize_files`, on every
    ///   spawn and every respawn.
    /// - [`Containerd`](Backend::Containerd) — staged per container
    ///   generation and bind-mounted read-only
    ///   (`kamaji_containerd_core::stage_spec_files`).
    /// - [`Docker`](Backend::Docker) / [`MicroVm`](Backend::MicroVm) — not
    ///   yet. Docker would need `docker cp` before start or a `-v` per file;
    ///   a microVM needs the bytes inside a guest rootfs image it builds, so
    ///   its write belongs to the rootfs assembly step rather than to deploy.
    pub fn materializes_files(self) -> bool {
        match self {
            Backend::Native | Backend::Containerd => true,
            Backend::Docker | Backend::MicroVm => false,
        }
    }
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
    /// The hydrate-on-place measurement kamaji took in front of this deploy
    /// (R850-T4) — `turso-backup-hydrate`'s own JSON line, verbatim and
    /// unparsed — or `None` when no restore happened.
    ///
    /// `None` from every backend in this crate, and that is structural rather
    /// than unimplemented: hydrate-on-place runs in the `kamaji-bin` daemon,
    /// on the deploy-dispatch path ahead of any backend, so the only impl that
    /// can ever carry a measurement is [`sibling`], which reads it off the
    /// wire. An inlined backend never restored anything to report.
    ///
    /// It is a `String` because kamaji does not interpret the helper's output.
    /// The consumer that does — `yah-cloud`'s `RecoveryRecord::from_helper_json`
    /// — parses the helper's own field names, so re-typing it here would create
    /// a second vocabulary free to drift from both ends.
    pub hydrate: Option<String>,
    /// Port(s) the supervisor **actually bound** for this workload, keyed by
    /// **port name** (R844-F2 introduced the field; R844-F15 named it).
    ///
    /// Distinct from the workload's *declared* ports (`spec.expose.mesh.ports`
    /// for a container, `serve_bundle.port` for a W272 bundle): a declared
    /// *name* is a request, this is the answer. A declared *number* is refused
    /// outright unless the port is fixed by the outside world
    /// ([`ports::WORLD_FIXED_PORTS`]), so since R844-F14 these no longer
    /// coincide by way of a pin — the allocator picks, and this reports.
    ///
    /// The **name** is what makes a multi-port workload resolvable: three bare
    /// numbers tell a consumer nothing about which one is the websocket
    /// listener, so it has to guess by index or by convention and is wrong the
    /// first time a port moves. A workload that declares no names at all still
    /// gets one — see [`name_anonymous_ports`], which is the single place that
    /// synthesis lives so every tier spells it the same way.
    ///
    /// Empty means "this backend does not resolve ports", not "no ports": a
    /// container backend puts the workload in its own namespace, where the
    /// declared port *is* the bound port and there is nothing to resolve.
    /// Consumers must fall back to the declared ports on empty rather than
    /// treating the workload as undialable.
    #[serde(default)]
    pub ports: BTreeMap<String, u16>,
}

/// Point-in-time state snapshot for one deployed workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadState {
    pub ident: MeshIdent,
    pub container_id: String,
    pub status: WorkloadStatus,
    pub mesh_ip: Option<Ipv4Addr>,
    /// Port(s) the supervisor currently has bound for this workload, keyed by
    /// port name — same meaning as [`DeployResult::ports`], observed rather
    /// than returned.
    ///
    /// This field is what makes a moved port *correctable*. `DeployResult` gets
    /// the resolved port into a service record once, at admission; this one
    /// rides every `list_workloads()` sweep, so a workload that restarted onto
    /// a different port updates the record instead of leaving it advertising a
    /// port nothing is listening on. A stale-but-healthy-looking record is a
    /// strictly worse failure than an absent one, because nothing detects it.
    ///
    /// Names ride the same sweep at no extra cost, which is why R844-F15 put
    /// them here rather than inventing a second channel: the correction path
    /// already re-asserts every resolved port on every pass.
    #[serde(default)]
    pub ports: BTreeMap<String, u16>,
}

/// Attach names to a port list that carries none.
///
/// A `Vec<u16>` — `expose.mesh.ports` on a [`WorkloadSpec`], a legacy
/// `serve_bundle.port`, an older peer's `WorkloadEntry.ports` off the sibling
/// wire — is the shape that predates named ports, and it genuinely has no
/// names to recover. This is the one function that decides what to call those
/// ports, so kamaji, yubaba's service records and the `PORT_<NAME>` env
/// contract (R844-T13) all spell the same workload's ports identically.
///
/// The rule, and why:
///
/// - **Exactly one** port becomes [`DEFAULT_PORT_NAME`] (`http`). A
///   single-listener workload is the overwhelmingly common case, `http` is the
///   name R844-F14's allocator gives it too, and there is nothing to be
///   ambiguous about: the one port a workload has *is* the one it serves on. So
///   the trivial case stays trivial and `PORT` can alias it (R844-T13).
/// - **Several** ports each become their own number, as a decimal string
///   (`{"8080": 8080, "9090": 9090}`) — and, importantly, **none of them
///   becomes `http`**.
///
/// That second clause is the whole care in this function, and it was nearly got
/// wrong: the obvious rule is "first port is `http`, rest are numbers", which
/// reads as reasonable and is exactly the index-guess named ports exist to
/// abolish. `expose.mesh.ports = [8080, 9090]` says a workload listens on two
/// ports; it does not say which one a front door should publish. Calling the
/// first one `http` would let
/// `ServiceRecordFanout::port_for` resolve an ingress rule against a positional
/// accident and publish a hostname at, say, a metrics listener — the failure
/// that only surfaces as a 502 at request time. A caller asking for `http` and
/// getting `None` is the honest answer; the operator then either pins `port` on
/// the slot or names the ports in the manifest, and both of those are somebody
/// stating the fact rather than the code inventing it.
///
/// Not `extra1`, not `port-9090`, for the smaller reason: an anonymous
/// declaration has no names and the number is the only identity those ports
/// actually carry, so an ordinal would name a thing nobody said. It also keeps
/// the env spelling readable (`PORT_9090`, not `PORT_PORT_9090`).
///
/// Deterministic and idempotent: the same list always yields the same map, and
/// re-naming an already-named port list never happens because named ports never
/// take this path. Duplicate numbers collapse, which is correct — a workload
/// cannot bind the same port twice. Note that collapsing can turn a two-element
/// list into a one-element map, and `[8080, 8080]` then *does* name `http`,
/// which is right: there is only one port.
///
/// Once a manifest spells `ports = ["http", "wss"]` the real names flow through
/// from the allocator and none of this synthesis runs.
pub fn name_anonymous_ports(ports: &[u16]) -> BTreeMap<String, u16> {
    let mut distinct: Vec<u16> = ports.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    match distinct.as_slice() {
        [one] => [(DEFAULT_PORT_NAME.to_string(), *one)].into_iter().collect(),
        many => many.iter().map(|&p| (p.to_string(), p)).collect(),
    }
}

/// The `name -> port` map for a workload's declared mesh exposure (R844-F17).
///
/// This is the one lowering from a *manifest* to the named ports every tier
/// below speaks, and it exists because [`name_anonymous_ports`] can only ever
/// synthesise: before R844-F17 `expose.mesh.ports` was an array of bare
/// numbers, so a two-listener workload had no way to say which one a front door
/// should publish and the honest answer was to refuse. Now it can say, and this
/// is what reads the answer.
///
/// The rule, and the care in it:
///
/// - **Nothing is named** — the whole list falls through to
///   [`name_anonymous_ports`], byte-for-byte the pre-F17 behaviour. A sole port
///   becomes `http`; several become their own numbers and none becomes `http`.
/// - **Something is named** — every declared name is used verbatim, and an
///   *unnamed sibling* becomes its own number rather than `http`. That second
///   clause is deliberate and is the whole difference from "the leftover one
///   must be the default": an author who names one of three ports has shown
///   they name ports on purpose, so promoting whichever one they left bare to
///   `http` would invent exactly the fact — *this* is the listener the world
///   dials — that naming exists to state. A caller asking for `http` and
///   getting `None` sends the author back to the manifest, which is the right
///   place to settle it.
///
/// Name-only entries (`ports = ["http"]`) have no number to map yet, so they
/// are absent here; a supervisor that allocates from the manifest is what fills
/// them in, and `validate::shape` warns that none does today.
///
/// Deterministic against a hostile spec as well as a validated one: declared
/// names are inserted first, so a manifest whose name collides with a sibling's
/// number-as-string (`[{ name = "8080", port = 9090 }, 8080]` — rejected by
/// `validate::shape`, but the binary wire is not validated) resolves the same
/// way on every node instead of by iteration order.
/// Refuse a spec carrying [`WorkloadSpec::files`] on a backend that does not
/// materialize them (R870-F23, narrowed by R870-F27).
///
/// [`Backend::materializes_files`] is the single fact this reads; see it for
/// which backends write and which refuse. A backend
/// that cannot write must call this rather than accept the spec and ignore
/// the field: the workload the field exists for reads its *entire* routing
/// table out of such a file, so a backend that silently skips it starts a
/// process against whatever happened to be at that path — nothing, or the
/// previous deploy's table. That comes up healthy and routes wrongly, which
/// is strictly worse than not starting.
///
/// The correct fix for any backend that acquires a real customer here is to
/// implement the write, not to relax this — which is exactly what R870-F27
/// did for containerd, and what the remaining two would copy.
pub fn reject_unmaterializable_files(
    spec: &workload_spec::WorkloadSpec,
    backend: Backend,
) -> anyhow::Result<()> {
    if spec.files.is_empty() || backend.materializes_files() {
        return Ok(());
    }
    let paths: Vec<String> = spec
        .files
        .iter()
        .map(|f| f.path.display().to_string())
        .collect();
    anyhow::bail!(
        "workload {} declares {} spec file(s) ({}) but the {backend:?} backend does not \
         materialize them. The native and containerd backends write WorkloadSpec::files; a \
         workload that reads its config from one of these paths would start against a stale or \
         absent file and route wrongly while reporting healthy. Deploy it on one of those two, \
         or implement materialization for {backend:?}",
        spec.name,
        paths.len(),
        paths.join(", "),
    )
}

pub fn declared_port_names(mesh: &workload_spec::MeshExpose) -> BTreeMap<String, u16> {
    if mesh.ports.iter().all(|p| p.name.is_none()) {
        return name_anonymous_ports(&mesh.numbers());
    }

    let mut out: BTreeMap<String, u16> = BTreeMap::new();
    for port in &mesh.ports {
        if let (Some(name), Some(number)) = (port.name.as_deref(), port.number) {
            out.insert(name.to_string(), number);
        }
    }
    for port in &mesh.ports {
        if port.name.is_none() {
            if let Some(number) = port.number {
                out.entry(number.to_string()).or_insert(number);
            }
        }
    }
    out
}

/// The deployment environment a container backend owes every workload it
/// starts: `YAH_MESH_IP`, the address the workload was placed at, and the
/// `PORT` / `PORT_<NAME>` contract (R844-T13) for its declared mesh ports.
///
/// One function because two backends used to spell it (R908-T1). This crate's
/// containerd backend injected both; kamaji-bin's — the one fleet nodes run —
/// injected neither, so a host-networked workload there had no way to learn
/// which address to bind, and `.yah/infra/workloads/yah-cloud-admin.toml` typed
/// its node's mesh IP into its own spec instead.
///
/// A container gets its own network namespace (or the host's), so the declared
/// `expose.mesh.ports` *is* the bound port — there is nothing to allocate.
/// Naming them through [`declared_port_names`] anyway is what makes a workload
/// read the same variable on a container as on the native backend, where the
/// number really was allocated.
///
/// Port variables yield to a name the spec's own env already declares: this
/// layer is applied *after* the spec's literal env, so injecting unconditionally
/// would override an explicit operator value instead of yielding to it.
/// `YAH_MESH_IP` does not yield — it reports where the supervisor put the
/// workload, which is not the spec's to restate.
pub fn deploy_contract_env(
    spec: &workload_spec::WorkloadSpec,
    mesh_ip: std::net::Ipv4Addr,
) -> Vec<String> {
    let mut env = vec![format!("YAH_MESH_IP={mesh_ip}")];
    let spec_names: Vec<&str> = spec.env.iter().map(|e| e.name.as_str()).collect();
    for (k, v) in ports::port_env(&declared_port_names(&spec.expose.mesh)) {
        if !spec_names.contains(&k.as_str()) {
            env.push(format!("{k}={v}"));
        }
    }
    env
}

/// The [`ports::PortSpec`] set a workload's declared mesh exposure asks for
/// (R844-F21) — the lowering from a *manifest* to an allocator's input.
///
/// [`declared_port_names`] answers "what number is each port already at".
/// This answers "what does this workload want", which is the question a
/// supervisor has to settle *before* anything is bound, and until R844-F21
/// nothing asked it: `ports = ["http", "wss"]` parsed, validated and crossed
/// both wires without a single consumer, so the names arrived at the
/// supervisor attached to no numbers and nothing bound them.
///
/// The two functions agree on naming by construction — every number-bearing
/// entry appears here under exactly the name `declared_port_names` gives it,
/// including the anonymous-port rules (a sole bare number is `http`; several
/// are their own numbers and none is `http`). A port allocated under one name
/// and published under another is the whole class of bug this relay exists to
/// remove, so the two readings are one reading.
///
/// A stated number rides through as [`ports::PortSpec::pin`] rather than being
/// honoured here, because what a written number *means* is a per-tier decision
/// R844-F14 already made — [`ports::LedgerPorts`] refuses one that is not
/// world-fixed, [`ports::EphemeralPorts`] treats it as a preference — and this
/// lowering has no business knowing which tier it feeds.
///
/// Name-only entries are the reason this exists: they carry no pin, so
/// `pin.is_none()` is exactly "the supervisor still owes this port a number".
pub fn declared_port_specs(mesh: &workload_spec::MeshExpose) -> Vec<ports::PortSpec> {
    let numbered = declared_port_names(mesh);
    let mut out: Vec<ports::PortSpec> = numbered
        .iter()
        .map(|(name, &number)| ports::PortSpec {
            name: name.clone(),
            pin: Some(number),
        })
        .collect();

    // Name-only entries, in declaration order. The `contains_key` guard keeps a
    // hostile spec deterministic rather than double-listing one name: the
    // binary wire is not validated, so `[{ name = "http", port = 8080 },
    // "http"]` can arrive here even though `validate::shape` rejects it.
    out.extend(
        mesh.ports
            .iter()
            .filter(|port| port.number.is_none())
            .filter_map(|port| port.name.as_deref())
            .filter(|name| !numbered.contains_key(*name))
            .map(ports::PortSpec::auto),
    );
    out
}

/// Refuse a port this backend cannot give a number to (R844-F21).
///
/// A name-only port is a request to *allocate*, and only a backend that owns
/// the workload's network namespace can honour it. A container does not: its
/// ports are its image's, fixed before the manifest was written, which is why
/// both container backends report [`DeployResult::ports`] empty rather than
/// echoing the declaration back (see `containerd::create_and_start`).
///
/// The alternative — allocating a *host* port and publishing that — was
/// considered and rejected: containerd publishes no host ports at all, and the
/// docker backend publishes only what `yah.docker.publish` explicitly maps, so
/// an allocated number would be published into a service record while nothing
/// answered on it. A front door dialling a number no listener holds is exactly
/// the confidently-wrong reading this relay exists to eliminate, and it is
/// strictly worse than the loud refusal here.
pub fn reject_unresolved_ports(
    workload: &str,
    mesh: &workload_spec::MeshExpose,
    backend: Backend,
) -> anyhow::Result<()> {
    let unresolved: Vec<&str> = mesh
        .ports
        .iter()
        .filter(|port| port.number.is_none())
        .filter_map(|port| port.name.as_deref())
        .collect();
    if unresolved.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "workload {workload}: port(s) {:?} name no number, but {:?} cannot \
         allocate one — a container's ports are its image's, fixed before this \
         manifest was written, and this backend publishes no host port to stand \
         in for them. State the number ({{ name = {:?}, port = <n> }}), or run \
         the workload on the native backend, where the supervisor allocates and \
         tells the process via PORT_<NAME>.",
        unresolved,
        backend,
        unresolved[0],
    )
}

/// R964-B1: where kamaji records containerd deploys for replay after a restart
/// (`<this>/.deploys`) unless `--containerd-state-dir` says otherwise. It must
/// sit under a path `kamaji.service` makes writable (`ProtectSystem=strict`):
/// a sibling of `--native-exec-dir /var/lib/yah/kamaji/native`, covered by the
/// unit's `StateDirectory=yah/kamaji`. The yah CLI's
/// `kamaji_unit_grants_every_host_path_kamaji_writes` pins this constant live.
pub const DEFAULT_CONTAINERD_STATE_DIR: &str = "/var/lib/yah/kamaji/containerd";

/// The name a workload's sole port gets when nothing named it, and the name a
/// front door publishes when a workload has several.
///
/// Shared by [`name_anonymous_ports`], R844-F14's allocator and yubaba's
/// ingress port resolution so a single-listener workload is called the same
/// thing at every tier — and so "which port does this hostname front" has one
/// answer rather than one per reader.
pub const DEFAULT_PORT_NAME: &str = "http";

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
        /// Whether the kernel's OOM killer was involved in this failure —
        /// R885-F3's classification, carried out to the wire by R885-T6.
        ///
        /// A plain `bool` rather than the richer `cgroup::ExitClass` because
        /// this is the one bit that has a consumer outside the node: it becomes
        /// [`kamaji_proto::WorkloadState::OomKilled`] at the UDS boundary. The
        /// full four-way classification stays in `reason`, which is where an
        /// operator reads it.
        ///
        /// `false` is the honest default for every backend that cannot tell —
        /// only the native backend reads `memory.events`. It means "not known
        /// to be an OOM", never "known not to be one", which is the same
        /// direction `ExitClass` takes an unreadable counter: inventing an OOM
        /// on a degraded host is the expensive error, because it sends an
        /// operator to raise a ceiling that was never the problem.
        oom_killed: bool,
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
    /// Resume point (R729-F2): an opaque cursor a previous [`LogEvent::cursor`]
    /// carried; the stream starts with the record AFTER it. `None` starts from
    /// the first retained record. A backend that cannot resume ignores it and
    /// leaves every `LogEvent::cursor` `None`.
    pub cursor: Option<String>,
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
    /// Position just after this event (R729-F2), when the backend can resume;
    /// see [`LogOpts::cursor`].
    pub cursor: Option<String>,
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
            cursor: None,
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
///
/// @yah:ticket(R960-F10, "Vend listener: embeddable Hrana-over-turso_core crate a Shape-1 service links, bound to YAH_MESH_IP, verifying camp-tokens; refuses rw until R960 P4")
/// @yah:status(review)
/// @yah:at(2026-10-07T23:41:34Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:phase(P3)
/// @yah:parent(R960)
/// @yah:next("No Hrana server exists in the tree (W358 baseline grep). Build the minimum Hrana surface the workbench client speaks, over the service's OWN turso_core handle (W195 one-writer rule: no second process opens the file). Bind YAH_MESH_IP (kamaji native.rs:705), never 0.0.0.0.")
/// @yah:next("Verify every request with cheers-verify: signature, kid, aud = <workload>/<db>, expiry. No token, expired, and wrong-aud fail IDENTICALLY. Refuse rw-scoped tokens outright until R960 P4 lifts it. Testable now with `yah cloud cheers token --aud ...` against a test workload.")
/// @yah:next("Fill StatefulServiceContract.vend_endpoint (kamaji lib.rs:854), unproduced since W195.")
/// @yah:gotcha("\"Crate home must be publishable: noisetable consumes cheers-* as registry deps (0.8.43-pre.1, web/services/account/Cargo.toml). Recommend oss/cheers beside cheers-turso (shares the turso pin + cheers-verify, no new mirror); a new oss/ subtree needs a mirror and an export-oss.sh entry. Record the choice and add the crate's path to this ticket's files.\"")
/// @arch:see(.yah/docs/working/W358-data-connections-remote-dbs-through-the-vault.md)
/// @yah:handoff("New publishable crate oss/cheers/crates/cheers-vend (workspace member, version 0.8.43-pre.1, deps cheers-core/cheers-verify/turso pin/axum 0.8). VendService::new(&turso::Database, VendConfig{verifier,kid,audience,reject_floor}) connects to the service's OWN Database (never opens the file) and sets PRAGMA query_only on that connection. VendListener::bind(ip,port,svc) refuses unspecified addrs; bind_mesh_from_env reads YAH_MESH_IP + PORT_SQL; endpoint() -> http://ip:port.")
/// @yah:handoff("Hrana subset: GET /v2,/v3; POST /v2/pipeline,/v3/pipeline with execute/batch(with conditions)/get_autocommit/close; stateless (baton always null); sql_id/sequence/describe/store_sql unsupported (per-request error).")
/// @yah:handoff("Gate: verify_mcp_at(token, now, kid) + aud == <workload>/<db> + scope sql:read. All refusals: 401, body 'unauthorized', WWW-Authenticate: Bearer, padded to reject_floor (default 50ms). Any sql:* scope other than sql:read -> 403 after verification (rw refused until R960 P4).")
/// @yah:handoff("kamaji: removed BuiltinService.vend_endpoint (a &'static str for a runtime mesh URL, always None); added StatefulServiceContract::with_vend_endpoint(url) - the service passes VendListener::endpoint() into it. No other users of the field in app/crates/oss.")
/// @yah:verify("cd oss/cheers && cargo test -p cheers-vend -> 5 passed, 0 failed, 0 warnings (2026-10-07; valid SELECT, no-token/expired/wrong-aud identical 401 above floor, rw 403, vended INSERT errors while owner conn writes, 0.0.0.0 bind refused). Daemon flagged unrelated peer edits (yubaba cloud, app cli) mid-run.")
/// @yah:verify("cd oss/kamaji && cargo check -p kamaji --tests -> EXIT=0")
/// @yah:gotcha("Not done here (W358 step 6 remainder): sql.hrana capability on GET /services, `sql` mesh port + verify-key mount in workload TOML and spec-loader refusal, noisetable-account link-in. Not wired into any service yet.")
/// @yah:assumes("Scope vocabulary sql:read / sql:write is defined here as constants (cheers_vend::SQL_READ/SQL_WRITE); cheers_core::yah_scopes has no sql namespace yet. R960-F9's minter must use these strings, or move them into yah_scopes and repoint.")
/// @yah:assumes("Used the `turso` wrapper (turso::Database, which wraps turso_core) rather than raw turso_core, matching cheers-turso and the services that will link this.")
/// @yah:assumes("Identical timing shape implemented as a minimum-latency floor on 401s, not constant-time crypto.")
/// @yah:files(oss/kamaji/crates/kamaji/src/lib.rs)
/// @yah:files(oss/cheers/crates/cheers-vend/src/lib.rs)
/// @yah:files(oss/cheers/crates/cheers-vend/src/hrana.rs)
/// @yah:files(oss/cheers/crates/cheers-vend/tests/vend.rs)
/// @yah:files(oss/cheers/crates/cheers-vend/Cargo.toml)
/// @yah:handoff("Leader (Fable session:62240105) re-verified 2026-10-07: cargo test -p cheers-vend 5 passed / 0 failed; cargo check -p kamaji --tests exit 0. Courier Ashguard session:1aeebae6. The W358 step-6 remainder listed in the gotcha (services capability, workload TOML wiring, noisetable link-in) is R960-F8 / F11 / noisetable R804-F2 scope, not this ticket's.")
/// @yah:verify("Leader re-run: cd oss/cheers && cargo test -p cheers-vend -> 5 passed, 0 failed; cd oss/kamaji && cargo check -p kamaji --tests -> EXIT=0.")
/// @yah:handoff("cheers-vend SQL_READ/SQL_WRITE now alias cheers_core::yah_scopes (R960-F9 residual; pub use re-export, Scope type not &str, so the two comparisons in lib.rs use .as_wire()); cargo test -p cheers-vend 5 passed / 0 failed")
/// @yah:gotcha("FOUND BY noisetable R804-F2 (Glimmerstone session:7596d334, 2026-10-08), dogfooding `yah sql` (libsql 0.9.30, the same client data-source/src/libsql_adapter.rs:71 runs) at the real noisetable-account binary: as shipped, this listener could NOT SERVE A SINGLE libsql READ, though the 'minimum surface the workbench's libsql client speaks' claim said otherwise. Three gaps: (1) libsql posts with no Content-Type, and axum's Json extractor answered 415; (2) libsql's prepare sends `describe` (libsql hrana/mod.rs:134), which was unsupported; (3) libsql's `query` reads rows only through POST /v3/cursor, which did not exist. All three were FIXED in oss/cheers/crates/cheers-vend (lib.rs pipeline + cursor handlers, hrana.rs describe/run_cursor/run_steps), and tests/libsql_client.rs now drives the real libsql client. R960-T12's live proof needs these bytes, and so does the cheers 0.8.43 publish.")
/// @yah:handoff("Seams for noisetable R804-F2, landed by courier @Miravel:eclipse under an annotation `R960-T1` in oss/cheers/crates/cheers-vend/src/lib.rs that the yah board does NOT scan (`yah board show R960-T1` = not found), so they are recorded here: cheers-turso TursoConn::database(); cheers-verify kid_for (the CLI's copy deleted, now a re-export); cheers-vend VendConfig::from_public_key(&[u8;32], aud), which derives the kid. Plus the three libsql fixes in the gotcha above. Consumer: noisetable web/services/account/src/vend.rs.")
/// @yah:verify("cd ~/ss/yah/oss/cheers && cargo test -p cheers-vend -> 10 passed / 0 failed (7 tests/vend.rs incl. new a_pipeline_without_a_content_type_is_served + 3 new tests/libsql_client.rs); cargo clippy -p cheers-vend --all-targets clean. Negative control: the same libsql client against the pre-fix listener failed first with 415, then with 'request type not supported'.")
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatefulServiceContract {
    /// Human-readable service name, unique within a camp / pond.
    pub name: String,
    /// Relative paths of `.turso` files owned by this service.
    pub files: Vec<String>,
    /// Optional SQL vending endpoint (Mode B per W195 §1): the Hrana base URL
    /// a `cheers-vend` listener reports once it has bound the mesh address
    /// (`VendListener::endpoint`). A runtime value — set it with
    /// [`with_vend_endpoint`](Self::with_vend_endpoint) after binding, never
    /// from a compile-time descriptor.
    pub vend_endpoint: Option<String>,
    /// Opaque schema version used by kamaji for drift detection. Typically
    /// an ISO-8601 date string matching when the schema was last changed.
    pub schema_version: String,
    /// Optional R2 (or compatible) backup target pattern, e.g.
    /// `"r2://yah-backups/{name}/{file}"`. `{file}` is replaced with the
    /// basename of each entry in `files`.
    pub backup_target: Option<String>,
}

impl StatefulServiceContract {
    /// Record where this service vends its database (W358 `vend` source).
    /// Called with the URL a bound vend listener reports.
    pub fn with_vend_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.vend_endpoint = Some(endpoint.into());
        self
    }
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
            schema_version,
            backup_target: None,
        }
    }

    /// Convert to an owned [`StatefulServiceContract`] for runtime use.
    pub fn contract(&self) -> StatefulServiceContract {
        StatefulServiceContract {
            name: self.name.to_string(),
            files: self.files.iter().map(|s| s.to_string()).collect(),
            vend_endpoint: None,
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
            reason: "boom".into(),
            oom_killed: false,
        }
        .is_terminal());
        // R885-T6: an OOM kill is a *refinement* of Failed, not a peer of it.
        // If this ever stops being terminal, a workload the kernel killed for
        // exceeding its ceiling would look to the supervisor like something
        // still worth waiting on.
        assert!(WorkloadStatus::Failed {
            reason: "OOM-killed".into(),
            oom_killed: true,
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

    // ── R844-F15: naming an anonymous port list ─────────────────────────────

    #[test]
    fn a_sole_anonymous_port_is_named_http() {
        assert_eq!(
            name_anonymous_ports(&[8080]),
            [(DEFAULT_PORT_NAME.to_string(), 8080)]
                .into_iter()
                .collect::<BTreeMap<_, _>>()
        );
    }

    /// The load-bearing half. An anonymous list of several ports says a
    /// workload listens on several ports; it does not say which one a front
    /// door should publish. Naming the first one `http` would make
    /// `ServiceRecordFanout::port_for` resolve an ingress rule off declaration
    /// order and point a hostname at, say, a metrics listener — visible only as
    /// a 502 at request time.
    #[test]
    fn several_anonymous_ports_name_none_of_themselves_http() {
        let named = name_anonymous_ports(&[8080, 9090]);
        assert_eq!(named.get("8080"), Some(&8080));
        assert_eq!(named.get("9090"), Some(&9090));
        assert_eq!(named.get(DEFAULT_PORT_NAME), None);
    }

    /// Declaration order does not change the answer — if it did, the map would
    /// carry the positional accident it exists to remove.
    #[test]
    fn naming_is_independent_of_declaration_order() {
        assert_eq!(
            name_anonymous_ports(&[9090, 8080]),
            name_anonymous_ports(&[8080, 9090])
        );
    }

    /// A repeated port is one port, so it *is* unambiguous and does get `http`.
    #[test]
    fn a_repeated_port_collapses_to_the_single_port_case() {
        assert_eq!(
            name_anonymous_ports(&[8080, 8080]),
            name_anonymous_ports(&[8080])
        );
    }

    #[test]
    fn no_ports_names_nothing() {
        assert!(name_anonymous_ports(&[]).is_empty());
    }

    // ── declared_port_names (R844-F17) ───────────────────────────────────────

    fn mesh(ports: Vec<workload_spec::MeshPort>) -> workload_spec::MeshExpose {
        workload_spec::MeshExpose {
            identity: workload_spec::MeshIdent("api".into()),
            ports,
            allow_from: vec![],
        }
    }

    /// The compatibility property the whole change rests on: every manifest
    /// written before names existed resolves to exactly what it always did.
    #[test]
    fn an_unnamed_declaration_resolves_identically_to_the_old_synthesis() {
        for numbers in [vec![], vec![8080], vec![8080, 9090], vec![8080, 8080]] {
            assert_eq!(
                declared_port_names(&mesh(
                    workload_spec::MeshExpose::anonymous_ports(numbers.clone())
                )),
                name_anonymous_ports(&numbers),
                "{numbers:?}"
            );
        }
    }

    #[test]
    fn a_declared_name_is_used_verbatim() {
        let named = declared_port_names(&mesh(vec![
            workload_spec::MeshPort::pinned("http", 8080),
            workload_spec::MeshPort::pinned("wss", 8443),
        ]));
        assert_eq!(named.get("http"), Some(&8080));
        assert_eq!(named.get("wss"), Some(&8443));
        assert_eq!(named.len(), 2);
    }

    /// Naming one port does not promote the leftover to `http`. Doing so would
    /// invent the fact — *this* is the listener the world dials — that naming
    /// exists to state, and would do it precisely for the author who has shown
    /// they name ports deliberately.
    #[test]
    fn an_unnamed_sibling_of_a_named_port_becomes_its_number_not_http() {
        let named = declared_port_names(&mesh(vec![
            workload_spec::MeshPort::pinned("metrics", 9090),
            workload_spec::MeshPort::anonymous(8080),
        ]));
        assert_eq!(named.get("metrics"), Some(&9090));
        assert_eq!(named.get("8080"), Some(&8080));
        assert_eq!(named.get(DEFAULT_PORT_NAME), None);
    }

    /// A name-only entry has no number yet, so it cannot appear in a
    /// `name -> port` map. It must not fabricate one and must not drag the rest
    /// of the list down with it.
    #[test]
    fn a_name_only_port_is_absent_until_something_allocates_it() {
        let named = declared_port_names(&mesh(vec![
            workload_spec::MeshPort::named("wss"),
            workload_spec::MeshPort::pinned("http", 8080),
        ]));
        assert_eq!(named.get("http"), Some(&8080));
        assert_eq!(named.get("wss"), None);
        assert_eq!(named.len(), 1);
    }

    // ── declared_port_specs / reject_unresolved_ports (R844-F21) ─────────────

    fn spec_by_name(specs: &[ports::PortSpec], name: &str) -> Option<Option<u16>> {
        specs.iter().find(|s| s.name == name).map(|s| s.pin)
    }

    /// The property that keeps allocation and publication one reading: every
    /// port `declared_port_names` can name appears in the spec set under
    /// exactly that name, carrying exactly that number as its pin.
    #[test]
    fn every_numbered_port_lowers_under_the_name_it_is_published_by() {
        for declaration in [
            vec![],
            workload_spec::MeshExpose::anonymous_ports([8080]),
            workload_spec::MeshExpose::anonymous_ports([8080, 9090]),
            vec![
                workload_spec::MeshPort::pinned("http", 8080),
                workload_spec::MeshPort::anonymous(9090),
            ],
        ] {
            let m = mesh(declaration.clone());
            let names = declared_port_names(&m);
            let specs = declared_port_specs(&m);
            for (name, &number) in &names {
                assert_eq!(
                    spec_by_name(&specs, name),
                    Some(Some(number)),
                    "{declaration:?} -> {name}"
                );
            }
            assert_eq!(specs.len(), names.len(), "{declaration:?}");
        }
    }

    /// The whole point of the lowering: a name-only port becomes an unpinned
    /// spec, which is what "the supervisor still owes this port a number"
    /// looks like to an allocator.
    #[test]
    fn a_name_only_port_lowers_to_an_unpinned_spec() {
        let specs = declared_port_specs(&mesh(vec![
            workload_spec::MeshPort::named("wss"),
            workload_spec::MeshPort::pinned("http", 8080),
        ]));
        assert_eq!(spec_by_name(&specs, "wss"), Some(None));
        assert_eq!(spec_by_name(&specs, "http"), Some(Some(8080)));
        assert_eq!(specs.len(), 2);
    }

    /// A number is lowered as a `pin`, never honoured here. What a written
    /// number means is a per-tier decision (R844-F14) and this function does
    /// not know which tier it is feeding.
    #[test]
    fn a_stated_number_is_lowered_as_a_pin_not_resolved() {
        let specs = declared_port_specs(&mesh(vec![workload_spec::MeshPort::pinned("https", 443)]));
        assert_eq!(spec_by_name(&specs, "https"), Some(Some(443)));
    }

    /// The hostile-spec case `declared_port_names` already guards: the postcard
    /// wire is not validated, so a name-only entry duplicating a numbered
    /// sibling's name must not produce two specs under one name — the allocator
    /// would reject the set and a legal manifest would be blamed for it.
    #[test]
    fn a_name_only_duplicate_of_a_numbered_port_lowers_once() {
        let specs = declared_port_specs(&mesh(vec![
            workload_spec::MeshPort::pinned("http", 8080),
            workload_spec::MeshPort::named("http"),
        ]));
        assert_eq!(specs.len(), 1);
        assert_eq!(spec_by_name(&specs, "http"), Some(Some(8080)));
    }

    /// R844-B22: `workload_spec::validate::select_mesh_port` has to name the
    /// default port too, and it cannot import this constant — kamaji sits above
    /// workload-spec in the publish DAG (`yah-base <- {qed,kamaji} <- yubaba`),
    /// so the dependency would invert the graph. The two are therefore agreed
    /// by convention, and this is the thing that makes the convention hold: if
    /// either side ever renames `http`, a dependent workload's `FromMesh` URL
    /// and its `PORT` env would silently disagree about which listener is the
    /// default. Asserted here because kamaji is the lower of the two crates
    /// that can see both.
    #[test]
    fn default_port_name_agrees_with_the_mesh_resolver() {
        assert_eq!(
            DEFAULT_PORT_NAME,
            workload_spec::validate::DEFAULT_PORT_NAME
        );
        assert_eq!(DEFAULT_PORT_NAME, ports::HTTP);
    }

    #[test]
    fn a_container_backend_refuses_a_port_it_cannot_allocate() {
        let declared = mesh(vec![
            workload_spec::MeshPort::pinned("http", 8080),
            workload_spec::MeshPort::named("wss"),
        ]);
        for backend in [Backend::Containerd, Backend::Docker] {
            let err = reject_unresolved_ports("api", &declared, backend)
                .expect_err("a name-only port has no number a container can bind");
            let msg = format!("{err:#}");
            assert!(msg.contains("wss"), "must name the port; got: {msg}");
            assert!(
                !msg.contains("8080"),
                "must not blame the port that is fine; got: {msg}"
            );
            assert!(
                msg.contains("api"),
                "must name the workload; got: {msg}"
            );
        }
    }

    #[test]
    fn a_fully_numbered_declaration_passes_every_container_backend() {
        let declared = mesh(workload_spec::MeshExpose::anonymous_ports([8080, 9090]));
        assert!(reject_unresolved_ports("api", &declared, Backend::Containerd).is_ok());
        assert!(reject_unresolved_ports("api", &declared, Backend::Docker).is_ok());
    }

    /// `validate::shape` rejects this, but the postcard wire is not validated,
    /// so the answer still has to be the same on every node.
    #[test]
    fn a_name_colliding_with_a_siblings_number_resolves_deterministically() {
        let collide = mesh(vec![
            workload_spec::MeshPort::pinned("8080", 9090),
            workload_spec::MeshPort::anonymous(8080),
        ]);
        let reversed = mesh(vec![
            workload_spec::MeshPort::anonymous(8080),
            workload_spec::MeshPort::pinned("8080", 9090),
        ]);
        // The declared name wins in both orders — it is the only half an author
        // actually wrote.
        assert_eq!(declared_port_names(&collide).get("8080"), Some(&9090));
        assert_eq!(declared_port_names(&collide), declared_port_names(&reversed));
    }
}

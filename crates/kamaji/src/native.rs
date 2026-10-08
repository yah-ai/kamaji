//! `Backend::Native` — direct fork+exec of a host binary (W199's "ideal
//! native-backend case"; the backend R490-F2 routes mesofact-dev through).
//!
//! Scope:
//!
//! - **fork+exec + supervise** via `tokio::process`.
//! - **cgroup v2 confinement** (R885-B1): each workload gets its own leaf inside
//!   the subtree systemd delegates to kamaji, carrying the spec's `memory.max`
//!   and its CPU **request** as a `cpu.weight` — plus a `cpu.max` quota only if
//!   the spec declares one (R885-B5; a request is not a ceiling). The child
//!   joins the leaf in the post-fork/pre-exec window, so the workload binary
//!   never executes outside its boundary. See [`crate::cgroup`]
//!   for where the leaf goes and why. On a host with no delegated subtree
//!   (macOS, a dev box, a container) this degrades to the old unbounded fork —
//!   loudly, via a `warn!` naming the reason, not silently.
//!   **Capability and filesystem policy are a separate axis and are NOT closed
//!   here** — W344 §"Audit residue" says so in as many words ("piece 1 below
//!   only closes the second"). A native workload still inherits kamaji's ambient
//!   capability set; see R885-B9.
//! - **`spec.entrypoint` + `spec.command`** concatenate to the argv, exactly
//!   container semantics (ENTRYPOINT vector + CMD args; CMD alone is the
//!   program). `spec.image` is identity metadata only — nothing is pulled.
//! - **Literal env vars** + `YAH_MESH_IP` injection, mirroring the docker
//!   backend.
//! - **stdout/stderr capture** to `<state_dir>/<ident>/{stdout,stderr}.log`;
//!   the initial spawn truncates, respawns append (crash-loop history is kept).
//!   `stream_logs` replays the captured files (`follow` is not supported —
//!   callers get the current contents and the stream ends).
//! - **Spec-retaining restart loop** (R591-F1): each workload is owned by a
//!   per-workload supervisor task that retains the `WorkloadSpec` and re-execs
//!   the child on exit per its [`RestartPolicy`] — `Always` (unconditional,
//!   after a short fixed delay so a fast-exiting binary can't hot-loop),
//!   `OnFailure { max_attempts, backoff }` (exponential backoff, gives up after
//!   `max_attempts` consecutive failures), or `Never` (park after one run).
//!   Restarts publish [`WorkloadStatus::Restarting`]; this is what lets a
//!   pinned-singleton appliance (e.g. headscale) survive a graceful-exit boot
//!   race instead of staying dead until next-boot reconcile.
//! - **Idempotent teardown**: SIGTERM → grace (fixed 5s) → SIGKILL, and the
//!   supervisor stops restarting. Same-ident redeploys tear the predecessor
//!   down first.
//! - **Crash semantics** per W199 §"Crash semantics": the restart loop lives
//!   *in* the supervising kamaji process, so if kamaji itself dies its native
//!   workloads are orphaned; next-boot reconcile re-adopts or re-deploys.
//!   `kill_on_drop` is intentionally off.
//!
//! @yah:ticket(R599-F6, "On-demand JIT lifecycle: kamaji holds the listen socket, forks on first connection (fd-passing), reaps after idle TTL")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-07-22T00:21:00Z)
//! @yah:phase(P2)
//! @yah:parent(R599)
//! @yah:depends_on(R599-F4)
//! @yah:depends_on(R599-F9)
//! @yah:handoff("DONE + verified (both halves). JIT on-demand lifecycle landed; the implementation lives in oss/kamaji/crates/kamaji/src/jit.rs (this native.rs block stays the canonical anchor per one-block-per-ID; jit.rs + kamaji-bin server.rs carry prose 'Part of R599-F6' pointers only, no 2nd @yah block).")
//! @yah:handoff("kamaji crate: new jit::JitRuntime = poll-fork-rearm on the custodian-held listener. bind_and_hold via SocketCustodian; watch the held fd for readiness via tokio AsyncFd WITHOUT accepting (kamaji stays out of the data path); on a pending connection fork the serve runtime passing the held fd as child fd 3 (pre_exec dup2->3 + clear FD_CLOEXEC, env LISTEN_FDS=1); re-arm on child exit and NEVER release the socket, so connections queued across a reap/re-fork are served by the next child (zero-dropped). Added SocketCustodian::held_raw_fds accessor (socket_custody.rs).")
//! @yah:handoff("kamaji-bin server.rs: deploy_mesofact_bundle now routes by lifecycle -- KeepAlive->native (R599-F10), OnDemand->new deploy_bundle_on_demand->JitRuntime. Shared materialize+serve-bin-resolution extracted to materialize_and_resolve_serve. --idle-ttl baked into the JIT spec; RestartPolicy::Never (the JIT supervisor owns re-forking; an idle self-reap is not a crash). NO probe target registered for on-demand (a 1s TcpConnect probe would connect+fork every interval, defeating the idle reap). BundleBackend gained `jit`; List merges both runtimes, Stop routes teardown to both (both idempotent).")
//! @yah:handoff("GOTCHA: LISTEN_PID is deliberately UNSET. mesofact-serve's socket_activation_listener adopts fd 3 whenever LISTEN_PID is absent; setting it to the child's own pid would require an async-signal-unsafe setenv inside the post-fork pre_exec hook (the pid isn't known before fork). Inherits R599-F10's loopback-port + one-bundle-per-node limit (mesh-IP-plane binding needs Deploy to carry a MeshAssignment -- shared follow-up, not F6-specific).")
//! @yah:next("FOLLOW-UP (shared with R599-F10, not F6-specific): loopback-port + one-bundle-per-node limit. On-demand binds 127.0.0.1:<bind_port> just like keep-alive; mesh-IP-plane binding + multiple bundles per node needs the UDS Deploy envelope to carry a MeshAssignment (bind IP + per-workload port). File if/when a node must host >1 bundle.")
//! @yah:next("COVERAGE NOTE: the full fork->serve->reap->re-fork mechanics are proven by the kamaji-crate E2E (tests/jit_lazy_fork.rs) with a real socket-activating child; the kamaji-bin bundle-serving test covers deploy/list(idle)/stop only, because a shell serve stand-in can't adopt fd 3 as a TCP listener. A bin-path fork E2E would need a real socket-activating serve bin (mesofact-serve, separate subcamp).")
//! @yah:verify("cargo test -p kamaji --features native-integration (27 lib + tests/jit_lazy_fork E2E: idle->connect->fork->serve->idle->reap->reconnect->re-fork, 0 dropped connections; non-flaky over repeated runs)")
//! @yah:verify("cargo test -p kamaji-bin --features bundle-serving (196 pass, incl server::tests::bundle_serving::ondemand_deploy_binds_and_appears_in_list_idle); default build unchanged (193 pass)")
//! @yah:verify("cargo clippy -p kamaji --features native-integration --tests + -p kamaji-bin --features bundle-serving: clean (only pre-existing warnings in object-store/pidfd)")
//!
//! @yah:ticket(R605-S6, "Firecracker-isolated x86 build capacity on fleet nodes: dynamic workload vs. permanent reserved sub-VM (may want both)")
//! @yah:status(review)
//! @yah:at(2026-08-19T06:37:42Z)
//! @yah:kind(spike)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @yah:next("Shape A: build/job as an ordinary Workload -- a firecracker.rs kamaji runtime backend sibling to native.rs/containerd.rs (mirrors R578-F1's macvm.rs pattern for Tart), admitted through the SAME [allocatable] capacity pool every other workload on a node already uses (R572-F5) rather than a special-cased build script. Generalizes past builds to one-off jobs (migrations, ad-hoc processes) too -- same shape, dynamically placed and torn down.")
//! @yah:next("Shape B: permanent reserved capacity -- stand up a long-lived VM inside an existing box (e.g. us-west-001) with a fixed carve-out, then `yah cloud machine attach` it as its own fleet entry tagged tag:build-worker (same pattern as us-west-003), so build capacity is a standing reservation instead of a dynamically-admitted placement. Operator explicitly wants BOTH shapes considered, not one instead of the other -- B also covers wanting guaranteed capacity independent of what else is scheduled on the parent box.")
//! @yah:next("Topology: Shape B nests a fleet node inside another fleet node's hypervisor -- same physical box as both parent and child. Operator is fine being recursive for now; deliberately OUT OF SCOPE for this spike is the redundancy/blast-radius diligence question (does the child's capacity disappear correlated with the parent's outages) -- flag it, don't resolve it here.")
//! @yah:gotcha("Adjacent, not duplicate: R605-F2 (agent:bundle-anthropic-glimmerstone, open) is \"Docker/buildx-capable QED runner substrate for the image-yah-{base,rust,rust-bun} jobs\" -- narrower (container image builds specifically) than this spike's general x86 build/job capacity question. Coordinate before landing a runtime backend both could plausibly own.")
//! @yah:gotcha("us-west-003 (candidate build-worker precedent for Shape B tagging) was found UNREACHABLE at application layer during this same investigation 2026-08-16: SSH times out mid banner-exchange, yubaba's 7443 accepts the TCP connection but never answers /identity (0 bytes, 4s timeout). Worth a live check before using it as the reference pattern.")
//! @arch:see(.yah/infra/machines/us-west-001.toml)
//! @arch:see(.yah/infra/machines/us-west-003.toml)
//! @arch:see(oss/kamaji/crates/kamaji-bin/src/native.rs)
//! @yah:handoff("DECIDED: BOTH SHAPES, B FIRST, AND NEITHER OF THEM IS THE URGENT THING. Full reasoning + evidence in .yah/docs/working/W325-isolated-x86-build-capacity.md. Three tickets filed under R605: R605-T7 (Shape B, the reserved us-west-004 build VM — blocked on an operator call), R605-F8 (Shape A, the microVM kamaji backend), R605-B9 (us-west-003 is dark).")
//! @yah:handoff("THE SPIKE'S PREMISE WAS HALF WRONG, and correcting it is the main result. Shape A's dynamic-placement half is ALREADY BUILT AND RUNNING: LifecycleArchetype::Job explicitly names forge runs as its container instance, WorkloadSpec::for_forge synthesizes the spec, CloudConfig::admit_workload applies the R572-F5 capacity floor + archetype taints + mesh-tag affinity, and velveteen_exec::remote::build_workload_spec has been deploying builds as ordinary Workloads since R594. What is missing is not placement. It is ISOLATION.")
//! @yah:handoff("THE FINDING THAT REFRAMES THE TICKET, executed not inferred: an x86/linux build offload lands on us-east-001 — prod raft VOTER 3, the live public-site host, declaring taints = []. It carries tag:build-worker, and among equally-matching machines first_match breaks ties in FILE-NAME order, so us-east-001.toml beats us-west-002.toml deterministically. Forge checks only a 2 GiB placement floor (FORGE_MEMORY_REQUEST_MB) while setting a 32 GiB cgroup ceiling (FORGE_MEMORY_LIMIT_MB); the box has 11682 MB. Nothing between 'QED wants to build V8' and 'a prod consensus member thrashes' says no.")
//! @yah:handoff("SUBSTRATE ANSWERED, and it was the one fact that could have killed both shapes: BOTH OVH nodes have nested virtualization. us-west-001 and us-east-001 each expose /dev/kvm (0660 root:kvm), kvm_intel is loaded, and /sys/module/kvm_intel/parameters/nested reads Y — on boxes that are themselves KVM guests (lscpu: Hypervisor vendor: KVM). ~10.9 GB RAM and ~92 GB disk free on each. Firecracker is buildable here. One snag recorded on R605-F8: the debian service user (uid 1000) is NOT in group kvm (gid 992).")
//! @yah:handoff("SHAPE A IS MUCH CHEAPER IN RUST THAN IT LOOKS, AND MUCH MORE EXPENSIVE OUTSIDE IT. kamaji::Backend is NOT a postcard wire type (kamaji-proto/src/codec.rs references only ErrorCode::BackendRefused), and backend selection is per-workload and annotation-driven — kamaji-bin/src/server.rs:1115 branches on spec.wants_native_exec(). So a microVM backend is a sibling branch on a new annotation value: no Workload enum variant, no exhaustive-match churn in peer-owned codec.rs, no postcard variant-order hazard. The real cost is the microVM supply chain (kernel+rootfs, jailer, TAP networking that still reaches crates.io, and getting the source tree in / artifacts out — forge_produced::durable_mount is a host bind-mount today). Sized on R605-F8.")
//! @yah:handoff("TICKET-TEXT CORRECTION: this ticket's own next-step said Shape A 'mirrors R578-F1's macvm.rs pattern for Tart'. There is no macvm.rs in the tree — R578-F1 is still open and unstarted, and the only occurrence of the string macvm anywhere is inside this ticket's annotation. There was no precedent to mirror. Recorded on R605-F8 so the next agent does not go looking for it.")
//! @yah:verify("cargo test -p xtask --test fleet_build_placement — 2 passed, 0 failed. Both tests green on the first run against the live fleet inventory, matching the predicted placement table exactly.")
//! @yah:verify("Live probes, 2026-08-19, all quoted in W325: us-west-001 and us-east-001 over ssh (KVM, nested=Y, capacity, kamaji+yubaba both `active`); us-west-003 ssh/22 + curl :7443 (both refused); us-west-002 ssh over mesh 100.64.0.4 (timed out).")
//! @yah:gotcha("FOUND WHILE WIRING THE GATE, and it invalidates a claim another ticket already made in writing: `xtask` is a workspace member but NOT a default-member, so check.toml's step-3 `cargo test` reaches NONE of its tests. Before this session exactly ONE xtask test ran in CI (cluster_epoch_drift, via its own named step). EIGHT test binaries were dark: fleet_taints, fleet_sovereign_groups, fleet_index, fleet_build_placement, workload_envelope, mirror_ingress, bundled_registry, release_bump. Three of those (the fleet_* trio) were written explicitly AS standing complaints — their module docs say 'a standing test is the difference between a guard that exists and a guard that fires' — and none had ever fired. Worse: R546-B7's handoff states workload_envelope 'runs under the check pipeline's existing cargo-test step'. It does not, and never did. The schema-drift and fleet-index STEPS run bash scripts, not the like-named tests, so those names do not close the gap either.")
//! @yah:gotcha("FIXED, not just reported: check.toml's new step is `xtask-tests` = `cargo test -p xtask --tests --locked`, i.e. the WHOLE suite, not a fourth narrow --test <name> step — one-more-narrow-step is exactly how the gap accumulated. Verified green before widening: the full suite ran exit 0 (33 + 3 + 8 + 2 + 6 + ... tests, all sub-second once compiled), INCLUDING the peer's uncommitted in-flight workload_envelope.rs. cluster-epoch-drift-guard deliberately KEEPS its own step even though xtask-tests subsumes it: its failure is a decision (bump the compatibility epoch vs re-record the hash) and the step name is how an operator knows which question they are being asked — worth more than the 0.06s it re-runs. Rationale is in the comment at the step, not only here.")
//! @yah:verify("cargo test -p xtask --tests --locked — exit 0, whole suite green, run BEFORE widening check.toml's step to it (it was queued ~30 min behind ~14 concurrent peer cargo builds on the shared target dir, which is why the narrow step was written first and then replaced once the evidence landed).")
//! @yah:handoff("EXTRA WORK, beyond the spike's brief and deliberately loud. (1) NEW xtask/tests/fleet_build_placement.rs — two tests that run the REAL chain (yah_qed::platform::build_worker_mesh_tags -> WorkloadSpec::for_forge -> CloudConfig::admit_workload) against the REAL .yah/infra/machines/ inventory, pinning where each (arch, os) build actually lands and asserting the prod-quorum overlap. This is what turned the finding above from reasoning into a fact; both passed on the FIRST run, matching the predicted table exactly. Shaped as a pin, not a complaint, so it is GREEN today — R605-T7 updates it as its acceptance gate. (2) .yah/qed/check.toml gains an `xtask-tests` step that runs the whole xtask suite — see the two gotchas below for why that is a wider fix than it sounds.")
//! @yah:verify("CONFIRMED POST-EDIT: `cargo test -p xtask --tests --locked` re-run after check.toml was widened — exit 0, 79 tests across 12 binaries, 0 failed, 1.66s of actual test time. That is the byte-identical argv the new `xtask-tests` step runs, so the step is proven rather than assumed. Cost is a rounding error next to the shared step-1 compile.")
//! @yah:handoff("RETRACTION, and it matters because it was in this ticket's own handoff: I reported us-west-003 as 'dark, refuses ssh/22 and yubaba/7443 in ~7 ms'. WRONG. The camp Mac is on 192.168.22.84/22 (gateway 192.168.20.1) with NO route to 192.168.10.0/24 — those RSTs came from the default gateway rejecting an off-subnet destination, not from a host at .32. Nothing was learned about 003. Operator flagged it: the camp reaches nodes over the MESH only, and a LAN IP is emergency break-glass, never an official route. R605-B9 was filed on that bad diagnosis and has been ARCHIVED and replaced by R605-B11.")
//! @yah:handoff("CORRECTED PICTURE, mesh only (`tailscale status` + yubaba /identity, 2026-08-19): us-west-014 (100.64.0.6) and us-west-015 (100.64.0.7) are UP, both answering /identity 200 over DERP — so the LAN site is NOT offline. us-west-002 (100.64.0.4) and us-west-013 (100.64.0.8) are genuinely offline, last seen 2d, tx>0 rx=0 (R605-B11). us-west-003 and us-west-011 have NO mesh_ipv4 at all and are unreachable from this camp BY CONSTRUCTION — not a fault to repair, a route never declared (R605-T10). The x86 conclusion is unchanged and if anything firmer: no dedicated x86 build worker is reachable, so us-east-001 is the only x86 node that answers.")
//! @yah:handoff("SECOND FINDING, same mechanism, opposite failure — surfaced only because the operator questioned the LAN probes. aarch64/linux build offloads elect us-west-011, which has NO mesh_ipv4 and whose only address is [connect].yubaba = http://192.168.10.11:7443. us-west-014 is the same arch, same tag:build-worker, mesh-joined at 100.64.0.6, and verified answering /identity 200 — and it sorts AFTER 011 in file-name order, so it never wins. x86 elects a node too important to build on; arm elects one that cannot be spoken to. Root cause on both: admit_workload is a pure function of the DECLARED inventory and has no opinion about whether the elected node answers. Filed as R605-T10; xtask/tests/fleet_build_placement.rs now documents both instances and says explicitly why it must NOT be taught to ping.")
//! @yah:gotcha("METHOD TRAP worth more than the finding: an off-subnet TCP connect from this camp to 192.168.10.x returns a fast `connection refused` from the DEFAULT GATEWAY, which is indistinguishable at a glance from a live host refusing the port. The tell is a ~7 ms refusal on EVERY port, including ones nothing listens on. I read it as evidence about the box and it was evidence about the router. Probe fleet nodes over the mesh (tailscale status / 100.64.x.y) — a LAN literal in [connect] is emergency break-glass, never a route this camp has.")
//! @yah:handoff("THIRD CORRECTION, operator-supplied: mesh membership and sovereign group are DIFFERENT AXES and I had them tangled. Mesh = ONE for the entire fleet, every node, regardless of group — no design question, 003 and 011 simply have not enrolled (R605-T10). Sovereign group = blast radius, and there are two declared: prod (us-west-001/us-south-001/us-east-001) and dev (us-west-011/us-west-013/us-west-014), with NO stamp on us-west-002/003/015. So us-west-011 being a different sovereign from 001 is already correct and recorded.")
//! @yah:handoff("AND IT SURFACED A REAL MODEL GAP (R605-F12). Operator's model is that us-west-003 is a NON-VOTING member of the 001-based prod group. The config cannot express that: sovereign_group is a single Option<String> and judge_join permits a join IFF both sides declare the same non-None group — so stamping 003 prod would make it quorum-ELIGIBLE, and its ABSENT stamp is currently the only thing refusing it into the prod raft, despite its own header insisting it must never hold a raft node id. judge_join's doc comment asserts the opposite model outright ('us-west-002/003/015 are deliberately not raft members'), so code and operator disagree about what 003 IS. A guarantee resting on a field nobody wrote is the same W305 failure that produced R742-T4.")
//! @yah:handoff("MY ERROR, corrected on R605-T7: I had instructed 'do NOT set sovereign_group — a build box must never become a prod quorum member', which conflated group membership with quorum eligibility. T7 now defers the field to R605-F12 instead of guessing it.")
//!
//! @yah:relay(R875, "Stop button on supervised services (mesofact-dev) silently fails to stop — kamaji respawns per RestartPolicy::Always")
//! @yah:status(review)
//! @yah:at(2026-09-09T02:06:27Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:gotcha("Reproduced 2026-09-08 on yah-marketing's mesofact-dev (port 4321): the running instance had PPID 1 (orphaned — its own supervisor was already gone), so a bare `kill <pid>` stuck with no respawn. That does NOT show the bug is benign — it shows supervision had already lapsed in that instance. RestartPolicy::Always in this file treats every child exit (crash or clean SIGTERM) as respawn-worthy unless the stop goes through kamaji's own Ctrl/teardown channel; a bare process kill or a UI Stop button that doesn't use that channel will appear to do nothing while kamaji quietly relaunches the child after ALWAYS_RESTART_DELAY.")
//! @yah:gotcha("TITLE AND PREMISE CORRECTED, verified by reading. This relay says \"kamaji respawns per RestartPolicy::Always\". It does not, for this workload: native_spec sets restart_policy: RestartPolicy::Never (oss/yubaba/crates/cloud/src/reconciler/native_support.rs:97), deliberately and with its own test (native_spec_carries_the_identity_only_digest asserts it) — the caller owns readiness, so a binary that cannot start must surface as a failed reconcile rather than a silent re-exec loop. Nothing was respawning mesofact-dev. The @yah:assumes on this relay was honest that the Stop handler had not been read; reading it found a different bug (R875-B1).")
//! @yah:gotcha("The Stop handler is mirror_run_down (app/yah/desktop/src/mirror_run.rs), NOT GeneralSection.tsx or TabStrip.tsx — the dev tier is a Run-tab mirror cell, not a Service-category plugin instance. It does route through the reconciler's own lifecycle contract (RunningWorkload::shutdown), so the original next-step's suspicion of a bare process kill was also wrong. The handle it was calling shutdown() on simply had nothing attached to it.")
//! @yah:handoff("Three children landed and in review: B1 (adopted mesofact-dev gets a real teardown + a log tail), B2 (workload.start/stop off the 500ms RPC floor), T3 (a restart verb + ⟳ button). Green with no input skew on the final runs: yah-cloud lib 17/17 on the touched modules, yah-agent-tools daemon_client 36/36, cargo check -p desktop --lib zero errors, bun typecheck clean, MirrorPanel+mirrorTier 40/40.")
//! @yah:verify("MANUAL, and the only thing left — needs a desktop rebuild+install (`yah qed run yah-desktop-install`, or Settings -> build -> \"Install & restart\"). None of this reaches the operator until then, because the running app carries the binary it was built with.")
//!
//! @yah:relay(R885, "Native workloads run unbounded: wire kamaji cgroup + sandbox boundary onto the live deploy path")
//! @yah:at(2026-09-10T07:28:48Z)
//! @arch:see(.yah/docs/working/W344-native-workloads-run-unbounded.md)
//!
//! @yah:ticket(R885-B1, "Wire CgroupV2 + spawn_native onto NativeRuntime, resolving the delegated cgroup root at runtime")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:at(2026-09-11T07:07:44Z)
//! @yah:phase(P1)
//! @yah:parent(R885)
//! @yah:next("Tier: Warrior. This is the only ticket in R885 with a live blast radius: it changes what already-running fleet workloads do. Everything else under R885 is additive and should land behind it.")
//! @yah:next("THE CODE ALREADY EXISTS AND IS GOOD. kamaji-bin/src/cgroup.rs (CgroupV2::create_workload :93, attach_pid :138, ensure_root :76) and kamaji-bin/src/native.rs (spawn :284) are complete and unit-tested. The parent-attaches / child-blocks-on-a-sync-pipe handshake at native.rs:364-372 (child side :475-480) is race-free — the child does nothing but a blocking read(2) until attach completes, then landlock + cap-drop + setresuid + execvpe. Do NOT rewrite it toward CLONE_INTO_CGROUP; just call it.")
//! @yah:next("WHAT ACTUALLY RUNS TODAY is kamaji::native::NativeRuntime — tokio::process::Command::new at kamaji/src/native.rs:434, .spawn() at :464. No cgroup, no landlock, no capability drop. Its module header at :6 says the R406 layers arrive when the backend graduates to fleet hosts; it graduated and they did not follow. server.rs:2326 states the consequence in as many words.")
//! @yah:next("THE PATH BUG THAT MUST LAND WITH THE WIRING, not after. kamaji.service sets Slice=yubaba.slice (:81), Delegate=yes (:85), DelegateSubgroup=native (:86), which puts kamaji at /yubaba.slice/kamaji.service/native and delegates THAT subtree. cgroup.rs DEFAULT_SLICE_ROOT (:31) plus the pushed \"native\" (:56-60) targets /sys/fs/cgroup/yubaba.slice/native — a SIBLING of kamaji.service, inside the slice but outside the delegation. Nothing reads /proc/self/cgroup (grep returns zero). Wire it as-is and kamaji writes into territory systemd owns and reconciles. Fix: resolve the delegated root from /proc/self/cgroup at startup instead of assuming a path.")
//! @yah:next("Two smaller corrections in the same unit while you are there: the comment at kamaji.service:83-84 has the delegation direction backwards (Delegate=yes delegates FROM systemd TO the service), and ReadWritePaths=/sys/fs/cgroup (:122) grants the whole cgroupfs where the delegated subtree would do.")
//! @yah:verify("Acceptance names a CALL SITE, not a test count: rg -n \"spawn_native|CgroupV2|create_workload\" --type rust -g \"!oss/kamaji/crates/kamaji-bin/src/cgroup.rs\" must return a live runtime call site in the deploy path, not only the lib.rs:64/:71 re-exports.")
//! @yah:verify("On a Linux fleet node with a deployed native workload: systemctl show kamaji.service -p ControlGroup; cat /proc/<workload-pid>/cgroup — the workload must sit in its OWN leaf INSIDE the delegated subtree, not in 0::/yubaba.slice/kamaji.service/native (which is what us-west-001 shows today, recorded at oss/yubaba/crates/cloud/src/config.rs:292).")
//! @yah:verify("cat /sys/fs/cgroup/<that-leaf>/memory.max — a real number, not the inherited parent value.")
//! @yah:gotcha("R406 children T4 and T5 both reached review having never been reachable from a running binary, and sat there ~2 months (cgroup.rs last changed 2026-07-17, kamaji-bin/src/native.rs 2026-07-12, neither dirty). The tests passed the whole time. That is why this ticket must NOT be accepted on a test count.")
//! @yah:handoff("LANDED AND PROVEN ON HARDWARE. Native workloads are confined to per-workload cgroup v2 leaves inside the subtree systemd actually delegates. Measured on us-east-001 2026-09-11 by @Ashguard:coffee (session:91597c1e), who shipped this tree to that node mid-session: ControlGroup=/yubaba.slice/kamaji.service; four workload pids each in 0::/yubaba.slice/kamaji.service/<ident> (yah-marketing, noisetable, yah-marketing-feed, yah-marketing-revalidate); each leaf memory.max=134217728 and cpu.max=25600 100000 — real values, not the inherited `max`. Every acceptance reading in the ticket is satisfied on a live node, not merely by a test.")
//! @yah:handoff("THE TRACED CALL CHAIN, which the ticket required be stated explicitly. (1) yubaba sends YubabaToKamaji::Deploy{Workload::Container} over the UDS. (2) kamaji-bin/src/server.rs:1783 deploy_container -> :2051 deploy_container_inner -> :2143 deploy_container_backend. (3) :2150 `if spec.wants_native_exec()` -> :2298 deploy_native_exec. (4) :2316 `native.deploy_workload(spec, &mesh)` on ctx.native, an Arc<kamaji::native::NativeRuntime> built at kamaji-bin/src/main.rs:686 from --native-exec-dir (and at server.rs:612 for the inlined shape). (5) kamaji/src/native.rs `impl Kamaji for NativeRuntime::deploy_workload` -> `self.cgroup.create_workload(&ident.0, &spec.resources)` -> kamaji/src/cgroup.rs CgroupV2::create_workload: mkdir the leaf, write cpu.max + memory.max. (6) spawn_child(..., cgroup.as_ref()) -> cmd.as_std_mut().pre_exec(hook) -> cmd.spawn(). The hook opens <leaf>/cgroup.procs and writes getpid(). (7) teardown_workload reaps the child, then destroy_workload rmdirs the leaf.")
//! @yah:handoff("THE DRIVER HAD TO MOVE CRATES, and this is the structural finding the ticket did not anticipate. kamaji-bin DEPENDS ON kamaji, so a driver homed in kamaji-bin was permanently unreachable from kamaji::native::NativeRuntime — the crate graph, not an oversight, is why R406-T4/T5 could never have been wired where they sat. oss/kamaji/crates/kamaji-bin/src/cgroup.rs is DELETED; the driver is now oss/kamaji/crates/kamaji/src/cgroup.rs, unconditional (pure std::fs, no new deps). kamaji-bin re-exports it (`pub use kamaji::cgroup;` + the named re-export in lib.rs) so kamaji_bin::CgroupV2 still resolves. `kamaji` became a NON-OPTIONAL dep of kamaji-bin: every `dep:kamaji` came out of the feature list, the `kamaji/<feature>` entries stayed. With default-features off that links nothing kamaji-bin did not already link.")
//! @yah:handoff("THE PATH RESOLUTION, which is the half with the live blast radius. CgroupV2::delegated() reads /proc/self/cgroup, takes the `0::` (unified) line, and joins it onto /sys/fs/cgroup. If the basename is the DELEGATE_SUBGROUP (`native`) the delegated ROOT is the PARENT — so leaves are SIBLINGS of native/, not children. That is not a guess: DelegateSubgroup= exists to satisfy cgroup v2's no-internal-process rule (a cgroup holding member processes may not enable controllers for its children), so kamaji's threads live in native/ precisely to leave kamaji.service/ process-free and able to carry cpu+memory in cgroup.subtree_control. Confirmed live: the controllers enabled fine and the leaves got real numbers. DEFAULT_SLICE_ROOT is retained but demoted to a documented dev/non-systemd fallback and is no longer used to build the production path — its doc comment now says so explicitly.")
//! @yah:handoff("SELF-ATTACH, NOT PARENT-ATTACH, and this is the one design call I made against the brief's letter — flagging it loudly. The brief said to call kamaji-bin's `spawn` (fork + parent-attaches + sync-pipe + execvpe). I did not, and kamaji-bin/src/native.rs is still dead. Reason: that function returns a raw NativeChild{pid,pidfd,stdout/stderr pipe fds}, while the LIVE path is built end-to-end on tokio::process::Child — supervise()'s Exit type, the spec-retaining restart loop, stop_child's SIGTERM/grace/SIGKILL, drain_reaper's SIGQUIT graceful-upgrade path, the <state_dir>/<ident>/{stdout,stderr}.log capture and stream_logs that replays it. Swapping the spawner rewrites all of that on the exact path the ticket exists to make SAFER, on a Mac, untestably. Instead the boundary operations moved into the live path's OWN post-fork/pre-exec window: cmd.as_std_mut().pre_exec(...), the identical kernel window pre_exec_in_child occupied (kamaji/src/jit.rs already uses the same idiom). The child writes its own pid to <leaf>/cgroup.procs before exec, so there is NO window in which workload code runs outside the boundary — and no sync pipe is needed, because nothing runs between fork and the write. The hook is allocation-free (CString built pre-fork, itoa into a stack buffer, open/write/close only).")
//! @yah:handoff("WHAT I DELIBERATELY DID NOT DO, grounded in the design doc rather than in scope-trimming: landlock and the capability drop. W344 §'Audit residue worth keeping' says it outright — 'Capability policy and resource policy are separate axes and piece 1 below only closes the second', naming ambient capability inheritance as the live instance. Two independent live reasons confirm it: (a) kamaji.service's own comment documents that native workloads inherit AmbientCapabilities and that this is how a sub-1024 bind works, and R858-T5's cleanup note records that whether passway-demux (TLS_PORT=443) is native-exec is UNRESOLVED — a blanket drop could take a door down; (b) derive_landlock builds its allow-list from spec.volumes Bind mounts only, and a native forge workload writes to /var/lib/yah/qed which appears on no spec as a volume. FILED AS R885-B9 with both refusals, the measurement that must come first, and the mechanical note that the hook to extend is the pre_exec one this ticket added.")
//! @yah:handoff("THE TWO UNIT-FILE CORRECTIONS (app/yah/cli/resources/kamaji.service). (1) The backwards delegation comment is rewritten: Delegate=yes delegates FROM systemd TO the service, and the replacement explains what DelegateSubgroup= is actually for (the no-internal-process rule) with an ASCII diagram of where leaves land, because that was the fact whose absence caused the original bug. (2) ReadWritePaths=/sys/fs/cgroup narrowed to /sys/fs/cgroup/yubaba.slice. NOT narrowed the last level to .../kamaji.service: under ProtectSystem=strict a ReadWritePaths entry that does not exist fails the whole mount namespace with 226/NAMESPACE — the trap this same file already records twice for yah/qed — and I could not establish from a Mac whether the service cgroup is materialised before the namespace is built. The slice is created when the first unit in it starts, so it is reliably present. Narrowing the last level is a safe follow-up for someone who can watch a node reboot.")
//! @yah:handoff("DISCOVERED AND FIXED, beyond the three things the ticket named: (a) the crate-boundary blocker above — the reason this had never been wirable, not merely unwired; (b) kamaji/src/native.rs's module header still claimed the R406 layers 'land when this backend graduates to fleet hosts', a statement W344 had already disproved — rewritten to describe what the module now does and to name R885-B9 for what it still does not; (c) graceful_upgrade_workload needed a decision the brief did not raise — the replacement joins the OUTGOING generation's leaf rather than a fresh one, because during a pingora handoff both processes serve the same listener and are one workload with one ceiling. Per-generation leaves are R885-B4 and need that ticket's teardown ordering; a comment at the site says so.")
//! @yah:handoff("THE `native` LEAF STILL EXISTS AND IS NOT THE BUG — write this down before anyone greps for it. @Ashguard:coffee's live reading found a `native` leaf alongside the four workload leaves, holding kamaji ITSELF (pid 650851, memory.max=max). That is correct: DelegateSubgroup=native put kamaji there at unit start. But `.../kamaji.service/native` is ALSO the exact string W344 records as the symptom of the pre-B1 bug, so the path alone proves nothing. THE DISCRIMINATOR IS WHOSE PID IS IN IT: a WORKLOAD pid there is the bug; the KAMAJI pid there with workloads in ident-named siblings is the fix working. Documented at both sites (cgroup.rs module doc, kamaji.service comment). I declined to rename the subgroup for clarity — the name lives in the unit file (shipped by provisioning) and in DELEGATE_SUBGROUP (shipped with the binary), and those upgrade separately; a node taking a new binary before a new unit would resolve its root to its own process-bearing cgroup, hit EBUSY, and fall back to UNBOUNDED with only a warn!. A naming nicety is not worth a silent un-confinement during a roll. The reasoning is in the unit file so the next person does not redo it.")
//! @yah:gotcha("THE FAILURE MODE IS A FALLBACK, AND IT IS DELIBERATE — know it before reading a green node as proof. If /proc/self/cgroup is unreadable, has no `0::` line (cgroup v1), reads `0::/` (cgroup namespace), or ensure_root fails (EBUSY / EPERM), NativeRuntime::new logs a warn! and sets cgroup=None, and every native workload then forks UNBOUNDED exactly as before R885-B1. I chose that over refusing the deploy because the mesh coordinator is itself a native workload and a kamaji that refused to start it on a host whose cgroup layout it did not recognise would trade an unbounded headscale for no headscale. THE COST: 'workloads are confined' is now a per-node runtime fact, not a build-time one. The only positive evidence is the startup line `native backend: confining workloads to cgroup leaves under the delegated root root=<path>`; its absence, or the matching warn!, means that node is unconfined. Grep the journal for it on any node you are reasoning about.")
//! @yah:gotcha("MY ReadWritePaths NARROWING IS UNEXERCISED ON HARDWARE. us-east-001 took the new BINARIES on 2026-09-11 but still carries the old wide `ReadWritePaths=/sys/fs/cgroup` — confirmed by @Ashguard:coffee, with `journalctl -u kamaji -b | grep -c 226/NAMESPACE` = 0. Wide permits everything narrow does, so nothing is broken and the live acceptance above is unaffected. But the FIRST node to re-provision or re-install this unit file is the first real test of the narrowing. Watch that node's next kamaji restart for 226/NAMESPACE, and if it appears, the fix is to widen this one line back to /sys/fs/cgroup while keeping everything else.")
//! @yah:gotcha("cpu.max IS NOW A HARD QUOTA ON THE LIVE PATH, and W344 Finding 5 already calls that a semantic bug. ResourceLimits documents cpu_millis as a REQUEST, the containerd/docker backends render it as a relative weight, and this driver renders it as `cpu.max` — a ceiling. Wiring the driver therefore ships the throttle: us-east-001's four workloads now sit at cpu.max=25600 100000, i.e. hard-capped at 0.256 of a core even on an idle node. I did NOT fix it here because R885-B5 owns exactly that split (request -> cpu.weight, optional annotation-carried limit -> cpu.max) and re-deciding it inside the wiring ticket would have made two tickets disagree. But B5 is no longer additive-and-optional the way the relay's ordering note implies: until it lands, every native workload on an upgraded node is throttled where before it could burst. Raise its priority accordingly.")
//! @yah:gotcha("A REDEPLOY REUSES THE LEAF, and R885-B4's race is now reachable rather than theoretical. deploy_workload tears the predecessor down first (which rmdirs the leaf) and then mkdirs the same path, so a rolling replacement of the same ident races teardown's rmdir against the new mkdir — exactly the failure R885-B4 describes. destroy_workload's error is logged and swallowed (teardown's contract is idempotent success; an EBUSY from a double-forked descendant has no recovery path until B4 lands cgroup.kill), so the visible symptom would be a leaked empty leaf or a warn! naming R885-B4, not a failed deploy. B4 was already depends_on(R885-B1); this is what it is now unblocked to fix.")
//! @yah:assumes("I did NOT verify that /sys/fs/cgroup/yubaba.slice/kamaji.service exists at the moment systemd builds kamaji's mount namespace. That unverified point is the ONLY reason ReadWritePaths was narrowed to the slice rather than to the exact delegated root. Someone who can watch a node reboot can settle it in one restart and take the last level.")
//! @yah:assumes("The child-side cgroup.procs write is unverified as CODE on a Linux host by me — I cross-compiled it (cargo zigbuild --target x86_64-unknown-linux-gnu, clean) but could not execute it here. It is verified by OUTCOME instead, which is stronger: @Ashguard:coffee's reading shows four real workload pids sitting in their own leaves on us-east-001, which only happens if that write ran.")
//! @yah:assumes("I did NOT measure passway-demux's exec substrate, so 'CAP_NET_BIND_SERVICE may still be load-bearing for a native workload' is unresolved in both directions. It did not block this ticket (capabilities are R885-B9's axis) but it blocks B9, and that is recorded there.")
//! @yah:cleanup("kamaji-bin/src/native.rs (SandboxPlan + the fork/landlock/cap-drop/execvpe spawner) is STILL DEAD CODE and is now the only dead half of the R406 boundary layer. It is deliberately left in place as R885-B9's landing site rather than deleted. If B9 resolves to 'derive the capability set in the pre_exec hook' as suggested, that file should be deleted in the same pass and its useful parts (drop_all_caps, install_landlock, parse_user, derive_landlock) moved into kamaji::sandbox — do not leave a second fork path behind, since having one is precisely what let this rot for two months.")
//! @yah:cleanup("Pre-existing, untouched, not mine: clippy's `too many arguments (8/7)` on jit.rs:312 supervise_on_demand, and kamaji-bin's three standing dead-code warnings (PidfdReaperHandle.events_tx, control_sock_from_spec, free_port), all of which are already named as pre-existing in other tickets' verify notes.")
//! @yah:verify("LIVE, us-east-001, 2026-09-11, read by @Ashguard:coffee (session:91597c1e) — the acceptance the ticket actually named. `systemctl show kamaji.service -p ControlGroup` = /yubaba.slice/kamaji.service. Workload pids in their OWN ident-named leaves: 650860 yah-marketing, 650861 noisetable, 650864 yah-marketing-feed, each `0::/yubaba.slice/kamaji.service/<ident>`. Per-leaf `memory.max=134217728` and `cpu.max=25600 100000` — real values, not the inherited `max`. Startup journal carries `native backend: confining workloads to cgroup leaves under the delegated root root=/sys/fs/cgroup/yubaba.slice/kamaji.service`. Headroom baseline for R885-F3: worst case yah-marketing peak=31277056 (29.8M) against 128M, every memory.events counter zero.")
//! @yah:verify("CALL SITE, the acceptance form the ticket insisted on: `rg -n \"spawn_native|CgroupV2|create_workload\" --type rust` now returns a live runtime call site — oss/kamaji/crates/kamaji/src/native.rs, `cg.create_workload(&ident.0, &spec.resources)` inside `impl Kamaji for NativeRuntime::deploy_workload` — not only the kamaji-bin lib.rs re-exports. Full chain from the UDS Deploy down to the spawn is traced step by step in the handoff above.")
//! @yah:verify("cargo test -p kamaji --features native-integration --lib: 116 pass / 0 fail (baseline 98 — +10 cgroup tests moved in from kamaji-bin, +6 new root-resolution tests, +2 new call-site tests).")
//! @yah:verify("cargo test -p kamaji-bin --features native-exec: 237 pass / 0 fail (baseline 247 — the 10 cgroup tests moved out to kamaji; no test was lost).")
//! @yah:verify("Two NEW tests pin the call site itself, which is the thing R406-T4/T5 had no test for: native::tests::deploying_a_workload_mints_a_cgroup_leaf_carrying_its_limits drives the real deploy_workload against a tempdir cgroup root and asserts the leaf plus its memory.max/cpu.max bytes, then that teardown reaps it; native::tests::a_host_without_a_delegated_subtree_still_deploys pins the degrade path (and asserts its own premise, so it cannot pass vacuously). Six more pin the resolution: the `0::` line is the one read, a v1-only host yields nothing, `/` yields nothing, the delegate subgroup resolves to the PARENT (with an explicit assert_ne against the pre-B1 sibling path), no subgroup resolves to self, and a leaf may not collide with kamaji's own cgroup.")
//! @yah:verify("Cross-compile, since the Linux-only pre_exec hook cannot run on this Mac: cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu — Finished, exit 0. So the Linux path is COMPILED, not merely reviewed by reading; and it is proven at runtime by the live pid readings above.")
//! @yah:verify("Host-target builds clean: cargo check -p kamaji-bin --all-targets and the same with containerd-integration,native-exec,bundle-serving,docker-integration,microvm,tenant-passway — exit 0, only the three pre-existing dead-code warnings. cargo check -p camp-identity (the root-workspace crate that depends on kamaji-bin, so the non-optional dep change is covered) — exit 0. cargo clippy -p kamaji --features native-integration --all-targets — one warning, pre-existing, jit.rs:312.")
//! @yah:gotcha("Follow-up fix (courier, 2026-09-11): the red `supervisor_unit::tests::kamaji_unit_grants_every_host_path_kamaji_writes` was NOT a template-comment grep trip — the dispatch brief's diagnosis (supervisor_unit.rs:81's launchd @@TOKEN@@ gotcha) does not apply here. `writable_paths` skips any line starting with `#` (supervisor_unit.rs:1164), so a comment in kamaji.service cannot inject or shadow a path, and the rootless unit is built by `render_user_kamaji` from its own template rather than by stripping the canonical one — so R885-B1's new Delegate=/ASCII-diagram comments (which do contain the literals `yubaba.slice`, `Delegate=`, `ProtectSystem=strict`) are unreachable from `user_scope_strips_slice_and_privileged_directives`'s whole-contents grep. Checked; no comment in that file trips any assertion.")
//! @yah:gotcha("Actual cause: this ticket's own intentional narrowing of `ReadWritePaths=` on app/yah/cli/resources/kamaji.service:190, from `/sys/fs/cgroup` to `/sys/fs/cgroup/yubaba.slice`. The test's path table still asserted the BROAD path, and `is_writable` only walks upward (a grant that is a DESCENDANT of the asserted path never matches), so the narrowing made a correct unit fail a stale assertion. Fixed by pointing the assertion at the path kamaji actually writes — `/sys/fs/cgroup/yubaba.slice/kamaji.service`, the delegated root that `CgroupV2::delegated` (oss/kamaji/crates/kamaji/src/cgroup.rs:381) resolves off /proc/self/cgroup — which still goes RED if the grant is dropped and additionally catches a narrowing that overshoots past what kamaji writes. The `ReadWritePaths=` line itself was NOT touched; the narrowing stands.")
//! @yah:gotcha("Louder-failure hardening, since a narrowed grant and an absent grant read IDENTICALLY in the old `Writable today: [...]` dump and cost a triage pass each time: new `narrowing_hint(unit, path)` helper (supervisor_unit.rs, tests module) appends \"NARROWED, not missing: the unit grants [...], which is INSIDE <path>\" whenever some grant sits below the asserted path. Wired into BOTH grant tests (kamaji and yubaba). Covered in `grant_checks_actually_fail_when_the_grant_is_removed`, which now also asserts the hint stays EMPTY for a genuinely deleted grant, so the two cases cannot be confused. Next person who narrows a ReadWritePaths gets told which deeper path to assert instead of bisecting.")
//!
//! @yah:ticket(R885-B12, "kamaji constructs TWO native backends and ONE jit backend per node — the reverse of what R885-B10 recorded, and it pairs with a 5s duplicate-workload-id warn")
//! @yah:status(review)
//! @yah:at(2026-09-11T21:28:26Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R885)
//! @yah:severity(P2)
//! @yah:next("FOUND BY R885's LIVE ACCEPTANCE ON us-east-001, not by reading code — measured 2026-09-11 at 21:14:41Z on kamaji 0.8.39-h1, pid 661039, immediately after the R885 hot ship. The journal carries THREE \"confining workloads to cgroup leaves under the delegated root\" lines at startup, and the backend label splits them NATIVE x2, JIT x1: two lines read `native backend:` (21:14:41.042251 and .043144) and one reads `jit backend:` (.043203), all three from module kamaji::native with root=/sys/fs/cgroup/yubaba.slice/kamaji.service. Each is paired with its own `pids controller enabled — workloads get a pids.max ceiling` twin, so THREE runtimes are genuinely constructed, not two logging twice.")
//! @yah:next("THIS CONTRADICTS R885-B10's ANNOTATION, which is the reason to look rather than shrug. B10's gotcha states \"TWO JitRuntimes EXIST PER NODE AND BOTH LOG THE SAME PREFIX — kamaji-bin builds a separate JitRuntime for BundleBackend::jit (server.rs:613) and for tenant_passway (main.rs:717 / server.rs:981), by design\", and tells the reader to expect the jit sentence twice. The live node shows the opposite multiplicity. Two readings, and they have different fixes: (a) the tenant_passway JitRuntime is NOT constructed on this node (config-conditional?) AND something constructs NativeRuntime twice — in which case B10's \"by design\" note is right about intent and wrong about what ships; or (b) the `backend` label argument is passed wrongly at one of the three construction sites, in which case the runtimes are as B10 says and only the log lies. Settle which by reading the three construction sites against the label each passes to resolve_cgroup_root, THEN fix either the construction or the annotation — do not fix the annotation to match the log without establishing which one is wrong.")
//! @yah:next("THE PAIRING THAT MAKES THIS WORTH A TICKET RATHER THAN A NOTE: kamaji on us-east-001 logs `duplicate workload id across backends … id=yah-marketing kept_state=Running dropped_state=Pending` every ~5 seconds, indefinitely. \"Two native backends constructed\" and \"duplicate workload id ACROSS BACKENDS\" is a suggestive coincidence and the first hypothesis to test — if a second NativeRuntime is supervising the same workload set, a permanent Running-vs-Pending disagreement between two backends is exactly the shape you would expect. BE HONEST ABOUT WHAT IS ESTABLISHED: the warn is PRE-EXISTING, not caused by the R885 ship — it fired at the same cadence under the old pid 650851 before activation and now carries the new pid 661048 — so this is not a regression and the causal link to the double construction is a HYPOTHESIS, not a finding. Independently observed by @Ashguard:coffee while working R876. Related and possibly the same root: the service-record probe returns THREE records for FOUR supervised workloads (noisetable, noisetable-account, yah-marketing have records; the yah-marketing-revalidate and yah-marketing-feed tiers have none), identically before and after the restart — also pre-existing, also unexplained.")
//! @yah:handoff("SETTLED: READING (a), BUT THE CONSTRUCTION IS CORRECT AND THE ANNOTATION WAS WRONG — there is no double-construction bug. Read all four sites against the label each passes to native::resolve_cgroup_root. (1) kamaji-bin/src/main.rs:686 ctx.with_native_exec(NativeRuntime::new(dir)) under `#[cfg(feature = \"native-exec\")]` + `if let Some(dir) = &args.native_exec_dir` -> label \"native\". (2) kamaji-bin/src/server.rs:635, INSIDE BundleBackend::new, `native: Arc::new(NativeRuntime::new(state_dir.clone()))` -> label \"native\". (3) server.rs:636, the very next line of the same struct literal, `jit: Arc::new(JitRuntime::new(state_dir.clone()))` -> label \"jit\". (4) main.rs:717 ctx.with_tenant_passway(JitRuntime::new(dir)) under `#[cfg(feature = \"tenant-passway\")]` + `if let Some(dir) = &args.tenant_passway_dir` -> label \"jit\". NO LABEL IS PASSED WRONGLY, so reading (b) is out: every one of the three live lines is truthful. Site (4) is not constructed on us-east-001 because app/yah/cli/resources/kamaji.service ExecStart (:78-81) passes only --socket, --containerd-socket and --native-exec-dir; the unit's own comment block (:55-61) says every other backend is attached by an `Environment=` drop-in (KAMAJI_BUNDLE_CACHE_DIR is what attaches the bundle backend on that node) and no tenant-passway variable is set. So native x2 + jit x1 is EXACTLY the designed census for that configuration. R885-B10's gotcha was wrong twice over: it counted JitRuntime sites and missed the NativeRuntime built on the line immediately above the jit one inside BundleBackend::new, and it assumed site (4) ships everywhere when it is opt-in. Corrected in source (board.update on R885-B10; the old \"TWO JitRuntimes EXIST PER NODE\" entry is removed, not merely annotated).")
//! @yah:handoff("THE HYPOTHESIS IS DISCONFIRMED, AND IT WAS DISCONFIRMED BY EVIDENCE RATHER THAN BY THE ABSENCE OF ANY. The ~5s `duplicate workload id across backends ... id=yah-marketing kept_state=Running dropped_state=Pending` is NOT two NativeRuntimes disagreeing. It is R599-B11's already-documented condition, and the doc comment on the function that emits it names this exact workload: kamaji-bin/src/server.rs:3829-3844 `dedupe_workload_entries` says \"on the ingress testbed a stale containerd container left over from the pre-bundle nginx stand-in shared the `yah-marketing` id with the live native bundle workload, and containerd reports a container with no task as `Pending`/`pid: None`\". Running-with-a-pid beating Pending-with-none is that sentence exactly. Two further reasons the two-native-supervisors story cannot hold: (i) the List handler (server.rs:1465-1595) merges ctx.native, containerd, bundle.native, bundle.jit, tenant_passway and docker as SEPARATE sources, so a duplicate needs two sources holding the id, and (ii) the two NativeRuntimes cannot both hold yah-marketing — ctx.native only ever receives a workload through deploy_native_exec, gated on `spec.wants_native_exec()` for a Container spec (server.rs:2150 -> :2298), while yah-marketing is a MesofactStatic carrying a serve_bundle and is routed to BundleBackend (deploy_mesofact_bundle -> deploy_bundle_keepalive). Each runtime's map is in-memory and populated only by its own deploys. So the ticket's suggestive pairing is a coincidence: the remaining suspect for that warn is a stale containerd record on us-east-001, which is an operator reap on that node and belongs to R599-B11, not here. That claim rests on reading the code; I did not touch the node, so the stale-container half is unverified ON THE NODE by design of this ticket's constraints.")
//! @yah:handoff("WHAT LANDED — an observability fix, not a construction fix, because the construction was right. THE DEFECT THAT WAS REAL: `backend` alone does not identify an instance, so two truthful `native backend: ...` lines were indistinguishable, and that ambiguity is the entire reason this was filed as a suspected bug. (1) oss/kamaji/crates/kamaji/src/native.rs — `resolve_cgroup_root` now takes `(backend: &str, state_dir: &Path)` and every one of its five log lines carries a `state_dir=` field: the two degrade warns, the confinement info, and both pids outcomes. R885-B1's grep string is untouched, byte for byte — `state_dir` is a structured FIELD, the message is unchanged, so `native backend: confining workloads to cgroup leaves under the delegated root` still matches. Doc comment states why the pair, not the label, is the identity. (2) native.rs NativeRuntime::new and (3) jit.rs JitRuntime::new pass `&state_dir` (struct literal reordered so the borrow precedes the move; no behaviour change). (4) jit.rs gained `pub fn state_dir(&self) -> &Path`, the counterpart of NativeRuntime::exec_dir, so the census is assertable. On a fleet node the three lines now read state_dir=/var/lib/yah/kamaji/native, and the bundle state dir twice. NOTE THE ONE NON-UNIQUE AXIS: BundleBackend hands ONE state_dir to both of its runtimes, so (label, state_dir) is unique but state_dir alone is not — the test asserts both halves of that.")
//! @yah:handoff("THE CENSUS IS PINNED BY A TEST, per the ticket's \"if a test would pin the multiplicity, add it\". `server::tests::bundle_serving::the_cgroup_resolving_runtime_census_is_two_native_and_one_jit` (oss/kamaji/crates/kamaji-bin/src/server.rs, in mod bundle_serving, additionally gated `#[cfg(feature = \"native-exec\")]`). It builds a ServerCtx the way the fleet builds one — with_native_exec over one tempdir, with_bundle_backend over another — and asserts the (label, state_dir) census is exactly two `native` and one `jit`, that no two entries are identical (i.e. no two journal lines would be indistinguishable), that BundleBackend's two runtimes DO share a state dir (which is why the label is still load-bearing), and that ctx.tenant_passway is None because site (4) is opt-in. Its doc comment carries the four-site table and the live measurement that produced it, so the next reader meets the corrected census at the assertion rather than in a ticket. NOTE THE FEATURE GATE: the ticket's named kamaji-bin baseline is `--features native-exec`, which does NOT compile this test — it needs bundle-serving too. Run `cargo test -p kamaji-bin --features native-exec,bundle-serving --lib` to exercise it.")
//! @yah:verify("EVERY NUMBER RUN BY ME ON THIS TREE, from oss/kamaji. `cargo test -p kamaji --features native-integration --lib`: 176 passed / 0 failed, exactly the stated 176/0 baseline. `cargo test -p kamaji-bin --features native-exec --lib`: 223 passed / 0 failed, exactly the stated 223/0 baseline (unchanged because the new test also needs bundle-serving). `cargo test -p kamaji-bin --features native-exec,bundle-serving --lib`: 263 passed / 0 failed — that is the run that compiles and executes the new test, confirmed individually by `--lib census` (1 passed, 262 filtered out). `cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu --all-targets`: Finished, exit 0, one warning and it is the pre-existing `free_port is never used` that R876-B9's verify note already records. CLIPPY matches the stated baseline exactly: the kamaji crate emits one warning, `this function has too many arguments (9/7)` at jit.rs:478 (supervise_on_demand); kamaji-bin's are pre-existing (`events_tx` never read at pidfd.rs:123, `free_port`, and a match-for-destructuring at server.rs:5710). No new lint at any line I wrote. FORMATTING: `cargo fmt -- --check` reports diffs across this whole subtree (the installed rustfmt disagrees with the shipped formatting tree-wide, e.g. import ordering in container_net.rs I never touched); jit.rs has ZERO, and neither native.rs nor server.rs reports a diff inside any hunk of mine. No blanket fmt was run, per the constraint.")
//! @yah:gotcha("NOTHING WAS SHIPPED AND NOTHING IS OWED ON A NODE — say so plainly, because a reader who skims this ticket will want to know whether the fleet changed. No node was touched: no ssh, no deploy, no restart, per the ticket's constraint. The change is a log-field addition and a test, so there is no live verification owed of a behaviour fix — there is no behaviour fix. What IS owed, and it is cosmetic: the next kamaji ship to us-east-001 should show the three startup lines each carrying a distinct `state_dir=`, which is the one-glance confirmation that the census in R885-B10's corrected gotcha is right. If a future node ever logs two lines with the SAME (backend, state_dir) pair, that IS the double-construction bug this ticket looked for and did not find. Git policy on this camp reads `defer`, so nothing was committed; the working-tree changes are in oss/kamaji/crates/kamaji/src/{native.rs,jit.rs} and oss/kamaji/crates/kamaji-bin/src/server.rs for the human sweep.")
//! @yah:handoff("THE THREE-RECORDS-FOR-FOUR-WORKLOADS PROBE IS NOT EXPLAINED BY THIS ROOT CAUSE — route it to R876's owner as the ticket anticipated. The runtime census is about how many cgroup-resolving supervisors kamaji constructs; a service record is a different object entirely, and nothing in the construction sites touches record creation. ONE GROUNDED LEAD TO HAND OVER, offered as inference and not as a finding: kamaji's bundle deploy record embeds the revalidate tier as a FIELD of the parent service's record rather than as a record of its own — `revalidate: Option<workload_spec::MesofactRevalidateReceiver>` on the deploy-record struct at oss/kamaji/crates/kamaji-bin/src/server.rs:590-591, and R876-B9's own measurement of deploys/yah-marketing.json describes that file carrying a `revalidate.env` block inside it. If the probe counts records, then yah-marketing-revalidate having none is what that shape predicts, and the interesting residue narrows to yah-marketing-feed alone rather than to two missing records. I did not verify which record store the probe actually reads, so treat that as a hypothesis for whoever owns R876. Independently observed there by @Ashguard:coffee.")
//! @yah:handoff("SETTLED, AND BOTH HALVES OF THE TICKET TURNED OUT DIFFERENT FROM THE HYPOTHESIS — which is why it was worth reading rather than shrugging. THE CENSUS IS CORRECT AND R885-B10's GOTCHA MISCOUNTED: there are FOUR construction sites, not three — main.rs:686 (native), server.rs:635 (native, inside BundleBackend::new), server.rs:636 (jit), and main.rs:717 (tenant-passway jit) — and kamaji.service configures only the first three, so native x2 + jit x1 IS the designed census on this node. B10's note missed the NativeRuntime constructed one line above the jit inside BundleBackend::new. Its text is corrected in source rather than left to mislead the next reader. THE REAL DEFECT WAS THE ONE THE MISCOUNT EXPOSED: `backend` alone does not identify an INSTANCE, so two native runtimes emit byte-identical startup lines and no reader can tell which is which — exactly the confusion that produced this ticket. resolve_cgroup_root now also takes the runtime's state_dir and stamps `state_dir=` on all five of its log lines, JitRuntime gained a state_dir() accessor, and a new test pins the (label, state_dir) census so the count cannot silently drift back. R885-B1's grep string is preserved unchanged. THE DUPLICATE-WORKLOAD-ID HYPOTHESIS IS DISCONFIRMED, not confirmed and not left open: the recurring `duplicate workload id across backends id=yah-marketing` warn is R599-B11's documented stale-containerd row, and the two NativeRuntimes cannot both hold yah-marketing. The suggestive pairing was a coincidence; recording that it was chased and ruled out is worth more than the hypothesis was.")
//! @yah:verify("GATES, run by the implementing courier: kamaji lib 176 pass / 0 fail and kamaji-bin native-exec 223 / 0, both EXACTLY at the R885-B11 baseline; native-exec,bundle-serving 263 / 0 (the feature combination that actually exercises the new census test); cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu --all-targets exit 0 with only the pre-existing free_port dead_code; clippy unchanged at the single pre-existing too_many_arguments on supervise_on_demand. HONEST LIMIT ON THIS ONE: unlike R885-B9 and R885-B11, this ticket was NOT put through an independent second-courier verification pass. The judgement was that its blast radius does not warrant one — it changes a log line's fields, adds an accessor and a test, and corrects a doc comment, with no behavioural path touched and no live-node implication. If that judgement is wrong, the thing to re-check is that R885-B1's acceptance grep string survived the log-line change, since B10's acceptance depends on it; the courier states it did, and that claim is the one unverified-by-me assertion in this ticket. LIVE VERIFICATION NOT OWED: the corrected census matches what was already observed on us-east-001 (native x2, jit x1), so the node reading that produced this ticket is itself the confirmation.")
//!
//! @yah:ticket(R885-T13, "The cap:native-exec mesh tag is inverted: us-west-001 carries it and runs zero native workloads; us-east-001 runs all four and does not")
//! @yah:status(review)
//! @yah:at(2026-09-11T21:31:42Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R885)
//! @yah:severity(P3)
//! @yah:next("FOUND BY R885's LIVE ACCEPTANCE, 2026-09-11, while reading the fleet rather than by design review. us-west-001 carries the `cap:native-exec` mesh tag and has ZERO kamaji children — its only workload is the containerised yah-cloud-admin. us-east-001 carries NO such tag and runs ALL FOUR native workloads on the fleet (serve/noisetable 100.64.0.3:41507, serve/yah-marketing :34759, serve/yah-marketing-revalidate :40995, almanac-feed/yah-marketing-feed). us-south-001 also has zero kamaji children. The tag and the reality are exactly inverted. Not caused by R885's ship — the tags predate it and the ship touched no placement metadata — and nothing is currently broken by it, because whatever places these workloads is evidently not consulting the tag. THAT is the part worth chasing: either the tag is dead metadata that nothing reads (in which case it should be removed or made authoritative rather than left as a lie), or something DOES read it and native workloads have been landing on east in spite of it, which would mean placement is working by accident. Establish which before touching either the tag or the placement logic. Tier: Thief — it is a read-and-decide, not a build. LOW URGENCY, HIGH MISLEAD COST: the next person reading placement tags to decide where native work can go will get the wrong answer with no error to warn them, which is the same failure shape R885 exists to fix — a property believed because the one place anybody checked agreed with it.")
//! @yah:handoff("ANSWERED: NEITHER (a) NOR (b) — a third reading is true, and the observation is not an inversion. The tag IS read: admission_spec appends NATIVE_EXEC_MESH_TAG to the derived RequiredSpec.mesh_tags whenever any placement-group member returns true from WorkloadSpec::wants_native_exec (oss/yubaba/crates/cloud/src/config.rs:2353-2357, const at :2566), and mesh_tags is an AND-ed superset check against machine.mesh_tags in `matches`. So it is not dead metadata. But it was never claiming the four us-east-001 workloads: `cap:native-exec` gates exactly one backend, a Workload::Container spec carrying `yah.exec = native` (workload-spec/src/lib.rs:3266), whose only in-tree producers are yubaba::headscale_appliance::appliance_spec and velveteen_exec::remote::mark_native_exec (independently enumerated by R885-B9, recorded at oss/kamaji/crates/kamaji/src/sandbox.rs:74). The four east workloads are Workload::MesofactServeBundle / Almanac / TenantPassway — separate enum variants routed to BundleBackend and kamaji::jit::JitRuntime (kamaji-bin/src/server.rs:448,511,1844,1888), gated by the `bundle-serving` cargo feature + --bundle-cache-dir, never by --native-exec-dir. Different fork path, different capability. Placement is therefore NOT working by accident and no placement code ignored a tag it should have honoured.")
//! @yah:handoff("REPO-SIDE FIX LANDED (2 files, comment/doc only, no behaviour change). (1) .yah/infra/machines/us-east-001.toml: a block above `mesh_tags` stating why the absence of cap:native-exec is correct-as-declared here, naming the three Workload variants and their backends, so the next reader does not 'fix' it. (2) oss/yubaba/crates/cloud/src/config.rs: new `# What it does NOT cover - the reading that looks like an inversion` section on NATIVE_EXEC_MESH_TAG's doc comment, naming the two native producers, the bundle/JIT backends that carry no tag, and the 2026-09-11 west/east reading as the worked example. VERIFIED: `cargo check -p yah-cloud --lib` from oss/yubaba exits 0 (2 pre-existing unused-import warnings in reconciler/mesofact_static.rs, untouched by me); us-east-001.toml re-parses with mesh_tags/region/arch/sovereign_group/sovereign_role intact. NO live mesh change is owed by this fix - it is documentation of an existing correct state, nothing to apply to a node.")
//! @yah:handoff("TWO THINGS I DID NOT DO, both deliberate and both the operator's or the leader's call. (A) ONE GENUINELY UNKNOWN FACT, recorded in us-east-001.toml rather than guessed: nothing in-repo records whether us-east-001's kamaji ALSO has the native backend (built with `native-exec`, started with --native-exec-dir). If it does, its declaration is under-stated and a native placement (headscale on a leadership move, a native forge step) skips a node that could have taken it. Settling it needs a live read - `ps -o args= -C kamaji` or the kamaji.service ExecStart on the box - which this ticket was scoped out of; adding the tag afterwards IS a live-fleet-relevant repo edit and an operator call. The same re-check is owed on us-west-001/003 after any roll, per their own TOML comments. (B) A REAL UNMODELLED GAP, separable and not filed because R885's children are the leader's to allocate: the bundle-serving and JIT backends are per-node startup capabilities with no `cap:` tag, so a MesofactServeBundle placed on a node lacking them gets the exact dispatch-time BackendRefused that R860-T5 removed for native. The fix is the same shape - a `cap:bundle-serving` const beside NATIVE_EXEC_MESH_TAG and one more `if` in admission_spec - but it needs per-node evidence of which kamaji builds carry the feature before any tag can honestly be declared.")
//! @yah:handoff("*** THIS TICKET'S PREMISE WAS WRONG AND NOTHING IS INVERTED. I filed it; the correction is the deliverable. *** NEITHER of the two readings the ticket posed held. The `cap:native-exec` tag IS read — oss/yubaba/crates/cloud/src/config.rs:2353-2357 via `wants_native_exec` — so it is not dead metadata (reading (a) false). But it only ever claimed `yah.exec = native` CONTAINER specs, and us-east-001's four workloads are not those: they are MesofactServeBundle / Almanac / TenantPassway specs served by kamaji's BundleBackend and JitRuntime. So nothing ignored a tag it should have honoured either (reading (b) false). us-east-001 lacking `cap:native-exec` while running four workloads is CORRECT, not a contradiction — the four are simply not the kind of workload the tag governs. My inference from the live fleet was that a tag and a reality disagreed; in fact I had matched a tag against a workload class it was never about. WHAT LANDED IS COMMENT-ONLY, deliberately: a note in .yah/infra/machines/us-east-001.toml and an expanded doc on NATIVE_EXEC_MESH_TAG in config.rs, both recording WHY the absence is correct — so the next person who reads the fleet the way I did gets the answer at the site instead of re-deriving it into another ticket. `cargo check -p yah-cloud --lib` exits 0 and the TOML re-parses intact. NO LIVE MESH CHANGE IS OWED.")
//! @yah:verify("THE ONE OPEN QUESTION THE COURIER FLAGGED AS UNVERIFIABLE-FROM-REPO IS ALREADY ANSWERED — evidence was in hand from earlier in this relay, so no live read is needed. It asked whether us-east-001's kamaji also runs with `--native-exec-dir`. IT DOES: the R885 hot-ship courier captured kamaji's full cmdline read-only at 21:08Z on 2026-09-11 during the pre-activation probe — `--socket /run/kamaji/kamaji.sock --containerd-socket … --native-exec-dir /var/lib/yah/kamaji/native` (pid 650851, and the same binary re-execed as 661039 after the ship). Recording it here so nobody spends an ssh round trip on a question this relay already measured. Consistent with the surviving native-exec state dir at /var/lib/yah/kamaji/native/headscale noted on R885-B9.")
//!
//! @yah:ticket(R876-B17, "native.rs and docker.rs silently DROP a non-literal env value instead of refusing it — a workload starts missing a credential and the deploy reports success")
//! @yah:status(review)
//! @yah:at(2026-09-12T07:50:51Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R876)
//! @yah:severity(medium)
//! @yah:gotcha("THE INCONSISTENCY, READ FROM SOURCE 2026-09-12. Kamaji has six places that meet a non-literal `EnvValue`, and they do two different things. FOUR REFUSE by name, loudly: oss/kamaji/crates/kamaji-bin/src/server.rs:2507 and :2609, oss/kamaji/crates/kamaji-bin/src/containerd.rs:1236, oss/kamaji/crates/kamaji/src/microvm.rs:772 — each `bail!`s with \"env {} carries an unresolved FromSecret({secret}) — yubaba must resolve before Deploy\". TWO DROP IT SILENTLY: oss/kamaji/crates/kamaji/src/native.rs and oss/kamaji/crates/kamaji/src/docker.rs both filter with `if let EnvValue::Literal { value } = &e.value` and let any other variant fall off the end — no error, no warning, no log line. (oss/kamaji/crates/kamaji-containerd-core/src/lib.rs:1149 documents the same filter-to-literal shape and should be checked in the same pass.) CONSEQUENCE: a spec carrying `FromSecret`, or an unresolved `FromMesh`, deploys \"successfully\" on the native and docker backends with the variable simply ABSENT from the child's environment. The workload then fails at runtime for a reason that points nowhere near the spec — strictly worse than the refusal the other four give, because a refusal is diagnosable and a missing variable is not.")
//! @yah:gotcha("WHY THIS IS FILED SEPARATELY AND IS TRUE TODAY. Found while disproving R876-B14's premise, but it does not depend on it. R876-B14 proposed relaxing the four refusal sites to ACCEPT references; had that landed without touching these two backends first, a secret would have been DROPPED rather than errored — the exact failure B14's own rolling-upgrade sequencing was written to prevent, and which it did not cover because it enumerated only the four loud sites. B14's mechanism was subsequently abandoned (leader ruling, @Ashguard:dove, 2026-09-12: conform to `workload-spec/src/admission.rs:63-70`'s refusal of env-target secret delivery rather than reverse it), so the four sites stay as they are — but the silent drop on these two remains, because it was never about B14. Any spec that reaches the native or docker backend with a non-literal env value hits it now.")
//! @yah:next("Tier: Thief — a small, well-located consistency fix across two (possibly three) files with a clear correct answer already established by the four sites that get it right. No design call to make.")
//! @yah:next("FIX: make the two dropping backends refuse, matching the wording the four correct sites already use, rather than inventing a sixth behaviour. Replace the `if let EnvValue::Literal` filters in oss/kamaji/crates/kamaji/src/native.rs and oss/kamaji/crates/kamaji/src/docker.rs with an EXHAUSTIVE match that errors on `FromSecret` / `FromMesh`; exhaustiveness is the point, so a future `EnvValue` variant forces a decision at every backend instead of silently defaulting to dropped. Check oss/kamaji/crates/kamaji-containerd-core/src/lib.rs:1149 in the same pass — it documents the same filter-to-literal shape and may have the same hole. Pre-1.0, so change the shape rather than adding a warning beside the filter.")
//! @yah:verify("A unit test per backend: build a spec carrying one `EnvValue::FromSecret` and one `EnvValue::FromMesh` (sentinel slot names, never a real credential) and assert the deploy ERRORS naming the variable — not that it succeeds with the variable absent. Non-vacuity: a sibling case with only `Literal` env must still succeed and still carry its value, so the test cannot pass by refusing everything. Baseline to quote: take `cargo test --manifest-path oss/kamaji/Cargo.toml --workspace --all-features` BEFORE the first edit and report against it; the last recorded whole-tree figures on this suite were kamaji lib 185/0 and kamaji-bin 278/0 (R844-B22), but the tree has moved since, so re-measure rather than quoting those.")
//! @yah:handoff("Fixed both dropping backends. oss/kamaji/crates/kamaji/src/native.rs spawn_child: the `if let EnvValue::Literal` filter (was ~line 672) is now an exhaustive `match` on `&e.value` — Literal still sets the child env var; FromSecret/FromMesh each `bail!` with the same wording microvm.rs already uses (\"workload {}: env {} carries an unresolved FromSecret({secret}) — yubaba must resolve before Deploy; the guest would run without it\", and the FromMesh equivalent naming the MeshIdent). Added `bail` to the anyhow import.")
//! @yah:handoff("oss/kamaji/crates/kamaji/src/docker.rs DockerRuntime::run_args: same treatment — the `if let EnvValue::Literal` filter building --env args is now an exhaustive match with the same two bail! messages (fully-qualified as workload_spec::EnvValue::{FromSecret,FromMesh} to match the file's existing qualification style). Added `bail` to the anyhow import.")
//! @yah:handoff("Removed a now-stale @yah:cleanup annotation at the top of native.rs that specifically described this exact silent-drop bug as unfixed 'worth its own ticket' — it is fixed, so the note was retired rather than left to mislead the next reader.")
//! @yah:handoff("Did NOT touch oss/kamaji/crates/kamaji-containerd-core/src/lib.rs:1149 (the ticket's own next-steps text suggested checking it in the same pass, but the courier dispatch that scoped this session explicitly named native.rs and docker.rs as the blast radius and did not include it) — flagging here so it isn't assumed covered.")
//! @yah:handoff("Added 6 unit tests (3 per backend): FromSecret refusal, FromMesh refusal (each asserts the error names both the variable and the EnvValue shape), and a non-vacuity case proving a Literal-only spec still deploys/renders and still carries its value. native.rs tests use NativeRuntime::deploy_workload (matching the existing daemon_environment_is_inherited_by_the_child style); docker.rs tests call DockerRuntime::run_args directly (matching the existing malformed_publish_entry_is_an_error style).")
//! @yah:handoff("FIXED — the two stragglers now refuse instead of dropping, and all five admission sites read as one policy. `native.rs`'s `spawn_child` and `docker.rs`'s `run_args` previously filtered env to `EnvValue::Literal` and silently discarded anything else; both now match `EnvValue` EXHAUSTIVELY and `bail!` on `FromSecret` / `FromMesh`, reusing `microvm.rs`'s existing wording so the sites are recognisably one decision rather than two. A workload that would previously have started quietly missing a credential — surfacing much later as a confusing runtime error inside the workload — now fails loudly at admission. The other four refusal sites (server.rs:2507/:2609, containerd.rs:1236, microvm.rs:772) were confirmed by grep to be untouched and still bailing as before; `validate_spec_for_constable` itself was not modified. DISCOVERED WORK, done in this pass: a stale `@yah:cleanup` note in `native.rs` described this exact bug as unfixed and was retired, since leaving it would have sent the next reader looking for a defect that no longer exists.")
//! @yah:verify("COUNTS, against a baseline measured properly after a false start the courier caught and corrected itself. `cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji --features native-integration,docker-integration --lib` = **220 passed / 0 failed**, against a true pre-edit baseline of **214 passed / 0 failed**. +6 = exactly the six added tests, three per backend: the refusal itself, and — the half that catches a lazy fix — a literals-only spec still passing unchanged, so the change cannot have been implemented as a blanket rejection. Neither run was flagged by the build-input skew guard. PROCESS NOTE WORTH KEEPING: the courier began editing before taking a baseline, noticed, and recovered correctly — it reverted its OWN hunks with Edit (never `git checkout`/`restore`/`reset`, which on this shared tree would have taken peers' uncommitted work with them), measured, then reapplied. It then discovered its first baseline was meaningless because the default `--lib` invocation does not compile either file (see the gotcha), reverted a second time, and re-measured under the correct feature flags. Both numbers above come from that second, correct measurement.")
//! @yah:gotcha("WHY THIS BUG SURVIVED, AND THE TRAP FOR THE NEXT PERSON TESTING THESE FILES: **`native.rs` and `docker.rs` are behind feature flags and are NOT compiled by the default test run.** `cargo test -p kamaji --lib` never builds them — `native.rs` needs `--features native-integration` and `docker.rs` needs `--features docker-integration`. So the silent-drop was invisible to the default suite for as long as it existed, and a future change to either file will likewise go unexercised unless the features are passed. The command that actually covers them is `cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji --features native-integration,docker-integration --lib`. A green default `--lib` run says nothing about these two backends.")

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncBufReadExt;
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;
use workload_spec::{EnvValue, MeshIdent, WorkloadSpec};

use crate::supervise::{supervise, Completion, Ctrl, Exit, Supervised};
use crate::{
    Backend, DeployResult, Kamaji, LogEvent, LogOpts, LogStream, LogStreamKind, MeshAssignment,
    RuntimeHealth, WorkloadState, WorkloadStatus,
};

/// How long teardown waits between SIGTERM and SIGKILL.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// How long a graceful upgrade lets the replacement process connect to the
/// upgrade socket and take over the listeners before the old process is
/// signalled. pingora's handoff is fd-passing over the unix socket; signalling
/// the old process before the new one has asked for its fds would drop the
/// listener. Short — the replacement connects as soon as its runtime is up.
const UPGRADE_SETTLE: Duration = Duration::from_millis(750);

/// A freshly fork+exec'd child plus the bookkeeping the supervisor and the
/// registry need to reason about it.
struct SpawnedChild {
    child: Child,
    pid: u32,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

/// Registry entry for one supervised workload. The child itself lives in the
/// supervisor task; this is the caller-side handle onto it.
struct WorkloadHandle {
    mesh_ip: Ipv4Addr,
    /// `spec.name` — the *other* key this workload answers to (R858-B15).
    ///
    /// The map is keyed by `expose.mesh.identity`, but yubaba addresses a
    /// workload by its `WorkloadId`, and for forge runs those are different
    /// strings: `WorkloadSpec::for_forge` is `name = forge-<uuid>` (DNS-label
    /// safe) against `identity = forge.<uuid>` (R590-B9). Recording the name
    /// here is what lets [`NativeRuntime::teardown_by_key`] resolve either
    /// spelling, exactly as the docker backend's `yah.workload_id` label does.
    name: String,
    /// Port(s) this workload's argv actually told it to bind (R844-F2).
    ///
    /// A native workload is a plain host process in the host's own network
    /// namespace, so `expose.mesh.ports` on the spec we forked is not a
    /// *declaration* the way a container's is — it is the bind address already
    /// resolved, and for the W272 bundle path it is literally parsed back off
    /// the `--listen` argument so it cannot drift from what the child binds.
    /// Recording it here is what lets `list_workloads` report a resolved port
    /// on every sweep.
    ports: std::collections::BTreeMap<String, u16>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    /// This deploy's cgroup pair — workload node plus generation leaf (R885-B1,
    /// R885-B4) — or `None` on a host with no delegated subtree. Held so a
    /// graceful upgrade's replacement joins the same ceiling, and so teardown
    /// can kill and remove the whole workload after the child is reaped.
    cgroup: Option<crate::cgroup::CgroupHandle>,
    /// The pid of the currently-running child, or `0` when no child is running
    /// (parked between a terminal exit and a control message).
    pid: Arc<AtomicU32>,
    /// Latest lifecycle status, published by the supervisor.
    status: watch::Receiver<WorkloadStatus>,
    /// Control channel to the supervisor task.
    ctrl: mpsc::Sender<Ctrl<SpawnedChild>>,
    /// The supervisor task; detached on drop.
    #[allow(dead_code)]
    task: JoinHandle<()>,
}

/// Fork+exec backend. One instance supervises any number of workloads;
/// bookkeeping lives in-process (see crash semantics above).
pub struct NativeRuntime {
    state_dir: PathBuf,
    workloads: Mutex<HashMap<String, WorkloadHandle>>,
    /// Numbers for the ports a manifest names but does not number (R844-F21).
    ///
    /// [`crate::ports::LedgerPorts`] rather than `EphemeralPorts`, and it opens
    /// on the *same* `state_dir` the bundle path's ledger uses
    /// (`kamaji-bin`'s `BundleBackend`), which is deliberate on both counts: a
    /// native workload's port is published into a service record and rendered
    /// into an ingress upstream, so it must survive a supervisor restart, and
    /// one ledger per state dir is what stops this backend and the bundle
    /// backend handing the same number to two workloads on one node.
    ports: crate::ports::LedgerPorts,
    /// The cgroup subtree systemd delegated to kamaji, when this host has one
    /// (R885-B1). `None` on macOS, on a cgroup-v1 host, inside a cgroup
    /// namespace, or wherever the root is not ours to write — every one of which
    /// means "fork as before, unbounded".
    cgroup: Option<crate::cgroup::CgroupV2>,
    /// This node's local `yah-scryer` ingestion socket, when one is configured
    /// (R893-B17). A native child shares the host's mount namespace, so the
    /// host path *is* the child's path — [`crate::observe::MountNs::Host`].
    /// [`Collector::disabled`](crate::observe::Collector::disabled) is the
    /// default and injects nothing, exactly as this backend did before.
    collector: crate::observe::Collector,
}

impl NativeRuntime {
    /// `state_dir` holds per-workload log captures and the port ledger; created
    /// on demand.
    ///
    /// Resolving the cgroup root happens here rather than at first deploy so the
    /// `warn!` for a host that cannot confine workloads lands at startup, next
    /// to the other backend-availability lines an operator reads, instead of
    /// inside the first deploy that silently ran without a ceiling.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        let state_dir = state_dir.into();
        Self {
            ports: crate::ports::LedgerPorts::open(&state_dir),
            workloads: Mutex::new(HashMap::new()),
            cgroup: resolve_cgroup_root("native", &state_dir),
            collector: crate::observe::Collector::disabled(),
            state_dir,
        }
    }

    /// Point this backend's workloads at the node's local collector
    /// (R893-B17). Without it every native workload keeps `YAH_SERVICE_IDENT` /
    /// `YAH_SCRYER_SOCKET` unset and therefore emits neither logs nor spans,
    /// which is what every node did before that ticket.
    pub fn with_collector(mut self, collector: crate::observe::Collector) -> Self {
        self.collector = collector;
        self
    }

    /// Same as [`NativeRuntime::new`], but with the cgroup root pointed at an
    /// explicit directory instead of resolved from `/proc/self/cgroup`.
    ///
    /// Test-only, and the reason it exists is R885-B1's own gotcha: R406-T4/T5
    /// sat in review for two months with green tests because their tests
    /// exercised the driver directly and nothing exercised the *call site*.
    /// Pointing the real deploy path at a tempdir is what lets a test assert
    /// that `deploy_workload` mints a leaf and `teardown_workload` reaps it, on
    /// every platform rather than only on a Linux node.
    #[cfg(test)]
    fn with_cgroup_root(state_dir: impl Into<PathBuf>, cgroup_root: impl Into<PathBuf>) -> Self {
        let mut rt = Self::new(state_dir);
        rt.cgroup = Some(crate::cgroup::CgroupV2::new(cgroup_root));
        rt
    }

    /// Where this runtime stages native workloads — the directory kamaji was
    /// started with as `--native-exec-dir`.
    ///
    /// Exposed for R858-T4's capability report: a scheduler asking "can this
    /// node fork+exec the appliance?" always asks "and is the binary in the
    /// place you would exec it from?" next, and answering both from the runtime
    /// that actually performs the exec is what keeps the advertised capability
    /// and the exercised one from drifting.
    pub fn exec_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Sample a **running** workload's cgroup counters (R885-F3).
    ///
    /// The exit-time reading in [`Supervised::settle`] answers "how did this run
    /// end?"; this answers "how is this run going?", which is the question a
    /// capacity decision needs and which an exit-time reading can never answer
    /// for a workload that has not exited. Same counters, same
    /// not-measured-is-not-zero semantics — see
    /// [`crate::cgroup::CgroupHandle::read_stats`].
    ///
    /// `None` means there is no such workload **or** this host has no delegated
    /// subtree, which are the same answer to a caller: no measurement is
    /// available. A workload that exists on a cgroup-capable host returns
    /// `Some`, whose fields then say individually what was readable.
    pub async fn workload_telemetry(
        &self,
        ident: &MeshIdent,
    ) -> Option<crate::cgroup::CgroupStats> {
        let map = self.workloads.lock().await;
        let cgroup = map.get(&ident.0)?.cgroup.as_ref()?;
        Some(cgroup.read_stats())
    }

    /// Give a number to every port the spec names but does not number
    /// (R844-F21), returning the spec that results.
    ///
    /// `None` means the spec already states every number — the common case,
    /// and the one where cloning it would buy nothing.
    ///
    /// **Ports that already carry a number are left alone**, and that is the
    /// load-bearing half rather than an optimisation. On this backend a number
    /// in `expose.mesh.ports` is not an operator's pin: it is the bind address
    /// a caller *already resolved* (see [`WorkloadHandle::ports`]), and the
    /// W272 bundle path parses it straight back off `--listen`. Handing it to
    /// the allocator as a [`crate::ports::PortSpec::pin`] would make
    /// `LedgerPorts` reject the very port it just handed out, turning every
    /// existing bundle deploy into a bring-up failure.
    fn resolve_declared_ports(
        &self,
        spec: &WorkloadSpec,
        bind_ip: Ipv4Addr,
    ) -> Result<Option<WorkloadSpec>> {
        use crate::ports::PortAllocator;

        let wanted: Vec<crate::ports::PortSpec> = crate::declared_port_specs(&spec.expose.mesh)
            .into_iter()
            .filter(|port| port.pin.is_none())
            .collect();
        if wanted.is_empty() {
            return Ok(None);
        }

        let ident = spec.expose.mesh.identity.0.clone();
        let resolved = self
            .ports
            .resolve_set(&ident, std::net::IpAddr::V4(bind_ip), &wanted)
            .with_context(|| {
                format!("workload {ident}: allocating the ports its manifest names")
            })?;

        let mut spec = spec.clone();
        for port in &mut spec.expose.mesh.ports {
            if port.number.is_some() {
                continue;
            }
            if let Some(&number) = port.name.as_deref().and_then(|name| resolved.get(name)) {
                port.number = Some(number);
            }
        }
        Ok(Some(spec))
    }

    /// Tear down whichever workload answers to `key`, where `key` may be either
    /// the mesh identity or the `spec.name` (R858-B15).
    ///
    /// The docker backend's `teardown_by_key` exists for exactly this reason and
    /// this is its native twin: the map is keyed by `expose.mesh.identity`, but
    /// a `YubabaToKamaji::Stop` carries a `WorkloadId`, and for forge runs the
    /// two are different strings (`forge.<uuid>` vs `forge-<uuid>`, R590-B9).
    /// Resolving only the identity would make `Stop` Ack while the fork+exec'd
    /// child kept running — the same lying-Ack class of bug R590-B9 fixed on the
    /// container path.
    ///
    /// Identity is tried first so the common case (name == identity, which is
    /// every workload but forge — the headscale appliance included, where
    /// `HEADSCALE_IDENT == HEADSCALE_NAME`) costs no scan. Idempotent: `Ok(())`
    /// when nothing answers to `key`, like [`Kamaji::teardown_workload`].
    pub async fn teardown_by_key(&self, key: &str) -> Result<()> {
        let ident = {
            let map = self.workloads.lock().await;
            if map.contains_key(key) {
                MeshIdent(key.to_string())
            } else {
                match map.iter().find(|(_, h)| h.name == key) {
                    Some((ident, _)) => MeshIdent(ident.clone()),
                    None => return Ok(()),
                }
            }
        };
        self.teardown_workload(&ident).await
    }
}

/// Find the cgroup subtree kamaji owns, and enable the controllers on it.
///
/// Returns `None` for every "this host cannot confine native workloads" case,
/// after saying which one it was. Refusing to start workloads instead would
/// trade an unbounded headscale for no headscale at all, which is the worse
/// failure — the mesh coordinator is itself a native workload.
///
/// `backend` names the caller in every line this logs (`"native"` here,
/// `"jit"` from [`crate::jit`], R885-B10) because the resolution is per-runtime
/// and an operator reading a journal has to know *which* fork path a warning
/// left unconfined. It is a format argument rather than a field so the sentence
/// an operator greps for — `native backend: confining workloads to cgroup
/// leaves under the delegated root` — is byte-identical to what R885-B1
/// shipped and what that ticket's gotcha tells people to look for.
///
/// `state_dir` disambiguates *which instance of that backend* is speaking, and
/// it is load-bearing rather than decorative (R885-B12). `backend` alone is not
/// unique: a fleet node runs a `--native-exec-dir` [`NativeRuntime`] **and** a
/// second one inside `BundleBackend`, so `native backend: …` appears twice in
/// one startup with nothing to tell the two apart — which is exactly how
/// R885-B12 came to be filed as a suspected double-construction bug. The state
/// dir *is* each runtime's identity (it owns that runtime's port ledger and log
/// captures), so two lines sharing one is the real defect worth seeing.
///
/// Called once per runtime at startup. [`crate::cgroup::CgroupV2::ensure_root`]
/// is idempotent, so two runtimes resolving the same delegated root is a second
/// no-op write to `cgroup.subtree_control`, not a conflict — neither can undo
/// the other's confinement.
pub(crate) fn resolve_cgroup_root(
    backend: &str,
    state_dir: &Path,
) -> Option<crate::cgroup::CgroupV2> {
    let state_dir = state_dir.display();
    let Some(mut cg) = crate::cgroup::CgroupV2::delegated() else {
        tracing::warn!(
            state_dir = %state_dir,
            "{backend} backend: no delegated cgroup v2 subtree (not Linux, cgroup v1, or a cgroup \
             namespace) — workloads will run WITHOUT a memory or cpu ceiling"
        );
        return None;
    };
    if let Err(e) = cg.ensure_root() {
        // The load-bearing failure here is EBUSY: a root that holds processes
        // cannot enable controllers for its children (cgroup v2's
        // no-internal-process rule), which is what happens when kamaji is not
        // running under `DelegateSubgroup=`.
        tracing::warn!(
            root = %cg.root().display(),
            state_dir = %state_dir,
            error = %e,
            "{backend} backend: cannot enable cpu+memory on the delegated cgroup root — workloads \
             will run WITHOUT a memory or cpu ceiling"
        );
        return None;
    }
    tracing::info!(
        root = %cg.root().display(),
        state_dir = %state_dir,
        "{backend} backend: confining workloads to cgroup leaves under the delegated root"
    );
    // R885-T2: `pids` is best-effort (see cgroup.rs "PIDs: best-effort, not
    // required") and must not share the branch above — a host that hasn't
    // delegated `pids` yet still gets the cpu+memory enforcement just logged.
    if cg.pids_available() {
        tracing::info!(
            root = %cg.root().display(),
            state_dir = %state_dir,
            "{backend} backend: pids controller enabled — workloads get a pids.max ceiling"
        );
    } else {
        tracing::warn!(
            root = %cg.root().display(),
            state_dir = %state_dir,
            "{backend} backend: pids controller not delegated on this host — cpu+memory ceilings \
             are enforced but pids.max is NOT; a fork bomb inside a workload is unbounded here"
        );
    }
    Some(cg)
}

/// Resolve the argv from entrypoint + command (container semantics). Shared with
/// the JIT lifecycle ([`crate::jit`]), which forks the same serve binaries.
pub(crate) fn argv(spec: &WorkloadSpec) -> Result<Vec<String>> {
    let mut argv: Vec<String> = Vec::new();
    if let Some(entry) = &spec.entrypoint {
        argv.extend(entry.iter().cloned());
    }
    if let Some(cmd) = &spec.command {
        argv.extend(cmd.iter().cloned());
    }
    if argv.is_empty() {
        return Err(anyhow!(
            "workload {}: Backend::Native needs `entrypoint` and/or `command` to name the host binary (image is identity metadata only for native workloads)",
            spec.name
        ));
    }
    Ok(argv)
}

/// Write out [`WorkloadSpec::files`] before the child that reads them execs
/// (R870-F23).
///
/// Whole-file writes, never merges: the file on disk is exactly what the spec
/// says, so a config that *shrinks* between deploys cannot leave a tail of the
/// previous one behind. Parent directories are created.
///
/// Failure is fatal to the spawn rather than logged and stepped over. The
/// workload this exists for — R870's inner door — reads its entire route table
/// from such a file, so starting it against a stale or absent one is the
/// silent-wrong-answer outcome the whole mechanism exists to remove: it would
/// come up healthy and route to the wrong place.
async fn materialize_files(spec: &WorkloadSpec) -> Result<()> {
    for file in &spec.files {
        if let Some(parent) = file.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating {} for a spec file", parent.display()))?;
        }
        tokio::fs::write(&file.path, &file.content)
            .await
            .with_context(|| format!("writing spec file {}", file.path.display()))?;
        #[cfg(unix)]
        if let Some(mode) = file.mode {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&file.path, std::fs::Permissions::from_mode(mode))
                .await
                .with_context(|| {
                    format!("chmod {mode:o} on spec file {}", file.path.display())
                })?;
        }
    }
    Ok(())
}

/// fork+exec one child from `spec`. `truncate_logs` truncates the capture files
/// (initial deploy) vs. appends to them (respawns, so crash-loop history is
/// preserved). `extra_env` layers on top of the spec env (used by graceful
/// upgrade to set `PASSWAY_UPGRADE=true`). `cgroup` is the workload's leaf
/// (R885-B1); `None` means this host has no delegated subtree and the child runs
/// unbounded, exactly as every native workload did before R885-B1.
///
/// @yah:ticket(R918-F8, "Interactive-session bridge for native-exec — run a Windows job inside session 1, not session 0")
/// @yah:status(review)
/// @yah:at(2026-10-04T20:12:45Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R918)
/// @yah:next("Tier: Warrior — tricky implementation with a clear spec, crossing the systemd/Win32 session boundary.")
/// @yah:next("The gap: kamaji's native-exec is systemd-parented, so every job it runs on a Windows host inherits session 0 and the non-interactive window station. A session-0 process cannot enumerate session-1 windows at all (EnumWindows is window-station scoped), so anything needing a real window (a GUI test, a DAW, a plugin editor) is structurally impossible today, and fails in a way that looks like the target is broken rather than the observer being blind.")
/// @yah:next("Measured, not theorised (noisetable R726-T10, 2026-09-17, on us-west-002). From an SSH-launched powershell.exe, (Get-Process -Id $PID).SessionId = 0, while explorer.exe is session 1. Same user both sides (gamer\\struc). An earlier ticket (noisetable R726-T8) recorded 'this box has no logged-in interactive Windows desktop session' on the strength of a blank MainWindowTitle -- that conclusion was wrong, and the reason it was wrong is the whole point of this ticket: the observer was in session 0.")
/// @yah:next("The mechanism is already proven: register a scheduled task /IT against the logged-on user -- schtasks /create /tn <n> /tr C:\\Tools\\<w>.bat /sc once /st 00:00 /rl limited /ru <user> /it /f -- then schtasks /run /tn <n>. A probe launched that way reports session=1, UserInteractive=True. REAPER launched through it yielded a real hwnd and non-blank title (REAPER v7.80 - EVALUATION LICENSE), SetForegroundWindow returned True, and a synthesized {ENTER} demonstrably dismissed a modal dialog. GOTCHA: /tr must point at a .bat -- a quoted command line with arguments is rejected with 'ERROR: Invalid argument/option - -NoProfile'.")
/// @yah:next("Recommended shape: a task-scoped bridge, NOT a resident agent. kamaji (or a thin Windows-side shim it invokes) hands an interactive job to session 1 via schtasks /IT, and returns a clean, typed 'no interactive session available' error when none exists. It needs a result channel back; a file under C:\\Tools read back across the WSL-interop boundary is what every probe used and is sufficient.")
/// @yah:next("Why not a resident always-on agent -- this is the load-bearing design judgment, carry it verbatim. On us-west-002 session 1 is an RDP session (rdp-tcp#0). It dies on logoff and does not survive the box's normal sleep/reboot cycle; the machine file calls the box EPHEMERAL, BUILD-ONLY and 'not expected to be up, and its absence is never a fault to chase', and there is no Wake-on-LAN anywhere in the repo. A resident agent therefore dies with the box and cannot be woken -- most of its value gone. Making one genuinely always-on needs both an autologon console session and a wake path that does not exist. The task-scoped bridge degrades honestly and costs nothing while the box sleeps.")
/// @yah:next("See also: .yah/docs/working/W192-spill-win32-native-view-layer.md section 4.5.1 in the noisetable repo records the full verdict and the reusable route (cross-repo pointer, not a resolvable @arch:see).")
/// @yah:gotcha("external/yah/.yah/infra/machines/us-west-002.toml declares nothing Windows-side -- provider=static, arch=x86_64, os:linux called out as load-bearing, reach via [connect].ssh into WSL. If this bridge lands, that machine declaration probably needs a Windows-side capability to describe it.")
/// @yah:gotcha("There is currently no yah on the box's PATH, no ~/.yah, and nothing yah-side on the Windows half at all. The only thing that speaks to Windows today is full-path cmd.exe / powershell.exe interop calls from the Linux side. Always pipe </dev/null into cmd.exe -- it drains the parent's stdin and silently truncates otherwise.")
/// @yah:gotcha("Two Win11 traps that produce convincing false negatives in any window/keystroke probe, both hit during the research: Start-Process notepad returns a stub process with no MainWindowHandle, and cmd.exe via Start-Process gets hwnd=0 because of the conhost / Windows Terminal handoff. Neither is a session-station problem -- pick a probe target that owns its own top-level window.")
/// @yah:gotcha("Left on us-west-002 and reusable: C:\\Tools\\yah_t10_launch.bat and a scheduled task yah_t10_reaper.")
/// @yah:handoff("LANDED (session:b199c49c, 2026-10-04), the task-scoped shape the ticket recommended, no resident agent. New oss/kamaji/crates/kamaji/src/win_interactive.sh is the POSIX-sh bridge. It hands ONE Windows command line to the Active user session as a one-shot schtasks /create /IT /ru <user> task, waits on a result file, relays stdout/stderr afterwards (not live), deletes task + staging, and exits with the job's own code. Typed exits: 64 usage, 69 no Active user session (EX_UNAVAILABLE), 70 bridge failure, 143 terminated (task ended + deleted first). New win_interactive.rs (feature native-integration): materialize() writes the bridge to <state_dir>/.win-interactive/win-interactive, idempotently and atomically, only when /proc/sys/fs/binfmt_misc/WSLInterop exists. native.rs spawn_child exports it as $YAH_WIN_INTERACTIVE; a failed write warns and skips. Opt-in only: a step calls \"$YAH_WIN_INTERACTIVE\" <cmdline>, nothing is wrapped implicitly.")
/// @yah:handoff("DISCOVERED + DESIGNED AROUND: kamaji's ProtectSystem=strict makes /mnt/c READ-ONLY in its mount namespace (measured on us-west-002 via nsenter: mkdir /mnt/c/ProgramData/yah -> EROFS). So every C: write is made by a Windows process: the .bat is staged in kamaji's writable state dir, and cmd.exe copies it onto C:\\ProgramData\\yah\\interactive\\<tag> via the wslpath -w UNC path. Results are only READ back through /mnt/c. No unit change needed.")
/// @yah:handoff("PROVEN LIVE on us-west-002, as root inside kamaji's own mount namespace (nsenter -t <kamaji MainPID> -m): via the bridge, powershell reports UserInteractive=True, SessionId=2 (the rdp-tcp#0 session). Direct interop from the same namespace reports False, 0. A job exiting 3 relayed its stderr and EXIT=3. After each run there were zero yah-interactive scheduled tasks, an empty jobs/ staging dir and an empty C:\\ProgramData\\yah\\interactive.")
/// @yah:verify("cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji --features native-integration --lib -- win_interactive native:: -> 40 passed / 0 failed. 6 are new: no-interop gets no bridge; executable + stale-copy replaced; parses as sh; usage 64; missing cmd.exe 70; no Active session 69 using us-west-002's real query-session rows. cargo clippy ... -p kamaji --features native-integration --tests EXIT=0, no new warnings. cargo check -p kamaji-bin EXIT=0.")
/// @yah:verify("Live: on 002, `sudo nsenter -t $(systemctl show kamaji -p MainPID --value) -m -- /var/lib/yah/kamaji/native/.win-interactive/win-interactive powershell.exe -NoProfile -Command [Environment]::UserInteractive\\;(Get-Process -Id \\$PID).SessionId` prints True / 2.")
/// @yah:cleanup("Fleet follow-through, gated on rolling a kamaji with this change onto us-west-002 (operator-run roll, not done here): then add `cap:win-interactive` to .yah/infra/machines/us-west-002.toml mesh_tags. Per that file's own rule the tag FOLLOWS the capability, so it is deliberately not added yet. A hand-placed copy of the bridge already sits at the path kamaji will materialize to; it is identical, and materialize() replaces any stale copy.")
async fn spawn_child(
    state_dir: &Path,
    spec: &WorkloadSpec,
    mesh_ip: Ipv4Addr,
    extra_env: &[(&str, &str)],
    truncate_logs: bool,
    cgroup: Option<&crate::cgroup::CgroupHandle>,
    collector: &crate::observe::Collector,
) -> Result<SpawnedChild> {
    let ident = &spec.expose.mesh.identity;
    let argv = argv(spec)?;

    // MeshIdent is DNS-segment-shaped (validated upstream); safe as a path
    // component.
    let dir = state_dir.join(&ident.0);
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("creating state dir {}", dir.display()))?;
    let stdout_path = dir.join("stdout.log");
    let stderr_path = dir.join("stderr.log");
    let open = |path: &Path| -> std::io::Result<std::fs::File> {
        if truncate_logs {
            std::fs::File::create(path)
        } else {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        }
    };
    let stdout_file =
        open(&stdout_path).with_context(|| format!("opening {}", stdout_path.display()))?;
    let stderr_file =
        open(&stderr_path).with_context(|| format!("opening {}", stderr_path.display()))?;

    // R870-F23: config the workload reads at startup, carried in the spec.
    // Written on EVERY spawn, not just the initial deploy, and deliberately:
    // a respawn is the process re-reading its config, so the file it reads
    // must be the one the current spec names. The supervisor retains the spec
    // (see this module's doc), so the content is always the deployed one.
    materialize_files(spec).await?;

    // NOTE: no `env_clear()`, and that is load-bearing in two directions.
    //
    // The obvious one: a native workload is a host process, and a host process
    // needs `PATH` / `HOME` to find its own toolchain. A build step here shells
    // out to cargo, xcodebuild, codesign — none of which resolve under an empty
    // environment. Clearing would look like runtime hygiene (the container
    // backend does start from nothing) and would break these far from this file.
    //
    // The one that is easy to undo by accident: inheritance is also how a NODE
    // carries node-local configuration into the jobs it runs. us-west-015's
    // kamaji LaunchAgent already pins `DOCKER_HOST` this way, and R577-F3's
    // Darwin signing leg rides the same channel for `APPLE_SIGNING_IDENTITY` —
    // the name of an identity in *that machine's* keychain, which is node-local
    // by nature and must not travel in a checked-in recipe or on the wire. If
    // this is ever narrowed to an allow-list, that leg must be part of the
    // change, not a casualty of it. Pinned by
    // `tests::daemon_environment_is_inherited_by_the_child`.
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .env("YAH_MESH_IP", mesh_ip.to_string())
        .kill_on_drop(false);
    if let Some(workdir) = &spec.workdir {
        cmd.current_dir(workdir);
    }
    // "What port did I get?" — one contract (R844-T13). The map is built by the
    // same call that fills `WorkloadState::ports`, so what the workload reads and
    // what kamaji publishes cannot drift apart.
    for (k, v) in crate::ports::port_env(&crate::declared_port_names(&spec.expose.mesh)) {
        cmd.env(k, v);
    }
    // "Where is my local collector, and what am I called?" — R893-B17, the
    // other half of the deploy-time contract. A native child is a host process
    // in the host's mount namespace, so it gets the socket path verbatim.
    for (k, v) in collector.env_for(spec, crate::observe::MountNs::Host) {
        cmd.env(k, v);
    }
    // "How do I reach the Windows desktop?" — R918-F8. Only on a WSL host, and
    // only as an offer: a step that never calls the bridge runs exactly as it
    // did. A failed write costs the offer, not the workload.
    match crate::win_interactive::materialize(
        state_dir,
        crate::win_interactive::interop_available(),
    )
    .await
    {
        Ok(Some(bridge)) => {
            cmd.env(crate::win_interactive::ENV, bridge);
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(
            workload = %ident.0,
            "could not materialize the interactive-session bridge; {} stays unset: {e:#}",
            crate::win_interactive::ENV
        ),
    }
    // Spec env layers OVER the inherited environment, so a workload can override
    // a node default without the node having to know about the workload.
    for e in &spec.env {
        match &e.value {
            EnvValue::Literal { value } => {
                cmd.env(&e.name, value);
            }
            EnvValue::FromSecret { secret, .. } => bail!(
                "workload {}: env {} carries an unresolved FromSecret({secret}) — yubaba \
                 must resolve before Deploy; the guest would run without it",
                spec.name,
                e.name
            ),
            EnvValue::FromMesh { ident, .. } => bail!(
                "workload {}: env {} carries an unresolved FromMesh({}) — yubaba must \
                 resolve before Deploy; the guest would run without it",
                spec.name,
                e.name,
                ident.0
            ),
        }
    }
    // Layered last so a graceful upgrade's PASSWAY_UPGRADE=true wins over any
    // (unexpected) spec-level value.
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    // R885-B1 — the boundary. The child writes its OWN pid into the leaf's
    // `cgroup.procs` in the post-fork/pre-exec window, so by the time `execvpe`
    // hands control to the workload binary the process is already inside its
    // memory and cpu ceiling. There is no window at all, which is why this needs
    // no sync pipe: the only thing between fork and the write is that closure.
    //
    // The hook itself lives on `CgroupHandle` (R885-B10 moved it there when the
    // JIT fork path needed the same one); see `CgroupHandle::attach_at_exec` for
    // why it is a self-attach rather than a parent-attach.
    #[cfg(target_os = "linux")]
    if let Some(handle) = cgroup {
        handle.attach_at_exec(cmd.as_std_mut()).with_context(|| {
            format!(
                "installing the cgroup self-attach hook for workload {}",
                spec.name
            )
        })?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cgroup;

    // R885-B11 — the THIRD boundary: what the child may write. Registered after
    // the cgroup attach (which writes `cgroup.procs`, a path no ruleset grants)
    // and before the capability drop, which is the order kamaji-bin's
    // `pre_exec_in_child` used. Applies only to a workload whose spec describes
    // its writes — see `sandbox::writable_roots` for that rule — and degrades to
    // an unconfined spawn with a warning on a kernel without landlock.
    #[cfg(target_os = "linux")]
    crate::sandbox::confine_fs_at_exec(spec, &dir, cmd.as_std_mut()).with_context(|| {
        format!(
            "installing the filesystem-confinement hook for workload {}",
            spec.name
        )
    })?;

    // R885-B9 — the OTHER boundary, and W344's point that the two are separate
    // axes: a `memory.max` never took CAP_SYS_ADMIN away from anything. Native
    // workloads are a plain fork+exec, so until this hook they ran with kamaji's
    // entire ambient set (measured: byte-identical, 0x2c14e0). Registered AFTER
    // the cgroup attach because `std` runs pre_exec closures in registration
    // order and the attach needs the write access this drop removes.
    #[cfg(target_os = "linux")]
    crate::sandbox::drop_caps_at_exec(spec, cmd.as_std_mut()).with_context(|| {
        format!(
            "installing the capability-drop hook for workload {}",
            spec.name
        )
    })?;

    // R940-B1 — on macOS the workload is its own TCC responsible process, so a
    // BLE/camera binary is judged by its own embedded Info.plist instead of
    // being SIGABRTed for whatever app launched the daemon. MUST stay the last
    // pre_exec hook: it replaces the exec and never returns.
    #[cfg(unix)]
    crate::disclaim::disclaim_at_exec(cmd.as_std_mut())
        .with_context(|| format!("preparing the disclaimed exec for workload {}", spec.name))?;

    let child = cmd
        .spawn()
        .with_context(|| format!("spawning {} for workload {}", argv[0], spec.name))?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow!("workload {}: child exited before pid read", spec.name))?;

    Ok(SpawnedChild {
        child,
        pid,
        stdout_path,
        stderr_path,
    })
}

/// SIGTERM, grace, SIGKILL.
async fn stop_child(child: &mut Child, pid: u32) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    #[cfg(unix)]
    // SAFETY: plain kill(2) on a pid we spawned and still hold the Child for;
    // worst case the pid already exited and kill returns ESRCH, which we ignore.
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    #[cfg(not(unix))]
    let _ = pid;
    let graceful = tokio::time::timeout(TERM_GRACE, child.wait()).await;
    if graceful.is_err() {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}

/// Drain + reap an outgoing process in the background (graceful upgrade): SIGQUIT
/// so pingora hands off its fds and drains in-flight connections, then force it
/// if it overstays the grace window.
fn drain_reaper(mut old: SpawnedChild) {
    tokio::spawn(async move {
        #[cfg(unix)]
        // SAFETY: SIGQUIT to a pid we spawned and still own the Child for; ESRCH
        // (already exited) is benign and ignored.
        unsafe {
            libc::kill(old.pid as i32, libc::SIGQUIT);
        }
        let _ = tokio::time::timeout(TERM_GRACE, old.child.wait()).await;
        if matches!(old.child.try_wait(), Ok(None)) {
            let _ = old.child.start_kill();
            let _ = old.child.wait().await;
        }
    });
}

/// The signal that killed a child, if one did.
///
/// `ExitStatus::code()` is `None` for a signalled process and says nothing about
/// which signal, so the OOM classification cannot be built on it. Unix-only by
/// nature; a non-unix build has no signals to report and classifies on the exit
/// code alone.
#[cfg(unix)]
fn exit_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

/// Render a leaf's counters for a log line / status reason. Absent counters are
/// **omitted**, never printed as `0` — see [`crate::cgroup::CgroupHandle::read_stats`]
/// for why "not measured" and "measured zero" must not collapse. An entirely
/// unmeasured leaf renders as the empty string, so the caller's message reads
/// the same as it did before this ticket on a host with no cgroup subtree.
pub(crate) fn format_stats(stats: &crate::cgroup::CgroupStats) -> String {
    let mut parts = Vec::new();
    if let Some(peak) = stats.memory_peak_bytes {
        parts.push(format!("memory.peak={peak}B"));
    }
    if let Some(oom) = stats.oom_kill {
        parts.push(format!("oom_kill={oom}"));
    }
    if let Some(group) = stats.oom_group_kill {
        parts.push(format!("oom_group_kill={group}"));
    }
    if let Some(throttled) = stats.cpu_nr_throttled {
        // Periods rides along only when there was throttling to put in context.
        match (throttled, stats.cpu_nr_periods) {
            (0, _) => parts.push("cpu.nr_throttled=0".to_string()),
            (n, Some(periods)) => parts.push(format!("cpu.nr_throttled={n}/{periods}")),
            (n, None) => parts.push(format!("cpu.nr_throttled={n}")),
        }
    }
    if let Some(usec) = stats.cpu_throttled_usec {
        parts.push(format!("cpu.throttled_usec={usec}"));
    }
    if let Some(pids) = stats.pids_current {
        parts.push(format!("pids.current={pids}"));
    }
    parts.join(" ")
}

/// The sentence that goes into [`WorkloadStatus::Failed`]'s `reason`.
///
/// `reason` is node-local: it does **not** reach yubaba, because the postcard
/// `WorkloadState` this flattens into (`kamaji-bin`'s `runtime_state_to_entry`)
/// is a fieldless enum with nowhere to carry it. That is R885-F3's deliberate
/// stopping point rather than an oversight — see this module's ticket block and
/// R885-T6, which carries the wire delta. Naming the OOM here and in the log
/// line is what collapses the R590-B10 diagnosis; the upward report is the
/// version bump's job.
fn describe_exit(
    class: crate::cgroup::ExitClass,
    status: &std::process::ExitStatus,
    stats: &crate::cgroup::CgroupStats,
) -> String {
    use crate::cgroup::ExitClass;
    let detail = format_stats(stats);
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!(" [{detail}]")
    };
    match class {
        ExitClass::OomKilled { signal } => format!(
            "OOM-killed by the kernel (signal {signal}); the workload exceeded its memory.max{detail}"
        ),
        ExitClass::ExitedUnderOom { exit_code } => format!(
            "exited with code {exit_code} after a descendant was OOM-killed against its memory.max{detail}"
        ),
        ExitClass::Signaled { .. } | ExitClass::Exited { .. } => {
            format!("exited with {status}{detail}")
        }
    }
}

/// Publish one run's cgroup telemetry to the node's journal (R885-F3).
///
/// `warn!` for an OOM and `debug!` otherwise, on the same reasoning R605-F31's
/// microVM terminal-status line settled: an ordinary exit is this backend's
/// routine business and a crash loop must not flood the journal, but an OOM is
/// a *capacity* fact an operator needs named at the node, and it is the only
/// place it is named at all until the wire carries it.
fn log_exit_telemetry(
    workload: &str,
    class: crate::cgroup::ExitClass,
    stats: &crate::cgroup::CgroupStats,
) {
    use crate::cgroup::ExitClass;
    let detail = format_stats(stats);
    match class {
        ExitClass::OomKilled { signal } => tracing::warn!(
            workload = %workload,
            signal,
            cgroup = %detail,
            "native backend: workload was OOM-killed — it exceeded its memory.max, not an ordinary crash (R885-F3)"
        ),
        ExitClass::ExitedUnderOom { exit_code } => tracing::warn!(
            workload = %workload,
            exit_code,
            cgroup = %detail,
            "native backend: a descendant of this workload was OOM-killed against its memory.max (R885-F3)"
        ),
        ExitClass::Signaled { signal } => tracing::debug!(
            workload = %workload,
            signal,
            cgroup = %detail,
            "native backend: workload was signalled; no OOM kill recorded against its cgroup"
        ),
        ExitClass::Exited { exit_code } => tracing::debug!(
            workload = %workload,
            exit_code,
            cgroup = %detail,
            "native backend: workload exited"
        ),
    }
}

/// Everything [`crate::supervise::supervise`] needs to re-exec this workload's
/// child, and nothing else.
///
/// The retained [`WorkloadSpec`] is the load-bearing field (R591-F1): a respawn
/// re-execs from the spec that was deployed, so a crash-looping workload keeps
/// running the argv, env and config files it was admitted with rather than
/// whatever the caller happens to still hold.
struct NativeProcess {
    state_dir: PathBuf,
    spec: WorkloadSpec,
    mesh_ip: Ipv4Addr,
    /// The workload's cgroup leaf (R885-B1), retained for the same reason the
    /// spec is: a respawn must land in the same ceiling the first run had, and
    /// the leaf outlives any individual child.
    cgroup: Option<crate::cgroup::CgroupHandle>,
    /// Retained for the same reason the spec is (R893-B17): a respawn must see
    /// the same collector the first run did, or a crash-looping workload would
    /// stop reporting the very restarts an operator is trying to read.
    collector: crate::observe::Collector,
    /// `memory.events`' `oom_kill` as of the last settled exit (R885-F3).
    ///
    /// The counter is cumulative over the **workload node's** life and the node
    /// outlives every restart — and, since R885-B4, every generation, which is
    /// why that ticket's deeper hierarchy did not retire this field the way it
    /// might look like it should. It stays nonzero forever after the first
    /// OOM (the counters are hierarchical, so the node's reading already
    /// includes every generation beneath it). Testing
    /// it for nonzero would therefore relabel every subsequent crash of a
    /// workload that OOMed once — the false-positive direction, and the one that
    /// matters, because a wrong "OOM" sends an operator to raise a ceiling that
    /// was never the problem. [`Supervised::settle`] diffs against this and then
    /// stores the new total, so what reaches [`crate::cgroup::classify_exit`] is
    /// always "OOM kills during *this* run".
    ///
    /// `0` is the right initial value: `deploy_workload` tears the predecessor
    /// down and `mkdir`s a fresh node immediately before the first child, so
    /// there is no prior history to miss.
    oom_kills_settled: std::sync::atomic::AtomicU64,
}

#[async_trait]
impl Supervised for NativeProcess {
    type Instance = SpawnedChild;

    fn pid(&self, inst: &SpawnedChild) -> u32 {
        inst.pid
    }

    async fn wait(&self, inst: &mut SpawnedChild) -> Exit {
        inst.child.wait().await
    }

    /// Respawns **append** to the capture files rather than truncating them, so
    /// a crash loop's history survives the loop that produced it.
    async fn start(&self) -> Result<SpawnedChild> {
        spawn_child(
            &self.state_dir,
            &self.spec,
            self.mesh_ip,
            &[],
            false,
            self.cgroup.as_ref(),
            &self.collector,
        )
        .await
    }

    async fn stop(&self, inst: &mut SpawnedChild) {
        stop_child(&mut inst.child, inst.pid).await
    }

    /// A host process's exit status is **almost** the whole story — there is no
    /// second channel the way the microVM backend has one, but since R885-B1 put
    /// a real `memory.max` on the live path there is a second *reading*, and
    /// R885-F3 takes it here.
    ///
    /// An exit status of `Signaled(SIGKILL)` is what an OOM kill, an operator's
    /// `kill -9` and this supervisor's own escalation after [`TERM_GRACE`] all
    /// look like; `memory.events`' `oom_kill` is the only thing that separates
    /// them, and until this ticket nothing read it. R590-B10 is the standing
    /// scar — a forge workload SIGKILLed against a 256 MB ceiling, diagnosed by
    /// disk forensics and stopgapped by raising the ceiling to 32 GiB.
    ///
    /// **This is the right place for the read and there is not a second one.**
    /// The counters live in the leaf, the leaf is `rmdir`ed by
    /// [`NativeRuntime::teardown_workload`], and `settle` runs inside the
    /// supervisor task the instant [`Supervised::wait`] returns — before the
    /// teardown that would remove them can be acknowledged. Reading any later
    /// races the `rmdir` and loses the evidence exactly when a workload is dying.
    async fn settle(&self, exit: Exit) -> Completion {
        let exit_code = match &exit {
            Ok(s) => s.code().unwrap_or(-1),
            Err(_) => -1,
        };
        let succeeded = matches!(&exit, Ok(s) if s.success());
        let signal = match &exit {
            Ok(s) => exit_signal(s),
            Err(_) => None,
        };

        let stats = self
            .cgroup
            .as_ref()
            .map(|cg| cg.read_stats())
            .unwrap_or_default();
        // Diff, don't test for nonzero — see `oom_kills_settled`. `None` leaves
        // the baseline untouched: an unreadable counter is not evidence that the
        // leaf's history restarted.
        let oom_kills_this_run = stats.oom_kill.map(|total| {
            let previous = self
                .oom_kills_settled
                .swap(total, std::sync::atomic::Ordering::SeqCst);
            total.saturating_sub(previous)
        });
        let class = crate::cgroup::classify_exit(signal, exit_code, oom_kills_this_run);

        log_exit_telemetry(&self.spec.expose.mesh.identity.0, class, &stats);

        Completion {
            succeeded,
            exit_code,
            terminal: if succeeded {
                WorkloadStatus::Stopped
            } else {
                WorkloadStatus::Failed {
                    reason: match &exit {
                        Ok(s) => format!("{} (no restart)", describe_exit(class, s, &stats)),
                        Err(e) => format!("wait failed: {e}"),
                    },
                    // The one place in the tree that can answer this — the
                    // counters live in the leaf and `settle` is the only read
                    // that beats the teardown's rmdir. R885-T6 carries it from
                    // here to `WorkloadState::OomKilled` on the wire.
                    oom_killed: class.is_oom(),
                }
            },
        }
    }

    fn discard(&self, replaced: SpawnedChild) {
        drain_reaper(replaced)
    }
}

#[async_trait]
impl Kamaji for NativeRuntime {
    fn backend(&self) -> Backend {
        Backend::Native
    }

    async fn deploy_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> Result<DeployResult> {
        if spec.replicas > 1 {
            return Err(anyhow!(
                "workload {}: Backend::Native supervises a single replica (got replicas={})",
                spec.name,
                spec.replicas
            ));
        }

        // Signed-recipe admission (R555-F4 / W235 §(c)). This backend fork+execs
        // on the host with no container boundary at all, so an un-admitted argv
        // here is worth strictly more to an attacker than the same argv on the
        // containerd path — the check belongs here first, not last.
        workload_spec::admission::check(spec)
            .map_err(|e| anyhow!("workload {} not admitted: {e}", spec.name))?;

        // R844-F21: `ports = ["http", "wss"]` is a request, not a fact. Settle
        // it here, before the fork, and write the numbers back onto the spec —
        // then the `PORT_<NAME>` env the child reads, `declared_port_names`,
        // `DeployResult::ports` and the service record downstream of them all
        // derive from ONE set of numbers instead of from a declaration and a
        // measurement that are free to disagree.
        let allocated = self.resolve_declared_ports(spec, mesh.mesh_ip)?;
        let spec = allocated.as_ref().unwrap_or(spec);

        let ident = spec.expose.mesh.identity.clone();

        // Idempotent: clear any prior workload with the same identity.
        self.teardown_workload(&ident).await?;

        // R885-B1: mint the cgroup leaf BEFORE the fork. A failure here fails
        // the deploy rather than degrading to an unbounded fork — this runtime
        // already decided at startup whether the host can confine anything
        // (`self.cgroup`), so a failure at this point means the subtree it
        // verified has gone wrong underneath us, which is worth surfacing.
        let cgroup = self
            .cgroup
            .as_ref()
            .map(|cg| {
                cg.create_workload(&ident.0, &crate::cgroup::WorkloadLimits::from_spec(spec))
            })
            .transpose()
            .with_context(|| format!("creating the cgroup leaf for workload {}", spec.name))?;

        // Spawn the first child synchronously so spawn errors (bad binary path,
        // empty argv) surface to the caller instead of failing in the
        // background supervisor.
        let initial = spawn_child(
            &self.state_dir,
            spec,
            mesh.mesh_ip,
            &[],
            true,
            cgroup.as_ref(),
            &self.collector,
        )
        .await?;
        let start_pid = initial.pid;
        let stdout_path = initial.stdout_path.clone();
        let stderr_path = initial.stderr_path.clone();

        let pid = Arc::new(AtomicU32::new(start_pid));
        let (status_tx, status_rx) = watch::channel(WorkloadStatus::Running);
        let (ctrl_tx, ctrl_rx) = mpsc::channel(8);
        let task = tokio::spawn(supervise(
            NativeProcess {
                state_dir: self.state_dir.clone(),
                spec: spec.clone(),
                mesh_ip: mesh.mesh_ip,
                cgroup: cgroup.clone(),
                collector: self.collector.clone(),
                // A freshly minted leaf has no OOM history — see the field doc.
                oom_kills_settled: std::sync::atomic::AtomicU64::new(0),
            },
            spec.restart_policy.clone(),
            initial,
            Arc::clone(&pid),
            status_tx,
            ctrl_rx,
        ));

        self.workloads.lock().await.insert(
            ident.0,
            WorkloadHandle {
                mesh_ip: mesh.mesh_ip,
                name: spec.name.clone(),
                ports: crate::declared_port_names(&spec.expose.mesh),
                stdout_path,
                stderr_path,
                cgroup,
                pid,
                status: status_rx,
                ctrl: ctrl_tx,
                task,
            },
        );

        Ok(DeployResult {
            container_id: format!("native-{start_pid}"),
            mesh_ip: mesh.mesh_ip,
            task_pid: start_pid,
            hydrate: None,
            ports: crate::declared_port_names(&spec.expose.mesh),
        })
    }

    async fn list_workloads(&self) -> Result<Vec<WorkloadState>> {
        let map = self.workloads.lock().await;
        Ok(map
            .iter()
            .map(|(ident, h)| WorkloadState {
                ident: MeshIdent(ident.clone()),
                container_id: format!("native-{}", h.pid.load(Ordering::SeqCst)),
                status: h.status.borrow().clone(),
                mesh_ip: Some(h.mesh_ip),
                ports: h.ports.clone(),
            })
            .collect())
    }

    async fn get_workload(&self, ident: &MeshIdent) -> Result<Option<WorkloadState>> {
        let map = self.workloads.lock().await;
        Ok(map.get(&ident.0).map(|h| WorkloadState {
            ident: ident.clone(),
            container_id: format!("native-{}", h.pid.load(Ordering::SeqCst)),
            status: h.status.borrow().clone(),
            mesh_ip: Some(h.mesh_ip),
            ports: h.ports.clone(),
        }))
    }

    async fn stream_logs(&self, ident: &MeshIdent, opts: LogOpts) -> Result<LogStream> {
        let (stdout_path, stderr_path) = {
            let map = self.workloads.lock().await;
            let h = map
                .get(&ident.0)
                .ok_or_else(|| anyhow!("no native workload with identity {}", ident.0))?;
            (h.stdout_path.clone(), h.stderr_path.clone())
        };

        let want = |kind: LogStreamKind| match opts.stream {
            None => true,
            Some(k) => k == kind,
        };

        let mut events: Vec<LogEvent> = Vec::new();
        for (path, kind) in [
            (stdout_path, LogStreamKind::Stdout),
            (stderr_path, LogStreamKind::Stderr),
        ] {
            if !want(kind) {
                continue;
            }
            let Ok(file) = tokio::fs::File::open(&path).await else {
                continue;
            };
            let mut lines = tokio::io::BufReader::new(file).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                events.push(LogEvent::plain(ident.clone(), kind, line));
            }
        }
        if let Some(tail) = opts.tail {
            let keep = tail as usize;
            if events.len() > keep {
                events.drain(..events.len() - keep);
            }
        }
        // No follow — replay the capture and end the stream.
        Ok(Box::pin(tokio_stream::iter(events)))
    }

    async fn restart_workload(&self, ident: &MeshIdent) -> Result<()> {
        let ctrl = {
            let map = self.workloads.lock().await;
            map.get(&ident.0).map(|h| h.ctrl.clone())
        };
        let Some(ctrl) = ctrl else {
            return Err(anyhow!("no native workload with identity {}", ident.0));
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        ctrl.send(Ctrl::Restart(ack_tx))
            .await
            .map_err(|_| anyhow!("supervisor for {} is gone", ident.0))?;
        ack_rx
            .await
            .map_err(|_| anyhow!("supervisor for {} dropped before restart ack", ident.0))??;
        Ok(())
    }

    /// Native graceful upgrade (R600-F4): spawn a replacement in pingora upgrade
    /// mode, let it inherit the listeners over the shared `PASSWAY_UPGRADE_SOCK`,
    /// then hand it to the supervisor to adopt (which SIGQUITs the old process so
    /// it drains and exits). Both processes run on this host, so no namespace
    /// juggling is needed — the shared upgrade-socket path (in the spec's env) is
    /// all pingora's fd-handoff requires. If no instance is running, this
    /// degenerates to a plain deploy (idempotent).
    async fn graceful_upgrade_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> Result<DeployResult> {
        let ident = spec.expose.mesh.identity.clone();

        let ctrl = {
            let map = self.workloads.lock().await;
            map.get(&ident.0).map(|h| h.ctrl.clone())
        };
        let Some(ctrl) = ctrl else {
            // Nothing to hand off from — a graceful upgrade of an absent
            // workload is just a deploy.
            return self.deploy_workload(spec, mesh).await;
        };
        // The replacement joins the LEAF THE OUTGOING GENERATION IS IN, not a
        // fresh one: for the duration of the handoff both processes are alive
        // and serving the same listener, so they are one workload and share one
        // ceiling.
        //
        // R885-B4 made the ceiling a property of the workload NODE rather than
        // of the leaf, so sharing the ceiling no longer requires sharing the
        // directory — but this site still shares it, deliberately. Minting a
        // generation here would leave `NativeProcess` holding a handle onto the
        // leaf it no longer runs in, and `Supervised::start` respawns a crashed
        // child into exactly that handle; the outgoing generation's directory
        // would then be both destroyed and restarted into. Carrying a fresh
        // handle through `Ctrl::Adopt` is what that needs, and neither defect
        // B4 exists for requires it: the race is a redeploy's teardown against
        // its own re-create, and a handoff `rmdir`s nothing.
        let cgroup = {
            let map = self.workloads.lock().await;
            map.get(&ident.0).and_then(|h| h.cgroup.clone())
        };

        // 1. Start the replacement in upgrade mode. It connects to the shared
        //    upgrade socket and receives the old process's listening fds instead
        //    of binding fresh.
        let mut replacement = spawn_child(
            &self.state_dir,
            spec,
            mesh.mesh_ip,
            &[("PASSWAY_UPGRADE", "true")],
            false,
            cgroup.as_ref(),
            &self.collector,
        )
        .await
        .context("spawning graceful-upgrade replacement")?;
        let new_pid = replacement.pid;

        // 2. Let the replacement settle (connect + take over listeners). If it
        //    died immediately (e.g. an unreadable cert), abort WITHOUT touching
        //    the old process — the live listener keeps serving the previous cert
        //    rather than dropping to nothing.
        tokio::time::sleep(UPGRADE_SETTLE).await;
        if let Ok(Some(status)) = replacement.child.try_wait() {
            stop_child(&mut replacement.child, new_pid).await;
            return Err(anyhow!(
                "workload {}: graceful-upgrade replacement exited during handoff ({status}); \
                 old instance left running",
                ident.0
            ));
        }

        // 3. Hand the replacement to the supervisor: it swaps to the new child
        //    and drains+reaps the outgoing one (SIGQUIT → grace → SIGKILL).
        let (ack_tx, ack_rx) = oneshot::channel();
        ctrl.send(Ctrl::Adopt {
            replacement,
            ack: ack_tx,
        })
        .await
        .map_err(|_| anyhow!("supervisor for {} is gone", ident.0))?;
        ack_rx
            .await
            .map_err(|_| anyhow!("supervisor for {} dropped before upgrade ack", ident.0))?;

        Ok(DeployResult {
            container_id: format!("native-{new_pid}"),
            mesh_ip: mesh.mesh_ip,
            task_pid: new_pid,
            hydrate: None,
            // A graceful upgrade is explicitly the *same* listener handed to a
            // new generation, so the resolved port is unchanged by construction.
            ports: crate::declared_port_names(&spec.expose.mesh),
        })
    }

    async fn teardown_workload(&self, ident: &MeshIdent) -> Result<()> {
        let handle = self.workloads.lock().await.remove(&ident.0);
        let Some(handle) = handle else {
            return Ok(());
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        // If the supervisor is still alive it stops the child and acks; if the
        // send fails the task already ended, so there's nothing left to stop.
        if handle.ctrl.send(Ctrl::Teardown(ack_tx)).await.is_ok() {
            let _ = ack_rx.await;
        }
        // The supervisor has stopped and reaped the child it owns. Anything the
        // workload double-forked away is NOT reaped by that — it was reparented
        // to init and is still sitting in the generation leaf. R885-B4's
        // `destroy_workload` is what reaches it: `cgroup.kill` (or a freeze +
        // `SIGKILL` sweep on a pre-5.14 kernel), then a bounded wait for the
        // leaf to drain, then the final counter read, then the `rmdir`.
        //
        // A failure is still logged and stepped over rather than propagated —
        // teardown's contract is idempotent success, and a leaked directory is
        // strictly better than a teardown the caller reads as "the workload is
        // still up". What changed is that reaching that branch now takes a
        // process the kernel itself could not kill, rather than any ordinary
        // double-fork.
        if let (Some(cg), true) = (self.cgroup.as_ref(), handle.cgroup.is_some()) {
            match cg.destroy_workload(&ident.0) {
                Ok(outcome) if outcome.leaked.is_empty() => tracing::debug!(
                    workload = %ident.0,
                    generations = outcome.removed,
                    kill = ?outcome.method,
                    telemetry = %format_stats(&outcome.stats),
                    "native backend: workload cgroup torn down"
                ),
                Ok(outcome) => tracing::warn!(
                    workload = %ident.0,
                    leaked = ?outcome.leaked,
                    kill = ?outcome.method,
                    telemetry = %format_stats(&outcome.stats),
                    "native backend: a workload cgroup generation could not be emptied — it and \
                     the ceiling above it are left in place so whatever survived stays bounded \
                     (R885-B4)"
                ),
                Err(e) => tracing::warn!(
                    workload = %ident.0,
                    error = %e,
                    "native backend: could not tear down the workload's cgroup (R885-B4)"
                ),
            }
        }
        Ok(())
    }

    async fn health(&self) -> Result<RuntimeHealth> {
        Ok(RuntimeHealth {
            ok: true,
            version: Some(format!("native/{}", env!("CARGO_PKG_VERSION"))),
            detail: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt as _;
    use workload_spec::{
        BackoffPolicy, ExposeSpec, ImageRef, MeshExpose, Millis, NamespaceId, ResourceLimits,
        RestartPolicy, StopPolicy, TenantId, TierTag,
    };

    fn native_spec(name: &str, argv: Vec<String>) -> WorkloadSpec {
        WorkloadSpec {
            name: name.to_string(),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            image: ImageRef {
                registry: "localhost".to_string(),
                repository: format!("native/{name}"),
                tag: "dev".to_string(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".to_string()),
            replicas: 1,
            command: Some(argv),
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
            files: vec![],
        }
    }

    // ── R885-F3: the OOM classification, driven through the real `settle`
    //    seam rather than through `classify_exit` alone. `cgroup.rs` owns the
    //    pure truth table; these pin that the supervisor actually reads the
    //    leaf, diffs the counter, and does not confuse the two kinds of kill.

    /// Build the `NativeProcess` the supervisor task holds, pointed at a real
    /// `CgroupHandle` over a tempdir leaf we can write counter files into.
    fn settle_fixture(name: &str) -> (tempfile::TempDir, NativeProcess) {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let cg = crate::cgroup::CgroupV2::new(&cgroup_root);
        let handle = cg
            .create_workload(
                name,
                &crate::cgroup::WorkloadLimits::from_request(&ResourceLimits {
                    memory_mb: 256,
                    cpu_millis: 500,
                    memory_request_mb: None,
                    cpu_limit_millis: None,
                    pids_max: None,
                    scratch_floor_mb: None,
                }),
            )
            .unwrap();
        let proc = NativeProcess {
            state_dir: tmp.path().join("state"),
            spec: native_spec(name, vec!["/bin/true".into()]),
            mesh_ip: Ipv4Addr::new(100, 64, 0, 9),
            cgroup: Some(handle),
            collector: crate::observe::Collector::disabled(),
            oom_kills_settled: std::sync::atomic::AtomicU64::new(0),
        };
        (tmp, proc)
    }

    fn write_oom_kill(proc: &NativeProcess, count: u64) {
        // R885-B4: the counters are on the workload NODE, not the generation
        // leaf — they are hierarchical, and the leaf carries no controller
        // files at all. This is the one line in the F3 fixtures that moved.
        let leaf = proc.cgroup.as_ref().unwrap().workload_path();
        std::fs::write(
            leaf.join("memory.events"),
            format!("low 0\nhigh 0\nmax 9\noom 1\noom_kill {count}\noom_group_kill 0\n"),
        )
        .unwrap();
    }

    /// `wait4` status word for "killed by `signal`" — what an OOM kill and a
    /// `kill -9` are equally indistinguishable as, before the counter is read.
    #[cfg(unix)]
    fn signalled(signal: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;
        std::process::ExitStatus::from_raw(signal)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_oom_killed_child_is_named_as_an_oom_at_the_settle_seam() {
        let (_tmp, proc) = settle_fixture("hungry");
        write_oom_kill(&proc, 1);

        let done = proc.settle(Ok(signalled(9))).await;

        assert!(!done.succeeded);
        let WorkloadStatus::Failed { reason, .. } = done.terminal else {
            panic!("a SIGKILLed child is a failure");
        };
        assert!(
            reason.contains("OOM-killed"),
            "the reason must name the OOM: {reason}"
        );
        assert!(
            reason.contains("memory.max"),
            "and point at what it exceeded: {reason}"
        );
    }

    /// The false-positive direction, which is the one that bites: a `kill -9`
    /// from an operator against a leaf that has never OOMed must not be dressed
    /// up as a capacity problem.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_plain_sigkill_is_not_misreported_as_an_oom() {
        let (_tmp, proc) = settle_fixture("shot");
        write_oom_kill(&proc, 0);

        let done = proc.settle(Ok(signalled(9))).await;

        let WorkloadStatus::Failed { reason, .. } = done.terminal else {
            panic!("a SIGKILLed child is a failure");
        };
        assert!(
            !reason.contains("OOM"),
            "a measured-zero counter is not an OOM: {reason}"
        );
        assert!(
            reason.contains("oom_kill=0"),
            "but it is reported: {reason}"
        );
    }

    /// A host with no delegated cgroup subtree reads nothing, and "we could not
    /// tell" must classify as the plain signal the whole fleet saw before this
    /// ticket — never as an invented OOM.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unmeasurable_host_reports_a_plain_signal_not_an_oom() {
        let (_tmp, mut proc) = settle_fixture("blind");
        proc.cgroup = None;

        let done = proc.settle(Ok(signalled(9))).await;

        let WorkloadStatus::Failed { reason, .. } = done.terminal else {
            panic!("a SIGKILLed child is a failure");
        };
        assert!(!reason.contains("OOM"), "no counter, no verdict: {reason}");
        assert!(
            !reason.contains("oom_kill"),
            "and an unmeasured counter is not printed as 0: {reason}"
        );
    }

    /// The reason the classifier takes a per-run **delta** and not the raw
    /// counter: `oom_kill` is cumulative over the leaf's life and the leaf
    /// outlives every restart, so a workload that OOMed once would otherwise
    /// have every later crash relabelled as an OOM forever.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stale_oom_count_from_an_earlier_run_does_not_taint_a_later_kill() {
        let (_tmp, proc) = settle_fixture("looper");

        write_oom_kill(&proc, 1);
        let first = proc.settle(Ok(signalled(9))).await;
        let WorkloadStatus::Failed { reason: first, .. } = first.terminal else {
            unreachable!()
        };
        assert!(
            first.contains("OOM-killed"),
            "run 1 really did OOM: {first}"
        );

        // Run 2: same leaf, counter unchanged — this kill was not an OOM.
        let second = proc.settle(Ok(signalled(9))).await;
        let WorkloadStatus::Failed { reason: second, .. } = second.terminal else {
            unreachable!()
        };
        assert!(
            !second.contains("OOM"),
            "an unchanged counter is not a second OOM: {second}"
        );

        // Run 3: the counter advances again — and it is an OOM again.
        write_oom_kill(&proc, 2);
        let third = proc.settle(Ok(signalled(9))).await;
        let WorkloadStatus::Failed { reason: third, .. } = third.terminal else {
            unreachable!()
        };
        assert!(third.contains("OOM-killed"), "a fresh kill counts: {third}");
    }

    /// R590-B10's actual shape: the root process exited nonzero of its own
    /// accord because a `rustc` beneath it was OOM-killed. Nothing was signalled,
    /// so only the counter can see it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_descendant_oom_is_named_even_though_the_root_exited_normally() {
        use std::os::unix::process::ExitStatusExt as _;
        let (_tmp, proc) = settle_fixture("forge");
        write_oom_kill(&proc, 1);

        // Exit code 101 (cargo's), not a signal.
        let done = proc
            .settle(Ok(std::process::ExitStatus::from_raw(101 << 8)))
            .await;

        let WorkloadStatus::Failed { reason, .. } = done.terminal else {
            panic!("a nonzero exit is a failure");
        };
        assert!(
            reason.contains("descendant was OOM-killed"),
            "the counter is the only witness: {reason}"
        );
    }

    /// The rest of the telemetry rides the same read, and an absent counter is
    /// omitted rather than printed as a measured zero.
    #[cfg(unix)]
    #[tokio::test]
    async fn peak_throttling_and_pids_ride_the_same_read() {
        let (_tmp, proc) = settle_fixture("noisy");
        // R885-B4: the workload NODE carries the counters, not the generation
        // leaf — see `write_oom_kill`.
        let leaf = proc.cgroup.as_ref().unwrap().workload_path().to_path_buf();
        write_oom_kill(&proc, 0);
        std::fs::write(leaf.join("memory.peak"), "268435456\n").unwrap();
        std::fs::write(
            leaf.join("cpu.stat"),
            "usage_usec 8000000\nnr_periods 400\nnr_throttled 37\nthrottled_usec 1250000\n",
        )
        .unwrap();
        // pids.current deliberately absent — R885-T2's undelegated-pids host.

        let done = proc.settle(Ok(signalled(9))).await;
        let WorkloadStatus::Failed { reason, .. } = done.terminal else {
            unreachable!()
        };
        assert!(reason.contains("memory.peak=268435456B"), "{reason}");
        assert!(reason.contains("cpu.nr_throttled=37/400"), "{reason}");
        assert!(reason.contains("cpu.throttled_usec=1250000"), "{reason}");
        assert!(
            !reason.contains("pids.current"),
            "an absent counter is omitted, not zeroed: {reason}"
        );
    }

    /// The live-workload half of the read path: counters for a workload that has
    /// not exited, which the exit-time reading can never provide.
    #[tokio::test]
    async fn telemetry_is_readable_while_the_workload_is_still_running() {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup_root = tmp.path().join("cgroup");
        let rt = NativeRuntime::with_cgroup_root(tmp.path().join("state"), &cgroup_root);
        let spec = native_spec("live", vec!["/bin/sleep".into(), "30".into()]);
        let ident = spec.expose.mesh.identity.clone();
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        rt.deploy_workload(&spec, &mesh).await.unwrap();

        std::fs::write(cgroup_root.join("live").join("pids.current"), "3\n").unwrap();

        let stats = rt.workload_telemetry(&ident).await.expect("a live leaf");
        assert_eq!(stats.pids_current, Some(3));
        assert_eq!(stats.oom_kill, None, "nothing wrote memory.events here");

        assert!(rt
            .workload_telemetry(&MeshIdent("absent".into()))
            .await
            .is_none());
        rt.teardown_workload(&ident).await.unwrap();
    }

    /// R885-B1 — THE CALL SITE, which is the whole point of that ticket.
    ///
    /// R406-T4 shipped a correct cgroup driver with passing tests that no
    /// running binary could reach; this asserts the opposite property, that the
    /// live `deploy_workload` path mints a per-workload leaf carrying the spec's
    /// limits and that `teardown_workload` reaps it. Pointed at a tempdir, so it
    /// runs on the camp Mac as well as on a node.
    #[tokio::test]
    async fn deploying_a_workload_mints_a_cgroup_leaf_carrying_its_limits() {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup_root = tmp.path().join("cgroup-root");
        let runtime = NativeRuntime::with_cgroup_root(tmp.path().join("state"), &cgroup_root);

        let spec = native_spec("native-cgroup", vec!["/bin/sh".into(), "-c".into(), "exit 0".into()]);
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        runtime.deploy_workload(&spec, &mesh).await.unwrap();

        let leaf = cgroup_root.join("native-cgroup");
        assert!(leaf.is_dir(), "deploy did not create {}", leaf.display());
        // native_spec declares 64 MiB / 128 millicores.
        assert_eq!(
            std::fs::read_to_string(leaf.join("memory.max")).unwrap(),
            (64u64 * 1024 * 1024).to_string()
        );
        // R885-B5: 128m is a REQUEST, so it renders as a relative weight and
        // NOT as a quota. This is the test that proves an ordinary workload
        // stops being throttled — before B5 this leaf carried
        // `cpu.max = 12800 100000`, capping it at 0.128 of a core on an idle
        // node.
        assert_eq!(
            std::fs::read_to_string(leaf.join("cpu.weight")).unwrap(),
            "12"
        );
        assert!(
            !leaf.join("cpu.max").exists(),
            "a spec with no yah.limits.cpu-millis must leave cpu.max unwritten"
        );
        // R885-T2: `with_cgroup_root` never calls `ensure_root`, so `pids` was
        // never (attempted to be) enabled here — this pins the call site's
        // best-effort degrade the same way the assertion above pins cpu.max.
        assert!(
            !leaf.join("pids.max").exists(),
            "pids.max must not be written when the controller was never enabled"
        );

        runtime
            .teardown_workload(&spec.expose.mesh.identity)
            .await
            .unwrap();
        // A tempdir has the control files as ordinary files, which a real
        // cgroupfs removes with the directory — clear them, then the rmdir the
        // teardown already attempted is observable as "nothing left holding it".
        for f in ["cpu.weight", "cpu.max", "memory.max"] {
            let _ = std::fs::remove_file(leaf.join(f));
        }
        assert!(
            std::fs::remove_dir(&leaf).is_ok() || !leaf.exists(),
            "the leaf was left holding something after teardown"
        );
    }

    // ── R885-B4 at the CALL SITE. The driver's own tests in `cgroup.rs` prove
    //    the mechanism; these prove the live `deploy_workload` /
    //    `teardown_workload` path actually drives it — which is the property
    //    R885-B1's first gotcha exists to insist on.

    /// The generation directories under a workload node, oldest first.
    fn generations(node: &Path) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(node) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The R885-B4 race, driven through the real deploy path: a rolling
    /// replacement of one ident must not hand the incoming process the
    /// directory the outgoing one is being torn out of. Two deploys, two
    /// distinct generation leaves, one surviving, and one ceiling throughout.
    #[tokio::test]
    async fn a_redeploy_mints_a_new_generation_beside_the_same_ceiling() {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup_root = tmp.path().join("cgroup-root");
        let runtime = NativeRuntime::with_cgroup_root(tmp.path().join("state"), &cgroup_root);
        let spec = native_spec("rolling", vec!["/bin/sleep".into(), "30".into()]);
        let ident = spec.expose.mesh.identity.clone();
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

        runtime.deploy_workload(&spec, &mesh).await.unwrap();
        let node = cgroup_root.join("rolling");
        let first = generations(&node);
        assert_eq!(first.len(), 1, "one deploy, one generation: {first:?}");

        // `deploy_workload` tears the predecessor down before it creates, so
        // this single call IS the rolling replacement.
        runtime.deploy_workload(&spec, &mesh).await.unwrap();
        let second = generations(&node);
        assert_eq!(
            second.len(),
            1,
            "the outgoing generation's leaf was left behind: {second:?}"
        );
        assert_ne!(
            first, second,
            "the redeploy landed in the outgoing generation's directory — the R885-B4 race"
        );
        // One workload, one ceiling: the node is shared and rewritten, not
        // duplicated per generation.
        assert_eq!(
            std::fs::read_to_string(node.join("memory.max")).unwrap(),
            (64u64 * 1024 * 1024).to_string()
        );

        runtime.teardown_workload(&ident).await.unwrap();
        assert!(
            generations(&node).is_empty(),
            "teardown left a generation leaf: {:?}",
            generations(&node)
        );
    }

    /// The other defect, through the real `teardown_workload`: a descendant the
    /// workload double-forked away is not reachable by the `SIGTERM`/`SIGKILL`
    /// the supervisor aims at its own child, and before R885-B4 it was left
    /// running with the `rmdir` failing `EBUSY` and nothing to do about it.
    #[cfg(unix)]
    #[tokio::test]
    async fn teardown_kills_a_double_forked_descendant_the_supervisor_cannot_reach() {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup_root = tmp.path().join("cgroup-root");
        let runtime = NativeRuntime::with_cgroup_root(tmp.path().join("state"), &cgroup_root);
        let spec = native_spec("forker", vec!["/bin/sleep".into(), "30".into()]);
        let ident = spec.expose.mesh.identity.clone();
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        runtime.deploy_workload(&spec, &mesh).await.unwrap();

        let node = cgroup_root.join("forker");
        let leaf = node.join(&generations(&node)[0]);

        // A real orphan: `sh` backgrounds a `sleep` and exits, so the `sleep` is
        // reparented to init and is nobody's child. Recorded in the leaf's
        // `cgroup.procs` the way a kernel would — the pre-exec attach hook opens
        // that path without `O_CREAT`, so against a tempdir nothing else does.
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30 >/dev/null 2>&1 & echo $!")
            .output()
            .unwrap();
        let orphan: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
        std::fs::write(leaf.join("cgroup.procs"), format!("{orphan}\n")).unwrap();
        assert!(
            unsafe { libc::kill(orphan as libc::pid_t, 0) } == 0,
            "fixture premise: the orphan must be running before teardown"
        );

        runtime.teardown_workload(&ident).await.unwrap();

        assert!(
            unsafe { libc::kill(orphan as libc::pid_t, 0) } != 0,
            "the double-forked descendant outlived teardown_workload"
        );
    }

    /// R885-F3 under R885-B4's hierarchy, through the real deploy path. The
    /// directory a child is attached to and the directory an OOM is counted in
    /// are no longer the same one, so this pins that the read still follows the
    /// node — a reader that followed the processes would report `None` and
    /// classify every OOM as an ordinary crash, silently.
    #[tokio::test]
    async fn an_oom_is_still_classified_through_the_real_deploy_path() {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup_root = tmp.path().join("cgroup-root");
        let runtime = NativeRuntime::with_cgroup_root(tmp.path().join("state"), &cgroup_root);
        let spec = native_spec("oomer", vec!["/bin/sleep".into(), "30".into()]);
        let ident = spec.expose.mesh.identity.clone();
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        runtime.deploy_workload(&spec, &mesh).await.unwrap();

        let node = cgroup_root.join("oomer");
        let leaf = node.join(&generations(&node)[0]);
        assert_ne!(leaf, node, "the premise: the two levels are distinct");

        std::fs::write(
            node.join("memory.events"),
            "low 0\nhigh 0\nmax 4\noom 1\noom_kill 1\noom_group_kill 0\n",
        )
        .unwrap();

        let stats = runtime
            .workload_telemetry(&ident)
            .await
            .expect("a live node");
        assert_eq!(
            stats.oom_kill,
            Some(1),
            "the node's counter did not reach the read path"
        );
        assert!(
            crate::cgroup::classify_exit(Some(9), -1, stats.oom_kill).is_oom(),
            "F3's classification stopped firing under the generation hierarchy"
        );

        runtime.teardown_workload(&ident).await.unwrap();
    }

    /// R885-B5, the other shape: a workload that explicitly asks for a ceiling
    /// gets one. `resources.cpu_limit_millis` is the only thing that may put a
    /// quota in `cpu.max`, and it is independent of the request in `cpu_millis`.
    #[tokio::test]
    async fn a_declared_cpu_ceiling_renders_as_cpu_max() {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup_root = tmp.path().join("cgroup-root");
        let runtime = NativeRuntime::with_cgroup_root(tmp.path().join("state"), &cgroup_root);

        let mut spec = native_spec("native-capped", vec!["/bin/sh".into(), "-c".into(), "exit 0".into()]);
        spec.resources.cpu_limit_millis = Some(500);
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        runtime.deploy_workload(&spec, &mesh).await.unwrap();

        let leaf = cgroup_root.join("native-capped");
        // The request is untouched by the ceiling: still 128m of weight.
        assert_eq!(
            std::fs::read_to_string(leaf.join("cpu.weight")).unwrap(),
            "12"
        );
        // 500m ceiling = half a core per 100ms period.
        assert_eq!(
            std::fs::read_to_string(leaf.join("cpu.max")).unwrap(),
            "50000 100000"
        );

        runtime
            .teardown_workload(&spec.expose.mesh.identity)
            .await
            .unwrap();
    }

    /// The other half: a host with no delegated subtree must still deploy.
    /// `NativeRuntime::new` on this Mac resolves no cgroup at all, so this is
    /// the shape every non-Linux and every non-systemd run takes, and it must
    /// stay a working unbounded fork rather than a refusal.
    #[tokio::test]
    async fn a_host_without_a_delegated_subtree_still_deploys() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        assert!(
            runtime.cgroup.is_none(),
            "the camp Mac has no delegated cgroup subtree; this test's premise is gone"
        );
        let spec = native_spec("native-uncgrouped", vec!["/bin/sh".into(), "-c".into(), "exit 0".into()]);
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        runtime.deploy_workload(&spec, &mesh).await.unwrap();
        runtime
            .teardown_workload(&spec.expose.mesh.identity)
            .await
            .unwrap();
    }

    /// R870-F23. The inner door reads its whole route table out of a file the
    /// spec carries, so the guarantee under test is ordering: by the time the
    /// child execs, the file is on disk with the *current* spec's bytes.
    #[tokio::test]
    async fn spec_files_are_written_before_the_child_reads_them() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let routes = tmp.path().join("nested/dir/inner.routes.json");
        let echoed = tmp.path().join("echoed.txt");

        let mut spec = native_spec(
            "native-files",
            vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("cat {} > {}", routes.display(), echoed.display()),
            ],
        );
        spec.files = vec![workload_spec::InlineFile {
            path: routes.clone(),
            content: "{\"schema_version\":1,\"routes\":[]}".to_string(),
            mode: Some(0o600),
        }];

        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        runtime.deploy_workload(&spec, &mesh).await.unwrap();

        // Parent directories were created for us.
        assert_eq!(
            std::fs::read_to_string(&routes).unwrap(),
            "{\"schema_version\":1,\"routes\":[]}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&routes).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "declared mode is applied");
        }

        // The child could actually read it — i.e. the write happened first,
        // not merely at some point during the deploy.
        for _ in 0..50 {
            if std::fs::read_to_string(&echoed).is_ok_and(|s| s.contains("schema_version")) {
                runtime.teardown_workload(&spec.expose.mesh.identity).await.unwrap();
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("child never read the materialized file at {}", routes.display());
    }

    /// The negative for every backend that does NOT write them: refuse the
    /// spec rather than start a process against a file that is not there.
    ///
    /// Docker is the stand-in now that containerd writes (R870-F27). Pinned
    /// against the predicate rather than against a hard-coded pair, so a
    /// backend that learns to materialize has to move
    /// [`crate::Backend::materializes_files`] — the one place both halves of
    /// the contract read — and cannot do it by editing a test.
    #[test]
    fn a_backend_that_cannot_materialize_files_refuses_the_spec() {
        let mut spec = native_spec("no-files-here", vec!["/bin/true".into()]);
        assert!(crate::reject_unmaterializable_files(&spec, crate::Backend::Docker).is_ok());

        spec.files = vec![workload_spec::InlineFile {
            path: "/etc/passway/inner.routes.json".into(),
            content: "{}".into(),
            mode: None,
        }];
        let err = crate::reject_unmaterializable_files(&spec, crate::Backend::Docker)
            .expect_err("docker does not write spec files")
            .to_string();
        assert!(err.contains("/etc/passway/inner.routes.json"), "{err}");
        assert!(err.contains("Docker"), "{err}");

        // And the two that DO write accept it — the half that would otherwise
        // rot into a guard nobody notices has been left on.
        for backend in [crate::Backend::Native, crate::Backend::Containerd] {
            assert!(
                backend.materializes_files(),
                "{backend:?} is expected to write WorkloadSpec::files"
            );
            assert!(crate::reject_unmaterializable_files(&spec, backend).is_ok());
        }
    }

    #[tokio::test]
    async fn deploy_status_logs_teardown_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let spec = native_spec(
            "native-smoke",
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo hello-native; sleep 30".into(),
            ],
        );
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

        let deployed = runtime.deploy_workload(&spec, &mesh).await.unwrap();
        assert!(deployed.task_pid > 0);

        let ident = spec.expose.mesh.identity.clone();
        let state = runtime.get_workload(&ident).await.unwrap().unwrap();
        assert_eq!(state.status, WorkloadStatus::Running);

        // stdout capture made it to the log stream.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut logs = runtime
            .stream_logs(
                &ident,
                LogOpts {
                    tail: None,
                    follow: false,
                    stream: None,
                    cursor: None,
                },
            )
            .await
            .unwrap();
        let mut saw = false;
        while let Some(ev) = logs.next().await {
            if ev.message.contains("hello-native") {
                saw = true;
            }
        }
        assert!(saw, "expected captured stdout line");

        runtime.teardown_workload(&ident).await.unwrap();
        assert!(runtime.get_workload(&ident).await.unwrap().is_none());
        // Idempotent.
        runtime.teardown_workload(&ident).await.unwrap();
    }

    /// R844-T13: a native child learns its port from `PORT` / `PORT_HTTP`, one
    /// contract, off the same map `WorkloadState::ports` reports. Driven through
    /// a real fork rather than asserted on the map, because the bug this
    /// prevents is the injection being skipped, not the map being wrong.
    #[tokio::test]
    async fn a_native_child_reads_its_port_from_the_one_env_contract() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let mut spec = native_spec(
            "native-port-env",
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo port=$PORT; echo port_http=$PORT_HTTP; \
                 echo legacy=$KAMAJI_BUNDLE_PORT/$MF_PORT; sleep 30"
                    .into(),
            ],
        );
        spec.expose.mesh.ports = MeshExpose::anonymous_ports([48211]);
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        runtime.deploy_workload(&spec, &mesh).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut logs = runtime
            .stream_logs(
                &ident,
                LogOpts {
                    tail: None,
                    follow: false,
                    stream: None,
                    cursor: None,
                },
            )
            .await
            .unwrap();
        let mut captured = String::new();
        while let Some(ev) = logs.next().await {
            captured.push_str(&ev.message);
            captured.push('\n');
        }
        runtime.teardown_workload(&ident).await.unwrap();

        assert!(
            captured.contains("port=48211"),
            "bare PORT is the alias a single-listener workload reads; got:\n{captured}"
        );
        assert!(
            captured.contains("port_http=48211"),
            "PORT_HTTP must be the same number, not a second fact; got:\n{captured}"
        );
        assert!(
            captured.contains("legacy=/"),
            "neither retired spelling may be produced; got:\n{captured}"
        );
    }

    /// R844-F21: `ports = ["http", "wss"]` binds something.
    ///
    /// Driven through a REAL fork rather than asserted on the returned map,
    /// because "the allocator returned two numbers" was already true before
    /// this ticket and bought nothing — the gap was that no number ever reached
    /// a process. So the assertion is that the child *read* them, and that the
    /// numbers it read are the ones `DeployResult` published.
    #[tokio::test]
    async fn a_manifest_that_names_its_ports_gets_numbers_the_child_can_read() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let mut spec = native_spec(
            "native-named-ports",
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo http=$PORT_HTTP; echo wss=$PORT_WSS; echo bare=$PORT; sleep 30".into(),
            ],
        );
        spec.expose.mesh.ports = vec![
            workload_spec::MeshPort::named("http"),
            workload_spec::MeshPort::named("wss"),
        ];
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        let deployed = runtime.deploy_workload(&spec, &mesh).await.unwrap();
        let http = *deployed
            .ports
            .get("http")
            .expect("the port named http was allocated");
        let wss = *deployed
            .ports
            .get("wss")
            .expect("the port named wss was allocated");
        assert_ne!(
            http, wss,
            "two listeners cannot share one number ({http})"
        );

        // The same numbers reach the sweep that writes the service record —
        // this is the leg the front door reads, so a DeployResult that agreed
        // with nothing downstream would be the same silent gap in a new place.
        let state = runtime.get_workload(&ident).await.unwrap().unwrap();
        assert_eq!(state.ports.get("http"), Some(&http));
        assert_eq!(state.ports.get("wss"), Some(&wss));

        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut logs = runtime
            .stream_logs(
                &ident,
                LogOpts {
                    tail: None,
                    follow: false,
                    stream: None,
                    cursor: None,
                },
            )
            .await
            .unwrap();
        let mut captured = String::new();
        while let Some(ev) = logs.next().await {
            captured.push_str(&ev.message);
            captured.push('\n');
        }
        runtime.teardown_workload(&ident).await.unwrap();

        assert!(
            captured.contains(&format!("http={http}")),
            "the child must read the allocated http port; got:\n{captured}"
        );
        assert!(
            captured.contains(&format!("wss={wss}")),
            "the child must read the allocated wss port; got:\n{captured}"
        );
        assert!(
            captured.contains(&format!("bare={http}")),
            "bare PORT stays an alias for the port named http, never a third \
             number; got:\n{captured}"
        );
    }

    /// A named port keeps its number across a supervisor restart — the ledger
    /// is keyed `(ident, name)`, so this is per PORT, not merely per workload.
    ///
    /// It matters because the number is published into a service record and
    /// rendered into an ingress upstream: a port that moved on every restart
    /// would make the front door's address correct only until kamaji bounced.
    #[tokio::test]
    async fn allocated_ports_survive_a_supervisor_restart_name_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        let mut spec = native_spec(
            "native-stable-ports",
            vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        );
        spec.expose.mesh.ports = vec![
            workload_spec::MeshPort::named("http"),
            workload_spec::MeshPort::named("wss"),
        ];
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        let first = {
            let runtime = NativeRuntime::new(tmp.path());
            let deployed = runtime.deploy_workload(&spec, &mesh).await.unwrap();
            runtime.teardown_workload(&ident).await.unwrap();
            deployed.ports
        };

        // A whole new NativeRuntime over the same state dir is what a restarted
        // kamaji is.
        let runtime = NativeRuntime::new(tmp.path());
        let second = runtime.deploy_workload(&spec, &mesh).await.unwrap().ports;
        runtime.teardown_workload(&ident).await.unwrap();

        assert_eq!(
            first, second,
            "each named port must come back with the number the ledger holds"
        );
    }

    /// A number already in the spec is left alone — it is the bind address a
    /// caller resolved, not an operator's pin, and `LedgerPorts` would reject
    /// it as one. Without this the W272 bundle path (which writes the resolved
    /// port onto the spec and forks native) would fail at every bring-up.
    #[tokio::test]
    async fn a_number_already_in_the_spec_is_not_re_resolved_as_a_pin() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let mut spec = native_spec(
            "native-resolved-already",
            vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        );
        // 48213 is not world-fixed, so a pin carrying it would be an error.
        spec.expose.mesh.ports = MeshExpose::anonymous_ports([48213]);
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        let deployed = runtime.deploy_workload(&spec, &mesh).await.unwrap();
        assert_eq!(deployed.ports.get("http"), Some(&48213));
        runtime.teardown_workload(&ident).await.unwrap();
    }

    /// A manifest that states one port and names another gets exactly one
    /// allocation. The mixed spelling is the one most likely to be written by
    /// hand, and the failure it guards against is the allocator either
    /// re-resolving the stated port (an error) or skipping the named one.
    #[tokio::test]
    async fn a_mixed_manifest_allocates_only_the_port_that_has_no_number() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let mut spec = native_spec(
            "native-mixed-ports",
            vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        );
        spec.expose.mesh.ports = vec![
            workload_spec::MeshPort::pinned("http", 48215),
            workload_spec::MeshPort::named("metrics"),
        ];
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        let deployed = runtime.deploy_workload(&spec, &mesh).await.unwrap();
        assert_eq!(deployed.ports.get("http"), Some(&48215));
        let metrics = *deployed.ports.get("metrics").expect("metrics allocated");
        assert_ne!(metrics, 48215);
        runtime.teardown_workload(&ident).await.unwrap();
    }

    /// The child inherits the daemon's environment, and a spec literal layers
    /// over it.
    ///
    /// This is the delivery channel R577-F3's Darwin signing leg uses: a node
    /// sets `APPLE_SIGNING_IDENTITY` (which names an identity in *its own*
    /// keychain) in the kamaji LaunchAgent, and the forked build inherits it —
    /// no coordinator→worker credential delivery, nothing per-camp in a
    /// checked-in recipe, nothing on the wire. `DOCKER_HOST` on us-west-015
    /// already works this way. It is also what gives a build `PATH` at all.
    ///
    /// An `env_clear()` added here as runtime hygiene would break both, and the
    /// failure would surface as `codesign` complaining about a missing identity
    /// on a machine where the identity is plainly installed. Hence a test rather
    /// than only a comment.
    #[tokio::test]
    async fn daemon_environment_is_inherited_by_the_child() {
        std::env::set_var("KAMAJI_NATIVE_INHERIT_PROBE", "from-the-daemon");
        std::env::set_var("KAMAJI_NATIVE_OVERRIDE_PROBE", "from-the-daemon");

        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let mut spec = native_spec(
            "native-inherit",
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo inherited=$KAMAJI_NATIVE_INHERIT_PROBE; \
                 echo overridden=$KAMAJI_NATIVE_OVERRIDE_PROBE; \
                 sleep 30"
                    .into(),
            ],
        );
        spec.env = vec![workload_spec::EnvVar {
            name: "KAMAJI_NATIVE_OVERRIDE_PROBE".into(),
            value: EnvValue::Literal {
                value: "from-the-spec".into(),
            },
        }];
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        runtime.deploy_workload(&spec, &mesh).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut logs = runtime
            .stream_logs(
                &ident,
                LogOpts {
                    tail: None,
                    follow: false,
                    stream: None,
                    cursor: None,
                },
            )
            .await
            .unwrap();
        let mut captured = String::new();
        while let Some(ev) = logs.next().await {
            captured.push_str(&ev.message);
            captured.push('\n');
        }

        runtime.teardown_workload(&ident).await.unwrap();
        std::env::remove_var("KAMAJI_NATIVE_INHERIT_PROBE");
        std::env::remove_var("KAMAJI_NATIVE_OVERRIDE_PROBE");

        assert!(
            captured.contains("inherited=from-the-daemon"),
            "a native child must inherit the daemon environment (no env_clear); got:\n{captured}"
        );
        assert!(
            captured.contains("overridden=from-the-spec"),
            "a spec literal must win over an inherited value; got:\n{captured}"
        );
    }

    /// R893-B17. The native half of the collector contract, read off a child
    /// that actually ran rather than off the `Command` we built — the failure
    /// this ticket fixes was precisely an injection everyone believed in and
    /// nobody had observed.
    ///
    /// `MountNs::Host`: a native child is a host process, so the socket path it
    /// is handed is the node's path verbatim, NOT the in-container one.
    #[tokio::test]
    async fn a_native_child_is_handed_the_collector_contract() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("scryer.sock");
        let runtime =
            NativeRuntime::new(tmp.path()).with_collector(crate::observe::Collector::at(&sock));
        let spec = native_spec(
            "native-collector",
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo ident=$YAH_SERVICE_IDENT; echo sock=$YAH_SCRYER_SOCKET; sleep 30".into(),
            ],
        );
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        runtime.deploy_workload(&spec, &mesh).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let captured = drain_logs(&runtime, &ident).await;
        runtime.teardown_workload(&ident).await.unwrap();

        assert!(
            captured.contains(&format!("ident={}", ident.0)),
            "YAH_SERVICE_IDENT must be the workload's mesh identity; got:\n{captured}"
        );
        assert!(
            captured.contains(&format!("sock={}", sock.display())),
            "a host-namespace child gets the host socket path verbatim; got:\n{captured}"
        );
    }

    /// The other half, and the one that matters for a node that runs no
    /// collector: nothing is injected, so `yah-log`'s `try_layer` keeps
    /// returning `None` instead of pointing a workload at a dead socket.
    #[tokio::test]
    async fn a_node_without_a_collector_injects_neither_variable() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let spec = native_spec(
            "native-no-collector",
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo ident=[$YAH_SERVICE_IDENT]; echo sock=[$YAH_SCRYER_SOCKET]; sleep 30".into(),
            ],
        );
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        runtime.deploy_workload(&spec, &mesh).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let captured = drain_logs(&runtime, &ident).await;
        runtime.teardown_workload(&ident).await.unwrap();

        assert!(captured.contains("ident=[]"), "got:\n{captured}");
        assert!(captured.contains("sock=[]"), "got:\n{captured}");
    }

    /// Collect a workload's captured stdout/stderr into one string.
    async fn drain_logs(runtime: &NativeRuntime, ident: &MeshIdent) -> String {
        let mut logs = runtime
            .stream_logs(
                ident,
                LogOpts {
                    tail: None,
                    follow: false,
                    stream: None,
                    cursor: None,
                },
            )
            .await
            .unwrap();
        let mut captured = String::new();
        while let Some(ev) = logs.next().await {
            captured.push_str(&ev.message);
            captured.push('\n');
        }
        captured
    }

    /// R876-B17: a non-literal env value must REFUSE the deploy, matching the
    /// other four admission-path sites, not silently drop the variable.
    #[tokio::test]
    async fn deploy_refuses_unresolved_from_secret_env() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let mut spec = native_spec("native-from-secret", vec!["/bin/true".into()]);
        spec.env = vec![workload_spec::EnvVar {
            name: "CREDENTIAL".into(),
            value: EnvValue::FromSecret {
                secret: "sentinel-secret".into(),
                key: "sentinel-key".into(),
            },
        }];
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

        let err = runtime
            .deploy_workload(&spec, &mesh)
            .await
            .expect_err("a spec carrying an unresolved FromSecret must be refused");
        let msg = err.to_string();
        assert!(msg.contains("CREDENTIAL"), "error must name the variable: {msg}");
        assert!(msg.contains("FromSecret"), "error must name the shape: {msg}");
    }

    /// R876-B17: same refusal for an unresolved `FromMesh` reference.
    #[tokio::test]
    async fn deploy_refuses_unresolved_from_mesh_env() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let mut spec = native_spec("native-from-mesh", vec!["/bin/true".into()]);
        spec.env = vec![workload_spec::EnvVar {
            name: "PEER_ADDR".into(),
            value: EnvValue::FromMesh {
                ident: MeshIdent("sentinel-peer".into()),
                kind: workload_spec::MeshLookup::Url,
            },
        }];
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

        let err = runtime
            .deploy_workload(&spec, &mesh)
            .await
            .expect_err("a spec carrying an unresolved FromMesh must be refused");
        let msg = err.to_string();
        assert!(msg.contains("PEER_ADDR"), "error must name the variable: {msg}");
        assert!(msg.contains("FromMesh"), "error must name the shape: {msg}");
    }

    /// Non-vacuity for the two tests above: a spec carrying only `Literal` env
    /// must still deploy and still carry its value — the refusal must not have
    /// widened into refusing everything.
    #[tokio::test]
    async fn deploy_still_succeeds_with_only_literal_env() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let mut spec = native_spec(
            "native-literal-only",
            vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
        );
        spec.env = vec![workload_spec::EnvVar {
            name: "PLAIN".into(),
            value: EnvValue::Literal {
                value: "plain-value".into(),
            },
        }];
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        runtime.deploy_workload(&spec, &mesh).await.unwrap();
        runtime.teardown_workload(&ident).await.unwrap();
    }

    #[tokio::test]
    async fn always_policy_respawns_after_exit() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        // Exits cleanly after a short run; RestartPolicy::Always must re-exec it.
        let mut spec = native_spec(
            "native-always",
            vec!["/bin/sh".into(), "-c".into(), "sleep 0.3".into()],
        );
        spec.restart_policy = RestartPolicy::Always;
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        let first = runtime.deploy_workload(&spec, &mesh).await.unwrap();
        let pid1 = first.task_pid;

        // Within a few restart cycles (0.3s run + 1s delay) the pid must change
        // to a freshly re-exec'd process, and it must be back to Running.
        let mut respawned = false;
        for _ in 0..80 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let state = runtime.get_workload(&ident).await.unwrap().unwrap();
            let pid = state.container_id.strip_prefix("native-").unwrap();
            if pid != "0" && pid != pid1.to_string() {
                respawned = true;
                break;
            }
        }
        assert!(respawned, "Always policy should have re-exec'd a new pid");

        runtime.teardown_workload(&ident).await.unwrap();
    }

    #[tokio::test]
    async fn on_failure_gives_up_after_max_attempts() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let mut spec = native_spec(
            "native-onfail",
            vec!["/bin/sh".into(), "-c".into(), "exit 7".into()],
        );
        spec.restart_policy = RestartPolicy::OnFailure {
            max_attempts: 2,
            backoff: BackoffPolicy {
                initial_ms: 50,
                max_ms: 100,
                multiplier: 2.0,
            },
        };
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        runtime.deploy_workload(&spec, &mesh).await.unwrap();

        // After exhausting 2 restart attempts (each ~50-100ms), it lands Failed.
        let mut failed = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let state = runtime.get_workload(&ident).await.unwrap().unwrap();
            if matches!(state.status, WorkloadStatus::Failed { .. }) {
                failed = true;
                break;
            }
        }
        assert!(
            failed,
            "OnFailure should give up as Failed after max_attempts"
        );

        runtime.teardown_workload(&ident).await.unwrap();
    }

    #[tokio::test]
    async fn restart_workload_replaces_running_process() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let spec = native_spec("native-restart", vec!["/bin/sleep".into(), "30".into()]);
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let ident = spec.expose.mesh.identity.clone();

        let first = runtime.deploy_workload(&spec, &mesh).await.unwrap();
        let pid1 = first.task_pid;

        runtime.restart_workload(&ident).await.unwrap();

        let state = runtime.get_workload(&ident).await.unwrap().unwrap();
        assert_eq!(state.status, WorkloadStatus::Running);
        assert_ne!(
            state.container_id,
            format!("native-{pid1}"),
            "restart should have re-exec'd a fresh process"
        );

        runtime.teardown_workload(&ident).await.unwrap();
    }

    #[tokio::test]
    async fn graceful_upgrade_swaps_process_and_signals_old() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        // Track the process directly (no shell) so the SIGQUIT lands on a
        // process with the default disposition (terminate) — a shell may ignore
        // SIGQUIT and make the assertion flaky.
        let spec = native_spec("native-upgrade", vec!["/bin/sleep".into(), "30".into()]);
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

        let first = runtime.deploy_workload(&spec, &mesh).await.unwrap();
        let old_pid = first.task_pid;

        // Graceful upgrade: a fresh replacement takes over, the old process is
        // SIGQUIT'd (the supervisor half of pingora's handoff).
        let upgraded = runtime
            .graceful_upgrade_workload(&spec, &mesh)
            .await
            .unwrap();
        let new_pid = upgraded.task_pid;
        assert_ne!(new_pid, old_pid, "a fresh replacement process took over");

        // Registry now tracks the replacement, still Running (no Stopping blip).
        let state = runtime
            .get_workload(&spec.expose.mesh.identity)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.status, WorkloadStatus::Running);
        assert_eq!(state.container_id, format!("native-{new_pid}"));

        // The old process received SIGQUIT and is reaped (poll up to ~2s for the
        // background reaper + kernel teardown).
        let mut gone = false;
        for _ in 0..40 {
            #[cfg(unix)]
            let alive = unsafe { libc::kill(old_pid as i32, 0) } == 0;
            #[cfg(not(unix))]
            let alive = false;
            if !alive {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            gone,
            "old process (pid {old_pid}) should be gone after SIGQUIT"
        );

        runtime
            .teardown_workload(&spec.expose.mesh.identity)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn graceful_upgrade_with_no_running_instance_is_a_deploy() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let spec = native_spec(
            "native-upgrade-fresh",
            vec!["/bin/sleep".into(), "30".into()],
        );
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

        // No prior instance — a graceful upgrade degenerates to a deploy.
        let res = runtime
            .graceful_upgrade_workload(&spec, &mesh)
            .await
            .unwrap();
        assert!(res.task_pid > 0);
        let state = runtime
            .get_workload(&spec.expose.mesh.identity)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.status, WorkloadStatus::Running);
        runtime
            .teardown_workload(&spec.expose.mesh.identity)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn failed_exit_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let spec = native_spec(
            "native-fail",
            vec!["/bin/sh".into(), "-c".into(), "exit 3".into()],
        );
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        runtime.deploy_workload(&spec, &mesh).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let state = runtime
            .get_workload(&spec.expose.mesh.identity)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(state.status, WorkloadStatus::Failed { .. }),
            "{:?}",
            state.status
        );
    }

    #[tokio::test]
    async fn empty_argv_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = NativeRuntime::new(tmp.path());
        let mut spec = native_spec("native-empty", vec![]);
        spec.command = None;
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let err = runtime.deploy_workload(&spec, &mesh).await.unwrap_err();
        assert!(err.to_string().contains("entrypoint"), "{err}");
    }
}

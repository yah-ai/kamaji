//! cgroup v2 driver for Kamaji's native workload backend.
//!
//! Native workloads each get their own cgroup leaf under the subtree systemd
//! **delegated** to kamaji. This module owns:
//!
//! - **Root resolution** — [`CgroupV2::delegated`] reads `/proc/self/cgroup` to
//!   find where kamaji actually is, instead of assuming a path. See
//!   "Where the leaves go" below; getting this wrong writes into territory
//!   systemd owns and periodically reconciles.
//! - **Setup** — [`CgroupV2::ensure_root`] enables the controllers we need
//!   (`cpu`, `memory`) on the delegated root's `cgroup.subtree_control`.
//! - **Per-workload create/destroy** — `mkdir`/`rmdir` the per-workload leaf.
//! - **Limits** — translate a workload's declared resources ([`WorkloadLimits`])
//!   into the strings written to `cpu.weight`, `cpu.max` and `memory.max`.
//! - **Process attach** — write a pid into `cgroup.procs`. The live caller is
//!   [`crate::native`]'s `spawn_child`, from the post-fork/pre-exec hook, so the
//!   child joins the cgroup before it execs the workload binary.
//!
//! cgroup v2 is the unified hierarchy on Linux. There are no dedicated
//! syscalls — every operation is a write to a virtual file under
//! `/sys/fs/cgroup`. The module therefore compiles everywhere; on non-Linux
//! hosts (and under tests) the writes target whatever root path the caller
//! supplies — typically a tempdir — and [`CgroupV2::delegated`] returns `None`.
//!
//! ## Where the leaves go (R885-B1)
//!
//! `app/yah/cli/resources/kamaji.service` sets `Slice=yubaba.slice`,
//! `Delegate=yes` and `DelegateSubgroup=native`. systemd therefore:
//!
//! 1. creates `/sys/fs/cgroup/yubaba.slice/kamaji.service/`,
//! 2. hands that whole subtree to kamaji (that is what `Delegate=yes` means —
//!    delegation runs *from* systemd *to* the service), and
//! 3. places kamaji's own processes one level down, in `.../kamaji.service/native/`.
//!
//! Step 3 is not decoration. cgroup v2's **no-internal-process rule** forbids a
//! cgroup from holding member processes *and* enabling controllers for its
//! children at the same time. `DelegateSubgroup=` exists precisely to satisfy
//! it: kamaji's own threads sit in `native/`, which leaves `kamaji.service/`
//! itself process-free and therefore able to carry `cpu`/`memory` in its
//! `cgroup.subtree_control` for the workload leaves.
//!
//! So the delegated root is the **parent** of kamaji's own cgroup whenever that
//! cgroup is the delegate subgroup, and a workload node is a *sibling* of
//! `native/`:
//!
//! ```text
//! /sys/fs/cgroup/yubaba.slice/kamaji.service/     <- delegated root (controllers here)
//!                                            native/            <- kamaji itself
//!                                            headscale/         <- workload node: the ceiling
//!                                                     1757...123/  <- generation leaf: the processes
//!                                            forge.<uuid>/
//! ```
//!
//! ## Generations: the ceiling is the workload's, the directory is the deploy's (R885-B4)
//!
//! Until R885-B4 the hierarchy stopped at `<workload-id>/`, and that single
//! directory held both the limits and the processes. A redeploy of the same
//! ident therefore tore down and re-created *the same path*: the outgoing
//! generation's `rmdir` raced the incoming generation's `mkdir`, and anything
//! the outgoing process had double-forked away was still sitting in the
//! directory the incoming one was about to join. There is now one more level:
//!
//! - `<root>/<workload-id>/` — the **workload node**. Carries `cpu.weight`,
//!   `cpu.max`, `memory.max`, `pids.max`, and every counter
//!   [`CgroupHandle::read_stats`] samples. Holds **no processes of its own**.
//! - `<root>/<workload-id>/<generation>/` — the **generation leaf**. Holds the
//!   processes of exactly one deploy, and nothing else: no limits are written
//!   into it.
//!
//! **Why the ceiling hangs on the node rather than on the leaf.** A workload
//! that leaks a generation (teardown could not empty it — see
//! [`CgroupV2::destroy_workload`] for how hard it now tries) would otherwise get
//! a *second* full ceiling for the replacement generation, silently doubling the
//! budget an operator declared once. On the node, the leak and the replacement
//! share the one ceiling the spec asked for, which is the correct reading: they
//! are one workload. It is also what makes R885-B1's graceful-upgrade decision
//! hold for free — during a pingora handoff both processes serve the same
//! listener and are one workload with one ceiling, and a ceiling on the node is
//! that property whether or not the two share a leaf.
//!
//! cgroup v2's **no-internal-process rule** is satisfied by construction and
//! costs nothing extra: the node holds no processes, and it does not need to
//! enable anything in its own `cgroup.subtree_control` because nothing inside
//! the generation leaf is a controller file. `cgroup.procs` (attach),
//! `cgroup.kill` and `cgroup.freeze` (teardown) are *core* interface files,
//! present on every non-root cgroup regardless of which controllers are on.
//! Writing `subtree_control` on the node would only add a failure mode — the
//! one that drops a host into R885-B1's unconfined degrade path — in exchange
//! for control files nothing reads.
//!
//! **The counters stay on the node, and R885-F3's delta bookkeeping stays
//! necessary.** `memory.events`, `memory.peak`, `pids.current` and `cpu.stat`
//! are hierarchical: the node's reading already includes every generation
//! beneath it. The node is minted at deploy and removed at teardown, so it
//! outlives every restart exactly as the flat leaf did — `oom_kill` is still
//! cumulative across restarts and still stays nonzero forever after the first
//! OOM. Diffing it per run (`NativeProcess::oom_kills_settled`) is therefore
//! still the only correct way to ask "did *this* run get OOM-killed?", and
//! moving the counters would not have changed that: a generation leaf outlives
//! the restarts inside its own generation.
//!
//! ### `native/` still exists after R885-B1, and that is correct
//!
//! Measured on us-east-001, 2026-09-11: the leaves are `native`, `noisetable`,
//! `yah-marketing`, `yah-marketing-feed`, `yah-marketing-revalidate`. The first
//! is **kamaji's own process** (`DelegateSubgroup=native` put it there at unit
//! start) and is deliberately unconstrained; the other four are workloads with
//! real `memory.max`/`cpu.max` values.
//!
//! This matters because `0::/yubaba.slice/kamaji.service/native` is also the
//! string W344 records as the *symptom* of the pre-R885-B1 bug, so the path
//! alone does not tell you whether a node is fixed. **The discriminator is
//! whose pid is in it.** A WORKLOAD pid in `.../native` is the bug (it inherited
//! kamaji's cgroup by fork). The KAMAJI pid in `.../native`, with workload pids
//! in sibling leaves named for their idents, is the fix working. Check
//! `cat /sys/fs/cgroup/yubaba.slice/kamaji.service/native/cgroup.procs` and
//! compare against kamaji's own pid before concluding anything.
//!
//! ## CPU: a request is not a ceiling (R885-B5)
//!
//! `ResourceLimits::cpu_millis` is a **request** — the share of a contended
//! node this workload is entitled to, and the quantity a bin-packer subtracts
//! from a node's budget. cgroup v2 spells that `cpu.weight` (range `1..=10000`,
//! default `100`), which is proportional only under contention and imposes no
//! ceiling on an idle node. It is what the containerd and docker backends have
//! always rendered `cpu_millis` into, via `ResourceLimits::cpu_shares`.
//!
//! A **ceiling** is `cpu.max`, and it is optional. It is written only when the
//! spec carries `yah.limits.cpu-millis` (`WorkloadSpec::cpu_limit_millis`); with
//! no annotation the file is left at the kernel's `max <period>` and the
//! workload may burst to the whole box.
//!
//! Between R885-B1 and R885-B5 this driver rendered the request straight into
//! `cpu.max`, which is how us-east-001's four native workloads came to sit at
//! `cpu.max = 25600 100000` — hard-capped at 0.256 of a core on an idle node
//! (W344 Finding 5). If you are tempted to derive a quota from the request
//! again: that is the bug, and it was live.
//!
//! ## PIDs: best-effort, not required (R885-T2)
//!
//! Enabling `pids` is not like enabling `cpu`/`memory` in
//! [`REQUIRED_CONTROLLERS`] — it is deliberately **not** in that list, and
//! must never be added to it. `NativeRuntime::new`'s degrade path (see this
//! module's "Where the leaves go" caller, `crate::native::resolve_cgroup_root`)
//! treats *any* [`CgroupV2::ensure_root`] failure as "this host cannot confine
//! native workloads at all" and sets the whole cgroup driver to `None` — which
//! would lose the `cpu`/`memory` enforcement `pids` was added beside, on any
//! host that has not (yet) delegated `pids` to kamaji's subtree. Trading a
//! fork-bomb-bounded-but-memory-unbounded workload for a completely unbounded
//! one is strictly worse, so it must not happen.
//!
//! Instead [`CgroupV2::ensure_root`] enables `cpu`+`memory` exactly as before
//! (still hard-failing, still degrading the whole driver on failure) and then
//! makes a **second, independent** attempt at `pids`: it checks
//! `cgroup.controllers` (which lists what is actually available to enable —
//! the kernel's ground truth, not an assumption) before writing, and records
//! the outcome on the instance ([`CgroupV2::pids_available`]) rather than
//! returning an error either way. [`CgroupV2::create_workload`] reads that
//! flag and skips the `pids.max` write when it is `false`; `cpu.weight`,
//! `cpu.max` and `memory.max` are written exactly as they always were. The
//! startup log carries a line for each outcome — see
//! `crate::native::resolve_cgroup_root` — so "this node has no pids ceiling"
//! is discoverable the same way "this node has no cgroup enforcement at all"
//! already was.
//!
//! What this module does **not** do: capability or filesystem policy. A cgroup
//! is a resource boundary, not a security one, and a `memory.max` on the
//! headscale appliance does not take `CAP_SYS_ADMIN` away from it. That axis is
//! R885-B9.
//!
//! Until R885-B1 this module assumed `/sys/fs/cgroup/yubaba.slice/native`
//! ([`DEFAULT_SLICE_ROOT`] plus a pushed `"native"`), which is a *sibling of
//! `kamaji.service`* — inside the slice but outside the delegation. It never
//! fired because nothing called the driver.
//!
//! @yah:ticket(R885-T2, "Add pids.max — nothing bounds a fork bomb today")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:at(2026-09-11T08:02:19Z)
//! @yah:phase(P2)
//! @yah:parent(R885)
//! @yah:next("Tier: Cleric. Small and mechanical — R885-B1 landed the live call site to hang it on (crate::native::spawn_child).")
//! @yah:next("REQUIRED_CONTROLLERS is &[\"cpu\", \"memory\"] — pids is not even enabled on cgroup.subtree_control, so this is an enable plus a write, not just a write. Verified absent tree-wide: the only \"pids\" hit outside this file is prose about process IDs at kamaji/src/docker.rs:168.")
//! @yah:next("CARRY THE VALUE AS AN ANNOTATION, not a ResourceLimits field. WorkloadSpec crosses a postcard wire where every field is mandatory and always encoded; kamaji-proto/src/version.rs:63 states the rule three times, and V2/V4/V5/V6/V7/V8 were each a bump for exactly one added field. Follow the yah.placement.memory-request-mb precedent. Pick a defensible default rather than leaving it unset — an absent limit is the current behaviour and closes nothing.")
//! @yah:verify("rg -n \"pids\" oss/kamaji/crates/kamaji/src/cgroup.rs — REQUIRED_CONTROLLERS contains it and pids.max is written in create_workload.")
//! @yah:verify("On a Linux node: cat /sys/fs/cgroup/<workload-leaf>/pids.max returns the configured bound, and a deliberate fork bomb inside a test workload is capped rather than taking the node.")
//! @yah:depends_on(R885-B1)
//! @yah:gotcha("THIS FILE MOVED, 2026-09-10 (R885-B1): it was oss/kamaji/crates/kamaji-bin/src/cgroup.rs and is now oss/kamaji/crates/kamaji/src/cgroup.rs. It had to — kamaji-bin depends on kamaji, so the driver could not stay in the crate that nothing on the live path can import. kamaji-bin re-exports it from here (lib.rs). Line numbers quoted in the notes above are from the old file and are stale; the symbol names are not.")
//! @yah:handoff("pids.max IS LIVE. Three files: (1) oss/yah-base/crates/workload-spec/src/lib.rs — new PIDS_LIMIT_ANNOTATION = \"yah.limits.pids-max\", DEFAULT_PIDS_MAX: u32 = 629_145 (15% of 4_194_304 — systemd's own DefaultTasksMax=15% convention applied to the pid_max systemd itself sets via 50-pid-max.conf on every 64-bit systemd>=243 host, which every fleet node is), and WorkloadSpec::pids_limit() -> u32 (NOT Option<u32> — deliberately the opposite default direction from cpu_limit_millis: absent/unparseable/0 all fall back to DEFAULT_PIDS_MAX, never to 'no ceiling', because an absent pids.max is exactly today's bug). (2) oss/kamaji/crates/kamaji/src/cgroup.rs — WorkloadLimits gained pids_max: u32 (always real, never Option); CgroupV2 gained a pids_available: bool field, CgroupV2::pids_available() accessor, and CgroupV2::ensure_root now takes &mut self. create_workload writes pids.max only when self.pids_available. (3) oss/kamaji/crates/kamaji/src/native.rs — resolve_cgroup_root logs a distinct tracing line for each pids outcome, and WorkloadLimits::from_spec(spec) already carried pids_max through (from_spec/from_request both updated in cgroup.rs).")
//! @yah:handoff("HAZARD RESOLVED — PIDS IS BEST-EFFORT, EXPLICITLY, AS REQUIRED. REQUIRED_CONTROLLERS stays &[\"cpu\",\"memory\"] UNCHANGED — pids was NOT added to it. ensure_root(&mut self) still enables cpu+memory exactly as before (same hard-fail-and-degrade-to-None semantics via NativeRuntime's caller). It THEN makes a second, independent attempt: reads <root>/cgroup.controllers (the kernel's own list of what's actually delegated) and only if \"pids\" appears there does it write \"+pids\" to subtree_control; the outcome (never an Err) is recorded as pids_available. create_workload writes cpu.weight/cpu.max/memory.max exactly as before regardless of pids_available, and writes pids.max only when it's true. So an undelegated-pids host keeps full cpu+memory confinement with no pids ceiling and a warn! log line naming exactly that, instead of losing everything to the existing cgroup=None degrade path.")
//! @yah:handoff("TESTS: cgroup.rs gained 4 (pids_is_enabled_when_delegated_and_the_default_ceiling_is_written = default applied; a_custom_pids_ceiling_is_written_when_pids_is_available = override applied via a WorkloadLimits literal; pids_unavailable_degrades_only_pids_cpu_and_memory_still_enforced = the important one, asserts cpu.weight and memory.max still write correctly and pids.max is absent when cgroup.controllers lacks \"pids\"; ensure_root_without_a_controllers_file_leaves_pids_unavailable = the plain-tempdir/off-Linux regression case). native.rs's existing deploying_a_workload_mints_a_cgroup_leaf_carrying_its_limits gained one assertion pinning pids.max absent at the real call site (with_cgroup_root never calls ensure_root, so pids_available is false there by construction). workload-spec/src/lib.rs gained 3 accessor tests mirroring the cpu_limit_millis pattern (default / override / garbage-and-zero-fall-back-to-default, NOT to none).")
//! @yah:handoff("PRE-EXISTING TESTS FIXED FOR THE &mut self SIGNATURE CHANGE, not touched otherwise: 7 call sites in cgroup.rs's own mod tests (let (_tmp, cg) -> let (_tmp, mut cg)) and 1 in oss/kamaji/crates/kamaji-bin/src/native.rs's off-Linux spawn_off_linux_returns_unsupported test (same fix, that file is the dead-code SandboxPlan/spawn path R885-B1 kept as R885-B9's landing site — still compiles, still tested, untouched otherwise). Also added pids_max: workload_spec::DEFAULT_PIDS_MAX to the one pre-existing WorkloadLimits struct literal in cgroup.rs's a_declared_ceiling_is_written_to_cpu_max_beside_the_weight test (new required field).")
//! @yah:verify("rg -n \"pids\" oss/kamaji/crates/kamaji/src/cgroup.rs confirms: REQUIRED_CONTROLLERS is UNCHANGED at &[\"cpu\",\"memory\"] (pids deliberately absent); a new try_enable_pids reads cgroup.controllers and writes +pids best-effort; create_workload writes pids.max gated on self.pids_available.")
//! @yah:verify("cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji --features native-integration --lib: 124 pass / 0 fail (baseline 120, +4 new cgroup.rs pids tests).")
//! @yah:verify("cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji-bin --features native-exec --lib: 237 pass / 0 fail (baseline 237, unchanged — only the &mut self fixup in the off-Linux dead-code test, no new test added there).")
//! @yah:verify("cargo test --manifest-path oss/yah-base/crates/workload-spec/Cargo.toml --lib: 196 pass / 0 fail. Stated baseline was 192; I added exactly 3 new tests (confirmed present by name in the run: a_declared_pids_limit_overrides_the_default, a_spec_that_declares_no_pids_limit_gets_the_default, an_unparseable_or_zero_pids_limit_falls_back_to_the_default), which would put the count at 195 — the extra +1 beyond my own additions is unaccounted for by my diff and is most likely a peer's concurrent test landing on this shared tree between when the baseline was recorded and when I ran; 0 failures either way.")
//! @yah:verify("scripts/check-schema-drift.sh: ok, .yah/schema is in sync — no regen needed (I added consts + a pure accessor method, no WorkloadSpec field/struct shape change, so schemars output is unaffected). scripts/check-workload-spec-ts.sh: ok, packages/yah/workload-spec/index.ts is in sync, same reasoning.")
//! @yah:verify("cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu (run from oss/kamaji, that workspace is excluded from the root workspace): Finished, exit 0 — the Linux pre_exec/pids.max path compiles. NOT achieved: no live Linux node reading (cat .../pids.max, an actual fork-bomb test) — this Mac cannot exercise cgroupfs at all, same limitation stated by both R885-B1 and R885-B5 for their own unverified-on-hardware items.")
//! @yah:assumes("DEFAULT_PIDS_MAX = 629_145 assumes every fleet node's kernel.pid_max is systemd's own 4_194_304 default (set via /usr/lib/sysctl.d/50-pid-max.conf on systemd>=243, 64-bit). Not verified against any specific live host's /proc/sys/kernel/pid_max or /sys/fs/cgroup/.../pids.max reading (no SSH access from this session) — grounded in the documented systemd default and the fact every fleet node runs kamaji as a systemd unit, not in a live measurement the way R885-B1/B5 grounded their us-east-001 numbers.")
//! @yah:assumes("try_enable_pids's availability check reads cgroup.controllers rather than blindly attempting the write-and-catch-EINVAL approach ensure_root's required half uses for NotFound. This is a design choice for testability (a tempdir test can fake cgroup.controllers content) and because it matches real cgroup v2 semantics (cgroup.controllers is the kernel's own list of what a cgroup may enable for its children) — not verified against a real kernel's exact errno behavior for writing an unavailable controller name, since this Mac has no cgroupfs to test against.")
//!
//! @yah:ticket(R885-F3, "OOM classification: an OOM-kill is currently indistinguishable from a crash")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:at(2026-09-11T08:12:23Z)
//! @yah:phase(P2)
//! @yah:parent(R885)
//! @yah:next("Tier: Warrior — the read path is easy, but reporting the distinction upward may cross the wire (see gotcha).")
//! @yah:next("THE DRIVER HAS NO READ PATH AT ALL. This module only ever writes; there is no reader outside its own tests. memory.events oom_kill is the only counter separating an OOM from an ordinary signal, and nothing reads it — the restart loop sees Signaled(SIGKILL) via translate_wait_status and treats it as ordinary failure.")
//! @yah:next("THIS HAS A SCAR ALREADY: R590-B10 is a forge workload SIGKILLed by a 256 MB ceiling during a rusty-v8 checkout, diagnosed the slow way and stopgapped by raising the ceiling to 32 GiB. That 32 GiB stopgap is in turn what R605-T10 is about. A one-line oom_kill read would have collapsed that diagnosis.")
//! @yah:next("COLLECT THE REST WHILE THE READ PATH EXISTS — they are free once there is one: memory.peak, cpu.stat throttling counters, pids.current. Surface them as workload telemetry. PSI is optional and not required by this ticket.")
//! @yah:next("R885-B1 MADE THIS URGENT RATHER THAN THEORETICAL. memory.max is now actually written on the live path, so the fleet can now produce an OOM kill where before it could only produce an unbounded process. The read seam is crate::native's supervisor settle() — it already has the exit status and (via WorkloadHandle) the leaf path.")
//! @yah:verify("rg -rn \"memory\\.events|memory\\.peak|cpu\\.stat|pids\\.current\" --type rust — returns real read sites, not doc comments.")
//! @yah:verify("On a Linux node: deploy a workload with a memory.max it will exceed; kamaji reports a state that names the OOM, distinct from the state a plain SIGKILL produces.")
//! @yah:depends_on(R885-B1)
//! @yah:gotcha("CHECK THE WIRE COST BEFORE DESIGNING THE REPORT. Surfacing an OOM distinction to yubaba may need a new WorkloadState shape, and WorkloadState crosses the postcard UDS where every field is mandatory — kamaji-proto/src/version.rs:63, currently V8. See whether an existing field or the annotations map can carry it before spending a ProtocolVersion bump. If a bump is genuinely needed, batch it with anything else under R885 that needs one rather than paying twice.")
//! @yah:gotcha("R885-T6 IS NOW A CERTAIN V9 BUMP (operator decided 2026-09-10 to delete ephemeral_storage_mb from ResourceLimits). If this ticket also needs a wire change to report the OOM distinction upward, check R885-T6 status first and batch both into one ProtocolVersion bump instead of paying two.")
//! @yah:handoff("THE READ PATH EXISTS AND THE CLASSIFICATION IS LIVE. Two files, both under oss/kamaji/crates/kamaji/src/. (1) cgroup.rs gained the module's FIRST reader: CgroupHandle::read_stats() -> CgroupStats, infallible, sampling memory.events (oom_kill, oom_group_kill), memory.peak, cpu.stat (nr_periods, nr_throttled, throttled_usec) and pids.current. Every field is an independent Option<u64> and None means NOT MEASURED, never a measured zero - CgroupStats::measured() reports whether the leaf told us anything at all. Both R885 degrade paths produce that shape (no delegated subtree at all -> cgroup=None; no delegated pids per R885-T2 -> a leaf with no pids.current file), so a reader that panicked or logged loud on an absent file would fire on ordinary supported fleet configurations. Helpers flat_keyed_value (whole-key match, so `oom` does not shadow `oom_kill`) and single_value (the literal `max` reads as None, not as a number to do arithmetic on). (2) native.rs wires it at NativeProcess::settle - the seam the ticket named - plus free fns exit_signal / format_stats / describe_exit / log_exit_telemetry, and a NativeRuntime::workload_telemetry(&ident) accessor for the live-workload half the exit-time read can never answer.")
//! @yah:handoff("THE COUNTER IS CUMULATIVE OVER THE LEAF, NOT THE PROCESS - THAT IS THE WHOLE CORRECTNESS PROBLEM AND IT IS NOT IN THE TICKET TEXT. The leaf is minted at deploy and rmdir'ed at teardown, so it outlives every restart and memory.events oom_kill stays nonzero FOREVER after the first OOM. Testing it for nonzero would relabel every later crash of a workload that OOMed once - the false-positive direction the acceptance calls out, and the expensive one, because a wrong OOM sends an operator to raise a ceiling that was never the problem. Fix: NativeProcess carries oom_kills_settled: AtomicU64, settle() swaps in the new total and feeds classify_exit the DELTA. A None (unreadable counter) deliberately leaves the baseline untouched - an unreadable file is not evidence the leaf's history restarted. Test a_stale_oom_count_from_an_earlier_run_does_not_taint_a_later_kill drives three consecutive settles through one leaf and pins OOM / not-OOM / OOM.")
//! @yah:handoff("FOUR-WAY CLASSIFICATION, not two. cgroup::classify_exit(signal, exit_code, oom_kills_this_run) -> ExitClass { OomKilled{signal} | Signaled{signal} | ExitedUnderOom{exit_code} | Exited{exit_code} }, with is_oom(). ExitedUnderOom is the R590-B10 shape VERBATIM and is why the classifier is not just a SIGKILL test: a forge workload's cargo exits 101 of its own accord because a rustc UNDER it was OOM-killed against the 256 MB ceiling. Nothing is signalled, so an exit-status-only classifier cannot see that OOM at all - and that is precisely the case that cost a disk-forensics pass. An unmeasured counter (None) classifies identically to Some(0), i.e. as the plain Signaled/Exited the whole fleet reported before this ticket, because the alternative is inventing an OOM on every degraded host; the None/Some(0) distinction survives in the telemetry, where it is the difference between `not OOM-killed` and `we could not tell`.")
//! @yah:handoff("WHERE THE OOM IS NAMED, AND THE RACE. settle() reads the leaf inside the supervisor task the instant Supervised::wait returns - before teardown_workload's rmdir can be acknowledged - which is the only safe point; anything later races the rmdir and loses the evidence exactly when a workload is dying. It then emits tracing::warn! `native backend: workload was OOM-killed - it exceeded its memory.max, not an ordinary crash (R885-F3)` (or the descendant variant) with workload/signal/cgroup fields, and debug! for the two non-OOM arms so a crash loop cannot flood the journal (same reasoning R605-F31 settled for the microVM terminal-status line). The same sentence goes into WorkloadStatus::Failed{reason} via describe_exit, alongside a bracketed telemetry tail rendered by format_stats - memory.peak / oom_kill / oom_group_kill / cpu.nr_throttled=N/periods / cpu.throttled_usec / pids.current, each OMITTED when unmeasured rather than printed as 0.")
//! @yah:handoff("OPTION (b) TAKEN ON THE WIRE, DELIBERATELY - NO ProtocolVersion BUMP. Option (a) was checked and genuinely cannot work: kamaji-bin/src/server.rs:3866 and :3924 both flatten `WorkloadStatus::Failed { .. } => WireState::Failed`, and kamaji_proto::WorkloadState (kamaji-proto/src/messages.rs:158) is a FIELDLESS #[non_exhaustive] enum - no reason string, no annotations map, nothing on WorkloadEntry that could carry it. So everything below the wire landed and the upward report did not. The exact V9 delta is written into R885-T6's @yah:next (append WorkloadState::OomKilled at the END so discriminants 0..5 are unmoved; map it at both server.rs sites off ExitClass::is_oom(), which settle already computes; the only new plumbing is carrying the class out of the crate-internal Completion). yubaba therefore still cannot tell an OOM from a crash - but the NODE can, which is most of the R590-B10 value, since that diagnosis was done by reading the node.")
//! @yah:verify("cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji --features native-integration --lib: 139 pass / 0 fail (baseline 124 after R885-T2; +15, all mine - 8 in cgroup.rs, 7 in native.rs). cargo test -p kamaji-bin --features native-exec --lib: 237 pass / 0 fail, baseline 237 unchanged (no kamaji-bin source touched).")
//! @yah:verify("THE TWO ACCEPTANCE TESTS, BOTH DIRECTIONS, at the real settle seam (not just against classify_exit): native::tests::an_oom_killed_child_is_named_as_an_oom_at_the_settle_seam (oom_kill=1 + SIGKILL -> reason names `OOM-killed` and `memory.max`) and native::tests::a_plain_sigkill_is_not_misreported_as_an_oom (oom_kill=0 + SIGKILL -> reason contains no `OOM` but does report `oom_kill=0`). Plus an_unmeasurable_host_reports_a_plain_signal_not_an_oom (cgroup=None -> no OOM verdict AND no `oom_kill` printed at all), a_stale_oom_count_from_an_earlier_run_does_not_taint_a_later_kill (the delta guard, three settles through one leaf), a_descendant_oom_is_named_even_though_the_root_exited_normally (R590-B10 shape, exit 101 with no signal), peak_throttling_and_pids_ride_the_same_read (telemetry rendering + absent pids.current omitted not zeroed), telemetry_is_readable_while_the_workload_is_still_running (workload_telemetry through the real deploy path). cgroup.rs adds 8 more covering the parse layer and the classification truth table.")
//! @yah:verify("Acceptance grep satisfied: grep -rnE 'memory\\.events|memory\\.peak|cpu\\.stat|pids\\.current' --include='*.rs' oss/kamaji/crates returns REAL read sites at oss/kamaji/crates/kamaji/src/cgroup.rs:550, :551, :559, :571 (CgroupHandle::read_stats), not doc comments or test-only helpers. Cross-compile: cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu - Finished, exit 0. cargo clippy -p kamaji --features native-integration --all-targets: 1 warning, PRE-EXISTING (jit.rs:312 too-many-arguments, the same one R885-B1 recorded), none from this change.")
//! @yah:verify("NOT ACHIEVED, stated plainly: no live Linux node reading. This is a macOS dev machine with no cgroupfs, so the ticket's second verify line (deploy a workload with a memory.max it will exceed and watch kamaji name the OOM) is unexercised. Everything is proven against tempdir leaves with hand-written counter files plus the cross-compile - same limitation R885-B1, B5 and T2 each recorded for their own Linux-only halves. The useful live baseline is already on this relay: native.rs:148 records us-east-001 2026-09-11 with every memory.events counter zero and a worst-case memory.peak of 31277056 (29.8M) against a 128M memory.max, so the fleet has headroom and has not yet produced a real OOM to read.")
//! @yah:next("WIRE HALF IS UNLANDED AND LIVES ON R885-T6 (already written into its @yah:next + a gotcha). Delta: append `OomKilled` to kamaji_proto::WorkloadState (messages.rs:158, already #[non_exhaustive]; postcard varint discriminant, so appending at the END leaves Pending..Failed on 0..5) and map it at kamaji-bin/src/server.rs:3866 and :3924 off crate::cgroup::ExitClass::is_oom(). Only new plumbing is carrying the ExitClass (or a bool) out of supervise::Completion, which is crate-internal, not a wire type. Do it inside T6's certain V9, not as a second bump.")
//! @yah:next("PSI was skipped as the ticket permits (optional, not required). Two follow-on reads worth someone's time but NOT claimed here: (a) a graceful upgrade (Ctrl::Adopt) discards the outgoing child without calling settle, so an OOM between an adopt and the replacement's eventual settle is attributed to the replacement - harmless for the verdict (the OOM is still named, on the same leaf, for the same workload) but the exit_code beside it belongs to the wrong run; (b) R885-B4's ordering note already states the correct teardown sequence as cgroup.kill -> reap -> read final counters -> rmdir, and read_stats is now the `read final counters` step it was waiting for, so B4 can call it directly rather than inventing one.")
//! @yah:gotcha("workload-spec/src/lib.rs was NOT touched (no new annotation, no ResourceLimits change), so scripts/check-schema-drift.sh and scripts/check-workload-spec-ts.sh are unaffected and were not run - there is no generator input in this diff. Files changed: oss/kamaji/crates/kamaji/src/cgroup.rs and oss/kamaji/crates/kamaji/src/native.rs only. Tree anchor at dispatch: 494e22fa14b21d0cc72dd8a3132e7f078d1eb5eb.")
//! @yah:gotcha("`cargo fmt -p kamaji` is NOT clean on this crate and that is PRE-EXISTING, camp-wide: 80+ hunks across container_net.rs, lib.rs, microvm.rs, ports.rs, probe.rs, sibling.rs and two integration tests, plus 9 in native.rs that predate this ticket. I hand-formatted only my own hunks and deliberately did NOT run a blanket cargo fmt - per root CLAUDE.md that is exactly the move that took 827 uncommitted lines of a peer's work on 2026-08-28. Anyone tempted to tidy this crate should do it as its own ticket on a quiet tree, not inside another one.")
//!
//! @yah:ticket(R885-B4, "Add a generation level and a safe teardown — redeploy races rmdir against mkdir, and EBUSY has no recovery")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:at(2026-09-11T08:29:41Z)
//! @yah:phase(P2)
//! @yah:parent(R885)
//! @yah:next("Tier: Warrior — teardown correctness and a race, on Linux-only paths the camp Mac cannot exercise.")
//! @yah:next("THE HIERARCHY IS TWO LEVELS AND ENFORCED FLAT: <delegated-root>/<workload-id>. validate_id forbids a slash in the id, so the flatness is deliberate, not incidental. A rolling replacement of svc-a therefore puts outgoing and incoming processes in the SAME directory and races teardown rmdir against the new mkdir. Fix: extend to <workload-id>/<generation>/ and relax validate_id for exactly that one level.")
//! @yah:next("TEARDOWN IS A BARE remove_dir whose own doc pushes the reap-before-rmdir obligation onto callers. R885-B1 gave it exactly one caller — crate::native::NativeRuntime::teardown_workload — which reaps first and then ignores the rmdir error, because there is no recovery path to take. There is no cgroup.procs read-back, no cgroup.kill, no freeze-and-sweep. A workload that double-forked leaves rmdir failing EBUSY and the leaf leaked. Correct order: cgroup.kill -> reap -> read final counters (pairs with R885-F3) -> rmdir.")
//! @yah:next("The concept is already in this codebase on the other side: kamaji-containerd-core/src/lib.rs:665-666 reasons about cgroup-wide kill reaching every process in a task cgroup. Only the native side lacks it. cgroup.kill appears nowhere under oss/kamaji today.")
//! @yah:verify("rg -rn \"cgroup\\.kill\" oss/kamaji — a real write site in destroy_workload, ordered before the rmdir.")
//! @yah:verify("Unit test: a workload cgroup with a live double-forked descendant is torn down cleanly rather than leaving EBUSY.")
//! @yah:verify("On a Linux node: redeploy the same workload id twice in quick succession; both generations get distinct leaves and the first is fully removed.")
//! @yah:depends_on(R885-B1)
//! @yah:handoff("THE HIERARCHY IS THREE LEVELS AND THE CEILING MOVED UP ONE. `<root>/<workload-id>/` is now the workload NODE (cpu.weight, cpu.max, memory.max, pids.max, and every counter read_stats samples) and `<root>/<workload-id>/<generation>/` is the generation LEAF, which holds processes and nothing else. CgroupHandle carries both paths: path() is the leaf the spawn hook attaches to, workload_path() is the node the limits and counters live on. I took the leader's call on where the limits go and the reason is sharper than the brief's: a workload that LEAKS a generation would otherwise get a second full ceiling for its replacement, silently doubling a budget an operator declared once - on the node, the leak and the replacement share the one ceiling, which is the correct reading because they are one workload. That is the leaked-survivor case this ticket exists for, not a hypothetical.")
//! @yah:handoff("I DID NOT WRITE cgroup.subtree_control ON THE WORKLOAD NODE, against the brief's letter, and this is the one design call I made against it. The no-internal-process rule constrains a cgroup that ENABLES controllers for its children; it does not require an internal node to enable them. Nothing inside the generation leaf is a controller file - cgroup.procs (attach), cgroup.kill and cgroup.freeze (teardown) are CORE interface files present on every non-root cgroup regardless of which controllers are on. Writing subtree_control would only have added the failure mode the brief warns about (an EBUSY that drops a host into R885-B1's unconfined degrade path) in exchange for files nothing reads. The resource control still lands correctly because cgroup v2 resolves a controller's css to the nearest ENABLED ancestor: a task in `<id>/<gen>` is charged to `<id>`'s memcg, scheduled under `<id>`'s cpu.weight, and counted against `<id>`'s pids.max. NO KAMAJI.SERVICE CHANGE IS NEEDED either: the delegated root already carries +cpu +memory in its subtree_control, which is exactly what materialises the node's control files, and ReadWritePaths=/sys/fs/cgroup/yubaba.slice already covers the extra level recursively.")
//! @yah:handoff("THE TEARDOWN, in the ticket's own order: cgroup.kill -> reap -> read final counters -> rmdir. CgroupV2::destroy_workload now (1) kill_cgroup() writes `1` to the leaf's cgroup.kill, one atomic write reaching every process AND every descendant - the ones the workload double-forked away, which the supervisor's SIGTERM/SIGKILL aimed at its own child can never touch; (2) drain() polls for a member that is still live, bounded by DRAIN_BUDGET=500ms, because the kill is asynchronous - SIGKILL lands and the write returns, but tasks leave cgroup.procs only once reaped; (3) reads the node's final counters via read_stats_at, returning them on a new DestroyOutcome so teardown can LOG them instead of rmdir-ing the evidence; (4) rmdirs the leaf, then the node. Every generation ON DISK is swept, not merely the one this process remembers minting - kamaji's bookkeeping is in memory and does not survive a restart (R885-B7), so a redeploy after a kamaji crash is exactly when an orphaned leaf is sitting there, and this is the one place that ever looks. A leaf that cannot be emptied is stepped over, counted in outcome.leaked, and its NODE is deliberately kept, so whatever survived stays under the ceiling it was deployed with.")
//! @yah:handoff("R885-F3'S DELTA BOOKKEEPING IS STILL NECESSARY AND STILL CORRECT - the ticket asked me to work out which and say so. A per-generation leaf would NOT have retired it, and the counters are not on the leaf anyway. memory.events/memory.peak/pids.current/cpu.stat are HIERARCHICAL, so the node's reading already includes every generation beneath it, and a generation leaf with no enabled controllers carries none of those files at all. read_stats() therefore reads the NODE. The node is minted at deploy and rmdir'ed at teardown exactly as the flat leaf was, so oom_kill is still cumulative across restarts and still stays nonzero forever after the first OOM; NativeProcess::oom_kills_settled's swap-and-diff is still the only correct answer to \"did THIS run get OOM-killed?\". Even had the counters been per-generation, a generation outlives the restarts inside it, so the delta would have been needed regardless. Exactly one line of F3's fixtures moved (native.rs write_oom_kill -> workload_path()); all seven of its settle tests pass untouched otherwise, and two new tests pin the property in both directions.")
//! @yah:handoff("THE KERNEL QUESTION: I COULD NOT ESTABLISH IT, SO I IMPLEMENTED THE FALLBACK - and it would have been the right call either way. No `uname -r` is recorded for ANY of the three prod voters in .yah/infra/machines/ (us-east-001, us-south-001, us-west-001); the only kernel reading in that directory is us-west-014's 6.18.34+rpt-rpi-2712, a Raspberry Pi and not a kamaji fleet host. R885-B1's us-east-001 readings record a memory.peak value, which WOULD imply >= 5.19 since memory.peak landed there, but the exact file that was cat'ed is not stated, so I am treating that as suggestive and not as established. The fallback is freeze + sweep: write cgroup.freeze (kernel >= 5.2), SIGKILL every pid in cgroup.procs, thaw. The freeze is what makes ONE pass sufficient - without it a process forking between the read and the signal is missed and the rmdir still fails EBUSY, which would be this ticket's bug reintroduced by a sloppier fallback. Selection needs no version number: cgroup.kill's PRESENCE is the whole check, and the driver never creates it (see the gotcha).")
//! @yah:handoff("DISCOVERED AND FIXED IN THIS PASS, beyond the ticket's two defects. (a) THE BUG MY OWN FIRST CUT SHIPPED, caught by the test suite and worth the write-up because it is subtle: `fs::write` opens with O_CREAT, so writing cgroup.kill on a host without one CREATES an ordinary file - which then blocks the very rmdir the kill existed to enable. On a real cgroupfs it happens to fail (kernfs has no ->create inode op) but relying on that accident is how it got past me once. New write_existing() opens without O_CREAT, so \"the kernel does not offer this interface\" is a first-class answer on every filesystem, and kill selection works identically against a tempdir and a node. (b) libc is NO LONGER an optional dep of the kamaji crate. cgroup.rs is unconditional (the crate graph forced the driver here, R885-B1), so gating a teardown that can signal a pid behind a backend feature would give a featureless build a silently weaker one; `dep:libc` came out of native-integration and microvm-integration. Cost is nil - tokio already depends on libc unconditionally on every unix target. (c) member_pids drops pid 0 and kamaji's own pid before any signal: kill(0, SIGKILL) signals the caller's whole process group and kill(self) is kamaji killing kamaji, and a malformed cgroup.procs must not be able to reach either. Pinned by a test.")
//! @yah:handoff("TWO SMALLER CALLS, stated so nobody re-litigates them. (1) validate_id was RENAMED to validate_component and NOT relaxed. The ticket said to relax it for one extra level; I built the path from two separately-validated components instead, which is strictly stronger than one component permitted to contain one separator, and costs nothing because the generation half is minted from a clock reading inside this module rather than supplied by a caller. A workload name still cannot smuggle nesting; a test pins it on both create and destroy. (2) graceful_upgrade_workload STILL SHARES the outgoing generation's leaf, deliberately, and the comment at that site now says why rather than pointing at this ticket. Minting a generation there would leave NativeProcess holding a handle onto a leaf it no longer runs in, and Supervised::start respawns a crashed child into exactly that handle - so the outgoing directory would be both destroyed and restarted into. Carrying a fresh handle through Ctrl::Adopt is what that needs, and NEITHER defect this ticket names requires it: the race is a redeploy's teardown against its own re-create, and a handoff rmdirs nothing.")
//! @yah:gotcha("THE DRAIN BLOCKS THE CALLING THREAD, up to DRAIN_BUDGET=500ms, and destroy_workload is called from the async teardown_workload. This is deliberate and bounded: the whole driver is blocking std::fs, the first poll runs immediately after the kill so the normal case sleeps ZERO times, and only a genuine survivor costs the sleeps. If someone later makes the driver async, this is the one function whose blocking is load-bearing rather than incidental. The budget is a judgement about the fleet: a workload wedged in uninterruptible sleep must not be able to hold a teardown open, because a leaked directory is strictly better than a teardown the caller reads as `the workload is still up` - the same trade teardown_workload already makes about the rmdir.")
//! @yah:gotcha("R885-B5'S DEFERRED DECISION IS RE-READ AND LEFT AS IT STANDS - do not change it on my account. B5's cleanup note asks whoever lands cgroup.kill to reconsider writing `max <period>` into cpu.max explicitly, because a leaf reused after a failed teardown keeps a stale quota. Two reasons to leave it: the residue is now much narrower (it takes a process the kernel itself could not kill, and the stale file would sit on the NODE, which create_workload rewrites cpu.weight and memory.max onto every deploy), and B5's own acceptance test asserts cpu.max does NOT EXIST when no ceiling is declared. Flipping that would break a peer's asserted acceptance to close a hazard I just narrowed. If a live node ever shows a stale cpu.max on a reused node, that is the evidence that reopens it; the manual remedy is still one line (`echo \"max 100000\" > <node>/cpu.max`).")
//! @yah:verify("THE ACCEPTANCE GREP: `rg -c 'cgroup.kill' oss/kamaji/crates/kamaji/src/cgroup.rs` = 19 hits, with the real write site at cgroup.rs:1039 - `write_existing(&leaf.join(\"cgroup.kill\"), \"1\")` inside kill_cgroup(), called from destroy_workload() BEFORE both rmdirs (the leaf's and the node's). Before this ticket the string appeared nowhere under oss/kamaji outside board prose.")
//! @yah:verify("THE THREE ACCEPTANCE TESTS THE TICKET NAMED, each at BOTH the driver and the live call site (R885-B1's first gotcha is why). (1) DOUBLE-FORKED DESCENDANT, with a real process rather than a simulation: `sh` backgrounds a `sleep` and exits so the sleep is reparented to init and is nobody's child - cgroup::tests::a_double_forked_descendant_is_killed_before_the_rmdir and native::tests::teardown_kills_a_double_forked_descendant_the_supervisor_cannot_reach both assert the orphan is DEAD after teardown and that nothing live is left holding the leaf. Both run the PRE-5.14 path (a tempdir has no cgroup.kill and the driver refuses to create one), which is the half no modern kernel can prove. (2) TWO GENERATIONS: cgroup::tests::two_generations_of_one_workload_get_distinct_leaves and native::tests::a_redeploy_mints_a_new_generation_beside_the_same_ceiling drive the real deploy_workload twice and assert distinct generations, exactly one surviving, and the same node carrying memory.max throughout. an_incoming_generation_never_lands_in_a_leaked_predecessors_leaf pins the harder half - the incoming generation gets its own directory even when the outgoing one LEAKED. (3) F3 UNDER THE NEW HIERARCHY: cgroup::tests::oom_counters_are_read_off_the_node_not_the_generation_leaf (with a decoy counter in the leaf, so a reader that followed the processes fails) and native::tests::an_oom_is_still_classified_through_the_real_deploy_path.")
//! @yah:verify("EVERY NUMBER RUN BY ME ON THIS TREE (anchor 494e22fa14b21d0cc72dd8a3132e7f078d1eb5eb). `cargo test -p kamaji --features native-integration --lib`: 153 pass / 0 fail, baseline 139 after R885-F3, +14 all mine (11 in cgroup.rs, 3 in native.rs; the six other new tests beyond the three acceptance pairs cover cgroup.kill preference, the neither-interface host, the bounded drain, the final-counter read, generation monotonicity/collision-freedom, and the pid-0/self signal guards). `cargo test -p kamaji-bin --features native-exec --lib`: 237 pass / 0 fail, baseline 237 UNCHANGED. `cargo check --manifest-path oss/kamaji/Cargo.toml --workspace --all-features --all-targets`: exit 0, no errors - this is the argv the non-optional-libc change makes non-optional. `cargo check -p camp-identity` (the root-workspace consumer of kamaji-bin): exit 0, only two pre-existing unused-variable warnings from a peer's in-flight rpc code. `cargo clippy -p kamaji --features native-integration --all-targets`: 1 warning, PRE-EXISTING, jit.rs:312 too-many-arguments - the same one R885-B1 and R885-F3 each recorded, none from this change. No generator input was touched (workload-spec is unchanged), so check-schema-drift.sh / check-workload-spec-ts.sh are unaffected and were not run.")
//! @yah:verify("CROSS-COMPILE, the Linux-path verification this Mac can achieve: `cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu` (run from oss/kamaji) - Finished, exit 0, on the final tree after formatting. FORMATTING: I ran rustfmt on cgroup.rs ONLY, after checking that every one of its eight diff hunks was in code I had just written - that file is absent from R885-F3's list of pre-existing unclean files and rustfmt --check confirmed it. native.rs was NOT blanket-formatted; I hand-applied my own two hunks and left the six pre-existing ones (lines 501, 633, 1021, 1635, 1841, 1879, 1931, 1938, 2098 region) exactly as R885-F3 found them. Per root CLAUDE.md, a blanket fmt on this tree is the move that cost a peer 827 uncommitted lines on 2026-08-28.")
//! @yah:verify("NOT ACHIEVED, stated plainly: NO LIVE LINUX NODE READING. This is a macOS dev machine with no cgroupfs, so the ticket's Linux-node acceptance (redeploy the same workload id twice on a node and watch both generations get distinct leaves with the first fully removed) is unexercised, as is the real cgroup.kill path - every test here runs the pre-5.14 FALLBACK, because a tempdir offers no cgroup.kill and the driver will not create one. Same limitation R885-B1, B5, T2 and F3 each recorded for their own Linux-only halves. THE LIVE ACCEPTANCE STILL OWED, on a node running these bytes: `ls /sys/fs/cgroup/yubaba.slice/kamaji.service/<ident>/` shows a 19-digit generation directory beside the control files; `cat .../<ident>/memory.max` is still the real number (the ceiling is on the NODE now, not one level down); `cat /proc/<workload-pid>/cgroup` ends in `/<ident>/<19 digits>`; redeploy once and the first generation directory is gone and a second, larger-numbered one is there; and `test -e .../<ident>/<gen>/cgroup.kill` decides once and for all whether the fleet takes the cgroup.kill path or the freeze+sweep fallback - which is the one reading that settles the kernel question I could not settle from the repo.")
//! @yah:assumes("THE FLEET'S KERNEL VERSION IS UNESTABLISHED IN BOTH DIRECTIONS. I did not verify that any fleet node has cgroup.kill (>= 5.14) or that any lacks it - no `uname -r` is recorded for us-east-001, us-south-001 or us-west-001 and I had no way to read one from here. The code does not depend on the answer (presence of the file is the whole check, and both paths are implemented and tested), but anyone reasoning about which path the fleet actually takes must read a node; the one-line probe is in the verify block above.")
//! @yah:assumes("THE cgroup v2 CONTROLLER-INHERITANCE CLAIM IS READ FROM THE KERNEL'S DOCUMENTED SEMANTICS, NOT MEASURED. The design rests on a task in `<id>/<gen>` being charged to `<id>`'s memcg, scheduled under `<id>`'s cpu.weight and counted against `<id>`'s pids.max, because cgroup v2 resolves a controller to the nearest ancestor that has it enabled. I am confident in it and it is why no subtree_control write was needed - but it is an inference from documented behaviour, and the tempdir tests cannot exercise it because a tempdir has no controllers at all. It is settled by one reading on a node: deploy a workload with a small memory.max, drive it past the ceiling, and confirm the OOM is counted in `<ident>/memory.events` rather than nowhere.")
//! @yah:handoff("BOTH DEFECTS CLOSED IN oss/kamaji/crates/kamaji/src/{cgroup.rs,native.rs} plus a non-optional libc in kamaji/Cargo.toml. The hierarchy gained a generation level so a redeploy can never hand the incoming process the outgoing one's directory, and the bare remove_dir became a kill -> drain -> read -> rmdir sequence with a pre-5.14 freeze+sweep fallback. 153/0 on kamaji --lib against a 139 baseline; 237/0 on kamaji-bin, baseline unchanged; cross-compile to x86_64-unknown-linux-gnu clean. No live node reading - see the verify block for the four commands that close it.")
//! @yah:verify("LIVE ON us-east-001 and correct, with one finding worth keeping that looked alarming and is not a regression. The generation hierarchy landed — every workload cgroup moved from the flat /yubaba.slice/kamaji.service/<id> to <id>/<generation> (e.g. .../yah-marketing/1789161281045010149). THE GENERATION LEAVES CARRY NO CONTROLLER FILES: <id>/<generation>/memory.max, cpu.max and pids.max DO NOT EXIST, and <id>/cgroup.subtree_control is empty. That is not an un-confinement, and it was checked rather than reasoned about: enforcement is hierarchical, <id> holds memory.max=134217728, and <id>-level memory.current reads 30842880 with pids.current 15 for yah-marketing — non-zero and tracking the descendant. The leaf's cgroup.controllers is empty, so it is not a controller cgroup and the nearest ancestor owns enforcement; the 128 MiB cap covers the generation leaf. WHAT IS ACTUALLY LOST is only the ABILITY to set a per-generation ceiling distinct from the workload's — if R885 ever wants that, <id>'s subtree_control needs `cpu memory pids` written to it. Worth knowing before anyone reads an empty leaf as a bug. SEPARATELY, R885-B1's \"new binary, old unit file\" hazard — whose comment names us-east-001 on 2026-09-11 specifically as the case that would resolve the delegated root to a process-bearing cgroup and silently run workloads unbounded — DID NOT FIRE on this ship: kamaji's own cgroup is .../kamaji.service/native, the delegated root holds 0 processes, and subtree_control reads `cpu memory pids`. DelegateSubgroup was already installed on the node.")

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;
use workload_spec::{ResourceLimits, WorkloadSpec};

/// Fallback root for contexts where `/proc/self/cgroup` cannot tell us where we
/// are — a non-systemd dev box, a unit test, a non-Linux host.
///
/// **Not the production path.** Production resolves the root at runtime via
/// [`CgroupV2::delegated`]; this constant only names the slice kamaji's unit
/// declares (`Slice=yubaba.slice`) so a caller with no `/proc` still has
/// something coherent to point at. Creating leaves directly under it on a
/// systemd node would land them *outside* the delegated subtree — see this
/// module's "Where the leaves go".
pub const DEFAULT_SLICE_ROOT: &str = "/sys/fs/cgroup/yubaba.slice";

/// Where the unified cgroup v2 hierarchy is mounted. Fixed by the kernel/systemd
/// contract; every path in `/proc/self/cgroup` is relative to it.
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";

/// The value of `DelegateSubgroup=` in `app/yah/cli/resources/kamaji.service`.
///
/// When kamaji's own cgroup ends in this component, the delegated root is one
/// level up — see this module's "Where the leaves go". Kept in sync with the
/// unit file by nothing but this comment; if the unit changes, change this.
const DELEGATE_SUBGROUP: &str = "native";

/// Controllers Kamaji's native driver requires enabled on the delegated root's
/// `cgroup.subtree_control` file.
const REQUIRED_CONTROLLERS: &[&str] = &["cpu", "memory"];

/// `cpu.max` period (microseconds). 100ms is the kernel default and what every
/// container runtime uses; keeping it makes quota arithmetic comparable across
/// native and container workloads.
const CPU_PERIOD_US: u64 = 100_000;

/// Millicores that make one full core (k8s convention: `1000m` = 1 CPU).
const MILLIS_PER_CORE: u64 = 1000;

/// `cpu.weight` for one full core's worth of request, and the value the kernel
/// (and systemd's `CPUWeight=`) uses when nothing sets the file.
///
/// This doubles as the millis→weight scale factor: `1000m` ⇒ `100` is the same
/// shape as the sibling backends' `1000m` ⇒ `1024` shares
/// (`ResourceLimits::cpu_shares`), where `1024` is cgroup v1's default. Both put
/// "one core" on the platform default, so a workload's relative standing is the
/// same whichever backend runs it.
const DEFAULT_CPU_WEIGHT: u64 = 100;

/// cgroup v2 rejects a `cpu.weight` outside `1..=10000`.
const CPU_WEIGHT_MIN: u64 = 1;
const CPU_WEIGHT_MAX: u64 = 10_000;

/// How long [`CgroupV2::destroy_workload`] waits between polls for a killed
/// generation leaf to stop holding live processes.
const DRAIN_POLL: Duration = Duration::from_millis(10);

/// Total time that drain is allowed to take before the leaf is declared leaked.
///
/// `cgroup.kill` delivers `SIGKILL` and returns; the tasks leave `cgroup.procs`
/// when they are reaped, which is the next scheduler tick for anything not stuck
/// in uninterruptible sleep. Half a second is generous for that and short enough
/// that a workload wedged in `D` state cannot hold a teardown open — a leaked
/// directory is a strictly better outcome than a teardown the caller reads as
/// "the workload is still up" (the same judgement `teardown_workload` already
/// makes about the `rmdir`).
const DRAIN_BUDGET: Duration = Duration::from_millis(500);

/// Driver scoped to one delegated cgroup subtree. Cheap to clone — only holds
/// paths.
#[derive(Debug, Clone)]
pub struct CgroupV2 {
    /// The cgroup directory workload leaves are created under.
    root: PathBuf,
    /// Kamaji's own cgroup, when known. A leaf may never collide with it —
    /// creating `<root>/native` when kamaji lives there would try to write
    /// limits onto the supervisor itself.
    own: Option<PathBuf>,
    /// Whether `pids` was actually enabled on `root/cgroup.subtree_control`.
    /// `false` until [`CgroupV2::ensure_root`] runs and finds it delegated;
    /// see this module's "PIDs: best-effort, not required". Read by
    /// [`CgroupV2::create_workload`] to decide whether `pids.max` is even
    /// possible to write.
    pids_available: bool,
}

impl CgroupV2 {
    /// Build a driver rooted at an explicit directory. Leaves are created
    /// directly under it.
    ///
    /// This is the test/dev constructor (point it at a tempdir). Production
    /// uses [`CgroupV2::delegated`].
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            own: None,
            pids_available: false,
        }
    }

    /// Resolve the subtree systemd delegated to this process, by reading
    /// `/proc/self/cgroup` rather than assuming a path.
    ///
    /// Returns `None` — meaning "this host has no cgroup subtree for us to own,
    /// run workloads unbounded as before" — when:
    ///
    /// - we are not on Linux, or `/proc/self/cgroup` is unreadable;
    /// - the file has no cgroup v2 (`0::`) line, i.e. this is a v1/hybrid host;
    /// - our own cgroup is the hierarchy root (`0::/`), which is what a process
    ///   in its own cgroup namespace sees and gives us no owned subtree.
    ///
    /// `None` is deliberately not an error: a kamaji that refused to start
    /// native workloads on a host whose cgroup layout it did not recognise
    /// would take the mesh down over a hardening feature.
    pub fn delegated() -> Option<Self> {
        let own_rel = own_cgroup_path(&fs::read_to_string("/proc/self/cgroup").ok()?)?;
        Self::from_own_cgroup(Path::new(CGROUP_MOUNT), &own_rel)
    }

    /// The pure half of [`CgroupV2::delegated`] — given the mount point and the
    /// hierarchy-relative path of our own cgroup, decide where leaves go.
    fn from_own_cgroup(mount: &Path, own_rel: &str) -> Option<Self> {
        let own_rel = own_rel.trim();
        if own_rel == "/" || own_rel.is_empty() {
            return None;
        }
        let own = mount.join(own_rel.trim_start_matches('/'));
        // `DelegateSubgroup=native` puts us one level inside the delegated
        // subtree, specifically so the subtree itself stays process-free and can
        // carry controllers for the leaves (no-internal-process rule). Anywhere
        // else, the best we can say is that our own cgroup is the boundary.
        let root = if own.file_name().and_then(|n| n.to_str()) == Some(DELEGATE_SUBGROUP) {
            own.parent()?.to_path_buf()
        } else {
            own.clone()
        };
        Some(Self {
            root,
            own: Some(own),
            pids_available: false,
        })
    }

    /// The directory workload leaves are created under.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether `pids` was enabled on the delegated root. Always `false`
    /// before [`CgroupV2::ensure_root`] has run. See this module's "PIDs:
    /// best-effort, not required".
    pub fn pids_available(&self) -> bool {
        self.pids_available
    }

    /// Enable `cpu` + `memory` on the delegated root's `cgroup.subtree_control`,
    /// then make a best-effort attempt at `pids` (recorded on
    /// [`CgroupV2::pids_available`], never causes this to fail). Idempotent;
    /// safe on every startup.
    ///
    /// On a systemd node the required half succeeds because `Delegate=yes`
    /// makes the parent slice offer those controllers and
    /// `DelegateSubgroup=native` keeps the root process-free. It fails with
    /// `EBUSY` on a root that holds processes (the no-internal-process rule)
    /// and with `EPERM`/`ENOENT` where we are not the owner — both of which
    /// the caller reads as "no cgroup enforcement here" rather than as a
    /// fatal error.
    ///
    /// `pids` is handled separately and cannot fail this call — see "PIDs:
    /// best-effort, not required" above for why it must not share the
    /// required path's all-or-nothing failure mode.
    ///
    /// Off-Linux (or against a tempdir) the controller file doesn't exist —
    /// we swallow `NotFound` so tests work without faking a cgroupfs.
    pub fn ensure_root(&mut self) -> Result<(), CgroupError> {
        create_dir_all(&self.root)?;
        let subtree_control = self.root.join("cgroup.subtree_control");
        let directive = enable_controllers_directive(REQUIRED_CONTROLLERS);
        match fs::write(&subtree_control, directive) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CgroupError::Io {
                    path: subtree_control,
                    source,
                });
            }
        }
        self.pids_available = self.try_enable_pids(&subtree_control);
        Ok(())
    }

    /// Best-effort half of [`CgroupV2::ensure_root`]. Checks
    /// `cgroup.controllers` — the kernel's own list of what this cgroup may
    /// enable for its children — before writing, rather than writing blind
    /// and hoping; an undelegated `pids` is expected on any host that hasn't
    /// taken the unit-file change this ticket assumes, not a bug to log loud
    /// about on every single startup.
    ///
    /// Never returns an error. A host where `pids` is unavailable, or where
    /// the write itself fails, still gets `cpu`/`memory` enforcement — that
    /// is the entire point of splitting this out of the required path.
    fn try_enable_pids(&self, subtree_control: &Path) -> bool {
        let offered = fs::read_to_string(self.root.join("cgroup.controllers"))
            .map(|s| s.split_whitespace().any(|c| c == "pids"))
            .unwrap_or(false);
        if !offered {
            return false;
        }
        fs::write(subtree_control, enable_controllers_directive(&["pids"])).is_ok()
    }

    /// Create this deploy's cgroup — the workload node at `<root>/<id>` carrying
    /// the resource limits, and a fresh generation leaf beneath it for the
    /// processes. The returned [`CgroupHandle`] names both, so the spawn path
    /// joins its forked child to the *leaf* via [`CgroupHandle::attach_pid`]
    /// while the ceiling stays on the node. See this module's "Generations".
    ///
    /// The node is `create_dir_all`ed rather than required-absent on purpose: a
    /// previous teardown that could not empty a leaf leaves the node behind
    /// (see [`CgroupV2::destroy_workload`]), and the right response is to
    /// rewrite the limits onto it and mint a new generation beside the leak —
    /// never to hand the incoming generation the outgoing one's directory,
    /// which is the R885-B4 race itself.
    ///
    /// `cpu.weight` and `memory.max` are always written. `cpu.max` is written
    /// **only** when the workload declares a hard ceiling — see this module's
    /// "CPU: a request is not a ceiling". A freshly `mkdir`ed cgroup starts at
    /// `cpu.max = "max <period>"`, so not writing it is the same as writing
    /// "unlimited"; the one case where it is not is a leaf that survived a
    /// failed teardown and is being reused, which is R885-B4's race.
    ///
    /// `pids.max` is written **only** when [`CgroupV2::pids_available`] is
    /// `true` — see this module's "PIDs: best-effort, not required". Unlike
    /// `cpu.max`, this is not "unlimited either way": a host where `pids` was
    /// never delegated has no `pids.max` file to write at all, so skipping is
    /// the only option, not a choice about the value.
    pub fn create_workload(
        &self,
        id: &str,
        limits: &WorkloadLimits,
    ) -> Result<CgroupHandle, CgroupError> {
        let node = self.workload_node(id)?;
        create_dir_all(&node)?;
        write_file(
            &node.join("cpu.weight"),
            &format_cpu_weight(limits.cpu_request_millis),
        )?;
        if let Some(ceiling_millis) = limits.cpu_limit_millis {
            write_file(&node.join("cpu.max"), &format_cpu_max(ceiling_millis))?;
        }
        write_file(
            &node.join("memory.max"),
            &format_memory_max(limits.memory_max_mb),
        )?;
        if self.pids_available {
            write_file(&node.join("pids.max"), &limits.pids_max.to_string())?;
        }
        let path = node.join(mint_generation(&node));
        create_dir_all(&path)?;
        Ok(CgroupHandle {
            path,
            workload: node,
        })
    }

    /// Kill, drain and remove every generation of `<root>/<id>`, then the
    /// workload node itself — the R885-B4 teardown, in the order the ticket
    /// names: **`cgroup.kill` → reap → read final counters → `rmdir`**.
    ///
    /// What each step is for, because the bare `remove_dir` this replaced looked
    /// adequate right up until a workload double-forked:
    ///
    /// 1. **kill** — [`kill_cgroup`] writes `cgroup.kill`, one atomic write that
    ///    reaches every process in the leaf *and every descendant*, including the
    ///    ones a workload forked away from the supervisor and which therefore
    ///    survive the `SIGTERM`/`SIGKILL` the supervisor aims at its own child.
    ///    Kernels before 5.14 have no such file; those fall back to freeze +
    ///    sweep, see [`KillMethod`].
    /// 2. **reap** — the kill is asynchronous. `SIGKILL` is delivered and the
    ///    write returns; the tasks leave `cgroup.procs` only once they are
    ///    reaped. [`DRAIN_BUDGET`] is how long that is allowed to take before the
    ///    leaf is reported leaked rather than waited on forever.
    /// 3. **read final counters** — the node's counters are the *workload's*
    ///    (they are hierarchical, see this module's "Generations") and they are
    ///    destroyed by step 4. This is the last moment anything can read how the
    ///    workload ended; the returned [`DestroyOutcome`] carries them out so
    ///    `crate::native`'s teardown can log them.
    /// 4. **rmdir** — now guaranteed to be an empty-of-processes directory, so
    ///    the `EBUSY` that had no recovery path cannot be reached by the ordinary
    ///    case any more.
    ///
    /// Every generation found on disk is swept, not merely the one this process
    /// remembers minting. kamaji's workload bookkeeping is in memory and does not
    /// survive a restart (R885-B7), so a redeploy after a kamaji crash is exactly
    /// when an orphaned generation leaf is sitting there — and this is the one
    /// place that ever looks.
    ///
    /// A leaf that could not be emptied is **stepped over, not fatal**: the
    /// remaining generations are still swept and the outcome counts the leak.
    /// The error is returned so a caller can log it, but the workload node
    /// deliberately stays behind when anything under it does, because removing
    /// the node would drop the ceiling off a still-running leak.
    pub fn destroy_workload(&self, id: &str) -> Result<DestroyOutcome, CgroupError> {
        let node = self.workload_node(id)?;
        let mut outcome = DestroyOutcome::default();
        for leaf in generation_leaves(&node) {
            outcome.method = Some(kill_cgroup(&leaf));
            match drain(&leaf).and_then(|()| remove_dir(&leaf)) {
                Ok(()) => outcome.removed += 1,
                Err(e) => outcome.leaked.push(e.to_string()),
            }
        }
        // Step 3: the node's counters are the workload's whole history and the
        // `rmdir` below is what destroys them.
        outcome.stats = read_stats_at(&node);
        // A node whose generations are gone is worth removing; one still holding
        // a leak is NOT, because the ceiling that bounds the leak hangs on it.
        if outcome.leaked.is_empty() {
            outcome.node_removed = remove_dir(&node).is_ok();
        }
        Ok(outcome)
    }

    /// `<root>/<id>`, once `id` is known to be a single safe path component and
    /// not kamaji's own cgroup.
    fn workload_node(&self, id: &str) -> Result<PathBuf, CgroupError> {
        validate_component(id)?;
        let node = self.root.join(id);
        if self.own.as_deref() == Some(node.as_path()) {
            // `<root>/native` is kamaji itself, not a workload.
            return Err(CgroupError::InvalidWorkloadId(id.to_string()));
        }
        Ok(node)
    }
}

/// What one workload's cgroup leaf is configured with — the numbers
/// [`CgroupV2::create_workload`] renders into `cpu.weight`, `cpu.max` and
/// `memory.max`.
///
/// A struct rather than a bare [`ResourceLimits`] because the two CPU numbers do
/// not both live there: the request is a spec *field*, the ceiling is a spec
/// *annotation* (`WorkloadSpec::cpu_limit_millis`), and the driver needs both.
/// `pids_max` (R885-T2) is the same shape as the ceiling — annotation-carried
/// — but always has a real value; see its field doc for why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadLimits {
    /// The CPU **request** in millicores → `cpu.weight`. `0` = no declared
    /// request, which renders as the default weight.
    pub cpu_request_millis: u32,
    /// The optional hard CPU **ceiling** in millicores → `cpu.max`. `None`
    /// leaves `cpu.max` unwritten, so the workload may burst to the whole node.
    pub cpu_limit_millis: Option<u32>,
    /// The memory ceiling in MiB → `memory.max`. `0` = unlimited.
    pub memory_max_mb: u32,
    /// The process-count ceiling → `pids.max`, written only when
    /// [`CgroupV2::pids_available`] is `true`. Unlike `cpu_limit_millis` this
    /// is never absent: [`WorkloadSpec::pids_limit`] and
    /// [`WorkloadLimits::from_request`] both fall back to
    /// `workload_spec::DEFAULT_PIDS_MAX` rather than to "no ceiling" — an
    /// unbounded `pids.max` is the bug R885-T2 closes, not a default worth
    /// keeping. See that constant's doc for where the number comes from.
    pub pids_max: u32,
}

impl WorkloadLimits {
    /// Read a workload's cgroup numbers off its spec: the CPU request from
    /// `resources.cpu_millis`, the optional CPU ceiling from the
    /// `yah.limits.cpu-millis` annotation, the pids ceiling from
    /// `yah.limits.pids-max` (defaulted by [`WorkloadSpec::pids_limit`] if
    /// absent). This is what the live deploy path uses.
    pub fn from_spec(spec: &WorkloadSpec) -> Self {
        Self {
            cpu_request_millis: spec.resources.cpu_millis,
            cpu_limit_millis: spec.cpu_limit_millis(),
            memory_max_mb: spec.resources.memory_mb,
            pids_max: spec.pids_limit(),
        }
    }

    /// Build from a bare [`ResourceLimits`], for callers that hold the limits
    /// without the spec they came from. There is no CPU ceiling in that case —
    /// the ceiling is an annotation and annotations live on the spec. The pids
    /// ceiling still gets the same default [`WorkloadSpec::pids_limit`] would
    /// have produced for a spec with no annotation, because that default is
    /// not optional the way the CPU ceiling's absence is.
    pub fn from_request(limits: &ResourceLimits) -> Self {
        Self {
            cpu_request_millis: limits.cpu_millis,
            cpu_limit_millis: None,
            memory_max_mb: limits.memory_mb,
            pids_max: workload_spec::DEFAULT_PIDS_MAX,
        }
    }
}

/// Handle to one deploy's cgroup pair; returned by
/// [`CgroupV2::create_workload`].
///
/// Two paths, because since R885-B4 the limits and the processes live at
/// different levels — see this module's "Generations". Nothing outside this
/// module should join them back together: the spawn path wants
/// [`CgroupHandle::path`] (the generation leaf) and the read path wants
/// [`CgroupHandle::workload_path`] (the node), and getting those the wrong way
/// round is silently wrong rather than an error — a pid written to the node
/// breaks the no-internal-process rule, and counters read off the leaf are all
/// absent.
#[derive(Debug, Clone)]
pub struct CgroupHandle {
    /// `<root>/<workload-id>/<generation>` — where the processes go.
    path: PathBuf,
    /// `<root>/<workload-id>` — where the limits and the counters are.
    workload: PathBuf,
}

impl CgroupHandle {
    /// The **generation leaf**: the directory this deploy's processes join.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The **workload node**: the directory carrying this workload's ceiling and
    /// its (hierarchical, so subtree-wide) counters.
    pub fn workload_path(&self) -> &Path {
        &self.workload
    }

    /// This deploy's generation — the last component of
    /// [`CgroupHandle::path`]. Monotonic across deploys of the same workload
    /// and across a kamaji restart; see [`mint_generation`].
    pub fn generation(&self) -> &str {
        self.path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
    }

    /// This leaf's `cgroup.procs`. A process writes its own pid here to join.
    pub fn procs_path(&self) -> PathBuf {
        self.path.join("cgroup.procs")
    }

    /// Write `pid` to this cgroup's `cgroup.procs`.
    pub fn attach_pid(&self, pid: u32) -> Result<(), CgroupError> {
        write_file(&self.procs_path(), &pid.to_string())
    }

    /// Register the post-fork/pre-exec hook that joins a forked child to **this**
    /// generation leaf, on `cmd`.
    ///
    /// This is the one and only way a kamaji-forked workload enters its cgroup
    /// (R885-B1 wrote it inline in [`crate::native`]; R885-B10 lifted it here
    /// when the JIT fork path needed the same thing). It lives on the handle
    /// rather than at either call site on purpose: two spawners each carrying
    /// their own copy of the attach is precisely the shape that let the R406
    /// boundary layers rot unreachable for two months, and a second copy would
    /// be free to drift to the wrong one of [`CgroupHandle::path`] /
    /// [`CgroupHandle::workload_path`] — a pid in the node breaks the
    /// no-internal-process rule and is silently wrong rather than an error.
    ///
    /// **Self-attach, not parent-attach.** The child writes its own pid into the
    /// leaf's `cgroup.procs` before `exec`, so there is no window in which
    /// workload code runs outside its ceiling, and no sync pipe is needed —
    /// nothing but this closure runs between `fork` and the write. A process may
    /// always move itself into a cgroup it can write, which under `Delegate=yes`
    /// this whole subtree is.
    ///
    /// Takes the **std** [`std::process::Command`]; a `tokio::process::Command`
    /// caller passes `cmd.as_std_mut()`. Errors before the fork (a NUL in the
    /// path) so a caller can fail the deploy rather than fork unconfined; an
    /// error *inside* the hook fails the spawn itself, which is the same
    /// choice — a workload that could not be confined does not start.
    ///
    /// # Which forks are in scope
    ///
    /// Auditing `Command::new` across this crate (R885-B10) turns up three
    /// classes, and only the first is this function's business:
    ///
    /// - **Workload forks** — `native::spawn_child` and `jit::spawn_jit_child`.
    ///   Both call this. A new one must too.
    /// - **The microVM's VMM** (`microvm::GuestBoot::boot`) — excluded, and
    ///   the reason is stated at that spawn site: the guest's ceiling is its
    ///   `mem_size_mib`, so a `memory.max` around the VMM would be a second
    ///   independent ceiling on one workload.
    /// - **kamaji's own tool invocations** — `docker`, `ip`, and friends, always
    ///   `.output()`-shaped and gone in milliseconds. They are kamaji doing its
    ///   job, not a tenant's code, so they belong in kamaji's own cgroup
    ///   (`<delegated-root>/native`) exactly where they land today.
    #[cfg(target_os = "linux")]
    pub fn attach_at_exec(&self, cmd: &mut std::process::Command) -> io::Result<()> {
        use std::os::unix::process::CommandExt as _;

        let procs = std::ffi::CString::new(self.procs_path().as_os_str().as_encoded_bytes())
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cgroup.procs path contains a NUL",
                )
            })?;
        // SAFETY: the closure runs post-fork/pre-exec in the child and calls only
        // async-signal-safe libc primitives (getpid, open, write, close) over a
        // stack buffer. The path CString is built here, before the fork, so the
        // child allocates nothing.
        unsafe {
            cmd.pre_exec(move || {
                let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut buf = [0u8; 20];
                let n = fmt_u32(libc::getpid() as u32, &mut buf);
                let written = libc::write(fd, buf[buf.len() - n..].as_ptr().cast(), n);
                let err = (written != n as isize).then(io::Error::last_os_error);
                libc::close(fd);
                match err {
                    Some(e) => Err(e),
                    None => Ok(()),
                }
            });
        }
        Ok(())
    }

    /// Sample every read-only counter this leaf exposes (R885-F3).
    ///
    /// **This is the module's only read path.** Until R885-F3 the driver wrote
    /// limits and never looked at what the kernel made of them, which is why an
    /// OOM kill and an ordinary `SIGKILL` were the same event to every layer
    /// above: `memory.events`' `oom_kill` is the one counter that separates
    /// them, and nothing read it.
    ///
    /// Infallible by construction. Every field is independently [`Option`] and a
    /// `None` means **not measured** — the file is absent, unreadable, or the
    /// kernel is too old for that key — which is deliberately distinct from
    /// `Some(0)`, "measured, and the answer is zero". The distinction is the
    /// whole point of the ticket: "this workload was not OOM-killed" and "this
    /// host could not tell us" must not be the same value, or the classification
    /// invents an answer on every host that degrades. Both degrade paths under
    /// R885 produce exactly that situation — a host with no delegated subtree
    /// has no leaf at all ([`crate::native::resolve_cgroup_root`] → `None`), and
    /// a host with no delegated `pids` has a leaf with no `pids.current` in it
    /// (R885-T2) — so a reader that panicked or logged loudly on an absent file
    /// would fire on ordinary, supported fleet configurations.
    ///
    /// The counters are cumulative over the *node's* life, not the process's.
    /// The node outlives every restart **and every generation** (it is minted at
    /// deploy and `rmdir`ed at teardown), so a caller asking "did **this run**
    /// get OOM-killed?" must diff against the previous sample rather than test
    /// for nonzero — see [`classify_exit`] and its caller in [`crate::native`].
    /// R885-B4's generation level did not make that delta unnecessary: it is the
    /// node that is read, precisely because these counters are hierarchical and
    /// a generation leaf carries none of them.
    pub fn read_stats(&self) -> CgroupStats {
        read_stats_at(&self.workload)
    }
}

/// The path half of [`CgroupHandle::read_stats`] — sample a workload node
/// directly, for a caller holding a path rather than a live handle (the teardown
/// read in [`CgroupV2::destroy_workload`]).
fn read_stats_at(node: &Path) -> CgroupStats {
    let memory_events = read_opt(&node.join("memory.events"));
    let cpu_stat = read_opt(&node.join("cpu.stat"));
    CgroupStats {
        oom_kill: memory_events
            .as_deref()
            .and_then(|c| flat_keyed_value(c, "oom_kill")),
        oom_group_kill: memory_events
            .as_deref()
            .and_then(|c| flat_keyed_value(c, "oom_group_kill")),
        memory_peak_bytes: read_opt(&node.join("memory.peak"))
            .as_deref()
            .and_then(single_value),
        cpu_nr_periods: cpu_stat
            .as_deref()
            .and_then(|c| flat_keyed_value(c, "nr_periods")),
        cpu_nr_throttled: cpu_stat
            .as_deref()
            .and_then(|c| flat_keyed_value(c, "nr_throttled")),
        cpu_throttled_usec: cpu_stat
            .as_deref()
            .and_then(|c| flat_keyed_value(c, "throttled_usec")),
        pids_current: read_opt(&node.join("pids.current"))
            .as_deref()
            .and_then(single_value),
    }
}

/// One sample of a leaf's read-only counters, from [`CgroupHandle::read_stats`].
///
/// `None` on any field is **not measured**, never "zero" — see that method for
/// why the two must stay distinct. [`Default`] is therefore "nothing was
/// measured", which is the correct reading for a workload on a host with no
/// cgroup subtree at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CgroupStats {
    /// `memory.events` `oom_kill` — processes in this leaf killed by the OOM
    /// killer, cumulative over the leaf's life. The one counter that separates
    /// an OOM from an ordinary `SIGKILL`.
    pub oom_kill: Option<u64>,
    /// `memory.events` `oom_group_kill` — times the whole leaf was killed as a
    /// group (`memory.oom.group`). Absent on kernels before 5.14.
    pub oom_group_kill: Option<u64>,
    /// `memory.peak` — high-water mark of this leaf's memory usage in bytes.
    /// Absent on kernels before 5.19, which is why it is not load-bearing for
    /// the classification: it is context for the operator, not evidence.
    pub memory_peak_bytes: Option<u64>,
    /// `cpu.stat` `nr_periods` — scheduling periods elapsed. Only counted once
    /// a `cpu.max` quota exists, so it is `Some(0)` on a workload that declares
    /// no ceiling (R885-B5) and that is the truthful answer.
    pub cpu_nr_periods: Option<u64>,
    /// `cpu.stat` `nr_throttled` — periods in which the leaf was throttled
    /// against its `cpu.max`. Nonzero here is the fingerprint of the R885-B5
    /// bug (a request rendered as a quota) and of a genuinely under-provisioned
    /// ceiling; the two are told apart by whether `cpu.max` was declared.
    pub cpu_nr_throttled: Option<u64>,
    /// `cpu.stat` `throttled_usec` — total time spent throttled.
    pub cpu_throttled_usec: Option<u64>,
    /// `pids.current` — processes in the leaf right now. Absent exactly when
    /// R885-T2's best-effort `pids` enable did not take, i.e. on a host that has
    /// not delegated `pids` to kamaji's subtree; the file does not exist there
    /// at all, so this reads `None` rather than `Some(0)`.
    pub pids_current: Option<u64>,
}

impl CgroupStats {
    /// `true` when at least one counter was readable. `false` is "this leaf told
    /// us nothing" — no cgroup, or a directory that is not a cgroupfs.
    pub fn measured(&self) -> bool {
        self.oom_kill.is_some()
            || self.oom_group_kill.is_some()
            || self.memory_peak_bytes.is_some()
            || self.cpu_nr_periods.is_some()
            || self.cpu_nr_throttled.is_some()
            || self.cpu_throttled_usec.is_some()
            || self.pids_current.is_some()
    }
}

/// How one run of a workload ended, once the exit status has been read
/// **together with** its cgroup's OOM counter (R885-F3).
///
/// The two inputs are needed jointly and neither is sufficient. An exit status
/// of `Signaled(SIGKILL)` is what an OOM kill, an operator's `kill -9` and a
/// supervisor's own escalation after `TERM_GRACE` all look like. An `oom_kill`
/// counter, read alone, is cumulative over the leaf's whole life and so stays
/// nonzero forever after the first OOM — which is the false-positive direction,
/// and the one that would quietly relabel every later crash of a workload that
/// OOMed once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitClass {
    /// Killed by a signal, and the leaf recorded an OOM kill during this run.
    /// The `memory.max` R885-B1 put on the live path is what the workload hit.
    OomKilled { signal: i32 },
    /// Killed by a signal with no OOM kill recorded against the leaf — an
    /// operator, a supervisor escalation, a segfault.
    Signaled { signal: i32 },
    /// Exited of its own accord, and the leaf recorded an OOM kill during this
    /// run: a **descendant** was OOM-killed and the root process reported the
    /// loss as its own failure.
    ///
    /// This is not a corner case, it is the R590-B10 shape verbatim — a forge
    /// workload whose `cargo` exited nonzero because a `rustc` under it was
    /// killed against a 256 MB ceiling. The root process was never signalled, so
    /// a classifier that only looked at the exit status could not see the OOM
    /// at all, and the diagnosis took a disk-forensics pass.
    ExitedUnderOom { exit_code: i32 },
    /// Ordinary exit, no OOM kill recorded.
    Exited { exit_code: i32 },
}

impl ExitClass {
    /// `true` when the kernel's OOM killer was involved in this run.
    pub fn is_oom(&self) -> bool {
        matches!(
            self,
            ExitClass::OomKilled { .. } | ExitClass::ExitedUnderOom { .. }
        )
    }
}

/// Classify one run's ending from its signal (if any) and the number of OOM
/// kills the leaf recorded **during that run**.
///
/// `oom_kills_this_run` is a *delta*, not a total, and `None` means the counter
/// could not be read at all (no cgroup, no `memory.events`). `None` is treated
/// exactly like `Some(0)` for the verdict — an unmeasured host classifies as
/// `Signaled`/`Exited`, the same answer the whole fleet gave before this ticket
/// — because the alternative is to invent an OOM on every degraded host. The
/// caller keeps the `None`/`Some(0)` distinction for its telemetry, where it is
/// the difference between "not OOM-killed" and "we could not tell".
pub fn classify_exit(
    signal: Option<i32>,
    exit_code: i32,
    oom_kills_this_run: Option<u64>,
) -> ExitClass {
    let oomed = oom_kills_this_run.unwrap_or(0) > 0;
    match (signal, oomed) {
        (Some(signal), true) => ExitClass::OomKilled { signal },
        (Some(signal), false) => ExitClass::Signaled { signal },
        (None, true) => ExitClass::ExitedUnderOom { exit_code },
        (None, false) => ExitClass::Exited { exit_code },
    }
}

/// Read a cgroup control file, or `None` if it is absent/unreadable. Never an
/// error: see [`CgroupHandle::read_stats`] for why an absent counter is an
/// ordinary, supported state rather than a fault.
fn read_opt(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

/// Pull one key out of a cgroup v2 **flat-keyed** file (`memory.events`,
/// `cpu.stat`): one `key value` pair per line, no header, no ordering promise.
///
/// `None` for a key the kernel does not emit — `oom_group_kill` before 5.14,
/// the `cpu.max`-dependent throttling keys on some configurations — which is
/// why the caller keeps every field optional rather than defaulting to 0.
fn flat_keyed_value(contents: &str, key: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let mut parts = line.split_ascii_whitespace();
        if parts.next()? != key {
            return None;
        }
        parts.next()?.parse().ok()
    })
}

/// Parse a cgroup v2 **single-value** file (`memory.peak`, `pids.current`): one
/// number, or the literal `max`. `max` reads as `None` — it is the absence of a
/// measurement, not a number a caller should do arithmetic on.
fn single_value(contents: &str) -> Option<u64> {
    contents.trim().parse().ok()
}

/// Pull the cgroup v2 path out of `/proc/self/cgroup`'s contents.
///
/// The unified hierarchy is always the line with controller list `0` and an
/// empty controller name: `0::/yubaba.slice/kamaji.service/native`. v1
/// hierarchies appear as `<n>:<controller>:<path>` lines and are ignored — a
/// host with no `0::` line has no cgroup v2 for us to use.
fn own_cgroup_path(proc_self_cgroup: &str) -> Option<String> {
    proc_self_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|p| p.trim().to_string())
}

/// Translate a millicore **request** (1000 = one full core) into a cgroup v2
/// `cpu.weight` value — the workload's relative share of a contended node,
/// imposing no ceiling on an idle one.
///
/// `1000m` ⇒ [`DEFAULT_CPU_WEIGHT`], the same "one core is the platform
/// default" scale the containerd and docker backends use with `cpu.shares`
/// (`1000m` ⇒ `1024`, cgroup v1's default). Clamped into the kernel's
/// `1..=10000`, so a sub-`10m` request still gets a nonzero share rather than a
/// rejected write. A request of `0` — none declared — renders as the default
/// weight, i.e. an ordinary share.
pub fn format_cpu_weight(cpu_millis: u32) -> String {
    if cpu_millis == 0 {
        return DEFAULT_CPU_WEIGHT.to_string();
    }
    let weight = (u64::from(cpu_millis) * DEFAULT_CPU_WEIGHT) / MILLIS_PER_CORE;
    weight.clamp(CPU_WEIGHT_MIN, CPU_WEIGHT_MAX).to_string()
}

/// Translate a millicore **ceiling** (1000 = one full core) into a cgroup v2
/// `cpu.max` line — `"<quota_us> <period_us>"`, or `"max <period>"` for
/// unlimited.
///
/// Only a workload that declares `yah.limits.cpu-millis` gets this file written
/// at all. Do not feed it `ResourceLimits::cpu_millis`: that is the request, and
/// rendering a request as a quota is the R885-B5 bug.
pub fn format_cpu_max(limit_millis: u32) -> String {
    if limit_millis == 0 {
        return format!("max {CPU_PERIOD_US}");
    }
    let quota = (u64::from(limit_millis) * CPU_PERIOD_US) / MILLIS_PER_CORE;
    let quota = quota.max(1);
    format!("{quota} {CPU_PERIOD_US}")
}

/// Translate `memory_mb` into a cgroup v2 `memory.max` line — a byte count, or
/// the literal `"max"` for unlimited.
pub fn format_memory_max(memory_mb: u32) -> String {
    if memory_mb == 0 {
        "max".to_string()
    } else {
        let bytes = u64::from(memory_mb) * 1024 * 1024;
        bytes.to_string()
    }
}

fn enable_controllers_directive(controllers: &[&str]) -> String {
    controllers
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// What [`CgroupV2::destroy_workload`] did, for the caller to log.
///
/// A teardown is the last thing that ever sees a workload's cgroup, so it is
/// also the last thing that can say anything about it. Returning this rather
/// than `()` is what lets `crate::native` report the final counters and the
/// leak count instead of `rmdir`ing the evidence and logging nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestroyOutcome {
    /// The workload node's final counters, sampled after the kill and before the
    /// `rmdir`. All-`None` when the node was already gone.
    pub stats: CgroupStats,
    /// Generation leaves killed, drained and removed.
    pub removed: usize,
    /// Why each generation leaf that could not be emptied or removed stayed —
    /// rendered at the point of failure, where the context is. Non-empty means
    /// the workload node was deliberately left in place too, so that whatever
    /// survived stays under the ceiling it was deployed with.
    ///
    /// **This, not the `Result`, is the thing a caller checks.** Teardown's
    /// contract is idempotent success and one stuck workload must not fail it;
    /// the `Result` is reserved for an id that was never valid.
    pub leaked: Vec<String>,
    /// Whether the workload node itself was removed. `false` with an empty
    /// `leaked` is the off-Linux/tempdir reading — there, the control files are
    /// ordinary files that hold the directory, where a real cgroupfs discards
    /// them with it.
    pub node_removed: bool,
    /// How the last generation swept was emptied. `None` when there was nothing
    /// to sweep — an already-torn-down workload, or a host with no cgroupfs.
    pub method: Option<KillMethod>,
}

/// How a generation leaf was emptied before its `rmdir`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillMethod {
    /// `cgroup.kill` — one write, reaching every process in the cgroup **and
    /// every descendant**, with no window for a survivor to fork away between
    /// the read of `cgroup.procs` and the signal. Requires kernel >= 5.14.
    CgroupKill,
    /// The pre-5.14 fallback: freeze the cgroup so nothing can fork, `SIGKILL`
    /// every pid in `cgroup.procs`, then thaw. Equivalent in effect —
    /// `cgroup.freeze` is kernel >= 5.2 and cgroup v2 deliberately lets fatal
    /// signals through to frozen tasks — but it is a read-then-signal rather
    /// than one atomic write, which is why it is the fallback and not the
    /// default.
    FreezeAndSweep { signalled: usize },
    /// Neither mechanism was available: no `cgroup.kill`, no `cgroup.freeze`,
    /// and nothing in `cgroup.procs`. This is the ordinary reading off-Linux and
    /// against a tempdir, and the ordinary reading on Linux for a leaf whose
    /// only process the supervisor already reaped.
    Unavailable,
}

/// Empty one generation leaf: [`KillMethod::CgroupKill`] when the kernel offers
/// it, otherwise freeze + sweep.
///
/// Returns without waiting — the kill is asynchronous either way, and
/// [`drain`] is the half that waits.
fn kill_cgroup(leaf: &Path) -> KillMethod {
    // A cgroup v2 kernel >= 5.14 materialises `cgroup.kill` on every non-root
    // cgroup, so a successful write is proof the kernel has it and an absent
    // file is proof it does not. There is no version number to read and no need
    // for one — which is what makes this safe to ship without having
    // established the fleet's kernel.
    if write_existing(&leaf.join("cgroup.kill"), "1").is_ok() {
        return KillMethod::CgroupKill;
    }
    freeze_and_sweep(leaf)
}

/// Write to a cgroup control file **without creating it**.
///
/// Every write in this module targets a file the kernel materialised; none of
/// them should ever bring a file into existence. On a real cgroupfs that is
/// already true by accident — kernfs has no `create` inode op, so `O_CREAT`
/// against a name that is not there fails — but relying on the accident is what
/// made the first cut of this teardown create a `cgroup.kill` on every host
/// without one, leaving a regular file behind that then blocked the very `rmdir`
/// the kill existed to enable. Asking for the file explicitly makes "the kernel
/// does not offer this interface" a first-class answer on every filesystem.
fn write_existing(path: &Path, contents: &str) -> io::Result<()> {
    use std::io::Write as _;
    fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .write_all(contents.as_bytes())
}

/// The pre-`cgroup.kill` teardown: hold the cgroup frozen so nothing in it can
/// fork a new survivor out from under us, `SIGKILL` everything the freeze
/// caught, then thaw so the kills are collected.
///
/// The freeze is what makes one pass sufficient. Without it, a process that
/// forks between the `cgroup.procs` read and the signal is missed, and the
/// `rmdir` still fails `EBUSY` — which is the whole failure this ticket exists
/// to close, reintroduced by a sloppier fallback.
fn freeze_and_sweep(leaf: &Path) -> KillMethod {
    let freeze = leaf.join("cgroup.freeze");
    let frozen = write_existing(&freeze, "1").is_ok();
    let mut signalled = 0;
    for pid in member_pids(leaf) {
        if kill_pid(pid) {
            signalled += 1;
        }
    }
    if frozen {
        // Thaw unconditionally: a `SIGKILL` is delivered to a frozen task but
        // the task does not finish dying until it runs, and a leaf left frozen
        // is a leaf that can never drain.
        let _ = write_existing(&freeze, "0");
    }
    if signalled == 0 && !frozen {
        KillMethod::Unavailable
    } else {
        KillMethod::FreezeAndSweep { signalled }
    }
}

/// Wait for a killed leaf to stop holding live processes, up to
/// [`DRAIN_BUDGET`].
///
/// Blocking rather than `async` because the whole driver is blocking `std::fs`
/// and the normal case does not sleep at all: the first poll runs immediately
/// after the kill and a leaf whose processes are already reaped returns on it.
/// Only a genuine survivor costs the sleeps, and only up to the budget.
fn drain(leaf: &Path) -> Result<(), CgroupError> {
    let mut waited = Duration::ZERO;
    loop {
        let live: Vec<u32> = member_pids(leaf)
            .into_iter()
            .filter(|p| is_live(*p))
            .collect();
        if live.is_empty() {
            return Ok(());
        }
        if waited >= DRAIN_BUDGET {
            return Err(CgroupError::Busy {
                path: leaf.to_path_buf(),
                pids: live,
                waited_ms: waited.as_millis() as u64,
            });
        }
        std::thread::sleep(DRAIN_POLL);
        waited += DRAIN_POLL;
    }
}

/// The pids in a cgroup's `cgroup.procs`, absent/unreadable reading as empty.
///
/// `0` is dropped rather than parsed: `kill(0, sig)` signals the caller's whole
/// process group, so a malformed line must never reach [`kill_pid`] as one.
fn member_pids(leaf: &Path) -> Vec<u32> {
    let Some(contents) = read_opt(&leaf.join("cgroup.procs")) else {
        return Vec::new();
    };
    contents
        .lines()
        .filter_map(|l| l.trim().parse::<u32>().ok())
        .filter(|pid| *pid != 0 && *pid != std::process::id())
        .collect()
}

/// `SIGKILL` one pid, reporting whether the signal was accepted.
#[cfg(unix)]
fn kill_pid(pid: u32) -> bool {
    // SAFETY: `kill(2)` with a validated non-zero pid. `member_pids` has already
    // excluded `0` (the whole process group) and kamaji's own pid.
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) == 0 }
}

#[cfg(not(unix))]
fn kill_pid(_pid: u32) -> bool {
    false
}

/// Whether a pid still names a live process. `EPERM` counts as live — it means
/// the process is there and not ours to signal, which is emphatically not
/// "drained".
#[cfg(unix)]
fn is_live(pid: u32) -> bool {
    // SAFETY: `kill(2)` with signal 0 — an existence probe that delivers
    // nothing. Same non-zero-pid guarantee as `kill_pid`.
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return true;
    }
    io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn is_live(_pid: u32) -> bool {
    false
}

/// Every generation directory under a workload node, oldest first.
///
/// Ordinary files are skipped: on a real cgroupfs the node's children are its
/// control files plus its cgroups, and only the latter are directories.
fn generation_leaves(node: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(node) else {
        return Vec::new();
    };
    let mut leaves: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .collect();
    leaves.sort();
    leaves
}

/// Name this deploy's generation directory under `node`.
///
/// The wall-clock nanosecond count, zero-padded to 19 digits so that a
/// lexicographic listing is a chronological one. Chosen over a counter because
/// **a counter has to live somewhere**: in memory it does not survive the kamaji
/// restart R885-B7 is about, and on disk it is a second piece of state to keep
/// consistent with the directory it names. The clock needs neither and is
/// already monotonic across a restart.
///
/// The `exists` bump makes collision-freedom a property of this function rather
/// than of the clock's resolution, and terminates because the number of
/// directories under `node` is finite.
fn mint_generation(node: &Path) -> String {
    let mut nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    loop {
        let name = format!("{nanos:019}");
        if !node.join(&name).exists() {
            return name;
        }
        nanos += 1;
    }
}

/// `rmdir`, with `NotFound` as success so teardown is idempotent.
fn remove_dir(path: &Path) -> Result<(), CgroupError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CgroupError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// One safe cgroup path component.
///
/// R885-B4 made the hierarchy `<workload-id>/<generation>` rather than a single
/// flat `<workload-id>`, and this is deliberately still the *component* rule
/// rather than a relaxed one that permits a slash. Two components validated
/// separately is strictly stronger than one component allowed to contain one
/// separator, and the generation half is minted from a clock reading here in
/// this module rather than supplied by a caller — so nothing gains the ability
/// to smuggle nesting through a workload name.
fn validate_component(id: &str) -> Result<(), CgroupError> {
    if id.is_empty() || id.contains('/') || id.contains('\0') || id == "." || id == ".." {
        return Err(CgroupError::InvalidWorkloadId(id.to_string()));
    }
    Ok(())
}

fn create_dir_all(path: &Path) -> Result<(), CgroupError> {
    fs::create_dir_all(path).map_err(|source| CgroupError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Render `n` into the tail of `buf` as decimal ASCII, returning the digit
/// count. Allocation-free on purpose: the only caller runs it in a forked
/// child, where `format!` would have to take the allocator's lock.
#[cfg(target_os = "linux")]
fn fmt_u32(mut n: u32, buf: &mut [u8; 20]) -> usize {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    buf.len() - i
}

fn write_file(path: &Path, contents: &str) -> Result<(), CgroupError> {
    fs::write(path, contents).map_err(|source| CgroupError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Debug, Error)]
pub enum CgroupError {
    #[error("workload id {0:?} is not a valid cgroup directory name")]
    InvalidWorkloadId(String),
    #[error("cgroup io at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// A generation leaf still held live processes after it was killed and
    /// waited on — the `EBUSY` case, but named, with the pids that caused it,
    /// instead of an errno with no evidence attached (R885-B4).
    #[error("cgroup at {path} still holds live processes {pids:?} after a kill and {waited_ms}ms")]
    Busy {
        path: PathBuf,
        pids: Vec<u32>,
        waited_ms: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A workload declaring a request and no ceiling — the ordinary shape.
    fn limits(memory_mb: u32, cpu_millis: u32) -> WorkloadLimits {
        WorkloadLimits::from_request(&ResourceLimits {
            memory_mb,
            cpu_millis,
            memory_request_mb: None,
            cpu_limit_millis: None,
            pids_max: None,
            scratch_floor_mb: None,
        })
    }

    fn driver() -> (TempDir, CgroupV2) {
        let tmp = TempDir::new().unwrap();
        let cg = CgroupV2::new(tmp.path());
        (tmp, cg)
    }

    /// A leaf with the control files a live cgroup v2 kernel writes.
    fn leaf_with(files: &[(&str, &str)]) -> (TempDir, CgroupHandle) {
        let (tmp, cg) = driver();
        let handle = cg.create_workload("svc", &limits(64, 500)).unwrap();
        for (name, contents) in files {
            fs::write(handle.workload_path().join(name), contents).unwrap();
        }
        (tmp, handle)
    }

    const MEMORY_EVENTS_ONE_OOM: &str =
        "low 0\nhigh 0\nmax 12\noom 1\noom_kill 1\noom_group_kill 0\n";

    const CPU_STAT_THROTTLED: &str = "usage_usec 8000000\nuser_usec 6000000\nsystem_usec 2000000\nnr_periods 400\nnr_throttled 37\nthrottled_usec 1250000\n";

    #[test]
    fn read_stats_pulls_every_counter_off_a_live_shaped_leaf() {
        let (_tmp, handle) = leaf_with(&[
            ("memory.events", MEMORY_EVENTS_ONE_OOM),
            ("memory.peak", "268435456\n"),
            ("cpu.stat", CPU_STAT_THROTTLED),
            ("pids.current", "12\n"),
        ]);
        let stats = handle.read_stats();
        assert_eq!(stats.oom_kill, Some(1));
        assert_eq!(stats.oom_group_kill, Some(0));
        assert_eq!(stats.memory_peak_bytes, Some(268_435_456));
        assert_eq!(stats.cpu_nr_periods, Some(400));
        assert_eq!(stats.cpu_nr_throttled, Some(37));
        assert_eq!(stats.cpu_throttled_usec, Some(1_250_000));
        assert_eq!(stats.pids_current, Some(12));
        assert!(stats.measured());
    }

    /// The distinction the whole ticket rests on: an absent counter must read as
    /// "not measured", never as a measured zero. Both R885 degrade paths produce
    /// this shape — no delegated subtree at all, or no delegated `pids`.
    #[test]
    fn an_absent_counter_reads_as_not_measured_rather_than_zero() {
        // A leaf with memory.events but no pids.current: exactly the host
        // R885-T2's best-effort `pids` enable declines to bound.
        let (_tmp, handle) = leaf_with(&[("memory.events", MEMORY_EVENTS_ONE_OOM)]);
        let stats = handle.read_stats();
        assert_eq!(stats.oom_kill, Some(1));
        assert_eq!(stats.pids_current, None, "absent file is not a measured 0");
        assert_eq!(stats.memory_peak_bytes, None);
        assert_eq!(stats.cpu_nr_throttled, None);
        assert!(stats.measured());

        // And a leaf with nothing in it at all — a non-cgroupfs directory, or a
        // host with no delegated subtree.
        let (_tmp2, bare) = leaf_with(&[]);
        let none = bare.read_stats();
        assert_eq!(none, CgroupStats::default());
        assert!(!none.measured(), "a leaf that told us nothing is not zero");
    }

    /// A kernel that emits `oom_kill` but not `oom_group_kill` (pre-5.14) must
    /// leave the second one absent rather than defaulting it to 0.
    #[test]
    fn a_key_the_kernel_does_not_emit_is_absent_not_zero() {
        let (_tmp, handle) =
            leaf_with(&[("memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")]);
        let stats = handle.read_stats();
        assert_eq!(stats.oom_kill, Some(0), "emitted and genuinely zero");
        assert_eq!(stats.oom_group_kill, None, "not emitted by this kernel");
    }

    #[test]
    fn flat_keyed_matches_the_whole_key_not_a_prefix() {
        // `oom` and `oom_kill` are different keys and `oom` comes first.
        assert_eq!(flat_keyed_value(MEMORY_EVENTS_ONE_OOM, "oom"), Some(1));
        assert_eq!(flat_keyed_value(MEMORY_EVENTS_ONE_OOM, "oom_kill"), Some(1));
        assert_eq!(flat_keyed_value(MEMORY_EVENTS_ONE_OOM, "oom_k"), None);
        assert_eq!(flat_keyed_value("", "oom_kill"), None);
        assert_eq!(flat_keyed_value("oom_kill\n", "oom_kill"), None);
        assert_eq!(flat_keyed_value("oom_kill bogus\n", "oom_kill"), None);
    }

    #[test]
    fn a_single_value_file_may_say_max_which_is_not_a_number() {
        assert_eq!(single_value("4194304\n"), Some(4_194_304));
        assert_eq!(single_value("max\n"), None);
        assert_eq!(single_value(""), None);
    }

    /// The classification truth table, both directions. The false-positive
    /// direction is the one that bites: a leaf whose `oom_kill` is nonzero from
    /// an EARLIER run must not relabel this run's ordinary `SIGKILL`, which is
    /// why the input is a per-run delta rather than the raw counter.
    #[test]
    fn an_oom_kill_and_a_plain_sigkill_classify_differently() {
        const SIGKILL: i32 = 9;
        assert_eq!(
            classify_exit(Some(SIGKILL), -1, Some(1)),
            ExitClass::OomKilled { signal: SIGKILL }
        );
        assert_eq!(
            classify_exit(Some(SIGKILL), -1, Some(0)),
            ExitClass::Signaled { signal: SIGKILL }
        );
        assert!(classify_exit(Some(SIGKILL), -1, Some(1)).is_oom());
        assert!(!classify_exit(Some(SIGKILL), -1, Some(0)).is_oom());
    }

    #[test]
    fn an_unmeasured_counter_never_invents_an_oom() {
        // A host with no cgroup subtree reads `None` and must classify exactly
        // as the whole fleet did before this ticket, not as an OOM.
        assert_eq!(
            classify_exit(Some(9), -1, None),
            ExitClass::Signaled { signal: 9 }
        );
        assert_eq!(
            classify_exit(None, 1, None),
            ExitClass::Exited { exit_code: 1 }
        );
        assert!(!classify_exit(Some(9), -1, None).is_oom());
    }

    /// R590-B10's shape: the root process exited nonzero of its own accord
    /// because a descendant was OOM-killed under it.
    #[test]
    fn a_descendant_oom_is_visible_even_though_the_root_exited_normally() {
        assert_eq!(
            classify_exit(None, 101, Some(1)),
            ExitClass::ExitedUnderOom { exit_code: 101 }
        );
        assert!(classify_exit(None, 101, Some(1)).is_oom());
        assert_eq!(
            classify_exit(None, 0, Some(0)),
            ExitClass::Exited { exit_code: 0 }
        );
    }

    #[test]
    fn ensure_root_creates_the_root_directory() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        assert!(cg.root().is_dir());
    }

    #[test]
    fn ensure_root_is_idempotent() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        cg.ensure_root().unwrap();
    }

    /// R885-B5, the limit-ABSENT shape — the one that proves an ordinary
    /// workload is no longer throttled. A request renders as a weight, and
    /// nothing writes `cpu.max` at all.
    #[test]
    fn a_workload_with_no_declared_ceiling_gets_a_weight_and_no_quota() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-a", &limits(256, 1000)).unwrap();

        let weight = fs::read_to_string(handle.workload_path().join("cpu.weight")).unwrap();
        assert_eq!(weight, "100");

        assert!(
            !handle.workload_path().join("cpu.max").exists(),
            "cpu.max must not be written for a workload that declares no ceiling — \
             writing the request there is the R885-B5 bug"
        );

        let mem = fs::read_to_string(handle.workload_path().join("memory.max")).unwrap();
        assert_eq!(mem, (256u64 * 1024 * 1024).to_string());
    }

    /// R885-B5, the limit-PRESENT shape. The ceiling is independent of the
    /// request: both files are written, and they carry different numbers.
    #[test]
    fn a_declared_ceiling_is_written_to_cpu_max_beside_the_weight() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let capped = WorkloadLimits {
            cpu_request_millis: 250,
            cpu_limit_millis: Some(2000),
            memory_max_mb: 256,
            pids_max: workload_spec::DEFAULT_PIDS_MAX,
        };
        let handle = cg.create_workload("svc-capped", &capped).unwrap();

        assert_eq!(
            fs::read_to_string(handle.workload_path().join("cpu.weight")).unwrap(),
            "25"
        );
        assert_eq!(
            fs::read_to_string(handle.workload_path().join("cpu.max")).unwrap(),
            "200000 100000"
        );
    }

    /// R885-T2, the ordinary shape: `pids` is delegated (a real
    /// `cgroup.controllers` lists it), `ensure_root` enables it, and an
    /// ordinary workload (no `yah.limits.pids-max` annotation, i.e.
    /// `WorkloadLimits::from_request`'s default) gets `pids.max` set to
    /// `DEFAULT_PIDS_MAX`. "Default applied."
    #[test]
    fn pids_is_enabled_when_delegated_and_the_default_ceiling_is_written() {
        let (_tmp, mut cg) = driver();
        fs::write(cg.root().join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        cg.ensure_root().unwrap();
        assert!(cg.pids_available());

        let handle = cg.create_workload("svc-pids", &limits(256, 1000)).unwrap();
        assert_eq!(
            fs::read_to_string(handle.workload_path().join("pids.max")).unwrap(),
            workload_spec::DEFAULT_PIDS_MAX.to_string()
        );
    }

    /// R885-T2, the override shape: a caller-supplied ceiling (what
    /// `WorkloadSpec::pids_limit` returns for a spec carrying
    /// `yah.limits.pids-max`) is written verbatim, independent of the
    /// default. "Annotation override applied."
    #[test]
    fn a_custom_pids_ceiling_is_written_when_pids_is_available() {
        let (_tmp, mut cg) = driver();
        fs::write(cg.root().join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        cg.ensure_root().unwrap();
        let capped = WorkloadLimits {
            cpu_request_millis: 500,
            cpu_limit_millis: None,
            memory_max_mb: 256,
            pids_max: 128,
        };
        let handle = cg.create_workload("svc-pids-custom", &capped).unwrap();
        assert_eq!(
            fs::read_to_string(handle.workload_path().join("pids.max")).unwrap(),
            "128"
        );
    }

    /// R885-T2's hazard, and the important one: a host where `pids` was never
    /// delegated (absent from `cgroup.controllers` — the ordinary case for
    /// any host that hasn't taken a matching unit-file change) must not lose
    /// `cpu`/`memory` enforcement over it. Only `pids.max` is skipped.
    #[test]
    fn pids_unavailable_degrades_only_pids_cpu_and_memory_still_enforced() {
        let (_tmp, mut cg) = driver();
        fs::write(cg.root().join("cgroup.controllers"), "cpu memory\n").unwrap();
        cg.ensure_root().unwrap();
        assert!(!cg.pids_available());

        let handle = cg
            .create_workload("svc-nopids", &limits(256, 1000))
            .unwrap();

        assert_eq!(
            fs::read_to_string(handle.workload_path().join("cpu.weight")).unwrap(),
            "100"
        );
        assert_eq!(
            fs::read_to_string(handle.workload_path().join("memory.max")).unwrap(),
            (256u64 * 1024 * 1024).to_string()
        );
        assert!(
            !handle.workload_path().join("pids.max").exists(),
            "pids.max must not be written when the controller was never enabled"
        );
    }

    /// The plain-tempdir / off-Linux case every other test in this module
    /// runs under: no `cgroup.controllers` file exists at all, which must
    /// read the same as "pids not offered" rather than panic or error.
    #[test]
    fn ensure_root_without_a_controllers_file_leaves_pids_unavailable() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        assert!(!cg.pids_available());
    }

    #[test]
    fn cpu_weight_translates_a_request_to_a_relative_share() {
        // 1000m = one core = the cgroup v2 default weight, mirroring the
        // containerd/docker `1000m` => 1024 shares (cgroup v1's default).
        assert_eq!(format_cpu_weight(1000), "100");
        // Proportional either side of it.
        assert_eq!(format_cpu_weight(250), "25");
        assert_eq!(format_cpu_weight(4000), "400");
        // Clamped into the kernel's 1..=10000: a tiny request still gets a
        // share, a huge one does not produce a rejected write.
        assert_eq!(format_cpu_weight(1), "1");
        assert_eq!(format_cpu_weight(9), "1");
        assert_eq!(format_cpu_weight(1_000_000), "10000");
        // No declared request = an ordinary share, not the minimum.
        assert_eq!(format_cpu_weight(0), "100");
    }

    #[test]
    fn cpu_max_translates_a_ceiling_to_quota_period() {
        // 1000m = one full core
        assert_eq!(format_cpu_max(1000), "100000 100000");
        // 2000m = two cores
        assert_eq!(format_cpu_max(2000), "200000 100000");
        // 500m = half a core
        assert_eq!(format_cpu_max(500), "50000 100000");
        // 1m rounds to a 100us quota, not zero.
        assert_eq!(format_cpu_max(1), "100 100000");
        // 0 renders unlimited — though `create_workload` never calls it with 0,
        // because an absent ceiling skips the write entirely.
        assert_eq!(format_cpu_max(0), "max 100000");
    }

    /// The request and the ceiling come off different parts of the spec, and
    /// `from_request` (no spec, so no annotations) can only ever see the
    /// request.
    #[test]
    fn from_request_carries_no_ceiling() {
        let bare = limits(64, 512);
        assert_eq!(bare.cpu_request_millis, 512);
        assert_eq!(bare.cpu_limit_millis, None);
        assert_eq!(bare.memory_max_mb, 64);
    }

    #[test]
    fn memory_max_zero_means_max() {
        assert_eq!(format_memory_max(0), "max");
        assert_eq!(format_memory_max(1), (1024u64 * 1024).to_string());
        assert_eq!(format_memory_max(4096), (4096u64 * 1024 * 1024).to_string());
    }

    #[test]
    fn attach_pid_writes_to_cgroup_procs() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-b", &limits(64, 512)).unwrap();
        handle.attach_pid(4242).unwrap();
        let procs = fs::read_to_string(handle.procs_path()).unwrap();
        assert_eq!(procs, "4242");
    }

    #[test]
    fn destroy_workload_removes_directory() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-c", &limits(64, 512)).unwrap();
        let leaf = handle.path().to_path_buf();
        let node = handle.workload_path().to_path_buf();
        drop(handle);
        // On a real cgroup v2 fs, `rmdir` succeeds even though `cpu.max` etc.
        // are visible — the kernel removes those control files atomically with
        // the directory. A tempdir-backed test has them as ordinary files, so
        // we clear them first to mirror that semantic.
        for f in ["cpu.weight", "cpu.max", "memory.max", "cgroup.procs"] {
            let p = node.join(f);
            if p.exists() {
                fs::remove_file(p).unwrap();
            }
        }
        let outcome = cg.destroy_workload("svc-c").unwrap();
        assert_eq!(outcome.removed, 1, "the generation leaf was not removed");
        assert!(outcome.leaked.is_empty(), "{:?}", outcome.leaked);
        assert!(outcome.node_removed);
        assert!(!leaf.exists());
        assert!(!node.exists());
    }

    // ── R885-B4: the generation level and the teardown that makes it safe.

    /// The central claim, with a real process. A descendant the supervisor never
    /// had a handle on — double-forked away and reparented to init, so no
    /// `SIGTERM`/`SIGKILL` aimed at the supervised child can reach it — is
    /// killed by the teardown instead of holding the leaf at `EBUSY` forever.
    ///
    /// This runs the **pre-5.14 path**: a tempdir has no `cgroup.kill`, and the
    /// driver refuses to create one (see `write_existing`), so the freeze +
    /// sweep fallback is what must do the work here. That is deliberate — it is
    /// the half that cannot be proven by a kernel that has `cgroup.kill`.
    #[cfg(unix)]
    #[test]
    fn a_double_forked_descendant_is_killed_before_the_rmdir() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-forker", &limits(64, 512)).unwrap();

        // `sh` backgrounds a `sleep` and exits; `output()` reaps the `sh`, so
        // the `sleep` is an orphan reparented to init. That is a double fork,
        // performed rather than simulated.
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30 >/dev/null 2>&1 & echo $!")
            .output()
            .unwrap();
        let orphan: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
        assert!(
            is_live(orphan),
            "fixture premise: the double-forked sleep must actually be running"
        );

        // What a real kernel would be showing in the leaf the workload joined.
        fs::write(handle.path().join("cgroup.procs"), format!("{orphan}\n")).unwrap();

        let outcome = cg.destroy_workload("svc-forker").unwrap();

        assert_eq!(
            outcome.method,
            Some(KillMethod::FreezeAndSweep { signalled: 1 }),
            "a tempdir offers no cgroup.kill, so the fallback must be what ran"
        );
        assert!(
            !is_live(orphan),
            "the double-forked descendant survived the teardown — this is the R885-B4 bug"
        );
        // The EBUSY case is gone: nothing LIVE is holding the leaf. What still
        // holds it is the stand-in `cgroup.procs`, an ordinary file here and a
        // control file a real cgroupfs discards with the directory — the same
        // tempdir/cgroupfs gap `destroy_workload_removes_directory` mirrors.
        assert!(
            !outcome
                .leaked
                .iter()
                .any(|e| e.contains("still holds live")),
            "teardown reported a live holder after killing it: {:?}",
            outcome.leaked
        );
        fs::remove_file(handle.path().join("cgroup.procs")).unwrap();
        fs::remove_dir(handle.path()).expect("nothing live was left holding the leaf");
    }

    /// On a kernel that offers it, `cgroup.kill` is what runs — one write that
    /// reaches the whole subtree, with no read-then-signal window. The file's
    /// presence is the whole version check, so a leaf that has one pins it.
    #[test]
    fn cgroup_kill_is_preferred_when_the_kernel_offers_it() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-modern", &limits(64, 512)).unwrap();
        let kill = handle.path().join("cgroup.kill");
        fs::write(&kill, "").unwrap();

        let outcome = cg.destroy_workload("svc-modern").unwrap();

        assert_eq!(outcome.method, Some(KillMethod::CgroupKill));
        assert_eq!(
            fs::read_to_string(&kill).unwrap(),
            "1",
            "the kill must actually be written, not merely attempted"
        );
    }

    /// A host with neither interface — and nothing to kill — is a supported,
    /// silent state, not a failure. This is every off-Linux run.
    #[test]
    fn a_host_with_neither_kill_interface_reports_it_rather_than_failing() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        cg.create_workload("svc-bare", &limits(64, 512)).unwrap();
        let outcome = cg.destroy_workload("svc-bare").unwrap();
        assert_eq!(outcome.method, Some(KillMethod::Unavailable));
        assert_eq!(outcome.removed, 1);
        assert!(outcome.leaked.is_empty(), "{:?}", outcome.leaked);
    }

    /// Redeploy: two generations of one workload id never share a directory, and
    /// the outgoing one is gone. The ceiling is the same node both times —
    /// that is the property that lets a handoff share one budget.
    #[test]
    fn two_generations_of_one_workload_get_distinct_leaves() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();

        let first = cg.create_workload("svc-roll", &limits(64, 512)).unwrap();
        let gen1 = first.path().to_path_buf();
        assert!(gen1.is_dir());

        // Exactly the sequence `deploy_workload` runs: tear the predecessor down
        // first, then create.
        let outcome = cg.destroy_workload("svc-roll").unwrap();
        assert_eq!(outcome.removed, 1);
        assert!(!gen1.exists(), "the outgoing generation's leaf survived");

        let second = cg.create_workload("svc-roll", &limits(64, 512)).unwrap();
        assert_ne!(
            first.generation(),
            second.generation(),
            "a redeploy reused the generation identifier"
        );
        assert_ne!(gen1, second.path());
        assert_eq!(
            first.workload_path(),
            second.workload_path(),
            "both generations must hang under the one ceiling"
        );
        assert_eq!(
            fs::read_to_string(second.workload_path().join("memory.max")).unwrap(),
            (64u64 * 1024 * 1024).to_string()
        );
    }

    /// The harder half of the same property: even when the outgoing generation
    /// **leaks** — the case a `cgroup.kill` cannot fix — the incoming one gets
    /// its own directory rather than being handed the leak's. Before R885-B4
    /// there was only one directory, so this was not expressible.
    #[test]
    fn an_incoming_generation_never_lands_in_a_leaked_predecessors_leaf() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let first = cg.create_workload("svc-stuck", &limits(64, 512)).unwrap();
        // A child cgroup inside the leaf: on a real cgroupfs that is a nested
        // cgroup and `rmdir` genuinely refuses, which is the leak this pins.
        fs::create_dir(first.path().join("nested")).unwrap();

        let outcome = cg.destroy_workload("svc-stuck").unwrap();
        assert_eq!(outcome.removed, 0);
        assert_eq!(outcome.leaked.len(), 1, "{:?}", outcome.leaked);
        assert!(
            !outcome.node_removed && first.workload_path().is_dir(),
            "the ceiling must outlive a leak that is still bounded by it"
        );

        let second = cg.create_workload("svc-stuck", &limits(64, 512)).unwrap();
        assert_ne!(first.path(), second.path());
        assert!(
            first.path().is_dir(),
            "the leak is still there, as recorded"
        );
        assert!(second.path().is_dir());
    }

    /// A member that has been signalled but not yet reaped still counts as live,
    /// and the drain gives up rather than blocking a teardown forever. The
    /// conservative direction: a leaked directory is reported, and the ceiling
    /// above it is deliberately kept.
    #[cfg(unix)]
    #[test]
    fn a_member_that_never_drains_is_reported_rather_than_waited_on_forever() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-wedged", &limits(64, 512)).unwrap();

        // Our own child, never reaped: `SIGKILL` lands, but the task stays
        // visible to `kill(pid, 0)` until someone calls `wait`.
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .unwrap();
        fs::write(
            handle.path().join("cgroup.procs"),
            format!("{}\n", child.id()),
        )
        .unwrap();

        let started = std::time::Instant::now();
        let outcome = cg.destroy_workload("svc-wedged").unwrap();
        let elapsed = started.elapsed();

        assert_eq!(outcome.removed, 0);
        assert!(
            outcome
                .leaked
                .iter()
                .any(|e| e.contains("still holds live")),
            "the undrained member must be named: {:?}",
            outcome.leaked
        );
        assert!(
            elapsed >= DRAIN_BUDGET && elapsed < DRAIN_BUDGET * 4,
            "the drain must be bounded by DRAIN_BUDGET, took {elapsed:?}"
        );
        assert!(handle.workload_path().is_dir());

        let _ = child.wait();
    }

    /// R885-F3 under the new hierarchy: the counters are read off the **node**,
    /// because they are hierarchical and a generation leaf carries none of them.
    /// A reader that followed the processes instead would see nothing and
    /// classify every OOM as an ordinary crash — silently, which is why this is
    /// asserted in both directions.
    #[test]
    fn oom_counters_are_read_off_the_node_not_the_generation_leaf() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-oom", &limits(64, 512)).unwrap();

        // What a kernel puts on the node: hierarchical, so it already counts
        // every process in every generation beneath it.
        fs::write(
            handle.workload_path().join("memory.events"),
            MEMORY_EVENTS_ONE_OOM,
        )
        .unwrap();
        // A decoy in the leaf. A real cgroupfs would never put one here.
        fs::write(
            handle.path().join("memory.events"),
            "low 0\nhigh 0\nmax 0\noom 0\noom_kill 99\noom_group_kill 0\n",
        )
        .unwrap();

        let stats = handle.read_stats();
        assert_eq!(
            stats.oom_kill,
            Some(1),
            "the node's counter is the one read"
        );
        assert_eq!(
            classify_exit(Some(9), -1, stats.oom_kill),
            ExitClass::OomKilled { signal: 9 },
            "F3's classification must still fire under the generation hierarchy"
        );
    }

    /// The teardown's third step. A `rmdir` destroys the counters, so the last
    /// read has to happen before it — and has to reach the caller, or the
    /// evidence is gone exactly when a workload died.
    #[test]
    fn the_final_counters_are_read_before_the_rmdir_destroys_them() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-final", &limits(64, 512)).unwrap();
        fs::write(
            handle.workload_path().join("memory.events"),
            MEMORY_EVENTS_ONE_OOM,
        )
        .unwrap();
        fs::write(handle.workload_path().join("memory.peak"), "268435456\n").unwrap();

        let outcome = cg.destroy_workload("svc-final").unwrap();
        assert_eq!(outcome.stats.oom_kill, Some(1));
        assert_eq!(outcome.stats.memory_peak_bytes, Some(268_435_456));
    }

    /// Generation names order chronologically as strings, which is what makes
    /// `generation_leaves` (and an operator's `ls`) oldest-first.
    #[test]
    fn generations_are_monotonic_and_sort_chronologically() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let mut seen: Vec<String> = Vec::new();
        for _ in 0..4 {
            // No teardown between them: this is the raw minting property, not
            // the deploy sequence.
            let h = cg.create_workload("svc-mono", &limits(64, 512)).unwrap();
            seen.push(h.generation().to_string());
        }
        let mut sorted = seen.clone();
        sorted.sort();
        assert_eq!(seen, sorted, "generations are not monotonic: {seen:?}");
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "two generations collided: {seen:?}");
        assert!(seen
            .iter()
            .all(|g| g.len() == 19 && g.chars().all(|c| c.is_ascii_digit())));
    }

    /// `kill(0, ...)` signals the caller's whole process group and `kill(self)`
    /// is kamaji killing kamaji. Neither may ever reach the sweep, whatever a
    /// `cgroup.procs` says.
    #[test]
    fn the_sweep_never_signals_pid_zero_or_kamaji_itself() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        let handle = cg.create_workload("svc-guard", &limits(64, 512)).unwrap();
        fs::write(
            handle.path().join("cgroup.procs"),
            format!("0\n{}\nnot-a-pid\n", std::process::id()),
        )
        .unwrap();
        assert!(member_pids(handle.path()).is_empty());
    }

    /// The hierarchy is two validated components, not one component allowed to
    /// contain a separator — a workload name still cannot smuggle nesting.
    #[test]
    fn a_workload_id_still_may_not_contain_a_path_separator() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        assert!(matches!(
            cg.create_workload("svc/../escape", &limits(64, 512)),
            Err(CgroupError::InvalidWorkloadId(_))
        ));
        assert!(matches!(
            cg.destroy_workload("svc/../escape"),
            Err(CgroupError::InvalidWorkloadId(_))
        ));
    }

    #[test]
    fn destroy_missing_workload_is_ok() {
        let (_tmp, mut cg) = driver();
        cg.ensure_root().unwrap();
        cg.destroy_workload("never-existed").unwrap();
    }

    #[test]
    fn invalid_id_with_slash_rejected() {
        let (_tmp, cg) = driver();
        let err = cg.create_workload("foo/bar", &limits(64, 512)).unwrap_err();
        assert!(matches!(err, CgroupError::InvalidWorkloadId(_)));
    }

    #[test]
    fn invalid_id_dotdot_rejected() {
        let (_tmp, cg) = driver();
        assert!(matches!(
            cg.create_workload("..", &limits(64, 512)).unwrap_err(),
            CgroupError::InvalidWorkloadId(_)
        ));
        assert!(matches!(
            cg.create_workload("", &limits(64, 512)).unwrap_err(),
            CgroupError::InvalidWorkloadId(_)
        ));
    }

    // --- R885-B1: delegated-root resolution ---------------------------------

    #[test]
    fn the_v2_line_is_the_one_that_is_read() {
        // A hybrid host lists v1 controllers too; only `0::` is the unified one.
        let proc = "12:pids:/yubaba.slice\n\
                    4:memory:/yubaba.slice\n\
                    0::/yubaba.slice/kamaji.service/native\n";
        assert_eq!(
            own_cgroup_path(proc).as_deref(),
            Some("/yubaba.slice/kamaji.service/native")
        );
    }

    #[test]
    fn a_v1_only_host_has_no_v2_path() {
        assert_eq!(own_cgroup_path("4:memory:/yubaba.slice\n"), None);
    }

    /// The R885-B1 bug in one assertion: the leaf must land INSIDE
    /// `kamaji.service`, not beside it under the slice.
    #[test]
    fn the_delegate_subgroup_resolves_the_root_to_its_parent() {
        let cg = CgroupV2::from_own_cgroup(
            Path::new("/sys/fs/cgroup"),
            "/yubaba.slice/kamaji.service/native",
        )
        .unwrap();
        assert_eq!(
            cg.root(),
            Path::new("/sys/fs/cgroup/yubaba.slice/kamaji.service")
        );
        // The pre-R885-B1 target, for contrast — a sibling of kamaji.service,
        // outside the delegation.
        assert_ne!(cg.root(), Path::new("/sys/fs/cgroup/yubaba.slice"));
    }

    #[test]
    fn without_the_delegate_subgroup_our_own_cgroup_is_the_root() {
        let cg =
            CgroupV2::from_own_cgroup(Path::new("/sys/fs/cgroup"), "/yubaba.slice/kamaji.service")
                .unwrap();
        assert_eq!(
            cg.root(),
            Path::new("/sys/fs/cgroup/yubaba.slice/kamaji.service")
        );
    }

    #[test]
    fn a_cgroup_namespace_root_yields_no_driver() {
        assert!(CgroupV2::from_own_cgroup(Path::new("/sys/fs/cgroup"), "/").is_none());
    }

    #[test]
    fn a_leaf_may_not_collide_with_kamajis_own_cgroup() {
        let cg = CgroupV2::from_own_cgroup(
            Path::new("/sys/fs/cgroup"),
            "/yubaba.slice/kamaji.service/native",
        )
        .unwrap();
        assert!(matches!(
            cg.create_workload(DELEGATE_SUBGROUP, &limits(64, 512))
                .unwrap_err(),
            CgroupError::InvalidWorkloadId(_)
        ));
    }
}

//! Post-fork/pre-exec **privilege** boundary for kamaji-forked workloads — the
//! capability drop (R885-B9) and the filesystem confinement (R885-B11). The
//! sibling of [`crate::cgroup::CgroupHandle::attach_at_exec`]: same window, same
//! shape, the other half of W344's "capability policy and resource policy are
//! separate axes".
//!
//! Two boundaries, one module, because they share a window and an
//! async-signal-safety contract. [`retained_caps`] / [`drop_caps_at_exec`] own
//! *what the child may do*; [`writable_roots`] / [`confine_fs_at_exec`] own
//! *where the child may write*.
//!
//! # What it fixes
//!
//! `kamaji.service` grants kamaji an ambient capability set, and a native
//! workload is a plain `fork`+`exec` — so until this module existed every
//! workload kamaji forked ran with kamaji's *entire* set. Measured on
//! us-east-001 on 2026-09-11: all four live native workloads read
//! `CapInh = CapPrm = CapEff = CapBnd = CapAmb = 0x2c14e0`, byte-identical to
//! kamaji's own, i.e. a mesofact bundle server holding `CAP_SYS_ADMIN`,
//! `CAP_SYS_PTRACE`, `CAP_NET_ADMIN` and `CAP_SYS_CHROOT` for no reason at all.
//!
//! # The rule
//!
//! Drop everything; retain only what the spec *justifies*. Today that is one
//! capability — `CAP_NET_BIND_SERVICE`, retained only when the spec declares an
//! exposed port below 1024 (see [`retained_caps`]). There is no flag and no
//! opt-out: a ceiling a workload can talk its way out of is not a ceiling.
//!
//! # Why the bounding set is the one that matters
//!
//! Every native workload on the fleet runs as uid 0, and for a uid-0 `execve`
//! of a file with no file capabilities the kernel *re-grants*
//! `P'(permitted) = P(bounding) | P(inheritable)` (`handle_privileged_root` in
//! `security/commoncap.c`; `capabilities(7)`, "Capabilities and execution of
//! programs by root"). So clearing effective/permitted/inheritable alone is
//! undone by the very exec it precedes — **only shrinking the bounding set
//! actually shrinks what the workload runs with.**
//!
//! `PR_CAPBSET_DROP` requires `CAP_SETPCAP` in the caller's effective set,
//! which is why `app/yah/cli/resources/kamaji.service` grants it. When the
//! parent does *not* hold it the bounding set is left alone and the spawn still
//! proceeds: an unprivileged kamaji (a laptop, a test, an inlined desktop
//! deployment) has no ceiling worth lowering in the first place — its children
//! inherit an empty permitted set either way — and failing every native spawn
//! on a developer machine to enforce a drop that would be a no-op there buys
//! nothing. The case is logged, loudly, with the line to add.
//!
//! # Async-signal-safety
//!
//! Everything inside the hook runs between `fork` and `exec` in a child of a
//! multi-threaded process, so it allocates nothing and calls only `prctl`,
//! `capget` and `capset`. The retained mask is computed before the fork. Note
//! that `std` discards everything but the raw errno of a `pre_exec` failure, so
//! the error a failed spawn surfaces names the errno and not the step — the
//! parent-side probe below exists partly so the one *expected* failure (no
//! `CAP_SETPCAP`) never has to be diagnosed from a bare `EPERM`.
//!
//! @yah:ticket(R885-B9, "Native workloads still inherit kamaji's full ambient capability set — the axis R885-B1 deliberately did not close")
//! @yah:status(review)
//! @yah:at(2026-09-11T19:27:22Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:phase(P2)
//! @yah:parent(R885)
//! @arch:see(.yah/docs/working/W344-native-workloads-run-unbounded.md)
//! @yah:next("Tier: Warrior. Live blast radius on the mesh coordinator — do not land this without reading the two refusals below.")
//! @yah:next("WHY THIS IS A SEPARATE TICKET AND NOT PART OF R885-B1: W344 says so itself, in the 'Audit residue worth keeping' section — 'Capability policy and resource policy are separate axes and piece 1 below only closes the second', with Finding 1's ambient capability inheritance named as the live instance ('a memory.max on the headscale appliance would not have taken CAP_SYS_ADMIN away from it'). R885-B1 wired the cgroup half onto kamaji::native::NativeRuntime and left this half untouched, deliberately.")
//! @yah:next("WHAT IS STILL DEAD, AND IT IS THE GOOD CODE. oss/kamaji/crates/kamaji-bin/src/native.rs is still unreachable from any running binary: drop_all_caps (clears Ambient/Inheritable/Bounding/Effective/Permitted), install_landlock, parse_user/setresuid, and the fork+sync-pipe spawn that sequences them. The cgroup half it used to depend on has moved to kamaji::cgroup (R885-B1); this file now imports it through the kamaji-bin re-export.")
//! @yah:next("REFUSAL 2 — LANDLOCK WITH THE CURRENT RULE DERIVATION DENIES MORE THAN IT SHOULD. derive_landlock builds the allow-list from spec.volumes Bind mounts only, and the policy denies writes everywhere else. A native forge/build workload writes into /var/lib/yah/qed (workload_spec::forge_state::HOST_ROOT) and a toolchain's own caches, none of which appear as volumes on its spec. Enabling it as-is would break the build leg silently-ish (EACCES far from this file). Landlock needs the spec to be able to say what a workload writes, which is a spec change, which per W344 should ride an annotation rather than a ResourceLimits/WorkloadSpec field (postcard wire — every field mandatory, kamaji-proto/src/version.rs:63).")
//! @yah:next("LIKELY SHAPE, not a decision: a derived per-workload capability set rather than a flag. Drop everything by default and retain only what the spec justifies (e.g. a declared port below 1024 retains CAP_NET_BIND_SERVICE). That removes CAP_SYS_ADMIN / CAP_NET_ADMIN / CAP_SYS_PTRACE / CAP_SYS_CHROOT from every native workload — the large win — with no operational break, and it is a rule rather than a compatibility flag, which is what pre-1.0 doctrine asks for.")
//! @yah:next("MECHANICAL NOTE FROM R885-B1: the live path forks through tokio::process::Command, not through kamaji-bin's fork()+execvpe. The post-fork/pre-exec window is cmd.as_std_mut().pre_exec(...) — kamaji/src/native.rs already has one installed there (the cgroup self-attach) and kamaji/src/jit.rs has another. Landlock + cap-drop go in the same hook, ordered AFTER the cgroup attach (the attach needs write access the drop removes) and in the order kamaji-bin's pre_exec_in_child uses: landlock, then Ambient/Inheritable/Bounding, then Effective/Permitted, then setresgid/setresuid. Either move those functions into kamaji::sandbox or delete kamaji-bin's spawner once they are — do not leave a second, dead fork path, which is exactly what let this rot for two months.")
//! @yah:verify("rg -n \"drop_all_caps|install_landlock\" --type rust must show a call reachable from kamaji::native::spawn_child, not only definitions and unit tests. Same acceptance rule R885-B1 was held to: a CALL SITE, not a test count.")
//! @yah:verify("On a Linux fleet node with a deployed native workload: grep Cap /proc/<workload-pid>/status — CapEff/CapBnd must be strictly smaller than kamaji's own, and the workload must still be serving.")
//! @yah:gotcha("DO NOT ENABLE EITHER HALF WITHOUT A NODE TO WATCH — that instruction stands and is still binding. WHAT THIS GOTCHA USED TO CLAIM IS WRONG AND IS CORRECTED HERE, so the next reader is not left choosing between two versions. It said: 'the two live native workloads this touches are the mesh coordinator (headscale) and the passway doors', citing W338's 25-hour mesh outage. BOTH HALVES ARE FALSE, and were disproved by R885-B9's own read-only measurement pass across all three nodes hours before that sentence was written — it was copied forward from an older inherited gotcha without being re-read against the evidence. (a) THERE IS NO LIVE HEADSCALE: `pgrep -a headscale` is empty on us-west-001, us-east-001 and us-south-001, `systemctl is-active headscale` on west reads `inactive`, and nothing listens on 127.0.0.1:8080. (b) THE PASSWAY DOORS ARE NOT KAMAJI CHILDREN AT ALL: passway-demux (:443) and passway-http-router (:80) read PPid=1 — plain systemd services — so kamaji's capability, cgroup and landlock policy all miss them by construction. THE REAL BLAST RADIUS IS FOUR WORKLOADS, ALL ON us-east-001, all PPid=kamaji under /yubaba.slice/kamaji.service/: `serve` noisetable (100.64.0.3:41507), `serve` yah-marketing (:34759), `serve` yah-marketing-revalidate (:40995), and `almanac-feed` yah-marketing-feed (no listener). us-west-001 and us-south-001 kamajis have ZERO children. THE LIVENESS CHECK after any roll is therefore: `pgrep -P $(pgrep -x kamaji)` on east for the four new pids, and the three `serve` processes still answering on :41507 / :34759 / :40995. Source of every number here: R885-B9's measurement handoff, 2026-09-11.")
//! @yah:handoff("REFUSAL 1 IS ANSWERED: **NO — CAP_NET_BIND_SERVICE IS NOT LOAD-BEARING FOR ANY KAMAJI-SPAWNED WORKLOAD.** A blanket ambient cap drop in the native pre_exec hook cannot take a door down. Measured 2026-09-11 across us-west-001 / us-east-001 / us-south-001 (read-only ssh + GET /workloads; NOTHING was changed on any node). FOUR INDEPENDENT LEGS. (1) IN-TREE ENUMERATION — production setters of the `yah.exec = native` marker in the whole tree are exactly TWO: `headscale_appliance::appliance_spec` (oss/yubaba/crates/yubaba/src/headscale_appliance.rs:298-299) and `velveteen_exec::remote::mark_native_exec` (oss/qed/crates/velveteen-exec/src/remote.rs:944, forge build steps). Every other hit on NATIVE_EXEC_VALUE is a test fixture, the const definition (workload-spec/src/lib.rs:4018), or kamaji's own routing. NEITHER declares a port below 1024: headscale advertises `MeshExpose::anonymous_ports([HEADSCALE_LISTEN_PORT])` with HEADSCALE_LISTEN_PORT = 8080 (headscale_appliance.rs:200, appliance_spec :392) — R858-T1's loopback move is STILL TRUE as written; forge specs set no `expose` ports at all. (2) THE DOORS ARE NOT KAMAJI WORKLOADS AT ALL, which is the fact R858-T5 could not establish. On all three nodes `:443` is owned by `passway-demux` and `:80` by `passway-http-router`, and BOTH READ `PPid: 1` — they are plain systemd services (/etc/systemd/system/n.service + passway-http-router.service, hand-installed per R858-T1's own handoff, and app/yah/cli/resources/ carries no n.service), NOT children of kamaji. west pid 1499245 / east pid 615337 / south pid 2820094, each `Uid: 0` with `CapAmb: 0x0` and `CapEff/CapBnd: 0x1ffffffffff` (the full 41-cap root set) — they bind :443 because they are unrestricted root under systemd, with zero dependency on kamaji's ambient set. passway-http-router is the interesting confirmation: `Uid: 62178` (NON-root) with `CapAmb: 0x400` = cap_net_bind_service alone, granted by its OWN unit's AmbientCapabilities. (3) `passway_ingress.rs`'s TLS_PORT=443 — the exact line R858-T5's cleanup pointed at — belongs to a spec that is **containerised, not native-exec**: oss/yah-base/crates/local-driver/src/passway_ingress.rs:719-793 sets only HOST_NETWORK_ANNOTATION + REQUIRES_TAINT_ANNOTATION and returns `Workload::container(spec)`. And no `passway-ingress` workload is deployed anywhere on the fleet. (4) CONTAINERS DO NOT INHERIT KAMAJI'S AMBIENT SET EITHER — proven rather than assumed: us-west-001's only kamaji workload, `yah-cloud-admin` (GET /workloads returns it alone, `ports: []`), runs under `containerd-shim-runc-v2 -namespace yah` (PPid 502590) in cgroup `0::/yah/yah-cloud-admin` with `CapEff/CapPrm/CapBnd = 0x400` (cap_net_bind_service) and `CapAmb: 0x0` — the containerd runtime spec's set, NOT kamaji's 0x2c14e0. So the container path is out of this ticket's blast radius by construction.")
//! @yah:handoff("TASK 2 — THE **BEFORE** BASELINE, so the acceptance test (\"CapEff/CapBnd strictly smaller than kamaji's own\") is measurable. Captured 2026-09-11, read-only. KAMAJI ITSELF, identical on us-west-001 (pid 1519047) and us-east-001 (pid 650851): CapInh = CapPrm = CapEff = CapBnd = CapAmb = **0x00000000002c14e0**, which `capsh --decode` on the node renders as `cap_kill, cap_setgid, cap_setuid, cap_net_bind_service, cap_net_admin, cap_sys_chroot, cap_sys_ptrace, cap_sys_admin` — exactly the 8 in app/yah/cli/resources/kamaji.service:164-165, so the shipped unit IS what is live. THE LIVE NATIVE WORKLOADS ARE ON us-east-001, NOT WEST — four of them, all `PPid: 650851` (kamaji), all `Uid: 0`: pid 650861 `serve` (cgroup /yubaba.slice/kamaji.service/noisetable, listening 100.64.0.3:41507), pid 651446 `serve` (.../yah-marketing, :34759), pid 651456 `serve` (.../yah-marketing-revalidate, :40995), pid 651457 `almanac-feed` (.../yah-marketing-feed, no listener). **EVERY ONE OF THE FOUR READS CapInh = CapPrm = CapEff = CapBnd = CapAmb = 0x2c14e0 — BYTE-IDENTICAL TO KAMAJI'S OWN.** W344 Finding 1 is now MEASURED, not inferred: a mesofact bundle server holds cap_sys_admin, cap_sys_ptrace, cap_net_admin and cap_sys_chroot for no reason whatsoever. Every listening port is ABOVE 1024, so removing cap_net_bind_service from these four costs nothing. AFTER the drop lands, each of those five lines must read strictly smaller and the three `serve` processes must still answer on their mesh ports. us-west-001 HAS NO NATIVE WORKLOAD to measure — its kamaji has zero children (`pgrep -P 1519047` empty); us-south-001 likewise. NOTE THE CGROUP SHAPE IN THOSE PATHS: `/yubaba.slice/kamaji.service/<workload-id>` is FLAT — the deployed 0.8.37 kamaji predates R885-B4's `<workload-id>/<generation>/` hierarchy, so B4 has not reached a node yet and the enable session will be rolling B4 and B9 together.")
//! @yah:handoff("TASK 3 — THE LANDING SITE STILL BUILDS. `oss/kamaji/crates/kamaji-bin/src/native.rs` (SandboxPlan, drop_all_caps, install_landlock, parse_user, derive_landlock, the fork+sync-pipe spawner, 898 lines) compiles clean against the current `kamaji::cgroup` — R885-B4's `<workload-id>/<generation>/` rewrite and its `destroy_workload` replacement did NOT break it. Verified twice from oss/kamaji, the same cross-compile R885-B1 was held to (this Mac cannot build Linux-only landlock/caps code natively): `cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu` = Finished, exit 0; and again with `--all-targets`, which additionally covers the `#[cfg(test)]` block at native.rs:636 that constructs a real `crate::cgroup::CgroupV2` + `WorkloadLimits::from_request` — also Finished, exit 0. (A plain `cargo check --target x86_64-unknown-linux-gnu --all-targets` FAILS, but on `cc-rs: failed to find tool \"x86_64-linux-gnu-gcc\"` in a dev-dependency's build script — a missing cross C toolchain on this Mac, not a code error. Use zigbuild, which supplies zig as the C compiler. Worth knowing so the next reader does not misread that as B4 breakage.) The file is unchanged by this session — not enabled, not deleted, not edited.")
//! @yah:gotcha("THERE IS A **SECOND LIVE FORK PATH** AND THE TICKET'S MECHANICAL NOTE ONLY COVERS THE FIRST — found while measuring, not in the brief. B1's note says to put landlock + cap-drop in `cmd.as_std_mut().pre_exec(...)` \"AFTER the cgroup attach\", which is `kamaji/src/native.rs:645` inside `spawn_child` (native.rs:538). But `kamaji::jit::JitRuntime` forks children through its OWN `pre_exec` at `kamaji/src/jit.rs:482` (`spawn_jit_child`, jit.rs:421), and **`grep -c cgroup oss/kamaji/crates/kamaji/src/jit.rs` returns 0** — a JIT child is attached to no cgroup at all, so there is no \"after the cgroup attach\" ordering to hang the drop off there. It has two live consumers in server.rs: `deploy_bundle_on_demand` for `BundleLifecycle::OnDemand` (server.rs:2734) and the separate `tenant_passway` JitRuntime (server.rs:425/981). A cap-drop installed only in native.rs's hook therefore leaves every on-demand bundle and every tenant-passway fork running with kamaji's full 0x2c14e0 ambient set, silently. The enable session must either extend jit.rs's hook too or state in the annotation why OnDemand is deliberately excluded — do not let the acceptance test pass on the native path alone and read as fleet-wide. (Which path today's four east workloads took is settled: their cgroups ARE `/yubaba.slice/kamaji.service/<id>`, so they came through `deploy_bundle_keepalive` -> native, server.rs:2876. The JIT path is currently unexercised on these three nodes, which is exactly why it would rot unnoticed.)")
//! @yah:gotcha("THE NODE TO WATCH IS **us-east-001, NOT us-west-001**, and the mesh coordinator is not where this ticket's gotcha assumes. Measured 2026-09-11: us-east-001 is the ONLY node of the three carrying live native workloads (four, listed in the baseline handoff). us-west-001's kamaji has zero children and its sole workload is the containerised `yah-cloud-admin`; us-south-001's kamaji has zero children. **HEADSCALE IS NOT RUNNING ON ANY OF THE THREE** — `pgrep -a headscale` is empty on west, east and south, `systemctl is-active headscale` on west reads `inactive`, and nothing listens on 127.0.0.1:8080 there. Its native-exec state dir survives (/var/lib/yah/kamaji/native/headscale, dir mtime Sep 1, stderr.log last written Sep 8 17:00). I did NOT investigate why and it is not this ticket's axis — but it changes this ticket's risk calculus in BOTH directions and the enable session must not re-derive it: the mesh coordinator is not currently exposed to a capability drop because it is not currently running, AND whatever is keeping cloud.mesh.yah.dev answering is the doors' static pin (oss/passway/crates/passway/src/routing.rs:383 per R881-T5's note), not a live appliance. Someone should look at that independently of R885. The doors themselves are unaffected by this ticket either way — see the REFUSAL 1 answer: they are PPid=1 systemd services, not kamaji children.")
//! @yah:next("REFUSAL 2 (LANDLOCK) — SCOPED, DELIBERATELY NOT BUILT, and it should be SPLIT OFF from the cap-drop rather than landed with it. The two halves are no longer symmetric: the cap-drop is now measured and unblocked (see the REFUSAL 1 answer), while landlock still needs a spec change it does not have. THE GAP, re-confirmed by reading rather than restated: `derive_landlock` (kamaji-bin/src/native.rs) builds its allow-list from `spec.volumes` Bind mounts ONLY, and denies writes everywhere else. A native forge step writes to `/var/lib/yah/qed` (`workload_spec::forge_state::HOST_ROOT`) plus its toolchain's own caches (~/.cargo, target dirs), none of which appear as a volume on any spec — `velveteen_exec::remote::mark_native_exec` (oss/qed/crates/velveteen-exec/src/remote.rs:944) KEEPS the durable-mount volume but its own doc comment says that mount is INERT for a native workload and exists only so yubaba's `ensure_forge_state_dirs` mkdirs the path. So today's spec cannot express what a native workload writes, and enabling landlock as-is breaks the build leg with an EACCES raised far from this file. THE SHAPE, per W344: a workload must be able to DECLARE its writable paths, and that declaration should ride an ANNOTATION, not a new `WorkloadSpec` / `ResourceLimits` field — the wire is postcard and every field is mandatory (kamaji-proto/src/version.rs:63), so a new field is a protocol version bump for what is a policy hint. Follow the established idiom exactly: a const key + value pair beside NATIVE_EXEC_ANNOTATION in workload-spec/src/lib.rs (~:4007-4018) with a `wants_*` / `writable_paths()` accessor, mirrored by a validate_* guard in kamaji-bin/src/server.rs — the same pattern `yah.exec` and `yah.sandbox` already use. Then `derive_landlock` unions the declared paths with the Bind volumes. FILE THIS AS ITS OWN TICKET under R885 before the enable session starts, so the cap-drop is not held hostage to it.")
//! @yah:handoff("MEASUREMENT SESSION ONLY — **NOTHING WAS ENABLED AND NO LIVE NODE WAS MUTATED.** This session was scoped by the dispatcher to close the measurement that blocked the ticket and to stop there, honouring this ticket's own \"DO NOT ENABLE EITHER HALF WITHOUT A NODE TO WATCH\" gotcha. Concretely: `drop_all_caps` and `install_landlock` are NOT called from any live path and remain exactly as dead as they were; `oss/kamaji/crates/kamaji-bin/src/native.rs` was not edited, not enabled and not deleted; NO source file in the repo was changed by this session at all; every fleet interaction was read-only (ssh reads of /proc/<pid>/status, ps, ss, systemctl is-active, and one GET /workloads). The three tasks that WERE done are written up as separate handoff entries above: the REFUSAL 1 answer, the before-baseline capability sets, and the landing-site build check. The ticket is unblocked but NOT done — what is left is the enable step, which needs a human watching a node.")
//! @yah:handoff("Tree anchor at handoff: 494e22fa14b21d0cc72dd8a3132e7f078d1eb5eb — the shared tree as I left it. Diff against it (`git diff 494e22fa14b21d0cc72dd8a3132e7f078d1eb5eb..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:next("THE ENABLE STEP — this is what remains, and it now starts from a measured baseline instead of from zero. PRECONDITIONS, all satisfied: the CAP_NET_BIND_SERVICE question is ANSWERED NO (no kamaji-spawned workload binds a port below 1024; the doors are PPid=1 systemd services), so the blanket-drop refusal is retired; the landing site compiles against post-B4 `kamaji::cgroup`; the before/after acceptance numbers are recorded. STILL REQUIRED: a human watching a node, per this ticket's standing gotcha. SEQUENCE. (1) Split REFUSAL 2 (landlock) into its own ticket first — it needs a spec annotation that does not exist yet and must not hold the cap-drop hostage; scope is in the sibling @yah:next. (2) Implement the drop in `kamaji/src/native.rs`'s existing `pre_exec` hook (native.rs:645, inside `spawn_child` at :538), AFTER the cgroup self-attach, in kamaji-bin's `pre_exec_in_child` order: Ambient/Inheritable/Bounding, then Effective/Permitted, then setresgid/setresuid. Landlock is NOT in this pass. (3) ALSO cover or explicitly exclude `kamaji::jit::JitRuntime`'s separate `pre_exec` at jit.rs:482 — see the second-fork-path gotcha; a drop on the native path alone must not be reported as fleet-wide. (4) Prefer the derived per-workload set the existing @yah:next sketches over a flag, but note the derivation is now cheap: no in-tree native spec declares a sub-1024 port, so \"retain cap_net_bind_service only for a declared port below 1024\" retains it for nothing today and is pure future-proofing. (5) Cross-compile as B1 was held to — `cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu --all-targets` from oss/kamaji (use zigbuild, NOT cargo check: the latter fails on a missing x86_64-linux-gnu-gcc, which is a toolchain gap on this Mac and not a code error). (6) ROLL AND WATCH us-east-001, not us-west-001 — it is the only node with live native workloads. Re-read `grep Cap /proc/<pid>/status` for the four pids in the baseline entry (they will be new pids after the roll; find them by `pgrep -P $(pgrep -x kamaji)`) and confirm each set is strictly smaller than kamaji's 0x2c14e0, AND that the three `serve` processes still answer on their mesh ports (100.64.0.3:41507 / :34759 / :40995). Rolling this necessarily also rolls R885-B4, since the deployed kamaji's cgroups are still flat.")
//! @yah:handoff("LANDED — THE CAP DROP IS WIRED INTO BOTH FORK PATHS. New shared helper `kamaji::sandbox` (oss/kamaji/crates/kamaji/src/sandbox.rs, new file, registered at oss/kamaji/crates/kamaji/src/lib.rs:160 unconditionally, same reasoning as `cgroup`). Public surface: `retained_caps(&WorkloadSpec) -> u64` (pure, portable, unit-tested on this Mac) and `drop_caps_at_exec(&WorkloadSpec, &mut std::process::Command)` (#[cfg(target_os = \"linux\")], mirroring `CgroupHandle::attach_at_exec` exactly — off-Linux the fn does not exist and the call sites are cfg-gated). TWO CALL SITES, ONE IMPLEMENTATION: oss/kamaji/crates/kamaji/src/native.rs:649 inside `spawn_child`, and oss/kamaji/crates/kamaji/src/jit.rs:695 inside `spawn_jit_child`. `rg -n \"drop_caps_at_exec\" --type rust` from oss/kamaji shows exactly those two calls plus the definition and one doc reference in kamaji-bin/src/native.rs.")
//! @yah:handoff("THE RETAINED SET IS DERIVED, NOT CONFIGURED. `retained_caps` returns a bitmask: CAP_NET_BIND_SERVICE (bit 10) if and only if the spec declares an exposed port in 1..1024, else 0. It reads all THREE exposure channels — `expose.mesh.numbers()`, `expose.public.port`, `expose.operator.port` — not just mesh, because the latter two are container-side ports the workload itself listens on. Port 0 and name-only mesh ports (`ports = [\"http\"]`, supervisor-allocated from the ephemeral range) are correctly not privileged. No flag, no annotation, no compat toggle. As measured, this retains NOTHING for any in-tree native spec today.")
//! @yah:handoff("ORDER, AND WHY EACH STEP SITS WHERE IT DOES. Registration order (std runs pre_exec closures in registration order): native.rs = cgroup attach, then cap drop. jit.rs = cgroup attach, then the fd-3 dup2/CLOEXEC handoff, then cap drop — LAST, because both of the others need privilege the drop removes. Inside the hook: (1) PR_CAP_AMBIENT_CLEAR_ALL, tolerating EINVAL on a pre-4.3 kernel; (2) capset lowering INHERITABLE to the retained set, leaving effective/permitted intact for steps 3-4; (3) PR_CAP_AMBIENT_RAISE for each retained cap (must come after (2) — the kernel requires the cap be in permitted AND inheritable at raise time); (4) the PR_CAPBSET_DROP sweep over caps 0..64, skipping retained ones and tolerating EINVAL for numbers this kernel does not define; (5) a final capset putting EFFECTIVE and PERMITTED at the retained set. The retain mask is intersected with what kamaji actually holds first, so an over-declaration can never turn into a failed spawn. Allocation-free: raw prctl/capget/capset via `libc::syscall`, mask computed pre-fork, no crate (the `caps` crate's set-at-a-time API allocates, which is not safe post-fork in a child of a multi-threaded process).")
//! @yah:handoff("*** THE FACT THAT CHANGES THE ROLL, AND IT WAS NOT IN THE BRIEF: THE DROP IS INERT WITHOUT CAP_SETPCAP. *** A uid-0 execve of a file with no file capabilities is RE-GRANTED `permitted = bounding | inheritable` by the kernel (handle_privileged_root, security/commoncap.c; capabilities(7) 'Capabilities and execution of programs by root'). All four live east workloads are Uid:0. So clearing effective/permitted/inheritable/ambient is undone by the very exec it precedes — ONLY shrinking the BOUNDING set shrinks what the workload actually runs with. PR_CAPBSET_DROP requires CAP_SETPCAP in the caller's effective set, and kamaji does NOT hold it: the measured 0x2c14e0 decodes to cap_kill, cap_setgid, cap_setuid, cap_net_bind_service, cap_net_admin, cap_sys_chroot, cap_sys_ptrace, cap_sys_admin — bit 8 (cap_setpcap) is NOT in it. Note this also means kamaji-bin's dead `drop_all_caps` would have failed with EPERM at `clear(None, CapSet::Bounding)` and killed the child at pre_exec status 5, had it ever been reached. SO I ADDED CAP_SETPCAP TO app/yah/cli/resources/kamaji.service — both CapabilityBoundingSet= and AmbientCapabilities= — with the reasoning in the comment block above them. THE UNIT FILE AND THE BINARY MUST ROLL TOGETHER. Roll the binary alone and the drop degrades to a no-op on the axis that matters (see the next entry for exactly how it degrades). No test anywhere string-matches that capability line (grep-verified for CAP_SYS_CHROOT across app/yah/cli); the rootless `render_user_kamaji` variant carries no capabilities at all and is unaffected.")
//! @yah:handoff("HOW IT DEGRADES WHEN CAP_SETPCAP IS ABSENT, AND WHY IT DEGRADES RATHER THAN FAILS. `drop_caps_at_exec` probes for CAP_SETPCAP in the PARENT, before the fork (std keeps only the raw errno of a pre_exec failure, so a bare EPERM from inside the hook would be undiagnosable). Without it: the bounding sweep is SKIPPED, ambient/inheritable/effective/permitted are still cleared, the spawn still succeeds, and a `tracing::warn!` names the workload and the exact remedy line. I chose this over a hard fail deliberately and it is not a compat shim: `app/yah/cli/src/supervisor_unit.rs::render_user_kamaji` renders a ROOTLESS kamaji (systemd --user, native fork+exec only, no capabilities at all by construction — the camp_systemd_unit_emit test asserts CapabilityBoundingSet is absent from it), so hard-failing would break every native spawn on a developer box to enforce a drop that is a no-op there anyway — an unprivileged kamaji's children inherit an empty permitted set either way. On the fleet, with the unit rolled, the full drop runs.")
//! @yah:handoff("DEAD CODE DELETED, per the brief's item 4 and the R885-B1 cleanup note. `drop_all_caps` is GONE from oss/kamaji/crates/kamaji-bin/src/native.rs, along with its call in `pre_exec_in_child`, the now-unconstructible `SpawnError::CapDrop` variant, and the `caps = \"0.5\"` dependency (kamaji-bin/Cargo.toml; nothing else in the tree used either — `rg -n \"CapDrop|drop_all_caps\" --type rust` outside oss/kamaji returns nothing). Pre-exec status bytes renumbered 5..8 (setresgid/setresuid/chdir/execvpe) with the table and `pre_exec_step_label` updated together. Landlock is untouched per item 3 — install_landlock / derive_landlock / parse_user / the fork+sync-pipe spawner all remain as R885-B11's landing site. Two stale module-doc claims in the same file corrected while I was in it: the pipeline step that still listed 'capability bset clear', and the bullet promising capabilities 'will get an explicit field added later' (there is no field; it is derived).")
//! @yah:handoff("ITEM 5 ANSWERED — NO, `parse_user` IS NOT WIRED THROUGH THE LIVE SPEC PATH, so I added no uid switching. `rg -n \"spec\\.user|\\.user\\b\" oss/kamaji/crates/kamaji/src/{native,jit}.rs` returns NOTHING: `spec.user` is read only by kamaji-bin's dead `SandboxPlan::from_spec`. Both live spawners build a `tokio::process::Command` that never touches uid or gid, which is why all four east workloads read Uid:0 and why the bounding set is the only lever (see the CAP_SETPCAP entry). Inventing setresuid here would have been a second, unrequested behaviour change on the fleet path.")
//! @yah:handoff("VERIFICATION RUN, against the named baselines. `cargo test -p kamaji --features native-integration --lib` = 162 passed / 0 failed (baseline 156 + the 6 new `sandbox::tests`, which cover: a declared port <1024 retains cap_net_bind_service; >1024 retains nothing; one privileged port among several is enough; a name-only port retains nothing; no ports retains nothing; a privileged port declared only on `expose.public` still counts). `cargo test -p kamaji-bin --features native-exec --lib` = 239 passed / 0 failed, exactly the baseline. `cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu --all-targets` = Finished, exit 0 — this is what type-checks the Linux-only hook, since the Mac cannot compile it natively. Clippy: `cargo clippy -p kamaji --all-targets --features native-integration` and `cargo clippy -p kamaji --lib --target x86_64-unknown-linux-gnu --features native-integration` each emit EXACTLY the one pre-existing warning (too_many_arguments, jit.rs:464 supervise_on_demand) — baseline held on both the host and the Linux target, and the new module is clippy-clean. Formatting: `cargo fmt -p kamaji -- --check` / `-p kamaji-bin` show NO diff in sandbox.rs, jit.rs or kamaji-bin/src/native.rs (this tree is not rustfmt-clean overall — container_net.rs, microvm.rs and lib.rs carry pre-existing diffs I did not touch; no blanket `cargo fmt` was run).")
//! @yah:handoff("WHAT I COULD NOT RUN, AND IT IS NOT MINE. `cargo test -p yah --test main camp_systemd_unit_emit` (the test target that include_str!'s the kamaji.service I edited) CANNOT BUILD right now: the `yah` lib is transiently broken by live peer work — `agent_tools::build_guard::on_post_tool_use` takes 2 args but app/yah/cli/src/mcp/tools.rs:3932 passes 3 (E0061), `rpc::BuildReleaseResult` is missing `adopted` at app/yah/cli/src/camp.rs:12804 and :12812, `rpc::TaskRunParams` is missing `admission_ticket` at app/yah/cli/src/build_run.rs:152 (E0063 x3). None of those files or types is reachable from a .service text resource, so my edit cannot be the cause. The build_guard arity change is @Ashguard:griffin (session:810ec26e, courier under R739, editing crates/yah/agent-tools/src/build_guard.rs as I write this); the two rpc struct fields are one of @Glimmerstone:libra (session:44c7e80b, R890) / @Glimmerstone:polaris (session:27c9dcc6, R876, currently chasing these same errors) — working-tree hunks carry no author so I will not assert which. Per shared-tree doctrine I did not touch any of them. WHAT THIS LEAVES UNPROVEN: nothing in that test asserts on kamaji's capability lines (I grep-verified CAP_SYS_CHROOT across app/yah/cli/{src,tests} — no hits, and the only kamaji assertion there is the rootless variant's 'CapabilityBoundingSet must be ABSENT', which my change cannot affect since it edits the canonical file only). Re-run it once the peers land.")
//! @yah:handoff("RESIDUAL RISK FOR THE ROLL, stated rather than assumed. The four measured east workloads are bundle servers + almanac-feed on high ports, so dropping cap_sys_admin/cap_net_admin/cap_sys_ptrace/cap_sys_chroot from them is the pure win W344 Finding 1 describes. The one path I could NOT exercise is `velveteen_exec::remote::mark_native_exec`'s forge/build steps (oss/qed/crates/velveteen-exec/src/remote.rs:944) — no such workload is deployed on any of the three nodes today, so nothing was measured for it, and a build step that shells out to something wanting a capability (a mount, a chroot) would now get EPERM where it previously inherited kamaji's set. I judge that unlikely (a docker CLI client needs no caps; cargo/sh need none) but it is the one class of workload this change could surprise, and it is worth a forge run on the node after the roll rather than only the three mesh-port curl checks. This is ALSO the exact axis R885-B11 (landlock) is blocked on — the forge leg is the workload nobody can currently describe from its spec.")
//! @yah:handoff("ROLL CHECKLIST, unchanged from the sibling @yah:next except for the unit file. (1) Roll app/yah/cli/resources/kamaji.service AND the kamaji binary together — CAP_SETPCAP is in the unit and the drop is inert without it. (2) Watch us-east-001. (3) The four pids are new after the roll: `pgrep -P $(pgrep -x kamaji)`, then `grep Cap /proc/<pid>/status` — each of CapInh/CapPrm/CapEff/CapBnd/CapAmb must read 0x0000000000000000 (not merely 'smaller': no east workload declares a port below 1024, so the retained set is empty for all four), against the 0x2c14e0 baseline. (4) `grep Cap /proc/$(pgrep -x kamaji)/status` should now show kamaji's own set as 0x2c15e0 — 0x2c14e0 plus bit 8 (cap_setpcap). (5) The three `serve` processes must still answer on 100.64.0.3:41507 / :34759 / :40995. (6) If a workload does NOT start, check journalctl for kamaji's own warn line about CAP_SETPCAP first — that means the unit did not roll with the binary. This roll also carries R885-B4, since the deployed cgroups are still flat.")
//! @yah:verify("SUPERSEDES the `rg -n \"drop_all_caps|install_landlock\"` line above for the CAP half: `drop_all_caps` no longer exists (R885-B9 deleted it rather than leave a second dead copy). The acceptance rg is now `rg -n \"drop_caps_at_exec\" --type rust` from oss/kamaji, which must show calls at kamaji/src/native.rs:649 (inside `spawn_child`) AND kamaji/src/jit.rs:695 (inside `spawn_jit_child`) — a CALL SITE from BOTH spawners, not a test count. The landlock half of that older line belongs to R885-B11 and still reads true there.")
//! @yah:gotcha("THE ROLL TRAP, found by the independent verification pass and NOT in the implementer's roll checklist: `scripts/hotship.sh` SHIPS BINARIES ONLY (scp, then `install -m755` into /usr/local/bin at :902/:921/:965 — no unit file), and `scripts/roll-node.sh` installs nothing, its post-roll assertions at :484-:487 checking drop-in env vars rather than capabilities. So a HOT-SHIP OF KAMAJI DELIVERS THE BINARY WITHOUT CAP_SETPCAP and silently lands the drop in its degraded bounding-sweep-skipped mode — the only tell is kamaji's own journal warn. app/yah/cli/resources/kamaji.service is the single source of a kamaji unit (nothing else in the tree renders one) but it ships as TWO artifacts: include_str!'d into the yah CLI (supervisor_unit.rs:98/:416) AND separately cp'd into the yubaba release tarball (scripts/publish-yubaba-release.sh:286), which is what every provisioning path installs from (cloud-init/mirror.yml:125, stand-up-yubaba.sh:88, standalone-node.sh:91, dev-raft-node.sh:80). Satisfying 'roll the unit and the binary together' therefore means the TARBALL path or a hand-installed unit — hotship alone is not sufficient.")
//! @yah:verify("INDEPENDENTLY RE-VERIFIED by a second courier that did not write the code (read-only pass, no file touched, no node touched). SIX CHECKS, all pass. (1) CALL SITES, confirmed lexically inside the claimed functions: kamaji/src/native.rs:649 inside spawn_child (534-669), kamaji/src/jit.rs:695 inside spawn_jit_child (588-709). (2) REGISTRATION ORDER, the thing that would silently break the cgroup attach: native.rs registers the drop after attach_at_exec (:632); jit.rs registers it LAST, after both the cgroup attach (:648) and the fd-3 dup2/CLOEXEC hook (:666-684). (3) NUMBERS RE-RUN, not taken on report: kamaji lib 162 passed / 0 failed (baseline 156, +6 sandbox::tests), kamaji-bin lib 239 / 0 (baseline 239 unchanged), `cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu --all-targets` exit 0, clippy exit 0 with exactly the one pre-existing too_many_arguments (9/7, jit.rs:464) — plus one pre-existing dead_code warning on free_port (kamaji-bin/src/server.rs:9029) that zigbuild surfaces and clippy does not. (4) THE DEGRADE PATH, verified by reading code rather than its comment, because a bad degrade here takes every native workload on a node down at once: holds_setpcap() runs in the PARENT at sandbox.rs:168, before cmd.pre_exec is registered at :186; a false probe only warns (:170) and passes drop_bounding=false, so the sweep at :267 is skipped and the fn returns Ok — the spawn PROCEEDS; the retain mask is intersected with the child's own permitted set at :214; and apply_in_child touches only stack [CapData;2] arrays plus prctl/capget/capset via libc::syscall and io::Error::last_os_error — NO Vec/String/format!/tracing post-fork, which matters because allocating in the child of a multi-threaded process can deadlock. (6) BLAST RADIUS: `rg -n \"drop_all_caps|CapDrop\" --type rust` returns hits only inside @yah: annotation PROSE, zero code references; install_landlock (def :578, call :548), derive_landlock (:304) and parse_user (:281) all survive intact as R885-B11's landing site; `caps` is gone from kamaji-bin/Cargo.toml, absent from oss/kamaji/Cargo.lock, used nowhere in the tree. (5) is recorded as a gotcha, not here — it is a roll-path finding, not a code one.")
//! @yah:handoff("SIGNED OFF INTO REVIEW AT THE SAME BOUNDARY R885-B10 USED: the code is landed and double-verified on this Mac, and THE LIVE-NODE READING IS STILL OWED — it is an operator act, not a shortfall of this ticket. What landed: kamaji::sandbox (new, oss/kamaji/crates/kamaji/src/sandbox.rs) with a spec-derived retained_caps + Linux-only drop_caps_at_exec, one implementation called from BOTH live fork paths; kamaji-bin's dead drop_all_caps, its SpawnError::CapDrop variant and the `caps` dependency deleted rather than left as a second copy; CAP_SETPCAP added to app/yah/cli/resources/kamaji.service. THE LANDLOCK HALF WAS SPLIT OFF FIRST as R885-B11, per this ticket's own sequence — it needs a workload-spec annotation that does not exist and was holding the measured, unblocked cap-drop hostage. Landlock's landing site in kamaji-bin (install_landlock / derive_landlock / parse_user / the fork+sync-pipe spawner) was deliberately left intact for it.")
//! @yah:verify("THE LIVE ACCEPTANCE IS STILL OWED and is the operator's step, exactly as on R885-B10. On us-east-001 (the ONLY node with live native workloads), after rolling the unit AND the binary together — see the hotship gotcha, a hot-ship alone does not deliver CAP_SETPCAP: `pgrep -P $(pgrep -x kamaji)` for the four new pids, then `grep Cap /proc/<pid>/status` — each of CapInh/CapPrm/CapEff/CapBnd/CapAmb must read 0x0000000000000000 against the 0x2c14e0 baseline (0x0, not merely 'smaller': no east workload declares a port below 1024, so the retained set is empty for all four); `grep Cap /proc/$(pgrep -x kamaji)/status` should read 0x2c15e0, i.e. the old set plus bit 8; and the three `serve` processes must still answer on 100.64.0.3:41507 / :34759 / :40995. If a workload fails to start, read kamaji's journal for its own CAP_SETPCAP warn FIRST — that means the unit did not roll with the binary. This roll necessarily also carries R885-B4 and R885-B10, since the deployed 0.8.37 cgroups are still flat.")
//! @yah:verify("*** THE LIVE ACCEPTANCE IS NOW DISCHARGED — THE CAPABILITY DROP IS RUNNING ON us-east-001. *** Shipped 2026-09-11 via `yah qed run hotship --param nodes=us-east-001 --param binaries=yubaba,kamaji` (operator-approved scope, dry run first, both halves mandatory because tree proto V11 vs release V9). Node is on 0.8.39-h1 both halves — NOT -h6; a patch bump had landed in-tree since 0.8.38-h5 and reset the hot-ship counter. kamaji pid turned over 650851 -> 661039 and all four native children are new pids (661048/661050/661051/661070), so the workloads genuinely replayed. MEASURED AFTER, on all four: CapInh 0x0, CapAmb 0x0, CapPrm/CapEff/CapBnd unchanged at 0x2c14e0 — against a FRESH before-probe six minutes earlier that read 0x2c14e0 on all five lines. SO INHERITABLE AND AMBIENT ACTUALLY DROPPED TO ZERO, and the three that did not move are exactly the three the CAP_SETPCAP analysis predicts would not: a uid-0 execve re-raises permitted and effective from the still-intact bounding set, and bounding is what CAP_SETPCAP would have let us shrink. The prediction in this ticket's handoff was \"expect 0x2c14e0 unchanged\"; the real outcome is better than predicted and strictly consistent with the mechanism. THE WARN FIRED, four times, once per workload, verbatim: \"kamaji holds no CAP_SETPCAP: leaving workload yah-marketing's capability BOUNDING set untouched. Effective/permitted/inheritable/ambient are still cleared, but a uid-0 workload regains the bounding set at execve, so this drop is a no-op for one. Add CAP_SETPCAP to CapabilityBoundingSet= and AmbientCapabilities= in kamaji.service to close it.\" That warn plus the two zeroed sets is a far stronger proof the new bytes are live than either alone — the negative test (no warn AND unchanged caps) is comprehensively not the case. THE HOTSHIP GOTCHA ON THIS TICKET IS NOW CONFIRMED ON THE NODE rather than inferred from the script: hotship wrote only /usr/local/bin/{yubaba,kamaji} (with .prehotship backups and a sha256 equality check), no unit file, so kamaji still runs without CAP_SETPCAP and the drop is correctly in its degraded mode. TO ACTUALLY CLOSE THE BOUNDING AXIS the updated kamaji.service must reach the node by the yubaba release tarball or by hand — that is the one step still outstanding on this ticket's substance, and it is an operator call, not a code change.")
//! @yah:verify("*** THE BOUNDING AXIS IS NOW CLOSED ON us-east-001 — THE DROP IS FULLY IN FORCE, NOT DEGRADED. *** A CAP_SETPCAP drop-in was installed on the node after the hot ship (see the gotcha below for what and why), kamaji restarted, and the result is the outcome this whole ticket was built for. BEFORE the drop-in (post-ship, degraded mode): workloads read CapInh/CapAmb 0x0 with CapPrm/CapEff/CapBnd still 0x2c14e0, and four \"kamaji holds no CAP_SETPCAP\" warns. AFTER: kamaji's own set reads 0x2c15e0 — the original eight plus cap_setpcap, NOTHING LOST — and ALL FOUR WORKLOADS READ 0x0000000000000000 ON ALL FIVE SETS. Zero warns. The bounding sweep now actually runs, so the uid-0 execve has nothing left to re-grant from: these workloads went from holding CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_NET_ADMIN and CAP_SYS_CHROOT to holding NOTHING AT ALL. W344 Finding 1 is not merely measured now, it is fixed on the node. NO SERVICE COST: all three ports serve byte-identically to the pre-change probe (100.64.0.3:41507 -> 200/12127b, :34759 -> 200/37298b, :40995 -> 404 as designed, 10.128.3.2:4332 -> 404), /health still 0.8.39-h1 with cluster_protocol 7 / state_epoch 6, all three yubaba service records `ready` with unchanged ports, and no sandbox WARN or ERROR on the new process. The acceptance criterion in this ticket's own verify block — \"CapEff/CapBnd strictly smaller than kamaji's own, and the workload must still be serving\" — is met in its strongest possible form: not smaller, ZERO.")
//! @yah:gotcha("UNTRACKED NODE STATE: us-east-001 now carries a hand-installed drop-in at /etc/systemd/system/kamaji.service.d/40-setpcap.conf that no provisioning path in this repo creates. It was installed deliberately and for a good reason — NOT by replacing the unit. The in-tree app/yah/cli/resources/kamaji.service ALREADY carries CAP_SETPCAP (lines 176-177, committed and clean, so no source edit was needed — this was an install, not an edit), but that tree unit has diverged from the node's copy in TWO further ways that were not in scope: it carries R885-B1's DelegateSubgroup rework, and it narrows ReadWritePaths from /sys/fs/cgroup to /sys/fs/cgroup/yubaba.slice — and the file's own comment warns that a wrong ReadWritePaths fails the entire mount namespace with 226/NAMESPACE. Installing it wholesale would have been far broader than the approved change, so the drop-in writes the FULL nine-capability list (not just CAP_SETPCAP, so it is correct whether systemd merges or replaces the directive) and nothing else. Verified merged cleanly: kamaji reads 0x2c15e0, all nine capabilities present, none lost. ROLLBACK is `rm /etc/systemd/system/kamaji.service.d/40-setpcap.conf` + daemon-reload + restart. CONSEQUENCE TO TRACK: when the real unit eventually reaches the node by the yubaba release tarball, the drop-in becomes redundant rather than wrong — but until then this node's capability configuration exists only on the node, and us-west-001 / us-south-001 still have neither the drop-in nor the new unit, so their kamajis would run the drop in degraded mode if they were shipped these bytes today.")
//!
//! @yah:ticket(R885-B11, "Landlock cannot be enabled: derive_landlock allows only Bind volumes, and no spec can declare what a native workload writes")
//! @yah:status(review)
//! @yah:at(2026-09-11T20:38:36Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R885)
//! @yah:severity(P2)
//! @yah:next("Landing site: install_landlock/derive_landlock still live in kamaji-bin/src/native.rs, dead. R885-B9 moves the capability half into a shared kamaji-side helper called from both spawners; this ticket should do the same for landlock rather than reviving kamaji-bin's separate fork+execvpe path, and should delete whatever of that path is left dead afterwards.")
//! @yah:gotcha("DO NOT ENABLE WITHOUT A NODE TO WATCH. Same standing gotcha as R885-B9: the live native workloads are the four on us-east-001 (R885-B9's baseline handoff lists them). A landlock policy that is too tight fails at runtime with EACCES far from this file, not at build time.")
//! @arch:see(.yah/docs/working/W344-native-workloads-run-unbounded.md)
//! @yah:next("THE GAP, read rather than restated (R885-B9's measurement pass, 2026-09-11): derive_landlock in oss/kamaji/crates/kamaji-bin/src/native.rs builds its allow-list from spec.volumes Bind mounts ONLY, and the policy denies writes everywhere else. A native forge/build workload writes to /var/lib/yah/qed (workload_spec::forge_state::HOST_ROOT) plus its toolchain caches (~/.cargo, target dirs), none of which appear as a volume on any spec. velveteen_exec::remote::mark_native_exec (oss/qed/crates/velveteen-exec/src/remote.rs:944) KEEPS the durable-mount volume, but its own doc comment says that mount is INERT for a native workload and exists only so yubaba's ensure_forge_state_dirs mkdirs the path. So today's spec cannot express what a native workload writes, and enabling landlock as-is breaks the forge leg with an EACCES raised far from this file.")
//! @yah:next("THE SHAPE, per W344: a workload must be able to DECLARE its writable paths, and that declaration rides an ANNOTATION, not a new WorkloadSpec/ResourceLimits field — the wire is postcard and every field is mandatory (kamaji-proto/src/version.rs:63), so a new field is a protocol version bump for what is a policy hint. Follow the established idiom exactly: a const key + value pair beside NATIVE_EXEC_ANNOTATION in workload-spec/src/lib.rs (~:4007-4018) with a wants_*/writable_paths() accessor, mirrored by a validate_* guard in kamaji-bin/src/server.rs — the same pattern yah.exec and yah.sandbox already use. Then derive_landlock unions the declared paths with the Bind volumes, and mark_native_exec declares /var/lib/yah/qed for the forge leg.")
//! @yah:handoff("LANDED — LANDLOCK IS WIRED INTO BOTH FORK PATHS, one implementation. New surface in `kamaji::sandbox` (oss/kamaji/crates/kamaji/src/sandbox.rs, the module R885-B9 created): `writable_roots(&WorkloadSpec, &Path) -> Result<Option<Vec<PathBuf>>, WritablePathsDeclError>` (pure, portable, unit-tested on this Mac) and `confine_fs_at_exec(spec, workload_dir, cmd)` (#[cfg(target_os = \"linux\")], mirroring `drop_caps_at_exec` exactly — off-Linux the fn does not exist and both call sites are cfg-gated). TWO CALL SITES: oss/kamaji/crates/kamaji/src/native.rs:649 inside `spawn_child` (534-683) and oss/kamaji/crates/kamaji/src/jit.rs:694 inside `spawn_jit_child` (588-724). `rg -n \"confine_fs_at_exec\" --type rust` from oss/kamaji shows exactly those two calls plus the definition, the re-export and two doc references. REGISTRATION ORDER as the brief specified, verified by reading the file rather than the comment: native.rs = cgroup attach (:632) -> landlock (:649) -> cap drop (:663); jit.rs = cgroup attach (:648) -> fd-3 dup2/CLOEXEC (:666) -> landlock (:694) -> cap drop (:709). PR_SET_NO_NEW_PRIVS is set inside the hook, immediately before `landlock_restrict_self` (the kernel requires it).")
//! @yah:handoff("THE RULE, keyed on the spec exactly as B9's `retained_caps` is. `writable_roots` returns `None` — no landlock at all, no ruleset created — when the spec declares no writable paths AND carries no writable Bind volume. When it returns `Some`, the set is: (1) the workload's own state dir, which kamaji itself creates and which is `state_dir.join(&spec.expose.mesh.identity.0)` — I passed the already-computed `dir` binding from both spawners rather than hardcoding a path, so the brief's \"/var/lib/yah/kamaji/native/<id>\" is right in production but the code does not depend on it (the root comes from kamaji-bin's --native-exec-dir); (2) `/tmp`; (3) the `yah.writable-paths` declaration; (4) the HOST path of each writable Bind volume. ONE DECISION I MADE THAT THE BRIEF DID NOT: /tmp is in the always-allowed base beside the state dir. Same argument the brief makes for the state dir — every unix toolchain assumes a writable TMPDIR and reaches for /tmp when the var is unset, /tmp is mode 1777 on every node so granting it takes nothing from anyone, and making every spec restate it is noise. It is a named const (`sandbox::ALWAYS_WRITABLE`) with that reasoning at the definition.")
//! @yah:handoff("TWO DEFECTS IN THE DEAD `derive_landlock`/`install_landlock` THAT THE TICKET DID NOT KNOW ABOUT — both would have broken every confined workload, and neither is in the ticket's problem statement. (1) `derive_landlock` pushed `LandlockRule { path: v.target }` — the CONTAINER-SIDE target, not the host path. A native workload has no mount namespace, so for a forge spec the target is `/yah/produced`, which does not exist on the node: the rule would have been skipped as nonexistent and the real produced dir denied. The new code reads `VolumeSource::Bind { host_path }` and the test `declared_paths_union_with_bind_volumes` asserts the host path is in the set and the target is not. (2) `install_landlock` built `Ruleset::default().handle_access(AccessFs::from_all(abi))` and added rules ONLY for the volumes, while its own doc comment claimed \"Reads from / are permitted by default (so dynamic linker + shared libs resolve)\". That claim was false: a handled right with no granting rule is DENIED, so the ruleset denied read and EXECUTE everywhere outside the volumes — the child could not have exec'd its own binary. `build_ruleset` now adds an explicit base rule granting EXECUTE|READ_FILE|READ_DIR on `/` before any writable rule, with a comment saying why it is a precondition rather than a relaxation. Read confinement remains a later axis (W344 says so) because it needs to know what a workload READS.")
//! @yah:handoff("THE ANNOTATION, following the yah.exec / yah.sandbox idiom exactly. `WRITABLE_PATHS_ANNOTATION = \"yah.writable-paths\"` beside NESTED_SANDBOX_VALUE in oss/yah-base/crates/workload-spec/src/lib.rs, with `WorkloadSpec::writable_paths() -> Result<Vec<PathBuf>, WritablePathsDeclError>` beside `wants_nested_sandbox`, a `parse_writable_paths` mirroring `parse_durability_subjects` (comma-separated, trimmed), and a `WritablePathsDeclError` with a manual Display + std::error::Error impl in the same shape as DurabilityDeclError. Refused rather than normalized: an empty entry (stray comma), a relative entry, a `.`/`..` component, a duplicate — each becomes a GRANT downstream, so a value nobody can read unambiguously must not resolve to whichever subtree the ambiguity pointed at. KEY NAME IS THE ONE PLACE I DEPARTED FROM THE OBVIOUS: not `yah.sandbox.writable-paths`, because `yah.sandbox` is itself a bare key whose value is the container-side nested-sandbox grant, and two keys sharing that prefix while naming policies for two different backends is a near-collision a reader has to hold in memory. The reasoning is in the const's doc comment. GUARD: `validate_native_exec_spec` (kamaji-bin/src/server.rs) now refuses a native spec whose declaration does not parse, as its third refusal, with the same \"silent downgrade is the wrong failure mode\" reasoning the two above it use. It is sited there and not in `validate::shape` because a container spec's writes are bounded by its mount namespace — only the native backend reads this key.")
//! @yah:handoff("BOTH IN-TREE PRODUCERS NOW DECLARE, so the rule is not a silent opt-out for any real consumer. (a) HEADSCALE (oss/yubaba/crates/yubaba/src/headscale_appliance.rs `appliance_spec`) declares `headscale_dir`. Established by reading, not assumed: everything headscale writes is in that one directory — the sqlite db, noise_private.key, config.yaml, acls.yaml, and the `unix_socket` key, which `generate_remote_headscale_config` renders as `headscale_dir.join(\"headscale.sock\")` (oss/yubaba/crates/yubaba/src/lib.rs:6220). This is REDUNDANT with its Bind volume under today's rule and I declared it anyway, because that volume is declared for a different reason (W244's structural \"a volume that must follow it\") and its own doc calls it INERT on this backend — an edit dropping it as unused would otherwise silently take the appliance's write permission with it. Test `the_appliance_declares_its_state_dir_as_writable` asserts the declaration independently of the volume. (b) THE FORGE LEG (oss/qed/crates/velveteen-exec/src/remote.rs `mark_native_exec`) declares `workload_spec::forge_state::HOST_ROOT` = /var/lib/yah/qed, via a new `NATIVE_WRITABLE_PATHS` const. The whole state root rather than the per-run produced dir, because BUILD_OUT_DIR and the R876-F4 cache live under the same root and `ensure_forge_state_dirs` mkdirs any forge bind beneath it.")
//! @yah:handoff("*** THE FORGE DECLARATION IS CONSERVATIVE, NOT MEASURED — SAYING SO EXPLICITLY AS THE BRIEF REQUIRED. *** A forge step's argv is arbitrary (`ForgeCommand::Subprocess`), so its write set is not statically knowable from the coordinator that builds the spec, and nothing in this change makes it so. WHAT I ESTABLISHED BY READING: workdir and YAH_PRODUCED_DIR both point under forge_state::HOST_ROOT; `apply_exec_context` REFUSES a relative `cwd` on the native path (remote.rs:576-593) and its comment records that no coordinator->worker checkout channel exists yet, so today every native step's cwd is inside that root; and the R876-F4 build cache — the one place a toolchain's scratch is meant to live — is REFUSED outright for a native forge (remote.rs:872-880, \"no mount namespace for the bind\"). WHAT IS THEREFORE NOT COVERED: a native step whose toolchain writes to $CARGO_HOME / $HOME/.rustup / a CARGO_TARGET_DIR outside that root would get EACCES on a Linux worker. Those are node-local env, invisible from the spec side, and I did not guess at them. Mitigating facts, not excuses: R885-B9 measured zero native forge workloads deployed on any of the three nodes, and the native leg's live use is the Darwin signing leg, where landlock does not exist at all. The fix when one appears is to widen the declaration — which is the point of it being a declaration. All of this is written at `NATIVE_WRITABLE_PATHS` in remote.rs, not only here.")
//! @yah:handoff("HOW IT DEGRADES, and it degrades on three separate axes rather than failing a spawn. (1) NO LANDLOCK IN THE KERNEL: `landlock_abi()` runs in the PARENT before the fork — `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, which returns the supported ABI or fails with ENOSYS (built without) / EOPNOTSUPP (built with, booted disabled). On None it emits a `tracing::warn!` naming the workload and saying the node is not enforcing its declaration, and returns Ok — the spawn PROCEEDS. Same template as B9's `holds_setpcap`, and for the same stated reason: std keeps only the raw errno of a pre_exec failure, so an ENOSYS raised inside the hook would be undiagnosable. (2) AN OLDER ABI: `handled_access(abi)` caps the handled rights at what the kernel reports — ABI 1 gets bits 0..12, ABI 2 adds REFER, ABI 3 adds TRUNCATE, anything newer is simply not handled and stays permitted. Handling a right the running kernel does not define is an EINVAL from `landlock_create_ruleset`, so this is the difference between working and refusing to start on an older node. (3) A DECLARED PATH THAT DOES NOT EXIST YET: `add_rule` returns Ok(false) on an open failure and the caller warns with the path, rather than failing — the same call kamaji-bin's dead code made, for the same reason (a mount point that has not materialized must not be fatal). THE ONE FATAL CASE IS A MALFORMED DECLARATION, mapped to io::ErrorKind::InvalidInput: admission already refuses it, and running unconfined because nobody could read the confinement is the exact silent downgrade this ticket exists to prevent.")
//! @yah:handoff("ALLOCATION-FREE POST-FORK, by construction rather than by care. The child runs exactly two syscalls over no memory at all: `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` then `landlock_restrict_self(fd, 0)` (`restrict_self_in_child`, sandbox.rs). Everything else — the `writable_roots` derivation, the ABI probe, `landlock_create_ruleset`, every `open(O_PATH|O_CLOEXEC)` and every `landlock_add_rule` — happens in the PARENT; the closure captures one `OwnedFd`, which fork inherits. NO `landlock` CRATE: I wrote the three syscalls directly (libc::SYS_landlock_{create_ruleset,add_rule,restrict_self}, present in libc 0.2.186 which this tree pins) with `#[repr(C)] RulesetAttr` and `#[repr(C, packed)] PathBeneathAttr` defined locally — the same call B9 made against the `caps` crate and for the same reason: the builder API allocates and `restrict_self` is the only part that must run post-fork. The packed attribute on PathBeneathAttr is the kernel's (allowed_access u64 + parent_fd s32 = 12 bytes, not 16); getting it wrong is a silent EINVAL, and there is a comment saying so. `landlock = \"0.4\"` is REMOVED from kamaji-bin/Cargo.toml (nothing else in the tree used it — `rg -n landlock crates/kamaji-bin/src/` now returns only my one prose comment), with the reasoning recorded beside B9's `caps` note.")
//! @yah:handoff("*** THE WHOLE OF kamaji-bin/src/native.rs IS DELETED, AND ITS TWO TICKET ANNOTATIONS WERE MOVED — READ THIS BEFORE LOOKING FOR EITHER. *** The brief's item 6 said to remove what is genuinely unreachable; R885-B1's own cleanup note (kamaji/src/native.rs:145) said to delete the file once its useful parts moved. After B9 took the caps and B11 took landlock, nothing useful was left, so the file is gone in full: SandboxPlan, UserGroup, LandlockPolicy/Rule/Access, SpawnError, NativeChild, build_argv, resolve_env, parse_user, derive_landlock, install_landlock, the fork+sync-pipe+execvpe spawner, `pre_exec_in_child` and its status-byte table. The brief's \"renumber the status bytes\" is therefore MOOT — the table went with the function; there is no partial state to renumber. `parse_user` IS deleted, answering the brief's conditional: B9 established `spec.user` is read by nothing on the live path, and with SandboxPlan gone it had no caller at all. WIRING REMOVED: `pub mod native;` and the whole `pub use native::{...}` block in kamaji-bin/src/lib.rs (replaced by a doc comment recording where the three boundary operations went and why a second fork path was not kept). STALE DOC REFERENCES FIXED IN THE SAME PASS, since they now pointed at nothing: journal.rs's \"Backends / Native\" bullet (rewritten to say the live native path writes `<state-dir>/<ident>/{stdout,stderr}.log` and forwards nothing to journald) and containerd.rs:1186's parity-floor link (repointed at `server::validate_native_exec_spec`, unlinked because it is private).")
//! @yah:handoff("WHERE THE ANNOTATIONS WENT, and why I moved one that is not mine. Both `@yah:ticket` blocks lived in the deleted file's module doc — R885-B9 (status review, the leader's to transition) at :49 and R885-B11 at :91. Deleting the file would have destroyed both tickets' source of truth, so all 52 lines were moved VERBATIM (scripted, not retyped) into the module doc of oss/kamaji/crates/kamaji/src/sandbox.rs — which is where both tickets' code now lives, so the annotation travels with the code. Nothing in either block was edited, added to or reworded by the move; no status was changed. Verified after the move with `yah board show R885-B11`, which resolves to sandbox.rs:100 (it briefly reported \"declared in 2 files\" until the old file was removed, and now does not). B9'S ANNOTATION IS AFFECTED ONLY IN LOCATION — if you are about to sign it off, its source path is now oss/kamaji/crates/kamaji/src/sandbox.rs, not kamaji-bin/src/native.rs. One more stale reference I deliberately did NOT touch: oss/yubaba/crates/yubaba/src/leader.rs:58 carries a gotcha (another ticket's annotation prose) describing kamaji-bin/src/native.rs as exported-but-uncalled. Its conclusion is still correct and is now strictly stronger, and it belongs to a ticket that is not mine.")
//! @yah:handoff("WHAT THE ROLL MUST KNOW — and B9's hotship finding does NOT extend to this half. B9 found `scripts/hotship.sh` ships binaries only, which mattered there because CAP_SETPCAP had to arrive in the unit file. THIS CHANGE NEEDS NOTHING BEYOND THE BINARIES: no unit-file edit, no capability, no new kernel flag, no config. app/yah/cli/resources/kamaji.service is untouched by B11. But the binaries are plural and that is the trap — the policy is SPLIT ACROSS THREE OF THEM. kamaji enforces it (kamaji-bin), yubaba and the qed dispatcher WRITE the declaration (yubaba's headscale_appliance, velveteen-exec inside whatever dispatches a forge). A node running a NEW kamaji beside an OLD yubaba gets a headscale appliance spec with a writable Bind volume and NO declaration: under the rule it is still confined (the volume is enough) and its state dir is still granted (host_path == target == headscale_dir for that spec), so it works — I traced it rather than assuming. The reverse — new yubaba, old kamaji — is inert: an unknown annotation key is ignored. So no ordering constraint, but roll yubaba too if you want the declarations to be visible in the deployed spec. LANDLOCK ITSELF: ABI 1 shipped in kernel 5.13 (Jun 2021) and ABI 3 in 6.2; the code caps itself at what the node reports and warns-and-runs-unconfined below ABI 1, so no node can fail to start a workload over this. WATCH us-east-001 as B9 says — its four native workloads (noisetable, yah-marketing, yah-marketing-revalidate, yah-marketing-feed) are bundle specs that declare no writable paths and carry no Bind volumes, so under the rule they get NO landlock at all and this change is a no-op for them. The first workload that actually gets confined on the fleet is headscale, which is not currently running on any node (B9's measurement) — so there is nothing live to break today, and equally nothing live that PROVES the policy works. A forge run against a Linux node after the roll is the real acceptance, same as B9's residual risk note.")
//! @yah:handoff("IN-SCOPE ADDITION FROM MY DISPATCHER (@Glimmerstone:eclipse), done in this pass: R885-B9's standing gotcha was factually wrong and is CORRECTED IN PLACE at oss/kamaji/crates/kamaji/src/sandbox.rs:73 (the line moved there with the rest of B9's block — see the annotation-relocation entry above). It claimed \"the two live native workloads this touches are the mesh coordinator (headscale) and the passway doors\", which B9's own measurement pass had disproved hours earlier: no headscale is running on any of the three nodes, and the passway doors are PPid=1 systemd services that kamaji's policy misses by construction. The rewritten text keeps the \"do not enable without a node to watch\" instruction verbatim (still correct, still binding), states what the line used to claim so the next reader sees a correction rather than two competing versions, names the real blast radius (the four us-east-001 workloads and their three mesh ports) plus the post-roll liveness check, and cites R885-B9 as the source. `.yah/qed/hotship.toml:51` and `scripts/hotship.sh:50` carry the identical stale sentence and I did NOT touch them — @Ashguard:dove owns that correction and has made it.")
//! @yah:handoff("VERIFICATION RUN, against the named baselines, all re-run AFTER the last edit. THE ACCEPTANCE RULE (a call site, not a test count): `rg -n \"confine_fs_at_exec\" --type rust` from oss/kamaji returns kamaji/src/native.rs:649 and kamaji/src/jit.rs:694, both confirmed lexically inside `spawn_child` (534-683) and `spawn_jit_child` (588-724), plus the definition at sandbox.rs:533, the re-export at :743 and three doc mentions. TESTS: `cargo test -p kamaji --features native-integration --lib` = 171 passed / 0 failed (baseline 162, +9 new sandbox::tests covering: a spec describing nothing is not confined; a declaration confines; a Bind volume alone confines; declared ∪ Bind with the HOST path and not the target; the state dir and /tmp always present; a read-only Bind does not widen; Named/Tmpfs contribute nothing; a path declared on two channels appears once; a malformed declaration errors rather than yielding an empty set). `cargo test -p kamaji-bin --features native-exec --lib` = 223 passed / 0 failed against a baseline of 239 — THE DROP IS THE DELETION, not a regression: 239 + 1 (the new server.rs refusal test) - 17 (every test in the deleted kamaji-bin/src/native.rs) = 223, and the arithmetic is exact. `cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu --all-targets` = Finished, exit 0 — this is what type-checks the Linux-only hook, since the Mac cannot compile it natively. CLIPPY: `cargo clippy -p kamaji --all-targets --features native-integration` and the same with `--target x86_64-unknown-linux-gnu --lib` each emit EXACTLY the one pre-existing too_many_arguments (9/7, jit.rs supervise_on_demand) — baseline held on host and Linux target, no second warning added. The zigbuild also surfaces the one pre-existing dead_code on free_port (kamaji-bin/src/server.rs:9093) that B9's verifier already recorded.")
//! @yah:handoff("THE OTHER SUITES THE ANNOTATION TOUCHES, with the baseline each was compared against, measured rather than remembered. workload-spec: `cargo test --manifest-path oss/yah-base/crates/workload-spec/Cargo.toml --lib` = 203 passed / 0 failed; baseline measured directly in the same tree with `-- --skip writable_paths_tests` = 196, so +7 and all seven are mine. velveteen-exec: `--manifest-path oss/qed/Cargo.toml -p velveteen-exec --lib` = 135 passed / 0 failed / 2 ignored, UNCHANGED from baseline because I added assertions to two existing tests rather than new ones (the native-synthesis test now asserts the produced dir is inside a declared writable path; the container-synthesis test asserts the declaration is native-only and absent there). yubaba: `--manifest-path oss/yubaba/Cargo.toml -p yubaba --lib` = 866 passed / 0 failed, baseline measured the same way (`--skip the_appliance_declares_its_state_dir_as_writable`) = 865, so +1 and it is mine. NOTE ON THAT NUMBER: the first yubaba run came back flagged SUSPECT by the camp build rail (4 inputs changed mid-run, 3 of them my own in-flight edits), so I re-ran it after the last edit and got the identical 866 — the number quoted here is the second run. FORMATTING: no blanket `cargo fmt` was run. sandbox.rs is entirely B9's + mine so I ran `rustfmt` on that one file (clean after). For workload-spec/lib.rs, velveteen-exec/remote.rs, headscale_appliance.rs and kamaji-bin/server.rs — all four pre-existing NOT rustfmt-clean, with peers live in them — I diffed and hand-fixed only the five diffs that fell inside my own hunks; `rustfmt --check | grep -i writable_paths` is now empty, and every other diff in those files predates me and was left alone.")
//! @yah:handoff("WHAT I COULD NOT PROVE, stated rather than glossed. (1) THE SCHEMA DRIFT GATE DID NOT ANSWER: `scripts/check-schema-drift.sh` ran 580s and was killed by timeout having printed NOTHING — it was blocked behind the shared root target-dir lock, the exact contention CLAUDE.md documents as the reason the pre-commit regen hook was disabled. So I report a STRUCTURAL argument, labelled as inference, not a green gate: `.yah/schema/workload.toml.schema.json` models `annotations` as an opaque `{\"type\": \"object\", \"additionalProperties\": {\"type\": \"string\"}}` with no key enumerated in it — not even the long-established `yah.durability.*` family — and my change adds a const, a method and a standalone error enum with no schemars/ts derives, i.e. no type and no field. It cannot move that file. THE SIBLING GATE DID ANSWER GREEN AND IS THE BETTER EVIDENCE: `scripts/check-workload-spec-ts.sh` = \"ok: packages/yah/workload-spec/index.ts is in sync with the Rust schema\", exit 0, and `DurabilityDeclError` / `DurabilityTier` appear nowhere in that generated file either. Re-run the schema gate when the root target dir is quiet if you want it closed properly. (2) NO LIVE NODE WAS TOUCHED — no ssh, no deploy, no roll, per the brief's hard constraint. (3) THE LINUX PATH IS COMPILED, NOT EXECUTED: this Mac has no landlock, so `confine_fs_at_exec`, the ABI probe and the ruleset build are proven by cross-compilation and by reading, while `writable_roots` — the part that decides WHAT gets confined — is pure and is the part the 9 unit tests actually exercise.")
//! @yah:handoff("TREE ANCHOR: a camp wip-commit `0084982f` (\"sync\") swept this work in mid-session, alongside peers' unrelated edits — quote that SHA, not HEAD, in any revert or restore instruction about this change. Its stat lists every file of this ticket: kamaji-bin/src/native.rs (-905, deleted), kamaji/src/sandbox.rs, kamaji/src/{native,jit}.rs, kamaji-bin/src/{server,lib,journal,containerd}.rs, kamaji-bin/Cargo.toml, workload-spec/src/lib.rs (+203), velveteen-exec/src/remote.rs (+70), headscale_appliance.rs (+40). Two files in that commit are NOT mine and I did not touch them: app/yah/cli/resources/kamaji.service (B9's CAP_SETPCAP edit) and workload-spec/src/control_plane_install.rs (a peer's). `landlock` is gone from oss/kamaji/Cargo.lock as well as from the manifest.")
//! @yah:verify("ACCEPTANCE, superseding the ticket's original framing now that the code has landed. THE CALL-SITE RULE: `rg -n \"confine_fs_at_exec\" --type rust` from oss/kamaji must show calls at kamaji/src/native.rs:649 (inside `spawn_child`) AND kamaji/src/jit.rs:694 (inside `spawn_jit_child`) — a call site from BOTH spawners, not a test count. `derive_landlock` / `install_landlock` no longer exist to grep for: R885-B11 deleted the whole of kamaji-bin/src/native.rs rather than leave a second dead fork path. THE LIVE ACCEPTANCE IS STILL OWED and is the operator's step. It is weaker than B9's on purpose, because under the \"confine what describes itself\" rule the four live us-east-001 workloads declare nothing and carry no Bind volumes, so they get NO landlock and this change is a NO-OP for them — `grep Cap` proves B9, not B11. What actually proves B11 on a node: (a) journal — kamaji must NOT log its \"kernel does not support landlock\" warn for any workload that does describe its writes; (b) the first genuinely confined workload is headscale, which is not running anywhere today, so standing it up on a node and confirming it writes its db/noise key/socket into its state dir is the real test; (c) a native forge run against a Linux worker, which is the case the conservative declaration could surprise — see the forge caveat in the handoff. Until one of those runs, the policy is proven by compilation, unit tests and reading, and nothing more.")
//! @yah:gotcha("THE RULE CAN BE OPTED OUT OF BY SAYING NOTHING, and that is deliberate — but it means a NEW native producer added later is unconfined by default and nothing will fail to tell you. Both of today's producers declare (velveteen_exec::remote::mark_native_exec and headscale_appliance::appliance_spec), and `validate_native_exec_spec` refuses a MALFORMED declaration — but it does not and must not refuse a MISSING one, because confining a workload that has never described its writes means confining it to a guess. If you add a third setter of `yah.exec = native`, declare `yah.writable-paths` on it in the same change, or it runs exactly as unbounded as everything did before R885.")
//! @yah:handoff("FIX 1 LANDED — /dev IS WRITABLE FOR A CONFINED WORKLOAD. Found by the independent verification pass, not by me: ALWAYS_WRITABLE was \"/tmp\" alone and the base rule grants only EXECUTE|READ_FILE|READ_DIR on `/`, so the FIRST confined workload to run `2>/dev/null` — a shell redirect, most subprocess spawns, much of cargo — would have taken an EACCES far from this file, exactly the failure mode this ticket exists to prevent. New `ALWAYS_WRITABLE_DEVICES` in sandbox.rs: /dev/null, /dev/zero, /dev/full, /dev/random, /dev/urandom, /dev/tty. THEY ARE GRANTED AS FILE RULES, NOT DIRECTORY RULES, and that is load-bearing rather than pedantic: the kernel's `landlock_append_fs_rule` returns -EINVAL for a rule on a non-directory whose mask is not a subset of ACCESS_FILE, so handing a device node the full handled mask would have failed the rule — and, before this change's degrade, the spawn with it. New `file_access(handled)` masks to EXECUTE|WRITE_FILE|READ_FILE|TRUNCATE (IOCTL_DEV omitted: this module never handles it, so it is permitted everywhere and granting it would be meaningless), pinned by `the_device_grant_carries_only_file_rights` across ABI 1..5. DEGRADE: a device the host lacks — /dev/tty is routinely absent in container-ish environments — is skipped via `add_rule_best_effort`, which swallows the add_rule syscall error too, and debug-logs. Declared paths keep the STRICTER treatment (a kernel-rejected rule there still errors), because a rejected rule on a declared path means the policy is not what the spec said.")
//! @yah:handoff("ONE DEPARTURE FROM FIX 1 AS BRIEFED, AND IT IS A CORRECTION RATHER THAN A TRIM: /dev/stdout AND /dev/stderR ARE DELIBERATELY NOT IN THE DEVICE SET. They were in the dispatched list; adding them would have been actively harmful. Both are symlinks into /proc/self/fd, and every rule in this module is built in the PARENT — so `open(\"/dev/stdout\", O_PATH)` resolves to KAMAJI's stdout, not the child's. On a fleet node kamaji runs under systemd with stdout on the journal socket, and `get_path_from_fd` rejects internal filesystems outright with -EBADFD; under the pre-Fix-1 error handling that would have failed EVERY confined spawn on the fleet, and under the new best-effort handling it would silently grant nothing. They are also unnecessary: a child opening /dev/stdout resolves it against its OWN /proc/self/fd/1, which both spawners point at `<state-dir>/<ident>/stdout.log` — inside the workload state dir, which writable_roots always grants. So the access already works, through a path that can actually be named. Both facts are written at the const and pinned by `dev_stdout_is_deliberately_not_in_the_device_set`, so the next reader sees a decision rather than an omission.")
//! @yah:handoff("FIX 2 LANDED — THE TRIGGER NARROWED, AND THIS CHANGES THIS TICKET'S OWN STATED RULE. WAS: confine if the spec declares writable paths OR carries Bind volumes. NOW: confine IF AND ONLY IF the spec carries a non-empty `yah.writable-paths` declaration. Nothing else turns the policy on. RATIONALE, recorded at `writable_roots` and not only here: a Bind volume is a RESOURCE declaration — \"this workload needs this directory\" — not a confinement opt-in, and reading it as consent confines specs nobody audited for it. That is not hypothetical, and it is the single path by which this hot ship could have bitten a live node: the four native workloads on us-east-001 are deployed from specs no in-tree producer emits, so nothing in this tree can prove they carry no writable Bind, and under the old both-channels rule they could have been confined without anybody having looked at them. BINDS STILL UNION INTO THE ALLOW-LIST once a declaration is present — they are real writes and denying them would be wrong — they simply no longer decide WHETHER the policy applies. Both in-tree producers stay confined because each declares explicitly, which is now the only reason either is confined. The narrowing also makes the earlier handoff entry \"a Bind volume alone confines\" obsolete — treat this entry as superseding it, and note I corrected the two producer doc comments that asserted the old rule (headscale_appliance.rs's \"redundant with the Bind volume\" paragraph, which was ALSO wrong about redundancy, and mark_native_exec's \"the kept volume is what makes this spec eligible for confinement\").")
//! @yah:handoff("GATES RE-RUN AFTER BOTH FIXES — DELTAS ONLY, everything else held. kamaji lib 176 passed / 0 failed (was 171, +5 new sandbox::tests: dev_null_is_always_writable, the_device_grant_carries_only_file_rights, dev_stdout_is_deliberately_not_in_the_device_set, the_handled_mask_is_capped_at_what_the_kernel_reports, a_bind_volume_still_unions_in_once_a_declaration_exists — plus two REWRITTEN rather than added: `a_bind_volume_alone_confines_too` is now `a_bind_volume_alone_does_not_confine` and asserts None, and `named_and_tmpfs_volumes_have_no_host_path_to_grant` now declares a path first and asserts the Named/Tmpfs targets are absent from the set, since under the new trigger \"returns None\" would have passed for the wrong reason). kamaji-bin lib 223 / 0 — UNCHANGED. workload-spec lib 203 / 0 — UNCHANGED (this round touched no workload-spec code). velveteen-exec 135 / 0 and yubaba headscale_appliance 16 / 16 — unchanged, both rounds were doc-comment corrections only. `cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu --all-targets` = Finished exit 0, with only the pre-existing free_port dead_code. Clippy on host AND on x86_64-unknown-linux-gnu: exactly the one pre-existing too_many_arguments (9/7, jit.rs supervise_on_demand) on each — baseline held. rustfmt --check on sandbox.rs: no diff. Drift gates not re-run and not needed — no generated type was touched (the new consts and the two helpers are Linux/test-gated `u64` arithmetic). NOTED for next time, from the verification pass: check-schema-drift.sh completes if given a private CARGO_TARGET_DIR, which is why it timed out on me behind the shared root lock.")
//! @yah:gotcha("SUPERSEDED BY FIX 2 — the earlier gotcha on this ticket said a new native producer that declares nothing \"runs exactly as unbounded as everything did before R885\". Still true, and now true of MORE specs: a Bind volume no longer triggers confinement either, so an explicit non-empty `yah.writable-paths` is the ONLY thing that turns landlock on. If you add a third setter of `yah.exec = native`, the annotation is not optional polish — without it the workload is unconfined, and with a volume but no annotation it is also unconfined. `validate_native_exec_spec` refuses a MALFORMED declaration and deliberately does not refuse a MISSING one.")
//! @yah:verify("CORRECTION to the acceptance entry above, forced by FIX 2. That entry justified \"this change is a NO-OP for the four live us-east-001 workloads\" with \"they declare nothing AND carry no Bind volumes\". The second half was never provable — those four are deployed from specs no in-tree producer emits, so nothing in this tree can establish their volume list, and the verification pass named exactly that as the risk. It is now IRRELEVANT rather than unproven: under the narrowed trigger only a non-empty `yah.writable-paths` declaration confines anything, and no deployed spec can carry one until a producer that writes it is rolled. So the no-op claim now rests on a fact about the CODE rather than an assumption about four specs nobody has read. Everything else in that entry stands, including that the live acceptance is still owed and is the operator's step.")
//! @yah:handoff("LANDED AND DOUBLE-VERIFIED. Landlock is wired into both live fork paths as kamaji::sandbox::{writable_roots, confine_fs_at_exec} — called from kamaji::native::spawn_child (native.rs:649) and kamaji::jit::spawn_jit_child (jit.rs:694), registration order cgroup attach -> (jit: fd-3 dup2/CLOEXEC) -> landlock -> cap drop. Driven by a new `yah.writable-paths` annotation + accessor + WritablePathsDeclError in workload-spec, a validate_native_exec_spec guard in kamaji-bin/server.rs, and declarations on BOTH in-tree native producers (velveteen-exec mark_native_exec declares forge_state::HOST_ROOT = /var/lib/yah/qed; yubaba appliance_spec declares headscale_dir), so the rule has no undeclared consumer left. The whole dead oss/kamaji/crates/kamaji-bin/src/native.rs was DELETED rather than left as a second fork path — that second copy is what let this rot for two months — and both R885-B9's and R885-B11's @yah: annotation blocks moved verbatim to kamaji/src/sandbox.rs, where the board still resolves each to exactly one block.")
//! @yah:handoff("TWO DEFECTS CAUGHT BY VERIFICATION AND FIXED BEFORE SIGN-OFF, both of which would have surfaced as an EACCES far from this file — the exact failure mode this ticket exists to prevent. (1) /dev WAS NOT WRITABLE: ALWAYS_WRITABLE was \"/tmp\" alone and the base rule grants only EXECUTE|READ_FILE|READ_DIR on /, so a CONFINED workload opening /dev/null for write got EACCES — and a shell redirect, most subprocess spawns and much of cargo do exactly that. Fixed with ALWAYS_WRITABLE_DEVICES (/dev/null, zero, full, random, urandom, tty) granted as FILE rules via a new file_access() mask (= handled & EXECUTE|WRITE_FILE|READ_FILE|TRUNCATE — a strict subset carrying no directory-only right, since the kernel EINVALs a non-directory rule that carries one), with absent or unrulable nodes skipped through add_rule_best_effort so a missing /dev/tty cannot fail a spawn. /dev/stdout and /dev/stderr are DELIBERATELY EXCLUDED and it matters why: they are /proc/self/fd symlinks that resolve at PARENT-side rule-build time against kamaji's own process, so on a fleet node they would resolve to kamaji's journal socket and error the strict add_rule path; the child needs no path grant for its inherited stderr anyway, because landlock gates path-based open and not write(2) on an already-open descriptor, and both spawners already point the child's fd 1/2 at stdout.log/stderr.log inside the always-granted state dir. (2) CONFINEMENT TRIGGERED ON BIND VOLUMES: writable_roots returned None only when declared paths AND binds were both empty, so a spec with a Bind volume and no declaration became accidentally confined to {state dir, /tmp, that bind} — and since the four live us-east-001 natives are deployed from specs no in-tree producer emits, nobody could prove they carry no such volume. That was the single path by which this change could have bitten a live node. The trigger now requires a NON-EMPTY explicit yah.writable-paths declaration; binds still union into the allow-list when a declaration is present, they just no longer trigger on their own. Rationale, now in the doc comment: a Bind volume is a resource declaration, not a confinement opt-in, and \"confine what describes itself\" means the spec has to actually say so.")
//! @yah:verify("TWO INDEPENDENT VERIFICATION PASSES by a courier that did not write the code, both read-only. FULL PASS, eight checks, all green: call sites lexically inside both spawners (native.rs:649, jit.rs:694); registration order confirmed by reading (native cgroup :632 -> landlock :649 -> cap drop :663; jit cgroup :647 -> fd-3 dup2 :667 -> landlock :694 -> cap drop :710); degrade path read from code not comments — landlock_abi() probes PARENT-side before cmd.pre_exec, returns None on rc<=0 into warn + Ok(()) so an unsupported kernel spawns UNCONFINED rather than failing, handled_access(abi) caps the mask at ABI 1/2/3 so an old kernel cannot EINVAL, PR_SET_NO_NEW_PRIVS is set, and the post-fork closure is exactly prctl + landlock_restrict_self over one captured OwnedFd with zero Vec/String/format!/tracing; BACKWARD COMPAT WITH SPECS ALREADY ON THE FLEET is the SKIP and not an empty deny-list — writable_paths() returns Ok(vec![]) for an absent annotation, the validate guard never fires, and writable_roots early-returns None so no ruleset is built at all; the deletion is clean (no dangling mod, tree-wide rg for every deleted item returns only prose); both ticket IDs still resolve to exactly one @yah:ticket block each. NUMBERS RE-RUN BY THE VERIFIER, not taken on report: kamaji lib 176 pass / 0 fail (162 -> 171 -> 176 across the three passes), kamaji-bin lib 223 / 0, workload-spec lib 203 / 0, zigbuild x86_64-unknown-linux-gnu --all-targets exit 0, clippy exactly the one pre-existing too_many_arguments (9/7, supervise_on_demand jit.rs:464). THE 239 -> 223 DROP ON kamaji-bin WAS AUDITED RATHER THAN ACCEPTED: `git show 0084982f^:.../kamaji-bin/src/native.rs` counts exactly 17 #[test]/#[tokio::test], the change adds exactly one, and zero `-#[test]` lines appear in any other kamaji-bin file — no live test was silently dropped. DRIFT GATES: check-workload-spec-ts.sh green; check-schema-drift.sh GREEN and actually run to completion (\"ok: .yah/schema is in sync with the Rust types\", exit 0) under a private CARGO_TARGET_DIR to sidestep the shared root target lock that had killed two earlier attempts at 580s — worth reusing, the structural argument is no longer needed. DELTA PASS after the two fixes above re-confirmed FIX 2's early return precedes the binds computation entirely, both producers still declare non-empty, the device rules carry no directory-only right, add_rule_best_effort collapses both an open failure and a kernel rejection to a debug log, and the post-fork closure is still allocation-free.")
//! @yah:verify("LIVE ON us-east-001 AND CORRECTLY INERT, which is this ticket's intended first-roll outcome rather than a missing result. Shipped 2026-09-11 with R885-B4/B9/B10 in the same 0.8.39-h1 hot ship. All four native workloads restarted and serve normally, and the journal carries ZERO landlock lines — no ruleset was built for any of them. That is exactly what FIX 2's trigger requires: none of the four carries a `yah.writable-paths` declaration, so `writable_roots` early-returns None and `confine_fs_at_exec` returns before creating a ruleset. The change therefore proved on a live node that it CANNOT confine a workload that has not opted in — which was the specific hot-ship risk the verification pass raised and FIX 2 closed. WHAT REMAINS UNEXERCISED, stated plainly so nobody reads this as full acceptance: NO WORKLOAD HAS YET BEEN CONFINED IN PRODUCTION. The confining path (a spec that declares writable paths -> a real landlock ruleset -> the workload still working) has been proven only by unit tests and cross-compilation. The first genuine exercise will be whichever of the two declaring producers deploys first — velveteen-exec's forge leg (declares /var/lib/yah/qed) or yubaba's headscale appliance (declares headscale_dir) — and the forge leg is the riskier of the two, since its write set was declared conservatively by reading rather than by observing a run. WATCH FOR EACCES on that first confined deploy, and note the /dev question is already handled: /dev/null, zero, full, random, urandom and tty are granted as file rules, and /dev/stdout and /dev/stderr are deliberately excluded because the child's fd 1/2 already point at stdout.log/stderr.log inside the always-granted state dir.")

use std::path::{Path, PathBuf};

use workload_spec::{VolumeSource, WorkloadSpec, WritablePathsDeclError};

/// `CAP_NET_BIND_SERVICE` — bind a socket to a port below 1024.
const CAP_NET_BIND_SERVICE: u32 = 10;

/// `CAP_SETPCAP` — among other things, `PR_CAPBSET_DROP`.
#[cfg(target_os = "linux")]
const CAP_SETPCAP: u32 = 8;

/// The lowest port number that needs `CAP_NET_BIND_SERVICE` to bind.
const PRIVILEGED_PORT_CEILING: u16 = 1024;

/// The capability set a workload keeps, as a bitmask over capability numbers.
///
/// **Derived from the spec, not configured.** The only capability any yah
/// workload has ever needed is `CAP_NET_BIND_SERVICE`, and the spec already
/// says whether it needs it: a declared port below 1024. Every other capability
/// in kamaji's ambient set exists for *kamaji's* work (`CAP_KILL` for
/// `pidfd_send_signal`, `CAP_SYS_PTRACE` for `waitid(P_PIDFD)`, `CAP_NET_ADMIN`
/// for netns setup) and never had a reason to reach a workload.
///
/// All three exposure channels are read, not just the mesh one:
/// [`workload_spec::PublicExpose::port`] and
/// [`workload_spec::OperatorExpose::port`] are container-side ports the
/// workload itself listens on, so a spec that named a privileged port only
/// there would otherwise lose the bind.
///
/// A **name-only** mesh port (`ports = ["http"]`) carries no number — the
/// supervisor allocates it, from the ephemeral range, so it is never
/// privileged. Port 0 is the kernel's "pick one for me" and is not privileged
/// either; both are correctly absent from the mask.
///
/// As of 2026-09-11 no in-tree native spec declares a port below 1024 — the two
/// production setters of the `yah.exec = native` marker are the headscale
/// appliance (8080) and velveteen-exec's forge steps (no exposed ports) — so
/// this retains nothing today. It is the rule that keeps a future privileged
/// listener working without anybody having to remember this module exists.
pub fn retained_caps(spec: &WorkloadSpec) -> u64 {
    let mesh = spec.expose.mesh.numbers().into_iter();
    let public = spec.expose.public.iter().map(|p| p.port);
    let operator = spec.expose.operator.iter().map(|o| o.port);
    let binds_privileged_port = mesh
        .chain(public)
        .chain(operator)
        .any(|p| p != 0 && p < PRIVILEGED_PORT_CEILING);

    if binds_privileged_port {
        1 << CAP_NET_BIND_SERVICE
    } else {
        0
    }
}

/// Always writable, whether or not any spec says so: the shared temp dir.
///
/// The same argument [`writable_roots`] makes for the workload's own state dir.
/// Every unix toolchain assumes a writable `TMPDIR` and reaches for this path
/// when the variable is unset — a `cargo` that cannot write a temp file fails
/// somewhere far from its cause — and `/tmp` is mode 1777 on every node, so
/// granting it takes nothing away from anybody: a workload that wanted to abuse
/// it could already do so before this module existed. Making every spec restate
/// it would be noise on the same order as restating the state dir.
const ALWAYS_WRITABLE: &str = "/tmp";

/// The device nodes every confined workload may write to, whether or not any
/// spec says so.
///
/// **`/dev/null` is not an optional convenience.** A shell redirect, most
/// subprocess spawns and much of `cargo` open it for writing, and the base rule
/// this module installs on `/` grants read and execute only — so without this
/// list the first confined workload takes an `EACCES` from something as ordinary
/// as `2>/dev/null`, raised far from this file, which is the exact failure mode
/// R885-B11 exists to prevent. The rest of the list is the conventional
/// always-present set; each is a character device with no state to corrupt, and
/// every one of them is world-writable (mode 666) or world-readable already, so
/// granting them takes nothing from anybody.
///
/// **These are files, not directories**, which matters mechanically: the kernel
/// rejects a rule on a non-directory whose access mask contains directory-only
/// rights (`landlock_append_fs_rule`'s `-EINVAL`), so they are granted
/// [`file_access`] and not the full handled mask.
///
/// # Why `/dev/stdout` and `/dev/stderr` are deliberately absent
///
/// They cannot be expressed as a static rule and adding one would be actively
/// harmful. Both are symlinks into `/proc/self/fd`, so resolving them at
/// rule-build time — which happens in the PARENT — yields *kamaji's* stdout, not
/// the child's: on a fleet node that is systemd's journal socket, which
/// `get_path_from_fd` rejects outright (`-EBADFD`, an internal filesystem), so
/// the rule would fail rather than mislead. They are also unnecessary. A child
/// opening `/dev/stdout` resolves it against its OWN `/proc/self/fd/1`, which
/// both spawners point at `<state-dir>/<ident>/stdout.log` — inside the workload
/// state dir, which [`writable_roots`] always grants. So the access works; it
/// just works through a path that can be named.
#[cfg(any(target_os = "linux", test))]
const ALWAYS_WRITABLE_DEVICES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
];

/// The thirteen filesystem access rights ABI 1 defines: bits 0..=12, from
/// `EXECUTE` through `MAKE_SYM`.
#[cfg(any(target_os = "linux", test))]
const ACCESS_FS_ABI1: u64 = (1 << 13) - 1;
/// `LANDLOCK_ACCESS_FS_REFER` — ABI 2. Linking/renaming *between* directories,
/// which ABI 1 always denied and ABI 2 made grantable.
#[cfg(any(target_os = "linux", test))]
const ACCESS_FS_REFER: u64 = 1 << 13;
/// `LANDLOCK_ACCESS_FS_TRUNCATE` — ABI 3.
#[cfg(any(target_os = "linux", test))]
const ACCESS_FS_TRUNCATE: u64 = 1 << 14;
/// `EXECUTE | READ_FILE | READ_DIR` — what the base rule grants on `/`.
#[cfg(any(target_os = "linux", test))]
const ACCESS_FS_READ: u64 = (1 << 0) | (1 << 2) | (1 << 3);
/// The kernel's `ACCESS_FILE`: the only rights a rule on a non-directory may
/// carry. `EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE` — `IOCTL_DEV` (ABI 5) is
/// the fifth member and is omitted because this module never *handles* it, so it
/// is permitted everywhere and granting it would be meaningless.
#[cfg(any(target_os = "linux", test))]
const ACCESS_FS_FILE: u64 = (1 << 0) | (1 << 1) | (1 << 2) | ACCESS_FS_TRUNCATE;

/// The access rights to *handle* — i.e. to deny unless a rule grants them — on a
/// kernel speaking `abi`.
///
/// Handling a right the running kernel does not define is an `EINVAL` from
/// `landlock_create_ruleset`, so this is capped at what `abi` reports rather than
/// at what this binary knows. Rights added by an ABI newer than 3 are simply not
/// handled, which means they stay permitted — the same best-effort posture the
/// `landlock` crate's `CompatLevel::BestEffort` takes, and the only one that
/// keeps a node on an older kernel running.
#[cfg(any(target_os = "linux", test))]
fn handled_access(abi: u32) -> u64 {
    let mut mask = ACCESS_FS_ABI1;
    if abi >= 2 {
        mask |= ACCESS_FS_REFER;
    }
    if abi >= 3 {
        mask |= ACCESS_FS_TRUNCATE;
    }
    mask
}

/// The subset of `handled` that a rule on a **file** may carry.
///
/// `landlock_append_fs_rule` returns `-EINVAL` for a non-directory rule whose
/// mask is not a subset of the kernel's `ACCESS_FILE`, so a device-node rule
/// built from the full handled mask would fail — and, before the degrade added
/// with it, would have failed the spawn.
#[cfg(any(target_os = "linux", test))]
fn file_access(handled: u64) -> u64 {
    handled & ACCESS_FS_FILE
}

/// The set of directory trees a native workload may write to, or `None` when it
/// is to run **unconfined**.
///
/// # The rule: confinement requires an explicit declaration
///
/// `None` — no landlock at all — unless the spec carries a **non-empty
/// [`WRITABLE_PATHS_ANNOTATION`](workload_spec::WRITABLE_PATHS_ANNOTATION)
/// declaration**. Nothing else turns confinement on. It is the same shape
/// [`retained_caps`] has — a rule keyed on what the spec says, not a
/// compatibility flag — and a spec that has never described its writes cannot be
/// confined without guessing, where a wrong guess is an `EACCES` raised hours
/// into a build, far from this file.
///
/// **A `Bind` volume does not trigger confinement**, and that narrowing is
/// deliberate (it tightened during R885-B11's own review). A volume is a
/// *resource* declaration — "this workload needs this directory" — not a
/// confinement opt-in, and reading it as one would confine specs nobody audited
/// for it. That is not hypothetical: the four native workloads live on
/// us-east-001 are deployed from specs no in-tree producer emits, so nothing in
/// this tree can prove they carry no writable `Bind`, and under the older
/// both-channels rule this change could have confined them on a hot ship. Binds
/// still **union into** the allow-list once a declaration is present — they are
/// real writes and denying them would be wrong — they simply no longer decide
/// *whether* the policy applies.
///
/// The cost of that rule is that it can be opted out of by saying nothing, which
/// is why R885-B11 landed the declarations for **both** in-tree producers of
/// `yah.exec = native` in the same change: `velveteen_exec`'s forge leg and
/// yubaba's headscale appliance. A third producer that declares nothing runs
/// unconfined — deliberately, and visibly, because that is better than the
/// alternative of confining it to a guess.
///
/// # What is in the set
///
/// 1. `workload_dir` — the per-workload state dir kamaji itself creates
///    (`<state-dir>/<mesh-ident>`, holding `stdout.log` / `stderr.log` and any
///    materialized spec files). It is the child's own scratch, kamaji made it,
///    and requiring every spec to restate it would be pure noise.
/// 2. [`ALWAYS_WRITABLE`]. The device nodes in [`ALWAYS_WRITABLE_DEVICES`] are
///    granted too, but by [`confine_fs_at_exec`] rather than here — they are
///    files, so they need a different access mask and are not directory roots.
/// 3. The spec's [`WorkloadSpec::writable_paths`] declaration.
/// 4. The **host** path of each writable `Bind` volume.
///
/// Note (4) is the *host* path, not the volume `target`. For a container the
/// two differ and the target is the one that matters; a native workload has no
/// mount namespace at all, so the target names a directory that does not exist
/// and the host path is the only one landlock can grant. `Named` and `Tmpfs`
/// sources have no host path to grant and are skipped — as they were in the
/// kamaji-bin derivation this replaces, which is where the rest of this rule
/// comes from.
///
/// A read-only `Bind` contributes nothing: reads are permitted everywhere by
/// [`confine_fs_at_exec`]'s base rule, so a read-only volume is already
/// satisfied and adding it here could only *widen* the grant.
pub fn writable_roots(
    spec: &WorkloadSpec,
    workload_dir: &Path,
) -> Result<Option<Vec<PathBuf>>, WritablePathsDeclError> {
    let declared = spec.writable_paths()?;
    if declared.is_empty() {
        return Ok(None);
    }

    let binds: Vec<&PathBuf> = spec
        .volumes
        .iter()
        .filter(|v| !v.read_only)
        .filter_map(|v| match &v.source {
            VolumeSource::Bind { host_path } => Some(host_path),
            _ => None,
        })
        .collect();

    let candidates = [workload_dir.to_path_buf(), PathBuf::from(ALWAYS_WRITABLE)]
        .into_iter()
        .chain(declared)
        .chain(binds.into_iter().cloned());
    // Order-preserving dedup rather than `sort` + `dedup`: the declared order is
    // what an operator reading a warning about a skipped path will be looking
    // at, and a duplicate here is a *duplicate rule*, which landlock tolerates
    // but which makes the ruleset misleading to audit.
    let mut roots: Vec<PathBuf> = Vec::new();
    for path in candidates {
        if !roots.contains(&path) {
            roots.push(path);
        }
    }
    Ok(Some(roots))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};

    use workload_spec::WorkloadSpec;

    use super::{
        file_access, handled_access, retained_caps, ACCESS_FS_READ, ALWAYS_WRITABLE_DEVICES,
        CAP_SETPCAP,
    };

    /// `_LINUX_CAPABILITY_VERSION_3` — the 64-bit, two-`__user_cap_data_struct`
    /// ABI every kernel since 2.6.26 speaks.
    const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    /// Capability numbers are dense from 0 and the kernel's `CAP_LAST_CAP` grows
    /// over time; scanning the whole 64-bit space and tolerating `EINVAL` for the
    /// ones this kernel has never heard of keeps the sweep correct on a kernel
    /// newer than this binary.
    const CAP_SCAN_LIMIT: u32 = 64;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapHeader {
        version: u32,
        pid: libc::c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    /// Register the post-fork/pre-exec hook that drops this child's capabilities
    /// to the set [`retained_caps`] derives from `spec`, on `cmd`.
    ///
    /// **One helper, both spawners** — `native::spawn_child` (the keep-alive
    /// tier) and `jit::spawn_jit_child` (the on-demand tier) each call this, for
    /// the reason [`crate::cgroup::CgroupHandle::attach_at_exec`] gives at
    /// length: two spawners carrying two copies of one boundary is exactly the
    /// shape that let the R406 boundary layer rot unreachable for two months,
    /// and a second copy is free to drift.
    ///
    /// **Register it AFTER the cgroup self-attach.** `std` runs `pre_exec`
    /// closures in registration order, and the attach needs write access to
    /// `cgroup.procs` that this drop can take away. In `jit.rs` it must also come
    /// after the fd-3 `dup2`/`CLOEXEC` handoff, for the same reason.
    ///
    /// Takes the **std** [`std::process::Command`]; a `tokio::process::Command`
    /// caller passes `cmd.as_std_mut()`.
    pub fn drop_caps_at_exec(
        spec: &WorkloadSpec,
        cmd: &mut std::process::Command,
    ) -> io::Result<()> {
        use std::os::unix::process::CommandExt as _;

        let retain = retained_caps(spec);

        // Probed HERE, in the parent, before the fork: the child cannot report
        // why it failed (std keeps only the errno of a `pre_exec` error), and
        // "kamaji was not granted CAP_SETPCAP" is the one failure an operator is
        // ever expected to hit. See the module docs for why this is skipped
        // rather than fatal.
        let can_drop_bounding = holds_setpcap()?;
        if !can_drop_bounding {
            tracing::warn!(
                workload = %spec.name,
                "kamaji holds no CAP_SETPCAP: leaving workload {}'s capability BOUNDING set \
                 untouched. Effective/permitted/inheritable/ambient are still cleared, but a \
                 uid-0 workload regains the bounding set at execve, so this drop is a no-op for \
                 one. Add CAP_SETPCAP to CapabilityBoundingSet= and AmbientCapabilities= in \
                 kamaji.service to close it.",
                spec.name
            );
        }

        // SAFETY: the closure runs post-fork/pre-exec in the child and calls only
        // async-signal-safe primitives (prctl, capget, capset) over stack data.
        // `retain` is computed above, before the fork, so the child allocates
        // nothing.
        unsafe {
            cmd.pre_exec(move || apply_in_child(retain, can_drop_bounding));
        }
        Ok(())
    }

    /// Whether the calling thread has `CAP_SETPCAP` in its effective set — the
    /// capability `PR_CAPBSET_DROP` demands.
    fn holds_setpcap() -> io::Result<bool> {
        let mut data = [CapData::default(); 2];
        capget(&mut data)?;
        Ok(data[0].effective & (1 << CAP_SETPCAP) != 0)
    }

    /// The drop itself. Runs in the forked child.
    ///
    /// Order is Ambient, Inheritable, Bounding, then Effective/Permitted — each
    /// step leaves the privilege the next one needs intact. The ambient *raise*
    /// of a retained capability has to sit after the inheritable write because
    /// `PR_CAP_AMBIENT_RAISE` demands the capability be in both the permitted and
    /// the inheritable set at the time of the call, and the bounding sweep has to
    /// sit before the final `capset` because it needs `CAP_SETPCAP` to still be
    /// effective.
    fn apply_in_child(retain: u64, drop_bounding: bool) -> io::Result<()> {
        let mut caps = [CapData::default(); 2];
        capget(&mut caps)?;

        // A capability we do not hold cannot be retained, and asking for it would
        // turn a harmless over-declaration into a failed spawn.
        let retain = retain & (caps[0].permitted as u64 | (caps[1].permitted as u64) << 32);
        let lo = retain as u32;
        let hi = (retain >> 32) as u32;

        // 1. Ambient — cleared wholesale. EINVAL means a kernel older than 4.3,
        //    which has no ambient set to clear.
        if unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        } != 0
        {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(err);
            }
        }

        // 2. Inheritable — down to the retained set, ahead of the ambient raise
        //    that reads it. Effective and permitted are carried through unchanged
        //    so steps 3 and 4 still have the privilege they need.
        caps[0].inheritable = lo;
        caps[1].inheritable = hi;
        capset(&caps)?;

        // 3. Ambient — put back exactly what the spec justified, so a retained
        //    capability survives the exec even for a workload that is not root.
        for cap in 0..CAP_SCAN_LIMIT {
            if retain & (1 << cap) == 0 {
                continue;
            }
            if unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                    cap as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }

        // 4. Bounding — the one that actually binds, because a uid-0 execve
        //    re-grants `permitted = bounding | inheritable` from a file with no
        //    capabilities. EINVAL is a capability number this kernel does not
        //    define; anything else is real.
        if drop_bounding {
            for cap in 0..CAP_SCAN_LIMIT {
                if retain & (1 << cap) != 0 {
                    continue;
                }
                if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong) } != 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINVAL) {
                        continue;
                    }
                    return Err(err);
                }
            }
        }

        // 5. Effective and permitted. Last, because everything above needed them.
        caps[0].effective = lo;
        caps[0].permitted = lo;
        caps[1].effective = hi;
        caps[1].permitted = hi;
        capset(&caps)?;

        Ok(())
    }

    /// `capget(2)` on the calling thread. Raw syscall rather than a crate: this
    /// runs post-fork in one of its two callers, where an allocating helper is
    /// not safe to call.
    fn capget(data: &mut [CapData; 2]) -> io::Result<()> {
        let mut header = CapHeader {
            version: CAPABILITY_VERSION_3,
            pid: 0,
        };
        // SAFETY: both pointers are to live, correctly-shaped stack storage, and
        // the version field selects the two-struct data ABI the array matches.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut header as *mut CapHeader,
                data.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    // ── Landlock (R885-B11) ──────────────────────────────────────────────────

    /// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` — ask
    /// the kernel which ABI it speaks instead of creating a ruleset.
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

    /// `LANDLOCK_RULE_PATH_BENEATH`, the only rule type ABI 1-3 defines.
    const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

    /// `struct landlock_ruleset_attr`. Only the ABI-1 field is passed; the
    /// syscall is size-versioned, so a shorter struct is how a caller says "I do
    /// not handle the rights the later ABIs added".
    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    /// `struct landlock_path_beneath_attr`, which the kernel declares
    /// **packed** — `allowed_access` is 8 bytes and `parent_fd` follows it at
    /// offset 8, for a 12-byte struct rather than the 16 natural alignment would
    /// give. Getting this wrong is a silent `EINVAL`.
    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: libc::c_int,
    }

    /// Register the post-fork/pre-exec hook confining this child's **writes** to
    /// the trees [`super::writable_roots`] derives from `spec`, on `cmd`.
    ///
    /// Does nothing at all when the spec describes no writes — see
    /// [`super::writable_roots`] for that rule and why it is a rule rather than
    /// a flag.
    ///
    /// **One helper, both spawners**, for the reason
    /// [`super::drop_caps_at_exec`] gives. **Register it AFTER the cgroup
    /// self-attach** (which writes to `cgroup.procs`, a path no ruleset grants)
    /// and, in `jit.rs`, after the fd-3 handoff; **before** the capability drop,
    /// which is the order `kamaji-bin`'s `pre_exec_in_child` used and the one
    /// that leaves each step the privilege the next one needs.
    ///
    /// # Degrade, never fail
    ///
    /// A kernel with no landlock, or one whose ABI predates the rights we ask
    /// for, **warns and spawns unconfined**. The probe runs in the PARENT,
    /// before the fork, for the reason [`holds_setpcap`] exists: `std` keeps only
    /// the raw errno of a `pre_exec` failure, so an `ENOSYS` raised inside the
    /// hook would be indistinguishable from any other `ENOSYS` in the spawn
    /// path. A declared path that does not exist on the node is skipped with a
    /// warning naming it, rather than failing the spawn — the kamaji-bin
    /// derivation this replaces made the same call, and for the same reason: a
    /// mount point that has not materialized yet must not be fatal.
    ///
    /// The one thing that IS fatal is a *malformed* declaration: that is a spec
    /// bug, `validate_native_exec_spec` already refuses it at admission, and
    /// running unconfined because nobody could read the confinement would be the
    /// silent-downgrade failure this module exists to avoid.
    pub fn confine_fs_at_exec(
        spec: &WorkloadSpec,
        workload_dir: &std::path::Path,
        cmd: &mut std::process::Command,
    ) -> io::Result<()> {
        use std::os::unix::process::CommandExt as _;

        let Some(roots) = super::writable_roots(spec, workload_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        else {
            return Ok(());
        };

        let Some(abi) = landlock_abi() else {
            tracing::warn!(
                workload = %spec.name,
                "kernel does not support landlock: spawning workload {} UNCONFINED. Its spec \
                 declares writable paths, so this node is not enforcing them.",
                spec.name
            );
            return Ok(());
        };

        // Every fd the child touches is opened here, in the parent: the hook
        // must not allocate, and `open` of a path needs a CString it would have
        // to build. The ruleset fd survives the fork (fds are inherited) and is
        // consumed before the exec that would close it.
        let ruleset = build_ruleset(abi, &roots, &spec.name)?;

        // SAFETY: the closure runs post-fork/pre-exec in the child and calls
        // only `prctl` and `landlock_restrict_self` on an fd opened before the
        // fork. It allocates nothing.
        unsafe {
            cmd.pre_exec(move || restrict_self_in_child(ruleset.as_raw_fd()));
        }
        Ok(())
    }

    /// The landlock ABI version this kernel speaks, or `None` when it speaks
    /// none. `ENOSYS` is a kernel built without landlock; `EOPNOTSUPP` is one
    /// built with it but booted with it disabled (`lsm=` without `landlock`).
    fn landlock_abi() -> Option<u32> {
        // SAFETY: the version query passes a null attr with size 0, which is the
        // documented shape for this flag.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if rc <= 0 {
            return None;
        }
        Some(rc as u32)
    }

    /// Create the ruleset and populate it. Parent-side; the child inherits only
    /// the resulting fd.
    ///
    /// The base rule grants [`ACCESS_FS_READ`] on `/` — read, readdir and
    /// **execute** everywhere. Without it the child could not exec its own
    /// binary, let alone resolve the dynamic linker, so this is not a
    /// relaxation of the policy but a precondition for having one. The policy
    /// this module enforces is about *writes*; W344 names a read confinement as
    /// a later axis, and it needs to know what a workload reads, which is a
    /// harder question than what it writes.
    ///
    /// After it come [`ALWAYS_WRITABLE_DEVICES`] — `/dev/null` and friends,
    /// granted [`file_access`] rather than the full mask because they are not
    /// directories — and then one rule per entry in `roots`. A device node that
    /// this host does not have is skipped, not fatal: `/dev/tty` is absent in
    /// plenty of container-ish environments, and refusing to spawn over it would
    /// be a worse failure than the one the grant prevents.
    fn build_ruleset(
        abi: u32,
        roots: &[std::path::PathBuf],
        workload: &str,
    ) -> io::Result<OwnedFd> {
        let handled = handled_access(abi);
        let attr = RulesetAttr {
            handled_access_fs: handled,
        };
        // SAFETY: `attr` is live stack storage and `size` describes it exactly.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `rc` is a fresh fd the kernel just returned and nothing else
        // owns it.
        let ruleset = unsafe { OwnedFd::from_raw_fd(rc as RawFd) };

        add_rule(
            &ruleset,
            std::path::Path::new("/"),
            handled & ACCESS_FS_READ,
        )?
        .then_some(())
        .ok_or_else(|| io::Error::other("landlock: cannot open / to grant the base read rule"))?;

        // Best-effort by design: an absent device node, or a kernel that refuses
        // the rule, must not fail a spawn over a grant the workload may never
        // use. `add_rule_best_effort` swallows the syscall error too, which the
        // declared-path loop below deliberately does not.
        let device_access = file_access(handled);
        for device in ALWAYS_WRITABLE_DEVICES {
            let path = std::path::Path::new(device);
            if !add_rule_best_effort(&ruleset, path, device_access) {
                tracing::debug!(
                    workload = %workload,
                    path = %device,
                    "landlock: device node absent or unrulable on this host; skipped"
                );
            }
        }

        for root in roots {
            if !add_rule(&ruleset, root, handled)? {
                tracing::warn!(
                    workload = %workload,
                    path = %root.display(),
                    "landlock: declared writable path does not exist on this node and was \
                     skipped; a write to it will fail with EACCES"
                );
            }
        }
        Ok(ruleset)
    }

    /// [`add_rule`] with every failure — an absent path *and* a rejected rule —
    /// collapsed into `false`.
    ///
    /// Only for [`ALWAYS_WRITABLE_DEVICES`], which nothing declared and which no
    /// spec depends on: these are a convenience grant, so a host that cannot
    /// carry one loses the convenience rather than the workload. A declared path
    /// keeps the stricter treatment — a rule the kernel *rejects* there means the
    /// policy is not what the spec said, and that deserves to surface.
    fn add_rule_best_effort(ruleset: &OwnedFd, path: &std::path::Path, access: u64) -> bool {
        add_rule(ruleset, path, access).unwrap_or(false)
    }

    /// Add one `PathBeneath` rule. `Ok(false)` means the path could not be
    /// opened — it does not exist yet, which is the caller's to warn about.
    fn add_rule(ruleset: &OwnedFd, path: &std::path::Path, access: u64) -> io::Result<bool> {
        use std::os::unix::ffi::OsStrExt as _;

        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return Ok(false);
        };
        // O_PATH is the right open mode for a landlock parent fd: it needs to
        // name the inode, not to read it, so this works for a directory the
        // daemon has no read permission on.
        // SAFETY: `c_path` is a live NUL-terminated string.
        let parent = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if parent < 0 {
            return Ok(false);
        }
        // SAFETY: a fresh fd nobody else owns; closed when this binding drops.
        let parent = unsafe { OwnedFd::from_raw_fd(parent) };

        let rule = PathBeneathAttr {
            allowed_access: access,
            parent_fd: parent.as_raw_fd(),
        };
        // SAFETY: `rule` is live stack storage matching the packed layout the
        // kernel documents for LANDLOCK_RULE_PATH_BENEATH.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const PathBeneathAttr,
                0u32,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(true)
    }

    /// The restriction itself. Runs in the forked child, and is the whole of
    /// what runs there: two syscalls over no memory at all.
    ///
    /// `PR_SET_NO_NEW_PRIVS` is not optional decoration —
    /// `landlock_restrict_self` returns `EPERM` without it for a caller lacking
    /// `CAP_SYS_ADMIN`, and it is the right posture anyway: a confined workload
    /// that could regain privilege through a setuid helper is not confined.
    fn restrict_self_in_child(ruleset_fd: RawFd) -> io::Result<()> {
        // SAFETY: prctl with a fixed option and no pointer arguments.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `ruleset_fd` was opened in the parent and is still open in
        // this child; the syscall takes no pointers.
        if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// `capset(2)` on the calling thread.
    fn capset(data: &[CapData; 2]) -> io::Result<()> {
        let mut header = CapHeader {
            version: CAPABILITY_VERSION_3,
            pid: 0,
        };
        // SAFETY: as for `capget` — live stack storage, matching ABI version.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_capset,
                &mut header as *mut CapHeader,
                data.as_ptr(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::{confine_fs_at_exec, drop_caps_at_exec};

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        ExposeSpec, ImageRef, MeshExpose, MeshIdent, MeshPort, Millis, NamespaceId, ResourceLimits,
        RestartPolicy, StopPolicy, TenantId, TierTag, VolumeSource, WorkloadSpec,
    };

    fn spec_with_ports(ports: Vec<MeshPort>) -> WorkloadSpec {
        WorkloadSpec {
            name: "capdrop".to_string(),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            image: ImageRef {
                registry: "localhost".to_string(),
                repository: "native/capdrop".to_string(),
                tag: "dev".to_string(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".to_string()),
            replicas: 1,
            command: Some(vec!["/bin/true".to_string()]),
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
                    identity: MeshIdent("capdrop".to_string()),
                    ports,
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            durability: None,
            annotations: Default::default(),
            files: vec![],
        }
    }

    #[test]
    fn a_declared_port_below_1024_retains_cap_net_bind_service() {
        let spec = spec_with_ports(vec![MeshPort::anonymous(443)]);
        assert_eq!(retained_caps(&spec), 1 << CAP_NET_BIND_SERVICE);
    }

    #[test]
    fn a_declared_port_above_1024_retains_nothing() {
        let spec = spec_with_ports(vec![MeshPort::anonymous(8080)]);
        assert_eq!(retained_caps(&spec), 0);
    }

    #[test]
    fn one_privileged_port_among_several_is_enough() {
        let spec = spec_with_ports(vec![
            MeshPort::anonymous(8080),
            MeshPort::pinned("acme", 80),
            MeshPort::anonymous(9090),
        ]);
        assert_eq!(retained_caps(&spec), 1 << CAP_NET_BIND_SERVICE);
    }

    #[test]
    fn a_name_only_port_is_supervisor_allocated_and_never_privileged() {
        // No number yet — the supervisor picks one from the ephemeral range, so
        // there is nothing here that could need the capability.
        let spec = spec_with_ports(vec![MeshPort::named("http")]);
        assert_eq!(retained_caps(&spec), 0);
    }

    #[test]
    fn a_workload_that_exposes_nothing_retains_nothing() {
        let spec = spec_with_ports(Vec::new());
        assert_eq!(retained_caps(&spec), 0);
    }

    fn bind(host_path: &str, target: &str, read_only: bool) -> workload_spec::VolumeMount {
        workload_spec::VolumeMount {
            source: VolumeSource::Bind {
                host_path: PathBuf::from(host_path),
            },
            target: PathBuf::from(target),
            read_only,
            from_secret_mount: false,
        }
    }

    fn workload_dir() -> PathBuf {
        PathBuf::from("/var/lib/yah/kamaji/native/capdrop")
    }

    fn declare(spec: &mut WorkloadSpec, value: &str) {
        spec.annotations.insert(
            workload_spec::WRITABLE_PATHS_ANNOTATION.to_string(),
            value.to_string(),
        );
    }

    #[test]
    fn a_spec_that_describes_no_writes_is_not_confined() {
        let spec = spec_with_ports(Vec::new());
        assert_eq!(writable_roots(&spec, &workload_dir()).unwrap(), None);
    }

    #[test]
    fn a_declared_path_confines_and_carries_the_state_dir_and_tmp() {
        let mut spec = spec_with_ports(Vec::new());
        declare(&mut spec, "/var/lib/yah/qed");
        assert_eq!(
            writable_roots(&spec, &workload_dir()).unwrap().unwrap(),
            vec![
                workload_dir(),
                PathBuf::from(ALWAYS_WRITABLE),
                PathBuf::from("/var/lib/yah/qed"),
            ]
        );
    }

    #[test]
    fn a_bind_volume_alone_does_not_confine() {
        // The narrowing R885-B11's review demanded, and the one this whole
        // change could have bitten a live node with. A volume is a RESOURCE
        // declaration — "this workload needs this directory" — not a
        // confinement opt-in. The four native workloads on us-east-001 are
        // deployed from specs no in-tree producer emits, so nothing here can
        // prove they carry no writable Bind; reading a volume as consent would
        // have confined them on a hot ship without anybody auditing them.
        let mut spec = spec_with_ports(Vec::new());
        spec.volumes = vec![bind(
            "/var/lib/yah-cloud/headscale",
            "/var/lib/yah-cloud/headscale",
            false,
        )];
        assert_eq!(writable_roots(&spec, &workload_dir()).unwrap(), None);
    }

    #[test]
    fn a_bind_volume_still_unions_in_once_a_declaration_exists() {
        // The other half of the same rule: binds no longer DECIDE whether the
        // policy applies, but they are real writes, so once the spec has opted
        // in they are still granted.
        let mut spec = spec_with_ports(Vec::new());
        declare(&mut spec, "/var/lib/yah-cloud/headscale");
        spec.volumes = vec![bind("/srv/extra", "/srv/extra", false)];
        assert_eq!(
            writable_roots(&spec, &workload_dir()).unwrap().unwrap(),
            vec![
                workload_dir(),
                PathBuf::from(ALWAYS_WRITABLE),
                PathBuf::from("/var/lib/yah-cloud/headscale"),
                PathBuf::from("/srv/extra"),
            ]
        );
    }

    #[test]
    fn declared_paths_union_with_bind_volumes() {
        let mut spec = spec_with_ports(Vec::new());
        declare(&mut spec, "/var/lib/yah/qed");
        spec.volumes = vec![bind("/var/lib/yah/qed/produced/f1", "/yah/produced", false)];
        let roots = writable_roots(&spec, &workload_dir()).unwrap().unwrap();
        assert!(roots.contains(&PathBuf::from("/var/lib/yah/qed")));
        // The HOST path, not the container-side target: a native workload has no
        // mount namespace, so `/yah/produced` names nothing on the node.
        assert!(roots.contains(&PathBuf::from("/var/lib/yah/qed/produced/f1")));
        assert!(!roots.contains(&PathBuf::from("/yah/produced")));
    }

    #[test]
    fn the_state_dir_is_always_present_without_being_declared() {
        let mut spec = spec_with_ports(Vec::new());
        declare(&mut spec, "/srv/data");
        let roots = writable_roots(&spec, &workload_dir()).unwrap().unwrap();
        assert!(roots.contains(&workload_dir()));
        assert!(roots.contains(&PathBuf::from(ALWAYS_WRITABLE)));
    }

    #[test]
    fn a_read_only_bind_does_not_widen_the_write_set() {
        let mut spec = spec_with_ports(Vec::new());
        declare(&mut spec, "/srv/data");
        spec.volumes = vec![bind("/etc/cfg", "/etc/cfg", true)];
        let roots = writable_roots(&spec, &workload_dir()).unwrap().unwrap();
        assert!(!roots.contains(&PathBuf::from("/etc/cfg")));
    }

    #[test]
    fn named_and_tmpfs_volumes_have_no_host_path_to_grant() {
        let mut spec = spec_with_ports(Vec::new());
        declare(&mut spec, "/srv/data");
        spec.volumes = vec![
            workload_spec::VolumeMount {
                source: VolumeSource::Named { name: "vol".into() },
                target: PathBuf::from("/vol"),
                read_only: false,
                from_secret_mount: false,
            },
            workload_spec::VolumeMount {
                source: VolumeSource::Tmpfs { size_mb: 64 },
                target: PathBuf::from("/scratch"),
                read_only: false,
                from_secret_mount: false,
            },
        ];
        let roots = writable_roots(&spec, &workload_dir()).unwrap().unwrap();
        assert!(!roots.contains(&PathBuf::from("/vol")));
        assert!(!roots.contains(&PathBuf::from("/scratch")));
    }

    #[test]
    fn a_path_declared_twice_across_channels_appears_once() {
        let mut spec = spec_with_ports(Vec::new());
        declare(&mut spec, "/srv/data");
        spec.volumes = vec![bind("/srv/data", "/srv/data", false)];
        let roots = writable_roots(&spec, &workload_dir()).unwrap().unwrap();
        assert_eq!(
            roots
                .iter()
                .filter(|p| *p == &PathBuf::from("/srv/data"))
                .count(),
            1
        );
    }

    #[test]
    fn dev_null_is_always_writable() {
        // The one that would have bitten first. The base rule grants read and
        // execute on `/` only, so without this list a confined workload takes
        // an EACCES from `2>/dev/null` — a shell redirect, most subprocess
        // spawns, much of cargo.
        assert!(ALWAYS_WRITABLE_DEVICES.contains(&"/dev/null"));
        for expected in ["/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"] {
            assert!(
                ALWAYS_WRITABLE_DEVICES.contains(&expected),
                "{expected} must be in the always-writable device set"
            );
        }
    }

    #[test]
    fn the_device_grant_carries_only_file_rights() {
        // `landlock_append_fs_rule` returns EINVAL for a rule on a
        // non-directory whose mask is not a subset of the kernel's ACCESS_FILE.
        // Every entry here is a device node, so the mask must be the file
        // subset — and it must still actually carry WRITE_FILE, or the grant
        // does nothing.
        for abi in 1..=5u32 {
            let mask = file_access(handled_access(abi));
            assert_eq!(
                mask & !ACCESS_FS_FILE,
                0,
                "abi {abi}: a file rule may carry only ACCESS_FILE rights"
            );
            assert_ne!(mask & (1 << 1), 0, "abi {abi}: WRITE_FILE must survive");
        }
    }

    #[test]
    fn dev_stdout_is_deliberately_not_in_the_device_set() {
        // It is a symlink into /proc/self/fd, so resolving it at rule-build
        // time — in the PARENT — names kamaji's own stdout, which on a fleet
        // node is systemd's journal socket and is rejected outright (EBADFD).
        // The child's own /dev/stdout resolves to
        // <state-dir>/<ident>/stdout.log, which the state-dir grant already
        // covers.
        for absent in ["/dev/stdout", "/dev/stderr"] {
            assert!(
                !ALWAYS_WRITABLE_DEVICES.contains(&absent),
                "{absent} cannot be expressed as a static rule; see the const's docs"
            );
        }
    }

    #[test]
    fn the_handled_mask_is_capped_at_what_the_kernel_reports() {
        // Handling a right the running kernel does not define is an EINVAL from
        // landlock_create_ruleset — i.e. a node on an older kernel failing to
        // build any ruleset at all.
        assert_eq!(handled_access(1), ACCESS_FS_ABI1);
        assert_eq!(handled_access(2), ACCESS_FS_ABI1 | ACCESS_FS_REFER);
        assert_eq!(
            handled_access(3),
            ACCESS_FS_ABI1 | ACCESS_FS_REFER | ACCESS_FS_TRUNCATE
        );
        // Newer ABIs add rights this module does not model; they stay permitted
        // rather than turning into an EINVAL.
        assert_eq!(handled_access(9), handled_access(3));
        // The base `/` rule must grant execute, or the child cannot exec itself.
        assert_ne!(handled_access(1) & ACCESS_FS_READ & 1, 0);
    }

    #[test]
    fn a_malformed_declaration_is_an_error_not_an_empty_set() {
        let mut spec = spec_with_ports(Vec::new());
        declare(&mut spec, "relative/path");
        assert!(writable_roots(&spec, &workload_dir()).is_err());
    }

    #[test]
    fn a_privileged_port_declared_only_on_the_public_channel_still_counts() {
        let mut spec = spec_with_ports(vec![MeshPort::anonymous(8080)]);
        spec.expose.public = Some(workload_spec::PublicExpose {
            hostname: "example.test".into(),
            port: 443,
            tls: workload_spec::PublicTls::CfManaged,
        });
        assert_eq!(retained_caps(&spec), 1 << CAP_NET_BIND_SERVICE);
    }
}

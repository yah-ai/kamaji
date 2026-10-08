//! On-demand ("serverless") JIT lifecycle for bundle workloads (R599-F6).
//!
//! The keep-alive backend ([`crate::native`]) forks the serve runtime at deploy
//! and keeps it resident. The **on-demand** tier instead keeps *zero* resident
//! process when idle: kamaji owns the workload's listen socket permanently (via
//! the [`SocketCustodian`] primitive, R599-F9), forks the serve runtime **on the
//! first connection**, hands it the socket, and reaps it after an idle TTL. The
//! first request eats the fork-to-serving latency; subsequent requests hit the
//! warm process; after `idle_ttl` with zero connections the process is gone and
//! the workload costs nothing but the held fd. This is the W272 §3 "serverless"
//! leg made concrete.
//!
//! ## The poll-fork-rearm loop
//!
//! kamaji is deliberately **out of the data path** — it never `accept()`s. Per
//! workload a supervisor task:
//!
//! 1. **Arms** a readable-watch on the held listener fd via [`tokio::io::unix::AsyncFd`]
//!    (edge-triggered readiness; we *poll*, the child accepts). A fresh
//!    registration each cycle observes the socket's current readability, so a
//!    connection that arrived while a child was serving is seen immediately.
//! 2. On a pending connection, **forks** the serve runtime, passing the held fd
//!    as the child's fd 3 (`dup2` → 3, clear `FD_CLOEXEC`) with `LISTEN_FDS=1` —
//!    the systemd socket-activation convention the serve binary adopts
//!    (`mesofact-serve`'s `socket_activation_listener`). The child accepts on the
//!    inherited fd.
//! 3. **Waits** for the child. The serve runtime self-reaps after its own
//!    `--idle-ttl` elapses with zero in-flight requests (kamaji does not own idle
//!    detection — the runtime does, deliberately). On child exit, kamaji does
//!    **not** release the socket; it loops back to (1) and re-arms.
//!
//! Because the socket lives in kamaji (never closes across a reap/re-fork),
//! connections that arrive between a reap and the next fork sit in the kernel
//! accept queue and are served by the freshly forked child — **zero dropped
//! connections**. A crash during idle costs nothing (there is no process);
//! a crash during serve is just an early exit that re-arms the watch.
//!
//! ## Why not reuse the native supervisor
//!
//! The native backend's supervisor ([`crate::native::supervise`]) owns a *live*
//! child at all times and re-execs it per a [`RestartPolicy`]. The JIT lifecycle
//! is the opposite invariant — no child most of the time, and the trigger to
//! spawn is a socket becoming readable, not a policy timer. Sharing the loop
//! would tangle two contradictory lifecycles, so JIT gets its own supervisor and
//! reuses only the leaf helpers (`argv`, log capture).
//!
//! ## What this module forks is a WORKLOAD, so it is confined (R885-B10)
//!
//! Answering the question the next auditor will ask, at the site, so it does not
//! have to be re-derived: the children [`spawn_jit_child`] forks are **tenant
//! workloads**, not kamaji-internal helpers. They are built from a
//! [`WorkloadSpec`] that arrived over the UDS `Deploy`, they carry that spec's
//! mesh identity, argv, env and [`workload_spec::ResourceLimits`], and they are
//! the same serve binaries the keep-alive tier forks — an on-demand bundle
//! (`BundleLifecycle::OnDemand`) and a per-tenant passway (R852-F1) differ from
//! a keep-alive bundle only in *when* the fork happens. So every reason R885-B1
//! gives for confining [`crate::native`]'s children applies here unchanged, and
//! this tier gets the same treatment through the same mechanism rather than one
//! of its own: [`crate::cgroup::CgroupV2`], the `<workload-id>/<generation>/`
//! hierarchy of R885-B4, and the self-attach hook
//! ([`crate::cgroup::CgroupHandle::attach_at_exec`]) that R885-B1 wrote and this
//! ticket lifted out of `native.rs` so there is exactly one copy of it.
//!
//! The JIT shape puts two wrinkles on that, both deliberate:
//!
//! - **One generation per deploy, not per fork.** The node and its generation
//!   leaf are minted in [`JitRuntime::deploy_on_demand`] and every cold start
//!   attaches into that same leaf, exactly as the native backend's restart loop
//!   respawns into the handle it already holds. The fork/reap cycle is one
//!   workload's lifecycle, not a succession of deploys, and a generation per
//!   cold start would litter the node with a directory per request burst.
//! - **The ceiling is live while the workload is idle.** A cgroup with no
//!   processes in it costs nothing, so holding the node across the zero-resident
//!   window is free and keeps the limits (and their counters) continuous across
//!   reaps — which is what makes a JIT workload's `memory.peak` readable at all.
//!
//! Degrade path, unchanged from R885-B1: a host whose delegated subtree cannot
//! be resolved logs a `warn!` at startup and forks unconfined, exactly as this
//! tier did before this ticket. It resolves its own root rather than sharing the
//! native backend's, so neither runtime can take the other's confinement down —
//! see [`crate::native::resolve_cgroup_root`].
//!
//! @yah:relay(R852, "Custom-domain onboarding, the halves outside passway/yubaba: declare a per-tenant passway workload, and render the tenant-facing enrollment page")
//! @yah:at(2026-09-03T06:26:19Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("Split out of R779 (free-tier ingress at 10k domains) at its P8 close-out, because both halves are outside R779's blast radius rather than unfinished inside it. R779 shipped and proved the whole passway/yubaba side: SNI demux on one shared :443 that terminates no TLS, per-tenant passway fd-3 adoption + idle self-reap behind kamaji JIT (oss/passway/crates/passway/tests/jit_cold_start.rs proves fork/serve/reap/re-fork end to end), the R2-backed cert store off raft, the enrollment set as the structural allowlist, the per-domain ACME issuer, and DNS-01 _acme-challenge CNAME delegation now proven against a real CA (oss/passway/crates/acme-engine/tests/pebble_dns01_delegation.rs). What is left is a way to DECLARE a per-tenant passway, and a place for a tenant to READ their two DNS records. Design canon: .yah/docs/working/W267-sovereign-public-ingress.md.")
//!
//! @yah:ticket(R852-F1, "A workload kind for a per-tenant passway, so kamaji JIT can actually fork one")
//! @yah:status(review)
//! @yah:at(2026-09-03T08:19:03Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R852)
//! @yah:next("THE PASSWAY HALF IS DONE AND PROVEN — do not rebuild it. JitRuntime::deploy_on_demand is already generic over WorkloadSpec, but kamaji-bin only ROUTES to it for a MesofactStatic workload carrying a serve_bundle (server.rs deploy_mesofact_bundle / deploy_bundle_on_demand). So a per-tenant passway has no way to be declared. Needs: a workload kind in workload-spec, a kamaji-bin routing arm, and a yah-cloud reconciler arm.")
//! @yah:next("THE BIND STRING IS THE FD-TABLE KEY AND MUST MATCH BYTE FOR BYTE. The workload's env must carry PASSWAY_LISTEN equal to kamaji's listen_addr as a string, plus PASSWAY_IDLE_TTL_SECS (self-reap; unset = never reap), plus LISTEN_FDS=1 which kamaji's jit.rs already sets. passway's socket-activation feature is on by default and PANICS rather than binding fresh if LISTEN_FDS is set and the seed does not take — deliberate, so a supervisor never silently gets a second listener. The demux route for the tenant points at that held socket.")
//! @yah:gotcha("Touching workload-spec trips the GENERATED-ARTIFACT drift gates: .yah/schema/*.toml.schema.json and packages/yah/workload-spec/index.ts no longer regenerate on commit (disabled 2026-08-15 because cargo run blocks on the shared target-dir lock). Regenerate by hand once your build is not contending with the camp: cargo run -p xtask -- emit-schemas, and cargo run --manifest-path oss/yah-base/crates/workload-spec/Cargo.toml --bin export-ts. schema-drift-guard / workload-spec-drift-guard in .yah/qed/check.toml will fail otherwise. Generated artifacts are NOT ownable under the shared-tree rule — regenerate them even if the type that moved was a peer's.")
//! @yah:next("SECOND-ORDER, and it only starts to matter once this lands: yubaba's secret_reload rotation watcher resolves from raft ALONE. It is driven by a raft state-change watch, so a cert rotated only into R2 by the per-domain issuer produces no bump and the reload never fires. Harmless for a short-lived JIT passway (it re-reads at every cold start) and harmless today (nothing declares one), but a long-running per-tenant passway would serve an expiring cert. Fix it in this relay if you make per-tenant passways long-lived: oss/yubaba/crates/yubaba/src/secret_reload.rs, and see the LayeredSecretStore seam R779 added at oss/yubaba/crates/yubaba/src/lib.rs.")
//! @yah:handoff("LANDED — kind = \"tenant-passway\", the fifth Workload variant, plus its kamaji routing arm and its yubaba reconciler. (1) workload_spec::TenantPasswayWorkload + TenantPasswayTls (oss/yah-base/crates/workload-spec/src/lib.rs), appended LAST to Workload and to all four tagging mirrors — postcard encodes an external tag as the variant index, so anywhere but the end renumbers the four a deployed node already decodes. jit_spec() renders the WorkloadSpec kamaji forks and DERIVES every load-bearing env key (PASSWAY_LISTEN, LISTEN_FDS=1, PASSWAY_IDLE_TTL_SECS, PASSWAY_UPSTREAMS, PASSWAY_TLS_*) from the declaration, applying the caller's env map FIRST so an escape hatch cannot break the fd handoff. (2) kamaji-bin gains a `tenant-passway` feature + --tenant-passway-dir + ServerCtx.tenant_passway, a deliberately SEPARATE JitRuntime from BundleBackend::jit (same rationale as ServerCtx::native vs BundleBackend::native), with arms in deploy_workload, Stop teardown, List merge, and the graceful-upgrade refusal. (3) yubaba::tenant_passway sweeps the same cert_store::enrolled() set demux_routes publishes from and arms one passway per domain via KamajiClient::deploy_envelope; wired into `yubaba serve` after attach_constable_client.")
//! @yah:verify("Generated artifacts regenerated per the ticket's own gotcha: cargo run -p xtask -- emit-schemas and the workload-spec export-ts bin. git diff on .yah/schema + packages/yah/workload-spec is ADDITIONS ONLY and all tenant-passway — no peer's type drift got swept in. Both drift gates read red only because the regenerated files are uncommitted; re-running the generators produces no further change.")
//! @yah:gotcha("A PEER EDITED UNDER ME, and the edit was correct so I kept it: oss/yubaba/crates/cloud/src/reconciler/static_asset_prune.rs's workload_kind_str helper (a hand-written four-arm match, the exact 'sixth place enumerating the variants' Workload::kind_str's doc warns about) went non-exhaustive when I added the variant, and someone replaced it with a kind_str() call while I was working. Verified against git show HEAD: the old form is in the last commit. Naming it here because it is in my diff and is not my authorship — likely @Ashguard:libra (session:d5b179fd) or the session running clippy on yah-cloud, but git cannot attribute an uncommitted hunk so I will not assert which.")
//! @yah:assumes("The ticket's third `next` — yubaba's secret_reload rotation watcher resolving from raft alone — is deliberately NOT fixed, because the condition it named ('fix it if you make per-tenant passways long-lived') does not hold: the default is cold (DEFAULT_IDLE_TTL_SECS = 60) and a cold passway re-reads its chain at every start. The never-reap escape hatch exists (YUBABA_TENANT_PASSWAY_IDLE_TTL_SECS=0), and the rotation gap it re-opens is documented on TenantPasswayWorkload::idle_ttl where someone setting it will read it, rather than left silent.")
//! @yah:verify("Tests, all green and all run: yah-workload-spec --test main 73 pass (5 new — postcard frame is [4]++payload, flat kind-tagged JSON round-trip, the derive-not-restate env invariant incl. an env map that tries to override PASSWAY_LISTEN/LISTEN_FDS, idle_ttl rounding up + None omitting the var, empty-upstreams). kamaji-bin --features tenant-passway --lib 220 pass (4 new: deploy arms the DECLARED socket and Stop releases it — asserted by trying to bind it ourselves, so nothing forks; a hostname listen is InvalidSpec; tier-not-attached names --tenant-passway-dir; and the no-feature build names --features tenant-passway, run separately without the feature). yubaba --lib 610 pass (7 new). yah-cloud --lib 958 pass. cargo check clean on all three workspaces: root --workspace --all-targets, oss/kamaji --workspace --all-targets --all-features, oss/yubaba --workspace --all-targets.")
//! @yah:gotcha("PRE-EXISTING RED, not mine: xtask --test main fleet_build_placement::build_offloads_land_where_this_table_says_they_do fails (x86_64/linux builds land on us-west-002, EXPECTED_BUILD_PLACEMENT says us-west-003). It is placement over .yah/infra/machines/*.toml — no machine file is modified in the working tree and I touched no placement code, so this is red on committed state. The other 56 xtask tests pass, including workload_envelope (I added \"tenant-passway\" to MODELLED_KINDS: no hand-written file carries the kind today, but listing it means the first one anyone writes is checked rather than skipped).")
//!
//! @yah:ticket(R885-B10, "A second live fork path at jit.rs bypasses the cgroup entirely — R885-B1 confined one spawner, not the backend")
//! @yah:at(2026-09-11T09:27:46Z)
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R885)
//! @yah:severity(P1)
//! @yah:next("Tier: Warrior — same live blast radius as R885-B1 (it changes what running fleet processes are bounded by), on a Linux-only path this Mac cannot exercise.")
//! @yah:next("FOUND BY R885-B9's MEASUREMENT PASS, 2026-09-11, not by reading the code: while scoping the capability-drop landing site, @Ashguard recorded 'a SECOND live fork path (jit.rs:482, no cgroup) that the enable step must cover or explicitly exclude'. It is filed here rather than on B9 because it is a RESOURCE-axis hole, which is R885's subject, not B9's capability axis.")
//! @yah:next("WHY THIS MATTERS MORE THAN ITS SIZE: R885's whole premise is 'native workloads run unbounded'. R885-B1 closed that for kamaji::native::NativeRuntime::spawn_child and its live acceptance was read there — four pids in their own leaves on us-east-001. If jit.rs forks a second way, then the relay's acceptance criterion is satisfied at the site that was measured and false at a site nobody looked at. That is the same shape as the bug R885 exists to fix: confinement believed to be in force because the one path anybody checked has it.")
//! @yah:next("FIRST QUESTION, AND IT DECIDES THE TICKET: are the processes jit.rs forks WORKLOADS, or are they kamaji-internal helpers? R885-B1's handoff notes jit.rs already installs a pre_exec hook (the same idiom the cgroup self-attach uses), so the post-fork window exists and the fix is cheap IF they are workloads. If they are internal helpers, the correct answer may be that they belong in kamaji's OWN cgroup and the ticket closes as a documented exclusion — but document it at the site, because the next person will ask again.")
//! @yah:next("IF THEY ARE WORKLOADS, the fix is mechanical and the pattern is four tickets old: resolve the leaf, attach in the pre_exec hook, and honour R885-B4's <workload-id>/<generation>/ hierarchy rather than minting a flat leaf. Do not invent a second confinement mechanism beside cgroup::CgroupV2 — having two of anything here is precisely what let the R406 layers rot unreachable for two months.")
//! @yah:next("MIND THE DEGRADE PATH. R885-B1 made NativeRuntime::new log a warn! and set cgroup=None on a host whose layout it cannot resolve, at which point everything runs unbounded; R885-T2 followed the same shape for pids. Whatever you do here must degrade no worse than that, and must not be able to take the EXISTING confinement down with it.")
//! @yah:handoff("WORKLOADS, NOT HELPERS — so they are confined, and that was decided by reading what the fork carries, not by analogy. jit.rs forks a child built from the WorkloadSpec that arrived over the UDS Deploy: its mesh identity, argv/entrypoint, env and ResourceLimits. Its two live consumers are an on-demand bundle (BundleLifecycle::OnDemand) and a per-tenant passway (R852-F1), i.e. the same serve binaries the keep-alive tier forks — the JIT tier differs from native only in WHEN the fork happens, never in whose code runs. The conclusion is written at the site as a new module-doc section in oss/kamaji/crates/kamaji/src/jit.rs ('What this module forks is a WORKLOAD, so it is confined'), so the next auditor gets the answer without re-deriving it.")
//! @yah:handoff("WHAT LANDED, three files under oss/kamaji/crates/kamaji/src. (1) jit.rs: JitRuntime gains cgroup: Option<CgroupV2> resolved once in new(); deploy_on_demand mints the workload node + this deploy's generation leaf via CgroupV2::create_workload with WorkloadLimits::from_spec, storing the CgroupHandle on JitHandle and passing a clone into supervise_on_demand; spawn_jit_child takes Option<&CgroupHandle> and registers the self-attach hook; teardown_workload now calls destroy_workload (R885-B4's kill -> drain -> read -> rmdir) with the same three-arm logging native uses. (2) cgroup.rs: the pre_exec self-attach that R885-B1 wrote inline in native.rs is now CgroupHandle::attach_at_exec (linux-only, takes a std Command; a tokio caller passes cmd.as_std_mut()), with fmt_u32 moved beside it. (3) native.rs: its inline hook is replaced by a call to that method, so there is exactly ONE attach implementation rather than a second one beside CgroupV2 — the failure mode the ticket named.")
//! @yah:handoff("ONE GENERATION PER DEPLOY, NOT PER COLD START — the one design call this ticket made beyond the mechanical fix, and it is deliberate. The JIT tier forks a fresh child on every cold start; minting a generation each time would leave a directory per request burst under the node. Instead the node+leaf are minted at deploy_on_demand and every cold start attaches into that same leaf, which is exactly what the native backend's restart loop already does (Supervised::start respawns into the handle it holds). Consequences, both good: the ceiling and its hierarchical counters stay continuous across reaps, so a JIT workload's memory.peak is readable at all; and a redeploy still gets a fresh generation, so R885-B4's rmdir-vs-mkdir race stays closed (pinned by jit::tests::a_redeploy_on_demand_mints_a_new_generation).")
//! @yah:handoff("THE DEGRADE PATH IS THE SAME ONE, AND IT CANNOT REACH THE NATIVE BACKEND. JitRuntime::new calls the SAME resolver (native::resolve_cgroup_root, made pub(crate) and given a `backend` label so its journal lines say which fork path they describe). An unresolvable host yields cgroup=None and JIT children fork unbounded exactly as they did before this ticket — no new refusal, no new failure mode. The two runtimes resolve INDEPENDENTLY rather than sharing one CgroupV2: ensure_root is idempotent (a second `+cpu +memory` write to cgroup.subtree_control), so a JIT-side failure returns None for JIT alone and cannot take the four confined workloads on us-east-001 down with it. R885-B1's grep string is preserved byte-for-byte for the native caller — the label is a format arg, so that line still reads `native backend: confining workloads to cgroup leaves under the delegated root`; JIT emits the same sentence with the `jit` prefix.")
//! @yah:handoff("A THIRD FORK PATH EXISTS AND IS NOW A STATED EXCLUSION, found by the acceptance grep rather than by the brief: microvm.rs GuestBoot::boot spawns the VMM (firecracker/cloud-hypervisor) and attaches to no leaf. Left unattached ON PURPOSE and commented at the site (microvm.rs, immediately above the Command::new): a microVM's ceiling is already the mem_size_mib written into its machine config (microvm.rs:951-952, guest_memory_mb/guest_vcpus from the spec), and the module's own doc at guest_memory_mb contrasts that with a cgroup ceiling. Wrapping memory.max around the VMM would put a second independent ceiling on one workload, and whichever fired first would OOM-kill the whole VM with no OOM inside the guest to explain it. The comment names attach_at_exec as the mechanism to use if a later ticket decides otherwise, so nobody grows a second one. The remaining Command::new sites in the crate (docker.rs, container_net.rs, microvm.rs:2561) are `.output()`-shaped kamaji tool invocations, not tenant code — they belong in kamaji's own `<root>/native` cgroup where they already land; that classification is written into attach_at_exec's doc under 'Which forks are in scope'.")
//! @yah:verify("THE ACCEPTANCE GREP, cited verbatim: `rg -n --no-heading -e 'Command::new' -e 'attach_at_exec' oss/kamaji/crates/kamaji/src/ -g '!*.md' | rg -v '^\\S+:[0-9]+: *//'`. Thirteen hits. The two workload fork sites (native.rs:592 and jit.rs:599) each pair with an attach_at_exec call twenty lines later (native.rs:632, jit.rs:632). microvm.rs:1115 is the VMM, unattached and carrying the exclusion comment directly above it. The rest are docker.rs:224/1094, container_net.rs:585, microvm.rs:2561 (kamaji's own `.output()` tool invocations) and three lines inside #[cfg(test)] modules. No fork reaches spawn() unattached and uncommented.")
//! @yah:verify("EVERY NUMBER RUN BY ME ON THIS TREE. `cargo test -p kamaji --features native-integration --lib`: 156 pass / 0 fail against the 153 baseline, +3 all mine. `cargo test -p kamaji --features native-integration,microvm-integration --lib`: 198 / 0 against the 195 baseline, same +3. `cargo test -p kamaji-bin --features native-exec --lib`: 239 / 0, baseline 239 UNCHANGED (kamaji-bin needed no call-site edit — JitRuntime::new resolves its own root, so main.rs:717, server.rs:613 and the five test constructors all get confinement for free). `cargo check --workspace --all-features --all-targets` from oss/kamaji: exit 0, only kamaji-bin's standing dead-code warnings. `cargo check -p camp-identity` from the root workspace: exit 0.")
//! @yah:verify("THE CALL-SITE TESTS, in R885-B1's shape — they drive the real deploy_on_demand/teardown_workload against a tempdir cgroup root, not the driver. jit::tests::deploying_on_demand_mints_a_cgroup_leaf_carrying_its_limits asserts the ceiling is on the NODE (memory.max=67108864, cpu.weight=12, no cpu.max for a request-only spec) with exactly one generation directory beneath it, and that teardown reaps the generation. jit::tests::a_redeploy_on_demand_mints_a_new_generation asserts two deploys get distinct generations, one survivor, one unchanged ceiling. jit::tests::a_host_without_a_delegated_subtree_still_deploys_on_demand pins the degrade path and asserts its own premise (runtime.cgroup.is_none()) so it cannot pass vacuously. A fourth, jit::tests::a_cold_start_child_joins_the_generation_leaf, is #[cfg(target_os = \"linux\")]: it connects to the held socket, waits for the cold start, and asserts the forked child's own pid is in the generation leaf's cgroup.procs — the only test that pins the ATTACH rather than the mint. It COMPILES for x86_64-unknown-linux-gnu (cargo zigbuild -p kamaji --features native-integration --target x86_64-unknown-linux-gnu --all-targets, exit 0) but has never been executed; this is a Mac.")
//! @yah:verify("CROSS-COMPILE, the Linux-path verification this Mac can achieve: `cargo zigbuild -p kamaji-bin --features containerd-integration,native-exec --target x86_64-unknown-linux-gnu` from oss/kamaji — Finished, exit 0, on the final tree after formatting. CLIPPY: `cargo clippy -p kamaji --features native-integration --all-targets` — exactly ONE warning, the pre-existing too-many-arguments on supervise_on_demand (jit.rs, the site four tickets have recorded). It now reads 9/7 rather than 8/7 because this ticket adds the cgroup handle parameter; same warning, same site, NOT fixed and not counted as mine, and it is hiding nothing — one warning is the whole output. FORMATTING: rustfmt --check is CLEAN on jit.rs and cgroup.rs; I hand-applied my own three hunks with Edit rather than running a blanket fmt. native.rs's eight and microvm.rs's thirty remaining diffs are all pre-existing (native.rs's are R885-F3/B4's recorded list, shifted by 17 lines where fmt_u32 moved out) and were left exactly as found.")
//! @yah:verify("NOT ACHIEVED, stated plainly: NO LIVE NODE READING. This is a macOS dev machine, so the attach itself is proven only by cross-compilation, exactly as R885-B1 was before @Ashguard:coffee read us-east-001. THE LIVE ACCEPTANCE STILL OWED, on a node running these bytes with an on-demand bundle or a tenant-passway deployed: `journalctl -u kamaji -b | grep 'jit backend:'` must show the confining line (its absence or the matching warn! means that node's JIT tier is unconfined); then drive one cold start and read `cat /proc/<serve-pid>/cgroup` — it must end in `/<ident>/<19-digit generation>`, NOT `/yubaba.slice/kamaji.service/native`; and `cat /sys/fs/cgroup/yubaba.slice/kamaji.service/<ident>/memory.max` must be the real number. Note the JIT path is currently UNEXERCISED on the three prod nodes (R885-B9 established the four east workloads all came through deploy_bundle_keepalive), so this needs a deliberate on-demand deploy to exercise rather than just a roll.")
//! @yah:gotcha("FOR R885-B9's CAP-DROP LANDING: the ordering note in kamaji-bin/src/native.rs ('AFTER the cgroup attach') now has a second site with a cgroup attach to hang off. jit.rs's spawn_jit_child registers the attach FIRST and the fd-3 dup2/CLOEXEC hook second (std runs pre_exec closures in registration order), so a capability drop belongs after BOTH — dropping caps before the dup2 is fine today but would break the moment the socket handoff needs a privileged operation. Better still: extend CgroupHandle::attach_at_exec's pattern and give the drop its own shared helper both spawners call, rather than a copy in each file. A drop installed in native.rs alone still leaves every on-demand bundle and tenant-passway fork with kamaji's full ambient set, which is exactly what B9's own gotcha warned about.")
//! @yah:assumes("The attach is unverified AS EXECUTED CODE on the JIT path by me — cross-compiled clean, never run, because the pre_exec hook is Linux-only and this is a Mac. It is the SAME function the native path runs, and that one is verified by outcome (four workload pids in their own leaves on us-east-001, R885-B1), so the confidence transfers to the mechanism but NOT to the JIT call site's plumbing around it.")
//! @yah:assumes("The microVM exclusion rests on mem_size_mib being a real enforced ceiling on the guest rather than a request the VMM may exceed. That is read from the code (microvm.rs:951-952 renders it from guest_memory_mb(cfg, spec), and guest_memory_mb's own doc contrasts it with a cgroup ceiling) and from how firecracker/cloud-hypervisor document machine config — NOT measured against a running VM's RSS. If VMM overhead above the guest's RAM ever turns out to matter on a node, the exclusion is the thing to revisit, and the comment at the site says so.")
//! @yah:handoff("CLOSED AS 'CONFINE', not as an exclusion. The JIT/on-demand tier now puts every forked child in its own cgroup v2 generation leaf through the same CgroupV2/CgroupHandle mechanism the keep-alive tier uses, with the self-attach hook extracted so exactly one copy of it exists. R885's acceptance criterion is no longer true only at the site that was measured.")
//! @yah:verify("Signed off against: the acceptance grep (no unattached, uncommented fork left in oss/kamaji/crates/kamaji/src), three new call-site tests on the real deploy path plus one Linux-only attach test that compiles for x86_64-unknown-linux-gnu, 156/0 on kamaji (baseline 153) and 239/0 on kamaji-bin (baseline 239), and a clean cross-compile. The live-node reading is still owed and is listed in the verify entries above.")
//! @yah:verify("*** THE OWED LIVE-NODE READING IS NOW DISCHARGED FOR THE CGROUP HIERARCHY — AND IT IS R885's OBSERVABLE WIN. *** Measured on us-east-001 2026-09-11 after the R885 hot ship put 0.8.39-h1 on both halves (kamaji pid 650851 -> 661039, all four native children new pids). BEFORE, captured read-only minutes earlier, every workload cgroup was FLAT: /yubaba.slice/kamaji.service/{noisetable,yah-marketing,yah-marketing-revalidate,yah-marketing-feed}. AFTER, every one carries the generation leaf this ticket and R885-B4 built: /yubaba.slice/kamaji.service/yah-marketing/1789161281045010149, .../yah-marketing-revalidate/...46789962, .../noisetable/...47234000, .../yah-marketing-feed/...49657945. The flat form is gone. All four workloads started and serve (100.64.0.3:41507 -> 200/12127b, :34759 -> 200/37298b, :40995 -> 404 as designed for the revalidate tier's allow-list), so the confinement did not cost a workload. TWO CAVEATS, both stated rather than buried. (1) THE JIT PATH IS STILL UNEXERCISED — this ship confirms the NATIVE spawner's attach on a live node; no on-demand bundle or tenant-passway was deployed, so jit::tests::a_cold_start_child_joins_the_generation_leaf remains cross-compiled-but-never-run, exactly as this ticket's verify block already said. That half of the acceptance is still owed and needs a deliberate on-demand deploy, not just a roll. (2) THIS TICKET'S \"TWO JitRuntimes PER NODE\" GOTCHA IS CONTRADICTED BY THE LIVE JOURNAL and I have filed R885-B12 for it rather than quietly correcting the annotation: startup logs three confining lines split `native backend:` x2 and `jit backend:` x1 — the reverse multiplicity — each with its own paired pids-controller line, so three runtimes are constructed. Either tenant_passway's JitRuntime is not constructed on this node while something builds NativeRuntime twice, or a `backend` label is passed wrongly at one of the three sites. R885-B12 carries the evidence, both readings, and the instruction to settle which before editing either the construction or this gotcha.")
//! @yah:gotcha("THE STARTUP-LINE CENSUS, CORRECTED BY R885-B12 (2026-09-11) AFTER A LIVE NODE DISPROVED THE ORIGINAL TEXT. This gotcha used to read \"TWO JitRuntimes EXIST PER NODE AND BOTH LOG THE SAME PREFIX\", telling readers to expect `jit backend: confining workloads...` twice. us-east-001 on kamaji 0.8.39-h1 at 21:14:41Z logs it ONCE and logs `native backend:` TWICE. The true census is FOUR construction sites, of which a fleet node reaches THREE: (1) ServerCtx::native from --native-exec-dir, kamaji-bin/src/main.rs:686, label `native`; (2) BundleBackend::native, kamaji-bin/src/server.rs:635, label `native`; (3) BundleBackend::jit, server.rs:636, label `jit`; (4) ServerCtx::tenant_passway from --tenant-passway-dir, main.rs:717, label `jit` — opt-in, and app/yah/cli/resources/kamaji.service does NOT pass that flag, so no fleet node constructs it. The original error was counting JitRuntime sites, missing the NativeRuntime that BundleBackend::new builds on the line ABOVE the jit one, and assuming site (4) is always present. NOTHING IS DOUBLE-CONSTRUCTED. The lines are now distinguishable rather than merely explained: native::resolve_cgroup_root takes the runtime's state_dir and every line it logs carries `state_dir=`, so (1) reads /var/lib/yah/kamaji/native while (2) and (3) read the bundle state dir. Pinned by server::tests::bundle_serving::the_cgroup_resolving_runtime_census_is_two_native_and_one_jit.")

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::process::Child;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use workload_spec::{EnvValue, MeshIdent, WorkloadSpec};

use crate::native::argv;
use crate::socket_custody::SocketCustodian;
use crate::{MeshAssignment, WorkloadState, WorkloadStatus};

/// The child fd the serve runtime adopts under the socket-activation convention
/// (`SD_LISTEN_FDS_START`). Kept in lockstep with `mesofact-serve`'s
/// `socket_activation_listener`, which reads fd 3.
const LISTEN_FD_CHILD: RawFd = 3;

/// Delay before re-arming after a *fork* failure, so a permanently-broken serve
/// binary can't hot-loop the fork on every arriving connection. A transient
/// failure recovers on the next connection after this pause.
const FORK_FAIL_BACKOFF: Duration = Duration::from_secs(1);

/// How long teardown waits for a live child to exit after SIGTERM before
/// SIGKILL — mirrors the native backend's `TERM_GRACE`.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// Caller-side handle onto one on-demand workload. The supervisor task owns the
/// lifecycle; this is the registry entry.
struct JitHandle {
    mesh_ip: Ipv4Addr,
    /// Port the custodian actually bound and holds for this workload (R844-F2).
    ///
    /// Parsed off `listen_addr` rather than read from the spec, because on this
    /// tier the custodian's socket *is* the workload's listener: it outlives
    /// every forked child, so the held socket's port is the resolved port by
    /// definition and cannot drift from what a child was told to expect.
    ports: std::collections::BTreeMap<String, u16>,
    /// pid of the currently-live serve child, or `0` when idle (no resident
    /// process — the whole point of the on-demand tier).
    pid: Arc<AtomicU32>,
    status: watch::Receiver<WorkloadStatus>,
    /// This deploy's cgroup pair — workload node plus generation leaf (R885-B10)
    /// — or `None` on a host with no delegated subtree, where children fork
    /// unbounded as they did before that ticket. Held for the whole deploy, not
    /// per cold start: see the module doc.
    cgroup: Option<crate::cgroup::CgroupHandle>,
    /// Flip to `true` to tear the workload down: the supervisor stops any live
    /// child and exits.
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

/// On-demand (JIT) runtime. One instance supervises any number of on-demand
/// workloads; it is the custodian of each one's listen socket.
pub struct JitRuntime {
    /// Owns the held listen sockets (R599-F9). Shared so the supervisor tasks
    /// and the teardown path see the same custody map.
    custodian: Arc<SocketCustodian>,
    state_dir: PathBuf,
    workloads: Mutex<HashMap<String, JitHandle>>,
    /// The cgroup subtree systemd delegated to kamaji, when this host has one
    /// (R885-B10). `None` on macOS, on a cgroup-v1 host, inside a cgroup
    /// namespace, or wherever the root is not ours to write — every one of which
    /// means "fork as before, unbounded".
    cgroup: Option<crate::cgroup::CgroupV2>,
    /// This node's local `yah-scryer` ingestion socket, when one is configured
    /// (R893-B17). A JIT child is forked into the host's mount namespace
    /// exactly as a native one is, so it gets the identical contract — a
    /// workload must not learn whether it is traced from which tier happened to
    /// start it.
    collector: crate::observe::Collector,
}

impl JitRuntime {
    /// `state_dir` holds each workload's stdout/stderr capture (per fork,
    /// appended so re-fork history is preserved), same as the native backend.
    ///
    /// Resolving the cgroup root happens here rather than at first deploy for
    /// the same reason it does in [`crate::native::NativeRuntime::new`]: the
    /// `warn!` for a host that cannot confine anything belongs at startup, next
    /// to the other backend-availability lines, not inside the first cold start
    /// that silently ran without a ceiling.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        let state_dir = state_dir.into();
        Self {
            custodian: Arc::new(SocketCustodian::new()),
            workloads: Mutex::new(HashMap::new()),
            cgroup: crate::native::resolve_cgroup_root("jit", &state_dir),
            collector: crate::observe::Collector::disabled(),
            state_dir,
        }
    }

    /// Point this backend's on-demand workloads at the node's local collector
    /// (R893-B17). The twin of
    /// [`crate::native::NativeRuntime::with_collector`]; both must be set from
    /// the same node config or a workload's telemetry would depend on which
    /// tier forked it.
    pub fn with_collector(mut self, collector: crate::observe::Collector) -> Self {
        self.collector = collector;
        self
    }

    /// Where this runtime stages each on-demand workload's capture files — and,
    /// because one runtime owns exactly one, this runtime's identity (R885-B12).
    ///
    /// The counterpart of [`crate::native::NativeRuntime::exec_dir`], and it
    /// exists for the same reason the startup line now carries `state_dir=`: a
    /// node runs more than one `JitRuntime`-shaped or `NativeRuntime`-shaped
    /// backend, so "which jit backend" is only answerable by the directory it
    /// was handed.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Same as [`JitRuntime::new`], but with the cgroup root pointed at an
    /// explicit directory instead of resolved from `/proc/self/cgroup`.
    ///
    /// Test-only, and it exists for the reason R885-B1's first gotcha gives:
    /// what has to be pinned is the **call site** — that the real
    /// `deploy_on_demand` mints a leaf and `teardown_workload` reaps it — not
    /// the driver, which `cgroup.rs` already tests. Pointing the live path at a
    /// tempdir is what lets that run on the camp Mac as well as on a node.
    #[cfg(test)]
    fn with_cgroup_root(state_dir: impl Into<PathBuf>, cgroup_root: impl Into<PathBuf>) -> Self {
        let mut rt = Self::new(state_dir);
        rt.cgroup = Some(crate::cgroup::CgroupV2::new(cgroup_root));
        rt
    }

    /// Deploy an on-demand workload. kamaji binds+holds `listen_addr` in the host
    /// netns, then arms the poll-fork-rearm loop.
    /// **No serve process is spawned** — the first fork happens on the first
    /// connection.
    ///
    /// `spec` supplies the fork argv (entrypoint ++ command) and literal env; the
    /// serve binary is expected to self-reap on idle (its argv should carry
    /// `--idle-ttl <secs>`). `listen_addr` is the `host:port` kamaji binds and
    /// the address the workload serves on — it must match the serve process's
    /// notion of its listen address so upstream/passway records never change.
    ///
    /// Idempotent: a prior workload with the same identity is torn down first.
    pub async fn deploy_on_demand(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
        listen_addr: &str,
    ) -> Result<()> {
        // Validate argv eagerly so a misconfigured spec fails the deploy rather
        // than the first connection's fork.
        let _ = argv(spec)?;
        let ident = spec.expose.mesh.identity.clone();

        // Idempotent redeploy: drop any predecessor (stops its supervisor +
        // releases its held socket) before binding fresh.
        self.teardown_workload(&ident).await?;

        // Bind + hold the listen socket in the HOST netns. This is what outlives
        // every forked child. A JIT workload is a plain forked host process, so
        // the host namespace is the one it actually runs in; the only per-workload
        // namespace this tree creates belongs to `container_net` on the container
        // deploy path, and it is named there by the site that creates it
        // (R895-F1). If a JIT workload ever needs one, that creator threads the
        // path in — this function must not derive a name for a namespace nobody
        // made.
        self.custodian
            .bind_and_hold(&ident.0, listen_addr, None)
            .with_context(|| {
                format!(
                    "binding on-demand listen socket {listen_addr} for {}",
                    ident.0
                )
            })?;

        // The single held listener fd we poll + hand to each child.
        let listen_fd = self
            .custodian
            .held_raw_fds(&ident.0)
            .and_then(|fds| fds.into_iter().next())
            .ok_or_else(|| anyhow!("custodian holds no fd for {} after bind_and_hold", ident.0))?;

        // The one resolved set for this workload: what `list_workloads` reports
        // and what the forked child reads as `PORT` (R844-T13) are the same map,
        // built once here, so a JIT workload's own idea of its port cannot differ
        // from the one kamaji publishes.
        let ports = crate::name_anonymous_ports(
            &listen_addr
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .into_iter()
                .collect::<Vec<_>>(),
        );

        // R885-B10: mint the workload node + this deploy's generation leaf before
        // the supervisor can fork anything into it. Minted here rather than at
        // the first cold start so a host that cannot confine the workload says
        // so at deploy time — and, as in `native`, a failure fails the deploy:
        // this runtime already decided at startup whether the host can confine
        // anything, so a failure now means the subtree it verified has changed
        // underneath us. Last fallible step before the supervisor starts, so a
        // deploy that fails later cannot leave a cgroup behind.
        let cgroup = self
            .cgroup
            .as_ref()
            .map(|cg| cg.create_workload(&ident.0, &crate::cgroup::WorkloadLimits::from_spec(spec)))
            .transpose()
            .with_context(|| {
                format!(
                    "creating the cgroup leaf for on-demand workload {}",
                    spec.name
                )
            })?;

        let pid = Arc::new(AtomicU32::new(0));
        let (status_tx, status_rx) = watch::channel(WorkloadStatus::Pending);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(supervise_on_demand(
            self.state_dir.clone(),
            spec.clone(),
            mesh.mesh_ip,
            listen_fd,
            ports.clone(),
            cgroup.clone(),
            self.collector.clone(),
            Arc::clone(&pid),
            status_tx,
            shutdown_rx,
        ));

        self.workloads.lock().await.insert(
            ident.0.clone(),
            JitHandle {
                mesh_ip: mesh.mesh_ip,
                ports,
                pid,
                status: status_rx,
                cgroup,
                shutdown: shutdown_tx,
                task,
            },
        );
        Ok(())
    }

    /// Snapshot every on-demand workload. `Pending` (pid `0`) is the idle,
    /// zero-resident state; `Running` means a serve child is currently live.
    pub async fn list_workloads(&self) -> Vec<WorkloadState> {
        let map = self.workloads.lock().await;
        map.iter()
            .map(|(ident, h)| WorkloadState {
                ident: MeshIdent(ident.clone()),
                container_id: format!("jit-{}", h.pid.load(Ordering::SeqCst)),
                status: h.status.borrow().clone(),
                mesh_ip: Some(h.mesh_ip),
                ports: h.ports.clone(),
            })
            .collect()
    }

    /// Snapshot one on-demand workload by identity.
    pub async fn get_workload(&self, ident: &MeshIdent) -> Option<WorkloadState> {
        let map = self.workloads.lock().await;
        map.get(&ident.0).map(|h| WorkloadState {
            ident: ident.clone(),
            container_id: format!("jit-{}", h.pid.load(Ordering::SeqCst)),
            status: h.status.borrow().clone(),
            mesh_ip: Some(h.mesh_ip),
            ports: h.ports.clone(),
        })
    }

    /// True if this runtime supervises an on-demand workload with `ident`.
    pub async fn holds(&self, ident: &MeshIdent) -> bool {
        self.workloads.lock().await.contains_key(&ident.0)
    }

    /// Tear an on-demand workload down: stop the supervisor (which kills any live
    /// child), then release the held listen socket. Idempotent.
    pub async fn teardown_workload(&self, ident: &MeshIdent) -> Result<()> {
        let handle = self.workloads.lock().await.remove(&ident.0);
        let had_cgroup = handle.as_ref().is_some_and(|h| h.cgroup.is_some());
        if let Some(handle) = handle {
            // Signal shutdown and wait for the supervisor to stop the child and
            // exit before we close the socket out from under it.
            let _ = handle.shutdown.send(true);
            let _ = handle.task.await;
        }
        // Close the held listener (safe now that the supervisor has stopped
        // polling / handing off the fd). Idempotent if never bound.
        self.custodian.release(&ident.0);
        // R885-B10, in R885-B4's order: `cgroup.kill` (or a freeze + `SIGKILL`
        // sweep on a pre-5.14 kernel) reaches whatever the serve child forked
        // away from the supervisor, then a bounded drain, then the final counter
        // read, then the `rmdir`. A failure is logged and stepped over rather
        // than propagated — teardown's contract here is idempotent success, and
        // a leaked directory is strictly better than a teardown the caller reads
        // as "the workload is still up".
        if let (Some(cg), true) = (self.cgroup.as_ref(), had_cgroup) {
            match cg.destroy_workload(&ident.0) {
                Ok(outcome) if outcome.leaked.is_empty() => tracing::debug!(
                    workload = %ident.0,
                    generations = outcome.removed,
                    kill = ?outcome.method,
                    telemetry = %crate::native::format_stats(&outcome.stats),
                    "jit backend: workload cgroup torn down"
                ),
                Ok(outcome) => tracing::warn!(
                    workload = %ident.0,
                    leaked = ?outcome.leaked,
                    kill = ?outcome.method,
                    telemetry = %crate::native::format_stats(&outcome.stats),
                    "jit backend: a workload cgroup generation could not be emptied — it and the \
                     ceiling above it are left in place so whatever survived stays bounded \
                     (R885-B4)"
                ),
                Err(e) => tracing::warn!(
                    workload = %ident.0,
                    error = %e,
                    "jit backend: could not tear down the workload's cgroup (R885-B10)"
                ),
            }
        }
        Ok(())
    }
}

/// A borrowed listener fd for readiness polling. Wraps a [`RawFd`] the custodian
/// owns; dropping it does **not** close the fd (no `Drop`), so an [`AsyncFd`]
/// built over it can be dropped each cycle to deregister from the reactor while
/// the custodian keeps the socket alive.
struct BorrowedListenFd(RawFd);

impl AsRawFd for BorrowedListenFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Await a pending connection on `listen_fd` **without accepting it** (the child
/// accepts). A fresh [`AsyncFd`] registration is created and dropped per call so
/// the reactor always reports the socket's *current* readability.
async fn wait_for_connection(listen_fd: RawFd) -> Result<()> {
    let afd = AsyncFd::with_interest(BorrowedListenFd(listen_fd), Interest::READABLE)
        .context("registering on-demand listener with the reactor")?;
    // Readiness only — we never read/accept; the forked child owns the accept.
    let _guard = afd
        .readable()
        .await
        .context("awaiting listener readability")?;
    Ok(())
    // `afd` dropped here → deregistered; the fd stays open (custodian owns it).
}

/// Per-workload on-demand supervisor: arm → fork-on-connection → wait → re-arm,
/// until torn down. Never accepts; forks the serve runtime and hands it the held
/// listener fd via socket activation.
///
/// Long argument list by construction: every one of these is per-deploy state a
/// detached supervisor task must own outright, and bundling them into a struct
/// would name a type whose only member function is this loop.
#[allow(clippy::too_many_arguments)]
async fn supervise_on_demand(
    state_dir: PathBuf,
    spec: WorkloadSpec,
    mesh_ip: Ipv4Addr,
    listen_fd: RawFd,
    ports: std::collections::BTreeMap<String, u16>,
    cgroup: Option<crate::cgroup::CgroupHandle>,
    collector: crate::observe::Collector,
    pid: Arc<AtomicU32>,
    status_tx: watch::Sender<WorkloadStatus>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        // ── IDLE: zero resident process. Arm the readable-watch; wake on a
        //    pending connection or a teardown.
        pid.store(0, Ordering::SeqCst);
        let _ = status_tx.send(WorkloadStatus::Pending);

        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() { return; }
            }
            r = wait_for_connection(listen_fd) => {
                if let Err(e) = r {
                    // Reactor registration failed — surface it and pause before
                    // retrying so we don't spin on a broken fd.
                    tracing::warn!(
                        workload = %spec.name,
                        error = %format!("{e:#}"),
                        "on-demand readable-watch failed; re-arming after backoff"
                    );
                    let _ = status_tx.send(WorkloadStatus::Failed {
                        oom_killed: false,
                        reason: format!("on-demand readable-watch failed: {e:#}"),
                    });
                    if backoff_or_shutdown(&mut shutdown, FORK_FAIL_BACKOFF).await {
                        return;
                    }
                    continue;
                }
            }
        }
        if *shutdown.borrow() {
            return;
        }

        // ── FORK: a connection is pending; spawn the serve runtime and hand it
        //    the held socket (LISTEN_FDS socket activation). The child accepts.
        // Every cold start attaches into the SAME generation leaf this deploy
        // minted — see the module doc's "one generation per deploy, not per
        // fork".
        let mut child = match spawn_jit_child(
            &state_dir,
            &spec,
            mesh_ip,
            listen_fd,
            &ports,
            cgroup.as_ref(),
            &collector,
        ) {
            Ok(c) => c,
            Err(e) => {
                // Logged, not only published: WorkloadStatus flattens to a bare
                // "Failed" on the wire, so an unlogged fork failure is a held
                // socket that silently never serves (R910-F2: an EROFS state dir
                // on us-west-011 looked exactly like a hung TLS handshake).
                tracing::warn!(
                    workload = %spec.name,
                    error = %format!("{e:#}"),
                    "on-demand fork failed; re-arming after backoff"
                );
                let _ = status_tx.send(WorkloadStatus::Failed {
                    oom_killed: false,
                    reason: format!("on-demand fork failed: {e:#}"),
                });
                // Broken serve bin: back off before re-arming so a fixed failure
                // doesn't hot-loop forks on a hammered port.
                if backoff_or_shutdown(&mut shutdown, FORK_FAIL_BACKOFF).await {
                    return;
                }
                continue;
            }
        };
        pid.store(child.pid, Ordering::SeqCst);
        let _ = status_tx.send(WorkloadStatus::Running);

        // ── SERVE + REAP: the child accepts on the inherited fd and self-reaps
        //    after its --idle-ttl with zero in-flight requests. Wait for it; a
        //    teardown mid-serve stops it. On exit we loop and re-arm — the socket
        //    is NOT released, so a connection arriving during/after the reap is
        //    queued in the kernel and served by the next fork (zero-dropped).
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    stop_child(&mut child.child, child.pid).await;
                    return;
                }
            }
            _ = child.child.wait() => {
                // Reaped (idle) or crashed — either way re-arm the watch.
            }
        }
    }
}

/// Sleep for `backoff`, or return `true` immediately if a teardown arrives
/// first. `true` ⇒ the caller should exit the supervisor.
async fn backoff_or_shutdown(shutdown: &mut watch::Receiver<bool>, backoff: Duration) -> bool {
    tokio::select! {
        biased;
        _ = shutdown.changed() => *shutdown.borrow(),
        _ = tokio::time::sleep(backoff) => false,
    }
}

/// A forked serve child under the JIT lifecycle.
struct JitChild {
    child: Child,
    pid: u32,
}

/// Fork the serve runtime for an on-demand connection, passing the custodian's
/// held listener as the child's fd 3 (socket activation). The argv/env come from
/// `spec` (same shape the native backend forks), plus `LISTEN_FDS=1`, the
/// `YAH_MESH_IP` injection, the `PORT` / `PORT_<NAME>` set (R844-T13) and the
/// `YAH_SERVICE_IDENT` / `YAH_SCRYER_SOCKET` collector contract (R893-B17).
///
/// `ports` is the custodian's *held* address, not a declared number — the child
/// adopts fd 3 rather than binding, so this is telling it which port it is
/// already serving on. It still needs to know: a serve runtime renders absolute
/// URLs and reports its own address, and a JIT workload that had to infer that
/// from the spec would be the one tier reading a different fact.
///
/// The child's argv is expected to carry `--idle-ttl <secs>` so the runtime
/// self-reaps; kamaji does not own idle detection.
///
/// `cgroup` is this deploy's generation leaf (R885-B10); `None` means the host
/// has no delegated subtree and the child forks unbounded, exactly as every
/// on-demand fork did before that ticket.
fn spawn_jit_child(
    state_dir: &Path,
    spec: &WorkloadSpec,
    mesh_ip: Ipv4Addr,
    listen_fd: RawFd,
    ports: &std::collections::BTreeMap<String, u16>,
    cgroup: Option<&crate::cgroup::CgroupHandle>,
    collector: &crate::observe::Collector,
) -> Result<JitChild> {
    let ident = &spec.expose.mesh.identity;
    let argv = argv(spec)?;

    // Per-workload log capture, appended across forks (each on-demand fork is a
    // fresh serve; keeping history mirrors the native backend's respawn append).
    let dir = state_dir.join(&ident.0);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating state dir {}", dir.display()))?;
    let open = |name: &str| -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(name))
    };
    let stdout_file =
        open("stdout.log").with_context(|| format!("opening {}/stdout.log", dir.display()))?;
    let stderr_file =
        open("stderr.log").with_context(|| format!("opening {}/stderr.log", dir.display()))?;

    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .env("YAH_MESH_IP", mesh_ip.to_string())
        // systemd socket-activation: the serve runtime adopts fd 3 as its
        // listener. We deliberately do NOT set LISTEN_PID — the serve binary
        // adopts fd 3 whenever LISTEN_PID is unset, and setting it to the child's
        // own pid would require an async-signal-unsafe setenv in the pre_exec
        // hook (the child's pid isn't known before fork). See
        // mesofact-serve::socket_activation_listener.
        .env("LISTEN_FDS", "1")
        .kill_on_drop(false);
    if let Some(workdir) = &spec.workdir {
        cmd.current_dir(workdir);
    }
    for (k, v) in crate::ports::port_env(ports) {
        cmd.env(k, v);
    }
    // R893-B17 — same host-namespace contract the native backend forks with.
    for (k, v) in collector.env_for(spec, crate::observe::MountNs::Host) {
        cmd.env(k, v);
    }
    for e in &spec.env {
        if let EnvValue::Literal { value } = &e.value {
            cmd.env(&e.name, value);
        }
    }

    // R885-B10 — the boundary, registered FIRST so the child is inside its
    // ceiling before it is handed anything. Both hooks run post-fork/pre-exec in
    // registration order, so no workload code runs either way; ordering it first
    // keeps the confinement ahead of the socket handoff rather than behind it.
    // Same hook the keep-alive tier uses — see `CgroupHandle::attach_at_exec`.
    #[cfg(target_os = "linux")]
    if let Some(handle) = cgroup {
        handle.attach_at_exec(cmd.as_std_mut()).with_context(|| {
            format!(
                "installing the cgroup self-attach hook for on-demand workload {}",
                spec.name
            )
        })?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cgroup;

    // Hand the held listener to the child as fd 3 and clear its close-on-exec so
    // it survives the exec. The custodian's fd is CLOEXEC (Rust sets it on every
    // socket it creates), so it would otherwise close on exec — dup2 onto a fresh
    // fd number clears CLOEXEC on the duplicate.
    //
    // SAFETY: the pre_exec closure runs post-fork/pre-exec in the child and calls
    // only async-signal-safe libc primitives (dup2, fcntl). `listen_fd` is valid
    // in the child because fork copies the parent's fd table.
    unsafe {
        cmd.as_std_mut().pre_exec(move || {
            // dup2 only when the held fd isn't already at the target slot; the
            // short-circuit keeps the "skip when equal" guard.
            if listen_fd != LISTEN_FD_CHILD && libc::dup2(listen_fd, LISTEN_FD_CHILD) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Clear FD_CLOEXEC on fd 3 (explicit — covers the listen_fd == 3 case
            // where dup2 is a no-op and does not clear the flag).
            let flags = libc::fcntl(LISTEN_FD_CHILD, libc::F_GETFD);
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(LISTEN_FD_CHILD, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    // R885-B11 — the filesystem boundary, registered between the fd-3 handoff
    // and the capability drop: the handoff's `dup2`/`fcntl` touch no path, but
    // keeping the confinement ahead of the drop matches kamaji-bin's
    // `pre_exec_in_child` order, in which landlock precedes every privilege
    // change. Confines only a spec that describes its writes — an on-demand
    // bundle server declares none today and so runs unconfined, exactly as the
    // rule says it should.
    #[cfg(target_os = "linux")]
    crate::sandbox::confine_fs_at_exec(spec, &dir, cmd.as_std_mut()).with_context(|| {
        format!(
            "installing the filesystem-confinement hook for on-demand workload {}",
            spec.name
        )
    })?;

    // R885-B9 — the capability boundary, the same helper the keep-alive tier
    // uses (`kamaji::sandbox::drop_caps_at_exec`). Registered LAST on purpose:
    // `std` runs pre_exec closures in registration order, and both the cgroup
    // self-attach above and the fd-3 handoff immediately above it need
    // privileges this drop takes away. An on-demand fork needs no capability of
    // its own to serve — kamaji binds the listener and hands it over as fd 3 —
    // but the drop is derived from the spec here exactly as it is on the native
    // path, so the two tiers cannot answer the question differently.
    #[cfg(target_os = "linux")]
    crate::sandbox::drop_caps_at_exec(spec, cmd.as_std_mut()).with_context(|| {
        format!(
            "installing the capability-drop hook for on-demand workload {}",
            spec.name
        )
    })?;

    let child = cmd
        .spawn()
        .with_context(|| format!("forking {} for on-demand workload {}", argv[0], spec.name))?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow!("on-demand child for {} exited before pid read", spec.name))?;
    Ok(JitChild { child, pid })
}

/// SIGTERM → grace → SIGKILL, mirroring the native backend's teardown.
async fn stop_child(child: &mut Child, pid: u32) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    // SAFETY: plain kill(2) on a pid we forked and still hold the Child for;
    // ESRCH (already exited) is benign and ignored.
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
    if tokio::time::timeout(TERM_GRACE, child.wait())
        .await
        .is_err()
    {
        let _ = child.start_kill();
        let _ = child.wait().await;
    }
}

// ── R885-B10: the CALL SITE, which is the whole point of the ticket ──────────
//
// `cgroup.rs` already tests the driver, and R885-B1's first gotcha is why that
// is not enough: R406-T4/T5 sat in review for two months with green driver
// tests and no running binary able to reach them. These drive the real
// `deploy_on_demand` / `teardown_workload` path against a tempdir cgroup root,
// so they run on the camp Mac as well as on a node.

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        ExposeSpec, ImageRef, MeshExpose, Millis, NamespaceId, ResourceLimits, RestartPolicy,
        StopPolicy, TenantId, TierTag,
    };

    /// A spec in the shape the on-demand tier actually receives: an entrypoint
    /// (the serve binary), a mesh identity, and the resource limits that become
    /// the cgroup's ceiling. 64 MiB / 128 millicores, like `native_spec`.
    fn jit_spec(name: &str, entrypoint: Vec<String>) -> WorkloadSpec {
        WorkloadSpec {
            name: name.to_string(),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            image: ImageRef {
                registry: "bundle".to_string(),
                repository: format!("mesofact/{name}"),
                tag: "serve".to_string(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".to_string()),
            replicas: 1,
            command: None,
            entrypoint: Some(entrypoint),
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

    /// The generation directories under a workload node, oldest first — the
    /// same reading `native::tests::generations` takes.
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

    /// Deploying an on-demand workload mints its cgroup **at deploy**, not at
    /// the first cold start — the node carrying the ceiling and one generation
    /// leaf beneath it (R885-B4's hierarchy, not a flat leaf) — and tearing it
    /// down reaps the generation.
    #[tokio::test]
    async fn deploying_on_demand_mints_a_cgroup_leaf_carrying_its_limits() {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup_root = tmp.path().join("cgroup-root");
        let runtime = JitRuntime::with_cgroup_root(tmp.path().join("state"), &cgroup_root);
        let spec = jit_spec("jit-cgroup", vec!["/bin/sh".into()]);
        let ident = spec.expose.mesh.identity.clone();
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

        runtime
            .deploy_on_demand(&spec, &mesh, "127.0.0.1:0")
            .await
            .unwrap();

        // The ceiling is on the NODE. Reading it off the generation leaf would
        // be the R885-B4 mistake this asserts against.
        let node = cgroup_root.join("jit-cgroup");
        assert!(node.is_dir(), "deploy did not create {}", node.display());
        assert_eq!(
            std::fs::read_to_string(node.join("memory.max")).unwrap(),
            (64u64 * 1024 * 1024).to_string()
        );
        // 128m is a REQUEST (R885-B5): a weight, never a quota.
        assert_eq!(
            std::fs::read_to_string(node.join("cpu.weight")).unwrap(),
            "12"
        );
        assert!(
            !node.join("cpu.max").exists(),
            "a spec with no yah.limits.cpu-millis must leave cpu.max unwritten"
        );

        // ...and the processes go one level down, in this deploy's generation.
        let gens = generations(&node);
        assert_eq!(
            gens.len(),
            1,
            "expected exactly one generation, got {gens:?}"
        );
        assert!(
            node.join(&gens[0]).is_dir(),
            "the generation leaf is where a cold start attaches"
        );

        runtime.teardown_workload(&ident).await.unwrap();
        assert!(
            generations(&node).is_empty(),
            "teardown left a generation behind: {:?}",
            generations(&node)
        );
    }

    /// The degrade path, and it asserts its own premise so it cannot pass
    /// vacuously: on a host with no delegated subtree the on-demand tier still
    /// deploys and still tears down — it just forks unbounded, exactly as it
    /// did before R885-B10. A regression here is the one way this ticket could
    /// make things worse than the hole it closed.
    #[tokio::test]
    async fn a_host_without_a_delegated_subtree_still_deploys_on_demand() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = JitRuntime::new(tmp.path());
        assert!(
            runtime.cgroup.is_none(),
            "the camp Mac has no delegated cgroup subtree; this test's premise is gone"
        );
        let spec = jit_spec("jit-uncgrouped", vec!["/bin/sh".into()]);
        let ident = spec.expose.mesh.identity.clone();
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

        runtime
            .deploy_on_demand(&spec, &mesh, "127.0.0.1:0")
            .await
            .unwrap();
        assert!(runtime.holds(&ident).await);
        runtime.teardown_workload(&ident).await.unwrap();
    }

    /// A redeploy of the same identity gets its OWN generation rather than
    /// reusing the predecessor's directory (R885-B4's race), driven through the
    /// real on-demand deploy path rather than through the driver.
    #[tokio::test]
    async fn a_redeploy_on_demand_mints_a_new_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup_root = tmp.path().join("cgroup-root");
        let runtime = JitRuntime::with_cgroup_root(tmp.path().join("state"), &cgroup_root);
        let spec = jit_spec("jit-rolling", vec!["/bin/sh".into()]);
        let ident = spec.expose.mesh.identity.clone();
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
        let node = cgroup_root.join("jit-rolling");

        runtime
            .deploy_on_demand(&spec, &mesh, "127.0.0.1:0")
            .await
            .unwrap();
        let first = generations(&node);
        assert_eq!(first.len(), 1);

        runtime
            .deploy_on_demand(&spec, &mesh, "127.0.0.1:0")
            .await
            .unwrap();
        let second = generations(&node);
        assert_eq!(
            second.len(),
            1,
            "the predecessor's generation must be reaped, not accumulated: {second:?}"
        );
        assert_ne!(
            first[0], second[0],
            "an incoming generation must never land in the outgoing one's directory"
        );
        // The ceiling belongs to the WORKLOAD and survives the replacement.
        assert_eq!(
            std::fs::read_to_string(node.join("memory.max")).unwrap(),
            (64u64 * 1024 * 1024).to_string()
        );

        runtime.teardown_workload(&ident).await.unwrap();
    }

    /// THE LINUX HALF: a real cold start's child lands in the generation leaf.
    ///
    /// Everything above pins that the leaf is minted and reaped; only this pins
    /// that a forked child actually *joins* it, which is the property the
    /// ticket exists for. It needs the `pre_exec` hook, so it is Linux-only —
    /// on the camp Mac the hook is `cfg`-ed out and there is nothing to assert.
    /// `cgroup.procs` is pre-created because a tempdir is not a cgroupfs and
    /// the hook opens without `O_CREAT`; on a node the kernel provides it.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_cold_start_child_joins_the_generation_leaf() {
        let tmp = tempfile::tempdir().unwrap();
        let cgroup_root = tmp.path().join("cgroup-root");
        let runtime = JitRuntime::with_cgroup_root(tmp.path().join("state"), &cgroup_root);
        // `sleep` so the child is still alive when we read the leaf.
        let spec = jit_spec("jit-attach", vec!["/bin/sleep".into(), "30".into()]);
        let ident = spec.expose.mesh.identity.clone();
        let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));

        // A real listener on a real port, so a connect() can trigger the fork.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        runtime
            .deploy_on_demand(&spec, &mesh, &addr.to_string())
            .await
            .unwrap();

        let node = cgroup_root.join("jit-attach");
        let gen = generations(&node).pop().expect("a generation leaf");
        let procs = node.join(&gen).join("cgroup.procs");
        std::fs::write(&procs, "").unwrap();

        // Trigger the cold start. Nobody accepts — the connection sits in the
        // kernel queue, which is exactly the tier's contract.
        let _conn = std::net::TcpStream::connect(addr).unwrap();

        let mut child_pid = 0;
        for _ in 0..100 {
            child_pid = runtime
                .get_workload(&ident)
                .await
                .map(|w| w.container_id)
                .and_then(|id| id.trim_start_matches("jit-").parse::<u32>().ok())
                .unwrap_or(0);
            if child_pid != 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_ne!(child_pid, 0, "no cold start inside 5s");

        let written = std::fs::read_to_string(&procs).unwrap();
        assert_eq!(
            written.trim(),
            child_pid.to_string(),
            "the forked child did not write its own pid into {}",
            procs.display()
        );

        runtime.teardown_workload(&ident).await.unwrap();
    }
}

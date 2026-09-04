//! Listen-port allocation — the one contract both supervisors answer through
//! (R844-F2 / W267).
//!
//! ## Why this exists
//!
//! Before this module, a workload's listen port was a *pin written by a human*
//! in a mirror file (`[providers.bundle] port = 8080`) and, when absent, a
//! node-wide fallback baked into kamaji's own process environment
//! (`KAMAJI_BUNDLE_PORT`, else 8080). Both are the same mistake wearing two
//! hats: a well-known port is a single node-wide slot, so exactly one bundle
//! could be served per node, and a second tenant landing on the same node
//! collided with the first. Co-tenancy — two bundles on one node, neither one
//! naming a port — is what this module is for.
//!
//! ## Two supervisors, one contract
//!
//! yah starts workloads through two different supervisors and both have to
//! answer "what port did it actually get?" the same way, or a service that runs
//! both locally and remotely learns its port from two mechanisms that can
//! disagree:
//!
//! - **Local tier** — the camp / desktop path (`cloud`'s `mesofact-static`
//!   reconciler spawning `mesofact-dev` on loopback). Ports here are
//!   disposable: the operator reaches the workload through a browser handle the
//!   reconciler prints, nothing persists across a camp restart, and a fresh
//!   port each run is fine. [`EphemeralPorts`].
//! - **Remote tier** — kamaji on a fleet node. Ports here are *published*: the
//!   resolved port flows back to yubaba, lands in a service record, and is
//!   rendered into an ingress upstream. A port that silently moves on restart
//!   leaves that upstream naming a dead port. [`LedgerPorts`].
//!
//! The difference between the two is whether the number is *published* — which
//! is exactly why they are two implementations of one trait rather than two
//! code paths. Everything else about them follows from that one fact: whether
//! the answer persists, and (R844-F14, below) whether a pin is an error or a
//! preference.
//!
//! ## Names, not numbers (R844-F14)
//!
//! A workload declares port *names* — `["http", "wss", "metrics"]` — and the
//! allocator picks every number. [`PortAllocator::resolve_set`] takes
//! `&[PortSpec]` and hands back `name -> port`, so a two-listener workload is
//! the ordinary case rather than a second mechanism, and the single-listener
//! case is a one-element set named [`HTTP`] with no special path through the
//! allocator.
//!
//! This deliberately reverses R844-F2's "declared always wins" (operator
//! decision, 2026-09-03): *always automatic* and *an honoured operator-written
//! number* are mutually exclusive, and picking both is how a stale pin from one
//! service silently lands on the port a co-tenant already holds. A
//! [`PortSpec::pin`] is therefore accepted only where the number is fixed by
//! the outside world — [`WORLD_FIXED_PORTS`], the 80/443 a browser dials by URL
//! scheme and passway must own — and is otherwise an **error naming the port**,
//! so a stale pin fails loudly at bring-up instead of colliding.
//!
//! The rule bites where a number is *published*, which is the same axis the two
//! implementations already split on:
//!
//! - [`LedgerPorts`] (remote tier) **rejects** a non-world-fixed pin. Its
//!   numbers reach a service record and an ingress upstream, so honouring one
//!   is how a wrong number gets published.
//! - [`EphemeralPorts`] (local tier) treats a pin as a *preference*: honoured
//!   when free, floated to an OS-assigned port when taken. Nothing publishes a
//!   camp port — it is a browser handle the operator typed (`localhost:4321`),
//!   and it cannot collide with a co-tenant because it yields.
//!
//! ## Stability across restart
//!
//! [`LedgerPorts`] persists `(ident, name) -> port` to a JSON file beside the
//! supervisor's other state. On restart, a workload that already has a ledger
//! entry gets its old port back if it is still bindable — per *port*, not just
//! per workload, so a two-listener workload comes back on both. That is what a
//! `keep-alive` workload needs: the rendered ingress upstream keeps pointing at
//! a live listener across a `systemctl restart kamaji`.
//!
//! `on-demand` (JIT) workloads need the same answer for a different reason:
//! kamaji itself is the socket custodian there, so the port cannot move while
//! kamaji lives, and the ledger is what keeps it from moving when kamaji does
//! not. Neither lifecycle reallocates on wake, so an ingress renderer never has
//! to re-resolve mid-flight — but the 15s service-record sweep carries the
//! resolved port on *every* pass anyway, so if a port ever does move (ledger
//! lost, old port taken by something else) the record is corrected rather than
//! left advertising a dead one.
//!
//! ## Telling the workload (R844-T13)
//!
//! A workload that does not write its own port number has to be *told* the one
//! it got, and before this there were three spellings of that single fact:
//! `KAMAJI_BUNDLE_PORT` (node-wide, so two co-tenants could not disagree about
//! it even in principle), `MF_PORT` (miniflare only), and a bare `PORT` one camp
//! spawn path wrote for itself. A service running both locally and on a fleet
//! node therefore learned its port from two mechanisms that could differ.
//!
//! [`port_env`] is the one answer, built from a resolved set and injected by
//! every spawn path — kamaji's native, JIT, containerd and docker backends, and
//! `cloud`'s `local-process` / `mesofact-static` / pond reconcilers.
//! `PORT_<NAME>` per named port, plus bare [`PORT_ENV`] aliasing the port named
//! [`HTTP`] so the single-listener case (most of them, and what `mesofact new`
//! scaffolds) stays a one-variable read.
//!
//! ## What this module deliberately does not do
//!
//! It does not ask yubaba where the ingress expects to connect. The operator
//! shape allowed for "possibly with a config query to yubaba", and the
//! measurement says it is not needed: the ingress renderer reads the port off
//! the service record, and the service record is written from the resolved port
//! this module hands back. A query in the other direction would be a second
//! source of truth for the same fact.
//!
//! @yah:ticket(R844-T13, "One env contract for 'what port did I get' — retire KAMAJI_BUNDLE_PORT, MF_PORT and bare PORT as three spellings of one fact")
//! @yah:status(review)
//! @yah:at(2026-09-03T23:04:32Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R844)
//! @yah:next("Three spellings exist today for the same question: `KAMAJI_BUNDLE_PORT` (kamaji-bin/src/main.rs:81, server.rs:460), `MF_PORT` (oss/yubaba/crates/cloud/src/reconciler/pond.rs:894), and bare `PORT` (app/yah/cli/src/camp.rs:7141). An app that runs both locally and on a fleet node learns its port from two mechanisms that can disagree.")
//! @yah:next("Settle on `PORT_<NAME>` per named port (uppercased, non-alnum to underscore), plus `PORT` aliased to the port named `http` so the trivial single-listener case stays trivial.")
//! @yah:next("mesofact's own template already reads `$PORT` (oss/mesofact/crates/mesofact/src/cli/new/template-lib/src/lib.rs:33) — the alias means it keeps working untouched, which is the point of having one.")
//! @yah:next("Inject from the supervisor spawn paths (kamaji native/jit/containerd, and cloud's mesofact_static / pond reconcilers) off the resolved set, not from a per-caller string.")
//! @yah:next("Document the contract in .yah/docs/guides/write-a-service-toml.md alongside the `ports = [...]` key.")
//! @yah:verify("A workload declaring only `http` sees both `PORT` and `PORT_HTTP` set to the same number.")
//! @yah:verify("A workload declaring http+wss sees PORT, PORT_HTTP, PORT_WSS and no legacy spelling.")
//! @yah:verify("grep across the tree finds no remaining producer of MF_PORT or KAMAJI_BUNDLE_PORT as a workload-facing variable.")
//! @yah:gotcha("Operator decision 2026-09-03 (option B). The named set this reads from is R844-F14's `resolve_set`; the record side that publishes the same names is R844-F15.")
//! @yah:depends_on(R844-F14)
//! @yah:handoff("SHIPPED the one env contract. `kamaji::ports::port_env(&BTreeMap<String,u16>) -> BTreeMap<String,String>` plus `port_env_var(name)`, `PORT_ENV` (\"PORT\") and `PORT_ENV_PREFIX` (\"PORT_\"). Every named port becomes `PORT_<NAME>` (uppercased, non-ASCII-alphanumeric folded to `_`, because a shell cannot export `PORT_WS-CONTROL`); the port named `ports::HTTP` is ADDITIONALLY published as bare `PORT`. Never two facts — `PORT` and `PORT_HTTP` are the same number by construction, and `PORT` is simply ABSENT when nothing is named `http` (an anonymous multi-port workload), which is the same refusal-to-guess `name_anonymous_ports` already makes. Two names folding to one variable keep the first in name order rather than last-write-wins.")
//! @yah:verify("cargo test -p kamaji --lib --all-features (oss/kamaji): 169 passed / 0 failed — 7 new `ports::tests::` cases, plus `native::tests::a_native_child_reads_its_port_from_the_one_env_contract` (a REAL fork: /bin/sh echoes $PORT/$PORT_HTTP/$KAMAJI_BUNDLE_PORT/$MF_PORT into the captured log, asserted through stream_logs) and `docker::tests::the_port_env_contract_renders_and_yields_to_a_spec_literal`.")
//! @yah:handoff("WIRED AT EVERY SPAWN PATH, off the resolved set rather than a per-caller string. kamaji: native.rs `spawn_child` (before spec env, so a spec literal still wins — the file's existing layering rule); jit.rs — the resolved set is now built ONCE in `deploy_on_demand` and threaded through `supervise_on_demand` -> `spawn_jit_child`, so `list_workloads` and the forked child cannot disagree (the JIT child adopts fd 3 and does not bind, but a serve runtime still renders absolute URLs off its own port); containerd.rs `create_and_start`, skipping any name the spec already sets — `deploy_env` is applied AFTER the spec's literal env there (pinned by `oci_spec_injects_mesh_ip_after_literal_env`), so an unconditional inject would have made containerd the one backend that overrides an operator value instead of yielding to it; docker.rs `render`, emitted BEFORE the spec env because `docker run` takes the final `--env` for a repeated name (measured, not assumed: `docker run -e FOO=1 -e FOO=2 alpine:3` prints 2). cloud: pond.rs:894 `MF_PORT` -> `PORT`/`PORT_HTTP` via `kamaji::ports::port_env`. app/yah/cli: camp.rs run.spawn's hand-written `cmd.env(\"PORT\", …)` now reads the contract (new `kamaji` dep on the cli crate); `port = 0` is portless per `RunSpawnParams::port`, feeds an empty list, and sets NEITHER variable — a process with no listener must not be told it has one.")
//! @yah:handoff("DISCOVERED WORK, done in this pass rather than filed. (1) `cloud::reconciler::mesofact_static` and `local_process` were reporting PORTLESS deploys: `native_support::native_spec` hardcodes `expose.mesh.ports: vec![]`, so the port each had just resolved/declared never reached the spec. Both now set it (mesofact_static.rs from the allocator's `spawn_port`, local_process.rs from `[process] port`, empty for a portless component). Two things follow that were both missing: the native backend can inject `PORT` from it, and `DeployResult::ports` / `WorkloadState::ports` stop reporting these workloads as having no ports. (2) `oss/yah-base/crates/local-driver/src/pond_miniflare.rs` was a FOURTH `MF_PORT` producer the ticket did not name; env building is extracted to `miniflare_env(&MiniflareSpec)` so the spelling is assertable without a container runtime. It writes `PORT`/`PORT_HTTP` literally rather than calling `kamaji::ports::port_env` — yah-base sits BELOW kamaji in the publish DAG (`yah-base <- {qed,kamaji} <- yubaba`, stated in oss/yah-base/Cargo.toml's own handoff), so a kamaji dep there would invert it. (3) `.yah/docs/guides/write-a-service-toml.md` told operators to \"name the ports in the manifest\" — NO SUCH KEY EXISTS. The only port key any schema carries is `MeshExpose.ports`, an array of INTEGERS (`.yah/schema/workload.toml.schema.json`; service/mirror schemas have none). Corrected in place: names are real everywhere downstream (allocator, service record, sibling wire, `PORT_&lt;NAME&gt;`), and the manifest surface for writing them is the piece still missing — worth a ticket, not filed, since it is R844-F15's territory.")
//! @yah:verify("The ticket's three criteria, each with its test. (1) http-only sees PORT == PORT_HTTP: `ports::tests::a_single_listener_sees_port_and_port_http_as_one_number` plus the real-fork `native::tests::a_native_child_reads_its_port_from_the_one_env_contract`. (2) http+wss sees PORT/PORT_HTTP/PORT_WSS and no legacy spelling: `ports::tests::a_multi_listener_workload_sees_one_variable_per_name` and `the_env_a_resolved_set_yields_is_the_set_the_allocator_returned`, which drives a real `LedgerPorts::resolve_set` rather than a hand-built map. NOTE the honest limit: no manifest key spells port NAMES yet (see the discovered-work entry), so the named multi-port case is exercised through the allocator, which is the only producer of names today. (3) grep: every surviving `MF_PORT` / `KAMAJI_BUNDLE_PORT` hit in the tree is a doc comment, a test asserting ABSENCE, kamaji's own daemon-flag READ (main.rs:81 / server.rs:460 — a node-wide operator flag whose value R844-F14 already refuses, never set on a workload), or the miniflare shim's compat read. Zero producers.")
//! @yah:verify("Full suites on this tree: kamaji --lib --all-features 169 passed / 0 failed; kamaji-bin --lib --all-features 272 / 0; yah-cloud --lib 1010 / 0 (only the 2 pre-existing unused-import warnings in mesofact_static.rs); yah-local-driver --lib 99 / 0 (+1 new, `pond_miniflare::tests::miniflare_env_spells_the_one_port_contract`); `cargo test -p yah --lib camp::` 370 / 0; `cargo check -p yah --lib` clean with the new kamaji dep.")
//! @yah:gotcha("THE yah-miniflare IMAGE MUST BE REBUILT before the containerised pond path is used again. `oss/qed/crates/qed/images/yah-miniflare/Dockerfile` now bakes `ENV PORT=4322` instead of `ENV MF_PORT=4322`, and the shim it COPYs (`oss/yubaba/crates/cloud/worker/miniflare-sim.mjs`) reads `PORT ?? MF_PORT ?? 4322`. A PRE-EXISTING image carries the OLD shim, which reads only MF_PORT — and since nothing produces MF_PORT any more, such a container falls back to its baked 4322 while `pond_miniflare` publishes `(spec.port, spec.port)`. When spec.port != 4322 that mismatch surfaces as the host-side HTTP ready-probe timing out, i.e. loud, not silent. The MF_PORT fallback in the shim is deliberately KEPT for a hand-run container, but it cannot help a stale image because the stale shim is the one inside it. No published digest is pinned (`YAH_MINIFLARE_DIGEST` is `option_env!`, so `None` unless a build sets it), which is why this is a rebuild note rather than a blocker.")
//!
//! @yah:ticket(R844-F14, "Port declaration becomes name-only — a numeric pin survives solely for world-fixed ports")
//! @yah:status(review)
//! @yah:at(2026-09-03T22:06:22Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R844)
//! @yah:next("Widen `PortAllocator::resolve(ident, bind_ip, declared) -> u16` (ports.rs:92) to a set-valued `resolve_set(ident, bind_ip, &[PortSpec]) -> BTreeMap<String, u16>`, where `PortSpec { name: String, pin: Option<u16> }`. One ledger entry per `(ident, name)` so `LedgerPorts` still returns the same number across a kamaji restart — per port, not just per workload.")
//! @yah:next("Retire §'Declared always wins' (ports.rs:35-43) as a general rule. A manifest declares port NAMES (`ports = [\"http\", \"wss\", \"metrics\"]`); the allocator picks every number. `pin` is accepted only where the port is fixed by the outside world (passway's 443/80) and should be REJECTED — not silently honoured — elsewhere, so a stale pin fails loudly at bring-up instead of colliding on a co-tenanted node.")
//! @yah:next("Keep `EphemeralPorts` and `LedgerPorts` as the two impls; the local/remote split is about persistence and is unaffected.")
//! @yah:next("Single-port workloads keep a one-element set named `http` — no special case in the allocator.")
//! @yah:verify("A two-port workload gets two distinct numbers, both stable across a simulated supervisor restart.")
//! @yah:verify("A `pin` on a non-world-fixed port is an error at resolve time, with the port name in the message.")
//! @yah:verify("R599-F12's bundle case (a workload that used to declare `serve_bundle.port`) still lands on a live listener under the new shape.")
//! @yah:gotcha("Operator decision 2026-09-03 (option B): 'always automatic' and an honoured operator-written number are mutually exclusive. This intentionally reverses the rule R844-F2 shipped at ports.rs:35-43, which is still in review — coordinate with its owner before landing.")
//! @yah:assumes("passway's 443/80 is the only genuinely world-fixed port in this fleet; if a second exists it needs the same pin allowance.")
//! @yah:depends_on(R844-F2)
//! @yah:handoff("SHIPPED the name-only port contract in oss/kamaji/crates/kamaji/src/ports.rs. `PortAllocator::resolve(ident, bind_ip, declared) -> u16` is gone; the trait is `resolve_set(ident, bind_ip, &[PortSpec]) -> BTreeMap<String,u16>` plus a provided `resolve_one` for the single-listener case (no second policy — it resolves a one-element set). `PortSpec { name: String, pin: Option<u16> }` with `auto()` / `http()` / `world_fixed()` constructors; `HTTP = \"http\"` is the name a sole port carries, agreed with R844-F15 so records and T13's PORT_<NAME> env can assume it.")
//! @yah:handoff("PIN RULE, the reversal of R844-F2 §'Declared always wins' (operator option B): a pin is honoured only for `WORLD_FIXED_PORTS = [80, 443]`. Anything else is an ERROR at resolve time naming the port, the number and the workload, telling the operator to delete the number. Rejection happens over the WHOLE spec set before anything is reserved, so one stale pin cannot leave the node holding ports for a deploy that then failed. `Some(0)` still reads as unpinned.")
//! @yah:handoff("THE ONE ASYMMETRY, deliberate and documented in the module header: LedgerPorts (remote/published tier) REJECTS a non-world-fixed pin; EphemeralPorts (local/camp tier) treats it as a PREFERENCE — honoured when free, floated when taken. A dev mirror's `port = 4321` is a browser handle the operator typed, nothing publishes it, and it yields, so it cannot cause the harm the rule exists to prevent. Making it fatal there would have broken `yah camp` for yah-marketing/dev.toml and scrabcake/dev.toml today, for no safety gain. The axis is publication, which is the same axis the two impls already split on.")
//! @yah:handoff("LEDGER v1 -> v2. Keyed `(ident, name)` now, serialized nested (`ports.<ident>.<name>.port`) so no separator is reserved out of either namespace. A v1 file MIGRATES rather than being dropped: its one anonymous port per ident becomes that ident's `http`, because dropping it would move a keep-alive workload's published port on the first restart after the upgrade — the exact failure the ledger exists to prevent. `release(ident)` now drops every named port of that ident; `reserved_port(ident, name)` and `reserved_ports(ident)` replace the old single-value accessor.")
//! @yah:handoff("CALLERS MIGRATED (compile scope, coordinated with @Ashguard:dove on R844-F15 who owns kamaji/src/lib.rs + the wire): kamaji-bin/src/server.rs — `BundleBackend::declared_port` -> `declared_pin`, new `http_spec()`, `resolve_port(ident, bind_ip, PortSpec)`, the three deploy call sites (keep-alive, on-demand, revalidate receiver); oss/yubaba/crates/cloud/src/reconciler/mesofact_static.rs:631 — EphemeralPorts now via `resolve_one` + a named `http` spec. I did not touch any `DeployResult`/`WorkloadState` construction.")
//! @yah:handoff("DISCOVERED WORK, done in this pass rather than filed. (1) `revalidate_port()` (serve+1) DELETED, server.rs ~2972: with every number allocated, `serve + 1` is an arbitrary port the ledger may already have promised elsewhere on the node — the receiver is its own ident with its own ledger entry, which is the same disjointness without the arithmetic. Its three test uses were rewritten. (2) The `--bundle-port` / `KAMAJI_BUNDLE_PORT` node-wide override is now REFUSED too, not honoured — a node-wide number is the worst kind of operator pin (one slot for every bundle on the node), and option B says automatic and an honoured operator number are mutually exclusive. The flag is kept, not deleted, so the refusal can name what it refused; main.rs help text and DEFAULT_BUNDLE_PORT docs updated to match. (3) Deleted two vacuous assertions in server.rs's native_bind_ip test (`Some(9001).unwrap_or(8080) == 9001`) that asserted on literals and described the retired fallback. (4) .yah/docs/guides/write-a-service-toml.md gained a `port` on a cloud mirror bullet (don't write one; `fronted = true` is the opt-in marker — spelling verified at mesofact_bundle.rs:156 / ingress.rs:89).")
//! @yah:verify("cargo test -p kamaji --lib (oss/kamaji): 34 passed, 0 failed — 16 of them ports:: cases, all new or rewritten. Covers the ticket's three criteria: a two-port workload gets two distinct numbers stable across a simulated restart (`a_two_port_workload_gets_two_distinct_stable_numbers`); a non-world-fixed pin errors naming the port (`a_pin_that_is_not_world_fixed_is_rejected_naming_the_port`, plus `a_rejected_pin_reserves_none_of_its_siblings_either`); the v1 ledger migrates (`a_v1_ledger_migrates_its_single_port_to_http`).")
//! @yah:verify("cargo test -p kamaji-bin --lib --all-features (oss/kamaji): 272 passed, 0 failed. R599-F12's bundle case under the new shape is `a_bundle_that_declares_no_number_lands_on_a_live_listener` (deploy -> List reports one port -> that number is what the ledger holds for (yah-marketing, http)); the reversal is `a_declared_port_now_fails_the_deploy_naming_the_port`.")
//! @yah:verify("cargo check -p yah-cloud --lib (oss/yubaba): clean, only the 2 pre-existing unused-import warnings in mesofact_static.rs. cargo test -p yah-cloud --lib mesofact_static: 68 passed, 0 failed.")
//! @yah:verify("THREE PRE-EXISTING TESTS FIXED, not adapted around: `a_mesh_assigned_bundle_binds_the_mesh_address_not_loopback` and `two_bundles_on_one_node_get_their_own_ports` both declared numbers (8443, 8081/8082) and now correctly fail that way. The mesh one seeds a v2 ledger before the deploy, because allocation probes the address the workload will bind and 100.64.0.3 does not exist on a test machine — a standing reservation is returned WITHOUT re-probing, which is the same path a kamaji restart and an on-demand redeploy take, not a test-only shortcut. The co-tenancy one now declares nothing, which IS the case under test.")
//! @yah:gotcha("ORDERING HAZARD, the one thing a reviewer must weigh: this makes a kamaji roll and the mirror-pin deletion (R844-T10) ORDER-DEPENDENT. `.yah/services/yah-marketing/mirrors/cloud.toml:244` still says `port = 8080`; that number reaches MesofactServeBundle.port (mesofact_bundle.rs:777) and now FAILS the deploy. Ship a kamaji carrying F14 to us-east-001 before deleting that line and yah.dev has no backend, with `port \"http\" is pinned to 8080, but listen ports are allocated, not declared` in the deploy detail. Recorded durably as @yah:notify_on on R844-T10 so its picker sees it. The loud failure IS the operator's decision (option B) — the alternative, allocating while the front door still dials the written 8080 (IngressRule::upstreams, ingress.rs:184), is the same outage without a message.")
//! @yah:gotcha("BOTH CROSS-TICKET FLAGS THIS TICKET RAISED ARE NOW CLOSED by @Ashguard:dove (R844-F15), re-verified on this tree: docker_backend_e2e 2 passed / 0 failed, kamaji-bin --lib --all-features 272 passed, kamaji --lib 34 passed. The `PeerClosed` on List was NOT docker — kamaji-proto is postcard, where `#[serde(skip_serializing_if)]` omits bytes a POSITIONAL decoder still reads, so the frame was unparseable by a peer of its own version. Fix was dropping the attribute and bumping ProtocolVersion::CURRENT to V6. The rule (every field on a postcard message is mandatory and always encoded; the version bump is the only compatibility mechanism) now lives in the V6 stanza of kamaji-proto/src/version.rs. kamaji/src/lib.rs's `DeployResult.ports` doc no longer cites the removed `PortAllocator::resolve`.")
//!
//! @yah:ticket(R844-F21, "Allocate from the manifest — make `ports = [&quot;http&quot;, &quot;wss&quot;]` actually bind something")
//! @yah:status(review)
//! @yah:at(2026-09-04T11:03:06Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R844)
//! @yah:depends_on(R844-F17)
//! @yah:gotcha("THE SPELLING EXISTS AND IS INERT — that is exactly what this ticket closes, and R844-F17 made it loud rather than silent on purpose. `expose.mesh.ports = [\\\"http\\\", \\\"wss\\\"]` parses, validates, survives both wires and reaches the supervisor as `MeshPort { name: Some(..), number: None }`. Nothing binds it. `validate::shape` emits a ShapeWarning saying so (workload-spec/src/validate.rs, `check_mesh_ports`), pinned by tests/mesh_ports.rs::a_name_only_port_validates_but_warns_that_nothing_will_bind_it. Deleting that warning is the last step of this ticket, not the first.")
//! @yah:gotcha("WHY NO CONSUMER EXISTS TODAY, measured 2026-09-03 rather than assumed — read this before designing, because two of the three tiers genuinely cannot take a name-only port and saying which is the whole design. (1) CONTAINER backends (docker.rs, containerd.rs): `expose.mesh.ports` IS the container-side bound port, fixed by the image; there is no allocation to do and containerd.rs:361 says so in its own comment. A name-only entry there is arguably a manifest error, not an allocation request. (2) NATIVE / BUNDLE (kamaji native.rs, kamaji-bin server.rs): the supervisor WRITES `expose.mesh.ports` rather than reading it — native.rs:158 states plainly that it is \\\"the bind address already resolved\\\", and server.rs's bundle archetype parses it back off `--listen` (R599-F12). (3) So the only place a manifest port set could drive allocation is a path that lowers an AUTHORED workload.toml into a spawn, and `kamaji::ports::PortAllocator::resolve_set` — built by R844-F14 for exactly this — has ZERO production callers: `rg 'resolve_set' --type rust` finds only ports.rs itself. Every live caller uses `resolve_one` with a hardcoded `PortSpec::http()` (kamaji-bin/src/server.rs:529 and :7193, yubaba cloud/src/reconciler/mesofact_static.rs:640).")
//! @yah:next("THE SHAPE: a `MeshExpose -> Vec<PortSpec>` lowering next to `kamaji::declared_port_names`, then swap the two `resolve_one(.., PortSpec::http())` call sites onto `resolve_set` over it. `PortSpec` already carries exactly the two fields `MeshPort` does (`name`, `pin: Option&lt;u16&gt;`), and R844-F14 already decided what a stated number means per tier — LedgerPorts REJECTS a non-world-fixed pin, EphemeralPorts treats it as a preference — so the tier semantics need no new decision.")
//! @yah:next("DECIDE FIRST, and it is the real content of this ticket, not the plumbing: does a name-only port on a CONTAINER workload become an error, or does the container backend gain host-side allocation? A container's ports are its image's, so \\\"allocate\\\" has no meaning container-side; the honest answers are either reject-at-validation-for-container-kind, or allocate a HOST port and publish that (which is what pond already does for the sim tier, local_runtime.rs, and would make the mesh record's port differ from the container's).")
//! @yah:verify("A workload.toml declaring `ports = [\\\"http\\\", \\\"wss\\\"]` deploys, and its service record answers `port(\\\"wss\\\")` with a real number that a mesh peer can dial — the assertion has to reach the RECORD, because \\\"the allocator returned two numbers\\\" is true today and buys nothing.")
//! @yah:verify("The R844 purity canary stays green: `cargo test -p xtask --test main mirror_ingress` = 11 passed / 0 failed, still planning the camp's REAL .yah/services tree with no network. Every child of this relay has been at risk of costing it and none has.")
//! @yah:handoff("SHIPPED — `ports = [\"http\", \"wss\"]` now binds. THE LOWERING the ticket asked for is `kamaji::declared_port_specs(&MeshExpose) -> Vec<PortSpec>` (kamaji/src/lib.rs, beside `declared_port_names`): every number-bearing entry lowers under EXACTLY the name `declared_port_names` publishes it by — including the anonymous rules — so a port cannot be allocated under one name and published under another. A stated number lowers as `PortSpec::pin`, never honoured there, because what a written number means is R844-F14 per-tier policy and the lowering must not know which tier it feeds. `pin.is_none()` is therefore precisely \"the supervisor still owes this port a number\".")
//! @yah:handoff("THE ALLOCATION lands in `NativeRuntime`, not at the two `resolve_one(.., PortSpec::http())` call sites the ticket named — and that divergence is the finding. Those two sites (kamaji-bin BundleBackend, cloud mesofact_static) are callers that ALREADY own allocation and write the resolved number onto the spec before forking; they were never where a manifest port set goes unread. The gap was one level down, in the backend every one of them forks through. `NativeRuntime` now holds a `LedgerPorts` opened on its own `state_dir` — the SAME dir kamaji-bin BundleBackend opens its ledger on, so one ledger per node state dir is what stops the two backends handing one number to two workloads — and `deploy_workload` calls `resolve_declared_ports` before the fork, writing the numbers back onto the spec. Fixing it at the backend covers every native caller at once (kamaji-bin, cloud local-process/mesofact-static/pg-driver, the desktop) instead of two of them.")
//! @yah:handoff("THE LOAD-BEARING RESTRAINT: a port that ALREADY carries a number is left alone. On this backend a number in `expose.mesh.ports` is not an operator pin — it is the bind address a caller already resolved (native.rs `WorkloadHandle::ports` says so), and the W272 bundle path parses it straight back off `--listen`. Feeding it to the allocator as a `pin` would make `LedgerPorts` reject the very port it had just handed out, turning EVERY existing bundle deploy into a bring-up failure. Pinned by `a_number_already_in_the_spec_is_not_re_resolved_as_a_pin` and `a_mixed_manifest_allocates_only_the_port_that_has_no_number`.")
//! @yah:handoff("THE DECISION THE TICKET FLAGGED AS ITS REAL CONTENT — name-only on a CONTAINER backend — is REJECT, not host-side allocation, implemented as `kamaji::reject_unresolved_ports(workload, mesh, backend)` called at the top of both container `deploy_workload`s. Measured, not assumed: containerd publishes NO host port at all and both backends already return `DeployResult::ports` empty deliberately (containerd.rs comments at :361/:482); docker opens a host port only for the explicit `yah.docker.publish` `host:container` map an operator wrote. So an allocated host number would be published into a service record with nothing listening on it — a front door dialling a port no listener holds, which is the exact confidently-wrong reading this relay exists to remove, and strictly worse than a loud refusal. The error names the offending port and not its healthy siblings.")
//! @yah:verify("cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji --lib --all-features = 184 passed / 0 failed (169 before this ticket, so +15 net new and nothing lost). The acceptance test is a REAL FORK, deliberately, because \"the allocator returned two numbers\" was already true before this ticket and bought nothing: `native::tests::a_manifest_that_names_its_ports_gets_numbers_the_child_can_read` deploys a spec declaring only `[\"http\",\"wss\"]`, asserts both names carry distinct numbers in `DeployResult`, asserts `get_workload().ports` (the leg the service-record sweep reads) agrees, and then greps the CHILD process own stdout for `http=<n>`, `wss=<n>` and `bare=<http>` — i.e. the numbers reached a process, which is the thing that was missing.")
//! @yah:verify("Stability and the mixed case: `allocated_ports_survive_a_supervisor_restart_name_by_name` deploys, tears down, builds a WHOLE NEW NativeRuntime over the same state dir (which is what a restarted kamaji is) and requires the identical name->port map back — per PORT, not merely per workload, because the number is published into a service record and rendered into an ingress upstream. Lowering + refusal covered by 6 new lib.rs cases: `every_numbered_port_lowers_under_the_name_it_is_published_by` (the agreement property, over 4 declaration shapes), `a_name_only_port_lowers_to_an_unpinned_spec`, `a_stated_number_is_lowered_as_a_pin_not_resolved`, `a_name_only_duplicate_of_a_numbered_port_lowers_once` (the unvalidated postcard wire), `a_container_backend_refuses_a_port_it_cannot_allocate`, `a_fully_numbered_declaration_passes_every_container_backend`.")
//! @yah:verify("WHOLE-TREE, re-run by me on a settled tree: cargo test --manifest-path oss/kamaji/Cargo.toml --workspace --all-features = every target ok, exit 0; kamaji-bin --features bundle-serving --lib 253/0; yah-cloud --lib 1019 passed / 0 failed / 4 ignored; yah-workload-spec 146/0 + 87/0; cargo check -p yah -p xtask --all-targets = zero errors. THE R844 PURITY CANARY HELD: cargo test -p xtask --test main mirror_ingress = 11 passed / 0 failed, still planning the camp REAL .yah/services tree with no network and no credentials.")
//! @yah:verify("HONEST LIMIT ON THE TICKET OWN ACCEPTANCE WORDING, which asked the assertion to reach the service RECORD. I verified that leg IN SOURCE rather than live: `oss/yubaba/crates/yubaba/src/service_records.rs:995` and `:1028` both assign `record.resolved_ports = state.ports.clone()` straight off the `WorkloadState.ports` my test asserts, so `ServiceRecord::port(\"wss\")` answers by construction. I did NOT dial it on a live fleet, because the mesh coordination server has been down since 2026-09-03T06:03:03Z (R858, root-caused this session) and no 100.64.0.0/10 address answers from this camp.")
//! @yah:gotcha("DISCOVERED AND FIXED IN PASS, both were statements this ticket falsified. (1) `oss/yah-base/crates/workload-spec/tests/mesh_ports.rs` had `a_name_only_port_validates_but_warns_that_nothing_will_bind_it` — the NAME and its comment are now false, since native binds it. Renamed to `..._and_warns_that_only_the_native_tier_binds_it` and strengthened to require the warning name both `PORT_WSS` and the container tier. (2) `validate::shape` warning text said \"no supervisor allocates from the manifest yet — nothing will bind it\"; it now names the split (native allocates and delivers via `PORT_<NAME>`; a container backend refuses). It stays a WARNING, not an error: shape validation cannot tell which backend a spec will land on because placement decides that later, so naming the split is the most that layer can honestly say. (3) `.yah/docs/guides/write-a-service-toml.md:121-125` told operators the spelling binds nothing and to state the number — corrected to prefer name-only on native and state numbers only for containers.")
//! @yah:gotcha("DELIBERATELY NOT DONE, with the reason: `NativeRuntime` does NOT call `PortAllocator::release` on teardown, so a permanently-removed native workload keeps its ledger entry. This is not an oversight — `deploy_workload` calls `teardown_workload` on itself for idempotency, so releasing there would hand every redeploy a fresh number and destroy exactly the cross-restart stability the ledger exists to provide (the same reason `LedgerPorts::resolve_set` lets a standing reservation win even when the port is currently unbindable). kamaji-bin releases only from its own explicit teardown path (server.rs:3457); a native equivalent needs a teardown verb that is distinguishable from the idempotency sweep, which does not exist today. Worth a ticket if native ledger growth is ever measured to matter; it is bounded by distinct idents, not by deploys.")

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// The name a single-listener workload's port carries. Nothing in the
/// allocator special-cases it — it is a one-element set like any other — but
/// every producer spelling it the same way is what lets a consumer (a service
/// record, T13's `PORT_<NAME>` env contract) assume `http` without asking.
pub const HTTP: &str = "http";

/// The ports whose number is fixed by something outside this fleet: 80 and 443,
/// the two a browser dials from a URL scheme alone. These are the only numbers
/// a [`PortSpec::pin`] may carry — see the module docs.
pub const WORLD_FIXED_PORTS: &[u16] = &[80, 443];

/// `true` when `port` is one the outside world fixes ([`WORLD_FIXED_PORTS`]).
pub fn is_world_fixed(port: u16) -> bool {
    WORLD_FIXED_PORTS.contains(&port)
}

/// The variable a single-listener workload reads to learn its port — an alias
/// for the port named [`HTTP`], never a fourth independent fact.
///
/// It exists because the trivial case has to stay trivial: mesofact's own
/// project template reads `$PORT` (`mesofact/src/cli/new/template-lib/src/lib.rs`),
/// as does every twelve-factor runtime anyone would bring here, and a contract
/// that made them all read `PORT_HTTP` would be a rename tax paid by every
/// workload for the benefit of the rare multi-listener one.
pub const PORT_ENV: &str = "PORT";

/// Prefix for the per-name spelling — `PORT_HTTP`, `PORT_WSS`, `PORT_METRICS`.
pub const PORT_ENV_PREFIX: &str = "PORT_";

/// The env var name a port called `name` is published under.
///
/// Uppercased, with every character that is not ASCII-alphanumeric folded to
/// `_`, because a port name is a manifest string (`ports = ["ws-control"]`) and
/// an env var name is not: a shell cannot export `PORT_WS-CONTROL`, and a
/// variable a workload cannot read is the same as one that was never set.
///
/// Anonymous ports arrive here already named after their number
/// ([`crate::name_anonymous_ports`]), so a two-port workload that named nothing
/// reads `PORT_8080` / `PORT_9090` — the number is the only identity those
/// ports carry, and inventing an ordinal would name a thing nobody said.
pub fn port_env_var(name: &str) -> String {
    let mut out = String::with_capacity(PORT_ENV_PREFIX.len() + name.len());
    out.push_str(PORT_ENV_PREFIX);
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.extend(ch.to_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// The environment a supervisor injects so a workload can answer "what port did
/// I get?" — the one contract behind R844-T13.
///
/// `resolved` is what an allocator handed back ([`PortAllocator::resolve_set`])
/// or what a backend observed itself binding; never a declared number, which is
/// a request rather than an answer.
///
/// Every named port becomes [`port_env_var`], and the port named [`HTTP`] is
/// *additionally* published as bare [`PORT_ENV`]. Both spellings of the same
/// number, deliberately: a workload that reads `PORT` and one that reads
/// `PORT_HTTP` are asking the same question and must not be able to get two
/// answers. When nothing is named `http` — an anonymous multi-port workload —
/// bare `PORT` is simply absent, which is the honest answer. Guessing one of
/// several listeners is exactly the positional accident
/// [`crate::name_anonymous_ports`] refuses to make.
///
/// This replaces three prior spellings of one fact: `KAMAJI_BUNDLE_PORT` (a
/// *node-wide* variable, so co-tenants could not disagree about it even in
/// principle), `MF_PORT` (miniflare-only), and an ad-hoc bare `PORT` written by
/// one camp spawn path. A workload that runs locally and on a fleet node now
/// learns its port from one mechanism instead of two that can disagree.
///
/// Two names can normalize to one variable (`ws-1` and `ws_1`). The first in
/// name order wins and the loser is dropped rather than silently overwriting —
/// deterministic either way, and the allocator has already rejected the only
/// collision that could lose a *port* (two specs sharing a name).
pub fn port_env(resolved: &BTreeMap<String, u16>) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (name, port) in resolved {
        out.entry(port_env_var(name))
            .or_insert_with(|| port.to_string());
    }
    if let Some(http) = resolved.get(HTTP) {
        out.insert(PORT_ENV.to_string(), http.to_string());
    }
    out
}

/// One listen port a workload asks for, **by name**.
///
/// `pin` is not "the port I want" — it is "this number is not mine to choose",
/// and the allocator enforces that: a pin outside [`WORLD_FIXED_PORTS`] is an
/// error on the published tier rather than a number quietly honoured (see the
/// module docs). `Some(0)` is the ephemeral sentinel and reads as no pin at
/// all, so a caller lowering an "unset" config value does not have to
/// special-case it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    /// Name of the port within the workload — `http`, `wss`, `metrics`. Unique
    /// within one [`PortAllocator::resolve_set`] call, and the key the resolved
    /// number comes back under.
    pub name: String,
    /// A number fixed by the outside world, or `None` (the normal case) to let
    /// the allocator pick.
    pub pin: Option<u16>,
}

impl PortSpec {
    /// A named port whose number the allocator picks — the normal case.
    pub fn auto(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pin: None,
        }
    }

    /// The single-listener case: one port named [`HTTP`], allocated.
    pub fn http() -> Self {
        Self::auto(HTTP)
    }

    /// A named port pinned to a number the outside world fixes.
    ///
    /// Errors *here*, at construction, when `port` is not in
    /// [`WORLD_FIXED_PORTS`] — so a caller that means "this is passway's 443"
    /// finds out at the call site rather than at bring-up. Building the struct
    /// literally is still allowed (a caller lowering a config file has to be
    /// able to represent the stale pin it just read); that path fails at
    /// resolve time instead.
    pub fn world_fixed(name: impl Into<String>, port: u16) -> Result<Self> {
        let name = name.into();
        anyhow::ensure!(
            is_world_fixed(port),
            "port {name:?} cannot be pinned to {port}: {:?} are the only \
             world-fixed ports",
            WORLD_FIXED_PORTS
        );
        Ok(Self {
            name,
            pin: Some(port),
        })
    }
}

/// How a supervisor decides what ports a workload listens on.
///
/// Implementations differ in whether the answer survives a supervisor restart,
/// and — following from that — in whether a pin is an error or a preference.
/// See the module docs.
pub trait PortAllocator: Send + Sync {
    /// Resolve every port `specs` names for `ident`, as `name -> port`.
    ///
    /// `bind_ip` is the address the workload will actually bind, because a port
    /// is only free *relative to an address* — probing loopback says nothing
    /// about whether the same port is free on the node's mesh address.
    ///
    /// Errors when a name is empty or repeated, and (on the published tier)
    /// when a `pin` is not world-fixed. The returned map always has exactly one
    /// entry per spec, and no two of them share a number.
    fn resolve_set(
        &self,
        ident: &str,
        bind_ip: IpAddr,
        specs: &[PortSpec],
    ) -> Result<BTreeMap<String, u16>>;

    /// Drop every reservation held for `ident`. Idempotent; an unknown ident is
    /// a no-op. Called on teardown so a torn-down workload's ports return to
    /// the pool instead of being held forever by a ledger nobody prunes.
    fn release(&self, ident: &str);

    /// One-port convenience over [`Self::resolve_set`] — the single-listener
    /// case, which is most callers. Not a second policy: it resolves a
    /// one-element set and unwraps the entry.
    fn resolve_one(&self, ident: &str, bind_ip: IpAddr, spec: PortSpec) -> Result<u16> {
        let resolved = self.resolve_set(ident, bind_ip, std::slice::from_ref(&spec))?;
        resolved
            .get(&spec.name)
            .copied()
            .with_context(|| format!("allocator returned no port named {:?} for {ident}", spec.name))
    }
}

/// Reject an unusable spec set before anything is allocated: every name must be
/// non-empty, and no two may collide (the map would silently keep one).
fn check_names(specs: &[PortSpec]) -> Result<()> {
    let mut seen: Vec<&str> = Vec::with_capacity(specs.len());
    for spec in specs {
        anyhow::ensure!(
            !spec.name.trim().is_empty(),
            "a port declaration has no name; ports are declared by name \
             (`ports = [\"http\"]`)"
        );
        anyhow::ensure!(
            !seen.contains(&spec.name.as_str()),
            "port name {:?} is declared twice",
            spec.name
        );
        seen.push(&spec.name);
    }
    Ok(())
}

/// The pin this spec actually carries on the *published* tier: `None` for the
/// normal case, `Some(world-fixed number)` for passway's 80/443 — and an error
/// naming the port for anything else.
fn published_pin(spec: &PortSpec) -> Result<Option<u16>> {
    match spec.pin.filter(|&p| p != 0) {
        None => Ok(None),
        Some(p) if is_world_fixed(p) => Ok(Some(p)),
        Some(p) => anyhow::bail!(
            "port {:?} is pinned to {p}, but listen ports are allocated, not \
             declared: a number is honoured only for a port the outside world \
             fixes ({:?}). Delete the number and keep the name — the supervisor \
             picks the port and publishes it (service record -> ingress \
             upstream), so a written-down {p} can only be stale or collide with \
             a co-tenant on this node.",
            spec.name,
            WORLD_FIXED_PORTS
        ),
    }
}

/// Pick a free port on `bind_ip` that `taken` does not already claim.
///
/// Bounded re-roll: `pick_free_port` can legitimately hand back a number this
/// call (or this ledger) has already promised, since each probe closes its
/// listener before the next one opens. Sixteen tries, then a loud error rather
/// than an unbounded spin on a pathological node.
fn allocate_avoiding(bind_ip: IpAddr, taken: impl Fn(u16) -> bool) -> Result<u16> {
    let mut port = pick_free_port(bind_ip)?;
    for _ in 0..16 {
        if !taken(port) {
            return Ok(port);
        }
        port = pick_free_port(bind_ip)?;
    }
    anyhow::ensure!(
        !taken(port),
        "could not find a port on {bind_ip} that is not already spoken for by \
         another port on this node"
    );
    Ok(port)
}

/// Ask the OS for a free port on `bind_ip` by binding `:0` and reading back
/// what the kernel assigned.
///
/// Inherently racy — the listener is closed before the workload binds, so
/// another process can take the port in between. That race is accepted here for
/// the same reason the local tier already accepts it (`cloud`'s
/// `mesofact_static.rs` does exactly this): the alternative is holding the
/// socket and passing the fd, which is the socket-custody path and is a much
/// heavier contract than "pick a number". The window is microseconds and the
/// failure mode is a bind error the supervisor already reports.
pub fn pick_free_port(bind_ip: IpAddr) -> Result<u16> {
    let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0))
        .with_context(|| format!("could not bind an ephemeral port on {bind_ip}"))?;
    Ok(listener
        .local_addr()
        .context("ephemeral listener has no local address")?
        .port())
}

/// `true` when `port` is currently bindable on `bind_ip`.
fn is_free(bind_ip: IpAddr, port: u16) -> bool {
    TcpListener::bind(SocketAddr::new(bind_ip, port)).is_ok()
}

/// The local tier's allocator: a pin is a *preference*, and anything else comes
/// from the OS. Holds no state and persists nothing.
///
/// This is the shape `cloud::reconciler::mesofact_static` already implemented
/// inline for `mesofact-dev`; naming it here is what makes the local and remote
/// tiers one contract instead of two lookalike code paths.
///
/// R844-F14: this is the one tier where a non-world-fixed pin is *not* an
/// error. A camp port is a browser handle the operator typed into a dev mirror
/// (`localhost:4321`), nothing publishes it, and it yields the moment it is
/// taken — so it cannot do the damage the pin rule exists to prevent.
#[derive(Debug, Clone, Copy, Default)]
pub struct EphemeralPorts;

impl PortAllocator for EphemeralPorts {
    fn resolve_set(
        &self,
        _ident: &str,
        bind_ip: IpAddr,
        specs: &[PortSpec],
    ) -> Result<BTreeMap<String, u16>> {
        check_names(specs)?;
        let mut out: BTreeMap<String, u16> = BTreeMap::new();
        for spec in specs {
            let preferred = spec.pin.filter(|&p| p != 0);
            let already = |p: u16, out: &BTreeMap<String, u16>| out.values().any(|&q| q == p);
            let port = match preferred {
                // A preferred port that is actually free, and not already
                // handed to a sibling in this same set, is honoured verbatim.
                Some(p) if is_free(bind_ip, p) && !already(p, &out) => p,
                // Taken: float to an OS-assigned one rather than failing the
                // bring-up. Locally the operator would rather have the workload
                // running somewhere than not running at all.
                Some(p) => {
                    let fallback = allocate_avoiding(bind_ip, |q| already(q, &out))?;
                    tracing::info!(
                        port = %spec.name,
                        preferred = p,
                        actual = fallback,
                        "preferred port is taken; falling back to an OS-assigned port"
                    );
                    fallback
                }
                None => allocate_avoiding(bind_ip, |q| already(q, &out))?,
            };
            out.insert(spec.name.clone(), port);
        }
        Ok(out)
    }

    fn release(&self, _ident: &str) {}
}

/// One persisted reservation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerEntry {
    port: u16,
}

/// On-disk shape of the port ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerFile {
    version: u32,
    /// `ident -> name -> reservation`. Nested rather than a flattened
    /// `"ident/name"` key so no separator has to be reserved out of either
    /// namespace, and so an operator reading the file sees one block per
    /// workload. `BTreeMap` so the file is stable under rewrite — a supervisor
    /// that rewrites this on every deploy should not produce a different byte
    /// sequence for the same content.
    ports: BTreeMap<String, BTreeMap<String, LedgerEntry>>,
}

/// The v1 shape, one anonymous port per ident. Migrated forward rather than
/// dropped: a v1 entry described the single listener, which is [`HTTP`] now, and
/// dropping it would move a keep-alive workload's published port on the first
/// restart after an upgrade.
#[derive(Debug, Deserialize)]
struct LedgerFileV1 {
    ports: BTreeMap<String, LedgerEntry>,
}

/// Schema version of [`LedgerFile`]. An unrecognized version degrades to "no
/// ledger" (warn, start empty) rather than refusing to boot: losing the
/// reservations costs a port reallocation that the service-record sweep then
/// corrects, whereas a supervisor that will not start costs the whole node.
///
/// v2 (R844-F14) keys by `(ident, name)`; v1 keyed by ident alone and is
/// migrated on read.
const LEDGER_VERSION: u32 = 2;

/// A ledger key: which workload, and which of its named ports.
type PortKey = (String, String);

/// The remote tier's allocator: allocates every port a workload names, plus an
/// `(ident, name) -> port` ledger on disk so a restarted supervisor gives a
/// workload back the ports it had.
///
/// The in-memory map is the authority while the process lives; the file is
/// written after every mutation so a crash loses at most the reservation that
/// was mid-write.
///
/// This is the tier where a non-world-fixed pin is an error: its numbers are
/// published into a service record and rendered into an ingress upstream, so
/// honouring a stale one is how a wrong number reaches the front door.
pub struct LedgerPorts {
    path: PathBuf,
    reserved: Mutex<BTreeMap<PortKey, u16>>,
}

impl LedgerPorts {
    /// File name of the port ledger, written inside the supervisor's state
    /// directory.
    pub const FILE_NAME: &'static str = "ports.json";

    /// Open (or start) a ledger at `<state_dir>/ports.json`.
    ///
    /// Every read failure — missing, unreadable, malformed, unknown version —
    /// starts empty rather than erroring, for the reason in [`LEDGER_VERSION`].
    pub fn open(state_dir: impl Into<PathBuf>) -> Self {
        let path = state_dir.into().join(Self::FILE_NAME);
        let reserved = load(&path);
        Self {
            path,
            reserved: Mutex::new(reserved),
        }
    }

    /// Where this ledger persists. Exposed for operators and tests.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The port currently reserved for `ident`'s port `name`, if any. Does not
    /// allocate.
    pub fn reserved_port(&self, ident: &str, name: &str) -> Option<u16> {
        self.reserved
            .lock()
            .ok()?
            .get(&(ident.to_string(), name.to_string()))
            .copied()
    }

    /// Every port currently reserved for `ident`, as `name -> port`. Empty when
    /// the ident has no reservations. Does not allocate.
    pub fn reserved_ports(&self, ident: &str) -> BTreeMap<String, u16> {
        let Ok(reserved) = self.reserved.lock() else {
            return BTreeMap::new();
        };
        reserved
            .iter()
            .filter(|((i, _), _)| i == ident)
            .map(|((_, name), &port)| (name.clone(), port))
            .collect()
    }

    fn save(&self, reserved: &BTreeMap<PortKey, u16>) {
        let mut ports: BTreeMap<String, BTreeMap<String, LedgerEntry>> = BTreeMap::new();
        for ((ident, name), &port) in reserved {
            ports
                .entry(ident.clone())
                .or_default()
                .insert(name.clone(), LedgerEntry { port });
        }
        let file = LedgerFile {
            version: LEDGER_VERSION,
            ports,
        };
        if let Err(e) = write_atomic(&self.path, &file) {
            tracing::warn!(
                path = %self.path.display(),
                error = format!("{e:#}"),
                "ports: could not persist the port ledger; allocations hold in \
                 memory but a restart before the next successful write will \
                 reallocate"
            );
        }
    }
}

impl PortAllocator for LedgerPorts {
    fn resolve_set(
        &self,
        ident: &str,
        bind_ip: IpAddr,
        specs: &[PortSpec],
    ) -> Result<BTreeMap<String, u16>> {
        check_names(specs)?;
        // Validate every pin BEFORE touching the ledger, so a set with one
        // stale pin reserves nothing at all: a half-applied set would leave the
        // node holding ports for a deploy that then failed.
        let pins = specs
            .iter()
            .map(published_pin)
            .collect::<Result<Vec<Option<u16>>>>()
            .with_context(|| format!("resolving listen ports for {ident}"))?;

        let mut reserved = self
            .reserved
            .lock()
            .map_err(|_| anyhow::anyhow!("port ledger mutex poisoned"))?;

        let mut out: BTreeMap<String, u16> = BTreeMap::new();
        let mut dirty = false;
        for (spec, pin) in specs.iter().zip(pins) {
            // A world-fixed pin is honoured and deliberately NOT written to the
            // ledger: 443 is not this node's to allocate or to hold, and
            // recording it would let a later removal of the pin keep binding it
            // from a file nobody reads.
            if let Some(port) = pin {
                out.insert(spec.name.clone(), port);
                continue;
            }

            let key: PortKey = (ident.to_string(), spec.name.clone());

            // A standing reservation for this (ident, name) wins, and it wins
            // even when the port is currently unbindable. That is not a nicety
            // — it is required by the on-demand tier: kamaji is the socket
            // custodian there, so on a redeploy the port is held by *this
            // workload's own* listener at the moment we resolve, and treating
            // "not free" as "reallocate" would move an on-demand workload's
            // port on every single redeploy.
            //
            // The count check is what keeps that from also swallowing a genuine
            // squatter: if this ledger has promised the port to exactly one
            // holder — this one — then whoever holds it is us. If the port is
            // somehow double-booked, fall through and allocate a fresh one
            // instead of handing out a number two workloads believe they own.
            if let Some(&port) = reserved.get(&key) {
                let promised_once = reserved.values().filter(|&&p| p == port).count() == 1;
                let taken_by_sibling = out.values().any(|&q| q == port);
                if !taken_by_sibling && (is_free(bind_ip, port) || promised_once) {
                    out.insert(spec.name.clone(), port);
                    continue;
                }
            }

            // Avoid both what the ledger has promised elsewhere (the OS can
            // hand back a port belonging to a workload that is not currently
            // listening, e.g. mid restart) and what this same call has already
            // handed to a sibling port — two names on one workload must not
            // land on one number.
            let port = allocate_avoiding(bind_ip, |p| {
                reserved.iter().any(|(k, &v)| v == p && *k != key)
                    || out.values().any(|&q| q == p)
            })?;

            reserved.insert(key, port);
            dirty = true;
            out.insert(spec.name.clone(), port);
        }

        if dirty {
            let snapshot = reserved.clone();
            drop(reserved);
            self.save(&snapshot);
        }
        Ok(out)
    }

    fn release(&self, ident: &str) {
        let Ok(mut reserved) = self.reserved.lock() else {
            return;
        };
        let before = reserved.len();
        reserved.retain(|(i, _), _| i != ident);
        if reserved.len() == before {
            return;
        }
        let snapshot = reserved.clone();
        drop(reserved);
        self.save(&snapshot);
    }
}

fn load(path: &Path) -> BTreeMap<PortKey, u16> {
    let Ok(bytes) = std::fs::read(path) else {
        return BTreeMap::new();
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "ports: unreadable port ledger; starting empty"
            );
            return BTreeMap::new();
        }
    };
    let version = value.get("version").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let parsed = match version {
        LEDGER_VERSION => serde_json::from_value::<LedgerFile>(value).map(|file| {
            file.ports
                .into_iter()
                .flat_map(|(ident, named)| {
                    named
                        .into_iter()
                        .map(move |(name, entry)| ((ident.clone(), name), entry.port))
                })
                .collect::<BTreeMap<PortKey, u16>>()
        }),
        // v1: one anonymous port per ident. That port WAS the single listener,
        // so it migrates to `http` rather than being dropped — dropping it
        // would move a keep-alive workload's published port on the first
        // restart after the upgrade, which is the exact failure the ledger
        // exists to prevent.
        1 => serde_json::from_value::<LedgerFileV1>(value).map(|file| {
            tracing::info!(
                path = %path.display(),
                "ports: migrating a v1 port ledger; each workload's single port becomes {HTTP:?}"
            );
            file.ports
                .into_iter()
                .map(|(ident, entry)| ((ident, HTTP.to_string()), entry.port))
                .collect::<BTreeMap<PortKey, u16>>()
        }),
        found => {
            tracing::warn!(
                path = %path.display(),
                found,
                expected = LEDGER_VERSION,
                "ports: unrecognized port-ledger version; starting empty"
            );
            return BTreeMap::new();
        }
    };
    parsed.unwrap_or_else(|e| {
        tracing::warn!(
            path = %path.display(),
            error = %e,
            "ports: malformed port ledger; starting empty"
        );
        BTreeMap::new()
    })
}

fn write_atomic(path: &Path, file: &LedgerFile) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create port-ledger dir {}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(file).context("serialize port ledger")?;
    std::fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    Ok(())
}

/// Loopback, the address every non-mesh supervisor binds. Convenience for
/// callers that have no mesh assignment.
pub const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience for the common single-port case in these tests.
    fn one(ledger: &LedgerPorts, ident: &str) -> u16 {
        ledger
            .resolve_one(ident, LOOPBACK, PortSpec::http())
            .unwrap()
    }

    #[test]
    fn a_pin_that_is_not_world_fixed_is_rejected_naming_the_port() {
        // The rule R844-F14 exists for: a mirror's stale `port = 8080` must
        // fail at bring-up, not quietly land on a co-tenant's listener.
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        let err = ledger
            .resolve_set(
                "yah-analytics",
                LOOPBACK,
                &[PortSpec {
                    name: "http".into(),
                    pin: Some(8081),
                }],
            )
            .expect_err("a non-world-fixed pin must not resolve");
        let msg = format!("{err:#}");
        assert!(msg.contains("\"http\""), "must name the port: {msg}");
        assert!(msg.contains("8081"), "must name the number: {msg}");
        assert!(
            msg.contains("yah-analytics"),
            "must name the workload: {msg}"
        );
        assert!(
            ledger.reserved_ports("yah-analytics").is_empty(),
            "a rejected set must reserve nothing"
        );
    }

    #[test]
    fn a_rejected_pin_reserves_none_of_its_siblings_either() {
        // Validation runs over the whole set before anything is written: a
        // half-applied set would hold ports for a deploy that then failed.
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        ledger
            .resolve_set(
                "svc",
                LOOPBACK,
                &[PortSpec::auto("http"), PortSpec { name: "wss".into(), pin: Some(9000) }],
            )
            .expect_err("one bad pin fails the set");
        assert!(ledger.reserved_ports("svc").is_empty());
    }

    #[test]
    fn a_world_fixed_pin_is_honoured_and_not_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        let resolved = ledger
            .resolve_set(
                "passway",
                LOOPBACK,
                &[
                    PortSpec::world_fixed("https", 443).unwrap(),
                    PortSpec::world_fixed("http", 80).unwrap(),
                ],
            )
            .unwrap();
        assert_eq!(resolved.get("https"), Some(&443));
        assert_eq!(resolved.get("http"), Some(&80));
        assert!(
            ledger.reserved_ports("passway").is_empty(),
            "443 is not this node's to hold — recording it would relocate the \
             pin into a file nobody reads rather than remove it"
        );
        assert!(
            PortSpec::world_fixed("http", 8080).is_err(),
            "the constructor rejects a number the outside world does not fix"
        );
    }

    #[test]
    fn a_two_port_workload_gets_two_distinct_stable_numbers() {
        // The verify for this ticket: two names, two numbers, both the same
        // after the supervisor restarts.
        let dir = tempfile::tempdir().unwrap();
        let specs = [PortSpec::auto("http"), PortSpec::auto("wss")];
        let first = LedgerPorts::open(dir.path())
            .resolve_set("yah-marketing", LOOPBACK, &specs)
            .unwrap();
        assert_eq!(first.len(), 2);
        assert_ne!(
            first["http"], first["wss"],
            "two ports on one workload must not share a number"
        );
        assert!(first.values().all(|&p| p != 0));

        let reopened = LedgerPorts::open(dir.path());
        assert_eq!(
            reopened.reserved_ports("yah-marketing"),
            first,
            "the ledger on disk is what makes each named port stable across restart"
        );
        assert_eq!(
            reopened
                .resolve_set("yah-marketing", LOOPBACK, &specs)
                .unwrap(),
            first
        );
    }

    #[test]
    fn undeclared_workloads_get_distinct_ports_on_one_node() {
        // The motivating case: two bundles, one node, neither naming a number.
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        let a = one(&ledger, "yah-marketing");
        let b = one(&ledger, "noisetable-com");
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b, "co-tenants must not be handed the same port");
    }

    #[test]
    fn resolving_the_same_ident_twice_is_stable_within_a_process() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        assert_eq!(one(&ledger, "yah-marketing"), one(&ledger, "yah-marketing"));
    }

    #[test]
    fn the_same_name_on_two_idents_is_two_reservations() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        let a = one(&ledger, "yah-marketing");
        let b = one(&ledger, "yah-marketing-revalidate");
        assert_ne!(a, b);
        assert_eq!(ledger.reserved_port("yah-marketing", HTTP), Some(a));
        assert_eq!(ledger.reserved_port("yah-marketing-revalidate", HTTP), Some(b));
    }

    #[test]
    fn releasing_returns_every_port_of_an_ident_to_the_pool_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        ledger
            .resolve_set(
                "gone",
                LOOPBACK,
                &[PortSpec::auto("http"), PortSpec::auto("metrics")],
            )
            .unwrap();
        let kept = one(&ledger, "stays");
        ledger.release("gone");
        assert!(ledger.reserved_ports("gone").is_empty());
        let reopened = LedgerPorts::open(dir.path());
        assert!(
            reopened.reserved_ports("gone").is_empty(),
            "release must reach disk, or a restart resurrects a dead reservation"
        );
        assert_eq!(
            reopened.reserved_port("stays", HTTP),
            Some(kept),
            "releasing one ident must not disturb another's"
        );
        // Idempotent.
        ledger.release("gone");
        ledger.release("never-existed");
    }

    #[test]
    fn a_corrupt_ledger_starts_empty_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LedgerPorts::FILE_NAME), b"{not json").unwrap();
        let ledger = LedgerPorts::open(dir.path());
        assert_eq!(ledger.reserved_port("anything", HTTP), None);
        // Still allocates — degrading to empty must not degrade to broken.
        assert_ne!(one(&ledger, "anything"), 0);
    }

    #[test]
    fn an_unknown_ledger_version_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(LedgerPorts::FILE_NAME),
            br#"{"version":9999,"ports":{"yah-marketing":{"http":{"port":8080}}}}"#,
        )
        .unwrap();
        assert_eq!(
            LedgerPorts::open(dir.path()).reserved_port("yah-marketing", HTTP),
            None
        );
    }

    #[test]
    fn a_v1_ledger_migrates_its_single_port_to_http() {
        // An upgrade must not move a keep-alive workload's published port.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(LedgerPorts::FILE_NAME),
            br#"{"version":1,"ports":{"yah-marketing":{"port":34567}}}"#,
        )
        .unwrap();
        let ledger = LedgerPorts::open(dir.path());
        assert_eq!(ledger.reserved_port("yah-marketing", HTTP), Some(34_567));
        assert_eq!(one(&ledger, "yah-marketing"), 34_567);
    }

    #[test]
    fn an_unnamed_or_repeated_port_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        assert!(ledger
            .resolve_set("svc", LOOPBACK, &[PortSpec::auto("  ")])
            .is_err());
        assert!(
            ledger
                .resolve_set(
                    "svc",
                    LOOPBACK,
                    &[PortSpec::auto("http"), PortSpec::auto("http")]
                )
                .is_err(),
            "a repeated name would silently collapse to one entry"
        );
        assert!(EphemeralPorts
            .resolve_set("svc", LOOPBACK, &[PortSpec::auto("")])
            .is_err());
    }

    #[test]
    fn ephemeral_allocator_hands_out_a_usable_port_when_nothing_is_pinned() {
        let port = EphemeralPorts
            .resolve_one("dev", LOOPBACK, PortSpec::http())
            .unwrap();
        assert_ne!(port, 0);
        // Freshly released by the probe, so it must be bindable again.
        assert!(is_free(LOOPBACK, port));
    }

    #[test]
    fn the_local_tier_treats_a_pin_as_a_preference_not_an_error() {
        // A dev mirror's `port = 4321` is a browser handle, not a published
        // address — honoured when free, floated when taken, never fatal.
        let free = pick_free_port(LOOPBACK).unwrap();
        assert_eq!(
            EphemeralPorts
                .resolve_one(
                    "dev",
                    LOOPBACK,
                    PortSpec {
                        name: "http".into(),
                        pin: Some(free)
                    }
                )
                .unwrap(),
            free
        );

        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let taken = held.local_addr().unwrap().port();
        let got = EphemeralPorts
            .resolve_one(
                "dev",
                LOOPBACK,
                PortSpec {
                    name: "http".into(),
                    pin: Some(taken),
                },
            )
            .unwrap();
        assert_ne!(
            got, taken,
            "the local tier floats off a taken port rather than failing bring-up"
        );
    }

    #[test]
    fn the_local_tier_also_hands_two_names_two_numbers() {
        let resolved = EphemeralPorts
            .resolve_set(
                "dev",
                LOOPBACK,
                &[PortSpec::auto("http"), PortSpec::auto("wss")],
            )
            .unwrap();
        assert_eq!(resolved.len(), 2);
        assert_ne!(resolved["http"], resolved["wss"]);
    }

    #[test]
    fn a_zero_pin_still_reads_as_unpinned() {
        // The ephemeral sentinel a caller gets from an unset config value.
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        let spec = PortSpec {
            name: HTTP.into(),
            pin: Some(0),
        };
        let port = ledger.resolve_one("svc", LOOPBACK, spec.clone()).unwrap();
        assert_ne!(port, 0);
        assert_eq!(ledger.reserved_port("svc", HTTP), Some(port));
        assert_ne!(
            EphemeralPorts.resolve_one("svc", LOOPBACK, spec).unwrap(),
            0
        );
    }

    // ── The `PORT` / `PORT_<NAME>` env contract (R844-T13) ──────────────────

    #[test]
    fn a_single_listener_sees_port_and_port_http_as_one_number() {
        // The trivial case stays trivial: a workload reading `$PORT` (mesofact's
        // own project template does) and one reading `$PORT_HTTP` must not be
        // able to get two different answers.
        let resolved: BTreeMap<String, u16> = [(HTTP.to_string(), 4321)].into_iter().collect();
        let env = port_env(&resolved);
        assert_eq!(env.get("PORT").map(String::as_str), Some("4321"));
        assert_eq!(env.get("PORT_HTTP").map(String::as_str), Some("4321"));
        assert_eq!(env.len(), 2, "nothing else is published: {env:?}");
    }

    #[test]
    fn a_multi_listener_workload_sees_one_variable_per_name() {
        let resolved: BTreeMap<String, u16> = [
            (HTTP.to_string(), 8080),
            ("wss".to_string(), 8081),
            ("metrics".to_string(), 9090),
        ]
        .into_iter()
        .collect();
        let env = port_env(&resolved);
        assert_eq!(env.get("PORT_HTTP").map(String::as_str), Some("8080"));
        assert_eq!(env.get("PORT_WSS").map(String::as_str), Some("8081"));
        assert_eq!(env.get("PORT_METRICS").map(String::as_str), Some("9090"));
        // `http` is present, so the alias is too — and it aliases `http`, not
        // whichever name happens to sort first.
        assert_eq!(env.get("PORT").map(String::as_str), Some("8080"));
        // The three retired spellings are gone as producers.
        for retired in ["MF_PORT", "KAMAJI_BUNDLE_PORT"] {
            assert!(!env.contains_key(retired), "{retired} is retired: {env:?}");
        }
    }

    #[test]
    fn without_a_port_named_http_the_bare_alias_is_absent() {
        // An anonymous multi-port workload names nothing `http`
        // (`name_anonymous_ports`), and guessing one of several listeners is the
        // positional accident named ports exist to abolish. Absent is the honest
        // answer.
        let resolved = crate::name_anonymous_ports(&[8080, 9090]);
        let env = port_env(&resolved);
        assert!(!env.contains_key("PORT"), "must not guess: {env:?}");
        assert_eq!(env.get("PORT_8080").map(String::as_str), Some("8080"));
        assert_eq!(env.get("PORT_9090").map(String::as_str), Some("9090"));
    }

    #[test]
    fn an_anonymous_single_port_still_gets_the_bare_alias() {
        // One port *is* the one it serves on, so `name_anonymous_ports` calls it
        // `http` and the alias follows — this is the whole reason the two agree
        // on the name.
        let env = port_env(&crate::name_anonymous_ports(&[3000]));
        assert_eq!(env.get("PORT").map(String::as_str), Some("3000"));
        assert_eq!(env.get("PORT_HTTP").map(String::as_str), Some("3000"));
    }

    #[test]
    fn a_port_name_is_folded_into_something_a_shell_can_export() {
        // `PORT_WS-CONTROL` is not a variable name any shell can export, so a
        // manifest that spells a port that way would get a variable the workload
        // cannot read — the same as one that was never set.
        assert_eq!(port_env_var("ws-control"), "PORT_WS_CONTROL");
        assert_eq!(port_env_var("http"), "PORT_HTTP");
        assert_eq!(port_env_var("9090"), "PORT_9090");
        assert_eq!(port_env_var("gRPC.v2"), "PORT_GRPC_V2");
    }

    #[test]
    fn two_names_folding_to_one_variable_keep_the_first_in_name_order() {
        // Deterministic rather than last-write-wins. The allocator has already
        // rejected the collision that could lose a *port* (two specs one name);
        // this one can only lose a spelling.
        let resolved: BTreeMap<String, u16> = [("ws-1".to_string(), 5001), ("ws_1".to_string(), 5002)]
            .into_iter()
            .collect();
        let env = port_env(&resolved);
        assert_eq!(env.get("PORT_WS_1").map(String::as_str), Some("5001"));
        assert_eq!(env.len(), 1, "no bare PORT, nothing named http: {env:?}");
    }

    #[test]
    fn the_env_a_resolved_set_yields_is_the_set_the_allocator_returned() {
        // End to end on the real allocator rather than a hand-built map: what a
        // workload reads is what `resolve_set` handed back, not a number some
        // caller carried alongside it.
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        let resolved = ledger
            .resolve_set(
                "two-listener",
                LOOPBACK,
                &[PortSpec::http(), PortSpec::auto("wss")],
            )
            .unwrap();
        let env = port_env(&resolved);
        assert_eq!(env["PORT"], resolved[HTTP].to_string());
        assert_eq!(env["PORT_HTTP"], resolved[HTTP].to_string());
        assert_eq!(env["PORT_WSS"], resolved["wss"].to_string());
        assert_ne!(env["PORT_HTTP"], env["PORT_WSS"]);
    }
}

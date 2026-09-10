//! @yah:ticket(R426-F3, "Kamaji scope + ownership-list check; canonical 401/403 + WWW-Authenticate bodies")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T22:46:00Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R426)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426-F2)
//! @yah:handoff("Landed W159 Layer 2 (scope + ownership-list) and the canonical 401/403 wire shapes. New modules: `kamaji::auth::policy` (Requirement + enforce) and `kamaji::auth::deny` (Deny + From<VerifyError> + serialization). Both match W159 §Failure responses byte-for-byte — the 401 example and the 403 example in the doc are direct asserts in the test suite. Scope check exact-match per composition rule 3 (no `<category>:admin` implication tree); scopes-first, owns-second so a missing scope is reported even when the token also lacks the resource.")
//! @yah:handoff("Wire shapes: 401 Unauthorized for any token-side rejection (Malformed/MissingKid/UnknownKid/SignatureMismatch/Expired/BadIssuer/BadAudience/BadClaims all map to `Deny::invalid_token` with operator-curated short reasons — NOT raw error strings, to avoid aiding forgery probing). 403 Forbidden for scope/owns failures from policy::enforce. JSON body always carries `error` + optional `scope` + optional `resource` only — no `error_description` in body (W159: finer-grained reasons stay in the local audit journal). WWW-Authenticate is single-line (RFC 7230 deprecates obs-fold) with parameters in canonical order: realm, error, error_description?, scope?, resource_metadata.")
//! @yah:handoff("Helper: `AuthConfig::resource_metadata_url()` derives `{expected_aud}/.well-known/oauth-protected-resource` for use as the WWW-Authenticate `resource_metadata` parameter. F4 ticket lands the matching endpoint.")
//! @yah:handoff("Out of F3 scope (→ follow-on): the HTTPS server / JSON-RPC dispatch loop that actually invokes verify() then enforce() and serializes a Deny onto the wire. F3 lands data shapes + pure-function logic; the request handler that calls them is a later integration ticket.")
//! @yah:next("Sign-off: review `kamaji::auth::{policy,deny}` shape + run `cargo test -p kamaji --lib auth` (expect 39 auth-module passes, 127 total kamaji lib passes). Confirm the 401/403 examples in W159 §Failure responses match what `Deny::www_authenticate` + `Deny::json_body` emit byte-for-byte.")
//! @yah:verify("cargo test -p kamaji --lib auth")
//!
//! @yah:ticket(R426-F4, "Kamaji /.well-known/oauth-protected-resource endpoint")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-03T22:46:01Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R426)
//! @arch:see(.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md)
//! @yah:depends_on(R426-F1)
//! @yah:handoff("Landed the RFC 9728 protected-resource metadata shape as `kamaji::auth::metadata`. `ProtectedResourceMetadata` carries `resource` / `authorization_servers` / `scopes_supported` / `bearer_methods_supported`. `from_config(&AuthConfig)` derives `resource` from `expected_aud`, `authorization_servers` from `cheers_issuer` (both trim trailing slashes), publishes the full `SCOPE_VOCABULARY` const, and pins `bearer_methods_supported = [\"header\"]` (we only accept `Authorization: Bearer`, never query/form).")
//! @yah:handoff("SCOPE_VOCABULARY exported as a const &[&str] — the canonical W159 §Scope vocabulary list, 16 entries including the two service-only scopes (`ownership:write`, `audit:write`). RFC 9728 §`scopes_supported` is \"every scope the resource accepts\", which includes service-only scopes since yubaba + kamaji themselves present them at the wire — cheers's grant API is what gates them from user principals at issuance time, not kamaji's verifier.")
//! @yah:handoff("Out of F4 scope (→ follow-on integration ticket): the actual HTTPS route handler that mounts `to_json()` at `/.well-known/oauth-protected-resource`. F4 ships the data shape + serializer ready to drop into whatever HTTP framework the dispatch loop lands on (axum/hyper). `AuthConfig::resource_metadata_url()` (from F3) and this module compose: the WWW-Authenticate header points at the URL this endpoint serves.")
//! @yah:handoff("6 new unit tests green (full-vocab publish, trailing-slash trim, custom-scope override, JSON round-trip, RFC 9728 field-name presence, service-only scope advertisement). Total kamaji lib: 133 tests.")
//! @yah:next("Sign-off: review `kamaji::auth::metadata` shape + run `cargo test -p kamaji --lib auth::metadata` (expect 6 passes). Confirm `SCOPE_VOCABULARY` matches the W159 §Scope vocabulary list including the service-only scopes.")
//! @yah:verify("cargo test -p kamaji --lib auth::metadata")
//!
//! @yah:ticket(R592-T5, "E2E sibling-wire deploy regression net: real Container WorkloadSpec with ImageRef through the postcard UDS into dispatch")
//! @yah:at(2026-07-06T06:58:07Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R592)
//! @yah:next("Two layers: (1) kamaji-proto round-trip tests over EVERY Workload variant with realistic payloads (ImageRef string form reg/repo@sha256 included) — postcard encode/decode symmetry; (2) integration test that spins the kamaji-bin UDS server (fake or native backend) and drives Deploy/Probe/List/Stop/Drain through the sibling client with a full WorkloadSpec.")
//! @yah:next("This is the regression net ABOVE the R590-B3 fix (peer-owned — do not implement the fix here). If the fix chose the DTO route (option A in R590-B3), test the DTO boundary explicitly. The depends_on gates this ticket until that fix reaches review.")
//! @yah:next("Context: the original R406-T9 smoke only did GET /workloads — a real deploy carrying an ImageRef through postcard was never exercised. This ticket closes that gap class permanently.")
//! @yah:verify("cd oss/kamaji && cargo test -p kamaji-proto && cargo test -p kamaji-bin")
//! @yah:depends_on(R590-B3)
//! @yah:tier(Warrior)
//! @yah:handoff("DONE (verify-clean). Additive regression net, no renames, oss/kamaji only. Layer 1 (kamaji-proto codec, +4 tests): every YubabaToKamaji + KamajiToYubaba variant round-trips encode_frame/decode_frame; every workload_spec::Workload variant across Deploy (Container for_forge all-None + full spec, MesofactStatic w/ nested ImageRef, Almanac, StaticAsset w/ BlakeHash); string-pinned ImageRef (ghcr.io/..@sha256) parsed from JSON then ridden across postcard. kamaji-proto 24 pass. Layer 2 (NEW kamaji-bin/tests/sibling_wire_e2e.rs, 2 tests) drives the real kamaji::sibling::KamajiClient: (a) real serve_with_shutdown UDS server -> Deploy decodes + reaches dispatch (BackendRefused, asserts NOT decode-failed/postcard/WontImplement/DeserializeBadOption) + Probe/List/Stop/Drain round-trip; (b) scripted real-frame backend -> accepted deploy appears in List, server-side asserts name+ImageRef.digest+env survived. Default kamaji-bin has no containerd backend so real-accept uses the scripted half (ticket's documented fallback). Nothing #[ignore]. cargo test oss/kamaji all green, 0 fail, no new warnings.")
//!
//! @yah:relay(R599, "mesofact bundles: content-addressed distribution + kamaji JIT serving")
//! @yah:at(2026-07-06T11:19:35Z)
//! @yah:status(open)
//! @arch:see(.yah/docs/working/W272-mesofact-bundles-kamaji-jit-serving.md)
//!
//! @yah:ticket(R599-F4, "Mesofact workload variant carries {bundle_digest, runtime, lifecycle}; kamaji-bin dispatches it to the native backend (un-reject the InvalidSpec arm)")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-07-20T04:47:22Z)
//! @yah:phase(P1)
//! @yah:parent(R599)
//! @yah:depends_on(R599-F2)
//! @yah:next("F4 FOLLOW-UP (blocked on R599-F3 serve binary): wire the real native bundle backend into kamaji-bin ServerCtx — add Option<NativeRuntime> + a node bundle store (yah-mesofact-bundle features=store + yah-object-store + R2 creds/cache dir); deploy_mesofact_bundle then materialize_bundle (R599-F1) -> resolve serve bin from runtime (self=bundle bins/<triple>/serve, mesofact/<ver>=node runtime-asset cache) -> build WorkloadSpec (serve --bundle <dir> --listen <addr>) -> NativeRuntime.deploy_workload. Needs a mesh assignment path the UDS server doesn't have today.")
//! @yah:next("R599-F6: the OnDemand JIT lifecycle (kamaji holds listen socket, forks on first connection via fd-passing, reaps after idle_ttl) consumes BundleLifecycle::OnDemand.")
//! @yah:next("R599-F8: services-tab sync arm sets serve_bundle {digest,runtime,lifecycle} on the deployed workload after publishing via cloud reconciler::bundle_store::publish_bundle_to_r2.")
//! @yah:handoff("LANDED (data model + admission, tests green). TWO halves: (1) workload-spec (oss/yah-base) — MesofactStaticWorkload grows optional `serve_bundle: Option<MesofactServeBundle>`; new MesofactServeBundle { digest: BlakeHash, runtime: String, lifecycle: BundleLifecycle } + BundleLifecycle { KeepAlive | OnDemand { idle_ttl } }. runtime is a plain String (wire-mirrors yah_mesofact_bundle::BundleRuntime) so workload-spec stays free of the bundle crate's non-TS/schema newtypes. (2) kamaji-bin server.rs deploy_workload — MesofactStatic WITH serve_bundle is admitted + routed to new deploy_mesofact_bundle(); WITHOUT it stays InvalidSpec (yubaba's build reconciler). Almanac/StaticAsset still InvalidSpec.")
//! @yah:handoff("CRITICAL gotcha for anyone adding Option fields to a postcard-wire workload-spec type: NO skip_serializing_if. postcard is non-self-describing/positional — skip_serializing_if omits the byte on serialize while decode still expects it, breaking kamaji-proto codec round-trip. serve_bundle mirrors ssr_runtime: #[serde(default)] + #[ts(optional=nullable)], always encoded. (I hit + fixed this: deploy_every_workload_variant_round_trips failed until I dropped skip_serializing_if.)")
//! @yah:handoff("SCOPE: this is the data model + un-rejection SEAM. deploy_mesofact_bundle currently returns BackendRefused (workload RECOGNIZED, not InvalidSpec — same idiom as Container-without-containerd) because the native bundle backend isn't wired into the UDS ServerCtx yet: NativeRuntime.deploy_workload takes a WorkloadSpec + MeshAssignment and ServerCtx holds no native backend today, AND the serve binary is R599-F3 (doesn't exist). Regen ran: export-ts (packages/yah/workload-spec/index.ts) + xtask emit-schemas (.yah/schema/workload.toml.schema.json); drift test green. Touched peer-owned kamaji-proto/codec.rs (1-line serve_bundle:None in a round-trip fixture) + kamaji-bin server.rs test literal.")
//! @yah:verify("cd oss/yah-base && cargo test -p yah-workload-spec (51 lib + round_trip/semantic/shape all pass)")
//! @yah:verify("cargo run -p yah-workload-spec --bin export-ts && cargo run -p xtask -- emit-schemas && cargo test -p xtask (drift green)")
//! @yah:verify("cd oss/kamaji && cargo test -p kamaji-proto (25 pass) && cargo test -p kamaji-bin --lib (193 pass, incl deploy_serve_bundle_mesofact_static_is_admitted_not_invalid_spec)")
//!
//! @yah:ticket(R599-F10, "Keep-alive native bundle backend: kamaji-bin forks + supervises mesofact-serve --bundle --listen (wire deploy_mesofact_bundle → NativeRuntime)")
//! @yah:status(review)
//! @yah:at(2026-07-20T18:12:24Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R599)
//! @yah:next("Unblocks R599-T5, but T5 additionally needs a kamaji BUILT WITH --features bundle-serving and rolled onto raft voters node1(south)+node3(east) — the deployed kamaji is 0.8.17/Jul1 and predates all R599. That control-plane roll is R608/W275 territory.")
//! @yah:next("Follow-up (file if/when needed): Deploy carries a MeshAssignment so bundles can bind the mesh IP plane and a node can host more than one bundle; and structured Drain for native workloads.")
//! @yah:handoff("LANDED (both halves), independently verified by the supervising session. (1) BACKEND: new `bundle-serving` cargo feature on kamaji-bin; `BundleBackend` (store + cache_dir + cache_budget + port) hangs off ServerCtx via `with_bundle_backend`; `deploy_mesofact_bundle` now delegates to `deploy_bundle_keepalive` — materialize the W272 bundle via BundleCache::ensure (on spawn_blocking so a cold R2 fetch can't park the dispatch loop) → resolve serve bin (runtime=self → <dir>/bins/<triple>/serve; mesofact/<ver> → <cache>/runtimes/<runtime>/<triple>/serve) → fork `mesofact-serve --bundle <dir> --listen 127.0.0.1:<port>` under the kamaji-crate NativeRuntime. List merges native bundle workloads; Stop routes to NativeRuntime::teardown_workload. Cross-workspace deps added as version deps + [patch.crates-io] entries in oss/kamaji/Cargo.toml (yah-object-store, yah-mesofact-bundle/store), mirroring the existing yah-workload-spec bridge.")
//! @yah:handoff("(2) BINARY WIRING: main.rs gained `--bundle-cache-dir` (env KAMAJI_BUNDLE_CACHE_DIR) and `--bundle-port` (env KAMAJI_BUNDLE_PORT); build_ctx constructs R2ObjectStore + BundleBackend and calls with_bundle_backend when configured, warns clearly when not, and hard-errors if the bundle flags are passed to a binary built WITHOUT the feature. R2 SECRETS ARE ENV/VAULT ONLY — never argv (R2ObjectStore::from_vault), and its blocking reqwest client is constructed off the async runtime. Help text + ABOUT updated. The default (no-feature) build is unchanged and still returns a precise BackendRefused telling the operator to rebuild with --features bundle-serving.")
//! @yah:handoff("PROCESS NOTE: implemented by a dispatched Warrior courier (session:a3c8a82d) under supervision of session:e17c479a. Supervisor re-ran every verify command independently rather than trusting the courier's report.")
//! @yah:verify("cargo build --manifest-path oss/kamaji/Cargo.toml -p kamaji-bin (no features — clean, only the pre-existing PidfdReaperHandle dead-code warning)")
//! @yah:verify("cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji-bin --features bundle-serving --lib (196 pass, was 193; new: bundle_serving::keepalive_deploy_forks_and_appears_in_list, ::ondemand_deploy_refuses_as_r599_f6, ::missing_runtime_asset_is_a_clear_error)")
//! @yah:verify("cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji-proto (25 pass)")
//! @yah:gotcha("DRAIN IS NOT WIRED for bundle workloads — deliberate: the NativeRuntime single-owns the child, so registering a pidfd DrainableHandle would double-own the process and race the supervisor's reaper. A Drain of a bundle workload returns DrainAck{accepted:false,\"unknown workload\"}; teardown is via Stop. Documented in the deploy_mesofact_bundle doc comment. Wiring structured drain for native workloads is a follow-up if/when it's needed.")
//! @yah:gotcha("BIND IS LOOPBACK, ONE BUNDLE PER NODE: listens on 127.0.0.1:<port> (DEFAULT_BUNDLE_PORT=8080), mirroring the existing passway→127.0.0.1:8080 testbed shape. MesofactServeBundle carries no port and the UDS Deploy carries no MeshAssignment, so mesh-IP-plane binding + multi-bundle-per-node needs Deploy to carry a MeshAssignment — that is the follow-up, not done here.")
//! @yah:gotcha("OnDemand/JIT still refuses cleanly (points at R599-F6) — out of scope by design.")
//!
//! @yah:ticket(R599-B11, "GET /workloads double-lists a bundle workload: stale Pending registry row alongside the Running native row")
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:at(2026-07-22T18:56:18Z)
//! @yah:parent(R599)
//! @yah:severity(low)
//! @yah:tier(Thief)
//! @yah:gotcha("Observed live on east 2026-07-21 immediately after the first successful bundle deploy: GET http://100.64.0.3:7443/workloads returns TWO rows for the same workload — {id:'yah-marketing', mesh_ident:null, pid:null, state:'Pending'} AND {id:'yah-marketing', mesh_ident:'yah-marketing', pid:67749, state:'Running'}. The Running row is correct. R599-F10's List merges native bundle workloads with the in-memory registry, and the registry's admission-time Pending row is never reconciled away once the native backend reports the process Running, so the merge emits both.")
//! @yah:next("OPS FOLLOW-UP (not code, and NOT done by this ticket): the stale containerd container named yah-marketing still exists on east. This fix makes /workloads report correctly despite it, but the container should still be reaped — it holds the id and will keep tripping the new warn!. This is the residue R599-T5 (delete the nginx/tar-pipe/python stand-ins) did not remove; check whether T5's cleanup missed containerd containers generally.")
//! @yah:next("The ticket's verify (\"after a bundle deploy, GET /workloads returns exactly one row\") was NOT run against the live cluster — no node access from this session. It is covered by unit tests reproducing the observed row shape. Re-confirm against east on the next deploy.")
//! @yah:handoff("FIXED, but the ticket's DIAGNOSIS WAS WRONG — read this before reviewing. The phantom row does NOT come from the registry. Evidence: (1) Registry.workloads is never written anywhere in kamaji-bin (only the field decl + list()'s clone) — the registry contributes ZERO rows to List; insert_probe, the only registry write a bundle deploy makes, touches `probes`, not `workloads`. (2) runtime_state_to_entry ALWAYS sets mesh_ident: Some(..), so it cannot emit the observed mesh_ident:null. (3) containerd.rs list() renders a container that exists with NO TASK as exactly {state: Pending, pid: None} with mesh_ident: labels.get(\"yah.mesh-ident\") → None when unlabelled. That is the observed row byte-for-byte. The phantom is a STALE CONTAINERD CONTAINER named yah-marketing — a leftover of the pre-bundle nginx stand-in — concatenated with the live native bundle row.")
//! @yah:handoff("FIX (oss/kamaji/crates/kamaji-bin/src/server.rs): new dedupe_workload_entries() + liveness_rank(), applied to the merged entries in the List arm. One row per workload id, keeping the most-live row and preserving first-seen order. Rank is (pid.is_some(), state) — a backend that can name a running process is authoritative over one that only knows a record exists. Deliberately liveness-based, NOT source-priority, so it stays correct regardless of which runtimes are compiled in or what order the merges run. WorkloadState is #[non_exhaustive]; an unknown future state ranks with Pending and so can never shadow a live pid.")
//! @yah:handoff("Also emits a warn! whenever a duplicate id is collapsed (both rows' state+pid). Deliberate: the dedupe alone would make a genuinely-stale container INVISIBLE, which trades a cosmetic bug for a silent one. The log keeps the operational signal.")
//! @yah:handoff("VERIFIED: 4 new unit tests reproduce the exact east 2026-07-21 shape (stale Pending/null-pid/null-mesh_ident vs Running/pid 67749) plus order-independence, distinct-id preservation, and pid-less tie-breaking. kamaji-bin lib 197 pass; full oss/kamaji workspace green, 0 failures; clippy clean; --features bundle-serving compiles.")
//! @yah:verify("cd oss/kamaji && cargo test -p kamaji-bin --lib dedupe (4 pass) && cargo test (workspace green)")
//! @yah:verify("On the next east bundle deploy: GET http://100.64.0.3:7443/workloads returns exactly one yah-marketing row with the correct pid + Running state; kamaji logs a 'duplicate workload id across backends' warn while the stale container survives")
//!
//! @yah:ticket(R626-F1, "Wire kamaji's existing docker/OrbStack backend into kamaji-bin (ServerCtx + Deploy/Stop/List routing)")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-07-23T02:25:58Z)
//! @yah:phase(P1)
//! @yah:parent(R626)
//! @yah:next("R626-F2 (migrate pond's per-slot reconcilers onto kamaji Deploy/Stop) is now unblocked — the backend it needs exists and is proven. Note pond currently drives its own docker via yubaba's runtime layer; F2 is about pointing those reconcilers at a kamaji that owns the daemon.")
//! @yah:next("Follow-up (not filed — small, and F2 may subsume it): thread a real MeshAssignment through the UDS Deploy so container AND bundle workloads can bind the mesh IP plane instead of the inlined loopback sentinel. Wanted by both this ticket and R599-F10.")
//! @yah:next("Do NOT add tag:build-worker to us-west-015 on the strength of this ticket alone — that still needs this node on 0.8.20 and a docker daemon reachable by the `yah` account (this was all verified as the `leif` account).")
//! @yah:handoff("LANDED + verified live against OrbStack 29.4.0. (1) BACKEND (oss/kamaji/crates/kamaji/src/docker.rs): docker.rs was complete but had never run wired — the R626 assumption is now DISCHARGED by a new live test (crates/kamaji/tests/docker_live.rs, 5 tests: deploy->inspect->list->stop round-trip, exited-container reports Failed with no pid, resolve/teardown by either key, unlabelled containers are not adopted, teardown idempotence). Fixed while there: task_pid was hardcoded 0 with a doc comment claiming 'Docker CLI doesn't surface the host PID' — it does, via .State.Pid; deploy now returns the real pid. New DockerWorkload {state, pid, workload_id} + list_workloads_detailed() carries the pid in the SAME docker inspect round-trips list_workloads already made; Kamaji::list_workloads now delegates to it.")
//! @yah:handoff("(2) WIRING (kamaji-bin): new `docker-integration` cargo feature (= dep:kamaji + kamaji/docker-integration, no new Rust deps — shells out). ServerCtx grows `docker: Option<DockerRuntime>` + with_docker(), mirroring the containerd/bundle Option<Backend> pattern. Deploy{Container} extracted into deploy_container(): containerd first when configured (a node with a containerd socket is a fleet node; its docker daemon is the developer's), else docker, else a build-aware BackendRefused from no_container_backend_error() that names each backend as 'not compiled in' vs 'compiled but unconfigured' — a rebuild and a restart-with-flags are different fixes. List merges docker rows via docker_workload_to_entry (joins the existing R599-B11 dedupe safely, and carries a real pid so it ranks on liveness rather than losing as pid-less). Stop routes to docker teardown.")
//! @yah:handoff("(3) BUG FOUND AND FIXED IN THE WIRING ITSELF — R590-B9 bites here. The sibling client sends id = spec.name (`forge-abc`) but the docker backend NAMES containers by mesh identity (`forge.abc`). Keying Stop on the id would find nothing, Ack, and leave the container running forever — a silent supervision leak. Fix: deploy stamps a `yah.workload_id` label (WORKLOAD_ID_LABEL), and new resolve()/teardown_by_key() accept EITHER key (direct inspect fast path, then a label scan). Recorded on the daemon rather than in an in-memory map so a kamaji restart can't lose it. List now reports id=workload_id + mesh_ident=identity, matching containerd's split so the two backends' rows are comparable in the dedupe. PROVEN: reverting teardown_by_key makes deploy_list_stop_through_kamaji_against_live_docker fail on 'Stop must actually remove the container from the daemon'.")
//! @yah:handoff("(4) BINARY (main.rs): --docker (ambient DOCKER_HOST) / --docker-host URL, env KAMAJI_DOCKER=1|<host>. Deliberately NOT keyed off a bare $DOCKER_HOST — nearly every dev host sets it and a supervisor must not adopt a daemon nobody asked it to supervise. Attach health-checks at startup and hard-errors (exit 1, verified) rather than failing on the first deploy; --docker against a no-feature build hard-errors like the bundle flags do. ABOUT + help text updated.")
//! @yah:verify("cargo test -p kamaji-bin -p kamaji --features docker-integration → kamaji-bin lib 200 pass (was 197), kamaji lib 52, docker_live 5, docker_backend_e2e 2. All green.")
//! @yah:verify("cargo test --workspace (default build) → all green, 197 kamaji-bin lib, unchanged behaviour with the feature off")
//! @yah:verify("cargo test -p kamaji-bin --features docker-integration,bundle-serving → 203 lib pass; cargo check --features containerd-integration,docker-integration --all-targets → clean (both backends compiled together)")
//! @yah:verify("cargo clippy -p kamaji -p kamaji-bin --features docker-integration --all-targets → clean (only pre-existing pidfd events_tx + cheers-mock redundant-closure warnings)")
//! @yah:verify("oss/yubaba: cargo check -p yubaba --features docker-integration → clean (yubaba forwards the kamaji feature)")
//! @yah:verify("LIVE BINARY: ./kamaji --socket /tmp/r626.sock --docker → 'docker backend attached docker_host=<inherited> version=29.4.0' + UDS bound; --docker-host unix:///nonexistent/docker.sock → actionable error, exit 1")
//! @yah:gotcha("The docker backend NAMES containers by mesh identity but yubaba ADDRESSES workloads by id, and for forge runs those differ (`forge.abc` vs `forge-abc`, R590-B9). Always reach for resolve()/teardown_by_key() when you hold a workload id — Kamaji::teardown_workload takes a MeshIdent and will silently no-op on an id. Containers deployed before this ticket carry no yah.workload_id label; they fall back to the identity, which is correct for every workload whose name and identity agree (i.e. everything but forge).")
//! @yah:gotcha("Deploy carries no MeshAssignment over the UDS (the same gap R599-F10 recorded for bundles), so deploy_container passes MeshAssignment::inlined(127.0.0.1). Docker uses it only for the yah.mesh_ip label + YAH_MESH_IP env, and pond has no mesh IP plane — but a workload that actually needs its mesh IP will read loopback. Threading a real assignment through Deploy is the follow-up.")
//! @yah:gotcha("When BOTH containerd and docker are configured, containerd wins Deploy{Container} — but Stop and List still route to BOTH (teardown is idempotent, and a node can hold containers from either). That asymmetry is deliberate: you must be able to stop what a previous configuration started.")
//!
//! @yah:ticket(R746-F1, "Node-side stock runtime asset: stage and resolve runtimes/mesofact/VER/TRIPLE/serve so vanilla bundles can serve")
//! @yah:status(review)
//! @yah:at(2026-08-12T02:55:06Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R746)
//! @yah:next("THE gap. assemble.rs:145 says it plainly: nothing currently stages runtimes/RUNTIME/TRIPLE/serve on a node, so a vanilla bundle assembles fine and then has nothing to exec. W272 section 2 names the cache layout: kamaji state dir holds bundles/DIGEST/... beside runtimes/mesofact/VER/TRIPLE/serve, LRU by digest.")
//! @yah:next("Scope: when a materialized bundle's manifest carries BundleRuntime::Mesofact { version }, resolve the serve binary from the node runtime cache, fetching it from the CDN on a miss (the artifact R560-T9 publishes), then fork it the same way the self-contained arm forks bins/TRIPLE/serve today (R599-F10's NativeRuntime path).")
//! @yah:next("Verify the fetch is content-addressed and checked before exec — blake3 against the published manifest. A runtime binary fetched over the network and exec'd unverified is a strictly worse trust posture than the self-contained bundle it replaces, whose bytes are covered by the bundle digest.")
//! @yah:verify("Two vanilla bundles at the same runtime version deployed to one node fetch the serve binary ONCE — the second deploy is a cache hit. That sharing is the whole point; a per-bundle copy would be the self-contained shape wearing a different manifest.")
//! @yah:verify("A bundle naming a runtime version the node cannot fetch fails the deploy loudly, naming the version and the URL it tried. It must not fall back to any other binary on the box.")
//! @yah:assumes("Tier: Warrior — crosses the kamaji/bundle-store boundary, adds a network fetch plus a verification step to the deploy hot path, and the cache-eviction interaction with bundles/ LRU is a design call, not a transcription.")
//! @yah:next("GENERALIZE THE CACHE KEY NOW, not later (W272 section 7). Custom runtimes are org/project-namespaced and get cached the same way stock ones do, so the node path should be runtimes/NAMESPACE/NAME/VER/TRIPLE/serve rather than the mesofact-specific runtimes/mesofact/VER/TRIPLE/serve. Stock resolves as the unnamespaced case. Cheap while nothing has been written to disk on a node; a migration once it has.")
//! @yah:next("TWO BACKENDS, ONE EXPRESSION. A custom runtime is either a static musl binary kamaji sandboxes (R2 runtime-asset tier, content-addressed, LRU — the model this ticket builds) or literally a container (cr.yah.dev, the digest-pinned registry R560-T7 already publishes builder images to). The service declares a requirement; which backend satisfies it is a resolution detail. Do not build a third store.")
//! @yah:handoff("LANDED. Vanilla bundles resolve and serve. NEW oss/yah-base/crates/mesofact-bundle/src/runtime.rs: RuntimeRef (types-only) parses both name/ver and ns/name/ver, validates every segment against traversal, and yields the cache path plus the by-name object key. Under the store feature, publish_runtime_asset + ensure_runtime_asset move the binary through the SAME blobs/blake3 space bundles use.")
//! @yah:handoff("RESOLUTION SITE: kamaji server.rs materialize_and_resolve_serve. The self arm is unchanged; the vanilla arm now parses a RuntimeRef and calls ensure_runtime_asset on the blocking pool (a cold fetch is a ~70MB download and must not park the dispatch loop). Resolution is purely under cache_dir: no PATH lookup, no scan, no reuse of another bundles bins/.")
//! @yah:handoff("TRUST: the by-name object runtimes/NS/NAME/VER/TRIPLE.toml names the binarys blake3; the bytes come from blobs/BLAKE3 and are verified, chmod 0755, and atomically renamed into place. Nothing unverified is ever visible at a forkable path. This is the property a self-contained bundle got free from the bundle digest, and vanilla must not be a weaker posture than the shape it replaces.")
//! @yah:handoff("CACHE KEY GENERALIZED NOW as the ticket asked: runtimes/NAMESPACE/NAME/VER/TRIPLE/serve, stock being the unnamespaced case. Nothing had been written to a node, so the migration never had to happen. BundleRuntime in the manifest still parses self and mesofact/VER only; F5/F6 own widening that field, and nothing on disk moves when they do.")
//! @yah:handoff("DISCOVERED WORK, done in this pass. (1) yah-object-store gained a defaulted ObjectStore::locate(key) returning the URL for R2 and the http origin, the bare key otherwise, because a dyn ObjectStore holder cannot reconstruct the origin and verify #2 demands the URL be in the message. (2) NEW CLI verb yah cloud bundle publish-runtime: without a publish half the fetch had nothing to fetch, and T3 needs it. (3) Corrected four doc comments that asserted nothing stages the runtime asset, which this ticket disproved: assemble.rs vanilla+self docs, BundleCommands::Build help, and the vanilla assembly note printed by yah cloud bundle build.")
//! @yah:handoff("DESIGN CALL worth knowing, and it diverges from the tickets wording. The ticket said fetch from the CDN, the artifact R560-T9 publishes. R560-T9 publishes gzipped TARBALLS at installer release keys for install.sh; a node needs a bare binary at a content-addressed key. Untarring installer artifacts on the node would couple the deploy path to the installers naming. So the asset lives in the bundle store instead: same bucket, same blobs space, and in production the node already reads that store over https://cdn.yah.dev via HttpReadOnlyObjectStore (kamaji-bin/src/main.rs bundle-origin), so it IS the CDN fetch the ticket asked for. R560-T9s output (the built musl binary) feeds publish-runtime as its input.")
//! @yah:cleanup("Runtime assets are deliberately outside the bundle LRU: BundleCache only scans bundles/, so nothing counts or reclaims runtimes/. That is correct for now (one asset backs every resident serve process at that version), but assets accumulate one per version x triple forever. An access marker is touched on every resolve so a future runtime-tier reclaim has recency to work from; wire the reclaim when a node has enough versions for it to matter.")
//! @yah:next("R746-T3 (yah-marketing flip) is unblocked on the node side. Remaining input is a real musl mesofact binary from R560-T8/T9, then one yah cloud bundle publish-runtime call per node triple before the first vanilla sync.")
//! @yah:next("NOT DONE, and deliberately not: the manifest runtime field still parses self and mesofact/VER only. R746-F5/F6 own the constraint expression. The node already resolves the general namespaced form, so widening the parse moves nothing on disk.")
//! @yah:verify("cargo test -p yah-mesofact-bundle --features store: 41 pass, 0 fail (10 new in runtime::tests). Types-only build also green: --no-default-features 25 pass.")
//! @yah:verify("cargo test -p kamaji-bin --features bundle-serving --lib: 221 pass, 0 fail (4 new in server::tests::bundle_serving).")
//! @yah:verify("cargo test -p yah-object-store: 31 pass. cargo check -p yah: clean. cargo test -p yah --lib cloud::: 114 pass, 0 fail.")
//! @yah:verify("VERIFY #1 (sharing is the whole point) is pinned by two_vanilla_bundles_at_one_version_fetch_the_runtime_once: two distinct vanilla digests deployed to one node cache, counting GETs of the runtime blob specifically. Asserts exactly 1.")
//! @yah:verify("VERIFY #2 (fail loudly, no fallback) is pinned by an_unfetchable_runtime_version_fails_naming_version_and_location: the failed DeployStatus detail must contain the version, the triple, and the key it looked for; plus versions_do_not_alias proves a cached 0.8.19 never stands in for an unpublished 0.8.20.")
//! @yah:verify("Content-addressed check before exec is pinned by tampered_bytes_are_refused_and_never_written (swap the blobs bytes under its address -> HashMismatch, and the resolved path does not exist afterwards) and a_misfiled_asset_manifest_is_refused.")
//! @yah:verify("cargo xtask install: /Users/leif/.local/bin/yah, build id yah 0.8.22+cf7a7291-dirty. yah cloud bundle publish-runtime --help renders. NOTE the install printed a W298 SUSPECT RESULT (two peer edits landed mid-build, in files unrelated to this ticket) - the binary installed and the verb works, but the build ran against a tree that moved.")
//! @yah:gotcha("The published runtime asset must be the WHOLE mesofact binary, not a serve-only build. kamaji forks it as BIN serve --bundle DIR --listen ADDR (W174 made mesofact subcommand-driven), so a binary taking --bundle as argv[1] exits on an unknown argument before it ever binds and kamaji logs nothing useful. The publish-runtime help says so; the file is named serve because that is the slot, not the subcommand.")
//!
//! @yah:ticket(R755-B5, "kamaji does not resume keep-alive bundle workloads after a restart — every control-plane roll takes the node's sites down until an apply")
//! @yah:status(review)
//! @yah:at(2026-08-28T18:13:38Z)
//! @yah:assignee(agent:user-custom-char-gul2)
//! @yah:parent(R755)
//! @yah:severity(high)
//! @yah:next("Persist the admitted bundle spec beside the state dir (or replay from yubaba's record) and re-spawn keep-alive serve_bundle workloads on kamaji start, so a control-plane roll is a restart and not an undeploy. Then delete release-wizard.toml's republish-site-after-roll step and roll-node.sh's apply hint — their existence is the regression test.")
//! @yah:verify("scripts/roll-node.sh us-east-001 (or a systemctl restart kamaji) ends with all three yah-marketing workloads Running and passway-test.yah.dev 200 with NO apply in between.")
//! @yah:gotcha("MEASURED LIVE on us-east-001 2026-08-28 during R755-T4's roll onto published 0.8.28, and again on the rollback to the hand-cut 0.8.23 build: systemd stop SIGKILLs the serve/almanac-feed/revalidate children (kamaji.service journal), the new kamaji logs only 'containerd backend attached' / 'bundle backend attached' / 'UDS listening', and GET /workloads then lists only the stale Pending registry row (R599 gotcha above) — yah-marketing-feed and yah-marketing-revalidate vanish entirely. passway-test.yah.dev answered 503 for ~5 minutes until `yah cloud apply --env cloud --service yah-marketing` re-admitted all three.")
//! @yah:gotcha("WHY: /var/lib/yah/kamaji/bundles/state/<id>/ holds only stdout.log/stderr.log — there is no persisted deploy spec for the bundle backend to replay, and grep finds no resume/reattach path in kamaji-bin (native.rs, server.rs). So a roll's 'restart kamaji' is a silent undeploy. release-wizard.toml now runs a second `yah cloud apply` after roll-the-fleet and roll-node.sh's FAIL names the apply as the fix — both are workarounds for this, not the fix.")
//! @yah:handoff("FIXED in oss/kamaji/crates/kamaji-bin: a serve-bundle Deploy is now persisted at admission as <state_dir>/deploys/<id>.json (BundleDeployRecord = id + MesofactServeBundle + revalidate receiver + MeshAssignment, atomic tmp+rename via BundleBackend::record_deploy); Stop removes it (forget_deploy, idempotent); ServerCtx::resume_bundle_workloads() reads every record and replays it through the SAME post-Ack task a fresh Deploy uses (spawn_bundle_run, factored out of deploy_mesofact_bundle), so a resumed deploy materializes/resolves/forks and reports through DeployStatus exactly like a new one. main.rs calls it after build_ctx and before the UDS answers. A record that cannot be written refuses the deploy (BackendRefused) rather than admitting something the next restart would drop; an unreadable record is logged and skipped so one corrupt file cannot keep other sites down.")
//! @yah:handoff("Keep-alive AND on-demand lifecycles are recorded and resumed (the lifecycle lives inside the recorded bundle). records_dir is a sibling of the native supervisor's per-ident capture dirs; NativeRuntime never scans state_dir, so deploys/ cannot be mistaken for a workload.")
//! @yah:handoff("NOT ON THE FLEET YET: us-east-001 runs the published 0.8.28, which predates this. release-wizard.toml's republish-site-after-roll step and roll-node.sh's FAIL hint stay as workarounds, with comments now pointing here and saying to delete them once every node runs a kamaji newer than 0.8.28.")
//! @yah:handoff("Not committed (git writes are the operator's): oss/kamaji/crates/kamaji-bin/src/{server.rs,main.rs,lib.rs}, .yah/qed/release-wizard.toml, scripts/roll-node.sh (comment-only on the last two).")
//! @yah:verify("cargo test -p kamaji-bin --features containerd-integration,native-exec,bundle-serving (oss/kamaji) = 257 lib tests passed + all integration binaries green. New: bundle_serving::a_recorded_keepalive_bundle_is_resumed_by_a_fresh_kamaji (deploy under ctx A, tear the child down as systemd would, drop A, new ctx B over the same state dir resumes 1 record, DeployStatus reaches Running, List shows it Running; Stop removes the record and a third ctx resumes 0) and bundle_serving::an_unreadable_record_is_skipped_not_fatal.")
//! @yah:verify("cargo clippy -p kamaji-bin --features containerd-integration,native-exec,bundle-serving --all-targets: no diagnostics in the changed code (two pre-existing test-line unwrap_or warnings at server.rs:6130-6131 untouched).")
//! @yah:verify("The ticket's own verify (systemctl restart kamaji on us-east-001 brings all three yah-marketing workloads back with no apply) needs a release carrying this fix rolled onto the node first; not yet run.")
//!
//! @yah:ticket(R876-B5, "hotship's bundle-serve activation is not tenant-scoped: shipping one tenant re-forks every mesofact serve on the node")
//! @yah:at(2026-09-09T08:51:04Z)
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R876)
//! @yah:severity(high)
//! @yah:next("Tier: Warrior — the defect is understood and located, the fix is a narrower process match; what makes it non-trivial is choosing the right identity to match on, not finding the bug. FILED BY THE AUTHOR OF THE DEFECT (2026-09-08 chat session): I wrote the bundle-serve arm and did not scope it. It has already run twice against production.")
//! @yah:next("THE DEFECT. scripts/hotship.sh's `bundle-serve` activation does `sudo pkill -TERM -f \"<ndir>/runtimes/mesofact/\"`. That path is the RUNTIME ASSET, which is shared by every bundle naming the same runtime — it is the whole point of the shared runtime tier (R746-F1, W272 §2/§7). So the pattern matches every mesofact serve process on the box regardless of which tenant or service it belongs to. Measured on us-east-001 2026-09-09: three matches — yah-marketing's bundle (:34759), its revalidate tier (:40995), and NOISETABLE's bundle (:41507, tenant 2, R870). A hot ship aimed at yah.dev re-forks a second tenant's site, with the same ~2s of 502 R876-T1 measured on the apex, and says nothing about having done so.")
//! @yah:next("THE FIX IS A NARROWER MATCH, BUT PICK THE IDENTITY DELIBERATELY. The serve argv carries `--bundle <ndir>/bundles/<digest>` (and the revalidate tier carries the bundle path plus `--allow-route`), so the bundle DIGEST is available and is per-service. Options worth weighing rather than grabbing the first: (a) match on the bundle digest(s) belonging to the named service, which needs hotship to learn which service it is shipping — today `--binaries mesofact` names a RUNTIME, not a workload; (b) ask kamaji which workloads use the runtime and signal by pid; (c) add a `--service` param to the hotship arm and refuse to activate without one. Note (a)/(c) change the arm's argument shape: a runtime asset is shared by construction, so \\\"hot-ship mesofact\\\" is genuinely ambiguous about blast radius and the CLI should probably stop pretending otherwise.")
//! @yah:gotcha("THE INSTALL HALF IS SHARED ON PURPOSE AND MUST NOT BE 'FIXED' WITH THE ACTIVATION HALF. One runtime asset backs every tenant naming that version, so replacing the file at `<ndir>/runtimes/mesofact/<ver>/<triple>/serve` necessarily changes the bytes all of them will fork next. That is correct and unavoidable for a runtime tier — the bug is only that ACTIVATION re-forks tenants nobody asked about, converting a shared-bytes change into a shared-outage change. Scoping activation leaves an un-activated tenant running old bytes off its open inode until it next restarts, which is the same staged state `--no-restart` already produces and is the honest behaviour; say so in the output rather than silently.")
//! @yah:verify("Reproduce before fixing, on us-east-001 or any node running two tenants off one runtime version: `pgrep -af \"/var/lib/yah/kamaji/bundles/runtimes/mesofact/\"` should list yah-marketing's two processes AND noisetable's. After the fix, a `--binaries mesofact` ship scoped to yah-marketing must leave noisetable's pid unchanged — assert on the pid, not on a log line. R876-T1's probe (scripts/hotship-probe.sh) points at yah.dev; point a second one at noisetable's hostname for the same run and it should show zero non-200s.")
//! @yah:handoff("FIXED, and the arm's argument shape changed as intended (option (c)+(a), no compatibility fallback — CLAUDE.md \"break it, don't tape it\"). scripts/hotship.sh gains `--services LIST`; .yah/qed/hotship.toml gains a `services` param (required=false, default=\"\", wired into build-and-ship). REFUSAL: if --binaries names a bundle-serve app and restart is on, an absent --services is a hard exit(1) BEFORE anything is built or shipped, with the `ls &lt;node&gt;:/var/lib/yah/kamaji/bundles/state/deploys/` command that lists the candidates. The converse is also an error: --services with no bundle-serve app in --binaries scopes nothing and says so. --no-restart needs no scope (it activates nothing). Service ids are charset-validated ([A-Za-z0-9._-] plus commas) because they are interpolated into a remote shell script.")
//! @yah:handoff("THE RESOLVER: service -&gt; bundle digest -&gt; pids, entirely from files already on the node, no kamaji round-trip (option (b) rejected as too heavy for a bash script). kamaji records each deploy at &lt;ndir&gt;/state/deploys/&lt;svc&gt;.json (BundleBackend::record_deploy, oss/kamaji/crates/kamaji-bin/src/server.rs:624) carrying `bundle.digest`; that digest appears in every serve argv the service owns — the bundle tier as `--bundle &lt;ndir&gt;/bundles/&lt;digest&gt;`, the revalidate tier as the same path positionally plus --allow-route — so ONE digest covers a service and its revalidate tier, which is the correct grouping. Matching is `pgrep -f \"^&lt;ndir&gt;/runtimes/&lt;rt&gt;/.*&lt;digest&gt;\"`, anchored so the ssh command's own cmdline cannot self-match. It then SIGNALS BY PID, not by pattern: the pid set is resolved once, printed, and killed, so what the run reports and what it kills cannot drift apart.")
//! @yah:handoff("BOTH REQUIRED BEHAVIOURS ARE EXPLICIT, not silent. (1) What was NOT restarted: every serve process under the runtime path that is out of scope is listed as `pid &lt;n&gt; &lt;listen&gt; bundle &lt;digest12&gt; service &lt;owner&gt;` under a header saying it keeps serving the OLD bytes off its already-open inode until it next restarts (owner reverse-mapped by grepping the deploys/*.json for the digest). The end-of-run summary repeats it: runtime bytes were replaced for every tenant, only [services] was re-forked. (2) What WAS restarted: `pids before:` / `pids after:` by number. Plus a standing assertion re-run on every ship — each out-of-scope pid is re-checked alive afterwards and an over-match prints a WARNING naming the pid. --dry-run now resolves and PRINTS the same scope through the SAME code path in `preview` mode, touching nothing, so a blast radius is inspectable before it is pointed at a tenant.")
//! @yah:handoff("DISCOVERED WORK DONE IN THIS PASS, not filed. (a) A node that does not run a named service is a loud SKIP, not an abort — the first cut exited 1 and would have half-applied a multi-node roll over a node that was never a customer for that tenant, which contradicts the rule the script already states for a missing `unit:` unit (hotship.sh, \"A missing unit is not an error\"). It now prints the service, the deployed list, and continues. (b) Every read of the deploy state goes through `sudo` even though the files are world-readable today — see R876-B9: they are 0644 with cleartext credentials, and that fix (0600/0700) would otherwise have silently disarmed this hot-ship arm the day it landed. (c) Filed R876-B9 for that exposure itself, parented to R876 for want of a better home — re-parent it if there is one; it is a kamaji-crate concern, not a hotship one.")
//! @yah:handoff("TWO REPORTING BUGS THE FIRST LIVE SHIP EXPOSED, both fixed and both worth knowing because each produced a CONFIDENT WRONG REPORT rather than a failure. (1) `kill -0 &lt;pid&gt;` as the login user against a root-owned process fails with EPERM, indistinguishable from ESRCH — the out-of-scope assertion printed \"WARNING: pid 614524 was OUT of scope and is gone\" about noisetable while noisetable was running untouched. Now `[ -d /proc/&lt;pid&gt; ]`, which needs no privilege. (2) A fixed `sleep 3` after SIGTERM reads the pid table inside the bundle spec's own 5s stop grace, so `pids before` and `pids after` came back byte-identical (611260 611273) on a ship that did re-fork both. Now it polls /proc until every signalled pid is gone, then polls until the replacement count matches the before count (capped 20s/15s) and warns with the shortfall if it does not.")
//! @yah:verify("BEFORE, us-east-001 2026-09-09 08:33Z, `pgrep -af \"/var/lib/yah/kamaji/bundles/runtimes/mesofact/\"` — exactly the three the ticket predicts: 611260 (yah-marketing revalidate, :40995, bundle dd8bdfb7, argv is the positional bundle path + --allow-route, NO --bundle flag), 611273 (yah-marketing bundle, :34759, dd8bdfb7), 614524 (noisetable, :41507, bundle 86b2fa81, started 07:45:39). NOTE the unanchored pattern in the ticket also matches the operator's own pgrep pipeline (two spurious pids appeared in a hand-run); the shipped matcher anchors with ^ and does not.")
//! @yah:verify("STEP 2, SCOPE PROVEN WITHOUT KILLING ANYTHING (--dry-run preview). `--services yah-marketing` resolves to bundle dd8bdfb7 and returns EXACTLY {611260, 611273}, with 614524/noisetable listed under NOT-restarted. The inverse checks too, which is what proves the match is real rather than accidentally yah-marketing-shaped: `--services noisetable` returns exactly {614524} and lists yah-marketing's two as out of scope; `--services yah-marketing,noisetable` returns all three; `--services nosuchsvc` skips loudly, resolves nothing, and lists all three as out of scope. Re-run after the sudo hardening — identical in all four directions.")
//! @yah:verify("STEP 3, FOUR REAL SHIPS against us-east-001 (0.8.36-h12/h13/h14/h15), each `--binaries mesofact --services yah-marketing` with scripts/hotship-probe.sh running against BOTH https://yah.dev/ and https://noisetable.com/ for the window. PASS CONDITION MET ON EVERY RUN. noisetable's pid 614524 is UNCHANGED across all four — asserted on the pid and on `ps -o lstart=` (Wed Sep 9 07:45:39 2026, i.e. predating every ship), not on a log line. noisetable probes: 66/60/38/36 = 200 samples, ZERO non-200s, all 200/8441 (constant body size, so not a served error page). yah-marketing re-forked every time: 611260,611273 -&gt; 617664,617671 -&gt; 617987,617998 -&gt; 618240,618253 -&gt; 619423,619436. yah.dev cost exactly 1x502/0 per activation (08:34:54, 08:36:33, 08:37:50, 08:43:02) against 55/49/30/30 x 200/44242 — a ~1s gap, tighter than the ~2s R876-T1 measured, and in-scope/expected.")
//! @yah:verify("HONEST LIMIT ON WHAT THE FOUR SHIPS PROVE. Per the dispatch, no artifact was built (`yah qed run mesofact-musl` is unsafe right now, R876-B8); the newest existing artifact was used — .yah/cache/artifacts/named/f5211a44c8b1.../mesofact-x86_64-unknown-linux-musl.tar.gz, sha256 7201cbbcdc1b13cc40bdb109c04c16a084518ac779c3490c76e2d0ce45eb5290 — which is BYTE-IDENTICAL to what was already installed at runtimes/mesofact/0.8.32/x86_64-unknown-linux-musl/serve. So these runs exercise install + activation + scoping in full, at zero behaviour risk, but they do not additionally demonstrate new code taking effect. Node left with serve.hotship stamped 0.8.36-h15, release_version 0.8.32, same sha. TOOLING: `bash -n scripts/hotship.sh` clean; `shellcheck -s bash` reports only the three PRE-EXISTING findings (SC2016 DOOR_ACTIVATE, SC2034 leader_id, SC2012 ls -t) and nothing in the new code; the remote heredoc extracted and checked separately is `sh -n` clean and shellcheck-clean at zero findings. `yah qed pipelines` parses hotship with the new `services` param, and the `[ -n \"{{services}}\" ] && args+=` line was tested to exit 0 under `set -euo pipefail` when services is empty (so the default yubaba ship is unaffected).")
//! @yah:handoff("LEADER DECISION, so the ticket's three-way \"which identity to match on\" question is settled: option (c) + (a) — an explicit required scope on the arm that REFUSES to activate without one, resolved to the per-service bundle digest for the match. Option (b) (ask kamaji by pid) was rejected as adding a runtime round-trip to a bash script for something already present in the serve argv. The install half was deliberately left shared and unchanged: one runtime asset backs every tenant naming that version, and that is correct for a runtime tier — the bug was only that ACTIVATION converted a shared-bytes change into a shared-outage change.")
//! @yah:verify("LIVE MEASUREMENT, four real ships against us-east-001 (0.8.36-h12/h13/h14/h15), asserted on pid rather than on a log line as the ticket demanded. yah-marketing re-forked 611260,611273 -> 617664,617671 -> 617987,617998 -> 618240,618253 -> 619423,619436 while noisetable's pid 614524 stayed UNCHANGED throughout, confirmed by both pid and `ps -o lstart`. noisetable's probe: zero non-200s across 200 samples. yah.dev cost exactly 1x502 per activation — its own restart, which is in-scope and expected. Before the fix the same ship re-forked all three processes.")
//! @yah:gotcha("THE FIRST LIVE SHIP EXPOSED TWO REPORTING BUGS IN THE NEW ARM AND BOTH WERE FIXED IN THE SAME PASS, which is worth knowing because both would have made a correct ship look wrong: a `kill -0` EPERM false alarm, and a fixed `sleep 3` that read pid state inside the 5s stop grace and so saw a partial set. The \"service not deployed on this node\" case was also changed from aborting a multi-node roll to a loud skip, matching the `unit:` arm's stated convention. Deploy-state reads were routed through sudo so that R876-B9's permission fix will not silently disarm this arm — that coupling is deliberate and B9 must not undo it.")

use std::collections::HashMap;
use std::future::Future;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::pin::pin;
use std::sync::Arc;

use anyhow::{Context, Result};
use kamaji_proto::{
    decode_frame, encode_frame, DrainOutcome, Error as CodecError, ErrorCode, KamajiToYubaba,
    ProtocolVersion, WorkloadEntry, WorkloadId, WorkloadState, YubabaToKamaji,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::drain;
use crate::journal::{JournalSender, LogSink};
use crate::probe::{run_probe, ProbeTarget};

// The `Kamaji` trait brings deploy/list/teardown into scope for the
// kamaji-crate backends: the NativeRuntime behind the bundle backend (R599-F10)
// and the DockerRuntime behind the docker backend (R626-F1).
#[cfg(any(
    feature = "bundle-serving",
    feature = "docker-integration",
    feature = "native-exec"
))]
use kamaji::Kamaji as _;
#[cfg(feature = "bundle-serving")]
use std::path::PathBuf;

/// Build version reported in [`KamajiToYubaba::Welcome`].
/// The version this binary reports — over the UDS handshake (which is where
/// yubaba's `/health` `kamaji_version` comes from) and from `--version`.
///
/// `CARGO_PKG_VERSION` unless `YAH_HOTSHIP_VERSION` was set at compile time.
/// See `yubaba::VERSION` for the full rationale and for why the stamp is a
/// prerelease of the NEXT patch (`0.8.36-h1`) rather than build metadata: in
/// short, a hot-shipped binary must not be able to claim a published release's
/// version, and us-east-001 reporting `kamaji 0.8.22` while carrying none of
/// the 0.8.22 tree (R746-T3) is what happens when it can.
///
/// `build.rs` carries the `rerun-if-env-changed` that makes changing the
/// variable actually invalidate the build.
pub const CONSTABLE_VERSION: &str = match option_env!("YAH_HOTSHIP_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Per-workload state Kamaji needs to drive a structured drain (R406-T7).
///
/// `pidfd` is the only field that must transfer ownership into the drain
/// enforcer — `pid` is kept for tracing and for the `WorkloadEntry.pid` field
/// surfaced via [`KamajiToYubaba::WorkloadList`].
pub struct DrainableHandle {
    pub pid: u32,
    pub pidfd: OwnedFd,
}

/// In-memory workload registry.
///
/// Holds:
///
/// - `workloads`: a snapshot list returned verbatim by `List` RPCs (one entry
///   per workload Kamaji is supervising).
/// - `drainable`: per-workload [`DrainableHandle`] containing the pidfd needed
///   to send signals and observe exit. Populated by the deploy path (lands
///   under R406-T8 when Kamaji starts owning workload lifecycle end-to-end)
///   and consumed by the Drain RPC handler. Tests poke entries in directly.
///
/// Held behind a [`tokio::sync::Mutex`] so the dispatch loop can read it
/// without parking the runtime thread.
#[derive(Default)]
pub struct Registry {
    workloads: Vec<WorkloadEntry>,
    drainable: HashMap<WorkloadId, DrainableHandle>,
    /// Progress of each **asynchronous** deploy (R330-F33), keyed by workload
    /// id. A bundle `Deploy` acks on admission and materializes in the
    /// background, so this is where the outcome — including the reason a
    /// deploy failed — lives until someone asks for it via `DeployStatus`.
    deploys: HashMap<WorkloadId, DeployProgress>,
    /// Per-workload probe configuration, keyed by workload id. Populated by
    /// the deploy path at admission time; consumed by the Probe RPC handler
    /// (R406-T11). Workloads whose spec carries no `healthcheck` field are
    /// absent here, which the Probe handler maps to [`ProbeStatus::Ready`] —
    /// i.e. "no probe declared ↔ trust the workload's existence".
    probes: HashMap<WorkloadId, ProbeTarget>,
    /// Digest of the `Workload` each admitted deploy carried (R852-B4), keyed
    /// by workload id and stamped onto `List` entries as
    /// [`WorkloadEntry::spec_digest`].
    ///
    /// Kept **here** rather than in each backend for two reasons. The backends
    /// hold a lowered spec (a `WorkloadSpec`, a container config), not the
    /// `Workload` the caller sent, so only the dispatch layer still has the
    /// value the caller can compare against. And a caller's question is about
    /// its own declaration, not about a backend's internals — one recording
    /// point keeps every backend's entries answering it the same way.
    ///
    /// In memory on purpose: after a kamaji restart nothing is bound, so the
    /// honest answer to "is this workload still deployed with that spec" is
    /// `None`/"redeploy", which is exactly what an empty map yields.
    digests: HashMap<WorkloadId, kamaji_proto::SpecDigest>,
}

/// Per-Kamaji runtime context handed to [`handle_message`] (R406-T9).
///
/// Bundles the in-memory registry (shared via mutex) with the optional
/// containerd backend. The backend lives outside the mutex so a slow
/// containerd RPC doesn't park the dispatch loop — the gRPC client is
/// internally synchronized.
pub struct ServerCtx {
    pub registry: Arc<Mutex<Registry>>,
    /// Shared log sink for both backends (R406-T10). On a Linux host with
    /// journald reachable this is a [`JournalSender`] writing the journald
    /// datagram protocol; otherwise it re-emits via `tracing`. Backends
    /// clone this Arc when they spawn per-workload forwarder tasks.
    pub log_sink: Arc<dyn LogSink>,
    /// Optional containerd backend. `None` outside the
    /// `containerd-integration` feature build, or when kamaji is started
    /// without `--containerd-socket`. When `None`, Deploy { Container }
    /// returns a clear "no containerd backend configured" error instead of
    /// the legacy "not implemented" message.
    #[cfg(feature = "containerd-integration")]
    pub containerd: Option<Arc<crate::containerd::ContainerdBackend>>,
    /// Optional keep-alive bundle backend (R599-F10). `None` outside the
    /// `bundle-serving` feature build, or when kamaji is started without a node
    /// bundle store configured. When `None`, Deploy of a `serve_bundle`
    /// mesofact-static workload returns a clear "rebuild with --features
    /// bundle-serving" `BackendRefused`, exactly like the containerd None arm.
    #[cfg(feature = "bundle-serving")]
    pub bundle: Option<BundleBackend>,
    /// Path to `turso-backup-hydrate`, from `--hydrate-helper` /
    /// `KAMAJI_HYDRATE_HELPER` (R850-F1). `None` on a node that has not been
    /// given one.
    ///
    /// Not behind a feature flag, unlike every backend beside it, and
    /// deliberately: the *helper* is what carries the database engine, so the
    /// only thing this build gains is a path and a `Command::output`. Gating it
    /// would mean a node built without the feature silently starts a workload
    /// whose declared restore never ran — the exact failure
    /// [`crate::hydrate::run`] refuses.
    pub hydrate_helper: Option<std::path::PathBuf>,
    /// Optional per-tenant passway JIT tier (R852-F1 / W267 §"Free-tier ingress
    /// at 10k domains"). `None` outside the `tenant-passway` feature build, or
    /// when kamaji is started without `--tenant-passway-dir`. When `None`, a
    /// `Deploy { TenantPassway }` returns a build-aware `BackendRefused`,
    /// exactly like the containerd and bundle `None` arms.
    ///
    /// Deliberately a **separate** [`JitRuntime`] from [`BundleBackend::jit`],
    /// for the reason [`ServerCtx::native`] is separate from
    /// [`BundleBackend::native`]: that one is the custodian of each served
    /// mesofact bundle's socket and keys on bundle identities, this one holds
    /// one socket per *enrolled custom domain*. Sharing a runtime would put two
    /// unrelated identity spaces in one map, and a node fronting tenant domains
    /// is not the same deployment as one serving bundles.
    ///
    /// [`JitRuntime`]: kamaji::jit::JitRuntime
    #[cfg(feature = "tenant-passway")]
    pub tenant_passway: Option<Arc<kamaji::jit::JitRuntime>>,
    /// Optional docker/OrbStack backend (R626-F1). `None` outside the
    /// `docker-integration` feature build, or when kamaji is started without
    /// `--docker`. This is the pond / dev-host counterpart to `containerd`:
    /// both serve `Deploy { Container }`, and when both are configured
    /// containerd wins (a node running containerd is a fleet node, and the
    /// docker daemon there is the developer's, not the fleet's). Shelling out
    /// to the `docker` CLI is cheap and stateless, so this needs no Arc — the
    /// runtime is a single `String`.
    #[cfg(feature = "docker-integration")]
    pub docker: Option<kamaji::docker::DockerRuntime>,
    /// Optional native fork+exec backend for **container-shaped** workloads
    /// that cannot run in a container (R577-T1 / W254). `None` outside the
    /// `native-exec` feature build, or when kamaji is started without
    /// `--native-exec-dir`.
    ///
    /// This is deliberately a separate field from [`BundleBackend::native`],
    /// even though both are a `NativeRuntime`: that one is the single owner of
    /// each *served mesofact bundle's* process and keys on bundle identities,
    /// while this one owns forge jobs. Sharing one runtime would put two
    /// unrelated identity spaces in the same map, and a bundle-serving build is
    /// not the same deployment as a Darwin build-worker.
    #[cfg(feature = "native-exec")]
    pub native: Option<Arc<kamaji::native::NativeRuntime>>,
    /// Optional Firecracker microVM backend (R605-F8 / W325 §5). `None`
    /// outside the `microvm` feature build, or when kamaji is started without
    /// `--microvm-dir`.
    ///
    /// The one backend whose absence is usually *not* a build-flag question: it
    /// needs a guest kernel and rootfs staged on the node, so `None` is the
    /// honest state of nearly every node even in a build that has the feature.
    /// `MicroVmRuntime::new` is the thing that decides, and it refuses at
    /// startup rather than at first deploy — see its doc comment for why.
    #[cfg(feature = "microvm")]
    pub microvm: Option<Arc<kamaji::microvm::MicroVmRuntime>>,
}

/// The node bundle backend: materialize a W272 bundle from the node store and
/// serve it under one of two lifecycle runtimes, selected by `bundle.lifecycle`:
/// the **keep-alive** [`NativeRuntime`] (R599-F10) forks a resident
/// `mesofact-serve` — the same supervisor R490 runs mesofact-dev under — and the
/// **on-demand** [`JitRuntime`] (R599-F6) holds the listen socket and forks the
/// serve runtime lazily, reaping it when idle.
///
/// The runtime is the **single owner** of each served bundle's child process
/// (spawn, restart/re-fork, log capture, teardown); the two hold disjoint
/// identities. The kamaji-bin [`Registry`] is *not* a second lifecycle owner for
/// bundle workloads: `List` merges both runtimes' live views (like the
/// containerd merge), `Stop` routes teardown to both, and the only registry
/// state a bundle deploy writes is a keep-alive probe target so `Probe` can dial
/// the serve process. See [`deploy_mesofact_bundle`] for the Drain caveat.
///
/// [`NativeRuntime`]: kamaji::native::NativeRuntime
/// [`JitRuntime`]: kamaji::jit::JitRuntime
#[cfg(feature = "bundle-serving")]
pub struct BundleBackend {
    /// Fork+exec supervisor — single owner of each **keep-alive** served
    /// bundle's process.
    pub native: Arc<kamaji::native::NativeRuntime>,
    /// On-demand (JIT) runtime (R599-F6) — custodian of each **on-demand**
    /// bundle's listen socket, forking the serve process on the first connection
    /// and reaping it after idle. Disjoint from `native`: a bundle's lifecycle
    /// selects exactly one of the two, so a given identity lives in one runtime.
    pub jit: Arc<kamaji::jit::JitRuntime>,
    /// Node bundle store (R2 in prod, in-memory in tests) the cache pulls from.
    pub store: Arc<dyn yah_object_store::ObjectStore>,
    /// Cache root. Materialized bundles live at `<cache_dir>/bundles/<digest>/`;
    /// named serve-runtime assets at
    /// `<cache_dir>/runtimes/[<namespace>/]<name>/<ver>/<triple>/serve`
    /// (R746-F1). The runtime tier sits outside `bundles/` so the bundle LRU
    /// neither counts nor reclaims it — one asset backs every resident serve
    /// process at that version.
    pub cache_dir: PathBuf,
    /// LRU byte budget for the bundle cache (0 = unbounded). A fresh
    /// `BundleCache` is constructed per deploy inside `spawn_blocking` (it holds
    /// no in-memory state beyond root+budget — recency is on-disk), so the
    /// blocking materialize never parks the async dispatch loop.
    pub cache_budget: u64,
    /// Node-wide port **override**, when the operator set one
    /// (`--bundle-port` / `KAMAJI_BUNDLE_PORT`). `None` — the fleet's actual
    /// configuration — means no override.
    ///
    /// R599-F12 demoted this from *the* port to a fallback: a bundle carries
    /// its own `serve_bundle.port`, and while every bundle shared this one
    /// value a node could host exactly one of them.
    ///
    /// R844-F2 demoted it again, from a fallback to an override, and that is
    /// the type change: it was `u16`, defaulting to [`DEFAULT_BUNDLE_PORT`]
    /// whenever the operator set nothing. A silent node-wide default is
    /// indistinguishable from a pin — every bundle that declared no port got
    /// 8080, so the second bundle on a node could not bind at all. Unset now
    /// means *allocate*, via [`kamaji::ports::PortAllocator`]. An operator who
    /// really does want every bundle on one known port can still say so, and
    /// then owns the collision.
    ///
    /// `Some(0)` is the ephemeral sentinel (tests, and anyone who wants
    /// "anything free"): it declares nothing, so allocation takes over.
    pub bind_port: Option<u16>,
    /// R844-F2: this node's listen-port allocator, persisted at
    /// `<state_dir>/ports.json`.
    ///
    /// A bundle that declares no port gets one from here instead of colliding
    /// on a node-wide default, and the ledger is what makes that port survive
    /// a kamaji restart — a keep-alive bundle whose port moved would leave the
    /// rendered ingress upstream naming a dead listener, which looks healthy
    /// and so is worse than an absent record.
    pub ports: Arc<kamaji::ports::LedgerPorts>,
    /// R755-B5: where admitted bundle deploys are recorded so a kamaji restart
    /// can replay them — `<state_dir>/deploys/<id>.json`, one
    /// [`BundleDeployRecord`] per live workload. Written at admission, removed
    /// on `Stop`, read once by [`ServerCtx::resume_bundle_workloads`].
    ///
    /// Sits beside (not inside) the native supervisor's per-ident log dirs.
    /// `NativeRuntime` never scans `state_dir`, so a `deploys/` sibling cannot
    /// be mistaken for a workload's capture dir.
    ///
    /// R876-B9: **owner-only, 0700.** A record is the whole admission input,
    /// which includes the revalidate tier's `env` — live cleartext credentials
    /// on a multi-tenant box. The mode is enforced in
    /// [`BundleBackend::record_deploy`] rather than here so that it is applied
    /// on every write, including to a directory an older kamaji already
    /// created at 0755.
    pub records_dir: PathBuf,
}

/// R755-B5: everything `Deploy` handed kamaji for one serve-bundle workload,
/// persisted so the deploy survives the daemon. A control-plane roll restarts
/// kamaji, systemd SIGKILLs every child under `yubaba.slice`, and before this
/// record existed nothing on the node remembered what had been running — the
/// site stayed down until an operator re-ran `yah cloud apply` (measured on
/// us-east-001 2026-08-28: passway-test.yah.dev 503 for ~5 minutes across a
/// roll *and* its rollback).
///
/// The record is the admission input, not the outcome: replaying it goes
/// through exactly [`deploy_mesofact_bundle`]'s post-Ack task (materialize →
/// resolve serve bin → fork), so a resumed deploy can fail the same ways and
/// report through the same `DeployStatus`.
#[cfg(feature = "bundle-serving")]
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BundleDeployRecord {
    pub id: String,
    pub bundle: workload_spec::MesofactServeBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revalidate: Option<workload_spec::MesofactRevalidateReceiver>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<kamaji_proto::MeshAssignment>,
}

/// @yah:ticket(R876-B9, "kamaji writes bundle deploy records world-readable (0644) with live secrets inside")
/// @yah:at(2026-09-09T09:16:19Z)
/// @yah:status(review)
/// @yah:assignee(agent:bundle-anthropic-glimmerstone)
/// @yah:parent(R876)
/// @yah:severity(high)
/// @yah:gotcha("MEASURED ON LIVE PRODUCTION us-east-001 2026-09-09 by @Glimmerstone:griffin while working R876-B5 (found reading kamaji deploy state to resolve service -> bundle digest; not fixed there because it is a different crate and a separable concern). `stat -c '%a %U:%G'` gives `644 root:root` on /var/lib/yah/kamaji/bundles/state/deploys/yah-marketing.json, with `755 root:root` on both parent dirs — so ANY unprivileged local account reads it. I read it end to end as the plain `debian` login user, no sudo. That file's `revalidate.env` block carries live credential material in cleartext: a CLOUDFLARE_API_TOKEN, a MESOFACT_S3_ACCESS_KEY_ID and a MESOFACT_S3_SECRET_ACCESS_KEY (values deliberately not reproduced here). Every deployed bundle gets one of these files, so the exposure is per-tenant and grows with the fleet.")
/// @yah:next("THE WRITE SITE: BundleBackend::record_deploy, oss/kamaji/crates/kamaji-bin/src/server.rs:624-630 — `std::fs::write(&tmp, bytes)` then `std::fs::rename`. std::fs::write creates with 0666 &amp; ~umask, i.e. 0644 under the default umask, and the subsequent rename preserves that mode. The record was added for restart-replay (the @yah:handoff at server.rs:164 describes it); persisting it is right, the mode is not.")
/// @yah:next("FIX SHAPE: create the tmp file with mode 0600 (OpenOptions + std::os::unix::fs::OpenOptionsExt::mode, or fs::set_permissions on the tmp before the rename — set it on the TMP, since setting it after the rename leaves a window where the final path is readable), and chmod the records_dir (server.rs:510, state_dir.join(&quot;deploys&quot;)) to 0700 at creation. Then remediate the fleet: the existing 0644 files on every node need chmod, and any credential that has been sitting world-readable on a multi-tenant box should be treated as disclosed and rotated — that rotation call is the operator's, not an agent's.")
/// @yah:verify("Reproduce: `ssh &lt;node&gt; 'stat -c &quot;%a %U:%G %n&quot; /var/lib/yah/kamaji/bundles/state/deploys/*.json /var/lib/yah/kamaji/bundles/state/deploys'` as the unprivileged login user — currently 644 on the files and 755 on the dir. After the fix a freshly-recorded deploy must be 600 in a 700 dir, still readable by kamaji (root) on restart-replay, and `resume_bundle_workloads()` must still find and replay it. NOTE for whoever takes this: R876-B5's hotship activation resolves service -&gt; bundle digest by reading these same files as the LOGIN user (scripts/hotship.sh, bundle_serve_remote). Tightening the mode to 0600/0700 will break that read — it must move behind `sudo` in the same pass, or the fix lands a broken hot-ship. That is a two-line change in the remote script (sudo on the grep and on the deploys-dir listing), not a redesign.")
/// @yah:handoff("CODE FIXED at the write site. BundleBackend::record_deploy (oss/kamaji/crates/kamaji-bin/src/server.rs, now ~:660) no longer uses std::fs::write. The tmp is created through OpenOptions with .mode(0o600) AND then f.set_permissions(0o600) on the open handle before any bytes are written - the second call is not redundant: .mode() applies only when THAT call creates the file, so a 0644 tmp left by an older kamaji that crashed mid-write would otherwise be reused as-is. The mode is set on the TMP and never after the rename, so the final path is never observable world-readable. records_dir is chmodded 0700 on EVERY record_deploy rather than only at creation, because DirBuilder::mode applies solely to dirs it creates (the same fact bind_listener documents at :1084) - so an upgraded node whose deploys/ already exists at 0755 self-heals on its next deploy instead of staying loose forever. Imports (std::io::Write, std::os::unix::fs::OpenOptionsExt) are scoped inside the fn: the module also compiles without the bundle-serving feature, where both would be unused. Doc comments at both sites (records_dir field and record_deploy) state why.")
/// @yah:handoff("EXPOSURE INVENTORY - what the operator needs to scope a rotation. Credential NAMES only; no value was read, printed or logged anywhere. ONE NODE IS AFFECTED: us-east-001 (vps-8dba9ff8, debian@51.81.85.145). FILE 1: /var/lib/yah/kamaji/bundles/state/deploys/yah-marketing.json, was 644 root:root, and it is the one carrying credential material - CLOUDFLARE_API_TOKEN, MESOFACT_S3_ACCESS_KEY_ID, MESOFACT_S3_SECRET_ACCESS_KEY, in cleartext in its revalidate env block. FILE 2: deploys/noisetable.json, also was 644 root:root, but a grep for the whole TOKEN/SECRET/KEY/PASSWORD name class returned zero hits, so no credential of that class is in it. Parent dir state/deploys was 755 root:root. DURATION, lower bound: the deploys DIRECTORY birth is 2026-08-31 19:42:36Z, i.e. at least 9 days of exposure to 2026-09-09. Do NOT read the per-file birth times as the exposure start - yah-marketing.json birth 2026-09-09 01:34:53Z and noisetable.json birth 2026-09-09 07:45:31Z are the CURRENT inodes only, because each redeploy renames a fresh file over the old one; the record itself has existed since the dir did. EXPLOITABILITY CONFIRMED, not inferred: read end to end as the plain debian login user with no sudo (READ OK before, READ DENIED after). NO OTHER NODE HAS RECORDS - checked us-west-001 (no /var/lib/yah/kamaji/bundles at all), us-south-001 (state/ exists, no deploys/), us-west-003, us-west-011, us-west-013, us-west-014, us-west-015: all absent. us-west-002 is the ONE GAP: ssh to struc@100.64.0.4 timed out, so it is unverified rather than clean. ROTATION IS THE OPERATOR CALL AND WAS NOT TOUCHED: nothing was rotated, revoked or re-issued by this ticket.")
/// @yah:handoff("FLEET REMEDIATED, us-east-001 only (it is the only node with records). sudo chmod 0600 on both deploys/*.json and sudo chmod 0700 on the deploys dir, one node, live. Health confirmed after and identical to the before-baseline: all four serve pids still alive by /proc presence - 610122 (almanac-feed), 614524 (noisetable serve), 619423 (yah-marketing revalidate), 619436 (yah-marketing bundle) - kamaji and yubaba both systemctl is-active, and yah.dev 200/44242, yah.dev/releases 200/41629, noisetable.com 200/8441, byte-identical sizes to the pre-chmod reading. Nothing was restarted; a chmod is invisible to a process that already holds the file open, and kamaji reads these as root. AN INCIDENTAL PROOF WORTH KNOWING: the verification stat failed the first time with a literal-glob error because the LOGIN user's shell could no longer expand deploys/*.json - that failure is itself the confirmation the dir is closed, and any later check of these files needs the glob inside sudo sh -c, not outside it.")
/// @yah:verify("THE TICKET'S OWN REPRODUCTION, run as the unprivileged debian login user on us-east-001, before and after. BEFORE: 755 root:root on state and on state/deploys, 644 root:root on both deploys/noisetable.json and deploys/yah-marketing.json, and an unprivileged cat of yah-marketing.json succeeded (READ OK). AFTER: 700 root:root on state/deploys, 600 root:root on both json files, and the same unprivileged cat now fails - READ DENIED, with ls reporting Permission denied on the directory. state/ itself was deliberately left 755: only the records dir needed closing, and tightening the shared state dir would have reached past the fix into the native supervisor's capture-dir siblings.")
/// @yah:verify("TESTS, against a baseline measured BEFORE the change on the same tree. BASELINE: cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji-bin --features bundle-serving = lib 270 passed / 0 failed / 0 ignored, plus the five integration targets (0+0+2+2+1) and 0 doc-tests, exit 0. AFTER: lib 271 passed / 0 failed / 0 ignored, same five targets unchanged, exit 0 - the +1 is exactly the one test added. cargo check --manifest-path oss/kamaji/Cargo.toml -p kamaji-bin --all-targets (i.e. WITHOUT bundle-serving) exit 0 with no unused-import warning, which is the check the fn-scoped imports exist for; the only two warnings on that run are the pre-existing never-used control_sock_from_spec (:2184) and free_port (:8277). NEW TEST a_deploy_record_is_written_owner_only_and_still_replays asserts all three claims together: mode 0600 on the record and 0700 on the dir; that a PRE-EXISTING 0755 dir and a stale 0644 tmp are tightened rather than trusted (the case that makes the explicit chmod load-bearing rather than decorative); and that recorded_deploys still round-trips the record byte-equal, which is the availability half - this fix must not trade a disclosure bug for a restart-replay bug. The existing end-to-end a_recorded_keepalive_bundle_is_resumed_by_a_fresh_kamaji also gained the two mode assertions, because it is the only test that reaches record_deploy through handle_message, so a regression that tightened only the direct callers would pass the focused test alone.")
/// @yah:verify("R876-B5's HOT-SHIP ARM IS INTACT - verified, not re-done. Confirmed by content in the current scripts/hotship.sh that every deploy-state read already goes through sudo: deploy_files is `sudo find` (:331), owner_of is `sudo grep` (:336), the presence check is `sudo test -f` (:357), and both the digest and runtime extractions are `sudo grep` (:366, :371), under B5's own comment at :325 naming this ticket. Then run for real AFTER the chmod: scripts/hotship.sh --nodes us-east-001 --binaries mesofact --services yah-marketing --dry-run resolved `scope: yah-marketing -> bundle dd8bdfb75a53 (runtime mesofact/0.8.32)`, put 619423 and 619436 in scope, and correctly reverse-mapped the out-of-scope pid 614524 to `service noisetable` - that reverse mapping is owner_of grepping every file in the now-0700 dir, so it is the strictest available proof the sudo route works against the tightened mode. Nothing was signalled (dry run). No change to hotship.sh was needed or made.")
/// @yah:handoff("FLEET REMEDIATION WAS DONE, NOT JUST THE WRITE PATH — that distinction matters, because fixing only `record_deploy` would have left every already-written 0644 file exposed forever. us-east-001 was the only node in the fleet carrying deploy records and was remediated live: files 0600, dir 0700, unprivileged read now denied, all four serve pids alive, and yah.dev / yah.dev/releases / noisetable.com byte-identical 200s afterwards. **us-west-002 is UNREACHABLE and therefore UNVERIFIED, not clean** — if it comes back and holds deploy records, it still needs the chmod.")
/// @yah:verify("THE R876-B5 COUPLING HELD: `scripts/hotship.sh --dry-run --services yah-marketing` still resolves the bundle digest and reverse-maps the out-of-scope noisetable pid through B5's sudo route against the now-0700 dir, so no script change was needed. This was the one way B9 could have silently disarmed the hot-ship arm, and it was checked rather than assumed. Leader re-verification of the sibling ticket also came back clean: yah-cloud lib re-run 1137/0/4 exactly as R876-B7 reported, and `public-ip` confirmed an AFFINITY key by code (`taint_effect` returns `Repels` only for `no-<archetype>` keys; `AFFINITY_TAINT_KEYS` holds `PUBLIC_IP_TAINT`), so B7 did not move any live placement.")
/// @yah:gotcha("THE CREDENTIAL ROTATION IS DELIBERATELY NOT DONE AND IS THE OPERATOR'S CALL — do not read this ticket reaching review as \"the exposure is closed\". Three credentials (CLOUDFLARE_API_TOKEN, MESOFACT_S3_ACCESS_KEY_ID, MESOFACT_S3_SECRET_ACCESS_KEY, values never reproduced) sat world-readable in /var/lib/yah/kamaji/bundles/state/deploys/ on us-east-001, a multi-tenant production box, for a 9-day LOWER BOUND measured from the deploys dir birth time. The permissions are now closed; the secrets should still be treated as disclosed until rotated.")
#[cfg(feature = "bundle-serving")]
impl BundleBackend {
    /// Build a bundle backend over `store`, caching materialized trees under
    /// `cache_dir` and keeping the native supervisor's per-workload log
    /// captures under `state_dir`.
    pub fn new(
        store: Arc<dyn yah_object_store::ObjectStore>,
        cache_dir: impl Into<PathBuf>,
        state_dir: impl Into<PathBuf>,
    ) -> Self {
        // R844-F2: no `.unwrap_or(DEFAULT_BUNDLE_PORT)`. Unset means allocate,
        // not "8080" — see the field docs.
        let bind_port = std::env::var("KAMAJI_BUNDLE_PORT")
            .ok()
            .and_then(|v| v.parse().ok());
        let state_dir = state_dir.into();
        Self {
            native: Arc::new(kamaji::native::NativeRuntime::new(state_dir.clone())),
            jit: Arc::new(kamaji::jit::JitRuntime::new(state_dir.clone())),
            store,
            cache_dir: cache_dir.into(),
            cache_budget: 0,
            bind_port,
            ports: Arc::new(kamaji::ports::LedgerPorts::open(&state_dir)),
            records_dir: state_dir.join("deploys"),
        }
    }

    /// The numeric pin someone wrote down for `bundle`, if any (R844-F2,
    /// reversed by R844-F14).
    ///
    /// Two sources, and both are a human writing a number:
    ///
    /// 1. The bundle's own `serve_bundle.port` — R599-F12's per-workload
    ///    declaration, which the mirror's `[providers.bundle] port` key writes.
    /// 2. The node-wide override an operator passed as `--bundle-port` /
    ///    `KAMAJI_BUNDLE_PORT`.
    ///
    /// `None` means nobody wrote one, which is the *normal* case and the one
    /// [`Self::resolve_port`] allocates for. `0` is the ephemeral sentinel and
    /// reads as "nobody said" too.
    ///
    /// R844-F14: this is no longer honoured. A written-down number now rides
    /// into [`kamaji::ports::PortSpec::pin`], where the allocator **rejects**
    /// it unless it is world-fixed (80/443) — so a stale mirror pin fails at
    /// bring-up naming the port, instead of quietly binding the number a
    /// co-tenant on this node already holds.
    pub fn declared_pin(&self, bundle: &workload_spec::MesofactServeBundle) -> Option<u16> {
        bundle.port.or(self.bind_port).filter(|&p| p != 0)
    }

    /// The port set a served bundle asks for: one port named
    /// [`kamaji::ports::HTTP`], carrying whatever pin someone wrote down so the
    /// allocator can reject it by name.
    pub fn http_spec(
        &self,
        bundle: &workload_spec::MesofactServeBundle,
    ) -> kamaji::ports::PortSpec {
        kamaji::ports::PortSpec {
            name: kamaji::ports::HTTP.to_string(),
            pin: self.declared_pin(bundle),
        }
    }

    /// Resolve the port `ident` will actually bind on `bind_ip` (R844-F2).
    ///
    /// A free port is allocated from the node's ledger and remembered for this
    /// `(ident, name)` across kamaji restarts. A `spec` carrying a
    /// non-world-fixed pin is an error, not a value — see [`Self::declared_pin`].
    ///
    /// The returned port is what gets forked into the workload's `--listen`,
    /// parsed back onto `expose.mesh.ports`, and reported to yubaba on the next
    /// `List` — one value, one path, no place for a second opinion.
    pub fn resolve_port(
        &self,
        ident: &str,
        bind_ip: std::net::Ipv4Addr,
        spec: kamaji::ports::PortSpec,
    ) -> std::result::Result<u16, String> {
        use kamaji::ports::PortAllocator;
        self.ports
            .resolve_one(ident, std::net::IpAddr::V4(bind_ip), spec)
            .map_err(|e| format!("could not resolve a listen port for {ident}: {e:#}"))
    }

    /// The store a workload's bundle objects are fetched from (R870-B6):
    /// **its own origin first, this node's behind it**.
    ///
    /// `origin` is `serve_bundle.origin`, the public HTTPS origin serving the
    /// bucket the workload was actually published to. `None` — every yah-owned
    /// mirror today — returns [`Self::store`] itself, so the single-tenant path
    /// is byte-identical and makes no extra request.
    ///
    /// This is [`Self::bind_port`]'s history on the store axis. A node-wide
    /// `KAMAJI_BUNDLE_ORIGIN` is correct exactly while every workload on the
    /// fleet publishes to the store the node was pointed at; the second tenant
    /// published to its own bucket, and its deploy passed admission and then
    /// failed with `missing blob manifests/<digest>` because the node looked in
    /// yah's store for noisetable's manifest.
    ///
    /// The node origin stays *behind* the workload's rather than being replaced
    /// by it, and that is deliberate: the stock `mesofact/<ver>` serve runtime
    /// is published once by the fleet, and a tenant that has not mirrored ~70MB
    /// of it into their own bucket must still be able to fork one. Chaining is
    /// safe because every key here is content-addressed and verified after the
    /// fetch — see [`yah_object_store::FallbackObjectStore`].
    ///
    /// Async because building the origin's `reqwest::blocking::Client` panics
    /// inside a tokio runtime; construction goes to the blocking pool, exactly
    /// as `attach_bundle_backend` does for the node-wide one.
    pub async fn store_for(
        &self,
        origin: Option<&str>,
    ) -> std::result::Result<Arc<dyn yah_object_store::ObjectStore>, String> {
        let Some(origin) = origin.map(str::to_string) else {
            return Ok(Arc::clone(&self.store));
        };
        let built = tokio::task::spawn_blocking({
            let origin = origin.clone();
            move || yah_object_store::HttpReadOnlyObjectStore::new(origin)
        })
        .await
        .map_err(|e| format!("workload bundle-origin construction task panicked: {e}"))?
        .map_err(|e| format!("workload bundle origin {origin:?}: {e}"))?;
        Ok(Arc::new(yah_object_store::FallbackObjectStore::new(
            Arc::new(built),
            Arc::clone(&self.store),
        )))
    }

    fn record_path(&self, id: &WorkloadId) -> PathBuf {
        self.records_dir.join(format!("{}.json", id.0))
    }

    /// Persist the admission input for `id` (R755-B5). Atomic: written to a
    /// sibling temp file and renamed, so a crash mid-write leaves either the
    /// previous record or none, never a half-record that fails to parse on
    /// resume.
    ///
    /// R876-B9: **0600 in a 0700 dir, and the mode is set on the TMP.** A
    /// record carries the deploy's `env` verbatim, which for the revalidate
    /// tier is live credential material (`CLOUDFLARE_API_TOKEN`,
    /// `MESOFACT_S3_*`). `std::fs::write` creates 0666 & ~umask — 0644 under
    /// the default umask — and `rename` preserves the source's mode, so the
    /// previous shape published every tenant's secrets to any local account.
    /// Tightening after the rename would be wrong for the same reason the
    /// write is done through a tmp at all: it leaves a window in which the
    /// *final* path is world-readable, and that path is the one another
    /// process is watching for.
    ///
    /// The dir is chmodded on every write rather than only at creation.
    /// `DirBuilder::mode` applies solely to directories it creates, so a node
    /// upgraded from an older kamaji would otherwise keep its 0755 `deploys/`
    /// forever; doing it here makes the next deploy self-heal the mode.
    pub fn record_deploy(&self, record: &BundleDeployRecord) -> std::io::Result<()> {
        // Scoped to this fn: the rest of the module is compiled without the
        // `bundle-serving` feature too, where these two would be unused.
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        std::fs::create_dir_all(&self.records_dir)?;
        std::fs::set_permissions(&self.records_dir, std::fs::Permissions::from_mode(0o700))?;
        let final_path = self.record_path(&WorkloadId::new(&record.id));
        let tmp = self.records_dir.join(format!(".{}.json.tmp", record.id));
        let bytes = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            // `.mode()` only applies when THIS call creates the file. A tmp
            // left behind by an older kamaji that crashed mid-write is 0644
            // and would be reused as-is, so tighten the open handle before any
            // bytes land in it.
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            f.write_all(&bytes)?;
        }
        std::fs::rename(&tmp, &final_path)
    }

    /// Drop the record for `id` (R755-B5). Idempotent — a Stop for a workload
    /// that was never a bundle, or was already stopped, is Ok.
    pub fn forget_deploy(&self, id: &WorkloadId) -> std::io::Result<()> {
        match std::fs::remove_file(self.record_path(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Every record on disk, in name order. A record that fails to parse is
    /// logged and skipped rather than aborting the whole resume — one corrupt
    /// file must not keep every other site on the node down.
    pub fn recorded_deploys(&self) -> Vec<BundleDeployRecord> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.records_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return out,
            Err(e) => {
                warn!(dir = %self.records_dir.display(), error = %e, "cannot read bundle deploy records");
                return out;
            }
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        for path in paths {
            match std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|b| serde_json::from_slice::<BundleDeployRecord>(&b).map_err(|e| e.to_string()))
            {
                Ok(rec) => out.push(rec),
                Err(e) => warn!(path = %path.display(), error = %e, "skipping unreadable bundle deploy record"),
            }
        }
        out
    }

    /// Set the node-wide port override — an explicit operator flag over the
    /// `KAMAJI_BUNDLE_PORT` env value picked in [`new`].
    ///
    /// R844-F14: a non-zero value here now *fails* every bundle deploy on this
    /// node, naming the port. It is kept rather than deleted so the refusal can
    /// say which number it refused and where it came from; deleting the flag
    /// would turn an operator's `--bundle-port 9100` into a silently ignored
    /// argument, which is the failure this ticket exists to stop.
    ///
    /// `0` is the ephemeral sentinel: it pins nothing, so
    /// [`BundleBackend::resolve_port`] allocates. That is what it already meant
    /// in practice — a `:0` listen address let the OS pick — except that the
    /// picked port used to be invisible, because `expose.mesh.ports` was parsed
    /// off the literal `:0` rather than off what the kernel assigned.
    ///
    /// [`new`]: BundleBackend::new
    pub fn with_bind_port(mut self, port: u16) -> Self {
        self.bind_port = Some(port);
        self
    }

    /// Override the bundle cache's LRU byte budget (0 = unbounded, the default).
    pub fn with_cache_budget(mut self, budget_bytes: u64) -> Self {
        self.cache_budget = budget_bytes;
        self
    }
}

/// The historical node-wide bundle port (R599-F10; demoted to a fallback by
/// R599-F12). Mirrors the 2026-07-06 ingress testbed (passway → :8080).
///
/// **R844-F2 retired it as a fallback**, and **R844-F14 retired the ask
/// as well**: a bundle's port is allocated ([`BundleBackend::resolve_port`]),
/// and asking for this number by name — mirror pin or `--bundle-port` — is now
/// refused, because one node-wide port is a single slot that the second bundle
/// on a node cannot have. The constant survives as the historical value the
/// help text and this doc name.
#[cfg(feature = "bundle-serving")]
pub const DEFAULT_BUNDLE_PORT: u16 = 8080;

/// The target triple keying this node's runtime-asset cache
/// (`runtimes/<runtime>/<triple>/serve`) and a self-contained bundle's
/// `bins/<triple>/serve`.
///
/// Resolved from the RUNNING build's cfg — deliberately NOT hardcoded musl: the
/// current fleet is x86_64 glibc (musl is R546, not yet live) and mesofact-serve
/// builds V8-free glibc, so the dogfood triple is `x86_64-unknown-linux-gnu`. On
/// the macOS dev/test host it resolves to the host's `*-apple-darwin` triple,
/// which is all the tests need — they stage the fake serve bin under this same
/// computed triple.
#[cfg(feature = "bundle-serving")]
fn node_triple() -> String {
    let arch = std::env::consts::ARCH;
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    let sys = "unknown-linux-musl";
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    let sys = "unknown-linux-gnu";
    #[cfg(target_os = "macos")]
    let sys = "apple-darwin";
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let sys = "unknown-unknown";
    format!("{arch}-{sys}")
}

impl ServerCtx {
    /// Build a context with no containerd backend. Suitable for tests and
    /// pond-tier kamaji instances. The default log sink is a
    /// [`JournalSender`] that gracefully falls back to `tracing` when no
    /// journald is reachable.
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Mutex::new(Registry::new())),
            log_sink: Arc::new(JournalSender::connect()),
            hydrate_helper: None,
            #[cfg(feature = "containerd-integration")]
            containerd: None,
            #[cfg(feature = "bundle-serving")]
            bundle: None,
            #[cfg(feature = "tenant-passway")]
            tenant_passway: None,
            #[cfg(feature = "docker-integration")]
            docker: None,
            #[cfg(feature = "native-exec")]
            native: None,
            #[cfg(feature = "microvm")]
            microvm: None,
        }
    }

    /// Build a context with the given registry handle — lets tests pre-seed
    /// the registry before dispatch.
    pub fn with_registry(registry: Arc<Mutex<Registry>>) -> Self {
        Self {
            registry,
            log_sink: Arc::new(JournalSender::connect()),
            hydrate_helper: None,
            #[cfg(feature = "containerd-integration")]
            containerd: None,
            #[cfg(feature = "bundle-serving")]
            bundle: None,
            #[cfg(feature = "tenant-passway")]
            tenant_passway: None,
            #[cfg(feature = "docker-integration")]
            docker: None,
            #[cfg(feature = "native-exec")]
            native: None,
            #[cfg(feature = "microvm")]
            microvm: None,
        }
    }

    /// Override the log sink. Tests use this to capture forwarded lines
    /// without hitting journald; the production binary uses the
    /// [`JournalSender::connect`] default established in [`new`].
    pub fn with_log_sink(mut self, sink: Arc<dyn LogSink>) -> Self {
        self.log_sink = sink;
        self
    }

    /// Attach a containerd backend. Only available with the
    /// `containerd-integration` feature.
    #[cfg(feature = "containerd-integration")]
    pub fn with_containerd(mut self, backend: Arc<crate::containerd::ContainerdBackend>) -> Self {
        self.containerd = Some(backend);
        self
    }

    /// Attach the keep-alive bundle backend (R599-F10). Only available with the
    /// `bundle-serving` feature; the production binary calls this in
    /// `app/yah/kamaji/src/main.rs` once the node bundle store (R2 creds + cache
    /// dir) is configured.
    #[cfg(feature = "bundle-serving")]
    pub fn with_bundle_backend(mut self, backend: BundleBackend) -> Self {
        self.bundle = Some(backend);
        self
    }

    /// Attach the per-tenant passway JIT tier (R852-F1). Only available with
    /// the `tenant-passway` feature; the binary calls this in `main.rs` when
    /// the operator passed `--tenant-passway-dir`.
    ///
    /// Opt-in rather than implied by the feature, for the same reason
    /// [`with_docker`](Self::with_docker) is: a node that is not a public front
    /// door should not start binding tenant sockets because the binary happens
    /// to have been built with the capability.
    #[cfg(feature = "tenant-passway")]
    pub fn with_tenant_passway(mut self, jit: Arc<kamaji::jit::JitRuntime>) -> Self {
        self.tenant_passway = Some(jit);
        self
    }

    /// Point hydrate-on-place at `turso-backup-hydrate` (R850-F1). The binary
    /// calls this in `main.rs` when the operator passed `--hydrate-helper`.
    ///
    /// Leaving it unset does not disable the feature — it makes a deploy that
    /// *declares* a durability tier fail loudly. See [`crate::hydrate::run`].
    pub fn with_hydrate_helper(mut self, helper: std::path::PathBuf) -> Self {
        self.hydrate_helper = Some(helper);
        self
    }

    /// Attach the docker/OrbStack backend (R626-F1). Only available with the
    /// `docker-integration` feature; the binary calls this in `main.rs` when
    /// the operator passed `--docker` / `--docker-host`.
    ///
    /// Attaching is deliberately opt-in rather than implied by the feature: a
    /// dev host usually has *some* docker daemon reachable via `DOCKER_HOST`,
    /// and a supervisor that adopts whichever daemon happens to be running
    /// would deploy fleet workloads onto a developer's laptop docker.
    #[cfg(feature = "docker-integration")]
    pub fn with_docker(mut self, backend: kamaji::docker::DockerRuntime) -> Self {
        self.docker = Some(backend);
        self
    }

    /// Attach the native fork+exec backend for native-marked container
    /// workloads (R577-T1). Only available with the `native-exec` feature; the
    /// binary calls this in `main.rs` when the operator passed
    /// `--native-exec-dir`.
    #[cfg(feature = "native-exec")]
    pub fn with_native_exec(mut self, backend: Arc<kamaji::native::NativeRuntime>) -> Self {
        self.native = Some(backend);
        self
    }

    /// Attach the microVM backend for microVM-marked container workloads
    /// (R605-F8). Only available with the `microvm` feature; the binary calls
    /// this in `main.rs` when the operator passed `--microvm-dir` *and*
    /// `MicroVmRuntime::new` accepted the node's guest material.
    #[cfg(feature = "microvm")]
    pub fn with_microvm(mut self, backend: Arc<kamaji::microvm::MicroVmRuntime>) -> Self {
        self.microvm = Some(backend);
        self
    }
}

impl Default for ServerCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn list(&self) -> Vec<WorkloadEntry> {
        self.workloads.clone()
    }

    /// Add a drainable handle for `id`. Replaces any prior entry — the caller
    /// owns the invariant that ids are unique per Kamaji lifetime.
    pub fn insert_drainable(&mut self, id: WorkloadId, handle: DrainableHandle) {
        self.drainable.insert(id, handle);
    }

    /// Remove and return the [`DrainableHandle`] for `id`, if any. Called from
    /// the Drain RPC dispatch — once removed, no further drain or list RPC
    /// observes this workload as drainable.
    pub fn take_drainable(&mut self, id: &WorkloadId) -> Option<DrainableHandle> {
        self.drainable.remove(id)
    }

    /// Register the probe target for `id`. Called by the deploy path once the
    /// workload's network endpoint is known (native: loopback + spec port;
    /// container: containerd bridge address). Replaces any prior entry —
    /// re-deploying a workload re-binds its probe target atomically.
    pub fn insert_probe(&mut self, id: WorkloadId, target: ProbeTarget) {
        self.probes.insert(id, target);
    }

    /// Look up the probe target for `id`, cloned so the dispatch loop can
    /// release the registry mutex before the (possibly slow) probe runs.
    pub fn probe_target(&self, id: &WorkloadId) -> Option<ProbeTarget> {
        self.probes.get(id).cloned()
    }

    /// Drop the probe target for `id` — called when the workload is torn down.
    pub fn remove_probe(&mut self, id: &WorkloadId) -> Option<ProbeTarget> {
        self.probes.remove(id)
    }

    /// Record where an asynchronous deploy has got to (R330-F33). Replaces any
    /// prior record, so re-deploying a workload restarts its progress rather
    /// than leaving the previous attempt's terminal state visible.
    pub fn set_deploy_progress(&mut self, id: WorkloadId, progress: DeployProgress) {
        self.deploys.insert(id, progress);
    }

    /// Progress of the asynchronous deploy for `id`, if kamaji has one on
    /// record. `None` means no deploy of this id has been admitted since
    /// kamaji started — which the `DeployStatus` handler reports as
    /// `UnknownWorkload` rather than inventing a state.
    pub fn deploy_progress(&self, id: &WorkloadId) -> Option<DeployProgress> {
        self.deploys.get(id).cloned()
    }

    /// Drop the deploy record for `id` — called when the workload is torn down,
    /// so a later `DeployStatus` doesn't report a stopped workload as `Running`.
    pub fn remove_deploy_progress(&mut self, id: &WorkloadId) -> Option<DeployProgress> {
        self.deploys.remove(id)
    }

    /// Record the digest of the `Workload` `id` was just deployed with
    /// (R852-B4). Replaces any prior record — the last accepted deploy is what
    /// this node is running, so a redeploy with a changed spec must not leave
    /// the previous digest visible and read as "unchanged".
    pub fn set_spec_digest(&mut self, id: WorkloadId, digest: kamaji_proto::SpecDigest) {
        self.digests.insert(id, digest);
    }

    /// Drop the spec digest for `id` — called when the workload is torn down,
    /// so a later redeploy of the same spec is not skipped as unchanged when
    /// nothing is actually bound.
    pub fn remove_spec_digest(&mut self, id: &WorkloadId) -> Option<kamaji_proto::SpecDigest> {
        self.digests.remove(id)
    }

    /// Stamp each entry with the digest of the spec it was deployed with.
    ///
    /// Applied to the *merged, deduped* list, after every backend has reported,
    /// so one recording point serves them all. An entry with no record keeps
    /// `None` — unknown, which the caller reads as "redeploy" — and a record
    /// with no live entry is simply never consulted, which is what makes a
    /// stale record harmless rather than a resurrection.
    pub fn stamp_spec_digests(&self, entries: &mut [WorkloadEntry]) {
        for entry in entries.iter_mut() {
            if entry.spec_digest.is_none() {
                entry.spec_digest = self.digests.get(&entry.id).copied();
            }
        }
    }
}

/// Where an asynchronous deploy has got to (R330-F33).
///
/// `state` walks `Pending` (admitted, bundle not yet materialized) → `Starting`
/// (materialized, fork issued) → `Running`, or lands on `Failed`. `detail` is
/// the failure reason — the message that a synchronous deploy used to return in
/// its `Error` reply, and without which an asynchronous failure is undebuggable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployProgress {
    pub state: WorkloadState,
    pub detail: Option<String>,
}

impl DeployProgress {
    /// In-flight state, carrying no reason.
    pub fn at(state: WorkloadState) -> Self {
        Self {
            state,
            detail: None,
        }
    }

    /// Terminal failure, carrying the reason.
    pub fn failed(detail: impl Into<String>) -> Self {
        Self {
            state: WorkloadState::Failed,
            detail: Some(detail.into()),
        }
    }
}

/// Bind the UDS, accept connections, dispatch frames until ctrl-c.
pub async fn serve(socket: &Path) -> Result<()> {
    serve_with_shutdown(socket, shutdown_signal()).await
}

/// Variant of [`serve`] that takes an explicit shutdown future — used by
/// integration tests so they don't have to send a real SIGINT. Builds a
/// fresh [`ServerCtx`] with no backend; for a backend-equipped instance use
/// [`serve_with_ctx`].
pub async fn serve_with_shutdown<F>(socket: &Path, shutdown: F) -> Result<()>
where
    F: Future<Output = ()>,
{
    serve_with_ctx(socket, Arc::new(ServerCtx::new()), shutdown).await
}

/// Variant of [`serve_with_shutdown`] that takes a caller-built
/// [`ServerCtx`] — needed by `app/yah/kamaji/src/main.rs` so the
/// production binary can attach the containerd backend (R406-T9) before
/// the listener starts accepting connections.
pub async fn serve_with_ctx<F>(socket: &Path, ctx: Arc<ServerCtx>, shutdown: F) -> Result<()>
where
    F: Future<Output = ()>,
{
    let listener =
        bind_listener(socket).with_context(|| format!("bind UDS at {}", socket.display()))?;
    info!(path = %socket.display(), "kamaji UDS listening");

    let mut shutdown = pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received; stopping accept loop");
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let ctx = Arc::clone(&ctx);
                        tokio::spawn(async move {
                            if let Err(e) = handle_conn(stream, ctx).await {
                                warn!(error = %e, "connection handler error");
                            }
                        });
                    }
                    Err(e) => warn!(error = %e, "accept failed"),
                }
            }
        }
    }

    let _ = tokio::fs::remove_file(socket).await;
    Ok(())
}

fn bind_listener(socket: &Path) -> Result<UnixListener> {
    if let Some(parent) = socket.parent() {
        if !parent.as_os_str().is_empty() {
            // Create any missing parent dirs owner-only (0700). `.mode()` on a
            // recursive DirBuilder applies only to dirs we create and never
            // chmods an existing one — so a systemd `RuntimeDirectory=kamaji`
            // (0750, pre-created) keeps its unit-defined mode, while a
            // dev/manual `--socket /tmp/...` run gets a private parent.
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .with_context(|| format!("create parent dir {}", parent.display()))?;
        }
    }
    // Clear any stale socket file left behind by a previous run. UnixListener::bind
    // refuses to overwrite an existing inode.
    if socket.exists() {
        std::fs::remove_file(socket)
            .with_context(|| format!("remove stale socket {}", socket.display()))?;
    }
    let listener = UnixListener::bind(socket)?;
    // Owner-only socket (0600): at the filesystem layer only our own uid can
    // connect, beneath the SO_PEERCRED gate in `handle_conn`. `bind()` creates
    // the socket node with the process umask, which may be looser, so tighten
    // it explicitly — defense in depth for the "any local peer can Deploy" path.
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", socket.display()))?;
    Ok(listener)
}

/// Authorize a freshly-accepted UDS peer by its kernel-supplied credentials.
///
/// Kamaji's control socket drives privileged workload lifecycle (Deploy / Stop
/// / Drain), so it must serve only the colocated warden. In every shipped
/// topology yubaba and kamaji run as the same uid — root, per the
/// `kamaji.service` / `yubaba.service` units (no `User=`) and the pond
/// supervisor (one container) — so we accept a peer whose uid is our own or
/// root and reject anything else. `SO_PEERCRED` is set by the kernel at
/// `connect(2)` time and cannot be spoofed. Together with the 0600 socket this
/// is defense in depth: the fs perms stop a foreign uid connecting at all, and
/// this rejects any that slip through (perms drift, a passed-in fd, a socket
/// bound in a world-traversable dir like `/tmp` in dev).
///
/// Principal-level authz (verify the PASETO bearer → `policy::enforce` → audit)
/// is deliberately NOT done here: that layer is sequenced under R593-F6, gated
/// behind the R592-T4 wire rename that reshapes these very envelopes, and is
/// flagged trust-boundary code requiring adversarial review. Peer-cred is the
/// correct transport-layer control for the local sibling UDS today.
#[cfg(target_os = "linux")]
fn peer_is_authorized(stream: &UnixStream) -> bool {
    let our_uid = unsafe { libc::getuid() };
    match stream.peer_cred() {
        Ok(cred) => {
            let uid = cred.uid();
            if uid == our_uid || uid == 0 {
                true
            } else {
                warn!(
                    peer_uid = uid,
                    our_uid, "rejecting kamaji UDS connection from foreign uid"
                );
                false
            }
        }
        Err(e) => {
            warn!(error = %e, "rejecting kamaji UDS connection: SO_PEERCRED unavailable");
            false
        }
    }
}

/// Non-Linux builds are dev-only (kamaji ships on Linux — cgroups, pidfds); the
/// 0600 socket perms set in [`bind_listener`] are the control there.
#[cfg(not(target_os = "linux"))]
fn peer_is_authorized(_stream: &UnixStream) -> bool {
    true
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn handle_conn(stream: UnixStream, ctx: Arc<ServerCtx>) -> Result<()> {
    // Transport-layer auth: only the colocated warden (same uid, or root) may
    // drive the control socket. Drop an unauthorized peer without emitting any
    // protocol to it. See [`peer_is_authorized`].
    if !peer_is_authorized(&stream) {
        return Ok(());
    }

    let (mut rd, mut wr) = stream.into_split();
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];

    loop {
        // Drain every complete frame currently in `buf` before issuing another read.
        loop {
            match decode_frame::<YubabaToKamaji>(&buf) {
                Ok((msg, consumed)) => {
                    let reply = handle_message(msg, &ctx).await;
                    let frame = encode_frame(&reply).context("encode reply")?;
                    wr.write_all(&frame).await.context("write reply")?;
                    buf.drain(..consumed);
                }
                Err(CodecError::Truncated { .. }) => break,
                Err(e) => {
                    let err_reply = KamajiToYubaba::Error {
                        request_id: None,
                        code: ErrorCode::Internal,
                        message: format!("decode failed: {e}"),
                    };
                    if let Ok(frame) = encode_frame(&err_reply) {
                        let _ = wr.write_all(&frame).await;
                    }
                    return Err(anyhow::anyhow!("decode failed: {e}"));
                }
            }
        }

        let n = rd.read(&mut tmp).await.context("read from peer")?;
        if n == 0 {
            debug!("peer closed");
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Dispatch one decoded message. Visible for unit testing.
///
/// R406-T9: when `ctx.containerd` is `Some`, Deploy { Container } and Stop
/// dispatch through the containerd backend; List merges the backend's
/// containers with the in-memory registry. When no backend is configured,
/// Deploy/Stop return a clear `BackendRefused` rather than silently
/// succeeding — operators see exactly why the dispatch path is missing.
pub async fn handle_message(msg: YubabaToKamaji, ctx: &Arc<ServerCtx>) -> KamajiToYubaba {
    match msg {
        YubabaToKamaji::Hello { version } => {
            if version != ProtocolVersion::CURRENT {
                return KamajiToYubaba::Error {
                    request_id: None,
                    code: ErrorCode::UnsupportedVersion,
                    message: format!("unsupported wire version: {version:?}"),
                };
            }
            KamajiToYubaba::Welcome {
                version: ProtocolVersion::CURRENT,
                kamaji_version: CONSTABLE_VERSION.to_string(),
            }
        }
        // R858-T4. Answered from the same `ctx.native` that `deploy_native_exec`
        // dispatches on, so the capability a scheduler reads and the capability
        // a deploy exercises cannot disagree — deriving it from the build
        // features or the CLI args instead would be a second source of truth
        // that drifts exactly when it matters.
        YubabaToKamaji::Capabilities { request_id } => {
            #[cfg(feature = "native-exec")]
            let (native_exec, native_exec_dir) = match &ctx.native {
                Some(rt) => (true, Some(rt.exec_dir().display().to_string())),
                None => (false, None),
            };
            #[cfg(not(feature = "native-exec"))]
            let (native_exec, native_exec_dir) = (false, None);

            KamajiToYubaba::CapabilitiesReport {
                request_id,
                capabilities: kamaji_proto::NodeCapabilities {
                    native_exec,
                    native_exec_dir,
                },
            }
        }
        YubabaToKamaji::List { request_id } => {
            // Start with the in-memory registry entries. This list is a
            // historical stub — nothing writes `Registry::workloads` outside
            // tests — so on a live daemon it is empty and every backend below
            // contributes its own live view.
            #[allow(unused_mut)]
            let mut entries = ctx.registry.lock().await.list();

            // Merge native fork+exec workloads (R858-B14). `ctx.native` is the
            // `--native-exec-dir` backend `deploy_native_exec` forks through —
            // the headscale appliance among them — and it was the one runtime
            // `List` never asked. Its workloads existed, were supervised, and
            // were invisible on the wire: yubaba's `get_workload` filters this
            // list by ident, so `observe_local_appliance` answered "not running
            // here" about a healthy appliance, `decide_owner` never reached
            // `OwnerServing(self)`, and every reconcile tick redeployed a
            // coordinator kamaji was already supervising correctly.
            #[cfg(feature = "native-exec")]
            if let Some(native) = &ctx.native {
                match native.list_workloads().await {
                    Ok(states) => {
                        entries.extend(states.into_iter().map(runtime_state_to_entry))
                    }
                    Err(e) => {
                        return KamajiToYubaba::Error {
                            request_id: Some(request_id),
                            code: ErrorCode::BackendRefused,
                            message: format!("native list failed: {e}"),
                        };
                    }
                }
            }

            // Merge containerd containers when the backend is configured.
            #[cfg(feature = "containerd-integration")]
            if let Some(backend) = &ctx.containerd {
                match backend.list().await {
                    Ok(ctr_entries) => entries.extend(ctr_entries),
                    Err(e) => {
                        return KamajiToYubaba::Error {
                            request_id: Some(request_id),
                            code: ErrorCode::BackendRefused,
                            message: format!("containerd list failed: {e}"),
                        };
                    }
                }
            }

            // Merge bundle workloads (R599-F10 keep-alive + R599-F6 on-demand).
            // Each runtime is the source of truth for its own workloads' live
            // status — mirror the containerd merge rather than tracking a stale
            // registry snapshot. The two runtimes hold disjoint identities.
            #[cfg(feature = "bundle-serving")]
            if let Some(backend) = &ctx.bundle {
                match backend.native.list_workloads().await {
                    Ok(states) => {
                        entries.extend(states.into_iter().map(runtime_state_to_entry))
                    }
                    Err(e) => {
                        return KamajiToYubaba::Error {
                            request_id: Some(request_id),
                            code: ErrorCode::BackendRefused,
                            message: format!("bundle backend list failed: {e}"),
                        };
                    }
                }
                entries.extend(
                    backend
                        .jit
                        .list_workloads()
                        .await
                        .into_iter()
                        .map(runtime_state_to_entry),
                );
            }

            // Merge per-tenant passways (R852-F1). Same shape as the on-demand
            // bundle merge above and a disjoint identity space: an armed-but-
            // idle passway appears as present with no pid, which is the honest
            // state of a zero-resident workload.
            #[cfg(feature = "tenant-passway")]
            if let Some(jit) = &ctx.tenant_passway {
                entries.extend(
                    jit.list_workloads()
                        .await
                        .into_iter()
                        .map(runtime_state_to_entry),
                );
            }

            // Merge microVM guests (R605-F8). The runtime owns each guest's
            // live status the same way the bundle runtimes own theirs, and the
            // identities are disjoint from every other backend's — a guest is
            // never also a container.
            #[cfg(feature = "microvm")]
            if let Some(microvm) = &ctx.microvm {
                use kamaji::Kamaji as _;
                match microvm.list_workloads().await {
                    Ok(states) => {
                        entries.extend(states.into_iter().map(runtime_state_to_entry))
                    }
                    Err(e) => {
                        return KamajiToYubaba::Error {
                            request_id: Some(request_id),
                            code: ErrorCode::BackendRefused,
                            message: format!("microvm list failed: {e}"),
                        };
                    }
                }
            }

            // Merge docker/OrbStack containers (R626-F1). Like the containerd
            // merge, the daemon is the source of truth for its own containers'
            // live status; `list_workloads_detailed` carries each container's
            // host pid in the same round-trips, so a docker row can win the
            // dedupe below on liveness rather than being ranked pid-less.
            #[cfg(feature = "docker-integration")]
            if let Some(docker) = &ctx.docker {
                match docker.list_workloads_detailed().await {
                    Ok(workloads) => {
                        entries.extend(workloads.into_iter().map(docker_workload_to_entry))
                    }
                    Err(e) => {
                        return KamajiToYubaba::Error {
                            request_id: Some(request_id),
                            code: ErrorCode::BackendRefused,
                            message: format!("docker list failed: {e}"),
                        };
                    }
                }
            }

            // One row per workload id (R599-B11). The merges above concatenate
            // independent backend views, and those views are NOT guaranteed
            // disjoint: a leftover containerd container can carry the same id as
            // a live native bundle workload, and containerd reports a
            // container-without-task as `Pending`/`pid: None`. Collapse to the
            // most-live row rather than emitting both.
            let mut entries = dedupe_workload_entries(entries);
            // R852-B4: stamp what each workload was deployed with, so a caller
            // can tell an unchanged declaration from a changed one and stop
            // re-deploying (on the JIT tier, re-binding) everything every
            // sweep. After the dedupe: the surviving row is the one that goes
            // out, and the digest is per-id, not per-backend.
            ctx.registry.lock().await.stamp_spec_digests(&mut entries);
            KamajiToYubaba::WorkloadList {
                request_id,
                entries,
            }
        }
        YubabaToKamaji::Drain {
            request_id,
            id,
            budget,
        } => {
            // Pull the workload's pidfd out of the registry. None means either
            // the workload never registered or it was already drained — either
            // way Yubaba gets DrainAck { accepted=false, reason="unknown" }.
            let handle = ctx.registry.lock().await.take_drainable(&id);
            let Some(handle) = handle else {
                return KamajiToYubaba::DrainAck {
                    request_id,
                    id,
                    accepted: false,
                    reason: Some("unknown workload".to_string()),
                };
            };

            // Synchronous-mode T7 (see DrainAck rustdoc): run the structured
            // drain to completion here, then reply with DrainAck reflecting
            // the outcome. The async-push form using DrainCompleted lands once
            // R406-T8 gives Kamaji a back-channel to Yubaba.
            let outcome = drain::enforce_drain(id.clone(), handle.pidfd, budget).await;
            let (accepted, reason) = drain_outcome_to_ack(outcome);
            KamajiToYubaba::DrainAck {
                request_id,
                id,
                accepted,
                reason,
            }
        }
        YubabaToKamaji::Deploy {
            request_id,
            id,
            spec,
            mesh,
        } => {
            // R599-F12. The wire assignment stays in its wire type until it
            // reaches a backend arm: `kamaji` (which owns the runtime type) is
            // an *optional* dep here, so a default build has no runtime
            // `MeshAssignment` to convert into. `None` = no mesh IP plane.
            deploy_workload(ctx, request_id, id, spec, mesh.as_ref()).await
        }
        YubabaToKamaji::GracefulUpgrade {
            request_id,
            id,
            spec,
        } => {
            // R852-B4: an accepted upgrade IS the workload's current spec, so
            // the digest record moves with it. Leaving the pre-upgrade digest
            // on record would make the next caller that re-declares the
            // upgraded spec see a mismatch and issue a plain `Deploy` — a
            // connection-dropping redeploy of the very workload the graceful
            // path had just replaced without dropping one.
            let digest = kamaji_proto::spec_digest(&spec);
            let reply = graceful_upgrade_workload(ctx, request_id, id.clone(), spec).await;
            if let (KamajiToYubaba::Ack { .. }, Some(digest)) = (&reply, digest) {
                ctx.registry.lock().await.set_spec_digest(id, digest);
            }
            reply
        }
        YubabaToKamaji::Stop { request_id, id } => stop_workload(ctx, request_id, id).await,
        YubabaToKamaji::Probe { request_id, id } => {
            // Clone the target so we don't hold the registry mutex across the
            // probe's network/exec wait. A workload teardown that races with
            // this probe just means we return ProbeResult for a workload
            // Yubaba's already decided to drop — harmless.
            let target = ctx.registry.lock().await.probe_target(&id);
            let status = run_probe(target.as_ref()).await;
            KamajiToYubaba::ProbeResult {
                request_id,
                id,
                status,
            }
        }
        YubabaToKamaji::DeployStatus { request_id, id } => {
            // R330-F33. An id with no record was never admitted by *this*
            // kamaji — report that rather than inventing a state, since
            // "Pending forever" and "you asked about the wrong workload" need
            // to look different to a caller polling in a loop.
            match ctx.registry.lock().await.deploy_progress(&id) {
                Some(progress) => KamajiToYubaba::DeployStatusResult {
                    request_id,
                    id,
                    state: progress.state,
                    detail: progress.detail,
                },
                None => KamajiToYubaba::Error {
                    request_id: Some(request_id),
                    code: ErrorCode::UnknownWorkload,
                    message: format!(
                        "no deploy on record for {} — it was never admitted by this kamaji, or \
                         kamaji restarted since (deploy progress is in-memory)",
                        id.0
                    ),
                },
            }
        }
        // The Yubaba→Kamaji enum is #[non_exhaustive]; reject any variant
        // we don't yet understand instead of relying on the match being total.
        _ => KamajiToYubaba::Error {
            request_id: None,
            code: ErrorCode::Internal,
            message: "unhandled message kind".to_string(),
        },
    }
}

/// Dispatch a `Deploy { id, spec, mesh }` to the right backend. R406-T9 wires
/// `Workload::Container` to the containerd backend. R599-F4 admits a
/// `MesofactStatic` workload that carries a `serve_bundle` (a deployed W272
/// bundle) and routes it to the native backend via [`deploy_mesofact_bundle`];
/// a build-and-publish-only `MesofactStatic` (no `serve_bundle`), `Almanac`, and
/// `StaticAsset` remain yubaba's reconcilers' business and surface as
/// `InvalidSpec` if they reach Kamaji.
///
/// `mesh` is the workload's mesh-plane placement (R599-F12), threaded here at
/// the *envelope* rather than per backend: every backend needs the same answer
/// to "what address does this workload live at", and the two that had grown
/// their own `MeshAssignment::inlined(127.0.0.1)` stand-in had each recorded
/// the same follow-up.
/// Rejection for a `kind = "container"` workload that arrived in the RECIPE
/// form (R783-F1 / W324) — a Dockerfile build, not a digest-pinned image.
///
/// Shared by deploy and graceful-upgrade so the two cannot describe the same
/// refusal differently.
fn recipe_is_not_deployable(request_id: kamaji_proto::RequestId) -> KamajiToYubaba {
    KamajiToYubaba::Error {
        request_id: Some(request_id),
        code: ErrorCode::InvalidSpec,
        message: "kamaji deploys digest-pinned container specs; this workload is a local \
                  build RECIPE (a [build] table) and names no digest. Build it first and \
                  send the lowered WorkloadSpec."
            .to_string(),
    }
}

/// Dispatch a `Deploy` to the backend its spec selects, and — on acceptance —
/// record what it was deployed with (R852-B4).
///
/// The digest is taken **before** dispatch, because the arms below take the
/// `Workload` apart and the value a caller compares against is the whole
/// envelope it sent, not one variant's remains. It is recorded only on an
/// `Ack`, so a refused deploy leaves no record and the next `List` reports the
/// workload as unknown-spec rather than as deployed-with-something.
///
/// One caveat the field's doc also carries: on the bundle path an `Ack` means
/// *admitted* (`ProtocolVersion::V3`), not running. A bundle that fails while
/// materializing therefore leaves a digest behind — harmless, because the
/// digest is only ever stamped onto an entry a backend still reports, and a
/// caller comparing digests is deciding whether to *re-declare*, not whether
/// the workload is healthy.
async fn deploy_workload(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: WorkloadId,
    spec: workload_spec::Workload,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> KamajiToYubaba {
    let digest = kamaji_proto::spec_digest(&spec);
    let reply = dispatch_deploy(ctx, request_id, id.clone(), spec, mesh).await;
    if let (KamajiToYubaba::Ack { .. }, Some(digest)) = (&reply, digest) {
        ctx.registry.lock().await.set_spec_digest(id, digest);
    }
    reply
}

#[allow(unused_variables)]
async fn dispatch_deploy(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: WorkloadId,
    spec: workload_spec::Workload,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> KamajiToYubaba {
    match spec {
        workload_spec::Workload::Container(manifest) => match manifest.into_spec() {
            Ok(spec) => deploy_container(ctx, request_id, &id, &spec, mesh).await,
            // R783-F1 / W324: the recipe form of `kind = "container"` is an
            // on-disk Dockerfile build. It names a tag, not a digest, so there
            // is nothing here for containerd to pull. It cannot normally reach
            // this far — the postcard serializer refuses it — so this arm is
            // the belt to that braces.
            Err(_recipe) => recipe_is_not_deployable(request_id),
        },
        // R599-F4: a mesofact-static workload that carries a `serve_bundle` is a
        // deployed W272 bundle kamaji serves via its native backend — no longer
        // rejected. The build-and-publish-only form (no serve_bundle) still
        // belongs to yubaba's mesofact-static reconciler.
        workload_spec::Workload::MesofactStatic(w) => match w.serve_bundle {
            // `w.serve_bundle` is moved out by this arm; `w.revalidate_receiver`
            // is a disjoint field, so borrowing it after is a legal partial move.
            Some(bundle) => {
                deploy_mesofact_bundle(
                    ctx,
                    request_id,
                    &id,
                    &bundle,
                    w.revalidate_receiver.as_ref(),
                    mesh,
                )
                .await
            }
            None => KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::InvalidSpec,
                message: "kamaji dispatches only mesofact-static workloads carrying a \
                          serve_bundle (R599-F4); a build-and-publish-only mesofact-static \
                          spec lives in yubaba's reconciler"
                    .to_string(),
            },
        },
        // R852-F1: one cold passway per enrolled custom domain, on the same JIT
        // tier the on-demand bundle path uses.
        workload_spec::Workload::TenantPassway(w) => {
            deploy_tenant_passway(ctx, request_id, &id, &w, mesh).await
        }
        workload_spec::Workload::Almanac(_) | workload_spec::Workload::StaticAsset(_) => {
            KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::InvalidSpec,
                message: "kamaji dispatches Workload::Container, serve-bundle \
                          mesofact-static and tenant-passway; almanac and static-asset live \
                          in yubaba's reconcilers"
                    .to_string(),
            }
        }
    }
}

/// Deploy one **per-tenant passway** on the JIT tier (R852-F1 / W267
/// §"Free-tier ingress at 10k domains").
///
/// kamaji binds and holds the domain's declared TLS backend socket — the
/// address the SNI demux splices to — and forks `passway` on the first
/// connection with that socket as fd 3. passway serves the handshake, then
/// self-reaps on `PASSWAY_IDLE_TTL_SECS`; kamaji never releases the socket, so
/// connections arriving between a reap and the next fork sit in the kernel
/// accept queue and are served by the fresh child.
///
/// **The Ack means "socket bound and armed", not "a process is running"** — the
/// same contract [`deploy_mesofact_bundle`]'s on-demand arm has, and the reason
/// no probe target is registered (a `TcpConnect` probe would dial the held
/// socket and fork the process on every interval, defeating the reap).
///
/// Unlike the bundle path there is nothing to materialize — the passway binary
/// is a node artifact and the cert pair is already on disk — so this is
/// synchronous: everything that can fail is decidable before the reply, which
/// is what R330-F33 moved the bundle path off a task to avoid.
///
/// **Restart resume is deliberately absent**, and that is not the gap it looks
/// like. The bundle path records each deploy on disk (R755-B5) because a node
/// that forgets its sites needs an operator to re-run `yah cloud apply`. A
/// tenant passway's source of truth is the enrollment set in the R2 cert store
/// (`yubaba::cert_store::enrolled`), which the same sweep that publishes the
/// demux routes already re-reads — so a kamaji restart re-arms from the
/// authoritative set on the next sweep instead of from a node-local copy that
/// could disagree with it.
#[allow(unused_variables)]
async fn deploy_tenant_passway(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: &WorkloadId,
    w: &workload_spec::TenantPasswayWorkload,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> KamajiToYubaba {
    #[cfg(feature = "tenant-passway")]
    {
        let Some(jit) = &ctx.tenant_passway else {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!(
                    "no per-tenant passway tier configured on this kamaji instance to serve \
                     {} ({}) — start kamaji with --tenant-passway-dir",
                    id.0, w.domain
                ),
            };
        };
        // The listen address is DECLARED, not allocated: it is the same string
        // the tenant's enrollment names as its demux backend, so an allocator
        // choosing a port here would arm a socket nothing routes to. Reject a
        // string that is not a bindable `host:port` now rather than at the
        // first connection, where it would read as a hung domain.
        if w.listen.parse::<std::net::SocketAddr>().is_err() {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::InvalidSpec,
                message: format!(
                    "tenant passway {} declares listen = {:?}, which is not a host:port socket \
                     address. This string is the fd-table key passway's socket activation \
                     matches on and the demux backend the enrollment routes to; a hostname here \
                     is an outage discovered as a hung handshake.",
                    w.domain, w.listen
                ),
            };
        }

        let spec = w.jit_spec(&id.0);
        // The netns from the mesh assignment is what keeps the held socket
        // routable when yubaba placed this workload on the mesh plane; without
        // one it is a loopback bind, which is the normal shape here (the demux
        // splices to it from the same node).
        let mesh = runtime_mesh(mesh);

        match jit.deploy_on_demand(&spec, &mesh, &w.listen).await {
            Ok(()) => {
                ctx.registry
                    .lock()
                    .await
                    .set_deploy_progress(id.clone(), DeployProgress::at(WorkloadState::Running));
                KamajiToYubaba::Ack {
                    request_id,
                    kind: kamaji_proto::AckKind::Deploy,
                }
            }
            Err(e) => KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!(
                    "binding/arming the per-tenant passway for {} on {} failed: {e:#}",
                    w.domain, w.listen
                ),
            },
        }
    }
    #[cfg(not(feature = "tenant-passway"))]
    {
        let _ = ctx;
        KamajiToYubaba::Error {
            request_id: Some(request_id),
            code: ErrorCode::BackendRefused,
            message: format!(
                "tenant passway for {} (listen={}) admitted for {} but this kamaji was built \
                 without the per-tenant passway tier — rebuild with --features tenant-passway \
                 (R852-F1)",
                w.domain, w.listen, id.0
            ),
        }
    }
}

/// Dispatch a `Workload::Container` to whichever backend this build has
/// configured.
///
/// Four backends can serve a container-shaped workload:
///
/// - **containerd** (R406-T9, `containerd-integration`) — the cloud tier.
/// - **docker/OrbStack** (R626-F1, `docker-integration`) — pond and dev hosts,
///   where the daemon speaks the Docker API rather than containerd's gRPC.
/// - **native fork+exec** (R577-T1, `native-exec`) — checked *first*, and only
///   for a spec carrying [`WorkloadSpec::wants_native_exec`].
/// - **microVM** (R605-F8, `microvm`) — checked second, and only for a spec
///   carrying [`WorkloadSpec::wants_microvm`]. It refuses on the same terms as
///   the native path and for a symmetric reason: a microVM request is a request
///   for isolation that does not rest on the host kernel, and a container
///   "fallback" would report success while delivering exactly the thing the
///   caller declined — an un-isolated build next to the raft voter W325 §5 is
///   trying to protect. The two markers are values of the same `yah.exec` key,
///   so no spec can satisfy both and their relative order is arbitrary.
///
/// The native check comes first because it is not a fallback: a workload that
/// asks for native execution is one that *cannot* run in a container. The W254
/// Darwin build leg is the case — `cargo tauri build` for
/// `aarch64-apple-darwin`, `codesign` and `xcrun notarytool` need a live macOS
/// userland, and the container a build-worker can offer is always a Linux
/// container. Silently falling through to docker there would not degrade the
/// build, it would run it against the wrong operating system. So an unsatisfied
/// native request refuses rather than falls back.
///
/// Between the two *container* backends, containerd wins when both are
/// configured: a node with a containerd socket is a fleet node, and its docker
/// daemon (if any) belongs to a developer, not to the fleet. When neither is,
/// the deploy reports a `BackendRefused` naming what this specific build is
/// missing — feature not compiled in vs compiled but unconfigured — so an
/// operator can tell a rebuild from a restart-with-flags.
#[allow(unused_variables)]
async fn deploy_container(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: &WorkloadId,
    spec: &workload_spec::WorkloadSpec,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> KamajiToYubaba {
    // Signed-recipe admission (R555-F4 / W235 §(c)), at the envelope rather than
    // per backend.
    //
    // R555-F4's brief named `containerd::validate_spec_for_constable` as the
    // site, alongside the tier guards it already carries. That is one backend of
    // three: `deploy_native_exec` fork+execs on the host and the docker arm
    // shells out to a daemon, and neither passes through that function. A gate a
    // workload can dodge by setting `yah.exec = native` is not a gate, so it
    // goes where every container-shaped deploy converges. The containerd
    // backend's own tier checks stay where they are — they are spec-shape rules,
    // not trust decisions.
    if let Err(e) = workload_spec::admission::check(spec) {
        return KamajiToYubaba::Error {
            request_id: Some(request_id),
            code: ErrorCode::InvalidSpec,
            message: format!("workload {} not admitted: {e}", spec.name),
        };
    }

    // R850-F1: hydrate-on-place. Before any backend starts anything, a workload
    // that declares a durability tier gets its named volume filled from the
    // declared store — under an ownership fence — or the deploy is refused.
    //
    // Sited here rather than in the containerd backend for the reason the
    // admission check above is: `deploy_native_exec` and the docker arm do not
    // pass through `validate_spec_for_constable`, and a durability guard a
    // workload can dodge by setting `yah.exec = native` is not a guard. This is
    // inert for every spec that declares nothing, which is every spec in the
    // tree today (`hydrate::plan` → `NotDeclared`).
    match crate::hydrate::run(ctx.hydrate_helper.as_deref(), spec).await {
        Ok(crate::hydrate::HydrateResult::Proceed(line)) => {
            if let Some(line) = line {
                info!(id = %id.0, outcome = %line, "hydrate-on-place");
            }
        }
        Err(message) => {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message,
            }
        }
    }

    if spec.wants_native_exec() {
        return deploy_native_exec(ctx, request_id, id, spec, mesh).await;
    }

    if spec.wants_microvm() {
        return deploy_microvm(ctx, request_id, id, spec, mesh).await;
    }

    #[cfg(feature = "containerd-integration")]
    if let Some(backend) = ctx.containerd.clone() {
        return match backend.deploy(id, spec).await {
            Ok(_pid) => KamajiToYubaba::Ack {
                request_id,
                kind: kamaji_proto::AckKind::Deploy,
            },
            Err(crate::containerd::BackendError::InvalidSpec(msg)) => KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::InvalidSpec,
                message: msg,
            },
            Err(crate::containerd::BackendError::Containerd(e)) => KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("containerd: {e:#}"),
            },
        };
    }

    #[cfg(feature = "docker-integration")]
    if let Some(docker) = ctx.docker.clone() {
        // R599-F12: the `Deploy` now carries the assignment, so the docker
        // backend stamps the `yah.mesh_ip` label and `YAH_MESH_IP` env with the
        // address yubaba actually admitted the workload at. On pond — where
        // there is no mesh IP plane at all — yubaba sends none and we keep the
        // loopback sentinel, since inventing a routable address there would be
        // a worse lie than loopback.
        let mesh = runtime_mesh(mesh);
        return match docker.deploy_workload(spec, &mesh).await {
            Ok(result) => {
                info!(
                    id = %id.0,
                    container_id = %result.container_id,
                    pid = result.task_pid,
                    "docker container deployed"
                );
                KamajiToYubaba::Ack {
                    request_id,
                    kind: kamaji_proto::AckKind::Deploy,
                }
            }
            Err(e) => KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("docker: {e:#}"),
            },
        };
    }

    no_container_backend_error(request_id)
}

/// Run a native-marked container workload on the node's own userland
/// (R577-T1 / W254) — the fork+exec half of [`deploy_container`].
///
/// The spec reaching here is an ordinary [`workload_spec::WorkloadSpec`]; only
/// its [`NATIVE_EXEC_ANNOTATION`](workload_spec::NATIVE_EXEC_ANNOTATION) marks
/// it. `NativeRuntime` treats `image` as identity metadata (nothing is pulled)
/// and resolves argv from `entrypoint` + `command` with container semantics, so
/// the same spec shape drives both paths.
///
/// `volumes` are inert here: a fork+exec'd process has no mount namespace. The
/// dispatcher compensates by pointing `workdir` and `YAH_PRODUCED_DIR` at the
/// real host path (see `velveteen_exec::remote::mark_native_exec`), which
/// yubaba has already created from that same volume entry before this deploy
/// arrives.
#[allow(unused_variables)]
async fn deploy_native_exec(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: &WorkloadId,
    spec: &workload_spec::WorkloadSpec,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> KamajiToYubaba {
    if let Err(message) = validate_native_exec_spec(spec) {
        return KamajiToYubaba::Error {
            request_id: Some(request_id),
            code: ErrorCode::InvalidSpec,
            message,
        };
    }

    #[cfg(feature = "native-exec")]
    if let Some(native) = ctx.native.clone() {
        let mesh = runtime_mesh(mesh);
        return match native.deploy_workload(spec, &mesh).await {
            Ok(result) => {
                info!(
                    id = %id.0,
                    pid = result.task_pid,
                    "native workload forked"
                );
                // R715-F3 / W315: a workload that declares the control socket
                // gets probed by *asking it*, not by inferring from a port.
                // Registered only for the native path — a fork+exec'd process
                // shares this filesystem, whereas a container's socket path
                // names a location inside its own mount namespace that kamaji
                // has no route to.
                if let Some(sock) = control_sock_from_spec(spec) {
                    info!(
                        id = %id.0,
                        sock = %sock.display(),
                        "native workload declares a process-control channel — probing it",
                    );
                    ctx.registry
                        .lock()
                        .await
                        .insert_probe(id.clone(), ProbeTarget::control(sock));
                }
                KamajiToYubaba::Ack {
                    request_id,
                    kind: kamaji_proto::AckKind::Deploy,
                }
            }
            Err(e) => KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("native exec: {e:#}"),
            },
        };
    }

    // Deliberately NOT a fallback to a container backend — see
    // [`deploy_container`]'s doc comment. A Darwin build handed to a Linux
    // container is a wrong answer, not a degraded one.
    #[cfg(feature = "native-exec")]
    let reason = "native backend not configured — start kamaji with --native-exec-dir";
    #[cfg(not(feature = "native-exec"))]
    let reason = "kamaji built without the native-exec feature";

    KamajiToYubaba::Error {
        request_id: Some(request_id),
        code: ErrorCode::BackendRefused,
        message: format!(
            "workload requests native host execution ({}={}) but no native backend is \
             available ({reason}); refusing rather than falling back to a container, which \
             would run the job against the wrong operating system (R577-T1)",
            workload_spec::NATIVE_EXEC_ANNOTATION,
            workload_spec::NATIVE_EXEC_VALUE,
        ),
    }
}

/// Boot a microVM-marked container workload in its own KVM guest
/// (R605-F8 / W325 §5) — the hypervisor arm of [`deploy_container`].
///
/// Structurally the twin of [`deploy_native_exec`]: the spec reaching here is
/// an ordinary [`workload_spec::WorkloadSpec`] and only its `yah.exec` value
/// marks it. What differs is the direction of the isolation. The native path
/// exists because some workloads cannot be *contained*; this one exists because
/// some workloads should not be *trusted* with a shared kernel, and it is the
/// only backend here whose boundary survives a kernel-level escape.
///
/// `volumes` are **not** inert on this path, unlike the native one — but they
/// are not bind mounts either. A guest kernel has no route to the host
/// filesystem, so each `Bind` source is copied into a scratch block device
/// before boot and copied back out after the guest halts. See
/// `kamaji::microvm::workspace` for why that round-trip runs through
/// `e2fsprogs` rather than a loop mount.
#[allow(unused_variables)]
async fn deploy_microvm(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: &WorkloadId,
    spec: &workload_spec::WorkloadSpec,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> KamajiToYubaba {
    if let Err(message) = validate_microvm_spec(spec) {
        return KamajiToYubaba::Error {
            request_id: Some(request_id),
            code: ErrorCode::InvalidSpec,
            message,
        };
    }

    #[cfg(feature = "microvm")]
    if let Some(microvm) = ctx.microvm.clone() {
        use kamaji::Kamaji as _;
        let mesh = runtime_mesh(mesh);
        return match microvm.deploy_workload(spec, &mesh).await {
            Ok(result) => {
                info!(
                    id = %id.0,
                    vmm_pid = result.task_pid,
                    "microVM booted"
                );
                KamajiToYubaba::Ack {
                    request_id,
                    kind: kamaji_proto::AckKind::Deploy,
                }
            }
            Err(e) => KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("microvm: {e:#}"),
            },
        };
    }

    // Deliberately NOT a fallback to a container backend — see
    // [`deploy_container`]'s doc comment.
    #[cfg(feature = "microvm")]
    let reason = "microVM backend not configured — start kamaji with --microvm-dir, and check \
                  that the node has a guest kernel + rootfs and that the service user can open \
                  /dev/kvm";
    #[cfg(not(feature = "microvm"))]
    let reason = "kamaji built without the microvm feature";

    KamajiToYubaba::Error {
        request_id: Some(request_id),
        code: ErrorCode::BackendRefused,
        message: format!(
            "workload requests microVM isolation ({}={}) but no microVM backend is available \
             ({reason}); refusing rather than falling back to a container, which would run the \
             job with the host kernel the caller asked to be isolated from (R605-F8)",
            workload_spec::NATIVE_EXEC_ANNOTATION,
            workload_spec::MICROVM_EXEC_VALUE,
        ),
    }
}

/// Admission floor for a microVM workload (R605-F8), returning the operator
/// message on refusal.
///
/// The counterpart to [`validate_native_exec_spec`], and deliberately a
/// *shorter* list than that one — the two guards differ exactly where the
/// substrates differ:
///
/// | check | native | microVM | why |
/// |---|---|---|---|
/// | `tier == "infra"` | yes | **no** | native runs argv on the host with no sandbox; a guest is a sandbox |
/// | env fully resolved | yes | yes | both write literals only, and both would run silently without the value |
/// | rejects `yah.sandbox` | yes | yes | neither has an OCI spec to widen |
///
/// The tier gate is the interesting omission. `validate_native_exec_spec`
/// carries it because native execution "is the widest escape hatch kamaji has",
/// and the same reasoning run over a microVM produces the opposite answer: it
/// is the *narrowest*. Gating it to `tier = "infra"` would mean a tenant
/// workload is allowed to share the host kernel but not allowed to be isolated
/// from it, which is backwards. Forge workloads are `tier = "infra"` anyway, so
/// this is not a relaxation of anything running today — it is a refusal to
/// write a rule that would be wrong the first time it mattered.
fn validate_microvm_spec(spec: &workload_spec::WorkloadSpec) -> Result<(), String> {
    // The microVM backend writes only `EnvValue::Literal` vars into the guest's
    // job document and has no way to resolve the rest — a guest cannot call
    // back into yubaba's secret store. An unresolved secret would therefore run
    // the build with the variable simply absent, failing far from its cause.
    // Same argument, same words, as the native path.
    for env in &spec.env {
        match &env.value {
            workload_spec::EnvValue::Literal { .. } => {}
            workload_spec::EnvValue::FromSecret { secret, .. } => {
                return Err(format!(
                    "env {} carries an unresolved FromSecret({secret}) — yubaba must resolve \
                     before Deploy; the guest has no route back to the secret store",
                    env.name
                ));
            }
            workload_spec::EnvValue::FromMesh { ident, .. } => {
                return Err(format!(
                    "env {} carries an unresolved FromMesh({}) — yubaba must resolve before \
                     Deploy; the guest has no route back to the mesh registry",
                    env.name, ident.0
                ));
            }
        }
    }

    // The nested-sandbox grant is an OCI capability set applied while building a
    // container's process spec. A microVM has no OCI spec, so — exactly as on
    // the native path (R577-T1) — accepting the pair would mean accepting a
    // request for widened privileges and ignoring it.
    //
    // Worth being precise about what is and is not being refused here: this is
    // *not* a claim that the guest must not have those capabilities. Inside its
    // own kernel it may well need them, and granting them there takes nothing
    // from the host. What cannot be honoured is this particular annotation,
    // whose meaning is defined in terms of a container that does not exist on
    // this path. A microVM that needs to describe its guest's privileges should
    // get its own marker rather than borrowing one whose answer to "what does
    // this grant?" would then depend on which backend received it.
    if spec.wants_nested_sandbox() {
        return Err(format!(
            "workload requests both microVM isolation ({}={}) and the nested-sandbox grant \
             ({}={}); these are mutually exclusive — the grant widens a container's capability \
             set and a microVM has no container. Drop one (R605-F8 / R636-B2)",
            workload_spec::NATIVE_EXEC_ANNOTATION,
            workload_spec::MICROVM_EXEC_VALUE,
            workload_spec::NESTED_SANDBOX_ANNOTATION,
            workload_spec::NESTED_SANDBOX_VALUE,
        ));
    }

    Ok(())
}

/// The process-control socket a spec declares, if any (R715-F3 / W315).
///
/// The declaration *is* `$YAH_CONTROL_SOCK` in the spec's env — the same
/// variable the workload reads to know where to bind. Deriving kamaji's probe
/// from the one value the supervisor already hands the process means there is
/// no second place to keep in sync, and no way to probe a path the workload was
/// never told about.
///
/// Only a literal counts: a secret-ref or mesh-ref resolves at deploy time
/// somewhere else, and a socket path is neither.
fn control_sock_from_spec(spec: &workload_spec::WorkloadSpec) -> Option<std::path::PathBuf> {
    spec.env
        .iter()
        .find(|e| e.name == procctl::CONTROL_SOCK_ENV)
        .and_then(|e| match &e.value {
            workload_spec::EnvValue::Literal { value } if !value.is_empty() => {
                Some(std::path::PathBuf::from(value))
            }
            _ => None,
        })
}

/// Admission floor for a native-exec workload (R577-T1), returning the operator
/// message on refusal.
///
/// The containerd path has `containerd::validate_spec_for_constable`; this is
/// its counterpart for the native path, which never goes through that function
/// (and is compiled out entirely in a build without `containerd-integration`).
/// Both checks below exist in the containerd version too — they matter *more*
/// here, because a native workload has no sandbox to fall back on.
fn validate_native_exec_spec(spec: &workload_spec::WorkloadSpec) -> Result<(), String> {
    // Native exec is the widest escape hatch kamaji has: no netns, no cgroup,
    // no capability drop, no rootfs — argv runs as the kamaji user on the host.
    // Host networking and the nested-sandbox grant are both gated to tier=infra
    // for strictly weaker reasons (see `validate_spec_for_constable`), so this
    // gets the same gate. Forge workloads are tier=infra by construction, so
    // this costs the Darwin build leg nothing.
    if spec.tier.0 != "infra" {
        return Err(format!(
            "workload requests native host execution (annotation {}={}) but tier is {:?}; \
             native execution runs argv on the host with no sandbox and is only permitted \
             for tier=\"infra\" (R577-T1)",
            workload_spec::NATIVE_EXEC_ANNOTATION,
            workload_spec::NATIVE_EXEC_VALUE,
            spec.tier.0,
        ));
    }

    // The native backend spawns only `EnvValue::Literal` vars and *silently
    // skips* the rest. An unresolved secret would therefore not fail the
    // deploy — it would run the build with the variable simply absent, and a
    // `codesign` that finds no identity fails somewhere far from the cause.
    // Resolving these is yubaba's job; reaching kamaji unresolved is a bug in
    // its admission layer, and this says so instead of absorbing it.
    for env in &spec.env {
        match &env.value {
            workload_spec::EnvValue::Literal { .. } => {}
            workload_spec::EnvValue::FromSecret { secret, .. } => {
                return Err(format!(
                    "env {} carries an unresolved FromSecret({secret}) — yubaba must resolve \
                     before Deploy; the native backend would drop it silently",
                    env.name
                ));
            }
            workload_spec::EnvValue::FromMesh { ident, .. } => {
                return Err(format!(
                    "env {} carries an unresolved FromMesh({}) — yubaba must resolve before \
                     Deploy; the native backend would drop it silently",
                    env.name, ident.0
                ));
            }
        }
    }

    // The nested-sandbox grant (R636-B2) and native exec are mutually
    // exclusive at dispatch even though they are independent annotations on
    // the spec. That grant is a *container* capability set — CAP_SETUID +
    // CAP_SETGID and `no_new_privs` off, applied while building the OCI spec —
    // and a native workload has no OCI spec to apply it to. Routing on the
    // native marker first (see `deploy_container`) would therefore accept a
    // spec asking for widened privileges and ignore the request entirely.
    //
    // Silently ignoring a security-relevant annotation is the wrong failure
    // mode in both directions: an operator reading the spec would believe the
    // grant applied, and a future reader could "fix" the omission by wiring
    // capabilities into a path that has no sandbox to widen in the first
    // place. Today's only setter of the grant is `build_image_workload_spec`,
    // which the dispatcher already refuses to send native — but kamaji takes
    // this off the wire and must not infer its input from what one dispatcher
    // happens to emit.
    if spec.wants_nested_sandbox() {
        return Err(format!(
            "workload requests both native host execution ({}={}) and the nested-sandbox \
             grant ({}={}); these are mutually exclusive — the grant widens a container's \
             capability set and native execution has no container. Drop one (R577-T1 / R636-B2)",
            workload_spec::NATIVE_EXEC_ANNOTATION,
            workload_spec::NATIVE_EXEC_VALUE,
            workload_spec::NESTED_SANDBOX_ANNOTATION,
            workload_spec::NESTED_SANDBOX_VALUE,
        ));
    }

    Ok(())
}

/// Wire assignment → the runtime [`kamaji::MeshAssignment`] the backends take
/// (R599-F12), with the loopback sentinel standing in for "no mesh plane".
///
/// The two types are deliberately distinct — the wire one is a cross-binary
/// contract — so this is the single conversion point in the daemon. It is
/// cfg-gated because `kamaji` is an *optional* dependency here: a default build
/// carries no backend and therefore no runtime type to convert into.
#[cfg(any(
    feature = "docker-integration",
    feature = "bundle-serving",
    feature = "native-exec",
    feature = "microvm",
    feature = "tenant-passway"
))]
fn runtime_mesh(mesh: Option<&kamaji_proto::MeshAssignment>) -> kamaji::MeshAssignment {
    let Some(mesh) = mesh else {
        return kamaji::MeshAssignment::inlined(std::net::Ipv4Addr::LOCALHOST);
    };
    kamaji::MeshAssignment {
        mesh_ip: mesh.mesh_ip,
        wg_private_key: mesh.wg_private_key.clone(),
        wg_listen_port: mesh.wg_listen_port,
        peers: mesh
            .peers
            .iter()
            .map(|p| kamaji::WireguardPeer {
                public_key: p.public_key.clone(),
                endpoint: p.endpoint,
                allowed_ips: p.allowed_ips.clone(),
            })
            .collect(),
        netns_name: mesh.netns_name.clone(),
    }
}

/// The address a **natively forked** workload must bind (R599-F12).
///
/// This is the half of the mesh gap that actually moves bytes. A native
/// workload is a plain host process — no netns, no per-workload interface — so
/// the address it binds has to be one that already exists on this node. When
/// yubaba sends an assignment it is sending exactly that (its own node mesh
/// address); with none, loopback, which is the pre-R599-F12 behaviour and the
/// only correct answer on a node with no mesh plane.
///
/// Binding the mesh address rather than loopback is what makes the workload
/// reachable *from another node*, which is what lets an ingress proxy stop
/// having to be co-located with the thing it fronts (W267).
#[cfg(feature = "bundle-serving")]
fn native_bind_ip(mesh: Option<&kamaji_proto::MeshAssignment>) -> std::net::Ipv4Addr {
    mesh.map(|m| m.mesh_ip)
        .unwrap_or(std::net::Ipv4Addr::LOCALHOST)
}

/// The `BackendRefused` a `Deploy { Container }` gets when no container backend
/// is available, spelled out per compiled-in feature.
///
/// Operators hit this in two very different situations — a binary built without
/// the backend, and a binary built with it but started without its flags — and
/// the remedies differ (rebuild vs restart). Naming the state of each backend
/// separately means the message is actionable without reading kamaji's source.
fn no_container_backend_error(request_id: kamaji_proto::RequestId) -> KamajiToYubaba {
    let mut reasons: Vec<&str> = Vec::new();

    #[cfg(feature = "containerd-integration")]
    reasons.push("containerd backend not configured — start kamaji with --containerd-socket");
    #[cfg(not(feature = "containerd-integration"))]
    reasons.push("kamaji built without containerd-integration feature");

    #[cfg(feature = "docker-integration")]
    reasons.push("docker backend not configured — start kamaji with --docker");
    #[cfg(not(feature = "docker-integration"))]
    reasons.push("kamaji built without docker-integration feature");

    KamajiToYubaba::Error {
        request_id: Some(request_id),
        code: ErrorCode::BackendRefused,
        message: format!(
            "no container backend available; Container workloads cannot be deployed ({})",
            reasons.join("; ")
        ),
    }
}

/// Dispatch a serve-bundle mesofact-static workload (R599-F4) to the native
/// backend: materialize the W272 bundle from the node store (R599-F1) and fork
/// the serve runtime under kamaji's native supervisor (R599-F10).
///
/// With the `bundle-serving` feature both lifecycles are live, routed on
/// `bundle.lifecycle` after a shared materialize → serve-bin-resolution front
/// (self → `<dir>/bins/<triple>/serve`; any named runtime →
/// `<cache>/runtimes/…/<triple>/serve`, fetched and blake3-verified from the
/// bundle store on a miss, R746-F1):
/// - **KeepAlive** ([`deploy_bundle_keepalive`], R599-F10) forks
///   `mesofact-serve --bundle <dir> --listen <addr>` as a resident process
///   under the native supervisor.
///
/// Both resolve `<addr>` the same way (R599-F12): the `mesh` assignment's IP
/// when yubaba sent one, loopback when it did not, paired with the workload's
/// own `serve_bundle.port` or the node-wide fallback.
/// - **OnDemand** ([`deploy_bundle_on_demand`], R599-F6) binds+holds the listen
///   socket in the [`JitRuntime`] and forks the serve runtime on the first
///   connection (`--idle-ttl <secs>`, socket activation), reaping it when idle.
///   The Ack means "socket bound and armed", not "process running".
///
/// Without the feature (default build), an admitted serve-bundle deploy reports
/// `BackendRefused` — the workload is *recognized* (no longer `InvalidSpec`) but
/// this kamaji build has no bundle backend, exactly as a `Container` deploy
/// reports `BackendRefused` without containerd.
///
/// **Drain caveat:** each runtime is the single owner of its child(ren), so a
/// bundle deploy does NOT register a pidfd `DrainableHandle` (that would
/// double-own the process and race the supervisor's reaper). Structured Drain of
/// a bundle workload is therefore not wired — a `Drain` returns
/// `DrainAck { accepted:false, reason:"unknown workload" }`; teardown is via
/// `Stop`, which routes to both runtimes' idempotent `teardown_workload`.
#[allow(unused_variables)]
async fn deploy_mesofact_bundle(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: &WorkloadId,
    bundle: &workload_spec::MesofactServeBundle,
    revalidate: Option<&workload_spec::MesofactRevalidateReceiver>,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> KamajiToYubaba {
    #[cfg(feature = "bundle-serving")]
    {
        // R330-F33: this reply is an *admission* decision, not an outcome.
        //
        // Everything below the admission checks — the per-blob R2 fetch, the
        // blake3 verify, the fork — is unbounded node work that used to be done
        // with the caller's request held open all the way from `yah cloud
        // apply`. A cold materialize of a bundle carrying its own 71MB serve
        // binary outruns any client patience worth configuring, and the caller
        // giving up did not stop the deploy: it succeeded on the node while the
        // operator was told it had timed out.
        //
        // So admit synchronously, then hand the slow half to a task and let the
        // caller poll `DeployStatus`. What can still fail *here* is only what
        // kamaji can decide without touching disk or network.
        if ctx.bundle.is_none() {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!(
                    "no bundle backend configured on this kamaji instance to serve mesofact \
                     bundle for {} — start kamaji with a node bundle store \
                     (ServerCtx::with_bundle_backend)",
                    id.0
                ),
            };
        }
        if let Err(e) = yah_mesofact_bundle::BundleHash::parse(bundle.digest.0.clone()) {
            // A malformed digest is decidable now, so it stays a synchronous
            // rejection rather than becoming a deploy that fails a poll later.
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::InvalidSpec,
                message: format!(
                    "bundle digest {:?} is not a valid blake3: {e}",
                    bundle.digest.0
                ),
            };
        }

        // R755-B5: remember the admission before acting on it. A deploy kamaji
        // cannot record is a deploy the next restart would silently drop, so a
        // record failure is a refusal here, not a warning — the disk this fails
        // on is the same one the materialize below needs anyway.
        let record = BundleDeployRecord {
            id: id.0.clone(),
            bundle: bundle.clone(),
            revalidate: revalidate.cloned(),
            mesh: mesh.cloned(),
        };
        if let Err(e) = ctx.bundle.as_ref().expect("checked above").record_deploy(&record) {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!(
                    "cannot persist the bundle deploy record for {} (it would not survive a \
                     kamaji restart): {e}",
                    id.0
                ),
            };
        }

        spawn_bundle_run(ctx, record).await;

        KamajiToYubaba::Ack {
            request_id,
            kind: kamaji_proto::AckKind::Deploy,
        }
    }
    #[cfg(not(feature = "bundle-serving"))]
    {
        let _ = ctx;
        let _ = revalidate;
        let lifecycle = match &bundle.lifecycle {
            workload_spec::BundleLifecycle::KeepAlive => "keep-alive".to_string(),
            workload_spec::BundleLifecycle::OnDemand { idle_ttl } => {
                format!("on-demand(idle_ttl={}ms)", idle_ttl.as_ms())
            }
        };
        KamajiToYubaba::Error {
            request_id: Some(request_id),
            code: ErrorCode::BackendRefused,
            message: format!(
                "mesofact bundle {} (runtime={}, lifecycle={lifecycle}) admitted for {} but this \
                 kamaji was built without the native bundle backend — rebuild with \
                 --features bundle-serving to serve keep-alive bundles (R599-F10)",
                bundle.digest.0, bundle.runtime, id.0
            ),
        }
    }
}

/// The post-Ack half of a serve-bundle deploy, shared by a fresh `Deploy` and
/// a restart-time resume (R755-B5): mark the workload `Pending`, then run the
/// lifecycle-appropriate slow path (materialize → resolve serve bin → fork /
/// arm) on its own task and record the outcome for `DeployStatus`.
///
/// Route by lifecycle: keep-alive forks a resident process (R599-F10);
/// on-demand hands the socket to a lazily-forked, idle-reaped process
/// (R599-F6). Both share the materialize + serve-bin-resolution front.
#[cfg(feature = "bundle-serving")]
async fn spawn_bundle_run(ctx: &Arc<ServerCtx>, record: BundleDeployRecord) {
    let id = WorkloadId::new(&record.id);
    ctx.registry
        .lock()
        .await
        .set_deploy_progress(id.clone(), DeployProgress::at(WorkloadState::Pending));

    let task_ctx = Arc::clone(ctx);
    tokio::spawn(async move {
        let BundleDeployRecord {
            bundle: task_bundle,
            revalidate: task_revalidate,
            mesh: task_mesh,
            ..
        } = record;
        let outcome = match &task_bundle.lifecycle {
            workload_spec::BundleLifecycle::KeepAlive => {
                run_bundle_keepalive(
                    &task_ctx,
                    &id,
                    &task_bundle,
                    task_revalidate.as_ref(),
                    task_mesh.as_ref(),
                )
                .await
            }
            workload_spec::BundleLifecycle::OnDemand { idle_ttl } => {
                let idle_ttl = *idle_ttl;
                run_bundle_on_demand(
                    &task_ctx,
                    &id,
                    &task_bundle,
                    idle_ttl,
                    task_revalidate.as_ref(),
                    task_mesh.as_ref(),
                )
                .await
            }
        };
        let progress = match outcome {
            Ok(()) => DeployProgress::at(WorkloadState::Running),
            Err(reason) => {
                // Nobody is waiting on this call any more, so the log is the
                // only place an operator not polling will ever see it.
                warn!(id = %id.0, %reason, "asynchronous bundle deploy failed");
                DeployProgress::failed(reason)
            }
        };
        task_ctx
            .registry
            .lock()
            .await
            .set_deploy_progress(id, progress);
    });
}

#[cfg(feature = "bundle-serving")]
impl ServerCtx {
    /// R755-B5: replay every recorded bundle deploy through the normal post-Ack
    /// path. Call once at startup, before the UDS starts answering — a
    /// control-plane roll restarts kamaji and SIGKILLs every served bundle, and
    /// without this the node forgets its sites until someone re-runs `yah cloud
    /// apply`. Returns how many records were replayed. A no-op without a bundle
    /// backend or with no records.
    pub async fn resume_bundle_workloads(self: &Arc<Self>) -> usize {
        let Some(backend) = &self.bundle else {
            return 0;
        };
        let records = backend.recorded_deploys();
        for record in &records {
            info!(
                id = %record.id,
                digest = %record.bundle.digest.0,
                runtime = %record.bundle.runtime,
                "resuming recorded bundle deploy after restart (R755-B5)"
            );
            spawn_bundle_run(self, record.clone()).await;
        }
        records.len()
    }
}

/// Materialize the W272 bundle tree from the node store (R599-F1) and resolve
/// the serve binary path (W272 §2/§3), shared by the keep-alive and on-demand
/// deploy paths. Returns `(bundle_dir, serve_bin)` or, as `Err`, the reason.
///
/// R330-F33 turned the `Err` side from a ready-made `KamajiToYubaba::Error`
/// into a plain string: this now runs *after* the Deploy has been acked, so
/// there is no longer a reply to put a failure in. It lands in
/// [`DeployProgress::failed`] and comes back out of a `DeployStatus` poll.
#[cfg(feature = "bundle-serving")]
async fn materialize_and_resolve_serve(
    backend: &BundleBackend,
    id: &WorkloadId,
    bundle: &workload_spec::MesofactServeBundle,
) -> std::result::Result<(PathBuf, PathBuf), String> {
    // 1. Materialize the bundle tree from the node store (R599-F1). The digest is
    //    the content-address; a bad hex shape is a spec error, not a backend one.
    let digest = yah_mesofact_bundle::BundleHash::parse(bundle.digest.0.clone())
        .map_err(|e| format!("bundle digest {:?} is not a valid blake3: {e}", bundle.digest.0))?;

    // R870-B6: the workload's own store, with the node's behind it. Resolved
    // once here and reused for the runtime asset below — the manifest, the
    // blobs and the serve runtime all have to come from the same chain, or a
    // tenant's bundle materializes and then fails to find anything to fork it
    // with.
    let workload_store = backend.store_for(bundle.origin.as_deref()).await?;

    // Cache materialize is synchronous fs + object-store I/O (a cold deploy may
    // fetch from R2). Run it on the blocking pool so the dispatch loop isn't
    // parked. A fresh BundleCache is cheap and stateless beyond root+budget.
    let store = Arc::clone(&workload_store);
    let cache_dir = backend.cache_dir.clone();
    let budget = backend.cache_budget;
    let digest_for_task = digest.clone();
    let materialized = tokio::task::spawn_blocking(move || {
        yah_mesofact_bundle::BundleCache::new(cache_dir, budget)
            .ensure(store.as_ref(), &digest_for_task)
    })
    .await;
    let bundle_dir = match materialized {
        Ok(Ok(dir)) => dir,
        Ok(Err(e)) => return Err(format!("materialize bundle {}: {e}", digest.as_str())),
        Err(e) => return Err(format!("bundle materialize task failed: {e}")),
    };

    // 1b. Read the materialized manifest for the contract version this bundle
    //     requires (R746-F6). It comes from the tree rather than the workload
    //     spec on purpose: the manifest's bytes are covered by the digest
    //     materialize just verified, so it cannot disagree with the bundle it
    //     describes, and no new wire field has to be kept in sync to say so.
    let manifest_path = bundle_dir.join("manifest.toml");
    let requires_contract = match std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("reading {}: {e}", manifest_path.display()))
        .and_then(|text| {
            yah_mesofact_bundle::BundleManifest::from_toml_str(&text)
                .map_err(|e| format!("parsing {}: {e}", manifest_path.display()))
        }) {
        Ok(manifest) => manifest.requires_contract,
        Err(e) => return Err(format!("materialized bundle {}: {e}", digest.as_str())),
    };

    // 2. Resolve the serve binary from the runtime selector (W272 §2/§3).
    let triple = node_triple();
    let serve_bin = if bundle.runtime == "self" {
        // Custom bundle ships its own bins/<triple>/serve inside the tree — its
        // bytes are covered by the bundle digest materialize just verified.
        bundle_dir.join("bins").join(&triple).join("serve")
    } else {
        // Vanilla bundle names its runtime and the node resolves it from the
        // shared runtime-asset tier (R746-F1), fetching + blake3-verifying it
        // from the bundle store on a miss. Same blocking pool as the
        // materialize above: a cold fetch is a ~70MB download.
        let runtime = yah_mesofact_bundle::RuntimeRef::parse(&bundle.runtime)
            .map_err(|e| format!("bundle runtime {:?}: {e}", bundle.runtime))?;
        // Same chain the materialize used (R870-B6). A tenant may publish its
        // own runtime asset; one that doesn't reads through to the node origin's
        // stock copy, and the miss costs one extra GET on a cold resolve only.
        let store = Arc::clone(&workload_store);
        let cache_dir = backend.cache_dir.clone();
        let triple_for_task = triple.clone();
        let resolved = tokio::task::spawn_blocking(move || {
            yah_mesofact_bundle::ensure_runtime_asset(
                store.as_ref(),
                &cache_dir,
                &runtime,
                &triple_for_task,
                yah_mesofact_bundle::SERVE_BIN,
                // R746-F6: the node-side backstop on the bundle↔runtime
                // contract. `yah cloud apply` refuses this pair before it ever
                // reaches a node; this catches the paths that don't go through
                // an apply — a workload deployed before the gate existed being
                // restarted, or a hand-rolled deploy — and it fails before the
                // ~70MB download rather than after.
                yah_mesofact_bundle::ContractRequirement::Version(requires_contract),
            )
        })
        .await;
        match resolved {
            Ok(Ok(path)) => path,
            // The error already names the runtime, the triple, and where it
            // looked (BundleError::RuntimeAssetMissing) or both contract
            // versions (BundleError::ContractUnsatisfied).
            Ok(Err(e)) => return Err(format!("serve runtime asset missing: {e}")),
            Err(e) => return Err(format!("runtime asset fetch task failed: {e}")),
        }
    };
    if !serve_bin.exists() {
        // Only reachable for `self` now — `ensure_runtime_asset` returns a path
        // it wrote. Kept as the self arm's missing-binary report.
        return Err(format!(
            "serve runtime asset missing at {} (triple={triple}, runtime={}): a \"self\" \
             bundle must ship bins/<triple>/serve",
            serve_bin.display(),
            bundle.runtime
        ));
    }
    // The serve bin must be executable to fork it. materialize_bundle writes blob
    // bytes 0644, and the stock runtime-asset fetch may not set +x either — ensure
    // it here (best-effort; a still-non-exec bin surfaces as the fork error below).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&serve_bin) {
            let mode = meta.permissions().mode();
            if mode & 0o111 == 0 {
                let mut perms = meta.permissions();
                perms.set_mode(mode | 0o755);
                let _ = std::fs::set_permissions(&serve_bin, perms);
            }
        }
    }
    let _ = id;
    Ok((bundle_dir, serve_bin))
}

/// The slow half of a keep-alive bundle deploy (R599-F10), run off the dispatch
/// loop by [`deploy_mesofact_bundle`] after the Deploy has been acked.
/// Materialize the W272 bundle, resolve the serve binary, and fork it under the
/// native supervisor as a resident process. See [`deploy_mesofact_bundle`] for
/// the Drain caveat.
#[cfg(feature = "bundle-serving")]
async fn run_bundle_keepalive(
    ctx: &Arc<ServerCtx>,
    id: &WorkloadId,
    bundle: &workload_spec::MesofactServeBundle,
    revalidate: Option<&workload_spec::MesofactRevalidateReceiver>,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> std::result::Result<(), String> {
    use std::net::SocketAddr;

    // Admission already established the backend is present; re-borrowing it in
    // the spawned task is the only way to reach it without holding a borrow
    // across the spawn.
    let backend = ctx
        .bundle
        .as_ref()
        .ok_or_else(|| format!("bundle backend vanished between admission and deploy of {}", id.0))?;

    let (bundle_dir, serve_bin) = materialize_and_resolve_serve(backend, id, bundle).await?;

    // Materialized — the fork is next, which is what `Starting` means.
    ctx.registry
        .lock()
        .await
        .set_deploy_progress(id.clone(), DeployProgress::at(WorkloadState::Starting));

    // Build the native WorkloadSpec (identity image, entrypoint=[serve_bin],
    // command=[--bundle <dir> --listen <addr>]) and fork it.
    //
    // R599-F12: the bind address is the workload's mesh address when yubaba
    // admitted one, loopback otherwise. Those two together are what close
    // R599-F10's follow-up — a mesh-bound listener is reachable from another
    // node, and a per-workload port means the node is no longer limited to the
    // one bundle that fits on 8080.
    //
    // R844-F2: the port now comes from the node's allocator rather than
    // `bundle.port.unwrap_or(backend.bind_port)` — allocated and remembered,
    // instead of silently landing on the node-wide 8080 that made "per-workload
    // port" true only for bundles whose operator had written one down.
    //
    // R844-F14: and a written-down number no longer wins. It rides in as
    // `PortSpec.pin`, where a non-world-fixed pin FAILS this deploy naming the
    // port — a stale mirror `[providers.bundle] port` is exactly the number
    // that would otherwise land on a co-tenant's listener.
    let bind_ip = native_bind_ip(mesh);
    let port = backend.resolve_port(&id.0, bind_ip, backend.http_spec(bundle))?;
    let listen = format!("{bind_ip}:{port}");
    // R556-T12: `bundle.env` is the deploy-resolved serve environment. Until it
    // existed, the static / SSR server was the one bundle process forked with
    // an empty env — an SSR route reading a private source got a
    // credential-less child that failed per request, while the revalidate
    // receiver beside it had had creds since R330-F12.
    let spec = bundle_workload_spec(id, &serve_bin, &bundle_dir, &listen, &bundle.env);
    let mesh = runtime_mesh(mesh);

    backend
        .native
        .deploy_workload(&spec, &mesh)
        .await
        .map_err(|e| format!("native fork of mesofact-serve for {} failed: {e:#}", id.0))?;

    // Register a probe target so Probe RPCs actually dial the serve
    // process (the only registry state a bundle deploy writes). It must
    // dial the address the process actually bound, not loopback.
    ctx.registry.lock().await.insert_probe(
        id.clone(),
        ProbeTarget::healthcheck(
            workload_spec::Healthcheck {
                probe: workload_spec::HealthProbe::TcpConnect { port },
                interval: workload_spec::Millis::from_ms(1000),
                timeout: workload_spec::Millis::from_ms(500),
                initial_delay: workload_spec::Millis::from_ms(0),
                failure_threshold: 3,
            },
            SocketAddr::from((bind_ip, port)),
        ),
    );

    // R330-F12: when the mirror declared a revalidate receiver, fork a
    // second resident `mesofact serve --revalidate` process against the
    // same materialized bundle. A fork failure fails the deploy — the
    // static server stays up (reap it via Stop), but a declared receiver
    // that silently didn't start is the failure to avoid.
    if let Some(rv) = revalidate {
        fork_revalidate_receiver(
            backend,
            id,
            &bundle_dir,
            &serve_bin,
            rv,
            bind_ip,
            bundle.origin.as_deref(),
        )
            .await
            .map_err(|e| {
                format!("mesofact revalidate receiver for {} failed to start: {e}", id.0)
            })?;
    }

    Ok(())
}

/// On-demand (JIT) bundle deploy (R599-F6). Materialize + resolve exactly like
/// keep-alive, then hand the workload to the [`JitRuntime`]: kamaji binds+holds
/// the listen socket and forks the serve runtime on the first connection,
/// reaping it after `idle_ttl`. No resident process is spawned at deploy — the
/// Ack means "the socket is bound and armed", not "a process is running".
///
/// **No probe target is registered** (unlike keep-alive): a `TcpConnect` probe
/// on a 1s interval would connect to the held socket and trigger a fork every
/// interval, defeating the idle reap. Absence of a probe maps to `Ready`
/// ("no probe declared ↔ trust the workload's existence"), which is the right
/// semantics for a serverless workload that is *supposed* to be zero-resident.
#[cfg(feature = "bundle-serving")]
async fn run_bundle_on_demand(
    ctx: &Arc<ServerCtx>,
    id: &WorkloadId,
    bundle: &workload_spec::MesofactServeBundle,
    idle_ttl: workload_spec::Millis,
    revalidate: Option<&workload_spec::MesofactRevalidateReceiver>,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> std::result::Result<(), String> {
    let backend = ctx
        .bundle
        .as_ref()
        .ok_or_else(|| format!("bundle backend vanished between admission and deploy of {}", id.0))?;

    let (bundle_dir, serve_bin) = materialize_and_resolve_serve(backend, id, bundle).await?;

    ctx.registry
        .lock()
        .await
        .set_deploy_progress(id.clone(), DeployProgress::at(WorkloadState::Starting));

    // The serve runtime owns idle detection: pass `--idle-ttl <secs>` and it
    // self-reaps. Round sub-second TTLs up to 1s — a `0` would tell the runtime
    // to never reap, silently turning the serverless workload keep-alive.
    let idle_ttl_secs = idle_ttl.as_ms().div_ceil(1000).max(1);
    // R599-F12: same bind resolution as keep-alive. Here it is the address
    // *kamaji itself* binds and holds as socket custodian, so the mesh address
    // has to be right at deploy time — a JIT bundle that armed on loopback is
    // unreachable off-node for the whole life of the workload.
    //
    // R844-F2: same allocator as keep-alive, and the custody makes it *more*
    // stable rather than less — kamaji holds this socket across every fork and
    // idle-reap, so an on-demand workload never reallocates on wake and the
    // rendered ingress upstream never has to re-resolve mid-flight. The ledger
    // covers the one case custody cannot: kamaji itself restarting.
    let bind_ip = native_bind_ip(mesh);
    let port = backend.resolve_port(&id.0, bind_ip, backend.http_spec(bundle))?;
    let listen = format!("{bind_ip}:{port}");
    // R556-T12: same deploy-resolved env as the keep-alive path. A JIT bundle
    // forks on the first connection, so a credential missing here would surface
    // as a 500 on a visitor's request rather than at deploy.
    let spec = bundle_workload_spec_jit(
        id,
        &serve_bin,
        &bundle_dir,
        &listen,
        idle_ttl_secs,
        &bundle.env,
    );
    let mesh = runtime_mesh(mesh);

    backend
        .jit
        .deploy_on_demand(&spec, &mesh, &listen)
        .await
        .map_err(|e| format!("on-demand bind/arm of mesofact-serve for {} failed: {e:#}", id.0))?;

    // R330-F12: the revalidate receiver is a *resident* process (it must
    // accept pokes at any time), independent of the static server's JIT
    // idle-reaping. Fork it against the same materialized bundle.
    if let Some(rv) = revalidate {
        fork_revalidate_receiver(
            backend,
            id,
            &bundle_dir,
            &serve_bin,
            rv,
            bind_ip,
            bundle.origin.as_deref(),
        )
            .await
            .map_err(|e| {
                format!("mesofact revalidate receiver for {} failed to start: {e}", id.0)
            })?;
    }

    Ok(())
}

/// Build the native [`WorkloadSpec`](workload_spec::WorkloadSpec) that forks
/// `mesofact-serve --bundle <dir> --listen <addr>` for a keep-alive bundle
/// (R599-F10). `image` is identity-only (the native backend pulls nothing);
/// argv is `entrypoint ++ command` = `[serve_bin, --bundle, <dir>, --listen,
/// <addr>]`; restart policy is `Always` (the resident-server archetype).
///
/// R599-F12: `expose.mesh.ports` carries the serving port. It used to be empty,
/// which reads as "this workload declares no ports" — and `expose.mesh.ports`
/// is the one place a workload's serving port is declared (yubaba's
/// `ServiceRecords` module says exactly that), so an empty list there is a
/// bundle a proxy has no address to dial.
#[cfg(feature = "bundle-serving")]
fn bundle_workload_spec(
    id: &WorkloadId,
    serve_bin: &Path,
    bundle_dir: &Path,
    listen: &str,
    env: &std::collections::BTreeMap<String, String>,
) -> workload_spec::WorkloadSpec {
    use workload_spec::{
        ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, NamespaceId, ResourceLimits,
        RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag, WorkloadSpec,
    };
    WorkloadSpec {
        schema_version: SchemaVersion::V1,
        name: id.0.clone(),
        image: ImageRef {
            // Identity metadata only — nothing is pulled for a native workload.
            registry: "bundle".into(),
            repository: format!("mesofact/{}", id.0),
            tag: "serve".into(),
            digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
        },
        tier: TierTag("infra".into()),
        tenant: TenantId::singleton(),
        namespace: NamespaceId::singleton(),
        replicas: 1,
        // `serve` is the SUBCOMMAND, not just the file name. The staged binary
        // is mesofact's consolidated prod binary (W174 §Binary surface), which
        // replaced the flat `mesofact-serve` / `-proxy` / `-publish` trio with
        // `mesofact serve|proxy|publish`. Forking it with a bare `--bundle`
        // makes clap reject the whole invocation ("unexpected argument
        // '--bundle' found") before it ever binds, and kamaji logs nothing —
        // the workload just sits in `Starting` with no pid. That is exactly how
        // this path looked when R330-F37 first ran it end to end: the flat form
        // matched the binary that existed when R599-F10 was written and nothing
        // re-checked it after the consolidation landed.
        command: Some(vec![
            "serve".into(),
            "--bundle".into(),
            bundle_dir.to_string_lossy().into_owned(),
            "--listen".into(),
            listen.to_string(),
        ]),
        entrypoint: Some(vec![serve_bin.to_string_lossy().into_owned()]),
        workdir: None,
        user: None,
        // R556-T12. This used to be a hard-coded `vec![]`, which is what made
        // every bundle-tier serve process credential-less by construction: the
        // env is now a *parameter*, so no caller can fork one of these without
        // deciding what it runs with.
        env: bundle_env_vars(env),
        secrets: vec![],
        volumes: vec![],
        resources: ResourceLimits {
            memory_mb: 128,
            cpu_millis: 256,
            ephemeral_storage_mb: 128,
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
                identity: MeshIdent(id.0.clone()),
                // Parsed back off `listen` rather than passed separately, so
                // the declared port cannot drift from the one actually bound.
                //
                // Named `http` explicitly (R844-F17): the allocator that chose
                // this number asked for it under that name
                // (`ServeState::http_spec` -> `PortSpec::http()`), so stating
                // it here means the service record publishes the name the
                // allocator used rather than one `name_anonymous_ports`
                // re-derives from the count. Same value either way today; the
                // difference is that it stays right if a bundle ever serves a
                // second listener.
                ports: listen
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse::<u16>().ok())
                    .map(|p| workload_spec::MeshPort::pinned(kamaji::ports::HTTP, p))
                    .into_iter()
                    .collect(),
                allow_from: vec![],
            },
            public: None,
            operator: None,
        },
        labels: Default::default(),
        annotations: Default::default(),
    }
}

/// Render a deploy-resolved `NAME → value` map as the
/// [`EnvVar`](workload_spec::EnvVar) list a forked bundle process carries
/// (R556-T12).
///
/// Every entry is a [`Literal`](workload_spec::EnvValue::Literal): the values
/// arrived already resolved from the operator's vault, so the node holds no
/// keystore slot names and needs no resolver of its own — the same contract
/// the revalidate receiver's `env` has carried since R330-F12.
#[cfg(feature = "bundle-serving")]
fn bundle_env_vars(env: &std::collections::BTreeMap<String, String>) -> Vec<workload_spec::EnvVar> {
    use workload_spec::{EnvValue, EnvVar};
    env.iter()
        .map(|(name, value)| EnvVar {
            name: name.clone(),
            value: EnvValue::Literal {
                value: value.clone(),
            },
        })
        .collect()
}

/// Build the [`WorkloadSpec`](workload_spec::WorkloadSpec) the on-demand (JIT)
/// runtime forks (R599-F6). Same shape as [`bundle_workload_spec`] plus
/// `--idle-ttl <secs>` so the serve runtime self-reaps on idle. `--listen` is
/// still passed as the fallback bind address, but the JIT runtime hands the
/// process kamaji's held socket via `LISTEN_FDS`, which takes precedence in
/// `mesofact-serve`'s `socket_activation_listener`. `restart_policy` is `Never`:
/// the JIT supervisor — not a restart loop — owns re-forking on the next
/// connection, and an idle self-reap is an *expected* exit, not a crash to
/// restart.
#[cfg(feature = "bundle-serving")]
fn bundle_workload_spec_jit(
    id: &WorkloadId,
    serve_bin: &Path,
    bundle_dir: &Path,
    listen: &str,
    idle_ttl_secs: u64,
    env: &std::collections::BTreeMap<String, String>,
) -> workload_spec::WorkloadSpec {
    use workload_spec::RestartPolicy;
    let mut spec = bundle_workload_spec(id, serve_bin, bundle_dir, listen, env);
    // Append the idle-ttl flag to the serve argv (command follows entrypoint).
    if let Some(cmd) = spec.command.as_mut() {
        cmd.push("--idle-ttl".into());
        cmd.push(idle_ttl_secs.to_string());
    }
    // The JIT supervisor re-forks on demand; a self-reap must not be restarted.
    spec.restart_policy = RestartPolicy::Never;
    spec
}

/// Fork the resident `mesofact serve --revalidate` receiver (R330-F12) — the
/// almanac push endpoint that mounts `POST /revalidate` and, on each poke, boots
/// V8 to re-render the route and republish to R2.
///
/// It runs against the *same* materialized bundle as the static server:
/// `--workload <bundle>/app`, so its V8 re-render reads
/// `<bundle>/app/dist/manifest.json`, and `--publish-config
/// <bundle>/app/<publish_config>` — the `[publish]` block the bundle assembly
/// staged next to `dist/` (creds still resolve from `env`, never the file).
/// Bound to its own allocated port on the same address (R844-F14). It used to
/// take the number immediately above the static server's, which only kept two
/// bundles disjoint (R599-F12) while both had *declared* ports; with every
/// number allocated, `serve + 1` is an arbitrary port the ledger may already
/// have promised elsewhere on this node. A ledger entry under
/// `<id>-revalidate` is the same guarantee without the arithmetic. `env` (R2
/// creds + `MESOFACT_MIRROR_KEY`) is resolved deploy-side and set on the child;
/// the node never sees keystore slot names.
///
/// Registered under `<id>-revalidate` so it is a separate row from the static
/// server in `List`/`Stop`. No probe target: the receiver's readiness is not on
/// the serve path, and a `TcpConnect` probe would add churn for no signal.
#[cfg(feature = "bundle-serving")]
async fn fork_revalidate_receiver(
    backend: &BundleBackend,
    id: &WorkloadId,
    bundle_dir: &Path,
    serve_bin: &Path,
    receiver: &workload_spec::MesofactRevalidateReceiver,
    bind_ip: std::net::Ipv4Addr,
    // R870-B6: the workload's `serve_bundle.origin`, carried through only so
    // the feed tier below resolves its runtime asset from the same store the
    // serve binary came from.
    origin: Option<&str>,
) -> std::result::Result<(), String> {
    let rv_id = WorkloadId(format!("{}-revalidate", id.0));
    // R844-F14: the receiver is its own ident with its own `http` port, not a
    // number derived from the static server's. See this function's docs.
    let rv_port = backend.resolve_port(&rv_id.0, bind_ip, kamaji::ports::PortSpec::http())?;
    let listen = format!("{bind_ip}:{rv_port}");
    let spec = bundle_workload_spec_revalidate(&rv_id, serve_bin, bundle_dir, &listen, receiver);
    let mesh = kamaji::MeshAssignment::inlined(bind_ip);
    backend
        .native
        .deploy_workload(&spec, &mesh)
        .await
        .map(|_res| ())
        .map_err(|e| format!("native fork of mesofact-serve --revalidate failed: {e:#}"))?;

    // R330-F31: a receiver with declared feeds also needs the fetch tier, or it
    // re-renders the data the bundle was built with forever. It is forked after
    // the receiver because its whole job is to poke it.
    if !receiver.feeds.is_empty() {
        fork_feed_tier(backend, id, bundle_dir, &listen, receiver, origin).await?;
    }
    Ok(())
}

/// Fork the resident `almanac-feed` fetcher (R330-F31) — the tier that refreshes
/// each declared feed's artifact **on the node** and pokes the receiver when it
/// actually changed.
///
/// It runs against the same materialized bundle: `--project-root <bundle>/app`
/// is exactly the root `mesofact-render`'s `read_data_inputs` resolves a route's
/// declared `data_inputs` against, so writing there is what makes the next poke
/// render new bytes. That is the *same* tree the receiver already writes its
/// rendered `dist/` output into — the bundle's content-addressing is a
/// materialize-time guarantee, not a read-only mount.
///
/// The binary resolves from one of two places, in the order the *bundle*
/// declares rather than by probing:
///
///   * `bins/<triple>/almanac-feed` inside the materialized tree — the
///     self-contained shape (`assemble_self_bundle_with`), closed over
///     everything it needs, bytes covered by the bundle digest;
///   * the node's shared runtime-asset cache, named by the receiver's
///     `feed_runtime` — the **vanilla** shape (R746-T3). A vanilla bundle
///     carries no `bins/` at all, so without this a site with a feed tier
///     could not be vanilla, and its sync would still need a cross-built musl
///     binary on the operator's disk. Same fetch + blake3-verify path `serve`
///     takes, so the trust posture is identical.
///
/// Registered as `<id>-feed` — its own row in `List`/`Stop`, because "the site
/// is serving but its data is frozen" has to be an observable state.
#[cfg(feature = "bundle-serving")]
async fn fork_feed_tier(
    backend: &BundleBackend,
    id: &WorkloadId,
    bundle_dir: &Path,
    receiver_listen: &str,
    receiver: &workload_spec::MesofactRevalidateReceiver,
    origin: Option<&str>,
) -> std::result::Result<(), String> {
    use std::net::Ipv4Addr;

    let triple = node_triple();
    let staged = bundle_dir.join("bins").join(&triple).join(FEED_BIN_NAME);
    let feed_bin = if staged.is_file() {
        staged
    } else if let Some(runtime) = receiver.feed_runtime.as_deref() {
        // Same blocking pool + verify-before-visible contract as the serve
        // runtime asset; the fetcher is ~9MB, so a cold fetch is cheap, but it
        // is still network I/O that must not park the dispatch loop.
        let rref = yah_mesofact_bundle::RuntimeRef::parse(runtime)
            .map_err(|e| format!("feed_runtime {runtime:?}: {e}"))?;
        // R870-B6: the workload's store chain, same as the serve runtime's. A
        // tenant naming a `feed_runtime` it published itself resolves from its
        // own origin; one naming the stock fetcher reads through to the node's.
        let store = backend.store_for(origin).await?;
        let cache_dir = backend.cache_dir.clone();
        let triple_for_task = triple.clone();
        let resolved = tokio::task::spawn_blocking(move || {
            yah_mesofact_bundle::ensure_runtime_asset(
                store.as_ref(),
                &cache_dir,
                &rref,
                &triple_for_task,
                FEED_BIN_NAME,
                // The sidecar exemption (R746-F6). `almanac-feed` is versioned
                // with yubaba and its interface is its own CLI, not the
                // bundle↔runtime contract — holding it to *that* contract's
                // versions would be a category error. Only a serve runtime is
                // contract-checked.
                yah_mesofact_bundle::ContractRequirement::Unchecked,
            )
        })
        .await;
        match resolved {
            Ok(Ok(path)) => path,
            Ok(Err(e)) => return Err(format!("{FEED_BIN_NAME} runtime asset missing: {e}")),
            Err(e) => return Err(format!("{FEED_BIN_NAME} asset fetch task failed: {e}")),
        }
    } else {
        return Err(format!(
            "bundle declares {} feed(s) but carries no {} and names no feed_runtime: stage the \
             fetcher with providers.bundle.revalidate.feed_bins, or (for a vanilla bundle) \
             publish it as a node asset and name it with \
             providers.bundle.revalidate.feed_runtime",
            receiver.feeds.len(),
            staged.display(),
        ));
    };

    // Same exec-bit fixup the serve bin gets: `materialize_bundle` writes blob
    // bytes 0644, and the manifest records no mode.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&feed_bin) {
            let mode = meta.permissions().mode();
            if mode & 0o111 == 0 {
                let mut perms = meta.permissions();
                perms.set_mode(mode | 0o755);
                let _ = std::fs::set_permissions(&feed_bin, perms);
            }
        }
    }

    let feed_id = WorkloadId(format!("{}-feed", id.0));
    let spec = bundle_workload_spec_feed_tier(
        &feed_id,
        &feed_bin,
        bundle_dir,
        receiver_listen,
        receiver,
    );
    let mesh = kamaji::MeshAssignment::inlined(Ipv4Addr::LOCALHOST);
    backend
        .native
        .deploy_workload(&spec, &mesh)
        .await
        .map(|_res| ())
        .map_err(|e| format!("native fork of almanac-feed failed: {e:#}"))
}

/// Name of the feed-fetch binary — `bins/<triple>/almanac-feed` inside a
/// self-contained bundle, and the filename it lands under in the node's
/// runtime-asset cache for a vanilla one.
///
/// This and `yah_cloud::reconciler::mesofact_bundle::FEED_BIN_NAME` used to be
/// two hand-copied consts pinned together by the argv-shape test below. They
/// are now one const in `yah-mesofact-bundle`, which both sides already depend
/// on — a shared definition beats a test that detects the drift after it
/// happens (R746-T3).
#[cfg(feature = "bundle-serving")]
use yah_mesofact_bundle::FEED_BIN as FEED_BIN_NAME;

/// Build the [`WorkloadSpec`](workload_spec::WorkloadSpec) for the feed-fetch
/// tier (R330-F31).
///
/// `--receiver` points at the receiver's own loopback address: the poke never
/// leaves the node, so the bearer never crosses a network. The bearer itself is
/// passed as `ALMANAC_MIRROR_KEY` in `env` rather than argv — the receiver's
/// `MESOFACT_MIRROR_KEY` value under a name the fetcher reads — so it does not
/// show up in `ps`.
///
/// Each feed's definition travels **by value** (`--feed <toml>`): the node has
/// no copy of the camp's `.yah/almanac/` tree.
///
/// @yah:ticket(R844-B9, "yah-marketing-feed advertises the revalidate receiver's port — the feed tier binds nothing")
/// @yah:status(review)
/// @yah:at(2026-09-03T17:44:19Z)
/// @yah:assignee(agent:bundle-anthropic-glimmerstone)
/// @yah:parent(R844)
/// @yah:severity(P3)
/// @yah:gotcha("MEASURED LIVE, not inferred. us-east-001 (100.64.0.3, yubaba+kamaji 0.8.30) `GET /workloads` after a clean `yah cloud apply --env cloud --service yah-marketing`: {\"id\":\"yah-marketing\",\"ports\":[8080]}, {\"id\":\"yah-marketing-revalidate\",\"ports\":[8081]}, {\"id\":\"yah-marketing-feed\",\"ports\":[8081]}. Two workloads advertising the same port on one node. The receiver genuinely binds 8081 (revalidate_port(8080) = serve+1); the FEED tier binds nothing at all and is a CLIENT of that address.")
/// @yah:gotcha("THE CAUSE IS WRITTEN IN THE CODE'S OWN COMMENT, so this is confirmed rather than suspected. bundle_workload_spec_feed_tier (oss/kamaji/crates/kamaji-bin/src/server.rs:2742) takes `receiver_listen: &str` — the revalidate receiver's `bind_ip:8081` — and at :2777-2779 says verbatim `The fetcher binds nothing, so listen is meaningless to it; reuse the bundle archetype for the identity-image/native shape and overwrite argv`, then passes `receiver_listen` straight into bundle_workload_spec. The archetype derives expose.mesh.ports from that listen string (R599-F12 parses the port back off it), so `meaningless to it` became `advertised by it` the moment R844-F2 started reporting resolved ports up the wire. argv is overwritten; the expose is not.")
/// @yah:next("PROPOSED FIX, small and contained: after `let mut spec = bundle_workload_spec(id, feed_bin, bundle_dir, receiver_listen, &env);` in bundle_workload_spec_feed_tier, clear the mesh expose alongside the existing `spec.command = Some(command);` — the fetcher binds nothing, so an empty port set is the honest answer and the comment at :2777 already argues for it. Add a test asserting the feed tier's spec exposes no port while the receiver's exposes serve+1. Keep passing `receiver_listen` in: it is still the right POKE target and the env/argv depend on it.")
/// @yah:next("WHY THIS IS P3 AND NOT LIVE BREAKAGE, so nobody escalates it or dismisses it. Not breakage today: R844-F2's cold-admission gate requires `is_declared_serving(ident)` AND a resolved port, and yubaba never declared either sibling serving, so neither gets a service record — verified live, `?ready=true` on us-east-001 returns yah-marketing alone while all three workloads are Running. Not cosmetic either: it is the second instance of exactly the hazard R844-B6 describes. passway's addrs_from_body has no ident filter, so any future route into the registry that does not re-check the serving declaration would publish `-feed` as a dialable upstream on a port belonging to the revalidation receiver — apex traffic load-balanced onto a poke endpoint. It also makes `GET /workloads` lie to an operator diagnosing a port collision, which is the tool they would reach for first. Fix it while the gate is the only thing standing between the two.")
/// @yah:handoff("FIXED as proposed, one line plus a test. oss/kamaji/crates/kamaji-bin/src/server.rs bundle_workload_spec_feed_tier now clears the archetype-derived mesh expose after overwriting argv: `spec.expose.mesh.ports.clear();` immediately after `spec.command = Some(command);`. receiver_listen is STILL passed in and still builds `--receiver http://{receiver_listen}` in argv plus the ALMANAC_MIRROR_KEY env projection — only the expose was wrong. The archetype (bundle_workload_spec, server.rs:2618-2629) parses the port back off `listen` into expose.mesh.ports (R599-F12); that is the exact line that turned `listen is meaningless to it` into `advertised by it`.")
/// @yah:handoff("Tree anchor at handoff: 02bd22254ac4e4bb2de846c5ca565046da89e430 — the shared tree as I left it. Diff against it (`git diff 02bd22254ac4e4bb2de846c5ca565046da89e430..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
/// @yah:handoff("COMMENT REPLACED, not just amended. The old two-line comment stated the belief that made the bug invisible (`the fetcher binds nothing, so listen is meaningless to it`) without noting that the archetype nevertheless derives an expose from it. It now says the archetype does not know the fetcher binds nothing, names the R599-F12 parse as the mechanism, cites the measured us-east-001 double-8081 as the symptom, and states why receiver_listen stays in the signature (it is the POKE target).")
/// @yah:handoff("TEST: server.rs tests::bundle_serving::feed_tier_declares_no_mesh_port_while_the_receiver_declares_serve_plus_one. Both halves from ONE receiver_listen string (`127.0.0.1:{revalidate_port(8080)}` = the same value that used to give the two specs the same number): asserts receiver_spec.expose.mesh.ports == [8081] AND feed_spec.expose.mesh.ports.is_empty(). Asserting only the empty side could not distinguish `cleared` from `the archetype never set a port at all`, which is the whole point. A third assert pins that clearing the expose did not disturb the poke target (argv still contains `http://127.0.0.1:8081`) - that is the regression a careless `pass an empty listen instead` fix would cause.")
/// @yah:verify("cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji-bin --features bundle-serving --lib: BEFORE 251 passed / 0 failed; AFTER 252 passed / 0 failed. The +1 is the new test; no existing test moved. The port-reporting neighbours that could have regressed all still pass by name: two_undeclared_bundles_co_tenant_a_node_on_distinct_reported_ports, two_bundles_on_one_node_get_their_own_ports, keepalive_deploy_with_feeds_forks_the_fetch_tier_as_a_third_process, keepalive_deploy_with_receiver_forks_both_processes, an_allocated_port_survives_a_kamaji_restart.")
/// @yah:verify("cargo check --manifest-path oss/kamaji/Cargo.toml -p kamaji-bin --features bundle-serving: clean, exit 0. Two dead_code warnings are PRE-EXISTING and not mine - PidfdReaperHandle.events_tx (native.rs) and control_sock_from_spec (server.rs:1835); neither is a file region this ticket touched. Nothing committed: edits are uncommitted in the shared tree, both hunks confined to oss/kamaji/crates/kamaji-bin/src/server.rs (bundle_workload_spec_feed_tier body + one new #[test] in the bundle_serving test module). No cargo fmt run, no other file touched.")
/// @yah:next("RE-MEASURE ON THE NEXT DEPLOY, not now - this fix only reaches a node when kamaji is rebuilt and rolled. Until then us-east-001 keeps reporting yah-marketing-feed on 8081. The confirmation is `GET /workloads` on 100.64.0.3 showing {\"id\":\"yah-marketing-feed\",\"ports\":[]} while yah-marketing-revalidate keeps [8081]; nothing else about the deploy should change, since argv and env are byte-identical to before.")
/// @yah:verify("RE-VERIFIED on disk after the handoff, since this is a shared tree: `spec.expose.mesh.ports.clear();` is present at server.rs:2977 (immediately after `spec.command = Some(command);` at :2976), and the test is at server.rs:6203. Second full run: 252 passed / 0 failed, with feed_tier_declares_no_mesh_port_while_the_receiver_declares_serve_plus_one named ok; cargo check --features bundle-serving Finished, 0 errors, same 2 pre-existing dead_code warnings. One caveat on the 251 baseline: the camp skew guard flagged server.rs as modified mid-run, because my own edit landed while that background baseline was compiling — the count is still a valid pre-edit baseline (it did not contain the new test name), and 252-251 = exactly the one test added.")
/// @yah:handoff("RELAY-LEADER SIGN-OFF (@Glimmerstone:dove, session:db829701, 2026-09-03). The feed tier no longer advertises a port it does not bind. `spec.expose.mesh.ports.clear()` at oss/kamaji/crates/kamaji-bin/src/server.rs:2978, immediately after `spec.command = Some(command)` at :2977 — the archetype derives BOTH from `receiver_listen` and only one of them was being overwritten, which is the whole bug in one line. `receiver_listen` correctly stays in the signature: it is still the POKE target the argv builds `--receiver http://{…}` from, and the env depends on it. The comment at :2961-2974 was rewritten to state what is TRUE (the archetype parses the port back off `listen` into expose.mesh.ports, per R599-F12) rather than the belief that hid the bug for so long (\"listen is meaningless to it\") — that rewrite is as valuable as the fix, since the old comment actively argued against noticing.")
/// @yah:verify("RE-RUN BY ME on a settled tree: cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji-bin --features bundle-serving --lib = 252 passed / 0 failed (baseline 251/0 measured by me before dispatch; +1 = the new test). cargo check --manifest-path oss/kamaji/Cargo.toml -p kamaji-bin --features bundle-serving = ZERO errors. THE TEST ASSERTS BOTH HALVES FROM ONE INPUT, which is what makes it meaningful: feed_tier_declares_no_mesh_port_while_the_receiver_declares_serve_plus_one (server.rs:6204) drives bundle_workload_spec_revalidate and bundle_workload_spec_feed_tier from the SAME receiver_listen and asserts receiver_spec.expose.mesh.ports == [8081] AND feed_spec.expose.mesh.ports.is_empty() — one half alone could not distinguish \"cleared\" from \"never set\" — plus a third assertion that the poke target http://127.0.0.1:8081 survives in argv, which is the thing the fix must NOT break.")
#[cfg(feature = "bundle-serving")]
fn bundle_workload_spec_feed_tier(
    id: &WorkloadId,
    feed_bin: &Path,
    bundle_dir: &Path,
    receiver_listen: &str,
    receiver: &workload_spec::MesofactRevalidateReceiver,
) -> workload_spec::WorkloadSpec {

    let app = bundle_dir.join("app");
    let mut command = vec![
        "--project-root".into(),
        app.to_string_lossy().into_owned(),
        "--receiver".into(),
        format!("http://{receiver_listen}"),
        "--interval-secs".into(),
        receiver.feed_interval_secs.to_string(),
    ];
    if let Some(prefix) = receiver.feed_project_prefix.as_ref() {
        command.push("--project-prefix".into());
        command.push(prefix.clone());
    }
    for feed in &receiver.feeds {
        command.push("--feed".into());
        command.push(feed.config_toml.clone());
    }

    // The fetcher reads the receiver's bearer under its OWN name, and nothing
    // else from the receiver's env — an R2 credential belongs to the process
    // that publishes, not to the one that pokes it.
    let env: std::collections::BTreeMap<String, String> = receiver
        .env
        .get("MESOFACT_MIRROR_KEY")
        .map(|key| [("ALMANAC_MIRROR_KEY".to_string(), key.clone())].into())
        .unwrap_or_default();

    // Reuse the bundle archetype for the identity-image/native shape, then
    // overwrite BOTH things it derives from `receiver_listen`.
    //
    // R844-B9: the fetcher binds nothing, but the archetype does not know that
    // — it parses the port back off `listen` into `expose.mesh.ports`
    // (R599-F12), so passing the RECEIVER's address in made the feed tier
    // advertise the receiver's port as its own. Measured on us-east-001:
    // `GET /workloads` reported yah-marketing-revalidate and yah-marketing-feed
    // both on 8081. An empty port set is the honest declaration for a pure
    // client, and `expose.mesh.ports` is the one place a serving port is
    // declared — a would-be dialer must find nothing here.
    //
    // `receiver_listen` still belongs in the signature: it is the POKE target
    // the argv above builds `--receiver http://{…}` from.
    let mut spec = bundle_workload_spec(id, feed_bin, bundle_dir, receiver_listen, &env);
    spec.command = Some(command);
    spec.expose.mesh.ports.clear();
    spec
}

/// Build the [`WorkloadSpec`](workload_spec::WorkloadSpec) for the revalidate
/// receiver (R330-F12): the same identity-image native archetype as
/// [`bundle_workload_spec`], but the serve argv runs the receiver mode
/// (`<app> --revalidate --publish-config <cfg> --listen <addr>`) and the child
/// carries the deploy-resolved `env` (R2 creds + `MESOFACT_MIRROR_KEY`, which
/// `mesofact serve` reads via `#[arg(env = "MESOFACT_MIRROR_KEY")]`).
/// `restart_policy` stays `Always` — the receiver is a resident server.
///
/// The workload dir is **positional** — `ServeArgs::workload` is
/// `Option<PathBuf>` with no `#[arg(long)]`, so a `--workload` flag is an
/// unexpected-argument clap error and the receiver would never boot.
#[cfg(feature = "bundle-serving")]
fn bundle_workload_spec_revalidate(
    id: &WorkloadId,
    serve_bin: &Path,
    bundle_dir: &Path,
    listen: &str,
    receiver: &workload_spec::MesofactRevalidateReceiver,
) -> workload_spec::WorkloadSpec {

    let app = bundle_dir.join("app");
    let publish_config = app.join(&receiver.publish_config);

    let mut spec = bundle_workload_spec(id, serve_bin, bundle_dir, listen, &receiver.env);
    // Same subcommand correction as `bundle_workload_spec` — the receiver is the
    // same consolidated binary invoked a different way.
    let mut command = vec![
        "serve".into(),
        app.to_string_lossy().into_owned(),
        "--revalidate".into(),
        "--publish-config".into(),
        publish_config.to_string_lossy().into_owned(),
        "--listen".into(),
        listen.to_string(),
    ];
    // The declared route allowlist, one `--allow-route` per entry (yah
    // R752-B7). Empty stays empty: `mesofact serve` reads no flags as "every
    // render-eligible route", which is what the config's own doc comment
    // promises for an empty list. Before this the field was parsed, shipped
    // over the wire and dropped here, so a receiver that declared
    // `routes = ["/releases"]` re-rendered and republished any route it was
    // asked for — measured against us-east-001 on 2026-08-12.
    for route in &receiver.routes {
        command.push("--allow-route".into());
        command.push(route.clone());
    }
    spec.command = Some(command);
    spec
}

/// How "live" a [`WorkloadEntry`] claims its workload is — the tie-breaker when
/// two backends report the same workload id (R599-B11).
///
/// A row carrying a pid outranks any pid-less row: a backend that can name an
/// actual process is authoritative over one that only knows a record exists.
/// State breaks the remaining ties, most-alive first.
fn liveness_rank(e: &WorkloadEntry) -> (u8, u8) {
    use kamaji_proto::WorkloadState as WireState;
    let state = match e.state {
        WireState::Running => 5,
        WireState::Starting => 4,
        WireState::Draining => 3,
        WireState::Pending => 2,
        WireState::Failed => 1,
        WireState::Exited => 0,
        // `WorkloadState` is #[non_exhaustive]: a state added by a newer peer
        // ranks with Pending — "a record exists, nothing more is known". It can
        // never outrank a row that names a live pid, so an unknown state can't
        // shadow a genuinely-running workload.
        _ => 2,
    };
    (u8::from(e.pid.is_some()), state)
}

/// Collapse a merged `List` result to **exactly one row per workload id**
/// (R599-B11), keeping the most-live row per [`liveness_rank`] and preserving
/// first-seen order.
///
/// The `List` handler concatenates the in-memory registry, containerd, and both
/// bundle runtimes. Those views are not disjoint in practice: on the ingress
/// testbed a stale containerd container left over from the pre-bundle nginx
/// stand-in shared the `yah-marketing` id with the live native bundle workload,
/// and containerd reports a container with no task as `Pending`/`pid: None` —
/// so `GET /workloads` returned both, with the *phantom* sorting first and
/// carrying a null pid. Anything taking the first match read the workload as
/// not-yet-started.
///
/// Deliberately a dedupe and not a source-priority rule: whichever backend can
/// point at a running process wins, so this stays correct regardless of which
/// runtimes are compiled in or which order the merges run.
fn dedupe_workload_entries(entries: Vec<WorkloadEntry>) -> Vec<WorkloadEntry> {
    let mut out: Vec<WorkloadEntry> = Vec::with_capacity(entries.len());
    for e in entries {
        // Linear scan: a node supervises tens of workloads, not thousands, and
        // this keeps first-seen order without a second index.
        match out.iter_mut().find(|kept| kept.id == e.id) {
            Some(kept) => {
                // Collapsing is the right wire answer, but a duplicate id means
                // two backends genuinely both hold a record — usually a stale
                // container/process the operator still needs to reap. Say so,
                // so the fix reports the condition instead of hiding it.
                //
                // R858-T4: the fields report the OUTCOME, not the incumbent. The
                // warn used to fire before the swap, so it labelled the row it
                // was about to discard `kept_` — a reader who trusted it saw
                // "kept_state=Pending kept_pid=None" beside a live pid and read
                // a correct dedupe as an inverted one. Measured on us-east-001
                // 2026-09-06, where it cost a full investigation before the
                // swap below proved the behaviour was right all along.
                let replace = liveness_rank(&e) > liveness_rank(kept);
                let (winner, loser) = if replace { (&e, &*kept) } else { (&*kept, &e) };
                warn!(
                    id = %e.id.0,
                    kept_state = ?winner.state, kept_pid = ?winner.pid,
                    dropped_state = ?loser.state, dropped_pid = ?loser.pid,
                    "duplicate workload id across backends — collapsing to the \
                     most-live row; the dropped row is likely a stale record"
                );
                if replace {
                    *kept = e;
                }
            }
            None => out.push(e),
        }
    }
    out
}

/// Map a kamaji-crate [`kamaji::WorkloadState`] into the wire
/// [`WorkloadEntry`] the `List` RPC returns (R599-F10).
///
/// Shared by every backend that reports through the `Kamaji` trait rather than
/// through a daemon of its own: the keep-alive bundle runtime, the JIT runtime,
/// and the microVM runtime. Those backends encode the supervised pid into
/// `container_id` as `"<kind>-<pid>"` — the trait has no pid field — and a `0`
/// pid means nothing is currently running (parked between exits, idle for JIT,
/// or halted for a microVM). Was `bundle_state_to_entry` until R605-F8 gave it
/// a third caller and the old name stopped being true. R852-F1 added a fourth
/// (the per-tenant passway JIT tier), which reports through the same trait.
/// R858-B14 added a fifth, `ServerCtx::native` — the `--native-exec-dir`
/// fork+exec backend, whose `container_id` already carries the `native-<pid>`
/// spelling this reads because it is the same `NativeRuntime` the bundle
/// backend uses, only keyed on a different identity space.
#[cfg(any(
    feature = "bundle-serving",
    feature = "microvm",
    feature = "tenant-passway",
    feature = "native-exec"
))]
fn runtime_state_to_entry(s: kamaji::WorkloadState) -> WorkloadEntry {
    use kamaji::WorkloadStatus;
    use kamaji_proto::WorkloadState as WireState;
    let state = match &s.status {
        WorkloadStatus::Pending => WireState::Pending,
        WorkloadStatus::Running => WireState::Running,
        WorkloadStatus::Stopping => WireState::Draining,
        WorkloadStatus::Stopped => WireState::Exited,
        WorkloadStatus::Restarting { .. } => WireState::Starting,
        WorkloadStatus::Failed { .. } => WireState::Failed,
    };
    let pid = s
        .container_id
        .strip_prefix("native-")
        .or_else(|| s.container_id.strip_prefix("jit-"))
        .or_else(|| s.container_id.strip_prefix("microvm-"))
        .and_then(|p| p.parse::<u32>().ok())
        .filter(|p| *p != 0);
    WorkloadEntry {
        id: WorkloadId(s.ident.0.clone()),
        state,
        pid,
        mesh_ident: Some(s.ident.0),
        // R844-F2: these backends fork plain host processes (or hold the
        // listen socket themselves), so the port they report is the port
        // something is actually bound to on this node — the fact yubaba needs
        // and previously had no channel for.
        //
        // R844-F15: both spellings of the same fact. `named_ports` is the one
        // a caller should read; `ports` stays populated because a peer that
        // predates the named field would otherwise see a portless entry.
        ports: s.ports.values().copied().collect(),
        named_ports: s.ports,
        // R852-B4: left `None` here and stamped by the `List` arm. A runtime
        // holds a lowered `WorkloadSpec`, not the `Workload` the caller sent,
        // so digesting it here would compare a *derived* value against the
        // caller's declaration and never match — the one shape of this field
        // that would be worse than not having it.
        spec_digest: None,
    }
}

/// Render a docker workload as a wire [`WorkloadEntry`] (R626-F1).
///
/// Unlike the bundle backend — whose `container_id` encodes the pid as
/// `native-<pid>` — docker carries the real container id, and the pid arrives
/// alongside it in [`DockerWorkload`].
///
/// `id` is the **workload id** (`yah.workload_id` label) and `mesh_ident` the
/// mesh identity (`yah.ident`), which differ for forge runs (R590-B9). This
/// matches the containerd backend's split — `id` is the deploy/stop key,
/// `mesh_ident` the handle yubaba's HTTP surface polls — and it is what makes
/// the cross-backend dedupe key comparable between the two.
///
/// [`DockerWorkload`]: kamaji::docker::DockerWorkload
#[cfg(feature = "docker-integration")]
fn docker_workload_to_entry(w: kamaji::docker::DockerWorkload) -> WorkloadEntry {
    use kamaji::WorkloadStatus;
    use kamaji_proto::WorkloadState as WireState;
    let state = match &w.state.status {
        WorkloadStatus::Pending => WireState::Pending,
        WorkloadStatus::Running => WireState::Running,
        WorkloadStatus::Stopping => WireState::Draining,
        WorkloadStatus::Stopped => WireState::Exited,
        // Docker's own restart-policy engine is re-launching the container —
        // it is coming up, not down. Matches the bundle mapping.
        WorkloadStatus::Restarting { .. } => WireState::Starting,
        WorkloadStatus::Failed { .. } => WireState::Failed,
    };
    WorkloadEntry {
        id: WorkloadId(w.workload_id),
        state,
        pid: w.pid,
        mesh_ident: Some(w.state.ident.0),
        // A docker container is namespaced: the declared port is the bound
        // port, so the backend resolves nothing and both of these stay empty.
        ports: w.state.ports.values().copied().collect(),
        named_ports: w.state.ports,
        // R852-B4: stamped by the `List` arm from the deploy record, like every
        // other backend's entries.
        spec_digest: None,
    }
}

/// Dispatch a `GracefulUpgrade { id, spec }` to the containerd backend's
/// zero-downtime cert-reload path (R600-F9). Only `Workload::Container` has a
/// backend that can hold the listen socket; other variants are yubaba's
/// reconcilers' business and surface as `InvalidSpec`. The backend itself falls
/// back to a connection-dropping redeploy for a non-passway container or when
/// custody isn't held, so a caller always gets a functional reload.
#[allow(unused_variables)]
async fn graceful_upgrade_workload(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: WorkloadId,
    spec: workload_spec::Workload,
) -> KamajiToYubaba {
    match spec {
        workload_spec::Workload::Container(manifest) => {
            let spec = match manifest.into_spec() {
                Ok(spec) => spec,
                Err(_recipe) => return recipe_is_not_deployable(request_id),
            };
            #[cfg(feature = "containerd-integration")]
            {
                let Some(backend) = ctx.containerd.clone() else {
                    return KamajiToYubaba::Error {
                        request_id: Some(request_id),
                        code: ErrorCode::BackendRefused,
                        message: "no containerd backend configured — \
                                  rebuild kamaji with --features containerd-integration \
                                  and start with --containerd-socket"
                            .to_string(),
                    };
                };
                match backend.graceful_upgrade(&id, &spec).await {
                    Ok(_pid) => KamajiToYubaba::Ack {
                        request_id,
                        kind: kamaji_proto::AckKind::GracefulUpgrade,
                    },
                    Err(crate::containerd::BackendError::InvalidSpec(msg)) => {
                        KamajiToYubaba::Error {
                            request_id: Some(request_id),
                            code: ErrorCode::InvalidSpec,
                            message: msg,
                        }
                    }
                    Err(crate::containerd::BackendError::Containerd(e)) => KamajiToYubaba::Error {
                        request_id: Some(request_id),
                        code: ErrorCode::BackendRefused,
                        message: format!("containerd: {e:#}"),
                    },
                }
            }
            #[cfg(not(feature = "containerd-integration"))]
            {
                let _ = (ctx, spec);
                KamajiToYubaba::Error {
                    request_id: Some(request_id),
                    code: ErrorCode::BackendRefused,
                    message: "kamaji built without containerd-integration feature; \
                              Container workloads cannot be graceful-upgraded"
                        .to_string(),
                }
            }
        }
        // A tenant passway is not graceful-upgradable and does not need to be:
        // it is zero-resident between requests, so a new cert or upstream set
        // lands by re-deploying the declaration (which re-arms the socket) and
        // is picked up by the next cold start. The R600-F9 SCM_RIGHTS dance
        // exists to avoid dropping connections on a *resident* passway.
        workload_spec::Workload::MesofactStatic(_)
        | workload_spec::Workload::Almanac(_)
        | workload_spec::Workload::StaticAsset(_)
        | workload_spec::Workload::TenantPassway(_) => KamajiToYubaba::Error {
            request_id: Some(request_id),
            code: ErrorCode::InvalidSpec,
            message: "kamaji only graceful-upgrades Workload::Container".to_string(),
        },
    }
}

/// Dispatch a `Stop { id }` to the right backend. With the containerd
/// backend configured the workload is torn down via containerd's
/// kill+delete; without a backend (or for a workload Kamaji doesn't know
/// about) we return `Ack` regardless — Stop is idempotent and the absence
/// of the workload satisfies the requested end-state.
///
/// @yah:ticket(R858-B15, "stop_workload has no ctx.native arm, so a Stop for a native-exec workload Acks while the process keeps running")
/// @yah:status(review)
/// @yah:at(2026-09-06T09:44:30Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R858)
/// @yah:severity(high)
/// @yah:verify("Add a test that is the write-side twin of R858-B14's a_native_exec_workload_is_visible_in_list: deploy a native-exec workload, issue YubabaToKamaji::Stop, then assert the workload is GONE from the next List reply (and that the pid is reaped). Falsify it by removing the new arm — it must fail, not merely pass. Do NOT verify this one on us-west-001 by driving a real leadership change until R858-T4 lands: east and south have no --native-exec-dir and no headscale binary, so an ownership move off west has nowhere to go and would decapitate the mesh whether or not this bug is fixed.")
/// @yah:next("The fix is the exact mirror of B14's: a `#[cfg(feature = \"native-exec\")]` arm in `stop_workload` calling `native.teardown_workload(&MeshIdent(id.0.clone()))`, idempotent like every arm beside it, placed with the others. Note `NativeRuntime::teardown_workload` takes a MeshIdent and the native runtime keys its map on `ident.0` (oss/kamaji/crates/kamaji/src/native.rs:786), which for the appliance is HEADSCALE_IDENT == HEADSCALE_NAME == \"headscale\" — but for forge runs the id and the mesh identity differ (R590-B9), so check whether the native path needs the same resolve-by-either-key treatment the docker arm has (`teardown_by_key`, :3601) before assuming a bare ident lookup is enough.")
/// @yah:gotcha("DELIBERATELY NOT FIXED IN B14's BINARY, AND THINK BEFORE YOU FIX IT. Right now this no-op is load-bearing in west's favour: R858-B13's D2 defect was a spurious `on_lost_leader -> stop_headscale` firing 4ms after a deploy. golem's `start_awaiting_proof` term fixed the yubaba side, but if ANY spurious-teardown path survives, this no-op is the only thing between it and a decapitated mesh — us-west-001 holds the cloud.mesh.yah.dev A record, the headscale DB and the ACME cache, and per R858-T4 neither east nor south can run the appliance at all (no --native-exec-dir, no headscale binary). So making teardown actually work converts a harmless lie into a real outage the moment anything calls it wrongly. LAND THIS AFTER R858-T4 gives the fleet somewhere to fail over to, or land it together with a hardware check that no spurious Stop is issued. It was left out of B14's ship on purpose: B14 needed a single-variable experiment to restore quorum, and this is a behaviour change whose blast radius is the mesh coordinator.")
/// @yah:assumes("I did NOT measure this on hardware — it is read from the code, not from a journal. The read is direct (stop_workload's arms are all in one function and none of them touches ctx.native), and B14's read of the identical omission in List was confirmed on hardware, so the inference is strong. But nobody has issued a Stop for a native-exec workload on us-west-001 and watched the process survive, and that is the measurement this ticket should open with.")
/// @yah:handoff("FIXED IN SOURCE, NOTHING ROLLED. Tree anchor 2a3bd7ed. Two files, both already carrying uncommitted peer work from R858-B14/R858-T4; I re-read each immediately before every Edit and did not commit, reformat, or touch a peer hunk. (1) oss/kamaji/crates/kamaji-bin/src/server.rs stop_workload — added the missing `#[cfg(feature = \"native-exec\")] if let Some(native) = &ctx.native` arm, placed FIRST to mirror the ordering R858-B14 gave the `List` merge. It calls `native.teardown_by_key(&id.0)` and then `ctx.registry.lock().await.remove_probe(&id)`. (2) oss/kamaji/crates/kamaji/src/native.rs — new `NativeRuntime::teardown_by_key`, plus a `name: String` field on WorkloadHandle populated from `spec.name` at the single insert site (native.rs:786).")
/// @yah:handoff("THE BARE IDENT LOOKUP WAS **NOT** ENOUGH — the ticket's own next-step suspicion was right, and I proved it rather than reasoned it. `NativeRuntime` keys its map ONLY on `spec.expose.mesh.identity` (native.rs:786) and records the WorkloadId nowhere at all, while a `YubabaToKamaji::Stop` carries a WorkloadId. For the appliance those agree (HEADSCALE_IDENT == HEADSCALE_NAME == \"headscale\"), so a bare `MeshIdent(id.0.clone())` fixes headscale. For FORGE runs they do not: `WorkloadSpec::for_forge` is `name = forge-<uuid>` against `identity = forge.<uuid>` (oss/yah-base/crates/workload-spec/src/lib.rs:2720, R590-B9), and `mark_native_exec` (oss/qed/crates/velveteen-exec/src/remote.rs:851) converts exactly that spec into the fork+exec shape — so native forge runs are real, not hypothetical. A bare-ident arm would therefore have MOVED the lying Ack from the appliance to forge runs rather than fixed it. `teardown_by_key` resolves either spelling (identity first so the common case costs no scan, then a scan on the recorded `name`), which is the native twin of the docker backend's `teardown_by_key` / `yah.workload_id` label at server.rs:3621.")
/// @yah:handoff("DISCOVERED WORK, both inside this ticket's blast radius. (a) The new arm also calls `remove_probe(&id)`: `deploy_native_exec` registers a control-socket ProbeTarget for any spec declaring one (server.rs:1846), and before this arm existed nothing ever removed it, so a probe would have outlived its child and kept polling a dead socket. (b) R858-B14's `a_native_exec_workload_is_visible_in_list` carried a trailing comment asserting `stop_workload` \"has no ctx.native arm either ... Filed separately rather than fixed here\". That is now false, so I retargeted the comment to point at the new write-side test. The manual runtime teardown in that test is unchanged and still correct.")
/// @yah:verify("MY OWN BASELINE, measured on the same tree before any edit (not taken off the board). `cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji-proto -p kamaji` = 91 passed / 0 failed (58 + 33, 1 ignored). `cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji-bin --features containerd-integration,native-exec,bundle-serving` = 290 passed / 0 failed (285+2+2+1).")
/// @yah:verify("AFTER: proto+kamaji 91 passed / 0 failed (unchanged). kamaji-bin 292 passed / 0 failed (287+2+2+1) — exactly +2, my two new tests, with zero pre-existing tests disturbed.")
/// @yah:verify("NEW TEST 1 — `a_native_exec_workload_is_gone_from_list_after_stop` (server.rs), the write-side twin of B14's read-side test the ticket asked for: deploy a native-exec `headscale` workload, capture its live pid off `List` (the only channel that carries it), assert the child is alive, issue `YubabaToKamaji::Stop`, then assert BOTH that the workload is absent from the next `List` reply AND that the pid is reaped. Both halves are asserted because either alone is passable by a wrong fix — dropping the map entry without signalling leaks the process, killing without dropping leaves a corpse in every later List.")
/// @yah:verify("NEW TEST 2 — `stop_tears_down_a_native_forge_workload_addressed_by_its_id` (server.rs), covering the R590-B9 divergence: deploy with `id`/`name` = `forge-abc123` but `expose.mesh.identity` = `forge.abc123`, Stop by the HYPHENATED id (what yubaba sends), assert gone from List and pid reaped.")
/// @yah:verify("FALSIFICATION 1 — arm removed (cfg'd out, whole arm dead): kamaji-bin = 285 passed / 2 FAILED. Both failures are exactly the two new tests, nothing else moved. So they FAIL without the fix, they do not merely pass with it.")
/// @yah:verify("FALSIFICATION 2 — arm present but reverted to the ticket's literally-suggested `native.teardown_workload(&MeshIdent(id.0.clone()))`: kamaji-bin = 286 passed / 1 FAILED. The appliance test PASSES and only the forge test FAILS. That is the empirical answer to 'does the native path need resolve-by-either-key': yes, and this run is the single-variable proof.")
/// @yah:verify("Pid reaping is checked with `kill -0` via a subprocess, not `libc::kill`: kamaji-bin's libc dep is `[target.'cfg(target_os = \"linux\")']` (Cargo.toml:157) and this camp's machines are darwin. `stop_child` awaits `child.wait()`, so a correct teardown leaves ESRCH rather than a zombie — which is precisely the distinction the assertion needs. Both new tests are gated `#[cfg(all(unix, feature = \"native-exec\"))]`.")
/// @yah:verify("clippy: `cargo clippy -p kamaji -p kamaji-bin --features containerd-integration,native-exec,bundle-serving --all-targets` produces NO diagnostic in native.rs or in any changed hunk. The two warnings it does emit are pre-existing test-code lint far from this work — `function free_port is never used` (server.rs:7789) and a single-pattern `match` (server.rs:4913).")
/// @yah:verify("NOT VERIFIED, STATED PLAINLY: nothing was run on hardware. Per this ticket's own scope limit I did not ssh anywhere, did not roll, did not deploy, and specifically did not drive a leadership change on us-west-001. The parent relay's `@yah:assumes` — that nobody has yet watched a native-exec process survive a Stop on a real node — is still unretired; this ticket closes the source defect, not that measurement.")
/// @yah:gotcha("ROLL GATE — THIS FIX MUST NOT SHIP AHEAD OF R858-T4 AND R858-T16. Landing it in SOURCE is safe and is what happened here, because a source change reaches no node: code arrives on a voter only via a deliberate yubaba/kamaji release plus scripts/roll-node.sh. ROLLING it is the gated act. This arm converts a Stop that used to Ack-and-no-op into one that really kills the child, and the child in question is the mesh coordinator — so any surviving spurious-teardown path that was previously harmless becomes a real decapitation the moment this binary is on a node. The gate is satisfied only when the release that carries this ALSO carries R858-T4 (all three voters given kamaji --native-exec-dir and the headscale v0.23.0 binary, so the fleet has somewhere to fail over to) and R858-T16 (config.yaml hydration in leader::start_headscale). Both were done/at-review when this landed, so the safe forward path is one release containing T4 + T16 + B13 + B14 + this. Whoever cuts that release: verify T4 and T16 are in the same build before rolling, and keep honouring the parent relay's warning against rolling published 0.8.33 onto us-west-001, which still runs two hand-built musl binaries.")
/// @yah:cleanup("UNCHECKED, ADJACENT, DELIBERATELY NOT TOUCHED: the bundle-serving arm of stop_workload still calls `backend.native.teardown_workload(&ident)` with a bare `MeshIdent(id.0.clone())`, as do the tenant-passway and microvm arms. Those are different runtime instances from `ctx.native` and I did not establish whether any of them can see a spec whose `name` and `expose.mesh.identity` diverge — I grepped oss/kamaji/crates/kamaji-bin/src/bundle.rs and oss/kamaji/crates/kamaji/src/jit.rs for an identity assignment and found no site, which is inconclusive rather than reassuring. If a bundle or JIT workload can ever be forge-shaped, those three arms carry the identical R590-B9 no-op and `NativeRuntime::teardown_by_key` is now sitting right there for the bundle one.")
#[allow(unused_variables)]
async fn stop_workload(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: WorkloadId,
) -> KamajiToYubaba {
    // Route teardown to the native fork+exec backend (R858-B15), the write-side
    // twin of the `List` merge R858-B14 added. `ctx.native` is the
    // `--native-exec-dir` backend `deploy_native_exec` forks through — the
    // headscale appliance among them — and it was the one runtime `Stop` never
    // asked. Every arm below it is docker/containerd/bundle/microvm, so a Stop
    // for a native workload fell through all of them and Acked while the child
    // kept running: a lying Ack, the same class R590-B9 fixed on the container
    // path.
    //
    // Resolved `by_key`, not by a bare `MeshIdent(id.0)`: the native runtime
    // keys its map on `expose.mesh.identity` while a Stop carries a
    // `WorkloadId`, and for forge runs those differ (`forge.<uuid>` vs
    // `forge-<uuid>`, R590-B9) — a native forge step is exactly the shape
    // `mark_native_exec` produces. A bare ident lookup would reintroduce the
    // lying Ack for that workload kind while fixing it for the appliance.
    // Idempotent (Ok when nothing answers to the key), like every arm beside it.
    #[cfg(feature = "native-exec")]
    if let Some(native) = &ctx.native {
        if let Err(e) = native.teardown_by_key(&id.0).await {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("native teardown: {e:#}"),
            };
        }
        // `deploy_native_exec` registers a control-socket probe for any spec
        // that declares one; a probe outliving its child would keep polling a
        // socket nothing is listening on.
        ctx.registry.lock().await.remove_probe(&id);
    }
    #[cfg(feature = "containerd-integration")]
    if let Some(backend) = ctx.containerd.clone() {
        if let Err(e) = backend.teardown(&id).await {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("containerd teardown: {e}"),
            };
        }
    }
    // Route teardown to the per-tenant passway tier (R852-F1). Idempotent for
    // the same reason the bundle arms below are, and this is the only path that
    // *releases the held socket* — an unenrolled domain whose passway is never
    // stopped leaves kamaji holding its `:8443` forever, which the next tenant
    // handed that port discovers as a bind failure.
    #[cfg(feature = "tenant-passway")]
    if let Some(jit) = &ctx.tenant_passway {
        let ident = workload_spec::MeshIdent(id.0.clone());
        if let Err(e) = jit.teardown_workload(&ident).await {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("tenant passway teardown: {e}"),
            };
        }
        ctx.registry.lock().await.remove_deploy_progress(&id);
    }
    // Route teardown to the bundle backend (R599-F10). `teardown_workload` is
    // idempotent (Ok when the ident is absent), so calling it for every Stop —
    // even a non-bundle one — is safe and keeps Stop's idempotent contract. The
    // native supervisor is the single owner of the child, so this is the only
    // path that stops a served bundle.
    #[cfg(feature = "bundle-serving")]
    if let Some(backend) = &ctx.bundle {
        let ident = workload_spec::MeshIdent(id.0.clone());
        // Both runtimes' teardown is idempotent (Ok when the ident is absent), so
        // routing every Stop to both — even a non-bundle one — is safe and keeps
        // Stop's idempotent contract. A given identity lives in at most one.
        if let Err(e) = backend.native.teardown_workload(&ident).await {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("bundle teardown: {e}"),
            };
        }
        if let Err(e) = backend.jit.teardown_workload(&ident).await {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("on-demand bundle teardown: {e}"),
            };
        }
        {
            // Drop the probe target and the R330-F33 deploy record together: a
            // stopped workload whose record survived would keep answering
            // `DeployStatus` with the `Running` its deploy ended on.
            let mut registry = ctx.registry.lock().await;
            registry.remove_probe(&id);
            registry.remove_deploy_progress(&id);
        }
        // R844-F2: and the port reservations. A ledger nobody prunes is a
        // leak that only shows up as pressure — every stopped-and-never-
        // redeployed workload would hold a port out of the pool forever.
        // Both the static server and its revalidate receiver are reserved
        // under their own idents; `release` is idempotent, so releasing a
        // receiver that never existed is free.
        {
            use kamaji::ports::PortAllocator;
            backend.ports.release(&id.0);
            backend.ports.release(&format!("{}-revalidate", id.0));
        }
        // R755-B5: and the on-disk admission record, or the next restart would
        // resurrect a workload the operator stopped.
        if let Err(e) = backend.forget_deploy(&id) {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("bundle stopped but its deploy record could not be removed: {e}"),
            };
        }
    }
    // Route teardown to the microVM backend (R605-F8), on the same idempotent
    // terms as the arms above. This is the only path that reclaims a guest's
    // TAP device and its slot, so a Stop that skipped it would leak host
    // networking state that outlives the workload — the one resource here whose
    // absence a later deploy would notice.
    #[cfg(feature = "microvm")]
    if let Some(microvm) = &ctx.microvm {
        use kamaji::Kamaji as _;
        let ident = workload_spec::MeshIdent(id.0.clone());
        if let Err(e) = microvm.teardown_workload(&ident).await {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("microvm teardown: {e}"),
            };
        }
    }
    // Route teardown to the docker backend (R626-F1). `teardown_workload`
    // swallows "no such container", so routing every Stop to it — including
    // one for a workload docker never owned — is safe, exactly like the
    // containerd and bundle arms above.
    #[cfg(feature = "docker-integration")]
    if let Some(docker) = &ctx.docker {
        // Resolve by workload id OR mesh identity: docker NAMES containers by
        // mesh identity, but a Stop carries the id, and the two differ for forge
        // runs (R590-B9). Keying only on the id would make Stop a silent no-op
        // that Acks while the container keeps running.
        if let Err(e) = docker.teardown_by_key(&id.0).await {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("docker teardown: {e:#}"),
            };
        }
    }
    // R852-B4: and the spec digest. Unconditional (not per-backend) because
    // `Stop` is: whatever held this id, nothing holds it now, so a later
    // redeploy of the identical spec must NOT be skipped as unchanged. A
    // record that outlived its workload is the one way this field could cause
    // a missing deploy rather than a redundant one.
    ctx.registry.lock().await.remove_spec_digest(&id);
    KamajiToYubaba::Ack {
        request_id,
        kind: kamaji_proto::AckKind::Stop,
    }
}

/// Translate a [`DrainOutcome`] from the enforcer into the
/// `(accepted, reason)` pair we return in [`KamajiToYubaba::DrainAck`].
///
/// Semantics (synchronous T7 shape — see [`KamajiToYubaba::DrainAck`]
/// rustdoc):
///
/// - `Flushed` / `Checkpointed` → `accepted=true`, reason carries the phase
///   and elapsed time so operators can spot workloads riding into checkpoint.
/// - `ForceKilled` → `accepted=false`, reason notes the SIGKILL escalation.
/// - `UnknownWorkload` → `accepted=false`, reason says "unknown workload".
///   (The Drain handler short-circuits this case before calling the enforcer,
///   but the helper handles it anyway for total-function semantics.)
/// - `Unsupported` → `accepted=false`, reason says drain is not available on
///   this Kamaji build.
/// - `Err(DrainError)` → `accepted=false`, reason carries the syscall error.
fn drain_outcome_to_ack(
    outcome: Result<DrainOutcome, drain::DrainError>,
) -> (bool, Option<String>) {
    match outcome {
        Ok(DrainOutcome::Flushed { exit, elapsed_ms }) => (
            true,
            Some(format!("flushed in {elapsed_ms}ms (exit={exit:?})")),
        ),
        Ok(DrainOutcome::Checkpointed { exit, elapsed_ms }) => (
            true,
            Some(format!("checkpointed in {elapsed_ms}ms (exit={exit:?})")),
        ),
        Ok(DrainOutcome::ForceKilled { elapsed_ms }) => (
            false,
            Some(format!(
                "force-killed after {elapsed_ms}ms — workload missed budget"
            )),
        ),
        Ok(DrainOutcome::UnknownWorkload) => (false, Some("unknown workload".to_string())),
        Ok(DrainOutcome::Unsupported) => (
            false,
            Some("drain not supported on this Kamaji build (non-Linux)".to_string()),
        ),
        // `DrainOutcome` is `#[non_exhaustive]` — future variants land in
        // kamaji-proto without a wire-version bump. Surface unknown
        // outcomes as not-accepted so a forward-version Kamaji replying
        // to an older Yubaba doesn't silently misreport success.
        Ok(other) => (
            false,
            Some(format!("unrecognised DrainOutcome variant: {other:?}")),
        ),
        Err(e) => (false, Some(format!("drain failed: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamaji_proto::{
        AckKind, DrainBudget, ExitStatus, RequestId, WorkloadId,
        WorkloadState as WireWorkloadState,
    };

    #[tokio::test]
    async fn hello_with_current_version_returns_welcome() {
        let ctx = Arc::new(ServerCtx::new());
        let reply = handle_message(
            YubabaToKamaji::Hello {
                version: ProtocolVersion::CURRENT,
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::Welcome {
                version,
                kamaji_version,
            } => {
                assert_eq!(version, ProtocolVersion::CURRENT);
                assert_eq!(kamaji_version, CONSTABLE_VERSION);
            }
            other => panic!("expected Welcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_on_empty_registry_returns_empty_entries() {
        let ctx = Arc::new(ServerCtx::new());
        let reply = handle_message(
            YubabaToKamaji::List {
                request_id: RequestId(7),
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::WorkloadList {
                request_id,
                entries,
            } => {
                assert_eq!(request_id, RequestId(7));
                assert!(entries.is_empty());
            }
            other => panic!("expected WorkloadList, got {other:?}"),
        }
    }

    /// R599-B11: the exact live shape observed on east 2026-07-21 — a stale
    /// containerd container (no task → `Pending`, null pid, no mesh-ident label)
    /// sharing an id with the live native bundle workload. The merged List must
    /// emit ONE row, and it must be the running one.
    #[test]
    fn dedupe_collapses_stale_pending_row_onto_the_running_one() {
        let entries = vec![
            // The phantom, as containerd's list() renders it — and it sorts first.
            WorkloadEntry {
                id: WorkloadId::new("yah-marketing"),
                state: WireWorkloadState::Pending,
                pid: None,
                mesh_ident: None,
                ports: Vec::new(),
                named_ports: Default::default(),
                spec_digest: None,
            },
            // The truth, as the native bundle runtime renders it.
            WorkloadEntry {
                id: WorkloadId::new("yah-marketing"),
                state: WireWorkloadState::Running,
                pid: Some(67749),
                mesh_ident: Some("yah-marketing".into()),
                ports: Vec::new(),
                named_ports: Default::default(),
                spec_digest: None,
            },
        ];
        let out = dedupe_workload_entries(entries);
        assert_eq!(out.len(), 1, "one row per workload id, got {out:?}");
        assert_eq!(out[0].state, WireWorkloadState::Running);
        assert_eq!(out[0].pid, Some(67749));
        assert_eq!(out[0].mesh_ident.as_deref(), Some("yah-marketing"));
    }

    /// The winning row must be picked regardless of which order the backend
    /// merges happened to run in — the rule is liveness, not source priority.
    #[test]
    fn dedupe_is_order_independent() {
        let running = WorkloadEntry {
            id: WorkloadId::new("w"),
            state: WireWorkloadState::Running,
            pid: Some(42),
            mesh_ident: Some("w".into()),
            ports: Vec::new(),
            named_ports: Default::default(),
            spec_digest: None,
        };
        let pending = WorkloadEntry {
            id: WorkloadId::new("w"),
            state: WireWorkloadState::Pending,
            pid: None,
            mesh_ident: None,
            ports: Vec::new(),
            named_ports: Default::default(),
            spec_digest: None,
        };
        for entries in [
            vec![pending.clone(), running.clone()],
            vec![running.clone(), pending.clone()],
        ] {
            let out = dedupe_workload_entries(entries);
            assert_eq!(out.len(), 1);
            assert_eq!(out[0], running, "liveness must win either way");
        }
    }

    /// Dedupe must not collapse genuinely distinct workloads, and must preserve
    /// the order they were merged in.
    #[test]
    fn dedupe_preserves_distinct_ids_and_order() {
        let mk = |id: &str, pid| WorkloadEntry {
            id: WorkloadId::new(id),
            state: WireWorkloadState::Running,
            pid: Some(pid),
            mesh_ident: Some(id.into()),
            ports: Vec::new(),
            named_ports: Default::default(),
            spec_digest: None,
        };
        let out = dedupe_workload_entries(vec![mk("a", 1), mk("b", 2), mk("c", 3)]);
        assert_eq!(out.len(), 3);
        let ids: Vec<_> = out.iter().map(|e| e.id.0.clone()).collect();
        assert_eq!(ids, ["a", "b", "c"], "first-seen order preserved");
    }

    /// Two pid-less rows for one id still collapse, keeping the more-alive
    /// state — a workload must never appear twice on the wire.
    #[test]
    fn dedupe_breaks_pidless_ties_on_state() {
        let out = dedupe_workload_entries(vec![
            WorkloadEntry {
                id: WorkloadId::new("w"),
                state: WireWorkloadState::Exited,
                pid: None,
                mesh_ident: None,
                ports: Vec::new(),
                named_ports: Default::default(),
                spec_digest: None,
            },
            WorkloadEntry {
                id: WorkloadId::new("w"),
                state: WireWorkloadState::Starting,
                pid: None,
                mesh_ident: None,
                ports: Vec::new(),
                named_ports: Default::default(),
                spec_digest: None,
            },
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].state, WireWorkloadState::Starting);
    }

    #[tokio::test]
    async fn stop_without_backend_acks_for_idempotency() {
        // R406-T9: stop is idempotent — without a backend (no containerd
        // attached), the absence of the workload satisfies the requested
        // end-state, so we reply with Ack rather than a contrived error.
        let ctx = Arc::new(ServerCtx::new());
        let reply = handle_message(
            YubabaToKamaji::Stop {
                request_id: RequestId(1),
                id: WorkloadId::new("w-1"),
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::Ack { request_id, kind } => {
                assert_eq!(request_id, RequestId(1));
                assert_eq!(kind, AckKind::Stop);
            }
            other => panic!("expected Ack, got {other:?}"),
        }
    }

    // AckKind is re-exported for the eventual ack path; touch it so unused-import
    // lint doesn't trip when handlers don't ack yet.
    #[test]
    fn ack_kind_is_addressable() {
        let _ = AckKind::Deploy;
    }

    // ── R406-T9: deploy dispatch ─────────────────────────────────────────────

    /// MesofactStatic / Almanac workloads are not kamaji's concern — they
    /// belong to yubaba's reconcilers. Kamaji rejects them with InvalidSpec
    /// so yubaba surfaces the misroute clearly instead of silently dropping.
    #[tokio::test]
    async fn deploy_mesofact_static_is_rejected_as_invalid_spec() {
        use workload_spec::{
            BuildConfig, BuildMode, MesofactStaticWorkload, SchemaVersion, Workload,
        };
        let ctx = Arc::new(ServerCtx::new());
        let workload = Workload::MesofactStatic(MesofactStaticWorkload {
            schema_version: SchemaVersion::V1,
            build: BuildConfig {
                command: Some("bun run build".into()),
                out_dir: std::path::PathBuf::from("dist"),
                render_command: None,
            },
            routes: std::path::PathBuf::from("routes.ts"),
            build_mode: BuildMode::HostSide,
            ssr_runtime: None,
            serve_bundle: None,
            revalidate_receiver: None,
        });
        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(11),
                id: WorkloadId::new("static-site"),
                spec: workload,
                mesh: None,
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(RequestId(11)));
                assert_eq!(code, ErrorCode::InvalidSpec);
                assert!(
                    message.contains("mesofact-static") || message.contains("yubaba"),
                    "got: {message}"
                );
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// R599-F4: a mesofact-static workload carrying a `serve_bundle` is a
    /// deployed W272 bundle — kamaji must *admit* it (route to the native bundle
    /// backend), NOT reject it as InvalidSpec. Until the native serve backend is
    /// wired (R599-F3/F6), an admitted bundle reports BackendRefused — the same
    /// "recognized but no backend" signal a Container deploy gives without
    /// containerd.
    #[tokio::test]
    async fn deploy_serve_bundle_mesofact_static_is_admitted_not_invalid_spec() {
        use workload_spec::{
            BlakeHash, BuildConfig, BuildMode, BundleLifecycle, MesofactServeBundle,
            MesofactStaticWorkload, SchemaVersion, Workload,
        };
        let ctx = Arc::new(ServerCtx::new());
        let workload = Workload::MesofactStatic(MesofactStaticWorkload {
            schema_version: SchemaVersion::V1,
            build: BuildConfig {
                command: Some("bun run build".into()),
                out_dir: std::path::PathBuf::from("dist"),
                render_command: None,
            },
            routes: std::path::PathBuf::from("routes.ts"),
            build_mode: BuildMode::HostSide,
            ssr_runtime: None,
            serve_bundle: Some(MesofactServeBundle {
                digest: BlakeHash("a".repeat(64)),
                runtime: "mesofact/0.8.20".to_string(),
                lifecycle: BundleLifecycle::default(),
                port: None,
                env: Default::default(),
                origin: None,
            }),
            revalidate_receiver: None,
        });
        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(21),
                id: WorkloadId::new("yah-marketing"),
                spec: workload,
                mesh: None,
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(RequestId(21)));
                // Recognized, not rejected: BackendRefused, never InvalidSpec.
                assert_eq!(code, ErrorCode::BackendRefused, "got: {message}");
                assert!(
                    message.contains("mesofact bundle") && message.contains("yah-marketing"),
                    "got: {message}"
                );
            }
            other => panic!("expected Error(BackendRefused), got {other:?}"),
        }
    }

    /// R577-T1: a native-marked Container deploy with no native backend
    /// available **refuses** — it must not silently fall back to a container
    /// backend, because a Darwin build in a Linux container is a wrong answer,
    /// not a degraded one.
    ///
    /// Deliberately not gated on `native-exec`: with the feature off there is
    /// no backend to attach, and with it on this `ServerCtx::new()` has none
    /// attached, so the refusal is the correct reply either way. Only the
    /// *reason* differs, which is what the two-arm assertion below checks.
    #[tokio::test]
    async fn native_marked_deploy_refuses_rather_than_falling_back_to_a_container() {
        let ctx = Arc::new(ServerCtx::new());
        let mut inner = make_minimal_container_spec("forge-dmg");
        inner.annotations.insert(
            workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
            workload_spec::NATIVE_EXEC_VALUE.to_string(),
        );
        assert!(inner.wants_native_exec());

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(77),
                id: WorkloadId::new("forge-dmg"),
                spec: workload_spec::Workload::container(inner),
                mesh: None,
            },
            &ctx,
        )
        .await;

        match reply {
            KamajiToYubaba::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(RequestId(77)));
                // Recognized, not rejected: the spec is well-formed, this node
                // just can't serve it.
                assert_eq!(code, ErrorCode::BackendRefused, "got: {message}");
                assert!(
                    message.contains("native host execution"),
                    "the operator must be told which request could not be served; got: {message}"
                );
                #[cfg(feature = "native-exec")]
                assert!(message.contains("--native-exec-dir"), "got: {message}");
                #[cfg(not(feature = "native-exec"))]
                assert!(message.contains("native-exec feature"), "got: {message}");
            }
            other => panic!("expected Error(BackendRefused), got {other:?}"),
        }
    }

    /// R577-T1: native execution is gated to `tier = "infra"`, the same gate
    /// host networking and the nested-sandbox grant carry — and for a stronger
    /// reason, since a native workload has no sandbox at all.
    ///
    /// This must be an `InvalidSpec`, not a `BackendRefused`: the answer is the
    /// same on every node in the fleet, so retrying elsewhere is pointless.
    #[tokio::test]
    async fn native_exec_is_refused_outside_the_infra_tier() {
        let ctx = Arc::new(ServerCtx::new());
        let mut inner = make_minimal_container_spec("tenant-job");
        inner.tier = workload_spec::TierTag("app".into());
        inner.annotations.insert(
            workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
            workload_spec::NATIVE_EXEC_VALUE.to_string(),
        );

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(79),
                id: WorkloadId::new("tenant-job"),
                spec: workload_spec::Workload::container(inner),
                mesh: None,
            },
            &ctx,
        )
        .await;

        match reply {
            KamajiToYubaba::Error {
                code, message, ..
            } => {
                assert_eq!(code, ErrorCode::InvalidSpec, "got: {message}");
                assert!(message.contains("tier"), "got: {message}");
            }
            other => panic!("expected Error(InvalidSpec), got {other:?}"),
        }
    }

    /// R858-B14: a workload the `--native-exec-dir` backend is supervising must
    /// appear in `List` — the regression that kept us-west-001 out of raft
    /// quorum for a day.
    ///
    /// `ctx.native` was wired into `Deploy` and into `Welcome`'s capability
    /// report but into neither `List` nor the registry, and `Registry::workloads`
    /// (whose comment called itself the native list) has no writer outside
    /// tests. So the headscale appliance forked, ran, was supervised — and was
    /// absent from every `List` reply. Yubaba's `get_workload` filters that list
    /// by ident, so `observe_local_appliance` reported "not running here" about a
    /// healthy coordinator and every reconcile tick redeployed it, killing a
    /// process kamaji was tending correctly. The pid assertion is the other half:
    /// yubaba logs `pid: 0` on deploy by design (the sibling `Deploy` acks on
    /// admission, before the fork), so `List` is the *only* channel that can
    /// carry the real pid back.
    #[cfg(feature = "native-exec")]
    #[tokio::test]
    async fn a_native_exec_workload_is_visible_in_list() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Arc::new(
            ServerCtx::new()
                .with_native_exec(Arc::new(kamaji::native::NativeRuntime::new(dir.path()))),
        );

        let mut inner = make_minimal_container_spec("headscale");
        inner.annotations.insert(
            workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
            workload_spec::NATIVE_EXEC_VALUE.to_string(),
        );
        inner.command = Some(vec!["/bin/sleep".into(), "30".into()]);

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(140),
                id: WorkloadId::new("headscale"),
                spec: workload_spec::Workload::container(inner),
                mesh: None,
            },
            &ctx,
        )
        .await;
        assert!(
            matches!(
                reply,
                KamajiToYubaba::Ack {
                    kind: kamaji_proto::AckKind::Deploy,
                    ..
                }
            ),
            "native deploy should Ack, got {reply:?}"
        );

        let list = handle_message(
            YubabaToKamaji::List {
                request_id: RequestId(141),
            },
            &ctx,
        )
        .await;
        let entries = match list {
            KamajiToYubaba::WorkloadList { entries, .. } => entries,
            other => panic!("expected WorkloadList, got {other:?}"),
        };
        let entry = entries
            .iter()
            .find(|e| e.id == WorkloadId::new("headscale"))
            .unwrap_or_else(|| {
                panic!("a supervised native workload must appear in List, got {entries:?}")
            });
        assert_eq!(
            entry.state,
            WorkloadState::Running,
            "yubaba adopts only on Running; anything else redeploys"
        );
        assert!(
            entry.pid.is_some_and(|p| p != 0),
            "List is the only channel carrying the forked pid back, got {entry:?}"
        );
        assert_eq!(
            entry.mesh_ident.as_deref(),
            Some("headscale"),
            "yubaba's get_workload matches on mesh_ident, got {entry:?}"
        );

        // Torn down through the runtime rather than through `Stop`, so this test
        // keeps covering only the read side. `stop_workload` grew its
        // `ctx.native` arm in R858-B15; the write side is asserted by
        // `a_native_exec_workload_is_gone_from_list_after_stop` below.
        {
            use kamaji::Kamaji as _;
            let native = ctx.native.clone().expect("native backend attached above");
            native
                .teardown_workload(&workload_spec::MeshIdent("headscale".into()))
                .await
                .unwrap();
        }
    }

    /// True when `pid` names no live process — i.e. the child was killed *and*
    /// reaped, not merely signalled into a zombie.
    ///
    /// `kill -0` rather than `libc::kill`: kamaji-bin's `libc` dependency is
    /// `[target.'cfg(target_os = "linux")']`, and this test runs on the camp's
    /// darwin machines too. A reaped pid gives ESRCH and a non-zero exit; a
    /// zombie would still answer 0, which is exactly the distinction being
    /// asserted — `stop_child` awaits `child.wait()`, so a correct teardown
    /// leaves nothing behind.
    #[cfg(all(unix, feature = "native-exec"))]
    fn pid_is_reaped(pid: u32) -> bool {
        !std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("spawn kill -0")
            .success()
    }

    /// R858-B15: a `Stop` for a native-exec workload must actually stop it —
    /// the write-side twin of `a_native_exec_workload_is_visible_in_list`.
    ///
    /// Every arm of `stop_workload` was containerd / tenant-passway / bundle /
    /// microvm / docker, so a Stop addressed to the `--native-exec-dir` backend
    /// fell through all of them and returned `Ack{Stop}` while the forked child
    /// kept running. That is a *lying* Ack: yubaba's teardown path reads the Ack
    /// as "it is gone", so `on_lost_leader -> stop_headscale` would report a
    /// torn-down coordinator over a live one, and the next `List` would still
    /// show it Running — two channels contradicting each other about the mesh
    /// coordinator.
    ///
    /// Both halves are asserted because either alone is passable by a wrong fix:
    /// dropping the map entry without signalling the child satisfies the List
    /// assertion while leaking the process, and killing the child without
    /// dropping the entry satisfies the pid assertion while leaving a corpse in
    /// every subsequent List reply.
    #[cfg(all(unix, feature = "native-exec"))]
    #[tokio::test]
    async fn a_native_exec_workload_is_gone_from_list_after_stop() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Arc::new(
            ServerCtx::new()
                .with_native_exec(Arc::new(kamaji::native::NativeRuntime::new(dir.path()))),
        );

        let mut inner = make_minimal_container_spec("headscale");
        inner.annotations.insert(
            workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
            workload_spec::NATIVE_EXEC_VALUE.to_string(),
        );
        inner.command = Some(vec!["/bin/sleep".into(), "30".into()]);

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(150),
                id: WorkloadId::new("headscale"),
                spec: workload_spec::Workload::container(inner),
                mesh: None,
            },
            &ctx,
        )
        .await;
        assert!(
            matches!(
                reply,
                KamajiToYubaba::Ack {
                    kind: kamaji_proto::AckKind::Deploy,
                    ..
                }
            ),
            "native deploy should Ack, got {reply:?}"
        );

        // Capture the live pid off `List` — the only channel that carries it
        // (R858-B14) — so the reaping assertion below has something to check.
        let pid = native_list_pid(&ctx, RequestId(151), "headscale")
            .await
            .expect("a supervised native workload must appear in List before Stop");
        assert!(pid != 0, "expected a real forked pid, got 0");
        assert!(
            !pid_is_reaped(pid),
            "precondition: the child must be alive before Stop, pid {pid}"
        );

        let stop = handle_message(
            YubabaToKamaji::Stop {
                request_id: RequestId(152),
                id: WorkloadId::new("headscale"),
            },
            &ctx,
        )
        .await;
        assert!(
            matches!(
                stop,
                KamajiToYubaba::Ack {
                    kind: AckKind::Stop,
                    ..
                }
            ),
            "Stop should Ack, got {stop:?}"
        );

        assert_eq!(
            native_list_pid(&ctx, RequestId(153), "headscale").await,
            None,
            "a stopped native workload must be absent from List"
        );
        assert!(
            pid_is_reaped(pid),
            "Stop Acked but pid {pid} is still alive — the lying Ack R858-B15 exists to fix"
        );
    }

    /// R858-B15 / R590-B9: a `Stop` for a native **forge** workload resolves by
    /// workload id even though the runtime is keyed by mesh identity.
    ///
    /// This is the half a bare `native.teardown_workload(&MeshIdent(id.0))`
    /// would get wrong. `WorkloadSpec::for_forge` is `name = forge-<uuid>`
    /// against `identity = forge.<uuid>` — dots are not DNS-label safe — and
    /// `mark_native_exec` turns exactly that spec into a fork+exec one. So the
    /// id yubaba addresses is not the key the native map holds, and looking up
    /// only the identity would Ack over a live child: the same lying Ack, moved
    /// from the appliance to forge runs rather than fixed. `teardown_by_key`
    /// resolves either spelling, mirroring the docker backend's
    /// `yah.workload_id` label.
    #[cfg(all(unix, feature = "native-exec"))]
    #[tokio::test]
    async fn stop_tears_down_a_native_forge_workload_addressed_by_its_id() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Arc::new(
            ServerCtx::new()
                .with_native_exec(Arc::new(kamaji::native::NativeRuntime::new(dir.path()))),
        );

        // The R590-B9 divergence, deliberately constructed: id/name hyphenated,
        // mesh identity dotted.
        let mut inner = make_minimal_container_spec("forge-abc123");
        inner.expose.mesh.identity = workload_spec::MeshIdent("forge.abc123".into());
        inner.annotations.insert(
            workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
            workload_spec::NATIVE_EXEC_VALUE.to_string(),
        );
        inner.command = Some(vec!["/bin/sleep".into(), "30".into()]);

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(154),
                id: WorkloadId::new("forge-abc123"),
                spec: workload_spec::Workload::container(inner),
                mesh: None,
            },
            &ctx,
        )
        .await;
        assert!(
            matches!(
                reply,
                KamajiToYubaba::Ack {
                    kind: kamaji_proto::AckKind::Deploy,
                    ..
                }
            ),
            "native forge deploy should Ack, got {reply:?}"
        );

        // Listed under the mesh identity, which is precisely why the id lookup
        // needs help.
        let pid = native_list_pid(&ctx, RequestId(155), "forge.abc123")
            .await
            .expect("native forge workload must appear in List under its mesh identity");
        assert!(pid != 0, "expected a real forked pid, got 0");

        let stop = handle_message(
            YubabaToKamaji::Stop {
                request_id: RequestId(156),
                // The hyphenated id, NOT the dotted identity — what yubaba sends.
                id: WorkloadId::new("forge-abc123"),
            },
            &ctx,
        )
        .await;
        assert!(
            matches!(
                stop,
                KamajiToYubaba::Ack {
                    kind: AckKind::Stop,
                    ..
                }
            ),
            "Stop should Ack, got {stop:?}"
        );

        assert_eq!(
            native_list_pid(&ctx, RequestId(157), "forge.abc123").await,
            None,
            "a Stop carrying the workload id must remove the workload the native \
             runtime keyed under its mesh identity"
        );
        assert!(
            pid_is_reaped(pid),
            "Stop Acked but pid {pid} is still alive — a bare ident lookup no-opped"
        );
    }

    /// `List` the native workloads and return the pid of the entry whose
    /// `mesh_ident` is `ident`, or `None` when no such entry exists.
    #[cfg(all(unix, feature = "native-exec"))]
    async fn native_list_pid(
        ctx: &Arc<ServerCtx>,
        request_id: RequestId,
        ident: &str,
    ) -> Option<u32> {
        let list = handle_message(YubabaToKamaji::List { request_id }, ctx).await;
        let entries = match list {
            KamajiToYubaba::WorkloadList { entries, .. } => entries,
            other => panic!("expected WorkloadList, got {other:?}"),
        };
        entries
            .iter()
            .find(|e| e.mesh_ident.as_deref() == Some(ident))
            .and_then(|e| e.pid)
    }

    /// R577-T1: an unresolved secret reaching the native path is a hard error,
    /// not a silently-missing env var.
    ///
    /// `NativeRuntime` spawns only `EnvValue::Literal` and skips the rest, so
    /// without this check a `codesign` step would run with
    /// `APPLE_SIGNING_IDENTITY` simply absent and fail somewhere far from the
    /// cause. That is the exact seam R577-F3 (Apple credential delivery) sits
    /// on, so it must fail loudly here.
    #[tokio::test]
    async fn native_exec_rejects_an_unresolved_secret_rather_than_dropping_it() {
        let ctx = Arc::new(ServerCtx::new());
        let mut inner = make_minimal_container_spec("forge-dmg");
        inner.annotations.insert(
            workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
            workload_spec::NATIVE_EXEC_VALUE.to_string(),
        );
        inner.env.push(workload_spec::EnvVar {
            name: "APPLE_SIGNING_IDENTITY".into(),
            value: workload_spec::EnvValue::FromSecret {
                secret: "apple-developer-id".into(),
                key: "identity".into(),
            },
        });

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(80),
                id: WorkloadId::new("forge-dmg"),
                spec: workload_spec::Workload::container(inner),
                mesh: None,
            },
            &ctx,
        )
        .await;

        match reply {
            KamajiToYubaba::Error {
                code, message, ..
            } => {
                assert_eq!(code, ErrorCode::InvalidSpec, "got: {message}");
                assert!(message.contains("APPLE_SIGNING_IDENTITY"), "got: {message}");
                assert!(message.contains("apple-developer-id"), "got: {message}");
            }
            other => panic!("expected Error(InvalidSpec), got {other:?}"),
        }
    }

    /// R577-T1 × R636-B2: a spec asking for both native execution and the
    /// nested-sandbox capability grant is refused rather than having the grant
    /// silently ignored.
    ///
    /// The two markers are independent *annotations* (R636-B2 has a test
    /// asserting exactly that), but they are mutually exclusive at *dispatch*:
    /// the grant widens a container's OCI capability set, and native execution
    /// has no container. Since `deploy_container` routes on the native marker
    /// first, without this check the privilege request would be accepted and
    /// dropped on the floor.
    #[tokio::test]
    async fn native_exec_and_the_nested_sandbox_grant_are_mutually_exclusive() {
        let ctx = Arc::new(ServerCtx::new());
        let mut inner = make_minimal_container_spec("forge-confused");
        inner.annotations.insert(
            workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
            workload_spec::NATIVE_EXEC_VALUE.to_string(),
        );
        inner.annotations.insert(
            workload_spec::NESTED_SANDBOX_ANNOTATION.to_string(),
            workload_spec::NESTED_SANDBOX_VALUE.to_string(),
        );
        // Both markers really are set — this is the combination under test, not
        // a spec that quietly failed to carry one of them.
        assert!(inner.wants_native_exec() && inner.wants_nested_sandbox());

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(81),
                id: WorkloadId::new("forge-confused"),
                spec: workload_spec::Workload::container(inner),
                mesh: None,
            },
            &ctx,
        )
        .await;

        match reply {
            KamajiToYubaba::Error { code, message, .. } => {
                assert_eq!(code, ErrorCode::InvalidSpec, "got: {message}");
                assert!(message.contains("mutually exclusive"), "got: {message}");
            }
            other => panic!("expected Error(InvalidSpec), got {other:?}"),
        }
    }

    /// R605-F8: a microVM-marked Container deploy with no microVM backend
    /// available **refuses** rather than falling back to a container.
    ///
    /// The symmetric case to the native one above, and the reason is symmetric
    /// too: the caller asked for isolation that does not rest on the host
    /// kernel, and a container is the one answer that silently is not that. On
    /// a node running a raft voter — the case W325 §5 is written for — the
    /// fallback would put an un-isolated build next to consensus while
    /// reporting success.
    #[tokio::test]
    async fn microvm_marked_deploy_refuses_rather_than_falling_back_to_a_container() {
        let ctx = Arc::new(ServerCtx::new());
        let mut inner = make_minimal_container_spec("forge-isolated");
        inner.annotations.insert(
            workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
            workload_spec::MICROVM_EXEC_VALUE.to_string(),
        );
        assert!(inner.wants_microvm());
        // The property the shared key buys: this spec cannot also be native.
        assert!(!inner.wants_native_exec());

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(91),
                id: WorkloadId::new("forge-isolated"),
                spec: workload_spec::Workload::container(inner),
                mesh: None,
            },
            &ctx,
        )
        .await;

        match reply {
            KamajiToYubaba::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(RequestId(91)));
                assert_eq!(code, ErrorCode::BackendRefused, "got: {message}");
                assert!(
                    message.contains("microVM isolation"),
                    "the operator must be told which request could not be served; got: {message}"
                );
                #[cfg(feature = "microvm")]
                assert!(message.contains("--microvm-dir"), "got: {message}");
                #[cfg(not(feature = "microvm"))]
                assert!(message.contains("microvm feature"), "got: {message}");
            }
            other => panic!("expected Error(BackendRefused), got {other:?}"),
        }
    }

    /// R605-F8: a microVM workload is **not** gated to `tier = "infra"`, unlike
    /// the native path.
    ///
    /// Pinned as a deliberate asymmetry rather than left implicit, because the
    /// obvious "make the guards match" refactor would be wrong: the native gate
    /// exists because that path has no sandbox, and copying it here would mean
    /// a tenant workload is permitted to share the host kernel but forbidden to
    /// be isolated from it. If this test ever starts failing, the question to
    /// ask is what changed about the guest boundary — not whether to add a tier
    /// check for symmetry.
    #[tokio::test]
    async fn microvm_is_not_tier_gated_the_way_native_exec_is() {
        let ctx = Arc::new(ServerCtx::new());
        let mut inner = make_minimal_container_spec("tenant-isolated");
        inner.tier = workload_spec::TierTag("app".into());
        inner.annotations.insert(
            workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
            workload_spec::MICROVM_EXEC_VALUE.to_string(),
        );

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(92),
                id: WorkloadId::new("tenant-isolated"),
                spec: workload_spec::Workload::container(inner),
                mesh: None,
            },
            &ctx,
        )
        .await;

        match reply {
            KamajiToYubaba::Error { code, message, .. } => {
                // Refused for want of a backend (retry elsewhere), never
                // rejected as malformed (retry is pointless).
                assert_eq!(
                    code,
                    ErrorCode::BackendRefused,
                    "a non-infra microVM spec must not be an InvalidSpec; got: {message}"
                );
            }
            other => panic!("expected Error(BackendRefused), got {other:?}"),
        }
    }

    /// R605-F8: an unresolved secret reaching the microVM path is a hard error.
    ///
    /// Sharper here than on the native path: a forked process at least shares
    /// the host's filesystem, so a missing value has a chance of being found
    /// some other way. A guest has no route back to yubaba's secret store at
    /// all, so whatever is not in the job document simply does not exist for
    /// the duration of the build.
    #[tokio::test]
    async fn microvm_rejects_an_unresolved_secret_rather_than_dropping_it() {
        let ctx = Arc::new(ServerCtx::new());
        let mut inner = make_minimal_container_spec("forge-isolated");
        inner.annotations.insert(
            workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
            workload_spec::MICROVM_EXEC_VALUE.to_string(),
        );
        inner.env.push(workload_spec::EnvVar {
            name: "CARGO_REGISTRY_TOKEN".into(),
            value: workload_spec::EnvValue::FromSecret {
                secret: "crates-io".into(),
                key: "token".into(),
            },
        });

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(93),
                id: WorkloadId::new("forge-isolated"),
                spec: workload_spec::Workload::container(inner),
                mesh: None,
            },
            &ctx,
        )
        .await;

        match reply {
            KamajiToYubaba::Error { code, message, .. } => {
                assert_eq!(code, ErrorCode::InvalidSpec, "got: {message}");
                assert!(message.contains("crates-io"), "got: {message}");
                assert!(message.contains("CARGO_REGISTRY_TOKEN"), "got: {message}");
            }
            other => panic!("expected Error(InvalidSpec), got {other:?}"),
        }
    }

    /// R605-F8 × R636-B2: microVM isolation and the nested-sandbox grant are
    /// mutually exclusive, for the same reason the native pair is — the grant
    /// describes an OCI capability set and there is no OCI spec on this path.
    #[tokio::test]
    async fn microvm_and_the_nested_sandbox_grant_are_mutually_exclusive() {
        let ctx = Arc::new(ServerCtx::new());
        let mut inner = make_minimal_container_spec("forge-confused-vm");
        inner.annotations.insert(
            workload_spec::NATIVE_EXEC_ANNOTATION.to_string(),
            workload_spec::MICROVM_EXEC_VALUE.to_string(),
        );
        inner.annotations.insert(
            workload_spec::NESTED_SANDBOX_ANNOTATION.to_string(),
            workload_spec::NESTED_SANDBOX_VALUE.to_string(),
        );
        assert!(inner.wants_microvm() && inner.wants_nested_sandbox());

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(94),
                id: WorkloadId::new("forge-confused-vm"),
                spec: workload_spec::Workload::container(inner),
                mesh: None,
            },
            &ctx,
        )
        .await;

        match reply {
            KamajiToYubaba::Error { code, message, .. } => {
                assert_eq!(code, ErrorCode::InvalidSpec, "got: {message}");
                assert!(message.contains("mutually exclusive"), "got: {message}");
            }
            other => panic!("expected Error(InvalidSpec), got {other:?}"),
        }
    }

    /// The negative half of the routing rule, and the one that protects live
    /// infrastructure: an *unmarked* Container spec must be untouched by
    /// R577-T1 and keep reaching the container backends. Every workload on the
    /// Linux fleet is in this class.
    #[tokio::test]
    async fn unmarked_container_deploy_does_not_take_the_native_path() {
        let ctx = Arc::new(ServerCtx::new());
        let spec = make_minimal_container_spec("svc");
        assert!(!spec.wants_native_exec());
        assert!(!spec.wants_microvm(), "nor by R605-F8");

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(78),
                id: WorkloadId::new("svc"),
                spec: workload_spec::Workload::container(spec),
                mesh: None,
            },
            &ctx,
        )
        .await;

        // Whatever this build's container backends do with it, the reply must
        // not be the native-path refusal.
        if let KamajiToYubaba::Error { message, .. } = &reply {
            assert!(
                !message.contains("native host execution"),
                "unmarked container workload took the native path: {message}"
            );
        }
    }

    /// R555-F4 / W235 §(c): the admission gate sits at the deploy envelope, so
    /// it must fire before any backend is consulted — including on a build with
    /// no container backend compiled in at all. Every other test in this module
    /// gets a `BackendRefused`; this one must not reach that far.
    ///
    /// The nested-sandbox widening is the case that needs a grant under the
    /// DEFAULT (permissive) policy, which makes it the only assertion of this
    /// wiring that need not mutate process environment — `NodeAdmission` caches
    /// in a process-wide `OnceLock`, so a test setting `YAH_ADMISSION` would
    /// decide the posture for every other test sharing the binary.
    #[tokio::test]
    async fn a_widening_request_without_a_grant_is_refused_at_the_envelope() {
        let ctx = Arc::new(ServerCtx::new());
        let mut spec = make_minimal_container_spec("build-worker");
        spec.annotations.insert(
            workload_spec::NESTED_SANDBOX_ANNOTATION.to_string(),
            workload_spec::NESTED_SANDBOX_VALUE.to_string(),
        );
        assert!(spec.wants_nested_sandbox() && !spec.wants_native_exec());

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(555),
                id: WorkloadId::new("build-worker"),
                spec: workload_spec::Workload::container(spec),
                mesh: None,
            },
            &ctx,
        )
        .await;

        match reply {
            KamajiToYubaba::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(RequestId(555)));
                assert_eq!(code, ErrorCode::InvalidSpec);
                assert!(message.contains("not admitted"), "got: {message}");
            }
            other => panic!("expected the admission refusal, got {other:?}"),
        }
    }

    /// The other half of the pair: an ordinary container workload carrying no
    /// grant must pass admission untouched under the default policy, and go on
    /// to whatever the build's backends say. Without this, the test above is
    /// equally satisfied by a gate that refuses everything.
    #[tokio::test]
    async fn an_ungranted_ordinary_workload_is_not_refused_by_admission() {
        let ctx = Arc::new(ServerCtx::new());
        let spec = make_minimal_container_spec("svc");

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(556),
                id: WorkloadId::new("svc"),
                spec: workload_spec::Workload::container(spec),
                mesh: None,
            },
            &ctx,
        )
        .await;

        if let KamajiToYubaba::Error { message, .. } = &reply {
            assert!(
                !message.contains("not admitted"),
                "permissive admission refused an unsigned ordinary workload: {message}"
            );
        }
    }

    /// Without the containerd-integration feature, Deploy { Container } must
    /// surface a clear "feature not built in" error rather than the old
    /// "not implemented (R406-T4..T6/T11)" stub. R406-T11 tracks probe.
    #[cfg(not(feature = "containerd-integration"))]
    #[tokio::test]
    async fn deploy_container_without_feature_says_so() {
        let ctx = Arc::new(ServerCtx::new());
        let spec = workload_spec::Workload::container(make_minimal_container_spec("svc"));
        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(12),
                id: WorkloadId::new("svc"),
                spec,
                mesh: None,
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(RequestId(12)));
                assert_eq!(code, ErrorCode::BackendRefused);
                assert!(message.contains("containerd-integration"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// R850-F1: the hydrate gate is on the *dispatch* path, not inside one
    /// backend — so it fires on a ctx with no backend at all, which is what
    /// proves it runs before any of them rather than after the first one that
    /// happens to be configured.
    ///
    /// This is also the property that keeps an appliance from coming up empty:
    /// a spec that declares durable state on a kamaji with no helper is refused
    /// rather than started, and the refusal names the flag.
    #[tokio::test]
    async fn a_workload_declaring_durability_is_refused_when_no_hydrate_helper_is_configured() {
        let ctx = Arc::new(ServerCtx::new());
        let mut spec = make_minimal_container_spec("acct");
        spec.volumes = vec![workload_spec::VolumeMount {
            source: workload_spec::VolumeSource::Named {
                name: "accounts".into(),
            },
            target: "/var/lib/app".into(),
            read_only: false,
        }];
        for (k, v) in [
            ("yah.durability.tier", "stream"),
            ("yah.durability.engine", "turso"),
            ("yah.durability.store", "s3://yah-backups/acct"),
            ("yah.durability.subjects", "accounts.db"),
        ] {
            spec.annotations.insert(k.into(), v.into());
        }
        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(77),
                id: WorkloadId::new("acct"),
                spec: workload_spec::Workload::container(spec),
                mesh: None,
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::Error { code, message, .. } => {
                assert_eq!(code, ErrorCode::BackendRefused);
                assert!(message.contains("--hydrate-helper"), "got: {message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// ...and the inverse, which is the one that would take the fleet down if
    /// it broke: a spec declaring nothing must reach the backend exactly as it
    /// did before this gate existed. Every spec in the tree is this shape.
    #[tokio::test]
    async fn a_workload_declaring_no_durability_reaches_the_backend_unchanged() {
        let ctx = Arc::new(ServerCtx::new());
        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(78),
                id: WorkloadId::new("svc"),
                spec: workload_spec::Workload::container(make_minimal_container_spec("svc")),
                mesh: None,
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::Error { message, .. } => assert!(
                !message.contains("hydrate"),
                "an undeclared workload must fall through to the backend arms: {message}"
            ),
            // Any non-error means it got past the gate, which is the assertion.
            _ => {}
        }
    }

    /// With the containerd-integration feature but no backend attached to
    /// ServerCtx, Deploy { Container } returns BackendRefused with a hint at
    /// the missing config.
    #[cfg(feature = "containerd-integration")]
    #[tokio::test]
    async fn deploy_container_without_attached_backend_says_so() {
        let ctx = Arc::new(ServerCtx::new());
        let spec = workload_spec::Workload::container(make_minimal_container_spec("svc"));
        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(12),
                id: WorkloadId::new("svc"),
                spec,
                mesh: None,
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(RequestId(12)));
                assert_eq!(code, ErrorCode::BackendRefused);
                assert!(message.contains("--containerd-socket"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// R626-F1: with the docker feature compiled in but no daemon attached to
    /// ServerCtx, a Container deploy must say *which* backend is missing and
    /// how to get it — a rebuild and a restart-with-flags are different fixes.
    #[cfg(feature = "docker-integration")]
    #[tokio::test]
    async fn deploy_container_without_attached_docker_says_so() {
        let ctx = Arc::new(ServerCtx::new());
        let spec = workload_spec::Workload::container(make_minimal_container_spec("svc"));
        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(21),
                id: WorkloadId::new("svc"),
                spec,
                mesh: None,
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::Error {
                request_id,
                code,
                message,
            } => {
                assert_eq!(request_id, Some(RequestId(21)));
                assert_eq!(code, ErrorCode::BackendRefused);
                assert!(message.contains("--docker"), "got: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// A docker workload renders with the workload id as `id` and the mesh
    /// identity as `mesh_ident` — the R590-B9 split the containerd backend also
    /// uses, so the two backends' rows are comparable in the List dedupe.
    #[cfg(feature = "docker-integration")]
    #[test]
    fn docker_entry_splits_workload_id_from_mesh_ident() {
        let w = kamaji::docker::DockerWorkload {
            state: kamaji::WorkloadState {
                ident: workload_spec::MeshIdent("forge.abc".into()),
                container_id: "deadbeef".into(),
                status: kamaji::WorkloadStatus::Running,
                mesh_ip: None,
                ports: Default::default(),
            },
            pid: Some(4242),
            workload_id: "forge-abc".into(),
        };
        let entry = docker_workload_to_entry(w);
        assert_eq!(entry.id, WorkloadId::new("forge-abc"));
        assert_eq!(entry.mesh_ident.as_deref(), Some("forge.abc"));
        assert_eq!(entry.pid, Some(4242));
        assert_eq!(entry.state, kamaji_proto::WorkloadState::Running);
    }

    /// Docker's restart-policy engine re-launching a container means it is
    /// coming UP, so the wire state is `Starting`, not `Failed` — a supervisor
    /// that read it as failed would tear down a container that is recovering.
    #[cfg(feature = "docker-integration")]
    #[test]
    fn docker_restarting_renders_as_starting_with_no_pid() {
        let w = kamaji::docker::DockerWorkload {
            state: kamaji::WorkloadState {
                ident: workload_spec::MeshIdent("svc".into()),
                container_id: "deadbeef".into(),
                status: kamaji::WorkloadStatus::Restarting {
                    last_exit_code: 2,
                    restart_count: 9,
                    last_finished_at_unix_ms: 1,
                },
                mesh_ip: None,
                ports: Default::default(),
            },
            pid: None,
            workload_id: "svc".into(),
        };
        let entry = docker_workload_to_entry(w);
        assert_eq!(entry.state, kamaji_proto::WorkloadState::Starting);
        assert_eq!(entry.pid, None);
    }

    fn make_minimal_container_spec(name: &str) -> workload_spec::WorkloadSpec {
        use workload_spec::{
            EnvValue, ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, ResourceLimits,
            RestartPolicy, SchemaVersion, StopPolicy, TierTag, WorkloadSpec,
        };
        let _ = EnvValue::Literal { value: "x".into() };
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.into(),
            image: ImageRef {
                registry: "ghcr.io".into(),
                repository: "x/y".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".into()),
            tenant: workload_spec::TenantId::singleton(),
            namespace: workload_spec::NamespaceId::singleton(),
            replicas: 1,
            command: Some(vec!["/bin/svc".into()]),
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 64,
                cpu_millis: 128,
                ephemeral_storage_mb: 128,
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
                    ports: MeshExpose::anonymous_ports([]),
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            annotations: Default::default(),
        }
    }

    // ── R406-T7: drain handler ───────────────────────────────────────────────

    #[tokio::test]
    async fn drain_unknown_workload_returns_drain_ack_with_accepted_false() {
        let ctx = Arc::new(ServerCtx::new());
        let reply = handle_message(
            YubabaToKamaji::Drain {
                request_id: RequestId(42),
                id: WorkloadId::new("never-registered"),
                budget: DrainBudget {
                    flush_ms: 100,
                    checkpoint_ms: 100,
                },
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::DrainAck {
                request_id,
                id,
                accepted,
                reason,
            } => {
                assert_eq!(request_id, RequestId(42));
                assert_eq!(id, WorkloadId::new("never-registered"));
                assert!(!accepted, "unknown workload must not be accepted");
                let reason = reason.expect("reason should be populated");
                assert!(
                    reason.contains("unknown"),
                    "reason should mention 'unknown', got: {reason}",
                );
            }
            other => panic!("expected DrainAck, got {other:?}"),
        }
    }

    #[test]
    fn drain_outcome_flushed_becomes_accepted_ack_with_summary() {
        let (accepted, reason) = super::drain_outcome_to_ack(Ok(DrainOutcome::Flushed {
            exit: ExitStatus::Exited(0),
            elapsed_ms: 250,
        }));
        assert!(accepted);
        let r = reason.expect("reason populated");
        assert!(r.contains("flushed"), "reason: {r}");
        assert!(r.contains("250"), "reason should carry elapsed_ms: {r}");
    }

    #[test]
    fn drain_outcome_checkpointed_is_accepted_with_checkpointed_label() {
        let (accepted, reason) = super::drain_outcome_to_ack(Ok(DrainOutcome::Checkpointed {
            exit: ExitStatus::Signaled(15),
            elapsed_ms: 5_800,
        }));
        assert!(accepted);
        let r = reason.expect("reason populated");
        assert!(r.contains("checkpointed"), "reason: {r}");
    }

    #[test]
    fn drain_outcome_force_killed_is_not_accepted() {
        let (accepted, reason) =
            super::drain_outcome_to_ack(Ok(DrainOutcome::ForceKilled { elapsed_ms: 6_100 }));
        assert!(!accepted, "force-kill must surface as accepted=false");
        let r = reason.expect("reason populated");
        assert!(r.contains("force-killed"), "reason: {r}");
        assert!(r.contains("6100"), "reason should carry elapsed_ms: {r}");
    }

    #[test]
    fn drain_outcome_unknown_workload_translates_cleanly() {
        let (accepted, reason) = super::drain_outcome_to_ack(Ok(DrainOutcome::UnknownWorkload));
        assert!(!accepted);
        assert!(reason.expect("reason populated").contains("unknown"));
    }

    #[test]
    fn drain_outcome_unsupported_is_not_accepted() {
        let (accepted, reason) = super::drain_outcome_to_ack(Ok(DrainOutcome::Unsupported));
        assert!(!accepted);
        let r = reason.expect("reason populated");
        assert!(
            r.contains("non-Linux") || r.contains("not supported"),
            "{r}"
        );
    }

    #[test]
    fn drain_outcome_error_carries_message() {
        // SIGTERM = 15 (POSIX). Avoids the libc dep on the cross-platform
        // test compile (libc is Linux-only in this crate's Cargo.toml).
        let err = drain::DrainError::Signal {
            signal: 15,
            source: std::io::Error::other("synthetic"),
        };
        let (accepted, reason) = super::drain_outcome_to_ack(Err(err));
        assert!(!accepted);
        let r = reason.expect("reason populated");
        assert!(r.contains("drain failed"), "{r}");
    }

    // ── R406-T11: probe RPC ──────────────────────────────────────────────────

    /// Probe of an unregistered workload returns Ready — the "no probe spec
    /// declared" convention. Probe-target absence ↔ Ready makes Yubaba's
    /// admission logic uniform: every Probe answer is wire-typed, never an
    /// error.
    #[tokio::test]
    async fn probe_unregistered_workload_returns_ready() {
        let ctx = Arc::new(ServerCtx::new());
        let reply = handle_message(
            YubabaToKamaji::Probe {
                request_id: RequestId(91),
                id: WorkloadId::new("no-probe-registered"),
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::ProbeResult {
                request_id,
                id,
                status,
            } => {
                assert_eq!(request_id, RequestId(91));
                assert_eq!(id, WorkloadId::new("no-probe-registered"));
                assert!(
                    matches!(status, kamaji_proto::ProbeStatus::Ready),
                    "expected Ready for absent probe target, got {status:?}",
                );
            }
            other => panic!("expected ProbeResult, got {other:?}"),
        }
    }

    /// Probe of a workload whose registered TcpConnect target points at an
    /// accepting listener returns Ready. Ties the registry → probe runner →
    /// wire shape together end-to-end inside the dispatcher.
    #[tokio::test]
    async fn probe_registered_tcp_connect_target_returns_ready() {
        use crate::probe::ProbeTarget;
        use std::net::{Ipv4Addr, SocketAddr};
        use tokio::net::TcpListener;
        use workload_spec::{HealthProbe, Healthcheck, Millis};

        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();

        let ctx = Arc::new(ServerCtx::new());
        ctx.registry.lock().await.insert_probe(
            WorkloadId::new("svc-1"),
            ProbeTarget::healthcheck(
                Healthcheck {
                    probe: HealthProbe::TcpConnect { port },
                    interval: Millis::from_ms(1000),
                    timeout: Millis::from_ms(500),
                    initial_delay: Millis::from_ms(0),
                    failure_threshold: 3,
                },
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            ),
        );

        let reply = handle_message(
            YubabaToKamaji::Probe {
                request_id: RequestId(92),
                id: WorkloadId::new("svc-1"),
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::ProbeResult {
                request_id,
                id,
                status,
            } => {
                assert_eq!(request_id, RequestId(92));
                assert_eq!(id, WorkloadId::new("svc-1"));
                assert!(
                    matches!(status, kamaji_proto::ProbeStatus::Ready),
                    "expected Ready, got {status:?}",
                );
            }
            other => panic!("expected ProbeResult, got {other:?}"),
        }
    }

    // ── R715-F3 / W315: the process-control channel ──────────────────────────

    /// The declaration is the env var the workload is already handed. Nothing
    /// else in the spec says "I speak the channel", and adding a second place
    /// to say it is how the two drift.
    #[test]
    fn a_spec_declares_its_control_channel_through_the_env_var() {
        use workload_spec::{EnvValue, EnvVar};

        let mut spec = make_minimal_container_spec("svc");
        assert_eq!(control_sock_from_spec(&spec), None, "no var, no channel");

        spec.env.push(EnvVar {
            name: procctl::CONTROL_SOCK_ENV.into(),
            value: EnvValue::Literal {
                value: "/tmp/yah/control.sock".into(),
            },
        });
        assert_eq!(
            control_sock_from_spec(&spec),
            Some(std::path::PathBuf::from("/tmp/yah/control.sock")),
        );
    }

    /// An empty value is what an unset-but-declared variable looks like, and a
    /// secret ref is not a path. Both must read as "no channel" rather than
    /// registering a probe against a socket that will never exist — that probe
    /// would hold the workload at `Starting` forever.
    #[test]
    fn a_non_literal_or_empty_control_var_declares_nothing() {
        use workload_spec::{EnvValue, EnvVar};

        let mut spec = make_minimal_container_spec("svc");
        spec.env.push(EnvVar {
            name: procctl::CONTROL_SOCK_ENV.into(),
            value: EnvValue::Literal { value: String::new() },
        });
        assert_eq!(control_sock_from_spec(&spec), None, "empty is not a path");

        spec.env.clear();
        spec.env.push(EnvVar {
            name: procctl::CONTROL_SOCK_ENV.into(),
            value: EnvValue::FromSecret {
                secret: "s".into(),
                key: "k".into(),
            },
        });
        assert_eq!(control_sock_from_spec(&spec), None, "a secret is not a path");
    }

    /// Registry → probe runner → wire, for the control channel: the workload's
    /// own word travels all the way out to yubaba as a `ProbeResult`.
    #[tokio::test]
    async fn probe_of_a_control_channel_workload_reports_what_the_workload_says() {
        use crate::probe::ProbeTarget;

        let tmp = tempfile::TempDir::new().unwrap();
        let sock = tmp.path().join("control.sock");
        let _producer = procctl::serve_at(&sock, || {
            procctl::ProcStatus::new(procctl::ProcState::Starting).with_detail("migrating 3/7")
        })
        .unwrap();

        let ctx = Arc::new(ServerCtx::new());
        ctx.registry
            .lock()
            .await
            .insert_probe(WorkloadId::new("gui-1"), ProbeTarget::control(&sock));

        let reply = handle_message(
            YubabaToKamaji::Probe {
                request_id: RequestId(93),
                id: WorkloadId::new("gui-1"),
            },
            &ctx,
        )
        .await;
        match reply {
            KamajiToYubaba::ProbeResult { id, status, .. } => {
                assert_eq!(id, WorkloadId::new("gui-1"));
                assert!(
                    matches!(status, kamaji_proto::ProbeStatus::Starting),
                    "a workload that says it is starting must not be reported ready, got {status:?}",
                );
            }
            other => panic!("expected ProbeResult, got {other:?}"),
        }
    }

    // ── R599-F10: keep-alive native bundle backend ───────────────────────────
    #[cfg(feature = "bundle-serving")]
    mod bundle_serving {
        use super::super::*;
        use kamaji_proto::{RequestId, WorkloadId};
        use std::collections::BTreeMap;
        use std::sync::Arc;
        use workload_spec::{
            BlakeHash, BuildConfig, BuildMode, BundleLifecycle, MesofactServeBundle,
            MesofactStaticWorkload, Millis, SchemaVersion, Workload,
        };
        use yah_mesofact_bundle::{
            publish_bundle, BundleHash, BundleManifest, BundleRuntime, SCHEMA_VERSION,
        };
        use yah_object_store::{InMemoryObjectStore, ObjectStore};

        /// Poll `DeployStatus` until the R330-F33 asynchronous deploy of `id`
        /// reaches a terminal state, and return `(state, detail)`.
        ///
        /// This is deliberately driven through `handle_message` rather than by
        /// reading the registry directly: what these tests need to hold is the
        /// contract a real caller sees over the wire, and polling is now part of
        /// that contract. Panics rather than returning on timeout — a deploy
        /// that never reaches a terminal state is the bug, not a slow test.
        async fn await_deploy(
            ctx: &Arc<ServerCtx>,
            id: &str,
        ) -> (WorkloadState, Option<String>) {
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                let reply = handle_message(
                    YubabaToKamaji::DeployStatus {
                        request_id: RequestId(9_000),
                        id: WorkloadId::new(id),
                    },
                    ctx,
                )
                .await;
                match reply {
                    KamajiToYubaba::DeployStatusResult { state, detail, .. } => {
                        if matches!(state, WorkloadState::Running | WorkloadState::Failed) {
                            return (state, detail);
                        }
                    }
                    other => panic!("expected DeployStatusResult, got {other:?}"),
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "deploy of {id} never reached a terminal state"
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }

        /// [`await_deploy`], asserting the deploy succeeded.
        async fn await_deploy_ok(ctx: &Arc<ServerCtx>, id: &str) {
            let (state, detail) = await_deploy(ctx, id).await;
            assert_eq!(
                state,
                WorkloadState::Running,
                "deploy of {id} failed: {detail:?}"
            );
        }

        /// Assemble a `runtime = "self"` bundle on disk (manifest + files),
        /// publish it to `store`, and return its digest hex. When `with_serve`
        /// is set, a fake `bins/<node-triple>/serve` shell script is included so
        /// the resolved serve bin exists; otherwise it's omitted (drives the
        /// "missing runtime asset" case).
        fn publish_self_bundle(store: &dyn ObjectStore, with_serve: bool) -> String {
            publish_self_bundle_with_bins(store, with_serve, &[])
        }

        /// [`publish_self_bundle`] plus extra `bins/<node-triple>/<name>`
        /// sidecars (R330-F31) — e.g. the `almanac-feed` fetcher a bundle with a
        /// declared feed tier must carry.
        fn publish_self_bundle_with_bins(
            store: &dyn ObjectStore,
            with_serve: bool,
            extra_bins: &[&str],
        ) -> String {
            let dir = tempfile::tempdir().unwrap();
            let mut files: Vec<(String, Vec<u8>)> =
                vec![("app/index.html".to_string(), b"<html>home</html>".to_vec())];
            if with_serve {
                // A serve bin that just sleeps so the supervised child stays up.
                let serve_rel = format!("bins/{}/serve", node_triple());
                files.push((serve_rel, b"#!/bin/sh\nexec sleep 30\n".to_vec()));
            }
            for name in extra_bins {
                files.push((
                    format!("bins/{}/{name}", node_triple()),
                    b"#!/bin/sh\nexec sleep 30\n".to_vec(),
                ));
            }

            let mut content = BTreeMap::new();
            for (path, bytes) in &files {
                let full = dir.path().join(path);
                std::fs::create_dir_all(full.parent().unwrap()).unwrap();
                std::fs::write(&full, bytes).unwrap();
                content.insert(path.clone(), BundleHash::of(bytes));
            }
            let manifest = BundleManifest {
                schema_version: SCHEMA_VERSION,
                requires_contract: yah_mesofact_bundle::BUNDLE_CONTRACT_VERSION,
                name: "yah-marketing".to_string(),
                runtime: BundleRuntime::self_contained(),
                content,
            };
            std::fs::write(
                dir.path().join("manifest.toml"),
                manifest.to_toml_string().unwrap(),
            )
            .unwrap();
            let report = publish_bundle(store, dir.path()).unwrap();
            report.digest.as_str().to_string()
        }

        fn serve_bundle_workload(digest_hex: &str, lifecycle: BundleLifecycle) -> Workload {
            serve_bundle_workload_on_port(digest_hex, lifecycle, None)
        }

        /// [`serve_bundle_workload`] with an explicit `serve_bundle.port`
        /// (R599-F12) — the per-workload serving port that lets one node host
        /// more than one bundle.
        fn serve_bundle_workload_on_port(
            digest_hex: &str,
            lifecycle: BundleLifecycle,
            port: Option<u16>,
        ) -> Workload {
            serve_bundle_workload_with_runtime(digest_hex, "self", lifecycle, port)
        }

        /// [`serve_bundle_workload_on_port`] with an explicit `runtime` selector
        /// — `"self"` for a bundle carrying its own binary, `"mesofact/<ver>"`
        /// for a vanilla one that resolves the shared node runtime asset
        /// (R746-F1).
        fn serve_bundle_workload_with_runtime(
            digest_hex: &str,
            runtime: &str,
            lifecycle: BundleLifecycle,
            port: Option<u16>,
        ) -> Workload {
            Workload::MesofactStatic(MesofactStaticWorkload {
                schema_version: SchemaVersion::V1,
                build: BuildConfig {
                    command: Some("bun run build".into()),
                    out_dir: std::path::PathBuf::from("dist"),
                    render_command: None,
                },
                routes: std::path::PathBuf::from("routes.ts"),
                build_mode: BuildMode::HostSide,
                ssr_runtime: None,
                serve_bundle: Some(MesofactServeBundle {
                    digest: BlakeHash(digest_hex.to_string()),
                    runtime: runtime.to_string(),
                    lifecycle,
                    port,
                    // R556-T12. The deploy paths' env threading is pinned by
                    // the spec-shape tests (`serve_spec_carries_the_deploy_
                    // resolved_env` and its JIT twin) — the native runtime
                    // keeps no readable copy of a forked spec, so these
                    // end-to-end deploys can only assert admission.
                    env: Default::default(),
                    // R870-B6. `None` is the single-tenant fleet: the node's
                    // own store answers, which is what these tests inject.
                    origin: None,
                }),
                revalidate_receiver: None,
            })
        }

        // ── R746-F1: vanilla bundles serve from the shared runtime asset ─────

        /// The stock runtime version these tests resolve against.
        const STOCK_RUNTIME: &str = "mesofact/0.8.20";

        /// Publish a **vanilla** bundle: `app/` only, no `bins/`, and
        /// `runtime = "mesofact/<ver>"`. `body` varies the content so two calls
        /// produce two distinct digests — two sites on one node.
        fn publish_vanilla_bundle(store: &dyn ObjectStore, body: &str) -> String {
            publish_vanilla_bundle_requiring(
                store,
                body,
                yah_mesofact_bundle::BUNDLE_CONTRACT_VERSION,
            )
        }

        /// [`publish_vanilla_bundle`] at an explicit bundle↔runtime contract
        /// version (R746-F6) — how a bundle assembled by a *different* tree
        /// arrives at this node.
        fn publish_vanilla_bundle_requiring(
            store: &dyn ObjectStore,
            body: &str,
            requires_contract: yah_mesofact_bundle::ContractVersion,
        ) -> String {
            let dir = tempfile::tempdir().unwrap();
            let bytes = body.as_bytes().to_vec();
            std::fs::create_dir_all(dir.path().join("app")).unwrap();
            std::fs::write(dir.path().join("app/index.html"), &bytes).unwrap();

            let mut content = BTreeMap::new();
            content.insert("app/index.html".to_string(), BundleHash::of(&bytes));
            let manifest = BundleManifest {
                schema_version: SCHEMA_VERSION,
                requires_contract,
                name: "yah-marketing".to_string(),
                runtime: BundleRuntime::parse(STOCK_RUNTIME).unwrap(),
                content,
            };
            std::fs::write(
                dir.path().join("manifest.toml"),
                manifest.to_toml_string().unwrap(),
            )
            .unwrap();
            publish_bundle(store, dir.path())
                .unwrap()
                .digest
                .as_str()
                .to_string()
        }

        /// Runtime ref for the feed-fetch sidecar (R746-T3). Its own ref, not a
        /// second binary under the mesofact runtime's: `almanac-feed` is
        /// versioned with yubaba and releases on its own cadence.
        const FEED_RUNTIME: &str = "almanac-feed/0.8.22";

        /// Publish the `almanac-feed` fetcher as a node asset — the vanilla
        /// shape's answer to "how does the fetcher reach the node", replacing
        /// the `bins/<triple>/almanac-feed` a self-contained bundle stages.
        fn publish_feed_runtime(store: &dyn ObjectStore) {
            let dir = tempfile::tempdir().unwrap();
            let bin = dir.path().join("almanac-feed");
            std::fs::write(&bin, b"#!/bin/sh\nexec sleep 30\n").unwrap();
            yah_mesofact_bundle::publish_runtime_asset(
                store,
                &yah_mesofact_bundle::RuntimeRef::parse(FEED_RUNTIME).unwrap(),
                &node_triple(),
                yah_mesofact_bundle::FEED_BIN,
                yah_mesofact_bundle::IMPLEMENTED_CONTRACTS,
                &bin,
            )
            .unwrap();
        }

        /// Publish the stock serve runtime asset for this node's triple — a
        /// stub that just sleeps, standing in for the ~70MB musl binary
        /// R560-T8/T9 build and ship.
        fn publish_stock_runtime(store: &dyn ObjectStore) {
            let dir = tempfile::tempdir().unwrap();
            let bin = dir.path().join("mesofact-serve");
            std::fs::write(&bin, b"#!/bin/sh\nexec sleep 30\n").unwrap();
            yah_mesofact_bundle::publish_runtime_asset(
                store,
                &yah_mesofact_bundle::RuntimeRef::parse(STOCK_RUNTIME).unwrap(),
                &node_triple(),
                yah_mesofact_bundle::SERVE_BIN,
                yah_mesofact_bundle::IMPLEMENTED_CONTRACTS,
                &bin,
            )
            .unwrap();
        }

        /// The dogfood shape end to end: a bundle carrying **no binary at all**
        /// deploys and runs, because the node fetched the runtime it named.
        /// Before R746-F1 this bundle assembled fine and then had nothing to
        /// exec, which is why yah-marketing was pinned to `runtime = "self"`.
        #[tokio::test]
        async fn a_vanilla_bundle_serves_from_the_shared_runtime_asset() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_vanilla_bundle(store.as_ref(), "<html>home</html>");
            publish_stock_runtime(store.as_ref());

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                .with_bind_port(0);
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(150),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload_with_runtime(
                        &digest,
                        STOCK_RUNTIME,
                        BundleLifecycle::KeepAlive,
                        Some(0),
                    ),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");
            await_deploy_ok(&ctx, "yah-marketing").await;

            // The asset landed at the namespaced node path, outside bundles/.
            let asset = cache
                .path()
                .join("runtimes/mesofact/0.8.20")
                .join(node_triple())
                .join("serve");
            assert!(asset.is_file(), "expected the runtime asset at {}", asset.display());
            // …and the bundle itself carries no binary, which is the point.
            let bundle_dir = cache.path().join("bundles").join(&digest);
            assert!(bundle_dir.join("app/index.html").is_file());
            assert!(!bundle_dir.join("bins").exists(), "a vanilla bundle carries no bins/");

            let _ = handle_message(
                YubabaToKamaji::Stop {
                    request_id: RequestId(151),
                    id: WorkloadId::new("yah-marketing"),
                },
                &ctx,
            )
            .await;
        }

        /// Verify #1 — the whole reason the vanilla shape exists. Two sites at
        /// one runtime version on one node fetch the serve binary **once**; a
        /// per-bundle copy would be the self-contained shape wearing a different
        /// manifest.
        #[tokio::test]
        async fn two_vanilla_bundles_at_one_version_fetch_the_runtime_once() {
            /// Counts GETs of the runtime-asset blob, the ~70MB object the
            /// sharing claim is about.
            struct CountingStore {
                inner: InMemoryObjectStore,
                runtime_blob: std::sync::Mutex<Option<String>>,
                blob_gets: std::sync::atomic::AtomicUsize,
            }
            impl ObjectStore for CountingStore {
                fn put(&self, key: &str, data: Vec<u8>) -> Result<(), yah_object_store::Error> {
                    self.inner.put(key, data)
                }
                fn get(&self, key: &str) -> Result<Option<Vec<u8>>, yah_object_store::Error> {
                    if self.runtime_blob.lock().unwrap().as_deref() == Some(key) {
                        self.blob_gets
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    self.inner.get(key)
                }
                fn delete(&self, key: &str) -> Result<(), yah_object_store::Error> {
                    self.inner.delete(key)
                }
                fn list_prefix(&self, p: &str) -> Result<Vec<String>, yah_object_store::Error> {
                    self.inner.list_prefix(p)
                }
            }

            let counting = Arc::new(CountingStore {
                inner: InMemoryObjectStore::new(),
                runtime_blob: std::sync::Mutex::new(None),
                blob_gets: std::sync::atomic::AtomicUsize::new(0),
            });
            let store: Arc<dyn ObjectStore> = Arc::clone(&counting) as Arc<dyn ObjectStore>;

            let a = publish_vanilla_bundle(store.as_ref(), "<html>site a</html>");
            let b = publish_vanilla_bundle(store.as_ref(), "<html>site b</html>");
            assert_ne!(a, b, "two sites must be two digests");
            publish_stock_runtime(store.as_ref());
            // Learn the runtime blob's key so only its reads are counted.
            let rref = yah_mesofact_bundle::RuntimeRef::parse(STOCK_RUNTIME).unwrap();
            let asset_manifest = store
                .get(&rref.asset_manifest_key(&node_triple()))
                .unwrap()
                .unwrap();
            let parsed = yah_mesofact_bundle::RuntimeAssetManifest::from_toml_str(
                &String::from_utf8(asset_manifest).unwrap(),
            )
            .unwrap();
            *counting.runtime_blob.lock().unwrap() =
                Some(yah_mesofact_bundle::blob_key(&parsed.serve));

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                .with_bind_port(0);
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            for (n, (id, digest)) in [("site-a", &a), ("site-b", &b)].into_iter().enumerate() {
                let reply = handle_message(
                    YubabaToKamaji::Deploy {
                        request_id: RequestId(160 + n as u64),
                        id: WorkloadId::new(id),
                        spec: serve_bundle_workload_with_runtime(
                            digest,
                            STOCK_RUNTIME,
                            BundleLifecycle::KeepAlive,
                            Some(0),
                        ),
                        mesh: None,
                    },
                    &ctx,
                )
                .await;
                assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");
                await_deploy_ok(&ctx, id).await;
            }

            assert_eq!(
                counting.blob_gets.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "the second site at the same runtime version must hit the node cache"
            );

            for (n, id) in ["site-a", "site-b"].into_iter().enumerate() {
                let _ = handle_message(
                    YubabaToKamaji::Stop {
                        request_id: RequestId(170 + n as u64),
                        id: WorkloadId::new(id),
                    },
                    &ctx,
                )
                .await;
            }
        }

        /// Verify #2 — a runtime version the node cannot fetch fails the deploy
        /// loudly, naming the version and where it looked, and falls back to
        /// nothing. Silently serving with some other binary on the box is the
        /// failure this must never have.
        #[tokio::test]
        async fn an_unfetchable_runtime_version_fails_naming_version_and_location() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_vanilla_bundle(store.as_ref(), "<html>home</html>");
            // Deliberately NOT publishing the runtime asset.

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path());
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(180),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload_with_runtime(
                        &digest,
                        STOCK_RUNTIME,
                        BundleLifecycle::KeepAlive,
                        Some(0),
                    ),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");

            let (state, detail) = await_deploy(&ctx, "yah-marketing").await;
            assert_eq!(state, WorkloadState::Failed);
            let message = detail.expect("a failed deploy must carry its reason");
            assert!(message.contains("mesofact/0.8.20"), "got: {message}");
            assert!(message.contains(&node_triple()), "got: {message}");
            assert!(
                message.contains("runtimes/mesofact/0.8.20/"),
                "the message must name what it looked for, got: {message}"
            );
        }

        // ── R870-B6: the bundle's store travels with the workload ────────────

        /// Point a bundle workload at the store it was published to.
        fn with_bundle_origin(spec: Workload, origin: &str) -> Workload {
            let Workload::MesofactStatic(mut w) = spec else {
                unreachable!("serve_bundle_workload_with_runtime builds a MesofactStatic")
            };
            w.serve_bundle
                .as_mut()
                .expect("a bundle workload carries a serve_bundle")
                .origin = Some(origin.to_string());
            Workload::MesofactStatic(w)
        }

        /// Serve `store` over a throwaway HTTP/1.1 origin on loopback — the
        /// shape an R2 custom domain presents to a node — and return its URL.
        ///
        /// Real HTTP rather than an injected `ObjectStore` on purpose: the
        /// thing under test is that a *URL on the wire* reaches
        /// `HttpReadOnlyObjectStore` and is what the fetch actually goes to. A
        /// test that handed the backend a second in-memory store would pass
        /// with the URL ignored, which is the bug.
        async fn serve_store_over_http(store: Arc<dyn ObjectStore>) -> String {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let store = Arc::clone(&store);
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 8192];
                        let read = match sock.read(&mut buf).await {
                            Ok(n) if n > 0 => n,
                            _ => return,
                        };
                        let head = String::from_utf8_lossy(&buf[..read]).into_owned();
                        let mut request = head.split_whitespace();
                        let method = request.next().unwrap_or_default().to_string();
                        let key = request
                            .next()
                            .unwrap_or("/")
                            .trim_start_matches('/')
                            .to_string();
                        // The store is sync; keep it off the runtime thread.
                        let found = tokio::task::spawn_blocking(move || store.get(&key))
                            .await
                            .unwrap()
                            .unwrap();
                        let mut out = match &found {
                            Some(bytes) => format!(
                                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                                bytes.len()
                            )
                            .into_bytes(),
                            None => b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\
                                      connection: close\r\n\r\n"
                                .to_vec(),
                        };
                        if method != "HEAD" {
                            out.extend(found.unwrap_or_default());
                        }
                        let _ = sock.write_all(&out).await;
                        let _ = sock.flush().await;
                    });
                }
            });
            format!("http://{addr}")
        }

        /// THE noisetable case, end to end. A second tenant publishes its
        /// bundle to its **own** store; the node's store holds the fleet's
        /// stock serve runtime and nothing of the tenant's. Both halves have to
        /// resolve for the deploy to come up: the manifest and blobs from the
        /// tenant's origin, the ~70MB runtime it did not republish from the
        /// node's.
        #[tokio::test]
        async fn a_second_tenants_bundle_materializes_from_its_own_origin() {
            let tenant: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_vanilla_bundle(tenant.as_ref(), "<html>noisetable</html>");

            // The node's own store — the fleet's, holding no tenant object.
            let node: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            publish_stock_runtime(node.as_ref());

            let origin = serve_store_over_http(Arc::clone(&tenant)).await;
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(
                BundleBackend::new(Arc::clone(&node), cache.path(), state.path())
                    .with_bind_port(0),
            ));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(190),
                    id: WorkloadId::new("noisetable-marketing"),
                    spec: with_bundle_origin(
                        serve_bundle_workload_with_runtime(
                            &digest,
                            STOCK_RUNTIME,
                            BundleLifecycle::KeepAlive,
                            Some(0),
                        ),
                        &origin,
                    ),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");
            await_deploy_ok(&ctx, "noisetable-marketing").await;

            // The tenant's content came from the tenant's origin…
            assert!(cache
                .path()
                .join("bundles")
                .join(&digest)
                .join("app/index.html")
                .is_file());
            // …and the stock runtime read through to the node's store, which is
            // the only place it was ever published.
            assert!(cache
                .path()
                .join("runtimes/mesofact/0.8.20")
                .join(node_triple())
                .join("serve")
                .is_file());

            let _ = handle_message(
                YubabaToKamaji::Stop {
                    request_id: RequestId(191),
                    id: WorkloadId::new("noisetable-marketing"),
                },
                &ctx,
            )
            .await;
        }

        /// The negative control for the test above, and the reported bug
        /// verbatim: the same tenant bundle with no `origin` on the wire is
        /// admitted and then cannot be materialized, because the node looks in
        /// its own store for a digest only the tenant's holds.
        #[tokio::test]
        async fn without_an_origin_a_tenant_bundle_fails_after_a_clean_admission() {
            let tenant: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_vanilla_bundle(tenant.as_ref(), "<html>noisetable</html>");
            let node: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            publish_stock_runtime(node.as_ref());

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(
                BundleBackend::new(Arc::clone(&node), cache.path(), state.path())
                    .with_bind_port(0),
            ));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(192),
                    id: WorkloadId::new("noisetable-marketing"),
                    spec: serve_bundle_workload_with_runtime(
                        &digest,
                        STOCK_RUNTIME,
                        BundleLifecycle::KeepAlive,
                        Some(0),
                    ),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");

            let (state, detail) = await_deploy(&ctx, "noisetable-marketing").await;
            assert_eq!(state, WorkloadState::Failed);
            let message = detail.expect("a failed deploy must carry its reason");
            assert!(message.contains(&digest), "got: {message}");
        }

        /// The node-wide origin is not *replaced* by a declared one, and a
        /// workload that declares none does not pay for the mechanism: it gets
        /// the node's store itself, with no second lookup behind it.
        #[tokio::test]
        async fn an_undeclared_origin_resolves_to_the_node_store_unchanged() {
            let node: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            node.put("blobs/x", b"node".to_vec()).unwrap();
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&node), cache.path(), state.path());

            let plain = backend.store_for(None).await.unwrap();
            assert!(
                Arc::ptr_eq(&plain, &node),
                "an undeclared origin must be the node's own store, not a wrapper"
            );

            // A tenant origin that holds nothing — the shape of a tenant that
            // published its site but not the stock runtime.
            let empty: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let origin = serve_store_over_http(empty).await;
            let chained = backend.store_for(Some(&origin)).await.unwrap();
            let looked = chained.locate("blobs/x");
            assert!(
                looked.contains(&format!("{origin}/blobs/x")),
                "the declared origin is where it looks first: {looked}"
            );
            // The node's store stays reachable behind it — this is what lets a
            // tenant fork the stock runtime it never republished. Off the
            // runtime thread: the origin above is served by a task on it.
            let read = tokio::task::spawn_blocking(move || chained.get("blobs/x"))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(read.unwrap(), b"node".to_vec());
        }

        // ── R844-F2: automatic port allocation + the resolved-port return ──

        /// THE motivating case, end to end through the real Deploy handler.
        /// Two bundles, one node, NEITHER declaring a port: both come up, on
        /// distinct ports, and `List` reports each one's actual port back to
        /// yubaba.
        ///
        /// Before this ticket the second deploy landed on the same node-wide
        /// 8080 as the first, and `List` reported no port at all — so even when
        /// the bind happened to work there was no way for the ingress renderer
        /// to learn where to send traffic.
        #[tokio::test]
        async fn two_undeclared_bundles_co_tenant_a_node_on_distinct_reported_ports() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            // No `.with_bind_port(...)`: this is the fleet's actual shape once
            // the mirror stops naming a port, and the case the old code could
            // not serve twice.
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(BundleBackend::new(
                Arc::clone(&store),
                cache.path(),
                state.path(),
            )));

            for (rid, id) in [(1_844u64, "yah-marketing"), (1_845, "noisetable-com")] {
                let reply = handle_message(
                    YubabaToKamaji::Deploy {
                        request_id: RequestId(rid),
                        id: WorkloadId::new(id),
                        spec: serve_bundle_workload_on_port(
                            &digest,
                            BundleLifecycle::KeepAlive,
                            None,
                        ),
                        mesh: None,
                    },
                    &ctx,
                )
                .await;
                assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");
                await_deploy_ok(&ctx, id).await;
            }

            let entries = match handle_message(
                YubabaToKamaji::List {
                    request_id: RequestId(1_846),
                },
                &ctx,
            )
            .await
            {
                KamajiToYubaba::WorkloadList { entries, .. } => entries,
                other => panic!("expected WorkloadList, got {other:?}"),
            };

            let port_of = |id: &str| -> u16 {
                let e = entries
                    .iter()
                    .find(|e| e.id == WorkloadId::new(id))
                    .unwrap_or_else(|| panic!("{id} missing from List: {entries:?}"));
                assert_eq!(e.state, WorkloadState::Running, "{id} is not Running");
                assert_eq!(
                    e.ports.len(),
                    1,
                    "{id} must report exactly the one port it bound, got {:?}",
                    e.ports
                );
                e.ports[0]
            };

            let marketing = port_of("yah-marketing");
            let noisetable = port_of("noisetable-com");
            assert_ne!(marketing, 0, "an unresolved :0 is not a reportable port");
            assert_ne!(
                marketing, noisetable,
                "co-tenants must not be handed the same port"
            );
            assert_ne!(
                marketing, DEFAULT_BUNDLE_PORT,
                "allocation must not fall back to the well-known port this ticket removes"
            );
        }

        /// R844-F14, the reversal of R844-F2's "declared always wins": a bundle
        /// that declares a NUMBER now fails its deploy, naming the port, rather
        /// than binding it.
        ///
        /// The number in a mirror's `[providers.bundle] port` is either stale or
        /// a co-tenancy collision waiting on this node — measured live on
        /// us-east-001, where yah-marketing-revalidate and yah-marketing-feed
        /// both sat on 8081. A refused deploy is visible; a second binder aimed
        /// at a held socket is not.
        #[tokio::test]
        async fn a_declared_port_now_fails_the_deploy_naming_the_port() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(BundleBackend::new(
                Arc::clone(&store),
                cache.path(),
                state.path(),
            )));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(1_847),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload_on_port(
                        &digest,
                        BundleLifecycle::KeepAlive,
                        Some(8080),
                    ),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");

            let (state, detail) = await_deploy(&ctx, "yah-marketing").await;
            assert_eq!(state, WorkloadState::Failed);
            let message = detail.expect("a failed deploy must carry its reason");
            assert!(
                message.contains("8080") && message.contains("\"http\""),
                "the refusal must name the number AND the port it was written \
                 for, got: {message}"
            );
        }

        /// The same bundle with no number deploys and reports back an allocated
        /// port — R599-F12's case under the new shape (the workload that used to
        /// declare `serve_bundle.port` still lands on a live listener).
        #[tokio::test]
        async fn a_bundle_that_declares_no_number_lands_on_a_live_listener() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(BundleBackend::new(
                Arc::clone(&store),
                cache.path(),
                state.path(),
            )));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(1_847),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload_on_port(&digest, BundleLifecycle::KeepAlive, None),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");
            await_deploy_ok(&ctx, "yah-marketing").await;

            let entries = match handle_message(
                YubabaToKamaji::List {
                    request_id: RequestId(1_848),
                },
                &ctx,
            )
            .await
            {
                KamajiToYubaba::WorkloadList { entries, .. } => entries,
                other => panic!("expected WorkloadList, got {other:?}"),
            };
            let e = entries
                .iter()
                .find(|e| e.id == WorkloadId::new("yah-marketing"))
                .expect("deployed bundle must be listed");
            assert_eq!(e.ports.len(), 1, "one listener, one reported port");
            let port = e.ports[0];
            assert_ne!(port, 0, "an unresolved :0 is not a reportable port");
            // The number the node reports is the number the ledger remembers
            // for this workload's `http` port — one value, one path.
            assert_eq!(
                ctx.bundle
                    .as_ref()
                    .unwrap()
                    .ports
                    .reserved_port("yah-marketing", kamaji::ports::HTTP),
                Some(port)
            );
        }

        /// An allocated port is STABLE across a kamaji restart. A keep-alive
        /// bundle whose port moved would leave the ingress upstream rendered
        /// from the first run naming a dead listener — which still reads as
        /// healthy, so nothing detects it.
        #[tokio::test]
        async fn an_allocated_port_survives_a_kamaji_restart() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();

            let listed_port = |ctx: &Arc<ServerCtx>| {
                let ctx = Arc::clone(ctx);
                async move {
                    match handle_message(
                        YubabaToKamaji::List {
                            request_id: RequestId(1_849),
                        },
                        &ctx,
                    )
                    .await
                    {
                        KamajiToYubaba::WorkloadList { entries, .. } => entries
                            .iter()
                            .find(|e| e.id == WorkloadId::new("yah-marketing"))
                            .unwrap_or_else(|| panic!("not listed: {entries:?}"))
                            .ports
                            .clone(),
                        other => panic!("expected WorkloadList, got {other:?}"),
                    }
                }
            };

            let first = Arc::new(ServerCtx::new().with_bundle_backend(BundleBackend::new(
                Arc::clone(&store),
                cache.path(),
                state.path(),
            )));
            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(1_850),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload_on_port(&digest, BundleLifecycle::KeepAlive, None),
                    mesh: None,
                },
                &first,
            )
            .await;
            assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");
            await_deploy_ok(&first, "yah-marketing").await;
            let before = listed_port(&first).await;
            assert_eq!(before.len(), 1);

            // Systemd stops kamaji: children are killed, the process goes away.
            first
                .bundle
                .as_ref()
                .unwrap()
                .native
                .teardown_workload(&workload_spec::MeshIdent("yah-marketing".into()))
                .await
                .unwrap();
            drop(first);

            // The restarted daemon replays its deploy record — and must give
            // the workload back the port the ledger remembers, not a new one.
            let second = Arc::new(ServerCtx::new().with_bundle_backend(BundleBackend::new(
                Arc::clone(&store),
                cache.path(),
                state.path(),
            )));
            assert_eq!(second.resume_bundle_workloads().await, 1);
            await_deploy_ok(&second, "yah-marketing").await;
            assert_eq!(
                listed_port(&second).await,
                before,
                "a resumed keep-alive bundle must come back on the same port"
            );
        }

        /// The `--bundle-port` / `KAMAJI_BUNDLE_PORT` node-wide override is a
        /// written-down number like any other, and R844-F14 rejects it.
        ///
        /// R844-F2 had kept it as "the operator may pin and then owns the
        /// collision". Option B (operator, 2026-09-03) says automatic and an
        /// honoured operator number are mutually exclusive — and a NODE-WIDE
        /// number is the worst of the two, since it aims every bundle on the
        /// node at one port. It still reaches the allocator, so the refusal
        /// names it instead of ignoring it.
        #[test]
        fn an_explicit_node_override_is_refused_rather_than_honoured() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let state = tempfile::tempdir().unwrap();
            let cache = tempfile::tempdir().unwrap();
            let pinned = BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                .with_bind_port(9100);
            let bundle = workload_spec::MesofactServeBundle {
                digest: workload_spec::BlakeHash("0".repeat(64)),
                runtime: "self".into(),
                lifecycle: BundleLifecycle::KeepAlive,
                port: None,
                env: Default::default(),
                origin: None,
            };
            assert_eq!(pinned.declared_pin(&bundle), Some(9100));
            let err = pinned
                .resolve_port(
                    "yah-marketing",
                    std::net::Ipv4Addr::LOCALHOST,
                    pinned.http_spec(&bundle),
                )
                .expect_err("a node-wide pin must not resolve");
            assert!(err.contains("9100") && err.contains("\"http\""), "got: {err}");

            // And with nothing written down, allocation takes over — no 8080.
            let unpinned = BundleBackend::new(store, cache.path(), state.path());
            assert_eq!(
                unpinned.declared_pin(&bundle),
                None,
                "unset must mean allocate, not DEFAULT_BUNDLE_PORT"
            );
            let port = unpinned
                .resolve_port(
                    "yah-marketing",
                    std::net::Ipv4Addr::LOCALHOST,
                    unpinned.http_spec(&bundle),
                )
                .unwrap();
            assert_ne!(port, 0);
            assert_ne!(port, DEFAULT_BUNDLE_PORT);
        }

        /// R746-F6, the node-side backstop. A bundle requiring a contract
        /// version the published runtime does not advertise fails the deploy
        /// naming BOTH versions — rather than forking a binary that would
        /// misread the tree and fail somewhere downstream, which is the failure
        /// mode the versioned contract exists to make impossible.
        ///
        /// `yah cloud apply` refuses this pair before it ever reaches a node.
        /// This is what catches the paths that don't go through an apply: a
        /// workload deployed before the gate existed being restarted, or a
        /// hand-rolled deploy.
        #[tokio::test]
        async fn a_runtime_that_does_not_implement_the_bundles_contract_fails_the_deploy() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            // A bundle from a future tree: it requires a contract version this
            // runtime does not implement.
            let future_contract = yah_mesofact_bundle::BUNDLE_CONTRACT_VERSION + 1;
            let digest = publish_vanilla_bundle_requiring(
                store.as_ref(),
                "<html>home</html>",
                future_contract,
            );
            publish_stock_runtime(store.as_ref());

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path());
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(185),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload_with_runtime(
                        &digest,
                        STOCK_RUNTIME,
                        BundleLifecycle::KeepAlive,
                        Some(0),
                    ),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");

            let (state, detail) = await_deploy(&ctx, "yah-marketing").await;
            assert_eq!(state, WorkloadState::Failed);
            let message = detail.expect("a failed deploy must carry its reason");
            assert!(message.contains(STOCK_RUNTIME), "got: {message}");
            assert!(
                message.contains(&future_contract.to_string())
                    && message
                        .contains(&yah_mesofact_bundle::BUNDLE_CONTRACT_VERSION.to_string()),
                "the refusal must name both contract versions, got: {message}"
            );
            // Nothing was forked and nothing was left forkable.
            assert!(
                !cache
                    .path()
                    .join("runtimes/mesofact/0.8.20")
                    .join(node_triple())
                    .join("serve")
                    .exists(),
                "a refused deploy must not leave a runtime binary in the cache"
            );
        }

        /// A runtime selector that is neither `self` nor a resolvable reference
        /// is rejected with the shapes it could have been.
        #[tokio::test]
        async fn an_unparseable_runtime_selector_is_rejected() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_vanilla_bundle(store.as_ref(), "<html>home</html>");
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path());
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let _ = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(190),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload_with_runtime(
                        &digest,
                        "caddy",
                        BundleLifecycle::KeepAlive,
                        Some(0),
                    ),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            let (state, detail) = await_deploy(&ctx, "yah-marketing").await;
            assert_eq!(state, WorkloadState::Failed);
            let message = detail.unwrap();
            assert!(message.contains("caddy"), "got: {message}");
        }

        // ── R330-F33: the deploy is asynchronous ─────────────────────────────

        /// An [`ObjectStore`] that stalls every read, standing in for the cold
        /// R2 fetch of a bundle carrying a 71MB serve binary.
        struct SlowStore {
            inner: Arc<dyn ObjectStore>,
            delay: std::time::Duration,
        }

        impl ObjectStore for SlowStore {
            fn put(&self, key: &str, data: Vec<u8>) -> Result<(), yah_object_store::Error> {
                self.inner.put(key, data)
            }
            fn get(&self, key: &str) -> Result<Option<Vec<u8>>, yah_object_store::Error> {
                std::thread::sleep(self.delay);
                self.inner.get(key)
            }
            fn delete(&self, key: &str) -> Result<(), yah_object_store::Error> {
                self.inner.delete(key)
            }
            fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, yah_object_store::Error> {
                self.inner.list_prefix(prefix)
            }
        }

        /// The headline of R330-F33, and the reason the wire version moved to
        /// V3: `Ack { Deploy }` now means *admitted*, and comes back while the
        /// node is still fetching blobs.
        ///
        /// This is what stops `yah cloud apply` reporting `operation timed out`
        /// for a deploy that then succeeds on the node — the client is no
        /// longer holding a request open across an unbounded materialize.
        #[tokio::test]
        async fn a_bundle_deploy_acks_before_it_has_materialized() {
            let inner: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(inner.as_ref(), true);
            let store: Arc<dyn ObjectStore> = Arc::new(SlowStore {
                inner,
                delay: std::time::Duration::from_millis(200),
            });
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(store, cache.path(), state.path());
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let started = std::time::Instant::now();
            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(201),
                    id: WorkloadId::new("slow-site"),
                    spec: serve_bundle_workload(&digest, BundleLifecycle::KeepAlive),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            let ack_took = started.elapsed();

            assert!(
                matches!(reply, KamajiToYubaba::Ack { .. }),
                "expected an admission Ack, got {reply:?}"
            );
            // The bundle has at least two objects to fetch, so a synchronous
            // deploy could not possibly have returned inside one delay.
            assert!(
                ack_took < std::time::Duration::from_millis(200),
                "Deploy blocked for {ack_took:?} — it is still materializing synchronously"
            );

            // And it really was still in flight, not merely fast.
            let in_flight = handle_message(
                YubabaToKamaji::DeployStatus {
                    request_id: RequestId(202),
                    id: WorkloadId::new("slow-site"),
                },
                &ctx,
            )
            .await;
            match in_flight {
                KamajiToYubaba::DeployStatusResult { state, .. } => assert!(
                    matches!(state, WorkloadState::Pending | WorkloadState::Starting),
                    "expected an in-flight state, got {state:?}"
                ),
                other => panic!("expected DeployStatusResult, got {other:?}"),
            }

            await_deploy_ok(&ctx, "slow-site").await;
            let _ = handle_message(
                YubabaToKamaji::Stop {
                    request_id: RequestId(203),
                    id: WorkloadId::new("slow-site"),
                },
                &ctx,
            )
            .await;
        }

        /// Polling a workload this kamaji never admitted must be
        /// distinguishable from one whose deploy is still `Pending` — a caller
        /// polling in a loop otherwise waits forever on a typo.
        #[tokio::test]
        async fn deploy_status_for_an_unknown_workload_is_an_error_not_a_state() {
            let ctx = Arc::new(ServerCtx::new());
            let reply = handle_message(
                YubabaToKamaji::DeployStatus {
                    request_id: RequestId(210),
                    id: WorkloadId::new("never-deployed"),
                },
                &ctx,
            )
            .await;
            match reply {
                KamajiToYubaba::Error { code, message, .. } => {
                    assert_eq!(code, ErrorCode::UnknownWorkload);
                    assert!(message.contains("never-deployed"), "got {message}");
                }
                other => panic!("expected UnknownWorkload, got {other:?}"),
            }
        }

        /// Stopping a workload drops its deploy record, so the terminal
        /// `Running` its deploy ended on can't outlive the process.
        #[tokio::test]
        async fn stopping_a_workload_clears_its_deploy_status() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path());
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(220),
                    id: WorkloadId::new("transient"),
                    spec: serve_bundle_workload(&digest, BundleLifecycle::KeepAlive),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            await_deploy_ok(&ctx, "transient").await;

            handle_message(
                YubabaToKamaji::Stop {
                    request_id: RequestId(221),
                    id: WorkloadId::new("transient"),
                },
                &ctx,
            )
            .await;

            let reply = handle_message(
                YubabaToKamaji::DeployStatus {
                    request_id: RequestId(222),
                    id: WorkloadId::new("transient"),
                },
                &ctx,
            )
            .await;
            assert!(
                matches!(
                    reply,
                    KamajiToYubaba::Error {
                        code: ErrorCode::UnknownWorkload,
                        ..
                    }
                ),
                "a stopped workload must not still report Running, got {reply:?}"
            );
        }

        /// (a) A KeepAlive serve_bundle deploy reaches the native runtime,
        /// returns Ack (no longer BackendRefused), and appears in List.
        #[tokio::test]
        async fn keepalive_deploy_forks_and_appears_in_list() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path());
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(101),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload(&digest, BundleLifecycle::KeepAlive),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            match reply {
                KamajiToYubaba::Ack { request_id, kind } => {
                    assert_eq!(request_id, RequestId(101));
                    assert_eq!(kind, kamaji_proto::AckKind::Deploy);
                }
                other => panic!("expected Ack, got {other:?}"),
            }
            // R330-F33: the Ack is admission; the fork happens after it.
            await_deploy_ok(&ctx, "yah-marketing").await;

            // The forked bundle shows up in List via the native-runtime merge.
            let list = handle_message(
                YubabaToKamaji::List {
                    request_id: RequestId(102),
                },
                &ctx,
            )
            .await;
            match list {
                KamajiToYubaba::WorkloadList { entries, .. } => {
                    assert!(
                        entries.iter().any(|e| e.id == WorkloadId::new("yah-marketing")),
                        "served bundle should appear in List, got {entries:?}"
                    );
                }
                other => panic!("expected WorkloadList, got {other:?}"),
            }

            // Clean up the supervised child.
            let _ = handle_message(
                YubabaToKamaji::Stop {
                    request_id: RequestId(103),
                    id: WorkloadId::new("yah-marketing"),
                },
                &ctx,
            )
            .await;
        }

        /// R755-B5: the roll that took passway-test.yah.dev down. Deploy under
        /// one kamaji, throw that kamaji away (the child dies with it under
        /// systemd; here we just drop the ctx), build a fresh ctx over the SAME
        /// state dir — which is what a restarted daemon is — and the workload
        /// must come back through `resume_bundle_workloads` with no Deploy.
        #[tokio::test]
        async fn a_recorded_keepalive_bundle_is_resumed_by_a_fresh_kamaji() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();

            let first = Arc::new(
                ServerCtx::new().with_bundle_backend(
                    BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                        .with_bind_port(0),
                ),
            );
            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(160),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload(&digest, BundleLifecycle::KeepAlive),
                    mesh: None,
                },
                &first,
            )
            .await;
            assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");
            await_deploy_ok(&first, "yah-marketing").await;
            let record = state.path().join("deploys/yah-marketing.json");
            assert!(record.is_file(), "admission must leave a record at {}", record.display());
            // R876-B9: the record is the admission input, secrets included, so
            // the real Deploy path must land it owner-only. Asserted here as
            // well as in the focused test below because this is the only test
            // that goes through `handle_message` — a regression that only
            // tightened `record_deploy`'s direct callers would pass there.
            assert_eq!(mode_of(&record), 0o600, "deploy record must be 0600");
            assert_eq!(
                mode_of(&state.path().join("deploys")),
                0o700,
                "deploy records dir must be 0700"
            );
            // Kill the first daemon's child the way systemd would, so the
            // resumed one is provably a NEW fork and not the survivor.
            first
                .bundle
                .as_ref()
                .unwrap()
                .native
                .teardown_workload(&workload_spec::MeshIdent("yah-marketing".into()))
                .await
                .unwrap();
            drop(first);

            // The restarted daemon.
            let second = Arc::new(
                ServerCtx::new().with_bundle_backend(
                    BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                        .with_bind_port(0),
                ),
            );
            assert_eq!(second.resume_bundle_workloads().await, 1);
            await_deploy_ok(&second, "yah-marketing").await;
            let list = handle_message(
                YubabaToKamaji::List {
                    request_id: RequestId(161),
                },
                &second,
            )
            .await;
            match list {
                KamajiToYubaba::WorkloadList { entries, .. } => assert!(
                    entries.iter().any(|e| e.id == WorkloadId::new("yah-marketing")
                        && e.state == WorkloadState::Running),
                    "resumed bundle should be Running in List, got {entries:?}"
                ),
                other => panic!("expected WorkloadList, got {other:?}"),
            }

            // Stop forgets the record, so a THIRD daemon resumes nothing.
            let _ = handle_message(
                YubabaToKamaji::Stop {
                    request_id: RequestId(162),
                    id: WorkloadId::new("yah-marketing"),
                },
                &second,
            )
            .await;
            assert!(!record.exists(), "Stop must remove the deploy record");
            let third = Arc::new(
                ServerCtx::new().with_bundle_backend(BundleBackend::new(
                    Arc::clone(&store),
                    cache.path(),
                    state.path(),
                )),
            );
            assert_eq!(third.resume_bundle_workloads().await, 0);
        }

        /// A corrupt record must not take every other site down with it.
        #[tokio::test]
        async fn an_unreadable_record_is_skipped_not_fatal() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(state.path().join("deploys")).unwrap();
            std::fs::write(state.path().join("deploys/broken.json"), b"{not json").unwrap();
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(BundleBackend::new(
                Arc::clone(&store),
                cache.path(),
                state.path(),
            )));
            assert_eq!(ctx.resume_bundle_workloads().await, 0);
        }

        /// Permission bits of `p`, minus the file-type bits.
        fn mode_of(p: &std::path::Path) -> u32 {
            std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
        }

        /// R876-B9. A deploy record is the admission input *verbatim*, and for
        /// any bundle with a revalidate tier that includes cleartext
        /// credentials — on us-east-001 a `CLOUDFLARE_API_TOKEN` and two
        /// `MESOFACT_S3_*` keys, measured 0644 in a 0755 dir, readable by every
        /// local account on a multi-tenant box.
        ///
        /// Three things are asserted together because the fix is only worth
        /// anything if all three hold: the mode is right, an *already loose*
        /// dir and a stale tmp are tightened rather than trusted, and
        /// `recorded_deploys` (the restart-replay reader, running as root) can
        /// still read what was written. The last one is the trade this fix must
        /// not make — a disclosure bug swapped for an availability bug.
        #[test]
        fn a_deploy_record_is_written_owner_only_and_still_replays() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();

            // Pre-create the state an older kamaji leaves behind: a 0755 dir
            // and a world-readable tmp from a crash mid-write. `.mode()` on
            // OpenOptions does nothing when the file already exists, so this is
            // the case that makes the explicit chmod load-bearing.
            let dir = state.path().join("deploys");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let stale = dir.join(".yah-marketing.json.tmp");
            std::fs::write(&stale, b"stale").unwrap();
            std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o644)).unwrap();

            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path());
            let record = BundleDeployRecord {
                id: "yah-marketing".to_string(),
                bundle: MesofactServeBundle {
                    digest: BlakeHash("a".repeat(64)),
                    runtime: "self".to_string(),
                    lifecycle: BundleLifecycle::KeepAlive,
                    port: None,
                    env: Default::default(),
                    origin: None,
                },
                revalidate: None,
                mesh: None,
            };
            backend.record_deploy(&record).unwrap();

            let written = dir.join("yah-marketing.json");
            assert_eq!(mode_of(&written), 0o600, "record must be 0600, not 0644");
            assert_eq!(mode_of(&dir), 0o700, "a pre-existing 0755 dir must be tightened");
            assert!(!stale.exists(), "the tmp is renamed onto the final path, not left behind");

            // Restart-replay still works: same bytes back out.
            assert_eq!(backend.recorded_deploys(), vec![record.clone()]);

            // And a second write over an existing 0600 record keeps it 0600
            // (`.mode()` alone would not, since it does not create the tmp).
            backend.record_deploy(&record).unwrap();
            assert_eq!(mode_of(&written), 0o600);
            assert_eq!(mode_of(&dir), 0o700);
        }

        /// (a1) R330-F12: the receiver's argv must match `mesofact serve`'s
        /// actual clap shape. `ServeArgs::workload` is a **positional**
        /// `Option<PathBuf>` — an earlier draft emitted `--workload <app>`,
        /// which clap rejects as an unexpected argument, so the forked receiver
        /// would have exited instantly while the fork itself still "succeeded".
        /// The fork/List test above can't catch that (its stub serve bin ignores
        /// argv), so assert the argv literally.
        #[test]
        fn revalidate_spec_argv_matches_mesofact_serve_clap_shape() {
            use workload_spec::MesofactRevalidateReceiver;

            let mut env = BTreeMap::new();
            env.insert("MESOFACT_MIRROR_KEY".to_string(), "bearer-xyz".to_string());
            env.insert(
                "MESOFACT_S3_ACCESS_KEY_ID".to_string(),
                "AKIA".to_string(),
            );
            let receiver = MesofactRevalidateReceiver {
                routes: vec!["/releases".into()],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: Some("YAH_MARKETING_MIRROR_KEY".into()),
                env,
                feeds: vec![],
                feed_interval_secs: 300,
                feed_project_prefix: None,
                feed_runtime: None,
            };

            let spec = bundle_workload_spec_revalidate(
                &WorkloadId::new("yah-marketing-revalidate"),
                Path::new("/opt/yah/bin/mesofact"),
                Path::new("/var/cache/yah/bundles/abc"),
                "127.0.0.1:3001",
                &receiver,
            );

            assert_eq!(
                spec.command.as_deref(),
                Some(
                    [
                        // `serve` SUBCOMMAND first. This test used to pin the
                        // flat form and stayed green while the real binary
                        // rejected it — the staged binary is mesofact's
                        // consolidated prod binary (`mesofact serve|proxy|
                        // publish`, W174), not the retired flat
                        // `mesofact-serve`. Measured on us-east-001: the flat
                        // form exits with "unexpected argument '--bundle'
                        // found" before binding, which surfaces only as a
                        // workload stuck in `Starting` with no pid (R330-F37).
                        "serve",
                        // positional workload — NOT `--workload`
                        "/var/cache/yah/bundles/abc/app",
                        "--revalidate",
                        "--publish-config",
                        "/var/cache/yah/bundles/abc/app/mesofact.config.toml",
                        "--listen",
                        "127.0.0.1:3001",
                        // The declared allowlist, one flag per route (yah
                        // R752-B7). This assertion is the whole point: the
                        // field was parsed, shipped and dropped here for as
                        // long as it existed, and this test declared
                        // `routes = ["/releases"]` while pinning an argv that
                        // never mentioned it — green the entire time.
                        "--allow-route",
                        "/releases",
                    ]
                    .map(String::from)
                    .as_slice()
                ),
            );
            assert_eq!(
                spec.entrypoint.as_deref(),
                Some(["/opt/yah/bin/mesofact".to_string()].as_slice()),
            );
            // Creds + bearer ride the child's env, resolved deploy-side; the
            // node never sees keystore slot names.
            let names: Vec<&str> = spec.env.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(names, ["MESOFACT_MIRROR_KEY", "MESOFACT_S3_ACCESS_KEY_ID"]);
            assert!(matches!(
                spec.restart_policy,
                workload_spec::RestartPolicy::Always
            ));
        }

        /// R556-T12: the STATIC/SSR serve process carries its declared env.
        ///
        /// This is the assertion whose absence was the bug. The receiver test
        /// above pinned an env-carrying child and stayed green for as long as
        /// the field existed, while the serve process next to it was forked
        /// with a hard-coded `env: vec![]` — so a `mode: "ssr"` route reading a
        /// private source deployed clean and 500'd on every request, on a
        /// machine nobody is watching.
        #[test]
        fn serve_spec_carries_the_deploy_resolved_env() {
            let mut env = BTreeMap::new();
            env.insert("ANALYTICS_R2_ACCESS_KEY".to_string(), "AKIA".to_string());
            env.insert("ANALYTICS_R2_SECRET_KEY".to_string(), "s3cret".to_string());

            let spec = bundle_workload_spec(
                &WorkloadId::new("yah-analytics"),
                Path::new("/opt/yah/bin/mesofact"),
                Path::new("/var/cache/yah/bundles/abc"),
                "100.64.0.3:8081",
                &env,
            );

            let pairs: Vec<(&str, &str)> = spec
                .env
                .iter()
                .map(|e| {
                    (
                        e.name.as_str(),
                        match &e.value {
                            workload_spec::EnvValue::Literal { value } => value.as_str(),
                            // Values are resolved deploy-side by design: a
                            // node that had to resolve one would need the
                            // operator's vault, which is the whole thing this
                            // contract avoids.
                            other => panic!("expected a literal, got {other:?}"),
                        },
                    )
                })
                .collect();
            assert_eq!(
                pairs,
                [
                    ("ANALYTICS_R2_ACCESS_KEY", "AKIA"),
                    ("ANALYTICS_R2_SECRET_KEY", "s3cret"),
                ],
            );
        }

        /// The JIT half of the same contract. An on-demand bundle forks on the
        /// first *connection*, so an env dropped here would surface as a 500 to
        /// a visitor rather than as a failed deploy — strictly harder to notice
        /// than the keep-alive case.
        #[test]
        fn jit_serve_spec_carries_the_deploy_resolved_env() {
            let mut env = BTreeMap::new();
            env.insert("ANALYTICS_R2_ACCESS_KEY".to_string(), "AKIA".to_string());

            let spec = bundle_workload_spec_jit(
                &WorkloadId::new("yah-analytics"),
                Path::new("/opt/yah/bin/mesofact"),
                Path::new("/var/cache/yah/bundles/abc"),
                "100.64.0.3:8081",
                60,
                &env,
            );

            let names: Vec<&str> = spec.env.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(names, ["ANALYTICS_R2_ACCESS_KEY"]);
        }

        /// The feed tier reads the receiver's bearer under its OWN name and
        /// takes nothing else from the receiver's env — an R2 credential
        /// belongs to the process that publishes, not to the one that pokes it.
        /// Pinned because R556-T12 turned that projection from a post-hoc
        /// `spec.env = …` overwrite into an argument, and an argument is easy
        /// to widen by accident.
        #[test]
        fn feed_tier_spec_takes_only_the_bearer_from_the_receiver_env() {
            use workload_spec::MesofactRevalidateReceiver;

            let mut env = BTreeMap::new();
            env.insert("MESOFACT_MIRROR_KEY".to_string(), "bearer-xyz".to_string());
            env.insert(
                "MESOFACT_S3_SECRET_ACCESS_KEY".to_string(),
                "s3cret".to_string(),
            );
            let receiver = MesofactRevalidateReceiver {
                routes: vec![],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: Some("YAH_MARKETING_MIRROR_KEY".into()),
                env,
                feeds: vec![],
                feed_interval_secs: 300,
                feed_project_prefix: None,
                feed_runtime: None,
            };

            let spec = bundle_workload_spec_feed_tier(
                &WorkloadId::new("yah-marketing-feed"),
                Path::new("/var/cache/yah/bundles/abc/bins/x/almanac-feed"),
                Path::new("/var/cache/yah/bundles/abc"),
                "127.0.0.1:3001",
                &receiver,
            );

            let names: Vec<&str> = spec.env.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(names, ["ALMANAC_MIRROR_KEY"]);
        }

        /// yah R752-B7, the other half: an empty `routes` list is the config's
        /// documented "every route" case, so it must emit NO flag rather than an
        /// empty-valued one — `--allow-route ""` would scope the receiver to a
        /// route that cannot exist and silently stop every revalidation.
        #[test]
        fn revalidate_spec_omits_allow_route_when_no_allowlist_is_declared() {
            use workload_spec::MesofactRevalidateReceiver;

            let receiver = MesofactRevalidateReceiver {
                routes: vec![],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: None,
                env: BTreeMap::new(),
                feeds: vec![],
                feed_interval_secs: 300,
                feed_project_prefix: None,
                feed_runtime: None,
            };

            let spec = bundle_workload_spec_revalidate(
                &WorkloadId::new("yah-marketing-revalidate"),
                Path::new("/opt/yah/bin/mesofact"),
                Path::new("/var/cache/yah/bundles/abc"),
                "127.0.0.1:3001",
                &receiver,
            );

            let argv = spec.command.expect("receiver spec always carries argv");
            assert!(
                !argv.iter().any(|a| a == "--allow-route"),
                "an empty allowlist must leave the receiver unrestricted, got {argv:?}"
            );
        }

        /// Two declared routes emit two flag pairs, in declaration order — clap
        /// collects a repeated `--allow-route` into the Vec the receiver reads.
        #[test]
        fn revalidate_spec_emits_one_allow_route_flag_per_declared_route() {
            use workload_spec::MesofactRevalidateReceiver;

            let receiver = MesofactRevalidateReceiver {
                routes: vec!["/releases".into(), "/issues".into()],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: None,
                env: BTreeMap::new(),
                feeds: vec![],
                feed_interval_secs: 300,
                feed_project_prefix: None,
                feed_runtime: None,
            };

            let spec = bundle_workload_spec_revalidate(
                &WorkloadId::new("yah-marketing-revalidate"),
                Path::new("/opt/yah/bin/mesofact"),
                Path::new("/var/cache/yah/bundles/abc"),
                "127.0.0.1:3001",
                &receiver,
            );

            let argv = spec.command.expect("receiver spec always carries argv");
            let tail: Vec<&str> = argv
                .iter()
                .skip_while(|a| a.as_str() != "--allow-route")
                .map(String::as_str)
                .collect();
            assert_eq!(
                tail,
                ["--allow-route", "/releases", "--allow-route", "/issues"],
                "allowlist flags trail the fixed argv in declaration order",
            );
        }

        /// R330-F31: the feed tier's argv must match `almanac-feed`'s own flag
        /// shape, and each feed definition must travel **by value** — the node
        /// has no copy of the camp's `.yah/almanac/` tree, so a path would
        /// resolve to nothing and the fetcher would exit at startup.
        #[test]
        fn feed_tier_spec_argv_carries_feeds_by_value_and_keeps_the_bearer_off_argv() {
            use workload_spec::{AlmanacFeed, MesofactRevalidateReceiver};

            let feed_toml = "[feed]\nname = \"releases\"\n";
            let mut env = BTreeMap::new();
            env.insert("MESOFACT_MIRROR_KEY".to_string(), "bearer-xyz".to_string());
            env.insert("MESOFACT_S3_ACCESS_KEY_ID".to_string(), "AKIA".to_string());
            let receiver = MesofactRevalidateReceiver {
                routes: vec!["/releases".into()],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: Some("YAH_MARKETING_MIRROR_KEY".into()),
                env,
                feeds: vec![AlmanacFeed {
                    name: "releases".into(),
                    config_toml: feed_toml.into(),
                }],
                feed_interval_secs: 60,
                feed_project_prefix: Some("app/yah/web/marketing".into()),
                feed_runtime: None,
            };

            let spec = bundle_workload_spec_feed_tier(
                &WorkloadId::new("yah-marketing-feed"),
                Path::new("/var/cache/yah/bundles/abc/bins/x/almanac-feed"),
                Path::new("/var/cache/yah/bundles/abc"),
                "127.0.0.1:3001",
                &receiver,
            );

            assert_eq!(
                spec.command.as_deref(),
                Some(
                    [
                        "--project-root",
                        // The workload root the receiver resolves `data_inputs`
                        // against — writing anywhere else is a no-op poke.
                        "/var/cache/yah/bundles/abc/app",
                        "--receiver",
                        "http://127.0.0.1:3001",
                        "--interval-secs",
                        "60",
                        // Without this the artifact lands at the feed's
                        // workspace-relative path inside the bundle, where the
                        // route's `data_inputs` never looks.
                        "--project-prefix",
                        "app/yah/web/marketing",
                        "--feed",
                        feed_toml,
                    ]
                    .map(String::from)
                    .as_slice()
                ),
            );
            assert_eq!(
                spec.entrypoint.as_deref(),
                Some(["/var/cache/yah/bundles/abc/bins/x/almanac-feed".to_string()].as_slice()),
            );
            // The bearer rides env under the name the fetcher reads — never
            // argv, which is world-readable in `ps`.
            let env: Vec<(&str, &str)> = spec
                .env
                .iter()
                .map(|e| {
                    let workload_spec::EnvValue::Literal { value } = &e.value else {
                        panic!("expected a literal env value")
                    };
                    (e.name.as_str(), value.as_str())
                })
                .collect();
            assert_eq!(env, [("ALMANAC_MIRROR_KEY", "bearer-xyz")]);
            assert!(
                !spec.command.as_deref().unwrap().iter().any(|a| a.contains("bearer-xyz")),
                "the bearer must not appear in argv"
            );
            // Resident: a fetcher that exits stops the site's data forever.
            assert!(matches!(
                spec.restart_policy,
                workload_spec::RestartPolicy::Always
            ));
        }

        /// R844-B9: the feed tier is a pure CLIENT of the receiver — it binds
        /// nothing — so it must declare no mesh port, while the receiver it
        /// pokes declares serve+1. Both halves are asserted from the one
        /// `receiver_listen` string that used to give them the same number:
        /// asserting only the empty side cannot tell "cleared" from "the
        /// archetype never set a port at all".
        ///
        /// Measured live before the fix (us-east-001, kamaji 0.8.30): `GET
        /// /workloads` reported yah-marketing-revalidate and yah-marketing-feed
        /// both on 8081. `expose.mesh.ports` is the one place a serving port is
        /// declared, so that made the fetcher look dialable on an address
        /// belonging to the revalidation receiver.
        #[test]
        fn feed_tier_declares_no_mesh_port_while_the_receiver_declares_serve_plus_one() {
            use workload_spec::MesofactRevalidateReceiver;

            let serve_port = 8080u16;
            // R844-F14: the receiver's port is allocated under its own ident
            // now, so this is just *a* listen address the spec was built from —
            // what is under test is which spec declares it on `expose.mesh`.
            let receiver_listen = format!("127.0.0.1:{}", serve_port + 1);
            let receiver = MesofactRevalidateReceiver {
                routes: vec![],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: None,
                env: BTreeMap::new(),
                feeds: vec![],
                feed_interval_secs: 300,
                feed_project_prefix: None,
                feed_runtime: None,
            };

            let receiver_spec = bundle_workload_spec_revalidate(
                &WorkloadId::new("yah-marketing-revalidate"),
                Path::new("/opt/yah/bin/mesofact"),
                Path::new("/var/cache/yah/bundles/abc"),
                &receiver_listen,
                &receiver,
            );
            let feed_spec = bundle_workload_spec_feed_tier(
                &WorkloadId::new("yah-marketing-feed"),
                Path::new("/var/cache/yah/bundles/abc/bins/x/almanac-feed"),
                Path::new("/var/cache/yah/bundles/abc"),
                &receiver_listen,
                &receiver,
            );

            assert_eq!(
                receiver_spec.expose.mesh.numbers(),
                vec![serve_port + 1],
                "the receiver binds serve+1 and must declare it",
            );
            assert!(
                feed_spec.expose.mesh.ports.is_empty(),
                "the feed tier binds nothing, got {:?}",
                feed_spec.expose.mesh.ports,
            );
            // …and it still pokes the receiver at that address.
            assert!(
                feed_spec
                    .command
                    .as_deref()
                    .expect("feed spec always carries argv")
                    .contains(&format!("http://{receiver_listen}")),
                "clearing the expose must not disturb the poke target",
            );
        }

        /// R330-F31: declaring feeds without staging the `almanac-feed` sidecar
        /// is the failure that looks like success — the site serves, the data
        /// never moves. The deploy must refuse instead.
        #[tokio::test]
        async fn a_declared_feed_tier_without_its_sidecar_binary_fails_the_deploy() {
            use workload_spec::{AlmanacFeed, MesofactRevalidateReceiver};

            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            // Carries `serve` but NOT `almanac-feed` — the mis-declared shape.
            let digest = publish_self_bundle(store.as_ref(), true);
            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                .with_bind_port(0);
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let mut env = BTreeMap::new();
            env.insert("MESOFACT_MIRROR_KEY".to_string(), "bearer-xyz".to_string());
            let receiver = MesofactRevalidateReceiver {
                routes: vec!["/releases".into()],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: None,
                env,
                feeds: vec![AlmanacFeed {
                    name: "releases".into(),
                    config_toml: "[feed]\nname = \"releases\"\n".into(),
                }],
                feed_interval_secs: 60,
                feed_project_prefix: None,
                feed_runtime: None,
            };
            let spec = match serve_bundle_workload(&digest, BundleLifecycle::KeepAlive) {
                Workload::MesofactStatic(mut w) => {
                    w.revalidate_receiver = Some(receiver);
                    Workload::MesofactStatic(w)
                }
                other => other,
            };

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(141),
                    id: WorkloadId::new("yah-marketing"),
                    spec,
                    mesh: None,
                },
                &ctx,
            )
            .await;
            // R330-F33: a missing sidecar is only discoverable once the bundle
            // has been materialized, so it can no longer fail the Deploy —
            // it fails the deploy's *poll*, with the same message.
            assert!(
                matches!(reply, KamajiToYubaba::Ack { .. }),
                "expected admission Ack, got {reply:?}"
            );
            let (state, detail) = await_deploy(&ctx, "yah-marketing").await;
            assert_eq!(state, WorkloadState::Failed);
            let message = detail.expect("a failed deploy must carry its reason");
            assert!(message.contains("almanac-feed"), "got {message}");
            assert!(message.contains("feed_bins"), "got {message}");
        }

        /// R330-F31: a bundle carrying the `almanac-feed` sidecar forks a THIRD
        /// resident process under `<id>-feed`, alongside the static server and
        /// the receiver. Its own row is the point — "serving but frozen" has to
        /// be visible in `List`/`Stop`.
        #[tokio::test]
        async fn keepalive_deploy_with_feeds_forks_the_fetch_tier_as_a_third_process() {
            use workload_spec::{AlmanacFeed, MesofactRevalidateReceiver};

            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle_with_bins(store.as_ref(), true, &["almanac-feed"]);

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                .with_bind_port(0);
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let receiver = MesofactRevalidateReceiver {
                routes: vec!["/releases".into()],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: None,
                env: BTreeMap::new(),
                feeds: vec![AlmanacFeed {
                    name: "releases".into(),
                    config_toml: "[feed]\nname = \"releases\"\n".into(),
                }],
                feed_interval_secs: 60,
                feed_project_prefix: None,
                feed_runtime: None,
            };
            let spec = match serve_bundle_workload(&digest, BundleLifecycle::KeepAlive) {
                Workload::MesofactStatic(mut w) => {
                    w.revalidate_receiver = Some(receiver);
                    Workload::MesofactStatic(w)
                }
                other => other,
            };

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(151),
                    id: WorkloadId::new("yah-marketing"),
                    spec,
                    mesh: None,
                },
                &ctx,
            )
            .await;
            assert!(
                matches!(reply, KamajiToYubaba::Ack { .. }),
                "deploy should Ack, got {reply:?}"
            );
            await_deploy_ok(&ctx, "yah-marketing").await;

            let list = handle_message(
                YubabaToKamaji::List {
                    request_id: RequestId(152),
                },
                &ctx,
            )
            .await;
            match list {
                KamajiToYubaba::WorkloadList { entries, .. } => {
                    for expected in ["yah-marketing", "yah-marketing-revalidate", "yah-marketing-feed"]
                    {
                        assert!(
                            entries.iter().any(|e| e.id == WorkloadId::new(expected)),
                            "{expected} should appear in List, got {entries:?}"
                        );
                    }
                }
                other => panic!("expected WorkloadList, got {other:?}"),
            }
        }

        /// R746-T3, and the last thing standing between yah.dev and a
        /// toolchain-free deploy: a **vanilla** bundle with a feed tier. It
        /// carries no `bins/` at all, so both the serve runtime AND the
        /// `almanac-feed` fetcher resolve from the node's shared asset cache.
        /// Before this, a feed tier forced the self-contained shape, which
        /// meant a cross-built musl binary had to exist on whichever machine
        /// pressed Sync.
        #[tokio::test]
        async fn a_vanilla_bundle_resolves_its_feed_fetcher_as_a_node_asset() {
            use workload_spec::{AlmanacFeed, MesofactRevalidateReceiver};

            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_vanilla_bundle(store.as_ref(), "<html>vanilla+feeds</html>");
            publish_stock_runtime(store.as_ref());
            publish_feed_runtime(store.as_ref());

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                .with_bind_port(0);
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let receiver = MesofactRevalidateReceiver {
                routes: vec!["/releases".into()],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: None,
                env: BTreeMap::new(),
                feeds: vec![AlmanacFeed {
                    name: "releases".into(),
                    config_toml: "[feed]\nname = \"releases\"\n".into(),
                }],
                feed_interval_secs: 60,
                feed_project_prefix: None,
                feed_runtime: Some(FEED_RUNTIME.to_string()),
            };
            let spec = match serve_bundle_workload_with_runtime(
                &digest,
                STOCK_RUNTIME,
                BundleLifecycle::KeepAlive,
                Some(0),
            ) {
                Workload::MesofactStatic(mut w) => {
                    w.revalidate_receiver = Some(receiver);
                    Workload::MesofactStatic(w)
                }
                other => other,
            };

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(160),
                    id: WorkloadId::new("yah-marketing"),
                    spec,
                    mesh: None,
                },
                &ctx,
            )
            .await;
            assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");
            await_deploy_ok(&ctx, "yah-marketing").await;

            // All three tiers forked, from a bundle that carries no binary.
            let list = handle_message(
                YubabaToKamaji::List {
                    request_id: RequestId(161),
                },
                &ctx,
            )
            .await;
            match list {
                KamajiToYubaba::WorkloadList { entries, .. } => {
                    for expected in [
                        "yah-marketing",
                        "yah-marketing-revalidate",
                        "yah-marketing-feed",
                    ] {
                        assert!(
                            entries.iter().any(|e| e.id == WorkloadId::new(expected)),
                            "{expected} should appear in List, got {entries:?}"
                        );
                    }
                }
                other => panic!("expected WorkloadList, got {other:?}"),
            }

            // The fetcher came from the node asset tier, not from the bundle.
            let feed_asset = cache
                .path()
                .join("runtimes/almanac-feed/0.8.22")
                .join(node_triple())
                .join("almanac-feed");
            assert!(
                feed_asset.is_file(),
                "expected the fetcher at {}",
                feed_asset.display()
            );
            assert!(
                !cache.path().join("bundles").join(&digest).join("bins").exists(),
                "a vanilla bundle carries no bins/, feed tier or not"
            );

            let _ = handle_message(
                YubabaToKamaji::Stop {
                    request_id: RequestId(162),
                    id: WorkloadId::new("yah-marketing"),
                },
                &ctx,
            )
            .await;
        }

        /// Same no-silent-staleness discipline the sidecar path has: a feed
        /// tier whose fetcher cannot be resolved fails the deploy naming what
        /// it looked for, rather than serving a site whose data is frozen.
        #[tokio::test]
        async fn a_vanilla_feed_tier_with_no_published_fetcher_fails_the_deploy() {
            use workload_spec::{AlmanacFeed, MesofactRevalidateReceiver};

            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_vanilla_bundle(store.as_ref(), "<html>no fetcher</html>");
            publish_stock_runtime(store.as_ref());
            // …but NOT publish_feed_runtime.

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                .with_bind_port(0);
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let receiver = MesofactRevalidateReceiver {
                routes: vec![],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: None,
                env: BTreeMap::new(),
                feeds: vec![AlmanacFeed {
                    name: "releases".into(),
                    config_toml: "[feed]\nname = \"releases\"\n".into(),
                }],
                feed_interval_secs: 60,
                feed_project_prefix: None,
                feed_runtime: Some("almanac-feed/9.9.9".to_string()),
            };
            let spec = match serve_bundle_workload_with_runtime(
                &digest,
                STOCK_RUNTIME,
                BundleLifecycle::KeepAlive,
                Some(0),
            ) {
                Workload::MesofactStatic(mut w) => {
                    w.revalidate_receiver = Some(receiver);
                    Workload::MesofactStatic(w)
                }
                other => other,
            };

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(163),
                    id: WorkloadId::new("yah-marketing"),
                    spec,
                    mesh: None,
                },
                &ctx,
            )
            .await;
            assert!(matches!(reply, KamajiToYubaba::Ack { .. }), "got {reply:?}");
            let (state, detail) = await_deploy(&ctx, "yah-marketing").await;
            assert_eq!(state, WorkloadState::Failed);
            let message = detail.expect("a failed deploy must carry its reason");
            assert!(message.contains("almanac-feed/9.9.9"), "got {message}");
            assert!(
                message.contains("runtimes/almanac-feed/9.9.9"),
                "the message must name what it looked for, got {message}"
            );

            let _ = handle_message(
                YubabaToKamaji::Stop {
                    request_id: RequestId(164),
                    id: WorkloadId::new("yah-marketing"),
                },
                &ctx,
            )
            .await;
        }

        /// (a2) R330-F12: a KeepAlive deploy whose spec carries a
        /// `revalidate_receiver` forks a SECOND resident process — `mesofact
        /// serve --revalidate` — registered under `<id>-revalidate`, alongside
        /// the static server. Both appear in List. (The stub serve bin sleeps and
        /// ignores argv, so this exercises the *fork/registration* plumbing, not
        /// the receiver's runtime behavior, which mesofact's own tests cover.)
        #[tokio::test]
        async fn keepalive_deploy_with_receiver_forks_both_processes() {
            use workload_spec::MesofactRevalidateReceiver;

            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            // Ephemeral bind port ⇒ the receiver's port (bind_port==0) is also
            // ephemeral, so neither child contends on a fixed port.
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                .with_bind_port(0);
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let mut env = BTreeMap::new();
            env.insert("MESOFACT_MIRROR_KEY".to_string(), "bearer-xyz".to_string());
            let receiver = MesofactRevalidateReceiver {
                routes: vec!["/releases".into()],
                publish_config: "mesofact.config.toml".into(),
                mirror_key_env: Some("YAH_MARKETING_MIRROR_KEY".into()),
                env,
                feeds: vec![],
                feed_interval_secs: 300,
                feed_project_prefix: None,
                feed_runtime: None,
            };
            let spec = match serve_bundle_workload(&digest, BundleLifecycle::KeepAlive) {
                Workload::MesofactStatic(mut w) => {
                    w.revalidate_receiver = Some(receiver);
                    Workload::MesofactStatic(w)
                }
                other => other,
            };

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(131),
                    id: WorkloadId::new("yah-marketing"),
                    spec,
                    mesh: None,
                },
                &ctx,
            )
            .await;
            match reply {
                KamajiToYubaba::Ack { request_id, kind } => {
                    assert_eq!(request_id, RequestId(131));
                    assert_eq!(kind, kamaji_proto::AckKind::Deploy);
                }
                other => panic!("expected Ack, got {other:?}"),
            }
            await_deploy_ok(&ctx, "yah-marketing").await;

            let list = handle_message(
                YubabaToKamaji::List {
                    request_id: RequestId(132),
                },
                &ctx,
            )
            .await;
            match list {
                KamajiToYubaba::WorkloadList { entries, .. } => {
                    assert!(
                        entries.iter().any(|e| e.id == WorkloadId::new("yah-marketing")),
                        "static server should appear in List, got {entries:?}"
                    );
                    assert!(
                        entries
                            .iter()
                            .any(|e| e.id == WorkloadId::new("yah-marketing-revalidate")),
                        "revalidate receiver should appear in List as a second process, \
                         got {entries:?}"
                    );
                }
                other => panic!("expected WorkloadList, got {other:?}"),
            }

            for wl in ["yah-marketing", "yah-marketing-revalidate"] {
                let _ = handle_message(
                    YubabaToKamaji::Stop {
                        request_id: RequestId(133),
                        id: WorkloadId::new(wl),
                    },
                    &ctx,
                )
                .await;
            }
        }

        /// (b) An OnDemand serve_bundle deploy binds+arms the JIT runtime (R599-F6):
        /// it Acks (no process forked yet — lazy), the workload appears in List as
        /// idle (Pending, no resident pid), and Stop releases it. Uses an ephemeral
        /// bind port so the test never contends on the default 8080.
        #[tokio::test]
        async fn ondemand_deploy_binds_and_appears_in_list_idle() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                .with_bind_port(0);
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(111),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload(
                        &digest,
                        BundleLifecycle::OnDemand {
                            idle_ttl: Millis::from_secs(30),
                        },
                    ),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            match reply {
                KamajiToYubaba::Ack { request_id, kind } => {
                    assert_eq!(request_id, RequestId(111));
                    assert_eq!(kind, kamaji_proto::AckKind::Deploy);
                }
                other => panic!("expected Ack (bound+armed), got {other:?}"),
            }
            await_deploy_ok(&ctx, "yah-marketing").await;

            // The armed on-demand workload appears in List as idle: present, but
            // Pending with no resident pid (zero-resident until first connection).
            let list = handle_message(
                YubabaToKamaji::List {
                    request_id: RequestId(112),
                },
                &ctx,
            )
            .await;
            match list {
                KamajiToYubaba::WorkloadList { entries, .. } => {
                    let e = entries
                        .iter()
                        .find(|e| e.id == WorkloadId::new("yah-marketing"))
                        .unwrap_or_else(|| panic!("on-demand workload should appear in List, got {entries:?}"));
                    assert_eq!(e.state, kamaji_proto::WorkloadState::Pending, "idle ⇒ Pending");
                    assert_eq!(e.pid, None, "no resident pid while idle");
                }
                other => panic!("expected WorkloadList, got {other:?}"),
            }

            // Stop releases the held socket and drops the workload.
            let _ = handle_message(
                YubabaToKamaji::Stop {
                    request_id: RequestId(113),
                    id: WorkloadId::new("yah-marketing"),
                },
                &ctx,
            )
            .await;
        }

        /// (c) A KeepAlive deploy whose bundle lacks the serve runtime asset
        /// surfaces a clear "missing" error rather than a fork failure.
        #[tokio::test]
        async fn missing_runtime_asset_is_a_clear_error() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            // Publish WITHOUT a serve bin → the resolved bins/<triple>/serve is absent.
            let digest = publish_self_bundle(store.as_ref(), false);

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path());
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(121),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload(&digest, BundleLifecycle::KeepAlive),
                    mesh: None,
                },
                &ctx,
            )
            .await;
            match reply {
                KamajiToYubaba::Ack { request_id, .. } => {
                    assert_eq!(request_id, RequestId(121));
                }
                other => panic!("expected admission Ack, got {other:?}"),
            }
            // R330-F33: resolving the serve binary needs the materialized tree,
            // so this is now a failed deploy rather than a refused one. The
            // message an operator has to read is unchanged.
            let (state, detail) = await_deploy(&ctx, "yah-marketing").await;
            assert_eq!(state, WorkloadState::Failed);
            let message = detail.expect("a failed deploy must carry its reason");
            assert!(
                message.contains("serve runtime asset missing"),
                "got: {message}"
            );
        }

        // ── R599-F12: mesh-plane bind + per-workload port ────────────────────

        /// The pair of resolutions the whole ticket reduces to. `native_bind_ip`
        /// is what decides whether a bundle is reachable off-node at all, and
        /// the port fallback is what decides whether a node can host more than
        /// one of them.
        #[test]
        fn bind_address_comes_from_the_assignment_and_the_port_from_the_workload() {
            use std::net::Ipv4Addr;

            // No assignment = no mesh plane on this node (pond, desktop, a
            // yubaba bound to 0.0.0.0). Loopback, exactly as before R599-F12.
            assert_eq!(native_bind_ip(None), Ipv4Addr::LOCALHOST);

            let assigned = kamaji_proto::MeshAssignment {
                mesh_ip: Ipv4Addr::new(100, 64, 0, 3),
                wg_private_key: String::new(),
                wg_listen_port: 0,
                peers: vec![],
                netns_name: None,
            };
            assert_eq!(
                native_bind_ip(Some(&assigned)),
                Ipv4Addr::new(100, 64, 0, 3),
                "a native workload must bind the address yubaba admitted it at — \
                 binding loopback is what made a bundle unreachable from another node",
            );

            // The port half of that address is no longer anyone's to declare
            // (R844-F14) — it comes from the node's ledger, which is what the
            // co-tenancy tests below cover. Two literal `unwrap_or` assertions
            // that used to sit here described the retired node-wide fallback
            // and measured nothing but themselves.
        }

        /// Verify #1's kamaji half: a `Deploy` carrying a mesh assignment makes
        /// the bundle bind that address, observable through the probe target the
        /// keep-alive path registers (the probe must dial what the process
        /// actually bound — dialing loopback for a mesh-bound server would
        /// report a healthy workload as dead).
        #[tokio::test]
        async fn a_mesh_assigned_bundle_binds_the_mesh_address_not_loopback() {
            use std::net::Ipv4Addr;

            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            // R844-F14: nothing declares a number any more, so the assertion is
            // about the *address kamaji resolved* — the IP half is the mesh
            // assignment, the port half comes from the ledger, and the probe
            // target records both verbatim.
            //
            // The ledger is seeded because allocation probes the address the
            // workload will bind, and 100.64.0.3 does not exist on a test
            // machine. A standing reservation is returned WITHOUT re-probing
            // (that is what an on-demand redeploy and a kamaji restart both
            // rely on), so this is the same path the node takes on its second
            // deploy of a workload rather than a test-only shortcut.
            std::fs::write(
                state.path().join(kamaji::ports::LedgerPorts::FILE_NAME),
                br#"{"version":2,"ports":{"yah-marketing":{"http":{"port":8443}}}}"#,
            )
            .unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                .with_bind_port(0);
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(130),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload_on_port(&digest, BundleLifecycle::KeepAlive, None),
                    mesh: Some(kamaji_proto::MeshAssignment {
                        mesh_ip: Ipv4Addr::new(100, 64, 0, 3),
                        wg_private_key: String::new(),
                        wg_listen_port: 0,
                        peers: vec![],
                        netns_name: None,
                    }),
                },
                &ctx,
            )
            .await;
            assert!(
                matches!(reply, KamajiToYubaba::Ack { .. }),
                "expected Ack, got {reply:?}"
            );
            await_deploy_ok(&ctx, "yah-marketing").await;

            let target = ctx
                .registry
                .lock()
                .await
                .probe_target(&WorkloadId::new("yah-marketing"))
                .expect("keep-alive deploy registers a probe target");
            let resolved = ctx
                .bundle
                .as_ref()
                .unwrap()
                .ports
                .reserved_port("yah-marketing", kamaji::ports::HTTP)
                .expect("an undeclared bundle gets a ledger entry");
            assert_eq!(
                target.addr.to_string(),
                format!("100.64.0.3:{resolved}"),
                "the bundle must be dialable at <mesh-ip>:<allocated-port>",
            );

            // The same address is declared on the spec a proxy would read it
            // from — an empty `expose.mesh.ports` means "declares no ports",
            // which is what yubaba's ServiceRecords refuses to publish.
            let spec = bundle_workload_spec(
                &WorkloadId::new("yah-marketing"),
                Path::new("/opt/serve"),
                Path::new("/cache/bundles/abc"),
                "100.64.0.3:8443",
                &Default::default(),
            );
            assert_eq!(spec.expose.mesh.numbers(), vec![8443]);
        }

        /// Verify #3: two bundles on ONE node. Before R599-F12 the port was a
        /// node-wide singleton, so the second deploy would have landed on the
        /// first one's address — which is precisely why passway had to be
        /// co-located with the single bundle a node could hold.
        #[tokio::test]
        async fn two_bundles_on_one_node_get_their_own_ports() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path());
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            // R844-F14: neither bundle names a number — that IS the co-tenancy
            // case now, and the ledger is what keeps the two apart.
            for (rid, name) in [(140, "site-a"), (141, "site-b")] {
                let reply = handle_message(
                    YubabaToKamaji::Deploy {
                        request_id: RequestId(rid),
                        id: WorkloadId::new(name),
                        spec: serve_bundle_workload_on_port(
                            &digest,
                            BundleLifecycle::KeepAlive,
                            None,
                        ),
                        mesh: None,
                    },
                    &ctx,
                )
                .await;
                assert!(
                    matches!(reply, KamajiToYubaba::Ack { .. }),
                    "deploying {name} failed: {reply:?}"
                );
                await_deploy_ok(&ctx, name).await;
            }

            let registry = ctx.registry.lock().await;
            let a = registry
                .probe_target(&WorkloadId::new("site-a"))
                .expect("site-a probe target");
            let b = registry
                .probe_target(&WorkloadId::new("site-b"))
                .expect("site-b probe target");
            assert_eq!(a.addr.ip().to_string(), "127.0.0.1");
            assert_eq!(b.addr.ip().to_string(), "127.0.0.1");
            assert_ne!(a.addr.port(), 0);
            assert_ne!(
                a.addr.port(),
                b.addr.port(),
                "two bundles on one node must be probed at two addresses"
            );
            drop(registry);

            // Both are live and distinct — one node, two bundles.
            let list = handle_message(
                YubabaToKamaji::List {
                    request_id: RequestId(142),
                },
                &ctx,
            )
            .await;
            match list {
                KamajiToYubaba::WorkloadList { entries, .. } => {
                    let ids: Vec<&str> = entries.iter().map(|e| e.id.0.as_str()).collect();
                    assert!(ids.contains(&"site-a"), "got {ids:?}");
                    assert!(ids.contains(&"site-b"), "got {ids:?}");
                }
                other => panic!("expected WorkloadList, got {other:?}"),
            }
        }

        /// Two bundles' revalidate receivers get two ports, and neither
        /// collides with either bundle's static server.
        ///
        /// R844-F14 replaced the `serve + 1` derivation this used to assert:
        /// once every number is allocated, `+1` is an arbitrary port the ledger
        /// may already have promised elsewhere on the node. Each receiver is
        /// its own ident (`<id>-revalidate`) with its own ledger entry, which
        /// is the same disjointness without the arithmetic.
        #[test]
        fn each_bundles_receiver_gets_its_own_allocated_port() {
            use kamaji::ports::{LedgerPorts, PortAllocator, PortSpec, LOOPBACK};

            let dir = tempfile::tempdir().unwrap();
            let ledger = LedgerPorts::open(dir.path());
            let port = |ident: &str| {
                ledger
                    .resolve_one(ident, LOOPBACK, PortSpec::http())
                    .unwrap()
            };
            let ports = [
                port("site-a"),
                port("site-a-revalidate"),
                port("site-b"),
                port("site-b-revalidate"),
            ];
            let mut distinct = ports.to_vec();
            distinct.sort_unstable();
            distinct.dedup();
            assert_eq!(
                distinct.len(),
                ports.len(),
                "two bundles and their receivers must not share a port: {ports:?}"
            );
        }
    }
    /// R852-F1 — the per-tenant passway routing arm.
    ///
    /// Nothing here forks a `passway`: the point under test is the half kamaji
    /// owns, which is that a `Deploy { TenantPassway }` ends with the DECLARED
    /// socket held. `oss/passway/crates/passway/tests/jit_cold_start.rs` proves
    /// the other half (fd-3 adoption, serve, self-reap, re-fork) against the
    /// real binary.
    mod tenant_passway {
        use super::*;
        use workload_spec::{TenantPasswayWorkload, Workload};

        /// A `127.0.0.1` port nobody is using, released before it is returned.
        ///
        /// Racy in principle; in practice the kernel does not hand the same
        /// ephemeral port out twice in the microseconds between drop and
        /// re-bind, and every alternative (a fixed port) is *reliably* flaky on
        /// a machine running a dozen concurrent test binaries.
        fn free_port() -> u16 {
            std::net::TcpListener::bind("127.0.0.1:0")
                .expect("bind an ephemeral port")
                .local_addr()
                .expect("read it back")
                .port()
        }

        fn deploy_msg(listen: &str) -> YubabaToKamaji {
            YubabaToKamaji::Deploy {
                request_id: RequestId(1),
                id: WorkloadId::new("passway.shop.tenant.io"),
                spec: Workload::TenantPassway(TenantPasswayWorkload::cold(
                    "shop.tenant.io",
                    listen,
                )),
                mesh: None,
            }
        }

        /// The whole contract in one test: the Ack means the declared socket is
        /// bound and armed (not that a process is running), and Stop is what
        /// releases it. A passway that is never stopped leaves kamaji holding
        /// the port forever, which the next tenant handed it discovers as a
        /// bind failure.
        #[cfg(feature = "tenant-passway")]
        #[tokio::test]
        async fn deploy_arms_the_declared_socket_and_stop_releases_it() {
            let dir = tempfile::tempdir().expect("temp state dir");
            let ctx = Arc::new(
                ServerCtx::new()
                    .with_tenant_passway(Arc::new(kamaji::jit::JitRuntime::new(dir.path()))),
            );
            let port = free_port();
            let listen = format!("127.0.0.1:{port}");

            let reply = handle_message(deploy_msg(&listen), &ctx).await;
            assert!(
                matches!(
                    reply,
                    KamajiToYubaba::Ack {
                        kind: AckKind::Deploy,
                        ..
                    }
                ),
                "expected a Deploy Ack, got {reply:?}"
            );
            assert!(
                std::net::TcpListener::bind(&listen).is_err(),
                "{listen} must be held by the custodian after the Ack — that IS the Ack"
            );

            // And it is visible as a workload, with no pid: the honest state of
            // something that is armed and zero-resident.
            let listed = handle_message(
                YubabaToKamaji::List {
                    request_id: RequestId(2),
                },
                &ctx,
            )
            .await;
            match listed {
                KamajiToYubaba::WorkloadList { entries, .. } => assert!(
                    entries.iter().any(|e| e.id.0 == "passway.shop.tenant.io"),
                    "an armed passway must appear in List, got {entries:?}"
                ),
                other => panic!("expected WorkloadList, got {other:?}"),
            }

            let stopped = handle_message(
                YubabaToKamaji::Stop {
                    request_id: RequestId(3),
                    id: WorkloadId::new("passway.shop.tenant.io"),
                },
                &ctx,
            )
            .await;
            assert!(
                matches!(stopped, KamajiToYubaba::Ack { .. }),
                "expected a Stop Ack, got {stopped:?}"
            );
            assert!(
                std::net::TcpListener::bind(&listen).is_ok(),
                "Stop must release the held socket, or the port leaks for the node's lifetime"
            );
        }

        /// The listen string is the fd-table key AND the demux backend, so a
        /// hostname is not a "resolve it later" convenience — it is a domain
        /// that resolves, handshakes, and hangs. Refuse it at deploy, where the
        /// error is attributable.
        #[cfg(feature = "tenant-passway")]
        #[tokio::test]
        async fn a_listen_that_is_not_a_socket_address_is_refused_as_invalid_spec() {
            let dir = tempfile::tempdir().expect("temp state dir");
            let ctx = Arc::new(
                ServerCtx::new()
                    .with_tenant_passway(Arc::new(kamaji::jit::JitRuntime::new(dir.path()))),
            );
            match handle_message(deploy_msg("shop.tenant.io:8443"), &ctx).await {
                KamajiToYubaba::Error { code, message, .. } => {
                    assert!(matches!(code, ErrorCode::InvalidSpec), "{message}");
                    assert!(message.contains("host:port"), "{message}");
                }
                other => panic!("expected InvalidSpec, got {other:?}"),
            }
        }

        /// Built with the tier but not started with it: name the flag, don't
        /// silently succeed. The Ack would otherwise claim a socket is armed
        /// when nothing is listening.
        #[cfg(feature = "tenant-passway")]
        #[tokio::test]
        async fn without_the_tier_attached_the_refusal_names_the_flag() {
            let ctx = Arc::new(ServerCtx::new());
            match handle_message(deploy_msg("127.0.0.1:8443"), &ctx).await {
                KamajiToYubaba::Error { code, message, .. } => {
                    assert!(matches!(code, ErrorCode::BackendRefused), "{message}");
                    assert!(message.contains("--tenant-passway-dir"), "{message}");
                }
                other => panic!("expected BackendRefused, got {other:?}"),
            }
        }

        /// R852-B4 — `List` reports what each workload was deployed WITH, so a
        /// reconciler can skip a domain whose declaration has not changed
        /// instead of tearing down and rebinding its socket every sweep.
        ///
        /// Asserted against `kamaji_proto::spec_digest` of the same `Workload`
        /// the caller sent: that equality is the entire contract, and a digest
        /// taken over anything kamaji *derived* (the lowered `WorkloadSpec`,
        /// say) would never match a caller's declaration and would leave the
        /// field looking present while being useless.
        #[cfg(feature = "tenant-passway")]
        #[tokio::test]
        async fn the_list_reports_the_digest_of_the_spec_it_was_deployed_with() {
            let dir = tempfile::tempdir().expect("temp state dir");
            let ctx = Arc::new(
                ServerCtx::new()
                    .with_tenant_passway(Arc::new(kamaji::jit::JitRuntime::new(dir.path()))),
            );
            let listen = format!("127.0.0.1:{}", free_port());
            let declared =
                Workload::TenantPassway(TenantPasswayWorkload::cold("shop.tenant.io", &listen));

            assert!(matches!(
                handle_message(deploy_msg(&listen), &ctx).await,
                KamajiToYubaba::Ack { .. }
            ));

            let entry = list_one(&ctx, "passway.shop.tenant.io").await;
            assert_eq!(
                entry.spec_digest,
                kamaji_proto::spec_digest(&declared),
                "the entry must carry the digest of the caller's own declaration"
            );

            // And a redeploy with a CHANGED declaration moves it — otherwise a
            // caller would compare against the spec before last and skip a
            // deploy that has to happen.
            let moved = format!("127.0.0.1:{}", free_port());
            assert!(matches!(
                handle_message(deploy_msg(&moved), &ctx).await,
                KamajiToYubaba::Ack { .. }
            ));
            let after = list_one(&ctx, "passway.shop.tenant.io").await;
            assert_ne!(after.spec_digest, entry.spec_digest);
            assert_eq!(
                after.spec_digest,
                kamaji_proto::spec_digest(&Workload::TenantPassway(
                    TenantPasswayWorkload::cold("shop.tenant.io", &moved)
                ))
            );

            // Release the port the second deploy is holding.
            let _ = handle_message(
                YubabaToKamaji::Stop {
                    request_id: RequestId(9),
                    id: WorkloadId::new("passway.shop.tenant.io"),
                },
                &ctx,
            )
            .await;
        }

        /// A `Stop` drops the digest with the workload. A record that outlived
        /// what it described is the ONE way this field could cause a *missing*
        /// deploy rather than a redundant one: a caller re-declaring the same
        /// spec would see agreement and skip, while nothing is bound.
        #[cfg(feature = "tenant-passway")]
        #[tokio::test]
        async fn stop_drops_the_digest_so_the_same_spec_is_deployed_again() {
            let dir = tempfile::tempdir().expect("temp state dir");
            let ctx = Arc::new(
                ServerCtx::new()
                    .with_tenant_passway(Arc::new(kamaji::jit::JitRuntime::new(dir.path()))),
            );
            let listen = format!("127.0.0.1:{}", free_port());
            assert!(matches!(
                handle_message(deploy_msg(&listen), &ctx).await,
                KamajiToYubaba::Ack { .. }
            ));
            assert!(list_one(&ctx, "passway.shop.tenant.io").await.spec_digest.is_some());

            assert!(matches!(
                handle_message(
                    YubabaToKamaji::Stop {
                        request_id: RequestId(3),
                        id: WorkloadId::new("passway.shop.tenant.io"),
                    },
                    &ctx,
                )
                .await,
                KamajiToYubaba::Ack { .. }
            ));

            // Nothing is listed any more, so ask the registry directly: would a
            // row for this id still be stamped?
            let mut ghost = vec![WorkloadEntry {
                id: WorkloadId::new("passway.shop.tenant.io"),
                state: kamaji_proto::WorkloadState::Pending,
                pid: None,
                mesh_ident: None,
                ports: Vec::new(),
                named_ports: Default::default(),
                spec_digest: None,
            }];
            ctx.registry.lock().await.stamp_spec_digests(&mut ghost);
            assert_eq!(
                ghost[0].spec_digest, None,
                "a stopped workload's digest must not survive it"
            );
        }

        /// A refused deploy records nothing. Recording on admission rather than
        /// on acceptance would tell the next `List` that a workload kamaji
        /// never took is deployed with the spec that was refused.
        #[cfg(feature = "tenant-passway")]
        #[tokio::test]
        async fn a_refused_deploy_leaves_no_digest_behind() {
            let dir = tempfile::tempdir().expect("temp state dir");
            let ctx = Arc::new(
                ServerCtx::new()
                    .with_tenant_passway(Arc::new(kamaji::jit::JitRuntime::new(dir.path()))),
            );
            // A hostname listen — refused as InvalidSpec by the arm above.
            assert!(matches!(
                handle_message(deploy_msg("shop.tenant.io:8443"), &ctx).await,
                KamajiToYubaba::Error { .. }
            ));
            let mut ghost = vec![WorkloadEntry {
                id: WorkloadId::new("passway.shop.tenant.io"),
                state: kamaji_proto::WorkloadState::Pending,
                pid: None,
                mesh_ident: None,
                ports: Vec::new(),
                named_ports: Default::default(),
                spec_digest: None,
            }];
            ctx.registry.lock().await.stamp_spec_digests(&mut ghost);
            assert_eq!(ghost[0].spec_digest, None);
        }

        /// `List` the workloads and return the one with this id.
        #[cfg(feature = "tenant-passway")]
        async fn list_one(ctx: &Arc<ServerCtx>, id: &str) -> WorkloadEntry {
            match handle_message(
                YubabaToKamaji::List {
                    request_id: RequestId(2),
                },
                ctx,
            )
            .await
            {
                KamajiToYubaba::WorkloadList { entries, .. } => entries
                    .into_iter()
                    .find(|e| e.id.0 == id)
                    .unwrap_or_else(|| panic!("{id} must appear in List")),
                other => panic!("expected WorkloadList, got {other:?}"),
            }
        }

        /// Built WITHOUT the tier: the workload is recognised (not
        /// `InvalidSpec`) and the refusal names the feature — the same
        /// build-aware shape the containerd and bundle arms have, so an
        /// operator can tell "wrong build" from "wrong manifest".
        #[cfg(not(feature = "tenant-passway"))]
        #[tokio::test]
        async fn without_the_feature_the_refusal_names_the_build() {
            let ctx = Arc::new(ServerCtx::new());
            match handle_message(deploy_msg("127.0.0.1:8443"), &ctx).await {
                KamajiToYubaba::Error { code, message, .. } => {
                    assert!(matches!(code, ErrorCode::BackendRefused), "{message}");
                    assert!(message.contains("--features tenant-passway"), "{message}");
                }
                other => panic!("expected BackendRefused, got {other:?}"),
            }
        }
    }
}

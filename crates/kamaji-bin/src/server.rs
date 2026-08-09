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
//! @yah:handoff("FIXED, but the ticket's DIAGNOSIS WAS WRONG — read this before reviewing. The phantom row does NOT come from the registry. Evidence: (1) Registry.workloads is never written anywhere in kamaji-bin (only the field decl + list()'s clone) — the registry contributes ZERO rows to List; insert_probe, the only registry write a bundle deploy makes, touches `probes`, not `workloads`. (2) bundle_state_to_entry ALWAYS sets mesh_ident: Some(..), so it cannot emit the observed mesh_ident:null. (3) containerd.rs list() renders a container that exists with NO TASK as exactly {state: Pending, pid: None} with mesh_ident: labels.get(\"yah.mesh-ident\") → None when unlabelled. That is the observed row byte-for-byte. The phantom is a STALE CONTAINERD CONTAINER named yah-marketing — a leftover of the pre-bundle nginx stand-in — concatenated with the live native bundle row.")
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
    ProtocolVersion, WorkloadEntry, WorkloadId, YubabaToKamaji,
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
pub const CONSTABLE_VERSION: &str = env!("CARGO_PKG_VERSION");

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
    /// Per-workload probe configuration, keyed by workload id. Populated by
    /// the deploy path at admission time; consumed by the Probe RPC handler
    /// (R406-T11). Workloads whose spec carries no `healthcheck` field are
    /// absent here, which the Probe handler maps to [`ProbeStatus::Ready`] —
    /// i.e. "no probe declared ↔ trust the workload's existence".
    probes: HashMap<WorkloadId, ProbeTarget>,
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
    /// stock serve-runtime assets at `<cache_dir>/runtimes/<runtime>/<triple>/serve`.
    pub cache_dir: PathBuf,
    /// LRU byte budget for the bundle cache (0 = unbounded). A fresh
    /// `BundleCache` is constructed per deploy inside `spawn_blocking` (it holds
    /// no in-memory state beyond root+budget — recency is on-disk), so the
    /// blocking materialize never parks the async dispatch loop.
    pub cache_budget: u64,
    /// **Fallback** port for a bundle that declares none — the node-wide
    /// default, overridable via `KAMAJI_BUNDLE_PORT`. Testbed convention
    /// (passway → 8080).
    ///
    /// R599-F12 demoted this from *the* port to the fallback: a bundle now
    /// carries its own `serve_bundle.port`, and while every bundle shared this
    /// one value a node could host exactly one of them.
    pub bind_port: u16,
}

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
        let bind_port = std::env::var("KAMAJI_BUNDLE_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_BUNDLE_PORT);
        let state_dir = state_dir.into();
        Self {
            native: Arc::new(kamaji::native::NativeRuntime::new(state_dir.clone())),
            jit: Arc::new(kamaji::jit::JitRuntime::new(state_dir)),
            store,
            cache_dir: cache_dir.into(),
            cache_budget: 0,
            bind_port,
        }
    }

    /// Override the node-wide fallback port. An explicit operator flag wins
    /// over the `KAMAJI_BUNDLE_PORT` env default picked in [`new`]. A bundle
    /// that declares its own `serve_bundle.port` wins over both (R599-F12).
    ///
    /// [`new`]: BundleBackend::new
    pub fn with_bind_port(mut self, port: u16) -> Self {
        self.bind_port = port;
        self
    }

    /// Override the bundle cache's LRU byte budget (0 = unbounded, the default).
    pub fn with_cache_budget(mut self, budget_bytes: u64) -> Self {
        self.cache_budget = budget_bytes;
        self
    }
}

/// Node-wide fallback port for a bundle that declares no `serve_bundle.port`
/// (R599-F10; demoted to a fallback by R599-F12). Mirrors the 2026-07-06
/// ingress testbed (passway → :8080).
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
            #[cfg(feature = "containerd-integration")]
            containerd: None,
            #[cfg(feature = "bundle-serving")]
            bundle: None,
            #[cfg(feature = "docker-integration")]
            docker: None,
            #[cfg(feature = "native-exec")]
            native: None,
        }
    }

    /// Build a context with the given registry handle — lets tests pre-seed
    /// the registry before dispatch.
    pub fn with_registry(registry: Arc<Mutex<Registry>>) -> Self {
        Self {
            registry,
            log_sink: Arc::new(JournalSender::connect()),
            #[cfg(feature = "containerd-integration")]
            containerd: None,
            #[cfg(feature = "bundle-serving")]
            bundle: None,
            #[cfg(feature = "docker-integration")]
            docker: None,
            #[cfg(feature = "native-exec")]
            native: None,
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
        YubabaToKamaji::List { request_id } => {
            // Start with the in-memory registry entries (native workloads).
            #[allow(unused_mut)]
            let mut entries = ctx.registry.lock().await.list();

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
                        entries.extend(states.into_iter().map(bundle_state_to_entry))
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
                        .map(bundle_state_to_entry),
                );
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
            KamajiToYubaba::WorkloadList {
                request_id,
                entries: dedupe_workload_entries(entries),
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
        } => graceful_upgrade_workload(ctx, request_id, id, spec).await,
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
#[allow(unused_variables)]
async fn deploy_workload(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: WorkloadId,
    spec: workload_spec::Workload,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> KamajiToYubaba {
    match spec {
        workload_spec::Workload::Container(spec) => {
            deploy_container(ctx, request_id, &id, &spec, mesh).await
        }
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
        workload_spec::Workload::Almanac(_) | workload_spec::Workload::StaticAsset(_) => {
            KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::InvalidSpec,
                message: "kamaji dispatches Workload::Container and serve-bundle \
                          mesofact-static; almanac and static-asset live in yubaba's \
                          reconcilers"
                    .to_string(),
            }
        }
    }
}

/// Dispatch a `Workload::Container` to whichever backend this build has
/// configured.
///
/// Three backends can serve a container-shaped workload:
///
/// - **containerd** (R406-T9, `containerd-integration`) — the cloud tier.
/// - **docker/OrbStack** (R626-F1, `docker-integration`) — pond and dev hosts,
///   where the daemon speaks the Docker API rather than containerd's gRPC.
/// - **native fork+exec** (R577-T1, `native-exec`) — checked *first*, and only
///   for a spec carrying [`WorkloadSpec::wants_native_exec`].
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
    if spec.wants_native_exec() {
        return deploy_native_exec(ctx, request_id, id, spec, mesh).await;
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
    feature = "native-exec"
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
/// (self → `<dir>/bins/<triple>/serve`, `mesofact/<ver>` →
/// `<cache>/runtimes/<runtime>/<triple>/serve`):
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
        // Route by lifecycle: keep-alive forks a resident process (R599-F10);
        // on-demand hands the socket to a lazily-forked, idle-reaped process
        // (R599-F6). Both share the materialize + serve-bin-resolution front.
        match &bundle.lifecycle {
            workload_spec::BundleLifecycle::KeepAlive => {
                deploy_bundle_keepalive(ctx, request_id, id, bundle, revalidate, mesh).await
            }
            workload_spec::BundleLifecycle::OnDemand { idle_ttl } => {
                let idle_ttl = *idle_ttl;
                deploy_bundle_on_demand(ctx, request_id, id, bundle, idle_ttl, revalidate, mesh)
                    .await
            }
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

/// Materialize the W272 bundle tree from the node store (R599-F1) and resolve
/// the serve binary path (W272 §2/§3), shared by the keep-alive and on-demand
/// deploy paths. Returns `(bundle_dir, serve_bin)` or, as `Err`, the exact
/// `KamajiToYubaba::Error` to send back.
#[cfg(feature = "bundle-serving")]
async fn materialize_and_resolve_serve(
    backend: &BundleBackend,
    request_id: kamaji_proto::RequestId,
    id: &WorkloadId,
    bundle: &workload_spec::MesofactServeBundle,
) -> std::result::Result<(PathBuf, PathBuf), KamajiToYubaba> {
    let err = |code: ErrorCode, message: String| KamajiToYubaba::Error {
        request_id: Some(request_id),
        code,
        message,
    };

    // 1. Materialize the bundle tree from the node store (R599-F1). The digest is
    //    the content-address; a bad hex shape is a spec error, not a backend one.
    let digest = yah_mesofact_bundle::BundleHash::parse(bundle.digest.0.clone()).map_err(|e| {
        err(
            ErrorCode::InvalidSpec,
            format!("bundle digest {:?} is not a valid blake3: {e}", bundle.digest.0),
        )
    })?;

    // Cache materialize is synchronous fs + object-store I/O (a cold deploy may
    // fetch from R2). Run it on the blocking pool so the dispatch loop isn't
    // parked. A fresh BundleCache is cheap and stateless beyond root+budget.
    let store = Arc::clone(&backend.store);
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
        Ok(Err(e)) => {
            return Err(err(
                ErrorCode::BackendRefused,
                format!("materialize bundle {}: {e}", digest.as_str()),
            ))
        }
        Err(e) => {
            return Err(err(
                ErrorCode::Internal,
                format!("bundle materialize task failed: {e}"),
            ))
        }
    };

    // 2. Resolve the serve binary from the runtime selector (W272 §2/§3).
    let triple = node_triple();
    let serve_bin = if bundle.runtime == "self" {
        // Custom bundle ships its own bins/<triple>/serve inside the tree.
        bundle_dir.join("bins").join(&triple).join("serve")
    } else if let Some(version) = bundle.runtime.strip_prefix("mesofact/") {
        if version.is_empty() {
            return Err(err(
                ErrorCode::InvalidSpec,
                format!("bundle runtime {:?} missing a version after 'mesofact/'", bundle.runtime),
            ));
        }
        // Vanilla bundle resolves the stock serve runtime asset from the node
        // cache: runtimes/mesofact/<ver>/<triple>/serve.
        backend
            .cache_dir
            .join("runtimes")
            .join(&bundle.runtime)
            .join(&triple)
            .join("serve")
    } else {
        return Err(err(
            ErrorCode::InvalidSpec,
            format!(
                "unrecognized bundle runtime {:?} (expected \"self\" or \"mesofact/<version>\")",
                bundle.runtime
            ),
        ));
    };
    if !serve_bin.exists() {
        return Err(err(
            ErrorCode::BackendRefused,
            format!(
                "serve runtime asset missing at {} (triple={triple}, runtime={}): a \"self\" \
                 bundle must ship bins/<triple>/serve; a \"mesofact/<ver>\" bundle needs the \
                 stock runtime asset present in the node runtime cache",
                serve_bin.display(),
                bundle.runtime
            ),
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

/// Keep-alive bundle deploy (R599-F10). Materialize the W272 bundle, resolve the
/// serve binary, and fork it under the native supervisor as a resident process.
/// See [`deploy_mesofact_bundle`] for the Drain caveat.
#[cfg(feature = "bundle-serving")]
async fn deploy_bundle_keepalive(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: &WorkloadId,
    bundle: &workload_spec::MesofactServeBundle,
    revalidate: Option<&workload_spec::MesofactRevalidateReceiver>,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> KamajiToYubaba {
    use std::net::SocketAddr;

    let err = |code: ErrorCode, message: String| KamajiToYubaba::Error {
        request_id: Some(request_id),
        code,
        message,
    };

    let Some(backend) = ctx.bundle.as_ref() else {
        return err(
            ErrorCode::BackendRefused,
            format!(
                "no bundle backend configured on this kamaji instance to serve mesofact bundle \
                 for {} — start kamaji with a node bundle store \
                 (ServerCtx::with_bundle_backend)",
                id.0
            ),
        );
    };

    let (bundle_dir, serve_bin) =
        match materialize_and_resolve_serve(backend, request_id, id, bundle).await {
            Ok(pair) => pair,
            Err(e) => return e,
        };

    // Build the native WorkloadSpec (identity image, entrypoint=[serve_bin],
    // command=[--bundle <dir> --listen <addr>]) and fork it.
    //
    // R599-F12: the bind address is the workload's mesh address when yubaba
    // admitted one, loopback otherwise; the port is the workload's own declared
    // `serve_bundle.port`, falling back to the node-wide default. Those two
    // together are what close R599-F10's follow-up — a mesh-bound listener is
    // reachable from another node, and a per-workload port means the node is no
    // longer limited to the one bundle that fits on 8080.
    let bind_ip = native_bind_ip(mesh);
    let port = bundle.port.unwrap_or(backend.bind_port);
    let listen = format!("{bind_ip}:{port}");
    let spec = bundle_workload_spec(id, &serve_bin, &bundle_dir, &listen);
    let mesh = runtime_mesh(mesh);

    match backend.native.deploy_workload(&spec, &mesh).await {
        Ok(_res) => {
            // Register a probe target so Probe RPCs actually dial the serve
            // process (the only registry state a bundle deploy writes). It must
            // dial the address the process actually bound, not loopback.
            ctx.registry.lock().await.insert_probe(
                id.clone(),
                ProbeTarget {
                    healthcheck: workload_spec::Healthcheck {
                        probe: workload_spec::HealthProbe::TcpConnect { port },
                        interval: workload_spec::Millis::from_ms(1000),
                        timeout: workload_spec::Millis::from_ms(500),
                        initial_delay: workload_spec::Millis::from_ms(0),
                        failure_threshold: 3,
                    },
                    addr: SocketAddr::from((bind_ip, port)),
                },
            );
            // R330-F12: when the mirror declared a revalidate receiver, fork a
            // second resident `mesofact serve --revalidate` process against the
            // same materialized bundle. A fork failure surfaces as an error —
            // the static server stays up (reap it via Stop), but a declared
            // receiver that silently didn't start is the failure to avoid.
            if let Some(rv) = revalidate {
                if let Err(e) =
                    fork_revalidate_receiver(backend, id, &bundle_dir, &serve_bin, rv, bind_ip, port)
                        .await
                {
                    return err(
                        ErrorCode::BackendRefused,
                        format!("mesofact revalidate receiver for {} failed to start: {e}", id.0),
                    );
                }
            }
            KamajiToYubaba::Ack {
                request_id,
                kind: kamaji_proto::AckKind::Deploy,
            }
        }
        Err(e) => err(
            ErrorCode::BackendRefused,
            format!("native fork of mesofact-serve for {} failed: {e:#}", id.0),
        ),
    }
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
async fn deploy_bundle_on_demand(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: &WorkloadId,
    bundle: &workload_spec::MesofactServeBundle,
    idle_ttl: workload_spec::Millis,
    revalidate: Option<&workload_spec::MesofactRevalidateReceiver>,
    mesh: Option<&kamaji_proto::MeshAssignment>,
) -> KamajiToYubaba {
    let err = |code: ErrorCode, message: String| KamajiToYubaba::Error {
        request_id: Some(request_id),
        code,
        message,
    };

    let Some(backend) = ctx.bundle.as_ref() else {
        return err(
            ErrorCode::BackendRefused,
            format!(
                "no bundle backend configured on this kamaji instance to serve mesofact bundle \
                 for {} — start kamaji with a node bundle store \
                 (ServerCtx::with_bundle_backend)",
                id.0
            ),
        );
    };

    let (bundle_dir, serve_bin) =
        match materialize_and_resolve_serve(backend, request_id, id, bundle).await {
            Ok(pair) => pair,
            Err(e) => return e,
        };

    // The serve runtime owns idle detection: pass `--idle-ttl <secs>` and it
    // self-reaps. Round sub-second TTLs up to 1s — a `0` would tell the runtime
    // to never reap, silently turning the serverless workload keep-alive.
    let idle_ttl_secs = idle_ttl.as_ms().div_ceil(1000).max(1);
    // R599-F12: same bind resolution as keep-alive. Here it is the address
    // *kamaji itself* binds and holds as socket custodian, so the mesh address
    // has to be right at deploy time — a JIT bundle that armed on loopback is
    // unreachable off-node for the whole life of the workload.
    let bind_ip = native_bind_ip(mesh);
    let port = bundle.port.unwrap_or(backend.bind_port);
    let listen = format!("{bind_ip}:{port}");
    let spec = bundle_workload_spec_jit(id, &serve_bin, &bundle_dir, &listen, idle_ttl_secs);
    let mesh = runtime_mesh(mesh);

    match backend.jit.deploy_on_demand(&spec, &mesh, &listen).await {
        Ok(()) => {
            // R330-F12: the revalidate receiver is a *resident* process (it must
            // accept pokes at any time), independent of the static server's JIT
            // idle-reaping. Fork it against the same materialized bundle.
            if let Some(rv) = revalidate {
                if let Err(e) =
                    fork_revalidate_receiver(backend, id, &bundle_dir, &serve_bin, rv, bind_ip, port)
                        .await
                {
                    return err(
                        ErrorCode::BackendRefused,
                        format!("mesofact revalidate receiver for {} failed to start: {e}", id.0),
                    );
                }
            }
            KamajiToYubaba::Ack {
                request_id,
                kind: kamaji_proto::AckKind::Deploy,
            }
        }
        Err(e) => err(
            ErrorCode::BackendRefused,
            format!("on-demand bind/arm of mesofact-serve for {} failed: {e:#}", id.0),
        ),
    }
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
        command: Some(vec![
            "--bundle".into(),
            bundle_dir.to_string_lossy().into_owned(),
            "--listen".into(),
            listen.to_string(),
        ]),
        entrypoint: Some(vec![serve_bin.to_string_lossy().into_owned()]),
        workdir: None,
        user: None,
        env: vec![],
        secrets: vec![],
        volumes: vec![],
        resources: ResourceLimits {
            memory_mb: 128,
            cpu_millis: 256,
            ephemeral_storage_mb: 128,
        },
        depends_on: vec![],
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
                ports: listen
                    .rsplit_once(':')
                    .and_then(|(_, p)| p.parse::<u16>().ok())
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
) -> workload_spec::WorkloadSpec {
    use workload_spec::RestartPolicy;
    let mut spec = bundle_workload_spec(id, serve_bin, bundle_dir, listen);
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
/// Bound to the port immediately above the static server's, on the same
/// address, so it never collides with it and so two bundles on one node get
/// two disjoint pairs (R599-F12). `env` (R2 creds + `MESOFACT_MIRROR_KEY`) is resolved deploy-side
/// and set on the child; the node never sees keystore slot names.
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
    serve_port: u16,
) -> std::result::Result<(), String> {
    let rv_port = revalidate_port(serve_port);
    let listen = format!("{bind_ip}:{rv_port}");
    let rv_id = WorkloadId(format!("{}-revalidate", id.0));
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
        fork_feed_tier(backend, id, bundle_dir, &listen, receiver).await?;
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
/// The binary is a bundle sidecar (`bins/<triple>/almanac-feed`, staged by
/// `assemble_self_bundle_with`), so a self-contained bundle stays closed over
/// everything it needs and the node resolves nothing.
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
) -> std::result::Result<(), String> {
    use std::net::Ipv4Addr;

    let triple = node_triple();
    let feed_bin = bundle_dir.join("bins").join(&triple).join(FEED_BIN_NAME);
    if !feed_bin.is_file() {
        return Err(format!(
            "bundle declares {} feed(s) but carries no {}: build it for {triple} and declare it \
             under providers.bundle.revalidate.feed_bins",
            receiver.feeds.len(),
            feed_bin.display(),
        ));
    }

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

/// Port the revalidate receiver binds, given its bundle's serving port
/// (R599-F12).
///
/// It rides the port immediately above the static server's, on the same
/// address, so a bundle occupies one contiguous pair. Deriving it from the
/// *workload's* port rather than the node default is what keeps two bundles on
/// one node from colliding once their static servers have been separated.
///
/// Two edges: `0` is the tests' OS-assigned-ephemeral sentinel and stays
/// ephemeral (rather than binding privileged port 1), and a declared port at
/// the top of the range saturates rather than wrapping into a privileged port.
#[cfg(feature = "bundle-serving")]
fn revalidate_port(serve_port: u16) -> u16 {
    if serve_port == 0 {
        0
    } else {
        serve_port.saturating_add(1)
    }
}

/// Bundle-relative name of the feed-fetch sidecar binary. Mirrors
/// `yah_cloud::reconciler::mesofact_bundle::FEED_BIN_NAME` — kamaji does not
/// depend on the yah-side reconciler, so the two are pinned by the argv-shape
/// test below.
#[cfg(feature = "bundle-serving")]
const FEED_BIN_NAME: &str = "almanac-feed";

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
#[cfg(feature = "bundle-serving")]
fn bundle_workload_spec_feed_tier(
    id: &WorkloadId,
    feed_bin: &Path,
    bundle_dir: &Path,
    receiver_listen: &str,
    receiver: &workload_spec::MesofactRevalidateReceiver,
) -> workload_spec::WorkloadSpec {
    use workload_spec::{EnvValue, EnvVar};

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

    // The fetcher binds nothing, so `listen` is meaningless to it; reuse the
    // bundle archetype for the identity-image/native shape and overwrite argv.
    let mut spec = bundle_workload_spec(id, feed_bin, bundle_dir, receiver_listen);
    spec.command = Some(command);
    spec.env = receiver
        .env
        .get("MESOFACT_MIRROR_KEY")
        .map(|key| {
            vec![EnvVar {
                name: "ALMANAC_MIRROR_KEY".to_string(),
                value: EnvValue::Literal { value: key.clone() },
            }]
        })
        .unwrap_or_default();
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
    use workload_spec::{EnvValue, EnvVar};

    let app = bundle_dir.join("app");
    let publish_config = app.join(&receiver.publish_config);

    let mut spec = bundle_workload_spec(id, serve_bin, bundle_dir, listen);
    spec.command = Some(vec![
        app.to_string_lossy().into_owned(),
        "--revalidate".into(),
        "--publish-config".into(),
        publish_config.to_string_lossy().into_owned(),
        "--listen".into(),
        listen.to_string(),
    ]);
    spec.env = receiver
        .env
        .iter()
        .map(|(name, value)| EnvVar {
            name: name.clone(),
            value: EnvValue::Literal {
                value: value.clone(),
            },
        })
        .collect();
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
                warn!(
                    id = %e.id.0,
                    kept_state = ?kept.state, kept_pid = ?kept.pid,
                    other_state = ?e.state, other_pid = ?e.pid,
                    "duplicate workload id across backends — collapsing to the \
                     most-live row; the losing row is likely a stale record"
                );
                if liveness_rank(&e) > liveness_rank(kept) {
                    *kept = e;
                }
            }
            None => out.push(e),
        }
    }
    out
}

/// Map a native [`kamaji::WorkloadState`] into the wire [`WorkloadEntry`] the
/// `List` RPC returns (R599-F10). `container_id` is `"native-<pid>"`; a `0` pid
/// means no child is currently running (parked between exits).
#[cfg(feature = "bundle-serving")]
fn bundle_state_to_entry(s: kamaji::WorkloadState) -> WorkloadEntry {
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
    // container_id is `native-<pid>` (keep-alive) or `jit-<pid>` (on-demand); a
    // `0` pid means no child is currently running (parked, or idle for JIT).
    let pid = s
        .container_id
        .strip_prefix("native-")
        .or_else(|| s.container_id.strip_prefix("jit-"))
        .and_then(|p| p.parse::<u32>().ok())
        .filter(|p| *p != 0);
    WorkloadEntry {
        id: WorkloadId(s.ident.0.clone()),
        state,
        pid,
        mesh_ident: Some(s.ident.0),
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
        workload_spec::Workload::Container(spec) => {
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
        workload_spec::Workload::MesofactStatic(_)
        | workload_spec::Workload::Almanac(_)
        | workload_spec::Workload::StaticAsset(_) => KamajiToYubaba::Error {
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
#[allow(unused_variables)]
async fn stop_workload(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: WorkloadId,
) -> KamajiToYubaba {
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
        ctx.registry.lock().await.remove_probe(&id);
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
            },
            // The truth, as the native bundle runtime renders it.
            WorkloadEntry {
                id: WorkloadId::new("yah-marketing"),
                state: WireWorkloadState::Running,
                pid: Some(67749),
                mesh_ident: Some("yah-marketing".into()),
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
        };
        let pending = WorkloadEntry {
            id: WorkloadId::new("w"),
            state: WireWorkloadState::Pending,
            pid: None,
            mesh_ident: None,
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
            },
            WorkloadEntry {
                id: WorkloadId::new("w"),
                state: WireWorkloadState::Starting,
                pid: None,
                mesh_ident: None,
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
                command: "bun run build".into(),
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
                command: "bun run build".into(),
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
                spec: workload_spec::Workload::Container(inner),
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
                spec: workload_spec::Workload::Container(inner),
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
                spec: workload_spec::Workload::Container(inner),
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
                spec: workload_spec::Workload::Container(inner),
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

        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(78),
                id: WorkloadId::new("svc"),
                spec: workload_spec::Workload::Container(spec),
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

    /// Without the containerd-integration feature, Deploy { Container } must
    /// surface a clear "feature not built in" error rather than the old
    /// "not implemented (R406-T4..T6/T11)" stub. R406-T11 tracks probe.
    #[cfg(not(feature = "containerd-integration"))]
    #[tokio::test]
    async fn deploy_container_without_feature_says_so() {
        let ctx = Arc::new(ServerCtx::new());
        let spec = workload_spec::Workload::Container(make_minimal_container_spec("svc"));
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

    /// With the containerd-integration feature but no backend attached to
    /// ServerCtx, Deploy { Container } returns BackendRefused with a hint at
    /// the missing config.
    #[cfg(feature = "containerd-integration")]
    #[tokio::test]
    async fn deploy_container_without_attached_backend_says_so() {
        let ctx = Arc::new(ServerCtx::new());
        let spec = workload_spec::Workload::Container(make_minimal_container_spec("svc"));
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
        let spec = workload_spec::Workload::Container(make_minimal_container_spec("svc"));
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
                    ports: vec![],
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
            ProbeTarget {
                healthcheck: Healthcheck {
                    probe: HealthProbe::TcpConnect { port },
                    interval: Millis::from_ms(1000),
                    timeout: Millis::from_ms(500),
                    initial_delay: Millis::from_ms(0),
                    failure_threshold: 3,
                },
                addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            },
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
                name: "yah-marketing".to_string(),
                runtime: BundleRuntime::SelfContained,
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
            Workload::MesofactStatic(MesofactStaticWorkload {
                schema_version: SchemaVersion::V1,
                build: BuildConfig {
                    command: "bun run build".into(),
                    out_dir: std::path::PathBuf::from("dist"),
                    render_command: None,
                },
                routes: std::path::PathBuf::from("routes.ts"),
                build_mode: BuildMode::HostSide,
                ssr_runtime: None,
                serve_bundle: Some(MesofactServeBundle {
                    digest: BlakeHash(digest_hex.to_string()),
                    runtime: "self".to_string(),
                    lifecycle,
                    port,
                }),
                revalidate_receiver: None,
            })
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
                        // positional workload — NOT `--workload`
                        "/var/cache/yah/bundles/abc/app",
                        "--revalidate",
                        "--publish-config",
                        "/var/cache/yah/bundles/abc/app/mesofact.config.toml",
                        "--listen",
                        "127.0.0.1:3001",
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
            match reply {
                KamajiToYubaba::Error { code, message, .. } => {
                    assert_eq!(code, ErrorCode::BackendRefused);
                    assert!(message.contains("almanac-feed"), "got {message}");
                    assert!(message.contains("feed_bins"), "got {message}");
                }
                other => panic!("expected an error naming the missing sidecar, got {other:?}"),
            }
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
                KamajiToYubaba::Error {
                    request_id,
                    code,
                    message,
                } => {
                    assert_eq!(request_id, Some(RequestId(121)));
                    assert_eq!(code, ErrorCode::BackendRefused, "got: {message}");
                    assert!(
                        message.contains("serve runtime asset missing"),
                        "got: {message}"
                    );
                }
                other => panic!("expected Error(BackendRefused), got {other:?}"),
            }
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

            // The port is the workload's own; the node-wide default is only the
            // fallback, and it is the fallback that limits a node to one bundle.
            let node_default = 8080;
            assert_eq!(Some(9001).unwrap_or(node_default), 9001);
            assert_eq!(None.unwrap_or(node_default), 8080);
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
            // Port 0 keeps the stub child off any real port; the assertion is
            // about the *address kamaji resolved*, which the probe target
            // records verbatim.
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path())
                .with_bind_port(0);
            let ctx = Arc::new(ServerCtx::new().with_bundle_backend(backend));

            let reply = handle_message(
                YubabaToKamaji::Deploy {
                    request_id: RequestId(130),
                    id: WorkloadId::new("yah-marketing"),
                    spec: serve_bundle_workload_on_port(
                        &digest,
                        BundleLifecycle::KeepAlive,
                        Some(8443),
                    ),
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

            let target = ctx
                .registry
                .lock()
                .await
                .probe_target(&WorkloadId::new("yah-marketing"))
                .expect("keep-alive deploy registers a probe target");
            assert_eq!(
                target.addr.to_string(),
                "100.64.0.3:8443",
                "the bundle must be dialable at <mesh-ip>:<declared-port>",
            );

            // The same address is declared on the spec a proxy would read it
            // from — an empty `expose.mesh.ports` means "declares no ports",
            // which is what yubaba's ServiceRecords refuses to publish.
            let spec = bundle_workload_spec(
                &WorkloadId::new("yah-marketing"),
                Path::new("/opt/serve"),
                Path::new("/cache/bundles/abc"),
                "100.64.0.3:8443",
            );
            assert_eq!(spec.expose.mesh.ports, vec![8443]);
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

            for (rid, name, port) in [(140, "site-a", 8081u16), (141, "site-b", 8082u16)] {
                let reply = handle_message(
                    YubabaToKamaji::Deploy {
                        request_id: RequestId(rid),
                        id: WorkloadId::new(name),
                        spec: serve_bundle_workload_on_port(
                            &digest,
                            BundleLifecycle::KeepAlive,
                            Some(port),
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
            }

            let registry = ctx.registry.lock().await;
            let a = registry
                .probe_target(&WorkloadId::new("site-a"))
                .expect("site-a probe target");
            let b = registry
                .probe_target(&WorkloadId::new("site-b"))
                .expect("site-b probe target");
            assert_eq!(a.addr.to_string(), "127.0.0.1:8081");
            assert_eq!(b.addr.to_string(), "127.0.0.1:8082");
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

        /// The revalidate receiver rides the port above its own bundle's, not
        /// above the node default — otherwise two bundles' receivers collide
        /// even after their static servers have been separated.
        #[test]
        fn each_bundles_receiver_rides_its_own_serve_port() {
            assert_ne!(
                revalidate_port(8081),
                revalidate_port(8082),
                "two bundles' receivers must not share a port"
            );
            assert_eq!(revalidate_port(8081), 8082);
            // 0 is the tests' OS-assigned-ephemeral sentinel: stay ephemeral
            // rather than binding privileged port 1.
            assert_eq!(revalidate_port(0), 0);
            // A declared port at the top of the range must not wrap into a
            // privileged one (or panic on the debug-build add).
            assert_eq!(revalidate_port(u16::MAX), u16::MAX);
        }
    }
}

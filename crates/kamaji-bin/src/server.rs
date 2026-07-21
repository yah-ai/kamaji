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

// R599-F10: the native bundle backend. The `Kamaji` trait brings
// deploy/list/teardown into scope for the kamaji-crate NativeRuntime.
#[cfg(feature = "bundle-serving")]
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
}

/// The R599-F10 keep-alive bundle backend: materialize a W272 bundle from the
/// node store and fork+supervise `mesofact-serve --bundle <dir> --listen <addr>`
/// under the kamaji crate's native (fork+exec) runtime — the same supervisor
/// R490 already runs mesofact-dev under.
///
/// The [`NativeRuntime`] is the **single owner** of each served bundle's child
/// process (spawn, restart-per-policy, log capture, teardown). The kamaji-bin
/// [`Registry`] is *not* a second lifecycle owner for bundle workloads: `List`
/// merges the native runtime's live view (like the containerd merge), `Stop`
/// routes teardown to it, and the only registry state a bundle deploy writes is
/// a probe target so `Probe` can dial the serve process. See
/// [`deploy_mesofact_bundle`] for the Drain caveat.
///
/// [`NativeRuntime`]: kamaji::native::NativeRuntime
#[cfg(feature = "bundle-serving")]
pub struct BundleBackend {
    /// Fork+exec supervisor — single owner of each served bundle's process.
    pub native: Arc<kamaji::native::NativeRuntime>,
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
    /// Loopback port each served bundle binds (`127.0.0.1:<port>`). Testbed
    /// convention (passway → 127.0.0.1:8080). Overridable via
    /// `KAMAJI_BUNDLE_PORT`. See the mesh-plane follow-up note in
    /// [`deploy_mesofact_bundle`].
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
        Self {
            native: Arc::new(kamaji::native::NativeRuntime::new(state_dir)),
            store,
            cache_dir: cache_dir.into(),
            cache_budget: 0,
            bind_port,
        }
    }

    /// Override the loopback port served bundles bind. An explicit operator
    /// flag wins over the `KAMAJI_BUNDLE_PORT` env default picked in [`new`].
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

/// Default loopback port a served bundle binds when no `KAMAJI_BUNDLE_PORT` is
/// set (R599-F10). Mirrors the 2026-07-06 ingress testbed (passway →
/// 127.0.0.1:8080).
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

            // Merge keep-alive bundle workloads (R599-F10). The native runtime
            // is the source of truth for their live status — mirror the
            // containerd merge rather than tracking a stale registry snapshot.
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
            }

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
        } => deploy_workload(ctx, request_id, id, spec).await,
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

/// Dispatch a `Deploy { id, spec }` to the right backend. R406-T9 wires
/// `Workload::Container` to the containerd backend. R599-F4 admits a
/// `MesofactStatic` workload that carries a `serve_bundle` (a deployed W272
/// bundle) and routes it to the native backend via [`deploy_mesofact_bundle`];
/// a build-and-publish-only `MesofactStatic` (no `serve_bundle`), `Almanac`, and
/// `StaticAsset` remain yubaba's reconcilers' business and surface as
/// `InvalidSpec` if they reach Kamaji.
#[allow(unused_variables)]
async fn deploy_workload(
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
                match backend.deploy(&id, &spec).await {
                    Ok(_pid) => KamajiToYubaba::Ack {
                        request_id,
                        kind: kamaji_proto::AckKind::Deploy,
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
                              Container workloads cannot be deployed"
                        .to_string(),
                }
            }
        }
        // R599-F4: a mesofact-static workload that carries a `serve_bundle` is a
        // deployed W272 bundle kamaji serves via its native backend — no longer
        // rejected. The build-and-publish-only form (no serve_bundle) still
        // belongs to yubaba's mesofact-static reconciler.
        workload_spec::Workload::MesofactStatic(w) => match w.serve_bundle {
            Some(bundle) => deploy_mesofact_bundle(ctx, request_id, &id, &bundle).await,
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

/// Dispatch a serve-bundle mesofact-static workload (R599-F4) to the native
/// backend: materialize the W272 bundle from the node store (R599-F1) and fork
/// the serve runtime under kamaji's native supervisor (R599-F10).
///
/// With the `bundle-serving` feature the KeepAlive path is live: materialize →
/// resolve the serve bin (self → `<dir>/bins/<triple>/serve`, `mesofact/<ver>` →
/// `<cache>/runtimes/<runtime>/<triple>/serve`) → fork
/// `mesofact-serve --bundle <dir> --listen 127.0.0.1:<port>` under the native
/// supervisor. OnDemand/JIT is out of scope (R599-F6) and refuses cleanly.
///
/// Without the feature (default build), an admitted serve-bundle deploy reports
/// `BackendRefused` — the workload is *recognized* (no longer `InvalidSpec`) but
/// this kamaji build has no bundle backend, exactly as a `Container` deploy
/// reports `BackendRefused` without containerd.
///
/// **Drain caveat:** the native runtime is the single owner of the child, so a
/// bundle deploy does NOT register a pidfd `DrainableHandle` (that would
/// double-own the process with the supervisor and race its reaper). Structured
/// Drain of a bundle workload is therefore not wired — a `Drain` returns
/// `DrainAck { accepted:false, reason:"unknown workload" }`; teardown is via
/// `Stop`, which routes to `NativeRuntime::teardown_workload`.
#[allow(unused_variables)]
async fn deploy_mesofact_bundle(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: &WorkloadId,
    bundle: &workload_spec::MesofactServeBundle,
) -> KamajiToYubaba {
    #[cfg(feature = "bundle-serving")]
    {
        deploy_bundle_keepalive(ctx, request_id, id, bundle).await
    }
    #[cfg(not(feature = "bundle-serving"))]
    {
        let _ = ctx;
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

/// Keep-alive bundle deploy (R599-F10). Materialize the W272 bundle, resolve the
/// serve binary, and fork it under the native supervisor. See
/// [`deploy_mesofact_bundle`] for the OnDemand refusal + Drain caveat.
#[cfg(feature = "bundle-serving")]
async fn deploy_bundle_keepalive(
    ctx: &Arc<ServerCtx>,
    request_id: kamaji_proto::RequestId,
    id: &WorkloadId,
    bundle: &workload_spec::MesofactServeBundle,
) -> KamajiToYubaba {
    use std::net::{Ipv4Addr, SocketAddr};

    let err = |code: ErrorCode, message: String| KamajiToYubaba::Error {
        request_id: Some(request_id),
        code,
        message,
    };

    // SCOPE: keep-alive only. On-demand/JIT socket-activation is R599-F6 — refuse
    // cleanly before doing any materialize work.
    if let workload_spec::BundleLifecycle::OnDemand { idle_ttl } = &bundle.lifecycle {
        return err(
            ErrorCode::BackendRefused,
            format!(
                "on-demand JIT bundle lifecycle (idle_ttl={}ms) is R599-F6; this kamaji serves \
                 only keep-alive serve_bundle workloads (R599-F10)",
                idle_ttl.as_ms()
            ),
        );
    }

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

    // 1. Materialize the bundle tree from the node store (R599-F1). The digest is
    //    the content-address; a bad hex shape is a spec error, not a backend one.
    let digest = match yah_mesofact_bundle::BundleHash::parse(bundle.digest.0.clone()) {
        Ok(d) => d,
        Err(e) => {
            return err(
                ErrorCode::InvalidSpec,
                format!("bundle digest {:?} is not a valid blake3: {e}", bundle.digest.0),
            )
        }
    };

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
            return err(
                ErrorCode::BackendRefused,
                format!("materialize bundle {}: {e}", digest.as_str()),
            )
        }
        Err(e) => {
            return err(
                ErrorCode::Internal,
                format!("bundle materialize task failed: {e}"),
            )
        }
    };

    // 2. Resolve the serve binary from the runtime selector (W272 §2/§3).
    let triple = node_triple();
    let serve_bin = if bundle.runtime == "self" {
        // Custom bundle ships its own bins/<triple>/serve inside the tree.
        bundle_dir.join("bins").join(&triple).join("serve")
    } else if let Some(version) = bundle.runtime.strip_prefix("mesofact/") {
        if version.is_empty() {
            return err(
                ErrorCode::InvalidSpec,
                format!("bundle runtime {:?} missing a version after 'mesofact/'", bundle.runtime),
            );
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
        return err(
            ErrorCode::InvalidSpec,
            format!(
                "unrecognized bundle runtime {:?} (expected \"self\" or \"mesofact/<version>\")",
                bundle.runtime
            ),
        );
    };
    if !serve_bin.exists() {
        return err(
            ErrorCode::BackendRefused,
            format!(
                "serve runtime asset missing at {} (triple={triple}, runtime={}): a \"self\" \
                 bundle must ship bins/<triple>/serve; a \"mesofact/<ver>\" bundle needs the \
                 stock runtime asset present in the node runtime cache",
                serve_bin.display(),
                bundle.runtime
            ),
        );
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

    // 3. Build the native WorkloadSpec (identity image, entrypoint=[serve_bin],
    //    command=[--bundle <dir> --listen <addr>]) and fork it. Bind to
    //    127.0.0.1:<port>, mirroring today's ingress testbed.
    //
    //    FOLLOW-UP: mesh-IP-plane binding + multi-bundle-per-node needs Deploy to
    //    carry a MeshAssignment (bind IP + per-workload port); the UDS Deploy
    //    envelope has none today, so every bundle shares the one loopback port.
    let listen = format!("127.0.0.1:{}", backend.bind_port);
    let spec = bundle_workload_spec(id, &serve_bin, &bundle_dir, &listen);
    let mesh = kamaji::MeshAssignment::inlined(Ipv4Addr::LOCALHOST);

    match backend.native.deploy_workload(&spec, &mesh).await {
        Ok(_res) => {
            // Register a probe target so Probe RPCs actually dial the serve
            // process (the only registry state a bundle deploy writes).
            let port = backend.bind_port;
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
                    addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                },
            );
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

/// Build the native [`WorkloadSpec`](workload_spec::WorkloadSpec) that forks
/// `mesofact-serve --bundle <dir> --listen <addr>` for a keep-alive bundle
/// (R599-F10). `image` is identity-only (the native backend pulls nothing);
/// argv is `entrypoint ++ command` = `[serve_bin, --bundle, <dir>, --listen,
/// <addr>]`; restart policy is `Always` (the resident-server archetype).
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
    let pid = s
        .container_id
        .strip_prefix("native-")
        .and_then(|p| p.parse::<u32>().ok())
        .filter(|p| *p != 0);
    WorkloadEntry {
        id: WorkloadId(s.ident.0.clone()),
        state,
        pid,
        mesh_ident: Some(s.ident.0),
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
        if let Err(e) = backend.native.teardown_workload(&ident).await {
            return KamajiToYubaba::Error {
                request_id: Some(request_id),
                code: ErrorCode::BackendRefused,
                message: format!("bundle teardown: {e}"),
            };
        }
        ctx.registry.lock().await.remove_probe(&id);
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
    use kamaji_proto::{AckKind, DrainBudget, ExitStatus, RequestId, WorkloadId};

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
        });
        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(11),
                id: WorkloadId::new("static-site"),
                spec: workload,
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
            }),
        });
        let reply = handle_message(
            YubabaToKamaji::Deploy {
                request_id: RequestId(21),
                id: WorkloadId::new("yah-marketing"),
                spec: workload,
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
            let dir = tempfile::tempdir().unwrap();
            let mut files: Vec<(String, Vec<u8>)> =
                vec![("app/index.html".to_string(), b"<html>home</html>".to_vec())];
            if with_serve {
                // A serve bin that just sleeps so the supervised child stays up.
                let serve_rel = format!("bins/{}/serve", node_triple());
                files.push((serve_rel, b"#!/bin/sh\nexec sleep 30\n".to_vec()));
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
                }),
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

        /// (b) An OnDemand serve_bundle deploy still refuses with the R599-F6
        /// message — JIT is out of F10 scope.
        #[tokio::test]
        async fn ondemand_deploy_refuses_as_r599_f6() {
            let store: Arc<dyn ObjectStore> = Arc::new(InMemoryObjectStore::new());
            let digest = publish_self_bundle(store.as_ref(), true);

            let cache = tempfile::tempdir().unwrap();
            let state = tempfile::tempdir().unwrap();
            let backend = BundleBackend::new(Arc::clone(&store), cache.path(), state.path());
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
                    assert_eq!(request_id, Some(RequestId(111)));
                    assert_eq!(code, ErrorCode::BackendRefused, "got: {message}");
                    assert!(
                        message.contains("R599-F6") && message.contains("on-demand"),
                        "got: {message}"
                    );
                }
                other => panic!("expected Error(BackendRefused), got {other:?}"),
            }
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
    }
}

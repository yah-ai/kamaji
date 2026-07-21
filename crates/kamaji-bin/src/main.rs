//! @yah:relay(R597, "Finish constable->kamaji / warden->yubaba rename tail (env-var + raft symbols)")
//! @yah:at(2026-07-06T07:45:13Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("Spawned from R592-T4 (the wire-surface rename, now in review). T4 renamed the pub types/client/field (WardenToConstable->YubabaToKamaji, ConstableToWarden->KamajiToYubaba, ConstableClient->KamajiClient, constable_version->kamaji_version) across oss/kamaji + root/hub + oss/yubaba and verified all 3 green. This relay finishes the two residual slices T4 deliberately deferred: R597-T1 (KAMAJI_SOCK env var rename, drags in oss/qed) and R597-T2 (yubaba-internal raft Warden* symbols). Both are independent, mechanical, and can run in either order once their lanes are quiet.")
//!
//! @yah:ticket(R597-T1, "Rename CONSTABLE_SOCK env var -> KAMAJI_SOCK across kamaji-bin + qed pond image + kamaji.service")
//! @yah:status(review)
//! @yah:at(2026-07-20T03:54:35Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R597)
//! @yah:next("DONE (R597-T1): renamed env-var to KAMAJI_SOCK across kamaji-bin/main.rs, yah-yubaba/Dockerfile, yah-yubaba/pond-supervise.sh, kamaji.service comment. Socket path /run/kamaji/kamaji.sock unchanged.")
//! @yah:next("Before claiming: oss/qed is a 4th workspace not cleared during R592-T4 -- check git status oss/qed + board inflight for a live peer first (R592-T4 deferred this specifically to avoid dragging qed into the wire-rename pass).")
//! @yah:next("Postcard/runtime note: env-var name is not on the wire; pure string-contract rename. No protocol impact.")
//! @yah:verify("cd oss/kamaji && cargo build -p kamaji-bin; pond-supervise.sh + Dockerfile reference KAMAJI_SOCK and /run/kamaji/kamaji.sock as the default path value")
//! @yah:gotcha("Tier: Thief -- rote cross-file string rename of a single env-var token, no logic. The only care is atomicity across the 4 sites (binary reader + qed Dockerfile/script setters + service comment) so a deploy can't read one name while the image sets the other.")

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

const DEFAULT_SOCKET: &str = "/run/kamaji/kamaji.sock";
const ABOUT: &str = "kamaji — Yubaba's sibling process supervisor.\n\nReads workload-control messages from Yubaba over a unix domain socket and dispatches them to the containerd backend (R406-T9), the native fork+exec path (R406-T5/T6), or the keep-alive mesofact bundle backend (R599-F10). Run with --containerd-socket to enable container workloads, and --bundle-cache-dir + --bundle-bucket to serve published W272 mesofact bundles.";

struct Args {
    socket: PathBuf,
    containerd_socket: Option<PathBuf>,
    /// Node bundle root (R599-F10). Materialized bundles land in
    /// `<root>/bundles/`, stock serve-runtime assets in `<root>/runtimes/`, and
    /// the native supervisor's per-workload log captures in `<root>/state/`.
    bundle_cache_dir: Option<PathBuf>,
    /// R2 bucket holding the published bundle store (blobs + manifests).
    bundle_bucket: Option<String>,
    /// Loopback port served bundles bind. Falls back to `$KAMAJI_BUNDLE_PORT`,
    /// then the compiled-in default. Only consumed by the bundle backend; the
    /// no-feature build still *parses* it (so `--bundle-port` isn't an "unknown
    /// argument") but has nothing to apply it to.
    #[cfg_attr(not(feature = "bundle-serving"), allow(dead_code))]
    bundle_port: Option<u16>,
}

fn parse_args() -> std::result::Result<Args, ParseError> {
    let mut socket: PathBuf = std::env::var_os("KAMAJI_SOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    let mut containerd_socket: Option<PathBuf> =
        std::env::var_os("CONTAINERD_SOCK").map(PathBuf::from);
    // R599-F10 bundle-serving config. Secrets are NEVER taken from argv — the R2
    // access key + secret come from the yah keystore (env fallback
    // CF_R2_ACCESS_KEY_ID / CF_R2_SECRET_KEY) via R2ObjectStore::from_vault, and
    // the account id from $CF_ACCOUNT_ID, matching every other R2 call site.
    let mut bundle_cache_dir: Option<PathBuf> =
        std::env::var_os("KAMAJI_BUNDLE_CACHE_DIR").map(PathBuf::from);
    let mut bundle_bucket: Option<String> = std::env::var("KAMAJI_BUNDLE_BUCKET").ok();
    let mut bundle_port: Option<u16> = match std::env::var("KAMAJI_BUNDLE_PORT") {
        Ok(v) => Some(
            v.parse()
                .map_err(|_| ParseError::BadValue("KAMAJI_BUNDLE_PORT"))?,
        ),
        Err(_) => None,
    };

    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--socket" | "-s" => {
                socket = iter
                    .next()
                    .map(PathBuf::from)
                    .ok_or(ParseError::MissingValue("--socket"))?;
            }
            "--containerd-socket" => {
                containerd_socket = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--containerd-socket"))?,
                );
            }
            "--bundle-cache-dir" => {
                bundle_cache_dir = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--bundle-cache-dir"))?,
                );
            }
            "--bundle-bucket" => {
                bundle_bucket = Some(
                    iter.next()
                        .ok_or(ParseError::MissingValue("--bundle-bucket"))?,
                );
            }
            "--bundle-port" => {
                bundle_port = Some(
                    iter.next()
                        .ok_or(ParseError::MissingValue("--bundle-port"))?
                        .parse()
                        .map_err(|_| ParseError::BadValue("--bundle-port"))?,
                );
            }
            "--help" | "-h" => return Err(ParseError::HelpRequested),
            "--version" | "-V" => return Err(ParseError::VersionRequested),
            other => return Err(ParseError::Unknown(other.to_string())),
        }
    }
    Ok(Args {
        socket,
        containerd_socket,
        bundle_cache_dir,
        bundle_bucket,
        bundle_port,
    })
}

enum ParseError {
    MissingValue(&'static str),
    BadValue(&'static str),
    Unknown(String),
    HelpRequested,
    VersionRequested,
}

fn print_help() {
    println!("{ABOUT}");
    println!();
    println!(
        "Usage: kamaji [--socket PATH] [--containerd-socket PATH]\n              \
         [--bundle-cache-dir PATH] [--bundle-bucket NAME] [--bundle-port PORT]"
    );
    println!();
    println!("Options:");
    println!(
        "  -s, --socket PATH         UDS path to bind (default: ${{KAMAJI_SOCK:-{DEFAULT_SOCKET}}})"
    );
    println!("      --containerd-socket PATH  containerd UDS to dispatch Container workloads to");
    println!("                                (default: $CONTAINERD_SOCK, else container deploys are refused)");
    println!("      --bundle-cache-dir PATH   node bundle root for serving published W272 mesofact");
    println!("                                bundles: <root>/bundles, <root>/runtimes, <root>/state");
    println!("                                (default: $KAMAJI_BUNDLE_CACHE_DIR, else serve-bundle");
    println!("                                deploys are refused)");
    println!("      --bundle-bucket NAME      R2 bucket holding the published bundle store");
    println!("                                (default: $KAMAJI_BUNDLE_BUCKET; required with");
    println!("                                --bundle-cache-dir)");
    println!("      --bundle-port PORT        loopback port served bundles bind on 127.0.0.1");
    println!(
        "                                (default: $KAMAJI_BUNDLE_PORT, else {})",
        bundle_port_default_str()
    );
    println!("  -h, --help                Print this message and exit");
    println!("  -V, --version             Print version and exit");
    println!();
    println!("Bundle-serving R2 credentials are read from the yah keystore (slots");
    println!("cloudflare-r2-access-key-id / cloudflare-r2-secret-key, env fallback");
    println!("CF_R2_ACCESS_KEY_ID / CF_R2_SECRET_KEY) plus $CF_ACCOUNT_ID — never from argv.");
}

/// The compiled-in bundle port default, or a note that this build can't serve
/// bundles at all (feature off).
fn bundle_port_default_str() -> String {
    #[cfg(feature = "bundle-serving")]
    {
        kamaji_bin::DEFAULT_BUNDLE_PORT.to_string()
    }
    #[cfg(not(feature = "bundle-serving"))]
    {
        "n/a — built without --features bundle-serving".to_string()
    }
}

fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = match parse_args() {
        Ok(a) => a,
        Err(ParseError::HelpRequested) => {
            print_help();
            return Ok(());
        }
        Err(ParseError::VersionRequested) => {
            println!("kamaji {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Err(ParseError::MissingValue(flag)) => {
            anyhow::bail!("flag {flag} requires a value");
        }
        Err(ParseError::BadValue(flag)) => {
            anyhow::bail!("{flag} has an invalid value");
        }
        Err(ParseError::Unknown(arg)) => {
            anyhow::bail!("unknown argument: {arg}");
        }
    };

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let ctx = build_ctx(&args).await?;
        kamaji_bin::serve_with_ctx(&args.socket, ctx, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    })
}

/// Assemble the [`kamaji_bin::ServerCtx`]. Attaches a containerd backend when
/// the operator passed `--containerd-socket` (or set `CONTAINERD_SOCK`) and
/// the binary was built with `--features containerd-integration`, and the
/// keep-alive mesofact bundle backend when they passed `--bundle-cache-dir`
/// (or set `KAMAJI_BUNDLE_CACHE_DIR`) and it was built with
/// `--features bundle-serving`. Failures here are fatal — if the operator asked
/// for a backend, missing it means those deploys would silently refuse and that
/// should surface at startup, not on the first deploy.
///
/// The log sink is the journald datagram socket (R406-T10). On hosts
/// without journald reachable, [`kamaji_bin::JournalSender::connect`] falls
/// back to tracing — see `crate::journal` for the fallback path.
async fn build_ctx(args: &Args) -> Result<Arc<kamaji_bin::ServerCtx>> {
    let log_sink: std::sync::Arc<dyn kamaji_bin::LogSink> =
        std::sync::Arc::new(kamaji_bin::JournalSender::connect());
    #[allow(unused_mut)]
    let mut ctx = kamaji_bin::ServerCtx::new().with_log_sink(log_sink.clone());

    // ── containerd backend ───────────────────────────────────────────────────
    #[cfg(feature = "containerd-integration")]
    {
        ctx = if let Some(sock) = &args.containerd_socket {
            let backend = kamaji_bin::containerd::ContainerdBackend::connect_at(sock)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("failed to connect to containerd at {}: {e}", sock.display())
                })?
                .with_log_sink(log_sink);
            tracing::info!(
                socket = %sock.display(),
                "containerd backend attached"
            );
            ctx.with_containerd(std::sync::Arc::new(backend))
        } else {
            tracing::warn!(
                "no --containerd-socket; Deploy {{ Container }} will refuse with BackendRefused. \
                 Pass --containerd-socket /run/containerd/containerd.sock for the production path."
            );
            ctx
        };
    }
    #[cfg(not(feature = "containerd-integration"))]
    if args.containerd_socket.is_some() {
        anyhow::bail!(
            "--containerd-socket requires the kamaji binary be built with \
             --features containerd-integration"
        );
    }

    // ── keep-alive mesofact bundle backend (R599-F10) ────────────────────────
    #[cfg(feature = "bundle-serving")]
    {
        ctx = attach_bundle_backend(ctx, args).await?;
    }
    #[cfg(not(feature = "bundle-serving"))]
    if args.bundle_cache_dir.is_some() || args.bundle_bucket.is_some() {
        anyhow::bail!(
            "--bundle-cache-dir / --bundle-bucket require the kamaji binary be built with \
             --features bundle-serving"
        );
    }

    Ok(Arc::new(ctx))
}

/// Attach the R599-F10 bundle backend when the node is configured for it.
///
/// Requires `--bundle-cache-dir` (the node bundle root) plus the R2 coordinates
/// of the published bundle store: `--bundle-bucket` and `$CF_ACCOUNT_ID`.
/// Credentials come from the yah keystore with env fallback via
/// [`R2ObjectStore::from_vault`] — never from argv. With no cache dir configured
/// this warns and leaves `ctx.bundle = None`, so a serve-bundle deploy keeps
/// returning the existing `BackendRefused`.
///
/// [`R2ObjectStore::from_vault`]: yah_object_store::R2ObjectStore::from_vault
#[cfg(feature = "bundle-serving")]
async fn attach_bundle_backend(
    ctx: kamaji_bin::ServerCtx,
    args: &Args,
) -> Result<kamaji_bin::ServerCtx> {
    use anyhow::Context as _;

    let Some(cache_dir) = args.bundle_cache_dir.clone() else {
        tracing::warn!(
            "no --bundle-cache-dir; Deploy {{ MesofactStatic + serve_bundle }} will refuse with \
             BackendRefused. Pass --bundle-cache-dir /var/lib/yah/kamaji/bundles plus \
             --bundle-bucket (and $CF_ACCOUNT_ID) for the production path."
        );
        return Ok(ctx);
    };

    let Some(bucket) = args.bundle_bucket.clone() else {
        anyhow::bail!(
            "--bundle-cache-dir requires --bundle-bucket (or $KAMAJI_BUNDLE_BUCKET) — the R2 \
             bucket holding the published bundle store to materialize from"
        );
    };
    let account_id = std::env::var("CF_ACCOUNT_ID").map_err(|_| {
        anyhow::anyhow!(
            "--bundle-cache-dir requires $CF_ACCOUNT_ID (the Cloudflare account id owning the \
             R2 bundle bucket)"
        )
    })?;

    // W272 §2: the node cache lives under kamaji's state dir. One root holds
    // materialized bundles (<root>/bundles), stock serve-runtime assets
    // (<root>/runtimes), and the native supervisor's log captures (<root>/state).
    // The cache's LRU eviction only ever scans <root>/bundles, so supervisor
    // state is never evicted out from under a running workload.
    std::fs::create_dir_all(&cache_dir)
        .with_context(|| format!("creating bundle cache dir {}", cache_dir.display()))?;
    let state_dir = cache_dir.join("state");
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("creating bundle state dir {}", state_dir.display()))?;

    // R2ObjectStore owns a `reqwest::blocking::Client`, which panics if it is
    // constructed inside a tokio runtime context — build it on the blocking pool.
    // Same discipline as yubaba's reconciler::bundle_store publish leg.
    let store = tokio::task::spawn_blocking({
        let bucket = bucket.clone();
        move || yah_object_store::R2ObjectStore::from_vault(account_id, bucket)
    })
    .await
    .context("R2 bundle-store construction task panicked")?
    .context("building R2ObjectStore for the node bundle store")?;

    let mut backend =
        kamaji_bin::BundleBackend::new(std::sync::Arc::new(store), &cache_dir, &state_dir);
    if let Some(port) = args.bundle_port {
        backend = backend.with_bind_port(port);
    }
    tracing::info!(
        cache_dir = %cache_dir.display(),
        bucket = %bucket,
        bind_port = backend.bind_port,
        "bundle backend attached (keep-alive serve_bundle workloads)"
    );
    Ok(ctx.with_bundle_backend(backend))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kamaji: {e:#}");
            ExitCode::FAILURE
        }
    }
}

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
const ABOUT: &str = "kamaji — Yubaba's sibling process supervisor.\n\nReads workload-control messages from Yubaba over a unix domain socket and dispatches them to the containerd backend (R406-T9), the docker/OrbStack backend (R626-F1), the native fork+exec path (R406-T5/T6), or the keep-alive mesofact bundle backend (R599-F10). Run with --containerd-socket (cloud tier) or --docker (pond / dev host) to enable container workloads, and --bundle-cache-dir + --bundle-origin to serve published W272 mesofact bundles.";

struct Args {
    socket: PathBuf,
    containerd_socket: Option<PathBuf>,
    /// Node bundle root (R599-F10). Materialized bundles land in
    /// `<root>/bundles/`, stock serve-runtime assets in `<root>/runtimes/`, and
    /// the native supervisor's per-workload log captures in `<root>/state/`.
    bundle_cache_dir: Option<PathBuf>,
    /// R2 bucket holding the published bundle store (blobs + manifests).
    bundle_origin: Option<String>,
    /// Loopback port served bundles bind. Falls back to `$KAMAJI_BUNDLE_PORT`,
    /// then the compiled-in default. Only consumed by the bundle backend; the
    /// no-feature build still *parses* it (so `--bundle-port` isn't an "unknown
    /// argument") but has nothing to apply it to.
    #[cfg_attr(not(feature = "bundle-serving"), allow(dead_code))]
    bundle_port: Option<u16>,
    /// Attach the docker/OrbStack backend for `Deploy { Container }` (R626-F1).
    /// `Some("")` means "use the ambient `DOCKER_HOST`" (bare `--docker`);
    /// `Some(host)` pins an explicit daemon. `None` leaves docker unattached.
    #[cfg_attr(not(feature = "docker-integration"), allow(dead_code))]
    docker_host: Option<String>,
    /// State dir for the native fork+exec backend (R577-T1), holding each
    /// native workload's stdout/stderr capture. `Some(dir)` attaches the
    /// backend; `None` leaves native-marked container deploys refused.
    #[cfg_attr(not(feature = "native-exec"), allow(dead_code))]
    native_exec_dir: Option<PathBuf>,
    /// Root of the node's microVM material (R605-F8): `<dir>/vmlinux`,
    /// `<dir>/rootfs.ext4`, and `<dir>/vms` for per-guest state. `Some(dir)`
    /// attaches the backend; `None` leaves microVM-marked deploys refused.
    #[cfg_attr(not(feature = "microvm"), allow(dead_code))]
    microvm_dir: Option<PathBuf>,
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
    let mut bundle_origin: Option<String> = std::env::var("KAMAJI_BUNDLE_ORIGIN").ok();
    let mut bundle_port: Option<u16> = match std::env::var("KAMAJI_BUNDLE_PORT") {
        Ok(v) => Some(
            v.parse()
                .map_err(|_| ParseError::BadValue("KAMAJI_BUNDLE_PORT"))?,
        ),
        Err(_) => None,
    };

    // R626-F1: docker backend opt-in. `KAMAJI_DOCKER=1` attaches with the
    // ambient DOCKER_HOST; `KAMAJI_DOCKER=<host>` pins a daemon. Deliberately
    // NOT keyed off a bare `$DOCKER_HOST` — nearly every dev host sets that,
    // and a supervisor must not adopt a daemon nobody asked it to supervise.
    let mut docker_host: Option<String> = match std::env::var("KAMAJI_DOCKER") {
        Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") => None,
        Ok(v) if v == "1" || v.eq_ignore_ascii_case("true") => Some(String::new()),
        Ok(v) => Some(v),
        Err(_) => None,
    };

    // R577-T1: native fork+exec backend opt-in, same explicit-opt-in discipline
    // as --docker. A supervisor must not start forking host processes because
    // some ambient variable happened to be set.
    let mut native_exec_dir: Option<PathBuf> =
        std::env::var_os("KAMAJI_NATIVE_EXEC_DIR").map(PathBuf::from);

    // R605-F8: microVM backend opt-in, same discipline again.
    let mut microvm_dir: Option<PathBuf> = std::env::var_os("KAMAJI_MICROVM_DIR").map(PathBuf::from);

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
            "--bundle-origin" => {
                bundle_origin = Some(
                    iter.next()
                        .ok_or(ParseError::MissingValue("--bundle-origin"))?,
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
            "--native-exec-dir" => {
                native_exec_dir = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--native-exec-dir"))?,
                );
            }
            "--microvm-dir" => {
                microvm_dir = Some(
                    iter.next()
                        .map(PathBuf::from)
                        .ok_or(ParseError::MissingValue("--microvm-dir"))?,
                );
            }
            // Bare `--docker` inherits DOCKER_HOST; `--docker-host URL` pins one.
            "--docker" => docker_host = Some(String::new()),
            "--docker-host" => {
                docker_host = Some(
                    iter.next()
                        .ok_or(ParseError::MissingValue("--docker-host"))?,
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
        bundle_origin,
        bundle_port,
        docker_host,
        native_exec_dir,
        microvm_dir,
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
        "Usage: kamaji [--socket PATH] [--containerd-socket PATH] [--docker | --docker-host URL]\n              \
         [--native-exec-dir PATH] [--microvm-dir PATH]\n              \
         [--bundle-cache-dir PATH] [--bundle-origin URL] [--bundle-port PORT]"
    );
    println!();
    println!("Options:");
    println!(
        "  -s, --socket PATH         UDS path to bind (default: ${{KAMAJI_SOCK:-{DEFAULT_SOCKET}}})"
    );
    println!("      --containerd-socket PATH  containerd UDS to dispatch Container workloads to");
    println!("                                (default: $CONTAINERD_SOCK, else container deploys are refused)");
    println!("      --docker                  supervise Container workloads on a Docker-compatible");
    println!("                                daemon (OrbStack, dockerd, podman) using the ambient");
    println!("                                $DOCKER_HOST (default: off; $KAMAJI_DOCKER=1 also enables)");
    println!("      --docker-host URL         as --docker, against an explicit daemon, e.g.");
    println!("                                unix:///var/run/docker.sock");
    println!("      --native-exec-dir PATH    supervise Container workloads marked");
    println!("                                `yah.exec = native` by forking them on this host's");
    println!("                                own userland, capturing logs under PATH. Needed by");
    println!("                                Darwin build-workers: no container can run");
    println!("                                cargo-tauri/codesign/notarytool (default:");
    println!("                                $KAMAJI_NATIVE_EXEC_DIR, else such deploys are refused)");
    println!("      --microvm-dir PATH        supervise Container workloads marked");
    println!("                                `yah.exec = microvm` by booting each one in its own");
    println!("                                KVM guest. PATH holds the guest kernel (vmlinux),");
    println!("                                the guest rootfs (rootfs.ext4) and per-guest state.");
    println!("                                Needs /dev/kvm openable by this user and");
    println!("                                CAP_NET_ADMIN for guest networking (default:");
    println!("                                $KAMAJI_MICROVM_DIR, else such deploys are refused)");
    println!("      --bundle-cache-dir PATH   node bundle root for serving published W272 mesofact");
    println!("                                bundles: <root>/bundles, <root>/runtimes, <root>/state");
    println!("                                (default: $KAMAJI_BUNDLE_CACHE_DIR, else serve-bundle");
    println!("                                deploys are refused)");
    println!("      --bundle-origin URL       public HTTPS origin serving the published bundle");
    println!("                                store, e.g. https://cdn.yah.dev — unauthenticated;");
    println!("                                blobs are content-addressed and digest-verified");
    println!("                                (default: $KAMAJI_BUNDLE_ORIGIN; required with");
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

/// Ceiling on guest RAM for this node, in MiB (R605-F8).
///
/// A microVM's memory is a real allocation, not a cgroup ceiling, so this
/// number is the difference between "a build runs isolated" and "the node
/// starts swapping under a raft voter" — which is precisely the outcome W325's
/// whole isolation argument exists to prevent.
///
/// Half of `MemTotal` by default. Half rather than most-of because the node is
/// not idle: on the fleet's OVH boxes it is simultaneously a raft voter and a
/// yubaba, and this backend's promise is that a guest shares a node *safely*.
/// `$KAMAJI_MICROVM_MAX_MEMORY_MB` overrides it for a dedicated build worker
/// where that reasoning does not apply.
///
/// Read from `/proc/meminfo` rather than a Rust dependency: one file, one line,
/// and the alternative is a crate in the supervisor's tree for a number this
/// process reads exactly once at startup.
#[cfg(feature = "microvm")]
fn microvm_memory_cap_mb() -> u32 {
    const FLOOR_MB: u32 = 2048;

    if let Some(explicit) = std::env::var("KAMAJI_MICROVM_MAX_MEMORY_MB")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v > 0)
    {
        return explicit;
    }

    let total_kb = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.split_whitespace().next().and_then(|n| n.parse::<u64>().ok()))
        })
        .unwrap_or(0);

    let half_mb = (total_kb / 1024 / 2) as u32;
    // The floor wins on a host whose /proc is unreadable *or* genuinely tiny.
    // Both cases end the same way — `MicroVmRuntime` refuses any workload
    // requesting more than the cap, with a message naming both numbers — so
    // guessing high here does not risk an over-committed guest.
    half_mb.max(FLOOR_MB)
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

    // R555-F4 / W235 §(c): say the admission posture out loud at startup.
    //
    // `workload_spec::admission::check` resolves this lazily and caches it, so
    // without this line the first evidence a node gives of what it enforces is
    // a refusal — or, worse, a silence that looks identical whether the
    // operator's `YAH_ADMISSION` took effect or was ignored. That "did my
    // security control turn on?" question is the one this module's typo-fails-
    // closed rule already exists to answer; answering it before anything is
    // dispatched costs one line.
    let admission = workload_spec::admission::NodeAdmission::from_env();
    tracing::info!(
        policy = ?admission.policy,
        pinned_keys = admission.trusted_keys.len(),
        policy_env = workload_spec::admission::POLICY_ENV,
        keys_env = workload_spec::admission::KEYS_ENV,
        "signed-recipe admission posture (W235 §(c))"
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let ctx = build_ctx(&args).await?;
        // R755-B5: bring back every bundle the previous kamaji was serving
        // BEFORE the socket answers, so a control-plane roll is a restart of
        // the node's sites and not an undeploy of them.
        #[cfg(feature = "bundle-serving")]
        {
            let n = ctx.resume_bundle_workloads().await;
            tracing::info!(resumed = n, "recorded bundle deploys replayed (R755-B5)");
        }
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

    // ── docker / OrbStack backend (R626-F1) ──────────────────────────────────
    // The pond / dev-host counterpart to containerd. Attached only on explicit
    // opt-in; when both are attached, containerd serves Container deploys.
    #[cfg(feature = "docker-integration")]
    {
        use kamaji::Kamaji as _;
        ctx = if let Some(host) = &args.docker_host {
            let backend = if host.is_empty() {
                kamaji::docker::DockerRuntime::new()
            } else {
                kamaji::docker::DockerRuntime::with_host(host.clone())
            };
            // Fail at startup, not on the first deploy: an operator who asked
            // for docker should learn immediately that the daemon is unreachable.
            let health = backend.health().await?;
            if !health.ok {
                anyhow::bail!(
                    "docker backend requested but the daemon is unreachable{}{}",
                    if host.is_empty() {
                        " (ambient DOCKER_HOST)".to_string()
                    } else {
                        format!(" at {host}")
                    },
                    health
                        .detail
                        .map(|d| format!(": {d}"))
                        .unwrap_or_default()
                );
            }
            tracing::info!(
                docker_host = if host.is_empty() { "<inherited>" } else { host },
                version = health.version.as_deref().unwrap_or("<unknown>"),
                "docker backend attached"
            );
            ctx.with_docker(backend)
        } else {
            tracing::info!(
                "no --docker; Deploy {{ Container }} will not use a docker daemon. \
                 Pass --docker (or --docker-host URL) to supervise containers on \
                 a Docker-compatible daemon such as OrbStack."
            );
            ctx
        };
    }
    #[cfg(not(feature = "docker-integration"))]
    if args.docker_host.is_some() {
        anyhow::bail!(
            "--docker / --docker-host require the kamaji binary be built with \
             --features docker-integration"
        );
    }

    // ── native fork+exec backend (R577-T1 / W254) ────────────────────────────
    // For container-shaped workloads that cannot run in a container at all —
    // the Darwin build leg. Explicit opt-in: this backend runs argv on the
    // host's own userland with no sandbox, so it must never attach by accident.
    #[cfg(feature = "native-exec")]
    {
        ctx = if let Some(dir) = &args.native_exec_dir {
            std::fs::create_dir_all(dir).map_err(|e| {
                anyhow::anyhow!("creating native-exec state dir {}: {e}", dir.display())
            })?;
            tracing::info!(
                state_dir = %dir.display(),
                "native-exec backend attached; Container workloads marked yah.exec=native \
                 will be forked on this host"
            );
            ctx.with_native_exec(Arc::new(kamaji::native::NativeRuntime::new(dir)))
        } else {
            tracing::debug!(
                "no --native-exec-dir; native-marked Container deploys will be refused"
            );
            ctx
        };
    }
    #[cfg(not(feature = "native-exec"))]
    if args.native_exec_dir.is_some() {
        anyhow::bail!(
            "--native-exec-dir requires the kamaji binary be built with \
             --features native-exec"
        );
    }

    // ── microVM backend (R605-F8 / W325 §5) ──────────────────────────────────
    // For workloads that must not share the host kernel — a build placed next
    // to a raft voter. Explicit opt-in like the others, but the flag alone is
    // not enough: `MicroVmRuntime::new` refuses unless the node actually has a
    // guest kernel and rootfs staged, and that refusal is fatal here rather
    // than a warning. A node that was *told* to serve microVM workloads and
    // silently could not would win placements it cannot honour, and every build
    // routed to it would fail at deploy — noisily, but on the wrong node's
    // ticket. Failing to start puts the error where the misconfiguration is.
    #[cfg(feature = "microvm")]
    {
        ctx = if let Some(dir) = &args.microvm_dir {
            let state_dir = dir.join("vms");
            std::fs::create_dir_all(&state_dir).map_err(|e| {
                anyhow::anyhow!("creating microVM state dir {}: {e}", state_dir.display())
            })?;
            let cfg = kamaji::microvm::MicroVmConfig {
                vmm_bin: PathBuf::from("/usr/bin/firecracker"),
                kernel_image: dir.join("vmlinux"),
                rootfs_image: dir.join("rootfs.ext4"),
                state_dir,
                network: Some(kamaji::microvm::GuestNetwork::default()),
                max_guest_memory_mb: microvm_memory_cap_mb(),
                max_guest_vcpus: std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(1),
            };
            let runtime = kamaji::microvm::MicroVmRuntime::new(cfg)?;
            tracing::info!(
                microvm_dir = %dir.display(),
                "microVM backend attached; Container workloads marked yah.exec=microvm \
                 will be booted in their own KVM guest"
            );
            ctx.with_microvm(Arc::new(runtime))
        } else {
            tracing::debug!("no --microvm-dir; microVM-marked Container deploys will be refused");
            ctx
        };
    }
    #[cfg(not(feature = "microvm"))]
    if args.microvm_dir.is_some() {
        anyhow::bail!("--microvm-dir requires the kamaji binary be built with --features microvm");
    }

    // ── keep-alive mesofact bundle backend (R599-F10) ────────────────────────
    #[cfg(feature = "bundle-serving")]
    {
        ctx = attach_bundle_backend(ctx, args).await?;
    }
    #[cfg(not(feature = "bundle-serving"))]
    if args.bundle_cache_dir.is_some() || args.bundle_origin.is_some() {
        anyhow::bail!(
            "--bundle-cache-dir / --bundle-origin require the kamaji binary be built with \
             --features bundle-serving"
        );
    }

    Ok(Arc::new(ctx))
}

/// Attach the R599-F10 bundle backend when the node is configured for it.
///
/// Requires `--bundle-cache-dir` (the node bundle root) plus `--bundle-origin`,
/// the public HTTPS origin serving the published bundle store.
///
/// **The node holds no credentials** (R599-T5). The read leg of a
/// content-addressed store does not need one: `materialize_bundle` verifies the
/// manifest hashes to the requested digest and that every blob hashes to its
/// recorded blake3, so integrity comes from the content address rather than the
/// transport — a hostile origin cannot inject bytes. Authentication would buy
/// only confidentiality, which published bundles do not need, at the cost of a
/// write-capable secret on every box in the fleet. Publishing stays on the
/// publisher via the credentialed `R2ObjectStore`. See
/// [`HttpReadOnlyObjectStore`] for the full rationale.
///
/// With no cache dir configured this warns and leaves `ctx.bundle = None`, so a
/// serve-bundle deploy keeps returning the existing `BackendRefused`.
///
/// [`HttpReadOnlyObjectStore`]: yah_object_store::HttpReadOnlyObjectStore
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
             --bundle-origin https://cdn.yah.dev for the production path."
        );
        return Ok(ctx);
    };

    let Some(origin) = args.bundle_origin.clone() else {
        anyhow::bail!(
            "--bundle-cache-dir requires --bundle-origin (or $KAMAJI_BUNDLE_ORIGIN) — the public \
             HTTPS origin serving the published bundle store, e.g. https://cdn.yah.dev"
        );
    };

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

    // Like R2ObjectStore, this owns a `reqwest::blocking::Client`, which panics
    // if constructed inside a tokio runtime context — build it on the blocking
    // pool. Same discipline as yubaba's reconciler::bundle_store publish leg.
    let store = tokio::task::spawn_blocking({
        let origin = origin.clone();
        move || yah_object_store::HttpReadOnlyObjectStore::new(origin)
    })
    .await
    .context("bundle-store construction task panicked")?
    .context("building the read-only bundle origin store")?;

    let mut backend =
        kamaji_bin::BundleBackend::new(std::sync::Arc::new(store), &cache_dir, &state_dir);
    if let Some(port) = args.bundle_port {
        backend = backend.with_bind_port(port);
    }
    tracing::info!(
        cache_dir = %cache_dir.display(),
        origin = %origin,
        bind_port = backend.bind_port,
        "bundle backend attached (keep-alive serve_bundle workloads; \
         unauthenticated content-addressed origin)"
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

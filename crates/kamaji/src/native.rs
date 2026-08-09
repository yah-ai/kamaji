//! `Backend::Native` — direct fork+exec of a host binary (W199's "ideal
//! native-backend case"; the backend R490-F2 routes mesofact-dev through).
//!
//! Scope:
//!
//! - **fork+exec + supervise** via `tokio::process` (the R406 cgroup subtree +
//!   pidfd hardening layers in when this backend graduates to fleet hosts;
//!   desktop/CI supervision needs lifecycle, not isolation).
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

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncBufReadExt;
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;
use workload_spec::{BackoffPolicy, EnvValue, MeshIdent, RestartPolicy, WorkloadSpec};

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

/// Fixed delay before an unconditional (`RestartPolicy::Always`) respawn, so a
/// binary that exits immediately can't spin the supervisor into a hot loop.
const ALWAYS_RESTART_DELAY: Duration = Duration::from_secs(1);

/// Control messages from the `NativeRuntime` trait methods to a workload's
/// supervisor task. The supervisor owns the live `Child`; every lifecycle
/// operation that touches the process is expressed as one of these so there is
/// a single owner of the child (the loop that also drives restarts).
enum Ctrl {
    /// Stop the child and end supervision (no further restarts).
    Teardown(oneshot::Sender<()>),
    /// Stop the current child and immediately re-exec from the retained spec.
    /// Acks with the new pid (or the spawn error).
    Restart(oneshot::Sender<Result<u32>>),
    /// Adopt a pre-spawned replacement as the supervised child (graceful
    /// upgrade). The supervisor drains + reaps the outgoing process in the
    /// background (SIGQUIT → grace → SIGKILL).
    Adopt {
        replacement: SpawnedChild,
        ack: oneshot::Sender<()>,
    },
}

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
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    /// The pid of the currently-running child, or `0` when no child is running
    /// (parked between a terminal exit and a control message).
    pid: Arc<AtomicU32>,
    /// Latest lifecycle status, published by the supervisor.
    status: watch::Receiver<WorkloadStatus>,
    /// Control channel to the supervisor task.
    ctrl: mpsc::Sender<Ctrl>,
    /// The supervisor task; detached on drop.
    #[allow(dead_code)]
    task: JoinHandle<()>,
}

/// Fork+exec backend. One instance supervises any number of workloads;
/// bookkeeping lives in-process (see crash semantics above).
pub struct NativeRuntime {
    state_dir: PathBuf,
    workloads: Mutex<HashMap<String, WorkloadHandle>>,
}

impl NativeRuntime {
    /// `state_dir` holds per-workload log captures; created on demand.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            workloads: Mutex::new(HashMap::new()),
        }
    }
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

/// fork+exec one child from `spec`. `truncate_logs` truncates the capture files
/// (initial deploy) vs. appends to them (respawns, so crash-loop history is
/// preserved). `extra_env` layers on top of the spec env (used by graceful
/// upgrade to set `PASSWAY_UPGRADE=true`).
async fn spawn_child(
    state_dir: &Path,
    spec: &WorkloadSpec,
    mesh_ip: Ipv4Addr,
    extra_env: &[(&str, &str)],
    truncate_logs: bool,
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
    // Spec env layers OVER the inherited environment, so a workload can override
    // a node default without the node having to know about the workload.
    for e in &spec.env {
        if let EnvValue::Literal { value } = &e.value {
            cmd.env(&e.name, value);
        }
    }
    // Layered last so a graceful upgrade's PASSWAY_UPGRADE=true wins over any
    // (unexpected) spec-level value.
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

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

/// Exponential backoff delay for the `attempt`-th consecutive `OnFailure`
/// restart (1-based): `initial_ms * multiplier^(attempt-1)`, capped at `max_ms`.
fn backoff_delay(b: &BackoffPolicy, attempt: u32) -> Duration {
    let factor = (b.multiplier as f64).powi(attempt.saturating_sub(1) as i32);
    let ms = (b.initial_ms as f64 * factor).min(b.max_ms as f64);
    Duration::from_millis(ms as u64)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Outcome of the running-phase select: the child exited, or a control message
/// arrived (`None` = the control channel closed, i.e. the runtime was dropped).
enum Ev {
    Exited(std::io::Result<std::process::ExitStatus>),
    Ctrl(Option<Ctrl>),
}

/// Parked phase: no child is running (a terminal exit, or a respawn that failed
/// to fork). Wait for a control message that either revives the workload
/// (`Restart`/`Adopt`) or ends supervision (`Teardown` / channel closed).
async fn park(
    ctrl_rx: &mut mpsc::Receiver<Ctrl>,
    state_dir: &Path,
    spec: &WorkloadSpec,
    mesh_ip: Ipv4Addr,
    pid: &Arc<AtomicU32>,
    status_tx: &watch::Sender<WorkloadStatus>,
) -> Option<SpawnedChild> {
    loop {
        match ctrl_rx.recv().await {
            None => return None,
            Some(Ctrl::Teardown(ack)) => {
                let _ = status_tx.send(WorkloadStatus::Stopped);
                let _ = ack.send(());
                return None;
            }
            Some(Ctrl::Adopt { replacement, ack }) => {
                pid.store(replacement.pid, Ordering::SeqCst);
                let _ = status_tx.send(WorkloadStatus::Running);
                let _ = ack.send(());
                return Some(replacement);
            }
            Some(Ctrl::Restart(ack)) => {
                match spawn_child(state_dir, spec, mesh_ip, &[], false).await {
                    Ok(new) => {
                        let p = new.pid;
                        pid.store(p, Ordering::SeqCst);
                        let _ = status_tx.send(WorkloadStatus::Running);
                        let _ = ack.send(Ok(p));
                        return Some(new);
                    }
                    Err(e) => {
                        let _ = status_tx.send(WorkloadStatus::Failed {
                            reason: format!("restart respawn failed: {e}"),
                        });
                        let _ = ack.send(Err(e));
                        // stay parked, wait for the next control message
                    }
                }
            }
        }
    }
}

/// Per-workload supervisor: owns the live child, re-execs it per the retained
/// spec's [`RestartPolicy`], and serves control messages (teardown, in-place
/// restart, graceful-upgrade adopt). Exits when torn down or when the control
/// channel closes.
async fn supervise(
    state_dir: PathBuf,
    spec: WorkloadSpec,
    mesh_ip: Ipv4Addr,
    initial: SpawnedChild,
    pid: Arc<AtomicU32>,
    status_tx: watch::Sender<WorkloadStatus>,
    mut ctrl_rx: mpsc::Receiver<Ctrl>,
) {
    let mut sc = initial;
    // Consecutive failed exits, for OnFailure's max_attempts/backoff. Reset on a
    // clean exit, an in-place restart, or an adopt.
    let mut failure_streak: u32 = 0;
    // Total re-execs, for the Restarting status payload.
    let mut restart_count: u32 = 0;

    loop {
        // ── RUNNING: own `sc`; wait for it to exit or a control message. The
        //    two futures borrow disjoint locals (`sc.child` / `ctrl_rx`) and are
        //    dropped before the handler runs, so the handler can move `sc`.
        let ev = tokio::select! {
            r = sc.child.wait() => Ev::Exited(r),
            c = ctrl_rx.recv() => Ev::Ctrl(c),
        };

        match ev {
            // Control channel closed — the runtime was dropped. Stop and exit.
            Ev::Ctrl(None) => {
                stop_child(&mut sc.child, sc.pid).await;
                return;
            }
            Ev::Ctrl(Some(Ctrl::Teardown(ack))) => {
                stop_child(&mut sc.child, sc.pid).await;
                pid.store(0, Ordering::SeqCst);
                let _ = status_tx.send(WorkloadStatus::Stopped);
                let _ = ack.send(());
                return;
            }
            Ev::Ctrl(Some(Ctrl::Restart(ack))) => {
                stop_child(&mut sc.child, sc.pid).await;
                pid.store(0, Ordering::SeqCst);
                match spawn_child(&state_dir, &spec, mesh_ip, &[], false).await {
                    Ok(new) => {
                        restart_count += 1;
                        failure_streak = 0;
                        let p = new.pid;
                        pid.store(p, Ordering::SeqCst);
                        let _ = status_tx.send(WorkloadStatus::Running);
                        sc = new;
                        let _ = ack.send(Ok(p));
                    }
                    Err(e) => {
                        let _ = status_tx.send(WorkloadStatus::Failed {
                            reason: format!("restart respawn failed: {e}"),
                        });
                        let _ = ack.send(Err(e));
                        match park(&mut ctrl_rx, &state_dir, &spec, mesh_ip, &pid, &status_tx).await
                        {
                            Some(new) => {
                                restart_count += 1;
                                failure_streak = 0;
                                sc = new;
                            }
                            None => return,
                        }
                    }
                }
            }
            Ev::Ctrl(Some(Ctrl::Adopt { replacement, ack })) => {
                // Graceful upgrade: the caller already spawned + settled the
                // replacement. Drain+reap the outgoing process and adopt the new
                // one; the main loop now supervises the replacement.
                drain_reaper(sc);
                restart_count += 1;
                failure_streak = 0;
                pid.store(replacement.pid, Ordering::SeqCst);
                let _ = status_tx.send(WorkloadStatus::Running);
                sc = replacement;
                let _ = ack.send(());
            }
            Ev::Exited(res) => {
                let exit_code = match &res {
                    Ok(s) => s.code().unwrap_or(-1),
                    Err(_) => -1,
                };
                let succeeded = matches!(&res, Ok(s) if s.success());
                pid.store(0, Ordering::SeqCst);

                let should_restart = match &spec.restart_policy {
                    RestartPolicy::Always => true,
                    RestartPolicy::Never => false,
                    RestartPolicy::OnFailure { max_attempts, .. } => {
                        !succeeded && failure_streak < *max_attempts
                    }
                };

                if !should_restart {
                    // Terminal: park until a control message arrives.
                    let terminal = if succeeded {
                        WorkloadStatus::Stopped
                    } else {
                        WorkloadStatus::Failed {
                            reason: match &res {
                                Ok(s) => format!("exited with {s} (no restart)"),
                                Err(e) => format!("wait failed: {e}"),
                            },
                        }
                    };
                    let _ = status_tx.send(terminal);
                    match park(&mut ctrl_rx, &state_dir, &spec, mesh_ip, &pid, &status_tx).await {
                        Some(new) => {
                            restart_count += 1;
                            failure_streak = 0;
                            sc = new;
                            continue;
                        }
                        None => return,
                    }
                }

                // Restarting: publish the rich status, back off, respawn.
                restart_count += 1;
                if !succeeded {
                    failure_streak += 1;
                }
                let _ = status_tx.send(WorkloadStatus::Restarting {
                    last_exit_code: exit_code,
                    restart_count,
                    last_finished_at_unix_ms: now_ms(),
                });

                let delay = match &spec.restart_policy {
                    RestartPolicy::Always => ALWAYS_RESTART_DELAY,
                    RestartPolicy::OnFailure { backoff, .. } => {
                        backoff_delay(backoff, failure_streak)
                    }
                    // Unreachable: should_restart is false for Never.
                    RestartPolicy::Never => Duration::ZERO,
                };

                // Interruptible backoff: a teardown (or a closed channel) during
                // the wait wins instead of blocking for the whole delay.
                let interrupted = tokio::select! {
                    _ = tokio::time::sleep(delay) => None,
                    c = ctrl_rx.recv() => Some(c),
                };
                match interrupted {
                    None => {} // backoff elapsed → fall through to respawn
                    Some(None) => return,
                    Some(Some(Ctrl::Teardown(ack))) => {
                        let _ = status_tx.send(WorkloadStatus::Stopped);
                        let _ = ack.send(());
                        return;
                    }
                    Some(Some(Ctrl::Adopt { replacement, ack })) => {
                        failure_streak = 0;
                        pid.store(replacement.pid, Ordering::SeqCst);
                        let _ = status_tx.send(WorkloadStatus::Running);
                        sc = replacement;
                        let _ = ack.send(());
                        continue;
                    }
                    Some(Some(Ctrl::Restart(ack))) => {
                        match spawn_child(&state_dir, &spec, mesh_ip, &[], false).await {
                            Ok(new) => {
                                failure_streak = 0;
                                let p = new.pid;
                                pid.store(p, Ordering::SeqCst);
                                let _ = status_tx.send(WorkloadStatus::Running);
                                sc = new;
                                let _ = ack.send(Ok(p));
                                continue;
                            }
                            Err(e) => {
                                let _ = status_tx.send(WorkloadStatus::Failed {
                                    reason: format!("restart respawn failed: {e}"),
                                });
                                let _ = ack.send(Err(e));
                                match park(
                                    &mut ctrl_rx,
                                    &state_dir,
                                    &spec,
                                    mesh_ip,
                                    &pid,
                                    &status_tx,
                                )
                                .await
                                {
                                    Some(new) => {
                                        failure_streak = 0;
                                        sc = new;
                                        continue;
                                    }
                                    None => return,
                                }
                            }
                        }
                    }
                }

                // Backoff elapsed uninterrupted: respawn.
                match spawn_child(&state_dir, &spec, mesh_ip, &[], false).await {
                    Ok(new) => {
                        pid.store(new.pid, Ordering::SeqCst);
                        let _ = status_tx.send(WorkloadStatus::Running);
                        sc = new;
                    }
                    Err(e) => {
                        let _ = status_tx.send(WorkloadStatus::Failed {
                            reason: format!("respawn failed: {e}"),
                        });
                        match park(&mut ctrl_rx, &state_dir, &spec, mesh_ip, &pid, &status_tx).await
                        {
                            Some(new) => {
                                failure_streak = 0;
                                sc = new;
                            }
                            None => return,
                        }
                    }
                }
            }
        }
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
        let ident = spec.expose.mesh.identity.clone();

        // Idempotent: clear any prior workload with the same identity.
        self.teardown_workload(&ident).await?;

        // Spawn the first child synchronously so spawn errors (bad binary path,
        // empty argv) surface to the caller instead of failing in the
        // background supervisor.
        let initial = spawn_child(&self.state_dir, spec, mesh.mesh_ip, &[], true).await?;
        let start_pid = initial.pid;
        let stdout_path = initial.stdout_path.clone();
        let stderr_path = initial.stderr_path.clone();

        let pid = Arc::new(AtomicU32::new(start_pid));
        let (status_tx, status_rx) = watch::channel(WorkloadStatus::Running);
        let (ctrl_tx, ctrl_rx) = mpsc::channel(8);
        let task = tokio::spawn(supervise(
            self.state_dir.clone(),
            spec.clone(),
            mesh.mesh_ip,
            initial,
            Arc::clone(&pid),
            status_tx,
            ctrl_rx,
        ));

        self.workloads.lock().await.insert(
            ident.0,
            WorkloadHandle {
                mesh_ip: mesh.mesh_ip,
                stdout_path,
                stderr_path,
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

        // 1. Start the replacement in upgrade mode. It connects to the shared
        //    upgrade socket and receives the old process's listening fds instead
        //    of binding fresh.
        let mut replacement = spawn_child(
            &self.state_dir,
            spec,
            mesh.mesh_ip,
            &[("PASSWAY_UPGRADE", "true")],
            false,
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
        RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag,
    };

    fn native_spec(name: &str, argv: Vec<String>) -> WorkloadSpec {
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
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
                ephemeral_storage_mb: 128,
            },
            depends_on: vec![],
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

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
use crate::socket_custody::{netns_path, SocketCustodian};
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
    /// pid of the currently-live serve child, or `0` when idle (no resident
    /// process — the whole point of the on-demand tier).
    pid: Arc<AtomicU32>,
    status: watch::Receiver<WorkloadStatus>,
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
}

impl JitRuntime {
    /// `state_dir` holds each workload's stdout/stderr capture (per fork,
    /// appended so re-fork history is preserved), same as the native backend.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            custodian: Arc::new(SocketCustodian::new()),
            state_dir: state_dir.into(),
            workloads: Mutex::new(HashMap::new()),
        }
    }

    /// Deploy an on-demand workload. kamaji binds+holds `listen_addr` (optionally
    /// inside the mesh netns from `mesh`), then arms the poll-fork-rearm loop.
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

        // Bind + hold the listen socket. This is what outlives every forked
        // child; the netns (if any) keeps the bound socket routable.
        let netns = mesh.netns_name.as_deref().map(netns_path);
        self.custodian
            .bind_and_hold(&ident.0, listen_addr, netns.as_deref())
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

        let pid = Arc::new(AtomicU32::new(0));
        let (status_tx, status_rx) = watch::channel(WorkloadStatus::Pending);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(supervise_on_demand(
            self.state_dir.clone(),
            spec.clone(),
            mesh.mesh_ip,
            listen_fd,
            Arc::clone(&pid),
            status_tx,
            shutdown_rx,
        ));

        self.workloads.lock().await.insert(
            ident.0.clone(),
            JitHandle {
                mesh_ip: mesh.mesh_ip,
                pid,
                status: status_rx,
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
        if let Some(handle) = handle {
            // Signal shutdown and wait for the supervisor to stop the child and
            // exit before we close the socket out from under it.
            let _ = handle.shutdown.send(true);
            let _ = handle.task.await;
        }
        // Close the held listener (safe now that the supervisor has stopped
        // polling / handing off the fd). Idempotent if never bound.
        self.custodian.release(&ident.0);
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
async fn supervise_on_demand(
    state_dir: PathBuf,
    spec: WorkloadSpec,
    mesh_ip: Ipv4Addr,
    listen_fd: RawFd,
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
                    let _ = status_tx.send(WorkloadStatus::Failed {
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
        let mut child = match spawn_jit_child(&state_dir, &spec, mesh_ip, listen_fd) {
            Ok(c) => c,
            Err(e) => {
                let _ = status_tx.send(WorkloadStatus::Failed {
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
/// `spec` (same shape the native backend forks), plus `LISTEN_FDS=1` and the
/// `YAH_MESH_IP` injection.
///
/// The child's argv is expected to carry `--idle-ttl <secs>` so the runtime
/// self-reaps; kamaji does not own idle detection.
fn spawn_jit_child(
    state_dir: &Path,
    spec: &WorkloadSpec,
    mesh_ip: Ipv4Addr,
    listen_fd: RawFd,
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
    for e in &spec.env {
        if let EnvValue::Literal { value } = &e.value {
            cmd.env(&e.name, value);
        }
    }

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

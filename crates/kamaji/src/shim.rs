//! `kamaji shim` — the per-workload parent that outlives kamaji (R1021-F2, W386 §1).
//!
//! A native workload forked straight from kamaji dies with kamaji, or survives
//! as an orphan whose exit status nobody can ever read (W386 spike T2:
//! `waitid(P_PIDFD)` → `ECHILD`). The shim closes that: it is the workload's
//! real parent, it latches the exit status, and it answers whichever kamaji
//! connects to it — the one that started it or the next one after a restart.
//!
//! # Shape
//!
//! - **Same binary, `shim` subcommand.** No new release artifact. Synchronous,
//!   threads only, no tokio: it does one job and must not share kamaji's
//!   failure modes.
//! - **Lifetime = one child.** The shim spawns exactly one workload process.
//!   When it exits the status is latched until a kamaji sends `ack_exit`, then
//!   the shim exits. A respawn is a new shim; the restart loop and its policy
//!   stay in kamaji's [`crate::supervise`].
//! - **Cgroups.** The shim joins the one shared leaf `<delegated root>/_shim/`
//!   ([`SHIM_LEAF`]; no mesh ident can contain `_`),
//!   never the workload's leaf: the workload's `memory.max` must not charge the
//!   shim, and an OOM there must not kill the one process that knows the exit
//!   status. The child joins `<ident>/<gen>/` in the same pre-exec hook the
//!   direct fork path uses ([`LaunchPlan::command`] is that path, shared).
//! - **Not in the data path.** stdout/stderr are the `O_APPEND` capture files,
//!   opened by the shim and handed to the child before exec. No pipes.
//!
//! # Rendezvous
//!
//! `<state_dir>/<ident>/shim.sock` — under the unit's `StateDirectory`, **never
//! `RuntimeDirectory`**: systemd deletes the latter on every stop, and W386
//! spike T3 measured the next kamaji then starting a second shim and a second
//! workload beside the live one. `sun_path` is 108 bytes on Linux (104 on
//! macOS); an over-long path fails the deploy loudly ([`check_socket_path`]).
//!
//! # Protocol (`proto` 1)
//!
//! Line-delimited JSON. On every connection the shim first sends
//! `{"event":"hello", proto, ident, generation, spec_digest, shim_pid,
//! child_pid, child_start, boot_id, last_exit}` — on Linux with the child's
//! pidfd attached via `SCM_RIGHTS` to that same write. `last_exit` is non-null
//! when the child has already exited, which is how an adopting kamaji (R1021-F3)
//! learns an exit that happened while no kamaji was connected. Otherwise
//! `{"event":"exit","code":N}` or `{"event":"exit","signal":N}` is pushed to
//! every connected client when the child exits.
//!
//! **JIT mode** (R1021-F7, a request carrying `jit`): the shim binds and holds
//! the workload's listener and runs the poll → fork → wait → re-arm loop that
//! used to live in kamaji's `jit.rs`, so connections queue on a socket that
//! outlives kamaji. `hello` carries `"mode":"jit"` and `listen_addr`;
//! `child_pid` is the live fork (`0` idle). Events per fork: `{"event":
//! "forked","pid":N}`, then `exit`; a failed fork is `fork_failed` and a 1s
//! backoff. `{"op":"stop","grace_ms":N}` TERMs the live fork, KILLs it after the
//! grace, closes the listener, removes the socket and exits.
//!
//! Client verbs: `{"op":"signal","sig":N}` (ignored once the child has exited,
//! so a latched pid can never be re-signalled after reuse) and `{"op":"ack_exit"}`
//! (ignored until the child has exited; then the shim removes its socket — only
//! if the path is still its own inode — and exits 0). Neither verb is answered:
//! the only server→client traffic is `hello` and `exit`.
//!
//! # Launch handshake
//!
//! kamaji spawns `<program> <args…>` with the [`ShimRequest`] JSON on stdin and
//! reads the shim's stdout until a line starting `KAMAJI-SHIM-READY` (socket
//! bound, child running) or `KAMAJI-SHIM-ERR` (with the reason). Lines without
//! the prefix are skipped, so a test harness's own banner is harmless. After
//! the ready line the shim points fd 1 at `/dev/null`; its diagnostics go to
//! stderr, which kamaji opens as `<state_dir>/<ident>/shim.log`.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use workload_spec::WorkloadSpec;

/// Protocol version carried in `hello`. Bump on any incompatible wire change;
/// R1021-F3's adoption treats a mismatch as "stop it and restart under a
/// current shim".
pub const PROTO: u32 = 1;

/// The socket's file name inside `<state_dir>/<ident>/`.
pub const SOCKET_NAME: &str = "shim.sock";

/// The persisted spec's file name inside `<state_dir>/<ident>/`.
pub const SPEC_NAME: &str = "spec.json";

/// The shared cgroup leaf every shim joins, under the delegated root.
///
/// `_shim`, not W386's `shim`: workload nodes are named by mesh ident in the
/// same directory, and an ident is `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`
/// (dot-joined segments for forge), so it can never contain `_` — a workload
/// called `shim` gets its own node instead of sharing the shims' leaf.
pub const SHIM_LEAF: &str = "_shim";

const READY: &str = "KAMAJI-SHIM-READY";
const ERR: &str = "KAMAJI-SHIM-ERR";

/// How kamaji starts a shim: `program args…`, with `env` added.
///
/// [`ShimLauncher::this_binary`] is the production shape — the running kamaji
/// re-exec'd as `kamaji shim`. Tests point it at their own harness binary with
/// a filter that lands in a function calling [`run_from_stdin`].
#[derive(Clone, Debug)]
pub struct ShimLauncher {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

impl ShimLauncher {
    /// The running executable, as `<exe> shim`.
    pub fn this_binary() -> std::io::Result<Self> {
        Ok(Self {
            program: std::env::current_exe()?,
            args: vec!["shim".to_string()],
            env: Vec::new(),
        })
    }
}

/// What kamaji hands a shim on stdin.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ShimRequest {
    pub ident: String,
    pub generation: String,
    /// R870-B24's `kamaji_proto::spec_digest` of the envelope this workload was
    /// deployed from, hex — computed by kamaji-bin, opaque here, echoed in
    /// `hello` so an adopting kamaji can report it in `List` (R1021-F3).
    pub spec_digest: Option<String>,
    pub socket: PathBuf,
    /// The shared shim leaf to join, when the host delegates a subtree.
    pub shim_cgroup: Option<PathBuf>,
    pub plan: crate::native::LaunchPlan,
    /// R1021-F7: present → JIT mode. The shim binds and holds this listener
    /// and forks `plan` per readiness instead of spawning it once.
    #[serde(default)]
    pub jit: Option<JitRequest>,
}

/// What a JIT-mode shim needs beyond the launch plan (R1021-F7).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JitRequest {
    /// `host:port` the shim binds — the address the workload serves on.
    pub listen_addr: String,
}

/// Which lifecycle a shim runs (R1021-F7). Reported in `hello`, so an
/// adopting kamaji hands the shim to the runtime that speaks it — the bundle
/// tier's native and JIT runtimes share one state dir.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShimMode {
    /// One child, spawned at start; the shim exits after `ack_exit`.
    #[default]
    Process,
    /// Holds a listener; forks a child per readiness, re-arms on its exit,
    /// lives until `stop`.
    Jit,
}

/// How the child ended. Exactly one of the two is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
}

impl ExitReport {
    fn of(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt as _;
        Self {
            code: status.code(),
            signal: status.signal(),
        }
    }

    /// Back to the `ExitStatus` the supervisor's `settle` already understands.
    pub fn to_status(self) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;
        let raw = match (self.code, self.signal) {
            (Some(code), _) => (code & 0xff) << 8,
            (None, Some(sig)) => sig & 0x7f,
            (None, None) => 0xff << 8,
        };
        std::process::ExitStatus::from_raw(raw)
    }
}

/// The first line of every connection. Carries everything R1021-F3 needs to
/// decide to adopt: version, identity, which generation leaf, which spec, and
/// enough of the child's identity (pid + start time + boot) to rule out reuse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub proto: u32,
    pub ident: String,
    pub generation: String,
    pub spec_digest: Option<String>,
    pub shim_pid: u32,
    pub child_pid: u32,
    pub child_start: Option<String>,
    pub boot_id: Option<String>,
    pub last_exit: Option<ExitReport>,
    /// R1021-F7. In JIT mode `child_pid` is the serve process currently
    /// forked, `0` while idle, and `last_exit` the previous fork's.
    #[serde(default)]
    pub mode: ShimMode,
    /// JIT mode: the address the held listener is bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,
}

/// Server → client.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ShimEvent {
    Hello(Hello),
    /// Process mode: the one child ended. JIT mode: this fork ended; the shim
    /// re-arms.
    Exit(ExitReport),
    /// JIT mode: a connection was pending and a serve process was forked.
    Forked { pid: u32 },
    /// JIT mode: the fork failed; the shim re-arms after a backoff.
    ForkFailed { reason: String },
}

/// Client → server.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ShimOp {
    Signal { sig: i32 },
    AckExit,
    /// JIT mode: stop re-arming, TERM the live fork (KILL after `grace_ms`),
    /// close the listener, remove the socket, exit.
    Stop { grace_ms: u64 },
}

/// Refuse a socket path the kernel would truncate or reject.
pub fn check_socket_path(path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    const SUN_PATH: usize = 108;
    #[cfg(not(target_os = "linux"))]
    const SUN_PATH: usize = 104;
    let len = path.as_os_str().len();
    if len >= SUN_PATH {
        bail!(
            "shim socket path {} is {len} bytes; sun_path holds {} — shorten the state dir or \
             the workload identity",
            path.display(),
            SUN_PATH - 1
        );
    }
    Ok(())
}

/// The kernel's boot id; a pid is only an identity within one boot.
pub(crate) fn boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
}

/// Write straight to fd 1, bypassing any stdout capture (a libtest harness
/// captures `print!` but not the descriptor).
fn emit(line: &str) {
    use std::os::fd::FromRawFd as _;
    // SAFETY: fd 1 is open for the process's life; ManuallyDrop keeps us from
    // closing it.
    let mut out = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(1) });
    // Leading newline: a harness may have left a partial line on fd 1.
    let _ = out.write_all(format!("\n{line}\n").as_bytes());
    let _ = out.flush();
}

/// Entry point for `kamaji shim`. Reads a [`ShimRequest`] from stdin and does
/// not return while the shim has work to do; returns a process exit code.
pub fn run_from_stdin() -> i32 {
    let mut raw = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut raw) {
        emit(&format!("{ERR} reading the request: {e}"));
        return 2;
    }
    let req: ShimRequest = match serde_json::from_str(&raw) {
        Ok(r) => r,
        Err(e) => {
            emit(&format!("{ERR} parsing the request: {e}"));
            return 2;
        }
    };
    match serve(req) {
        Ok(code) => code,
        Err(e) => {
            emit(&format!("{ERR} {e:#}"));
            1
        }
    }
}

struct State {
    exit: Option<ExitReport>,
    clients: Vec<UnixStream>,
}

fn write_event(stream: &mut UnixStream, event: &ShimEvent) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(event).map_err(std::io::Error::other)?;
    line.push(b'\n');
    stream.write_all(&line)
}

fn serve(req: ShimRequest) -> Result<i32> {
    // Out of kamaji's session and process group: nothing aimed at kamaji's
    // group (a terminal ^C on a dev box, a group kill) reaches the shim.
    // SAFETY: plain setsid(2); failure (already a leader) is harmless.
    unsafe {
        libc::setsid();
    }

    if let Some(leaf) = &req.shim_cgroup {
        join_shim_leaf(leaf);
    }

    check_socket_path(&req.socket)?;
    // A stale path (a dead predecessor, or a live one being replaced by a
    // graceful upgrade) is unlinked: the canonical path names the newest shim.
    let _ = std::fs::remove_file(&req.socket);
    let listener = UnixListener::bind(&req.socket)
        .with_context(|| format!("binding {}", req.socket.display()))?;
    let our_inode = inode(&req.socket);

    if let Some(jit) = &req.jit {
        return serve_jit(&req, jit, listener, our_inode);
    }

    let mut child = req
        .plan
        .command()?
        .spawn()
        .with_context(|| format!("spawning {} for workload {}", req.plan.argv[0], req.ident))?;
    let child_pid = child.id();
    let child_start = crate::orphan::start_time(child_pid);
    let pidfd = pidfd::open(child_pid);

    let hello = Hello {
        proto: PROTO,
        ident: req.ident.clone(),
        generation: req.generation.clone(),
        spec_digest: req.spec_digest.clone(),
        shim_pid: std::process::id(),
        child_pid,
        child_start,
        boot_id: boot_id(),
        last_exit: None,
        mode: ShimMode::Process,
        listen_addr: None,
    };

    let state = Arc::new(Mutex::new(State {
        exit: None,
        clients: Vec::new(),
    }));

    {
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let report = match child.wait() {
                Ok(status) => ExitReport::of(status),
                Err(_) => ExitReport {
                    code: None,
                    signal: None,
                },
            };
            let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
            st.exit = Some(report);
            let event = ShimEvent::Exit(report);
            st.clients.retain_mut(|c| write_event(c, &event).is_ok());
        });
    }

    emit(&format!("{READY} {child_pid}"));
    // fd 1 back to /dev/null: nobody reads it past the handshake.
    if let Ok(null) = std::fs::OpenOptions::new().write(true).open("/dev/null") {
        use std::os::fd::AsRawFd as _;
        // SAFETY: dup2 onto fd 1 of a descriptor we hold.
        unsafe {
            libc::dup2(null.as_raw_fd(), 1);
        }
    }

    for conn in listener.incoming() {
        let Ok(mut conn) = conn else { continue };
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        let mut hello = hello.clone();
        hello.last_exit = st.exit;
        if send_hello(&mut conn, &hello, pidfd.as_ref()).is_err() {
            continue;
        }
        let Ok(writer) = conn.try_clone() else { continue };
        if st.exit.is_none() {
            st.clients.push(writer);
        }
        drop(st);

        let state = Arc::clone(&state);
        let socket = req.socket.clone();
        let pidfd_raw = pidfd.as_ref().map(|fd| {
            use std::os::fd::AsRawFd as _;
            fd.as_raw_fd()
        });
        std::thread::spawn(move || {
            for line in BufReader::new(conn).lines() {
                let Ok(line) = line else { break };
                let Ok(op) = serde_json::from_str::<ShimOp>(&line) else {
                    eprintln!("kamaji shim: ignoring an unparseable op: {line}");
                    continue;
                };
                let st = state.lock().unwrap_or_else(|p| p.into_inner());
                match op {
                    // Under the lock, so the waiter cannot latch (the pid
                    // becoming reusable) between the check and the kill.
                    ShimOp::Signal { sig } if st.exit.is_none() => {
                        pidfd::signal(pidfd_raw, child_pid, sig);
                    }
                    ShimOp::Signal { .. } => {}
                    ShimOp::AckExit if st.exit.is_some() => {
                        if inode(&socket) == our_inode {
                            let _ = std::fs::remove_file(&socket);
                        }
                        std::process::exit(0);
                    }
                    ShimOp::AckExit | ShimOp::Stop { .. } => {}
                }
            }
        });
    }
    Ok(0)
}

/// How long a JIT shim backs off after a failed fork, so a broken serve binary
/// does not hot-loop forks on a hammered port (R599-F6's backoff, moved here).
const JIT_FORK_FAIL_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);

/// How often the idle JIT loop looks up from `poll(2)` to notice a `stop`.
const JIT_POLL_MS: i32 = 200;

struct JitState {
    /// The live fork, `0` while idle.
    child_pid: u32,
    child_start: Option<String>,
    pidfd: Option<std::os::fd::OwnedFd>,
    last_exit: Option<ExitReport>,
    stopping: bool,
    clients: Vec<UnixStream>,
}

impl JitState {
    fn broadcast(&mut self, event: &ShimEvent) {
        self.clients.retain_mut(|c| write_event(c, event).is_ok());
    }

    /// Signal the live fork, if any. Under the state lock, so the loop cannot
    /// clear the pid (the reap) between the check and the kill.
    fn signal_child(&self, sig: i32) {
        if self.child_pid != 0 {
            use std::os::fd::AsRawFd as _;
            pidfd::signal(self.pidfd.as_ref().map(|f| f.as_raw_fd()), self.child_pid, sig);
        }
    }
}

/// JIT mode (R1021-F7): the shim is the custodian of the workload's listener
/// and runs R599-F6's poll → fork → wait → re-arm loop, so connections queue on
/// a socket that outlives kamaji and are served by a fork nobody replays.
/// Idle detection stays with the serve runtime (`--idle-ttl`): a child that
/// self-reaps is just an exit, and the loop re-arms. Lives until `stop`.
fn serve_jit(
    req: &ShimRequest,
    jit: &JitRequest,
    listener: UnixListener,
    our_inode: Option<(u64, u64)>,
) -> Result<i32> {
    use std::os::fd::AsRawFd as _;
    let tcp = std::net::TcpListener::bind(&jit.listen_addr)
        .with_context(|| format!("binding on-demand listen socket {}", jit.listen_addr))?;
    let listen_addr = tcp.local_addr()?.to_string();
    let listen_fd = tcp.as_raw_fd();

    let hello = Hello {
        proto: PROTO,
        ident: req.ident.clone(),
        generation: req.generation.clone(),
        spec_digest: req.spec_digest.clone(),
        shim_pid: std::process::id(),
        child_pid: 0,
        child_start: None,
        boot_id: boot_id(),
        last_exit: None,
        mode: ShimMode::Jit,
        listen_addr: Some(listen_addr.clone()),
    };
    let state = Arc::new(Mutex::new(JitState {
        child_pid: 0,
        child_start: None,
        pidfd: None,
        last_exit: None,
        stopping: false,
        clients: Vec::new(),
    }));

    emit(&format!("{READY} {listen_addr}"));
    if let Ok(null) = std::fs::OpenOptions::new().write(true).open("/dev/null") {
        // SAFETY: dup2 onto fd 1 of a descriptor we hold.
        unsafe {
            libc::dup2(null.as_raw_fd(), 1);
        }
    }

    {
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { continue };
                let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
                let mut hello = hello.clone();
                hello.child_pid = st.child_pid;
                hello.child_start = st.child_start.clone();
                hello.last_exit = st.last_exit;
                if write_event(&mut conn, &ShimEvent::Hello(hello)).is_err() {
                    continue;
                }
                let Ok(writer) = conn.try_clone() else { continue };
                st.clients.push(writer);
                drop(st);
                let state = Arc::clone(&state);
                std::thread::spawn(move || jit_client(conn, &state));
            }
        });
    }

    loop {
        if state.lock().unwrap_or_else(|p| p.into_inner()).stopping {
            break;
        }
        let mut pfd = libc::pollfd {
            fd: listen_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll(2) on one pollfd we own for the call.
        let ready = unsafe { libc::poll(&mut pfd, 1, JIT_POLL_MS) };
        if ready <= 0 || pfd.revents & libc::POLLIN == 0 {
            continue;
        }

        // Spawn under the lock, so a `stop` racing the fork either wins (no
        // fork) or sees the pid to TERM.
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        if st.stopping {
            break;
        }
        let spawned = req
            .plan
            .command_with_listen_fd(listen_fd)
            .and_then(|mut cmd| {
                cmd.spawn().with_context(|| {
                    format!("forking {} for on-demand workload {}", req.plan.argv[0], req.ident)
                })
            });
        let mut child = match spawned {
            Ok(child) => child,
            Err(e) => {
                let reason = format!("{e:#}");
                eprintln!("kamaji shim: on-demand fork failed: {reason}");
                st.broadcast(&ShimEvent::ForkFailed { reason });
                drop(st);
                std::thread::sleep(JIT_FORK_FAIL_BACKOFF);
                continue;
            }
        };
        let pid = child.id();
        st.child_pid = pid;
        st.child_start = crate::orphan::start_time(pid);
        st.pidfd = pidfd::open(pid);
        st.broadcast(&ShimEvent::Forked { pid });
        drop(st);

        let report = match child.wait() {
            Ok(status) => ExitReport::of(status),
            Err(_) => ExitReport {
                code: None,
                signal: None,
            },
        };
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        st.child_pid = 0;
        st.child_start = None;
        st.pidfd = None;
        st.last_exit = Some(report);
        st.broadcast(&ShimEvent::Exit(report));
    }

    drop(tcp);
    if inode(&req.socket) == our_inode {
        let _ = std::fs::remove_file(&req.socket);
    }
    Ok(0)
}

/// One kamaji connection to a JIT shim: `signal` reaches the live fork, `stop`
/// ends the shim (after the fork, if any, has gone).
fn jit_client(conn: UnixStream, state: &Arc<Mutex<JitState>>) {
    for line in BufReader::new(conn).lines() {
        let Ok(line) = line else { break };
        let Ok(op) = serde_json::from_str::<ShimOp>(&line) else {
            eprintln!("kamaji shim: ignoring an unparseable op: {line}");
            continue;
        };
        let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
        match op {
            ShimOp::Signal { sig } => st.signal_child(sig),
            ShimOp::Stop { grace_ms } => {
                st.stopping = true;
                let pid = st.child_pid;
                if pid == 0 {
                    continue;
                }
                st.signal_child(libc::SIGTERM);
                drop(st);
                let state = Arc::clone(state);
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(grace_ms));
                    let st = state.lock().unwrap_or_else(|p| p.into_inner());
                    if st.child_pid == pid {
                        st.signal_child(libc::SIGKILL);
                    }
                });
            }
            ShimOp::AckExit => {}
        }
    }
}

fn inode(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

#[cfg(target_os = "linux")]
fn join_shim_leaf(leaf: &Path) {
    let attach = std::fs::create_dir_all(leaf).and_then(|()| {
        std::fs::write(leaf.join("cgroup.procs"), std::process::id().to_string())
    });
    if let Err(e) = attach {
        eprintln!(
            "kamaji shim: could not join the shim leaf {}: {e}; staying in the inherited cgroup",
            leaf.display()
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn join_shim_leaf(_leaf: &Path) {}

#[cfg(target_os = "linux")]
fn send_hello(
    conn: &mut UnixStream,
    hello: &Hello,
    pidfd: Option<&std::os::fd::OwnedFd>,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let mut line = serde_json::to_vec(&ShimEvent::Hello(hello.clone()))
        .map_err(std::io::Error::other)?;
    line.push(b'\n');
    let Some(fd) = pidfd else {
        return conn.write_all(&line);
    };
    // The pidfd rides the first byte(s) of the hello; any tail is a plain write.
    let raw = fd.as_raw_fd();
    let fds = [raw];
    let iov = [std::io::IoSlice::new(&line)];
    let cmsg = [nix::sys::socket::ControlMessage::ScmRights(&fds)];
    let sent = nix::sys::socket::sendmsg::<()>(
        conn.as_raw_fd(),
        &iov,
        &cmsg,
        nix::sys::socket::MsgFlags::empty(),
        None,
    )
    .map_err(std::io::Error::from)?;
    conn.write_all(&line[sent..])
}

#[cfg(not(target_os = "linux"))]
fn send_hello(
    conn: &mut UnixStream,
    hello: &Hello,
    _pidfd: Option<&std::os::fd::OwnedFd>,
) -> std::io::Result<()> {
    write_event(conn, &ShimEvent::Hello(hello.clone()))
}

mod pidfd {
    use std::os::fd::OwnedFd;

    #[cfg(target_os = "linux")]
    pub(super) fn open(pid: u32) -> Option<OwnedFd> {
        use std::os::fd::FromRawFd as _;
        // SAFETY: pidfd_open(2) with flags 0; a non-negative return is a new fd
        // we own.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn open(_pid: u32) -> Option<OwnedFd> {
        None
    }

    /// Signal the child, by pidfd where the kernel has one.
    pub(super) fn signal(pidfd: Option<i32>, pid: u32, sig: i32) {
        #[cfg(target_os = "linux")]
        if let Some(fd) = pidfd {
            // SAFETY: pidfd_send_signal(2) on a pidfd we hold open.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd,
                    sig,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                )
            };
            if rc == 0 {
                return;
            }
        }
        let _ = pidfd;
        // SAFETY: kill(2) on our own unreaped child (the caller holds the
        // lock that orders this before the reap is latched).
        unsafe {
            libc::kill(pid as libc::pid_t, sig);
        }
    }
}

// ─── kamaji side ────────────────────────────────────────────────────────────

/// kamaji's end of one shim connection.
///
/// A reader task owns the read half and publishes the exit on a `watch`, so
/// waiting is cancel-safe inside `select!` (the deadline arm) and an
/// "exited yet?" probe never blocks.
pub(crate) struct ShimConn {
    pub hello: Hello,
    writer: tokio::net::unix::OwnedWriteHalf,
    exit: tokio::sync::watch::Receiver<Option<Result<ExitReport, String>>>,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for ShimConn {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl ShimConn {
    pub(crate) async fn connect(socket: &Path) -> Result<Self> {
        use tokio::io::AsyncBufReadExt as _;
        let stream = tokio::net::UnixStream::connect(socket)
            .await
            .with_context(|| format!("connecting to shim at {}", socket.display()))?;
        let (read, writer) = stream.into_split();
        let mut lines = tokio::io::BufReader::new(read).lines();
        let hello = read_hello(&mut lines, socket).await?;
        let (tx, rx) = tokio::sync::watch::channel(hello.last_exit.map(Ok));
        let reader = tokio::spawn(async move {
            if tx.borrow().is_some() {
                return;
            }
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        if let Ok(ShimEvent::Exit(report)) = serde_json::from_str(&line) {
                            let _ = tx.send(Some(Ok(report)));
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = tx.send(Some(Err("shim closed without an exit".into())));
                        return;
                    }
                    Err(e) => {
                        let _ = tx.send(Some(Err(format!("reading from shim: {e}"))));
                        return;
                    }
                }
            }
        });
        Ok(Self {
            hello,
            writer,
            exit: rx,
            reader,
        })
    }

    /// Wait for the child's exit. Cancel-safe.
    pub(crate) async fn wait_exit(&mut self) -> std::io::Result<ExitReport> {
        let got = self
            .exit
            .wait_for(Option::is_some)
            .await
            .map_err(|_| std::io::Error::other("shim reader ended"))?;
        match got.as_ref().expect("waited for Some") {
            Ok(r) => Ok(*r),
            Err(e) => Err(std::io::Error::other(e.clone())),
        }
    }

    /// The exit, if it has already been reported.
    pub(crate) fn try_exit(&self) -> Option<std::io::Result<ExitReport>> {
        self.exit.borrow().as_ref().map(|r| match r {
            Ok(r) => Ok(*r),
            Err(e) => Err(std::io::Error::other(e.clone())),
        })
    }

    async fn send(&mut self, op: &ShimOp) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let mut line = serde_json::to_vec(op).map_err(std::io::Error::other)?;
        line.push(b'\n');
        self.writer.write_all(&line).await
    }

    pub(crate) async fn signal(&mut self, sig: i32) {
        let _ = self.send(&ShimOp::Signal { sig }).await;
    }

    /// Release the latched status; the shim exits.
    pub(crate) async fn ack_exit(&mut self) {
        let _ = self.send(&ShimOp::AckExit).await;
    }
}

/// kamaji's end of one JIT-mode shim connection (R1021-F7). Unlike
/// [`ShimConn`], `exit` is not terminal here — every fork reports `forked`
/// then `exit` — so the caller reads the event stream itself.
pub(crate) struct JitConn {
    pub hello: Hello,
    writer: tokio::net::unix::OwnedWriteHalf,
    lines: tokio::io::Lines<tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>>,
}

impl JitConn {
    pub(crate) async fn connect(socket: &Path) -> Result<Self> {
        use tokio::io::AsyncBufReadExt as _;
        let stream = tokio::net::UnixStream::connect(socket)
            .await
            .with_context(|| format!("connecting to shim at {}", socket.display()))?;
        let (read, writer) = stream.into_split();
        let mut lines = tokio::io::BufReader::new(read).lines();
        let hello = read_hello(&mut lines, socket).await?;
        Ok(Self {
            hello,
            writer,
            lines,
        })
    }

    /// The next event, `None` once the shim has closed the connection (it
    /// exited). Cancel-safe (`Lines::next_line` is).
    pub(crate) async fn next_event(&mut self) -> Option<ShimEvent> {
        loop {
            match self.lines.next_line().await {
                Ok(Some(line)) => {
                    if let Ok(event) = serde_json::from_str(&line) {
                        return Some(event);
                    }
                }
                Ok(None) | Err(_) => return None,
            }
        }
    }

    /// Ask the shim to stop: TERM the live fork, KILL after `grace`, exit.
    pub(crate) async fn stop(&mut self, grace: std::time::Duration) {
        use tokio::io::AsyncWriteExt as _;
        let op = ShimOp::Stop {
            grace_ms: grace.as_millis() as u64,
        };
        let Ok(mut line) = serde_json::to_vec(&op) else {
            return;
        };
        line.push(b'\n');
        let _ = self.writer.write_all(&line).await;
    }
}

/// Read the opening `hello`, refusing a `proto` this kamaji does not speak.
async fn read_hello(
    lines: &mut tokio::io::Lines<tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>>,
    socket: &Path,
) -> Result<Hello> {
    let first = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("shim at {} closed before hello", socket.display()))?;
    // R1021-F3: an older or newer shim is not driven over a wire we do not
    // speak. Read `proto` alone before the full parse, so a shape change
    // still reports as "incompatible" rather than as garbage.
    let proto = serde_json::from_str::<serde_json::Value>(&first)?
        .get("proto")
        .and_then(serde_json::Value::as_u64);
    if proto != Some(u64::from(PROTO)) {
        return Err(IncompatibleProto(proto).into());
    }
    match serde_json::from_str::<ShimEvent>(&first)? {
        ShimEvent::Hello(h) => Ok(h),
        other => bail!("shim at {} opened with {other:?}, not hello", socket.display()),
    }
}

/// Start a shim for `req` and connect to it.
pub(crate) async fn launch(launcher: &ShimLauncher, req: &ShimRequest) -> Result<ShimConn> {
    start(launcher, req).await?;
    ShimConn::connect(&req.socket).await
}

/// Start a JIT-mode shim for `req` (which must carry `jit`) and connect to it.
pub(crate) async fn launch_jit(launcher: &ShimLauncher, req: &ShimRequest) -> Result<JitConn> {
    start(launcher, req).await?;
    JitConn::connect(&req.socket).await
}

/// Spawn the shim and wait for its ready line.
async fn start(launcher: &ShimLauncher, req: &ShimRequest) -> Result<()> {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

    check_socket_path(&req.socket)?;
    let log_path = req.plan.workload_dir.join("shim.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening {}", log_path.display()))?;
    let mut cmd = tokio::process::Command::new(&launcher.program);
    cmd.args(&launcher.args)
        .envs(launcher.env.iter().map(|(k, v)| (k, v)))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::from(log))
        // The whole point: the shim must outlive us.
        .kill_on_drop(false);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning shim {}", launcher.program.display()))?;

    let body = serde_json::to_vec(req)?;
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(&body).await.context("writing the shim request")?;
        // Dropped here: EOF ends the shim's read.
    }
    let stdout = child.stdout.take().expect("piped stdout");
    let mut lines = tokio::io::BufReader::new(stdout).lines();
    let handshake = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while let Some(line) = lines.next_line().await? {
            if line.starts_with(READY) {
                return Ok(());
            }
            if let Some(reason) = line.strip_prefix(ERR) {
                bail!("shim for {} failed: {}", req.ident, reason.trim());
            }
        }
        bail!(
            "shim for {} exited before it was ready (see {})",
            req.ident,
            log_path.display()
        )
    })
    .await
    .map_err(|_| anyhow!("shim for {} did not become ready within 30s", req.ident))?;
    if let Err(e) = handshake {
        let _ = child.start_kill();
        let _ = child.wait().await;
        return Err(e);
    }
    // Dropping a tokio Child without kill_on_drop leaves it running, and tokio
    // reaps it in the background if it exits while we live. After a kamaji
    // restart it is init's (or the unit's subreaper's) to reap.
    drop(child);
    Ok(())
}

/// A shim that answered with a `proto` this kamaji does not speak (`None`: no
/// readable `proto` at all). R1021-F3 stops such a workload by its leaf and
/// restarts it under a current shim.
#[derive(Debug)]
pub(crate) struct IncompatibleProto(pub Option<u64>);

impl std::fmt::Display for IncompatibleProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "shim speaks proto {:?}, this kamaji speaks {PROTO}", self.0)
    }
}

impl std::error::Error for IncompatibleProto {}

/// `<state_dir>/<ident>/spec.json`: everything a later kamaji needs to adopt or
/// restart this workload without a deploy record (W386 §1 — headscale has none).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PersistedSpec {
    pub spec_digest: Option<String>,
    pub mesh_ip: std::net::Ipv4Addr,
    pub spec: WorkloadSpec,
}

/// Persist the spec beside the socket.
pub(crate) fn persist_spec(workload_dir: &Path, persisted: &PersistedSpec) -> Result<()> {
    let body = serde_json::to_vec_pretty(persisted)?;
    crate::atomic_file::write_atomic(&workload_dir.join(SPEC_NAME), &body)
        .with_context(|| format!("persisting {}", workload_dir.join(SPEC_NAME).display()))
}

/// Read back what [`persist_spec`] wrote.
pub(crate) fn read_spec(workload_dir: &Path) -> Result<PersistedSpec> {
    let path = workload_dir.join(SPEC_NAME);
    let body = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&body).with_context(|| format!("parsing {}", path.display()))
}

/// A launcher that re-execs THIS test binary into [`tests::shim_entry`], so the
/// crate's own tests drive a real out-of-process shim without a kamaji binary.
#[cfg(test)]
pub(crate) fn test_launcher() -> ShimLauncher {
    ShimLauncher {
        program: std::env::current_exe().expect("test binary path"),
        args: vec![
            "--exact".into(),
            "shim::tests::shim_entry".into(),
            "--test-threads=1".into(),
        ],
        env: vec![(TEST_ENTRY_ENV.into(), "1".into())],
    }
}

#[cfg(test)]
const TEST_ENTRY_ENV: &str = "KAMAJI_TEST_SHIM_ENTRY";

#[cfg(test)]
mod tests {
    use super::*;

    /// Not a test: the shim's `main` when [`test_launcher`] re-execs the
    /// harness. A plain test run (env unset) passes trivially.
    #[test]
    fn shim_entry() {
        if std::env::var_os(TEST_ENTRY_ENV).is_some() {
            std::process::exit(run_from_stdin());
        }
    }

    #[test]
    fn exit_reports_round_trip_through_a_wait_status() {
        let code = ExitReport { code: Some(42), signal: None }.to_status();
        assert_eq!(code.code(), Some(42));
        use std::os::unix::process::ExitStatusExt as _;
        let sig = ExitReport { code: None, signal: Some(9) }.to_status();
        assert_eq!((sig.code(), sig.signal()), (None, Some(9)));
    }

    #[test]
    fn the_wire_shapes_are_the_documented_ones() {
        let exit = serde_json::to_string(&ShimEvent::Exit(ExitReport {
            code: Some(42),
            signal: None,
        }))
        .unwrap();
        assert_eq!(exit, r#"{"event":"exit","code":42}"#);
        assert_eq!(
            serde_json::to_string(&ShimOp::Signal { sig: 15 }).unwrap(),
            r#"{"op":"signal","sig":15}"#
        );
        assert_eq!(serde_json::to_string(&ShimOp::AckExit).unwrap(), r#"{"op":"ack_exit"}"#);
    }

    #[test]
    fn an_over_long_socket_path_is_refused_loudly() {
        let long = PathBuf::from(format!("/{}/shim.sock", "x".repeat(120)));
        let err = check_socket_path(&long).unwrap_err().to_string();
        assert!(err.contains("sun_path"), "{err}");
        assert!(check_socket_path(Path::new("/var/lib/kamaji/native/hs/shim.sock")).is_ok());
    }
}

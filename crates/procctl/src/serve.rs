//! The producer half: bind the control socket, answer `status`.
//!
//! std-only and thread-based on purpose. The motivating adopter is a winit GUI
//! with no async runtime at all (noisetable's `cargo run -p dev`), and asking a
//! workload to grow a tokio runtime to answer one JSON line would make the
//! channel cost more than the log-grepping it replaces.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::{clear_stale_socket, control_sock_path, ProcStatus, STATUS_CMD};

/// A connected client that never sends its request line holds the listener
/// thread. Bounded so a stuck peer costs one request's latency, not the
/// channel.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The request line. Only `cmd` is defined; unknown fields are ignored so the
/// verb set can grow without breaking older producers.
#[derive(Deserialize)]
struct Request {
    cmd: String,
}

/// A live control channel. Answers `status` until dropped.
///
/// Dropping it stops the listener thread and unlinks the socket file, so the
/// next run of the same process binds cleanly. Leaking it (`std::mem::forget`,
/// or a `let _ = ` binding that drops immediately — use `let _guard =`) leaves
/// a stale socket file behind, which the next [`serve_at`] will clear.
#[derive(Debug)]
pub struct ControlServer {
    path: PathBuf,
    shutdown: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ControlServer {
    /// The socket this server is bound to.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        // The listener thread is parked in a blocking `accept()`. Connecting to
        // ourselves is what wakes it; it then sees the flag and returns.
        let _ = UnixStream::connect(&self.path);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bind `$YAH_CONTROL_SOCK` and answer `status` from `status_fn`.
///
/// `Ok(None)` when the variable is unset or empty — the process is not running
/// under a supervisor that wants a channel, which is not an error. That is the
/// contract that lets the same binary run unchanged outside a camp.
///
/// The closure runs on the listener thread, once per request. Keep it cheap and
/// keep it panic-free: a panic there takes the channel down, which the
/// supervisor reads as a process that stopped answering.
pub fn serve_env<F>(status_fn: F) -> std::io::Result<Option<ControlServer>>
where
    F: Fn() -> ProcStatus + Send + 'static,
{
    match control_sock_path() {
        Some(path) => serve_at(path, status_fn).map(Some),
        None => Ok(None),
    }
}

/// Bind an explicit path and answer `status` from `status_fn`.
///
/// Creates the parent directory if needed, and clears a *dead* socket file left
/// by a predecessor (a live one is refused rather than unlinked — see
/// [`crate::clear_stale_socket`]).
pub fn serve_at<F>(path: impl Into<PathBuf>, status_fn: F) -> std::io::Result<ControlServer>
where
    F: Fn() -> ProcStatus + Send + 'static,
{
    let path = path.into();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    clear_stale_socket(&path)?;
    let listener = UnixListener::bind(&path)?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let pid = std::process::id();

    let thread = {
        let shutdown = shutdown.clone();
        std::thread::Builder::new()
            .name("procctl-control".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if shutdown.load(Ordering::Acquire) {
                        return;
                    }
                    let Ok(stream) = stream else { continue };
                    serve_connection(stream, &status_fn, pid, started);
                }
            })?
    };

    Ok(ControlServer {
        path,
        shutdown,
        thread: Some(thread),
    })
}

/// One connection: read request lines, answer each with one document line.
///
/// Multiple requests per connection are supported even though the reference
/// client opens a fresh connection per poll — reading to EOF is the same three
/// lines either way, and it makes an interactive `nc` session work.
fn serve_connection<F>(stream: UnixStream, status_fn: &F, pid: u32, started: Instant)
where
    F: Fn() -> ProcStatus,
{
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
    let Ok(mut out) = stream.try_clone() else {
        return;
    };
    let mut lines = BufReader::new(stream).lines();
    while let Some(Ok(line)) = lines.next() {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Request>(&line) {
            Ok(req) if req.cmd == STATUS_CMD => {
                let mut status = status_fn();
                // Stamp what the helper knows for certain, when the producer
                // did not answer it itself.
                status.pid.get_or_insert(pid);
                status
                    .uptime_secs
                    .get_or_insert_with(|| started.elapsed().as_secs());
                serde_json::to_string(&status)
                    .unwrap_or_else(|e| error_line(&format!("status not serializable: {e}")))
            }
            Ok(req) => error_line(&format!(
                "unknown command {:?}; this process implements only {STATUS_CMD:?}",
                req.cmd
            )),
            Err(e) => error_line(&format!("unparseable request: {e}")),
        };
        if out.write_all(reply.as_bytes()).is_err()
            || out.write_all(b"\n").is_err()
            || out.flush().is_err()
        {
            return;
        }
    }
}

/// An error reply is still one JSON line. A consumer parsing for `state` fails
/// to find it and treats the endpoint as unreachable, which is the right read:
/// this process did not tell it anything about its state.
fn error_line(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProcState, CONTROL_SOCK_ENV};

    /// The consumer side of one poll, spelled out rather than imported — this
    /// is also the twenty-line proof that the protocol needs no library.
    fn ask(path: &Path, line: &str) -> String {
        let mut stream = UnixStream::connect(path).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(line.as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        stream.flush().unwrap();
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply).unwrap();
        reply.trim().to_string()
    }

    fn ask_status(path: &Path) -> ProcStatus {
        serde_json::from_str(&ask(path, r#"{"cmd":"status"}"#)).unwrap()
    }

    #[test]
    fn a_two_line_producer_answers_status() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_at(&sock, || {
            ProcStatus::new(ProcState::Running).with_detail("3 windows open")
        })
        .unwrap();

        let got = ask_status(server.path());
        assert_eq!(got.state, ProcState::Running);
        assert_eq!(got.detail.as_deref(), Some("3 windows open"));
    }

    /// The helper knows its own pid and start time; a producer that answers
    /// only `state` still gets a document a supervisor can use.
    #[test]
    fn pid_and_uptime_are_stamped_when_the_producer_omits_them() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_at(&sock, || ProcStatus::new(ProcState::Starting)).unwrap();

        let got = ask_status(server.path());
        assert_eq!(got.pid, Some(std::process::id()));
        assert!(got.uptime_secs.is_some());
    }

    #[test]
    fn a_producer_supplied_pid_is_not_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_at(&sock, || {
            ProcStatus::new(ProcState::Running).with_pid(4242)
        })
        .unwrap();

        assert_eq!(ask_status(server.path()).pid, Some(4242));
    }

    /// The closure is re-run per request — that is what makes the channel a
    /// live signal rather than a snapshot taken at bind time.
    #[test]
    fn the_status_closure_runs_once_per_request() {
        use std::sync::atomic::AtomicUsize;
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let calls = Arc::new(AtomicUsize::new(0));
        let server = {
            let calls = calls.clone();
            serve_at(&sock, move || {
                // starting, starting, then running — the shape the readiness
                // ladder exists to observe.
                let n = calls.fetch_add(1, Ordering::SeqCst);
                ProcStatus::new(if n < 2 {
                    ProcState::Starting
                } else {
                    ProcState::Running
                })
            })
            .unwrap()
        };

        assert_eq!(ask_status(server.path()).state, ProcState::Starting);
        assert_eq!(ask_status(server.path()).state, ProcState::Starting);
        assert_eq!(ask_status(server.path()).state, ProcState::Running);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn several_requests_share_one_connection() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_at(&sock, || ProcStatus::new(ProcState::Running)).unwrap();

        let mut stream = UnixStream::connect(server.path()).unwrap();
        stream.write_all(b"{\"cmd\":\"status\"}\n{\"cmd\":\"status\"}\n").unwrap();
        stream.flush().unwrap();
        let mut reader = BufReader::new(stream);
        for _ in 0..2 {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let s: ProcStatus = serde_json::from_str(line.trim()).unwrap();
            assert_eq!(s.state, ProcState::Running);
        }
    }

    #[test]
    fn an_unknown_verb_is_refused_without_killing_the_channel() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_at(&sock, || ProcStatus::new(ProcState::Running)).unwrap();

        let reply = ask(server.path(), r#"{"cmd":"restart"}"#);
        assert!(reply.contains("unknown command"), "{reply}");
        assert!(
            serde_json::from_str::<ProcStatus>(&reply).is_err(),
            "an error reply must not parse as a status document"
        );
        // Still serving.
        assert_eq!(ask_status(server.path()).state, ProcState::Running);
    }

    #[test]
    fn garbage_is_refused_without_killing_the_channel() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_at(&sock, || ProcStatus::new(ProcState::Running)).unwrap();

        assert!(ask(server.path(), "not json at all").contains("unparseable"));
        assert_eq!(ask_status(server.path()).state, ProcState::Running);
    }

    #[test]
    fn dropping_the_server_unlinks_the_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let server = serve_at(&sock, || ProcStatus::new(ProcState::Running)).unwrap();
        assert!(sock.exists());
        drop(server);
        assert!(!sock.exists(), "a dropped server must leave no socket file");
    }

    /// A process restarting in the same workspace finds its predecessor's
    /// socket file. Binding on top of it fails with EADDRINUSE even though
    /// nothing is listening, so the helper has to clear it.
    #[test]
    fn a_stale_socket_file_from_a_dead_predecessor_is_reclaimed() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        {
            let _dead = UnixListener::bind(&sock).unwrap();
        }
        let server = serve_at(&sock, || ProcStatus::new(ProcState::Running)).unwrap();
        assert_eq!(ask_status(server.path()).state, ProcState::Running);
    }

    /// Two live processes on one path is a misconfiguration, and the second one
    /// silently stealing the socket would make the first invisible to its
    /// supervisor. Refuse instead.
    #[test]
    fn a_live_predecessor_is_refused_rather_than_stolen() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let first = serve_at(&sock, || ProcStatus::new(ProcState::Running)).unwrap();
        let err = serve_at(&sock, || ProcStatus::new(ProcState::Failed)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        assert_eq!(ask_status(first.path()).state, ProcState::Running);
    }

    #[test]
    fn the_parent_directory_is_created() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("jit/native/noisetable/control.sock");
        let server = serve_at(&sock, || ProcStatus::new(ProcState::Running)).unwrap();
        assert!(sock.exists());
        assert_eq!(ask_status(server.path()).state, ProcState::Running);
    }

    /// Outside a camp there is no supervisor asking, and a workload must not
    /// fail for the variable's absence.
    #[test]
    fn serve_env_declines_quietly_when_the_variable_is_unset() {
        let prev = std::env::var_os(CONTROL_SOCK_ENV);
        std::env::remove_var(CONTROL_SOCK_ENV);
        let got = serve_env(|| ProcStatus::new(ProcState::Running)).unwrap();
        if let Some(v) = prev {
            std::env::set_var(CONTROL_SOCK_ENV, v);
        }
        assert!(got.is_none(), "no variable, no channel, no error");
    }
}

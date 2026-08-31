//! The consumer half: ask a process for its status document.
//!
//! Feature-gated (`client`) because a producer must not be made to link tokio
//! to answer one JSON line. Supervisors — kamaji's probe runner, a camp daemon
//! serving `run.status` — turn it on.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{control_sock_path, ProcStatus, STATUS_CMD};

/// How long to wait for one document. A status answer is a local read on a
/// unix socket; anything slower than this is a wedged producer, and waiting
/// longer only delays the supervisor's own poll loop.
const REPLY_TIMEOUT: Duration = Duration::from_secs(2);

/// Ask the process bound at `path` for its status document, once.
///
/// An error means *unreachable or unparseable*, which is not the same as
/// unhealthy: a process that has not yet bound its socket is indistinguishable
/// here from one that never will. Callers deciding readiness should poll with
/// [`wait_ready`] rather than treating one error as a verdict.
///
/// The connection is not reused. A poll happens every few seconds at most, and
/// a per-call connection means a wedged reader on the producer side cannot
/// poison later polls — worth more than the syscalls saved.
pub async fn fetch_at(path: &Path) -> std::io::Result<ProcStatus> {
    let mut stream = tokio::net::UnixStream::connect(path).await?;
    stream
        .write_all(format!("{{\"cmd\":\"{STATUS_CMD}\"}}\n").as_bytes())
        .await?;
    stream.flush().await?;

    let mut line = String::new();
    let read = tokio::time::timeout(
        REPLY_TIMEOUT,
        BufReader::new(stream).read_line(&mut line),
    )
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "control socket {} did not answer within {REPLY_TIMEOUT:?}",
                path.display()
            ),
        )
    })??;
    if read == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("control socket {} closed without answering", path.display()),
        ));
    }
    serde_json::from_str(line.trim()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("control socket {} answered {line:?}: {e}", path.display()),
        )
    })
}

/// [`fetch_at`] against `$YAH_CONTROL_SOCK`. `Ok(None)` when unset — for a
/// consumer that inherited the same environment as the process it supervises.
pub async fn fetch() -> std::io::Result<Option<ProcStatus>> {
    match control_sock_path() {
        Some(path) => fetch_at(&path).await.map(Some),
        None => Ok(None),
    }
}

/// Outcome of waiting for a process to report itself ready.
#[derive(Debug)]
pub enum ReadyOutcome {
    /// The process reported [`crate::ProcState::Running`].
    Ready(ProcStatus),
    /// The process reported a terminal state — it is not coming up. Failing
    /// here rather than burning the whole timeout is the practical difference
    /// between a five-second and a twenty-second edit loop.
    Terminal(ProcStatus),
    /// The deadline passed. `last` is the most recent document read, or `None`
    /// when the endpoint never answered at all — "never bound its socket" and
    /// "stuck in starting" are different bugs with different fixes, so the
    /// distinction is worth carrying into the error message.
    TimedOut { last: Option<ProcStatus> },
}

/// Poll `path` until the process reports ready, reports terminal, or `timeout`
/// expires.
pub async fn wait_ready(path: &Path, timeout: Duration) -> ReadyOutcome {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last: Option<ProcStatus> = None;
    loop {
        if let Ok(status) = fetch_at(path).await {
            if status.is_ready() {
                return ReadyOutcome::Ready(status);
            }
            if status.state.is_terminal() {
                return ReadyOutcome::Terminal(status);
            }
            last = Some(status);
        }
        if tokio::time::Instant::now() >= deadline {
            return ReadyOutcome::TimedOut { last };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{serve_at, ProcState, ProcStatus};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn the_client_reads_what_the_helper_serves() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let _server = serve_at(&sock, || {
            ProcStatus::new(ProcState::Running).with_detail("3 windows")
        })
        .unwrap();

        let got = fetch_at(&sock).await.unwrap();
        assert_eq!(got.state, ProcState::Running);
        assert_eq!(got.detail.as_deref(), Some("3 windows"));
        assert_eq!(got.pid, Some(std::process::id()));
    }

    #[tokio::test]
    async fn wait_ready_polls_through_starting_to_running() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let calls = Arc::new(AtomicUsize::new(0));
        let _server = {
            let calls = calls.clone();
            serve_at(&sock, move || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                ProcStatus::new(if n < 2 {
                    ProcState::Starting
                } else {
                    ProcState::Running
                })
            })
            .unwrap()
        };

        let outcome = wait_ready(&sock, Duration::from_secs(5)).await;
        assert!(
            matches!(&outcome, ReadyOutcome::Ready(s) if s.state == ProcState::Running),
            "{outcome:?}"
        );
    }

    /// `failed` must short-circuit. Burning the full readiness timeout on a
    /// process that has already said it is not coming up is the slow-edit-loop
    /// failure this outcome exists to prevent.
    #[tokio::test]
    async fn wait_ready_fails_fast_on_a_terminal_state() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let _server = serve_at(&sock, || {
            ProcStatus::new(ProcState::Failed).with_detail("no GPU")
        })
        .unwrap();

        let started = std::time::Instant::now();
        let outcome = wait_ready(&sock, Duration::from_secs(30)).await;
        assert!(
            matches!(&outcome, ReadyOutcome::Terminal(s) if s.detail.as_deref() == Some("no GPU")),
            "{outcome:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must not burn the 30s timeout on a terminal state"
        );
    }

    #[tokio::test]
    async fn nothing_listening_times_out_with_no_last_document() {
        let tmp = tempfile::tempdir().unwrap();
        let outcome = wait_ready(&tmp.path().join("never-bound.sock"), Duration::from_millis(300))
            .await;
        assert!(
            matches!(outcome, ReadyOutcome::TimedOut { last: None }),
            "an endpoint that never answered must report no last document"
        );
    }

    /// An error reply is a well-formed JSON line that is not a status document.
    /// It must read as unreachable, never as some default state.
    #[tokio::test]
    async fn an_error_reply_is_not_mistaken_for_a_status() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("control.sock");
        let _server = serve_at(&sock, || ProcStatus::new(ProcState::Running)).unwrap();

        // Speak the wire directly to send a verb the helper refuses.
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        stream.write_all(b"{\"cmd\":\"nope\"}\n").await.unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).await.unwrap();
        assert!(serde_json::from_str::<ProcStatus>(line.trim()).is_err());
    }
}

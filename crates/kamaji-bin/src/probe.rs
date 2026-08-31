//! Workload health probe runner (R406-T11).
//!
//! ## Decision
//!
//! Kamaji polls the [`Healthcheck`](workload_spec::Healthcheck) declared in
//! the workload spec. Three executors map to the three [`HealthProbe`] variants:
//! `HttpGet`, `Exec`, `TcpConnect`. Stdio sentinel was considered and rejected
//! — see `.yah/docs/working/W154-yubaba-dual-runtime.md` §"Resolved decisions".
//!
//! ## Surface
//!
//! - [`ProbeTarget`] — per-workload data Kamaji retains across deploy:
//!   the [`Healthcheck`] spec plus the network endpoint to dial (`addr`,
//!   resolved at deploy time — `127.0.0.1` for native and pond, the
//!   containerd bridge IP for cloud-tier container workloads), and/or the
//!   workload's **process-control socket**.
//! - [`run_probe`] — execute one probe and return [`ProbeStatus`]. Honors
//!   `Healthcheck.timeout`; on a `None` target returns `ProbeStatus::Ready`
//!   (no probe declared ↔ "trust the workload's existence as readiness").
//!
//! ## The control channel outranks the healthcheck (R715-F3 / W315)
//!
//! A workload that speaks the process-control channel answers the question
//! directly — `starting`, `running`, `failed` — instead of being inferred from
//! a bound port. `kamaji_proto::WorkloadState` and `procctl::ProcState` are the
//! *same six words* by construction, so that answer is believed verbatim.
//!
//! When a target carries a control socket it is the whole probe: an
//! unreachable socket reports `Starting`, never a fallback to the port. That is
//! deliberate and it is the point of the channel — a bound port says nothing
//! about whether the thing behind it finished booting, so falling back to it
//! would reinstate exactly the false `Ready` W315 exists to end.
//!
//! Yubaba drives cadence by re-issuing
//! [`kamaji_proto::YubabaToKamaji::Probe`]; this module answers one
//! probe per call. `Healthcheck.interval` / `initial_delay` /
//! `failure_threshold` live in Yubaba's policy layer.
//!
//! ## HTTP client choice
//!
//! HttpGet uses a hand-rolled HTTP/1.1 GET over `tokio::net::TcpStream` rather
//! than reqwest/hyper. Kamaji's memory budget is tight (W154 §"Memory
//! budget for cheap boxes" targets 15-25 MB RSS for the whole binary); the
//! +5-10 MB an HTTP client crate brings is hard to justify when the only
//! request shape is "GET <path> HTTP/1.1, read enough to extract the status
//! line". Probes are localhost-or-bridge anyway — no TLS, no redirect chains,
//! no proxy logic.
//!
//! @yah:ticket(R592-B6, "Flaky test: http_get_starting_when_port_refused races connection-reset vs connection-refused under parallel load")
//! @yah:at(2026-07-03T01:03:37Z)
//! @yah:status(review)
//! @yah:parent(R592)
//! @yah:severity(minor)
//! @yah:next("Pre-existing flake (predates R592-T1; that refactor never touched probe.rs). Under full-workspace parallel cargo test on macOS the probe occasionally sees 'Connection reset by peer (os error 54)' instead of refused and maps to Unhealthy, failing the Starting assertion at probe.rs:501. Passes 3/3 in isolation. Fix: either bind-then-drop a listener to guarantee a dead port race-free, or accept reset as Starting-equivalent in the starting-window branch.")
//! @yah:verify("for i in 1..20: cargo test -p kamaji-bin --lib --all-features (full parallel suite) with zero probe flakes")
//! @yah:tier(Thief)
//! @yah:handoff("DONE (verify-clean). Root cause: connection teardown AFTER a successful connect(), not at connect. Under full-workspace parallel load on macOS, connect() to a just-dropped loopback port races to succeed, then request write / first read gets ECONNRESET (os 54) -> fell through to HttpError::Io => Unhealthy, failing the Starting|Timeout assertion at probe.rs.\n\nFix (probe.rs production classifier, NOT the test): is_not_serving(kind)=Refused|Reset|Aborted|BrokenPipe + pre_response_err(), threaded through connect + write_all + flush + first read. Teardown BEFORE any response byte => Starting; teardown AFTER partial bytes stays Io => Unhealthy (truncated); well-formed non-2xx unaffected. Renamed HttpError::NotListening -> NotServing. Same predicate applied to run_tcp_connect (identical latent flake). Hardens real probing: workload mid-startup RSTing early connections now reads Starting not Unhealthy.\n\nVerify: 30x full parallel cargo test -p kamaji-bin --lib --all-features => 0 flakes (was ~35%). 23/23 probe unit tests green; full lib suite 188 passed. No test assertions changed.")

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use kamaji_proto::ProbeStatus;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use workload_spec::{HealthProbe, Healthcheck};

/// Per-workload probe configuration Kamaji retains across deploy.
///
/// A target carries a control socket, a healthcheck, or both. With a control
/// socket present it decides alone — see the module docs for why there is no
/// fallback to the healthcheck.
///
/// `addr` is the host:port to dial for `HttpGet` / `TcpConnect`. The deploy
/// path resolves it at admission time:
///
/// - Native workload: `127.0.0.1` (host networking, port from the probe spec).
/// - Container workload: the containerd-assigned bridge IP, or `127.0.0.1`
///   for pond-tier container workloads on the docker socket.
///
/// `Exec` ignores `addr` — argv runs in the workload's namespace and doesn't
/// need a network endpoint.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    /// The spec's declared healthcheck. `None` for a workload whose only
    /// readiness signal is its control channel — a portless GUI process has no
    /// port to probe and inventing a healthcheck for it would be a lie.
    pub healthcheck: Option<Healthcheck>,
    /// Endpoint the healthcheck dials. Inert when `healthcheck` is `None`.
    pub addr: SocketAddr,
    /// The workload's process-control socket (`$YAH_CONTROL_SOCK`), when it
    /// declared one. Outranks `healthcheck`.
    pub control: Option<PathBuf>,
}

impl ProbeTarget {
    /// A target probed by the spec's declared healthcheck at `addr`.
    pub fn healthcheck(healthcheck: Healthcheck, addr: SocketAddr) -> Self {
        Self {
            healthcheck: Some(healthcheck),
            addr,
            control: None,
        }
    }

    /// A target probed by asking the workload directly (R715-F3 / W315).
    ///
    /// No `addr`: a workload on the control channel need not have a listener at
    /// all, and the port is not consulted when the channel is present.
    pub fn control(sock: impl Into<PathBuf>) -> Self {
        Self {
            healthcheck: None,
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            control: Some(sock.into()),
        }
    }
}

/// Execute a single probe against `target` and return its [`ProbeStatus`].
///
/// `target = None` is the "no healthcheck declared" path — surface
/// [`ProbeStatus::Ready`] so Yubaba's admission logic doesn't have to special-
/// case workloads without a spec'd probe.
pub async fn run_probe(target: Option<&ProbeTarget>) -> ProbeStatus {
    let Some(target) = target else {
        return ProbeStatus::Ready;
    };
    if let Some(control) = &target.control {
        return run_control(control).await;
    }
    let Some(healthcheck) = &target.healthcheck else {
        return ProbeStatus::Ready;
    };
    let deadline = Duration::from_millis(healthcheck.timeout.as_ms());
    match &healthcheck.probe {
        HealthProbe::HttpGet {
            path,
            port,
            expect_status,
        } => {
            let addr = with_port(target.addr, *port);
            run_http_get(addr, path, *expect_status, deadline).await
        }
        HealthProbe::TcpConnect { port } => {
            let addr = with_port(target.addr, *port);
            run_tcp_connect(addr, deadline).await
        }
        HealthProbe::Exec { argv } => run_exec(argv, deadline).await,
    }
}

/// Ask the workload what it is doing, and believe it.
///
/// The vocabulary is shared with [`kamaji_proto::WorkloadState`] by
/// construction (`procctl` holds the `From` impl, and it is an exhaustive
/// match), so this is a projection onto the coarser [`ProbeStatus`] rather than
/// a translation table:
///
/// | reported | probe |
/// |---|---|
/// | `running` | `Ready` — the only state that counts as serving |
/// | `pending`, `starting` | `Starting` |
/// | `draining`, `exited`, `failed` | `Unhealthy`, carrying the workload's own `detail` |
///
/// An unreachable socket is `Starting`, not `Unhealthy`: a workload that has
/// not bound its control socket yet is indistinguishable here from one that
/// never will, and calling the first case unhealthy would fail a workload for
/// starting slowly.
async fn run_control(sock: &Path) -> ProbeStatus {
    use procctl::ProcState;

    let status = match procctl::fetch_at(sock).await {
        Ok(status) => status,
        Err(e) => {
            tracing::trace!(sock = %sock.display(), error = %e, "control channel unreachable");
            return ProbeStatus::Starting;
        }
    };
    let detail = status
        .detail
        .as_deref()
        .map(|d| format!(": {d}"))
        .unwrap_or_default();
    match status.state {
        ProcState::Running => ProbeStatus::Ready,
        ProcState::Pending | ProcState::Starting => ProbeStatus::Starting,
        state @ (ProcState::Draining | ProcState::Exited | ProcState::Failed) => {
            ProbeStatus::Unhealthy {
                reason: format!("workload reports {state}{detail}"),
            }
        }
    }
}

fn with_port(addr: SocketAddr, port: u16) -> SocketAddr {
    let mut a = addr;
    a.set_port(port);
    a
}

async fn run_http_get(
    addr: SocketAddr,
    path: &str,
    expect_status: Option<u16>,
    deadline: Duration,
) -> ProbeStatus {
    match timeout(deadline, http_get_once(addr, path)).await {
        Ok(Ok(status)) => classify_http(status, expect_status),
        Ok(Err(HttpError::NotServing)) => ProbeStatus::Starting,
        Ok(Err(HttpError::Io(e))) => ProbeStatus::Unhealthy {
            reason: format!("http probe i/o error: {e}"),
        },
        Ok(Err(HttpError::MalformedResponse(reason))) => ProbeStatus::Unhealthy { reason },
        Err(_) => ProbeStatus::Timeout,
    }
}

fn classify_http(status: u16, expect: Option<u16>) -> ProbeStatus {
    match expect {
        Some(want) if status == want => ProbeStatus::Ready,
        Some(want) => ProbeStatus::Unhealthy {
            reason: format!("http {status}, expected {want}"),
        },
        None if (200..300).contains(&status) => ProbeStatus::Ready,
        None => ProbeStatus::Unhealthy {
            reason: format!("http {status}"),
        },
    }
}

#[derive(Debug)]
enum HttpError {
    /// The endpoint could not be reached as a serving HTTP peer *before any
    /// response byte arrived* — a refused/reset/aborted connect, or the
    /// connection torn down while we were still sending the request or waiting
    /// for the first byte. Indistinguishable from "not up yet", so it maps to
    /// `ProbeStatus::Starting`.
    NotServing,
    Io(std::io::Error),
    MalformedResponse(String),
}

/// True when a connect-or-early-exchange I/O error means "no endpoint is
/// serving HTTP here yet" rather than a genuine post-response fault.
///
/// `ConnectionRefused` is the clean case (kernel RST, no listener). But a
/// workload mid-startup — or a listen socket being torn down/rebound under
/// load — can also: RST/abort the SYN itself (`ConnectionReset` /
/// `ConnectionAborted` at connect), or *complete* the handshake and then RST
/// the request write or the first read (`ConnectionReset` / `BrokenPipe`
/// mid-exchange, before any response byte). To a health probe every one of
/// these is the same fact: we never received an HTTP response, so the workload
/// is not ready. Folding them into `Starting` — but only before the first
/// response byte — also removes a real test flake: a just-dropped loopback
/// listener races connect-succeeds-then-read-resets under parallel load
/// (R592-B6). A teardown *after* partial response bytes stays an `Io` error
/// (truncated response → `Unhealthy`), and a well-formed non-2xx is unaffected.
fn is_not_serving(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        kind,
        ConnectionRefused | ConnectionReset | ConnectionAborted | BrokenPipe
    )
}

/// Map an I/O error seen *before the first response byte* to `NotServing` when
/// it is a connection teardown, else a genuine `Io` fault.
fn pre_response_err(e: std::io::Error) -> HttpError {
    if is_not_serving(e.kind()) {
        HttpError::NotServing
    } else {
        HttpError::Io(e)
    }
}

async fn http_get_once(addr: SocketAddr, path: &str) -> Result<u16, HttpError> {
    let mut stream = TcpStream::connect(addr).await.map_err(pre_response_err)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: kamaji-probe\r\n\
         Accept: */*\r\nConnection: close\r\n\r\n",
        path = path,
        addr = addr,
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(pre_response_err)?;
    stream.flush().await.map_err(pre_response_err)?;

    // Read the status line. We don't need to consume the body — a probe only
    // cares about the response code, and the workload will see the connection
    // close once we drop the stream.
    let mut head = [0u8; 64];
    let mut filled = 0usize;
    loop {
        let n = match stream.read(&mut head[filled..]).await {
            Ok(n) => n,
            // A teardown with no bytes in hand is the startup race — the peer
            // accepted then reset before serving. Once we hold partial bytes a
            // reset is a truncated response, which is a real fault (`Io`).
            Err(e) if filled == 0 => return Err(pre_response_err(e)),
            Err(e) => return Err(HttpError::Io(e)),
        };
        if n == 0 {
            break;
        }
        filled += n;
        if head[..filled].windows(2).any(|w| w == b"\r\n") {
            break;
        }
        if filled == head.len() {
            return Err(HttpError::MalformedResponse(
                "no CRLF in first 64 bytes of response".into(),
            ));
        }
    }
    parse_status_line(&head[..filled])
}

/// Extract the numeric status code from an HTTP/1.x status line.
/// Pure — easy to unit-test without a live socket.
fn parse_status_line(buf: &[u8]) -> Result<u16, HttpError> {
    let end = buf
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| HttpError::MalformedResponse("missing CRLF terminator".into()))?;
    let line = std::str::from_utf8(&buf[..end])
        .map_err(|_| HttpError::MalformedResponse("status line not utf-8".into()))?;
    let mut parts = line.splitn(3, ' ');
    let version = parts
        .next()
        .ok_or_else(|| HttpError::MalformedResponse("empty status line".into()))?;
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError::MalformedResponse(format!(
            "unsupported version: {version}"
        )));
    }
    let code = parts
        .next()
        .ok_or_else(|| HttpError::MalformedResponse("missing status code".into()))?;
    code.parse::<u16>()
        .map_err(|_| HttpError::MalformedResponse(format!("status code {code:?} not a u16")))
}

async fn run_tcp_connect(addr: SocketAddr, deadline: Duration) -> ProbeStatus {
    match timeout(deadline, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => ProbeStatus::Ready,
        Ok(Err(e)) if is_not_serving(e.kind()) => ProbeStatus::Starting,
        Ok(Err(e)) => ProbeStatus::Unhealthy {
            reason: format!("tcp connect failed: {e}"),
        },
        Err(_) => ProbeStatus::Timeout,
    }
}

async fn run_exec(argv: &[String], deadline: Duration) -> ProbeStatus {
    if argv.is_empty() {
        return ProbeStatus::Unhealthy {
            reason: "exec probe argv is empty".into(),
        };
    }
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ProbeStatus::Unhealthy {
                reason: format!("exec probe spawn failed: {e}"),
            };
        }
    };

    match timeout(deadline, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            if output.status.success() {
                ProbeStatus::Ready
            } else {
                let stderr_tail = tail_utf8_lossy(&output.stderr, 256);
                let code_part = output
                    .status
                    .code()
                    .map(|c| format!("exit {c}"))
                    .unwrap_or_else(|| "signaled".to_string());
                let reason = if stderr_tail.is_empty() {
                    format!("exec probe failed: {code_part}")
                } else {
                    format!("exec probe failed: {code_part}: {stderr_tail}")
                };
                ProbeStatus::Unhealthy { reason }
            }
        }
        Ok(Err(e)) => ProbeStatus::Unhealthy {
            reason: format!("exec probe wait failed: {e}"),
        },
        Err(_) => ProbeStatus::Timeout,
    }
}

/// Take the last `cap` bytes (utf-8 lossy) so we surface the most-recent
/// stderr fragment without unbounded message growth.
fn tail_utf8_lossy(buf: &[u8], cap: usize) -> String {
    let start = buf.len().saturating_sub(cap);
    String::from_utf8_lossy(&buf[start..]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;
    use workload_spec::Millis;

    fn hc(probe: HealthProbe, timeout_ms: u64) -> Healthcheck {
        Healthcheck {
            probe,
            interval: Millis::from_ms(1000),
            timeout: Millis::from_ms(timeout_ms),
            initial_delay: Millis::from_ms(0),
            failure_threshold: 3,
        }
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    // ── parse_status_line ──────────────────────────────────────────────────────

    #[test]
    fn parse_status_line_extracts_2xx() {
        assert_eq!(
            parse_status_line(b"HTTP/1.1 200 OK\r\nServer: x\r\n").unwrap(),
            200
        );
    }

    #[test]
    fn parse_status_line_extracts_5xx_with_no_reason_phrase() {
        // Some minimal servers omit the reason phrase entirely.
        assert_eq!(parse_status_line(b"HTTP/1.1 503 \r\n").unwrap(), 503);
    }

    #[test]
    fn parse_status_line_rejects_http2() {
        let err = parse_status_line(b"HTTP/2.0 200\r\n").unwrap_err();
        match err {
            HttpError::MalformedResponse(m) => assert!(m.contains("unsupported")),
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    #[test]
    fn parse_status_line_rejects_missing_crlf() {
        let err = parse_status_line(b"HTTP/1.1 200 OK").unwrap_err();
        assert!(matches!(err, HttpError::MalformedResponse(_)));
    }

    // ── classify_http ──────────────────────────────────────────────────────────

    #[test]
    fn classify_http_2xx_with_no_expect_is_ready() {
        assert!(matches!(classify_http(200, None), ProbeStatus::Ready));
        assert!(matches!(classify_http(204, None), ProbeStatus::Ready));
    }

    #[test]
    fn classify_http_5xx_with_no_expect_is_unhealthy() {
        match classify_http(500, None) {
            ProbeStatus::Unhealthy { reason } => assert!(reason.contains("500")),
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    #[test]
    fn classify_http_expect_match_is_ready() {
        assert!(matches!(classify_http(418, Some(418)), ProbeStatus::Ready));
    }

    #[test]
    fn classify_http_expect_mismatch_is_unhealthy() {
        match classify_http(200, Some(204)) {
            ProbeStatus::Unhealthy { reason } => {
                assert!(reason.contains("200") && reason.contains("204"));
            }
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    // ── tail_utf8_lossy ────────────────────────────────────────────────────────

    #[test]
    fn tail_caps_message_length() {
        let buf = vec![b'A'; 1024];
        let t = tail_utf8_lossy(&buf, 256);
        assert_eq!(t.len(), 256);
    }

    #[test]
    fn tail_short_buf_is_passed_through() {
        assert_eq!(tail_utf8_lossy(b"  short ", 256), "short");
    }

    // ── run_probe: TcpConnect ──────────────────────────────────────────────────

    #[tokio::test]
    async fn tcp_connect_ready_when_listener_accepts() {
        let listener = TcpListener::bind(loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = ProbeTarget::healthcheck(
            hc(HealthProbe::TcpConnect { port }, 1000),
            loopback(port),
        );
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Ready), "got {status:?}");
    }

    #[tokio::test]
    async fn tcp_connect_starting_when_port_refused() {
        // Bind then drop to release the port; if the OS reuses it instantly
        // before the probe connects we'd flake, but this is the standard
        // "find a free port" pattern.
        let listener = TcpListener::bind(loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let target = ProbeTarget::healthcheck(
            hc(HealthProbe::TcpConnect { port }, 200),
            loopback(port),
        );
        let status = run_probe(Some(&target)).await;
        assert!(
            matches!(status, ProbeStatus::Starting | ProbeStatus::Timeout),
            "got {status:?}",
        );
    }

    // ── run_probe: HttpGet ─────────────────────────────────────────────────────

    /// Tiny one-shot HTTP server that accepts a single connection and replies
    /// with the given status. Returns the bound port.
    async fn spawn_one_shot(reply: &'static [u8]) -> u16 {
        let listener = TcpListener::bind(loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Drain the request — best-effort.
                let mut buf = [0u8; 1024];
                let _ = tokio::time::timeout(Duration::from_millis(200), sock.read(&mut buf)).await;
                let _ = sock.write_all(reply).await;
                let _ = sock.shutdown().await;
            }
        });
        port
    }

    #[tokio::test]
    async fn http_get_ready_on_200() {
        let port = spawn_one_shot(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        let target = ProbeTarget::healthcheck(
            hc(
                HealthProbe::HttpGet {
                    path: "/healthz".into(),
                    port,
                    expect_status: None,
                },
                1000,
            ),
            loopback(port),
        );
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Ready), "got {status:?}");
    }

    #[tokio::test]
    async fn http_get_unhealthy_on_503() {
        let port = spawn_one_shot(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n").await;
        let target = ProbeTarget::healthcheck(
            hc(
                HealthProbe::HttpGet {
                    path: "/healthz".into(),
                    port,
                    expect_status: None,
                },
                1000,
            ),
            loopback(port),
        );
        let status = run_probe(Some(&target)).await;
        match status {
            ProbeStatus::Unhealthy { reason } => assert!(reason.contains("503")),
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn http_get_expect_status_match_is_ready() {
        let port = spawn_one_shot(b"HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\n\r\n").await;
        let target = ProbeTarget::healthcheck(
            hc(
                HealthProbe::HttpGet {
                    path: "/healthz".into(),
                    port,
                    expect_status: Some(418),
                },
                1000,
            ),
            loopback(port),
        );
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Ready), "got {status:?}");
    }

    #[tokio::test]
    async fn http_get_starting_when_port_refused() {
        let listener = TcpListener::bind(loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let target = ProbeTarget::healthcheck(
            hc(
                HealthProbe::HttpGet {
                    path: "/healthz".into(),
                    port,
                    expect_status: None,
                },
                200,
            ),
            loopback(port),
        );
        let status = run_probe(Some(&target)).await;
        assert!(
            matches!(status, ProbeStatus::Starting | ProbeStatus::Timeout),
            "got {status:?}",
        );
    }

    #[tokio::test]
    async fn http_get_timeout_when_server_never_replies() {
        // Bind a listener that accepts and then hangs without replying — the
        // probe's 100ms timeout should fire before our 5s wait_forever
        // sentinel.
        let listener = TcpListener::bind(loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(5)).await;
                drop(sock);
            }
        });
        let target = ProbeTarget::healthcheck(
            hc(
                HealthProbe::HttpGet {
                    path: "/healthz".into(),
                    port,
                    expect_status: None,
                },
                100,
            ),
            loopback(port),
        );
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Timeout), "got {status:?}");
    }

    // ── run_probe: Exec ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn exec_exit_zero_is_ready() {
        let target = ProbeTarget::healthcheck(
            hc(
                HealthProbe::Exec {
                    argv: vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
                },
                1000,
            ),
            loopback(0),
        );
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Ready), "got {status:?}");
    }

    #[tokio::test]
    async fn exec_nonzero_is_unhealthy_with_exit_in_reason() {
        let target = ProbeTarget::healthcheck(
            hc(
                HealthProbe::Exec {
                    argv: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "echo broken >&2; exit 7".into(),
                    ],
                },
                1000,
            ),
            loopback(0),
        );
        let status = run_probe(Some(&target)).await;
        match status {
            ProbeStatus::Unhealthy { reason } => {
                assert!(reason.contains("exit 7"), "reason: {reason}");
                assert!(reason.contains("broken"), "reason: {reason}");
            }
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn exec_timeout_when_command_hangs() {
        let target = ProbeTarget::healthcheck(
            hc(
                HealthProbe::Exec {
                    argv: vec!["/bin/sh".into(), "-c".into(), "sleep 10".into()],
                },
                100,
            ),
            loopback(0),
        );
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Timeout), "got {status:?}");
    }

    #[tokio::test]
    async fn exec_empty_argv_is_unhealthy() {
        let target = ProbeTarget::healthcheck(
            hc(HealthProbe::Exec { argv: vec![] }, 1000),
            loopback(0),
        );
        let status = run_probe(Some(&target)).await;
        match status {
            ProbeStatus::Unhealthy { reason } => assert!(reason.contains("empty")),
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn exec_unknown_binary_is_unhealthy() {
        let target = ProbeTarget::healthcheck(
            hc(
                HealthProbe::Exec {
                    argv: vec!["/no/such/binary/zzz".into()],
                },
                1000,
            ),
            loopback(0),
        );
        let status = run_probe(Some(&target)).await;
        assert!(
            matches!(status, ProbeStatus::Unhealthy { .. }),
            "got {status:?}"
        );
    }

    // ── run_probe: None target ─────────────────────────────────────────────────

    #[tokio::test]
    async fn no_target_returns_ready() {
        let status = run_probe(None).await;
        assert!(matches!(status, ProbeStatus::Ready));
    }

    // ── run_probe: the control channel (R715-F3 / W315) ────────────────────────

    /// Stand up a real conforming producer via the helper crate, so these
    /// exercise the actual wire rather than a hand-rolled stand-in.
    fn producer(
        dir: &tempfile::TempDir,
        status: procctl::ProcStatus,
    ) -> (procctl::ControlServer, std::path::PathBuf) {
        let sock = dir.path().join("control.sock");
        let server = procctl::serve_at(&sock, move || status.clone()).unwrap();
        (server, sock)
    }

    #[tokio::test]
    async fn a_workload_reporting_running_is_ready() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (_srv, sock) = producer(&tmp, procctl::ProcStatus::new(procctl::ProcState::Running));
        let status = run_probe(Some(&ProbeTarget::control(sock))).await;
        assert!(matches!(status, ProbeStatus::Ready), "got {status:?}");
    }

    /// The whole point: a process that is up, has bound everything it is going
    /// to bind, and is *still booting* gets to say so.
    #[tokio::test]
    async fn a_workload_reporting_starting_is_not_ready() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (_srv, sock) = producer(
            &tmp,
            procctl::ProcStatus::new(procctl::ProcState::Starting).with_detail("replaying WAL 3/7"),
        );
        let status = run_probe(Some(&ProbeTarget::control(sock))).await;
        assert!(matches!(status, ProbeStatus::Starting), "got {status:?}");
    }

    /// A workload that says it failed is unhealthy *and* explains itself — the
    /// `detail` line is the one that replaces grepping a log tail.
    #[tokio::test]
    async fn a_workload_reporting_failed_is_unhealthy_in_its_own_words() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (_srv, sock) = producer(
            &tmp,
            procctl::ProcStatus::new(procctl::ProcState::Failed).with_detail("no GPU"),
        );
        match run_probe(Some(&ProbeTarget::control(sock))).await {
            ProbeStatus::Unhealthy { reason } => {
                assert!(reason.contains("failed"), "{reason}");
                assert!(reason.contains("no GPU"), "{reason}");
            }
            other => panic!("expected Unhealthy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_draining_workload_is_not_ready() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (_srv, sock) = producer(&tmp, procctl::ProcStatus::new(procctl::ProcState::Draining));
        assert!(matches!(
            run_probe(Some(&ProbeTarget::control(sock))).await,
            ProbeStatus::Unhealthy { .. }
        ));
    }

    /// "Hasn't bound its socket yet" and "never will" are indistinguishable
    /// from here, and calling the first one unhealthy fails a workload for
    /// starting slowly. Yubaba's `failure_threshold` is what eventually decides.
    #[tokio::test]
    async fn an_unbound_control_socket_reads_as_starting_not_unhealthy() {
        let tmp = tempfile::TempDir::new().unwrap();
        let target = ProbeTarget::control(tmp.path().join("never-bound.sock"));
        let status = run_probe(Some(&target)).await;
        assert!(matches!(status, ProbeStatus::Starting), "got {status:?}");
    }

    /// The ladder, asserted: a listener is accepting on the declared
    /// healthcheck's port — which would read `Ready` on its own — and the
    /// workload says it is still starting. The workload wins.
    #[tokio::test]
    async fn the_control_channel_outranks_an_accepting_port() {
        let listener = TcpListener::bind(loopback(0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let tmp = tempfile::TempDir::new().unwrap();
        let (_srv, sock) = producer(&tmp, procctl::ProcStatus::new(procctl::ProcState::Starting));

        let port_only =
            ProbeTarget::healthcheck(hc(HealthProbe::TcpConnect { port }, 1000), loopback(port));
        assert!(
            matches!(run_probe(Some(&port_only)).await, ProbeStatus::Ready),
            "precondition: the port alone reads as ready",
        );

        let mut both = port_only.clone();
        both.control = Some(sock);
        assert!(
            matches!(run_probe(Some(&both)).await, ProbeStatus::Starting),
            "a declared channel must supersede the port",
        );
    }
}

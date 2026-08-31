//! **Producer helper for the yah process-control channel** — the two lines a
//! workload writes so its supervisor stops having to guess at it.
//!
//! ## What the channel is
//!
//! A supervisor watching a process from outside can ask exactly two questions:
//! is the pid alive, and is the port open. Both are proxies. A process that has
//! finished booting, one still replaying a WAL, and one wedged on a lock answer
//! them identically — so the real answer has always been somewhere in stdout,
//! and reading it means grepping a log tail for a sentence nobody agreed on.
//!
//! W315's rule: **any process built to run under a yah camp SHOULD expose a
//! control channel.** One verb, `status`, answering with a status document:
//!
//! ```json
//! {"state":"running","pid":71455,"uptime_secs":41,"detail":"3 windows open"}
//! ```
//!
//! `state` is the only required field, and its vocabulary is *exactly*
//! [`kamaji_proto::WorkloadState`] — `pending | starting | running | draining |
//! exited | failed`. That is the whole compatibility story: the supervisor
//! already answers a `Probe` verb in these words, so a workload reporting in
//! the same words is believed verbatim instead of run through a translation
//! table that rots the first time either side gains a state. Build with the
//! `kamaji` feature and the `From` impls between the two enums are exhaustive
//! matches — adding a state to either side stops compiling until both agree.
//!
//! ## Using it
//!
//! ```no_run
//! use procctl::{ProcState, ProcStatus};
//!
//! # fn windows_open() -> usize { 3 }
//! # fn booted() -> bool { true }
//! // Hold the guard for as long as the process should answer. Dropping it
//! // stops the listener and unlinks the socket.
//! let _control = procctl::serve_env(|| {
//!     if booted() {
//!         ProcStatus::new(ProcState::Running)
//!             .with_detail(format!("{} windows open", windows_open()))
//!     } else {
//!         ProcStatus::new(ProcState::Starting)
//!     }
//! })?;
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! [`serve_env`] returns `Ok(None)` when `YAH_CONTROL_SOCK` is unset, which is
//! the contract: the same binary runs unchanged outside a camp, and a process
//! MUST NOT fail for the variable's absence.
//!
//! The closure runs on the listener thread, on demand, once per request. It
//! must not block for long and must not panic — a panic there takes the
//! listener down with it, which reads to the supervisor as a process that
//! stopped answering.
//!
//! ## What this crate deliberately is not
//!
//! It is **not required**. The protocol is one newline-delimited JSON verb
//! precisely so the producer side is implementable in twenty lines, with no
//! dependency, in any language, by someone whose actual job that day is their
//! own app. A Bun script or a Python daemon emitting the same line is a
//! first-class conforming producer. This crate is ergonomics for the Rust
//! case, not a gate — and that is also why it does not reach for
//! `kamaji-proto`'s postcard wire, which would make conforming mean linking a
//! Rust crate (W315 §"Why newline-JSON").
//!
//! The `client` feature adds the consumer half (async, tokio) for supervisors.
//! Producers should leave it off; the default build is std-only.
//!
//! @arch:see(.yah/docs/working/W315-process-control-channel.md)

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

mod serve;
pub use serve::{serve_at, serve_env, ControlServer};

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
pub use client::{fetch, fetch_at, ReadyOutcome, wait_ready};

/// Environment variable naming the control socket a supervised process should
/// bind. Absent → the process is not running under a supervisor that wants a
/// control channel, and MUST NOT fail for its absence.
pub const CONTROL_SOCK_ENV: &str = "YAH_CONTROL_SOCK";

/// Conventional HTTP path for the status document on a process that already
/// serves HTTP. Not enforced — `[process.control] http_path` overrides it —
/// but a service with no reason to differ should use this one.
pub const DEFAULT_HTTP_PATH: &str = "/_yah/status";

/// The one verb the channel requires.
pub const STATUS_CMD: &str = "status";

/// Lifecycle vocabulary of a supervised process.
///
/// Deliberately identical to [`kamaji_proto::WorkloadState`] on the wire. Kept
/// as a separate type rather than a re-export so the default build of this
/// crate — the one a workload links — carries no supervisor protocol at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcState {
    /// Accepted, nothing started yet.
    Pending,
    /// Started, not yet serving — booting, migrating, warming a cache.
    Starting,
    /// Serving. This is the only state that counts as ready.
    Running,
    /// Shutting down gracefully.
    Draining,
    /// Exited cleanly.
    Exited,
    /// Exited with a failure, or reported itself unrecoverable.
    Failed,
}

impl ProcState {
    /// Whether a process in this state is ready to be used.
    ///
    /// `Starting` is deliberately *not* ready: the entire point of the channel
    /// is to distinguish "the port is open" from "I am serving".
    pub fn is_ready(self) -> bool {
        matches!(self, ProcState::Running)
    }

    /// Whether this state is terminal — no amount of further polling changes
    /// it, so a readiness wait should fail fast rather than burn its timeout.
    pub fn is_terminal(self) -> bool {
        matches!(self, ProcState::Exited | ProcState::Failed)
    }

    /// The wire token, which is also what an operator reads in a log line.
    pub fn as_str(self) -> &'static str {
        match self {
            ProcState::Pending => "pending",
            ProcState::Starting => "starting",
            ProcState::Running => "running",
            ProcState::Draining => "draining",
            ProcState::Exited => "exited",
            ProcState::Failed => "failed",
        }
    }
}

impl std::fmt::Display for ProcState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── kamaji bridge ────────────────────────────────────────────────────────────
//
// Exhaustive on purpose: no `_` arm, no `#[non_exhaustive]` escape. If either
// vocabulary gains a state, this stops compiling, which is the only mechanism
// that keeps "believed verbatim" true a year from now.

#[cfg(feature = "kamaji")]
impl From<ProcState> for kamaji_proto::WorkloadState {
    fn from(s: ProcState) -> Self {
        match s {
            ProcState::Pending => kamaji_proto::WorkloadState::Pending,
            ProcState::Starting => kamaji_proto::WorkloadState::Starting,
            ProcState::Running => kamaji_proto::WorkloadState::Running,
            ProcState::Draining => kamaji_proto::WorkloadState::Draining,
            ProcState::Exited => kamaji_proto::WorkloadState::Exited,
            ProcState::Failed => kamaji_proto::WorkloadState::Failed,
        }
    }
}

// The reverse direction (`WorkloadState -> ProcState`) is deliberately absent.
// `WorkloadState` is `#[non_exhaustive]`, so a match on it from outside its
// crate needs a wildcard arm — and a wildcard is exactly the translation-table
// rot W315 refuses: a state added there would silently become whatever the
// wildcard picked. Nothing needs that direction anyway; the flow is workload →
// supervisor.

/// A workload's self-description. Only [`Self::state`] is required.
///
/// Field-for-field the same document `yah-cloud`'s `proc_control` client
/// parses; the two types are separate only because neither side may force its
/// dependencies on the other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcStatus {
    /// Lifecycle state, in kamaji's vocabulary.
    pub state: ProcState,
    /// Redundant convenience mirror of `state == running`, accepted from
    /// producers that emit it. Never trusted over `state` — a document
    /// claiming `{"state":"starting","ready":true}` is a producer bug, and
    /// believing the optimistic half of it is how a supervisor reports a
    /// half-booted process as up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    /// Process id. Stamped by [`ControlServer`] when the producer leaves it
    /// unset — the helper knows its own pid and cannot get it wrong.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Seconds since the process considered itself started. Stamped by
    /// [`ControlServer`] (from when the control server was started) when the
    /// producer leaves it unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    /// Build/version string, for an operator staring at two of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// One human line elaborating on `state` — "replaying WAL 3/7",
    /// "waiting for GPU". This is the field that replaces log-grepping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Named addresses the process serves — `{"http":"http://127.0.0.1:4325"}`.
    /// A portless process may legitimately name a non-URL surface here.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub endpoints: std::collections::BTreeMap<String, String>,
    /// Numeric gauges the process wants surfaced. Free-form on purpose: this
    /// is a status channel, not a metrics pipeline.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub metrics: std::collections::BTreeMap<String, f64>,
}

impl ProcStatus {
    /// A document reporting `state` and nothing else.
    pub fn new(state: ProcState) -> Self {
        Self {
            state,
            ready: None,
            pid: None,
            uptime_secs: None,
            version: None,
            detail: None,
            endpoints: Default::default(),
            metrics: Default::default(),
        }
    }

    /// The one human line that replaces log-grepping.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Build/version string. `env!("CARGO_PKG_VERSION")` is the usual argument.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Override the pid the server would otherwise stamp — for a producer that
    /// supervises something other than itself.
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Override the uptime the server would otherwise stamp.
    pub fn with_uptime_secs(mut self, secs: u64) -> Self {
        self.uptime_secs = Some(secs);
        self
    }

    /// Name an address this process serves. A portless process may legitimately
    /// name a non-URL surface (`"gui" -> "winit://main"`).
    pub fn with_endpoint(mut self, name: impl Into<String>, addr: impl Into<String>) -> Self {
        self.endpoints.insert(name.into(), addr.into());
        self
    }

    /// Surface a numeric gauge.
    pub fn with_metric(mut self, name: impl Into<String>, value: f64) -> Self {
        self.metrics.insert(name.into(), value);
        self
    }

    /// Ready iff the *state* says so. See [`Self::ready`] for why the
    /// producer-supplied boolean does not get a vote.
    pub fn is_ready(&self) -> bool {
        self.state.is_ready()
    }

    /// One-line rendering for an operator-facing note or log line.
    pub fn summary(&self) -> String {
        let mut s = self.state.as_str().to_string();
        if let Some(detail) = &self.detail {
            s.push_str(" — ");
            s.push_str(detail);
        }
        if let Some(v) = &self.version {
            s.push_str(&format!(" (v{v})"));
        }
        s
    }
}

/// The socket path this process was told to bind, or `None` outside a camp.
///
/// Producers that want to log the path (or decline the channel for their own
/// reasons) can read it without going through [`serve_env`].
pub fn control_sock_path() -> Option<PathBuf> {
    match std::env::var_os(CONTROL_SOCK_ENV) {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => None,
    }
}

/// A leftover socket *file* makes `bind` fail with `EADDRINUSE` even when
/// nothing is listening, so a stale one has to go. Removing it blindly would
/// stomp a live predecessor, so probe first: a connect that is *refused* proves
/// no one is on the other end.
fn clear_stale_socket(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!(
                "{} is already bound by a live listener — refusing to unlink it",
                path.display()
            ),
        )),
        // Refused (or anything else non-connectable) means the file outlived
        // its process. Safe to unlink.
        Err(_) => std::fs::remove_file(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// If this drifts, a workload's own report can no longer be handed to the
    /// supervisor verbatim — the entire compatibility claim of W315.
    #[test]
    fn the_state_vocabulary_is_exactly_kamajis() {
        for (state, wire) in [
            (ProcState::Pending, "\"pending\""),
            (ProcState::Starting, "\"starting\""),
            (ProcState::Running, "\"running\""),
            (ProcState::Draining, "\"draining\""),
            (ProcState::Exited, "\"exited\""),
            (ProcState::Failed, "\"failed\""),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), wire);
            assert_eq!(serde_json::from_str::<ProcState>(wire).unwrap(), state);
            assert_eq!(format!("\"{state}\""), wire, "Display must match the wire");
        }
    }

    #[test]
    fn state_is_the_only_required_field() {
        let s: ProcStatus = serde_json::from_str(r#"{"state":"running"}"#).unwrap();
        assert!(s.is_ready());
        assert_eq!(s.pid, None);
        assert!(s.endpoints.is_empty());
    }

    /// A producer that contradicts itself must not be believed on the
    /// optimistic half — that is precisely how a half-booted process gets
    /// reported as up, which is the failure this channel exists to end.
    #[test]
    fn a_ready_flag_never_overrides_a_not_running_state() {
        let s: ProcStatus = serde_json::from_str(r#"{"state":"starting","ready":true}"#).unwrap();
        assert_eq!(s.ready, Some(true), "the claim is preserved verbatim");
        assert!(!s.is_ready(), "but state decides");
    }

    #[test]
    fn absent_optionals_are_not_emitted() {
        let json = serde_json::to_string(&ProcStatus::new(ProcState::Running)).unwrap();
        assert_eq!(json, r#"{"state":"running"}"#);
    }

    #[test]
    fn the_builder_composes_a_full_document() {
        let s = ProcStatus::new(ProcState::Starting)
            .with_detail("replaying WAL 3/7")
            .with_version("0.8.23")
            .with_pid(71455)
            .with_uptime_secs(41)
            .with_endpoint("gui", "winit://main")
            .with_metric("fps", 59.9);
        assert_eq!(s.summary(), "starting — replaying WAL 3/7 (v0.8.23)");
        let round: ProcStatus = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(round, s);
    }

    #[test]
    fn terminal_and_ready_are_disjoint_and_only_running_is_ready() {
        for st in [
            ProcState::Pending,
            ProcState::Starting,
            ProcState::Draining,
            ProcState::Exited,
            ProcState::Failed,
        ] {
            assert!(!st.is_ready(), "{st} must not be ready");
        }
        assert!(ProcState::Running.is_ready());
        assert!(ProcState::Exited.is_terminal() && ProcState::Failed.is_terminal());
        assert!(!ProcState::Starting.is_terminal());
    }

    #[test]
    fn a_live_listener_is_never_unlinked() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("live.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let err = clear_stale_socket(&sock).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        assert!(sock.exists(), "the live socket must survive");
    }

    #[test]
    fn a_dead_socket_file_is_unlinked() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("dead.sock");
        {
            let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        }
        assert!(sock.exists(), "dropping a listener leaves the file behind");
        clear_stale_socket(&sock).unwrap();
        assert!(!sock.exists());
    }

    /// The claim is that these are the same six states under the same six
    /// names. Assert it against `WorkloadState`'s own `Debug`, so a rename on
    /// either side fails here rather than in a supervisor six months later.
    #[cfg(feature = "kamaji")]
    #[test]
    fn every_proc_state_maps_onto_the_kamaji_state_of_the_same_name() {
        for st in [
            ProcState::Pending,
            ProcState::Starting,
            ProcState::Running,
            ProcState::Draining,
            ProcState::Exited,
            ProcState::Failed,
        ] {
            let via: kamaji_proto::WorkloadState = st.into();
            assert_eq!(
                format!("{via:?}").to_lowercase(),
                st.as_str(),
                "{st} must map onto the kamaji state of the same name"
            );
        }
    }
}

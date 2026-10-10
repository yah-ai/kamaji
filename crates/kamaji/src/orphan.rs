//! Orphans of a previous native runtime on the same state dir (R967-B1).
//!
//! `NativeRuntime` keeps its bookkeeping in memory, so a child that outlives its
//! runtime (daemon crash, SIGKILL, a quit path that skipped teardown) is
//! invisible to the next one. Worse, `LedgerPorts` deliberately hands the
//! remembered port back to the same owner, so the replacement dies with
//! `EADDRINUSE` against its own predecessor.
//!
//! The identity of an orphan is a pid file, `<state_dir>/<ident>/pid`, holding
//! the pid and the process start time. The start time is what makes a recycled
//! pid distinguishable; argv / basename matching is deliberately NOT used,
//! because another workspace's camp runs a same-named binary on its own ports.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Name of the pid file inside a workload's state dir.
const PID_FILE: &str = "pid";

pub(crate) fn pid_path(state_dir: &Path, ident: &str) -> PathBuf {
    state_dir.join(ident).join(PID_FILE)
}

/// Opaque process start time, comparable only against itself.
pub(crate) fn start_time(pid: u32) -> Option<String> {
    imp::start_time(pid)
}

/// Record `pid` (and its start time) as the live child of `ident`; if `pid` is
/// already dead, remove the file instead.
pub(crate) fn record(state_dir: &Path, ident: &str, pid: u32) {
    // No readable start time means the process is already gone: nothing is
    // running, so nothing should be recorded - and a file left from an earlier
    // child must not keep naming it.
    let Some(start) = start_time(pid) else {
        clear(state_dir, ident);
        return;
    };
    let path = pid_path(state_dir, ident);
    if let Err(e) = std::fs::write(&path, format!("{pid} {start}\n")) {
        tracing::warn!(path = %path.display(), "could not record the child's pid: {e}");
    }
}

/// Forget the recorded child (clean exit / teardown).
pub(crate) fn clear(state_dir: &Path, ident: &str) {
    let _ = std::fs::remove_file(pid_path(state_dir, ident));
}

fn read(state_dir: &Path, ident: &str) -> Option<(u32, String)> {
    let text = std::fs::read_to_string(pid_path(state_dir, ident)).ok()?;
    let (pid, start) = text.trim().split_once(' ')?;
    Some((pid.parse().ok()?, start.to_string()))
}

fn alive(pid: u32) -> bool {
    // SAFETY: signal 0 only probes for existence.
    unsafe {
        libc::kill(pid as i32, 0) == 0
            || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

async fn wait_gone(pid: u32, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while alive(pid) {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    true
}

/// If `ident` has a recorded child from a previous runtime that is still the
/// same live process, SIGTERM it, wait `grace`, SIGKILL, and wait for exit.
/// Always leaves no pid file behind. Returns the pid reaped, if any.
pub(crate) async fn reap(state_dir: &Path, ident: &str, grace: Duration) -> Option<u32> {
    let recorded = read(state_dir, ident);
    clear(state_dir, ident);
    let (pid, start) = recorded?;
    if pid == 0 || !alive(pid) || start_time(pid).as_deref() != Some(start.as_str()) {
        return None;
    }
    tracing::warn!(
        workload = ident,
        pid,
        "reaping the orphaned child of a previous native runtime on this state dir"
    );
    // SAFETY: plain kill(2) on a pid whose identity was just verified.
    unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if !wait_gone(pid, grace).await {
        // SAFETY: as above.
        unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        wait_gone(pid, Duration::from_secs(5)).await;
    }
    Some(pid)
}

/// `true` when a listener already answers on `bind_ip:port`.
///
/// A connect probe rather than the ledger's bind probe (`ports::is_free`), for
/// two reasons measured while fixing R967-B1. (1) On macOS a SO_REUSEADDR bind
/// to a specific IP succeeds while another socket holds `*:P`, and the dev
/// drivers bind `0.0.0.0` against a loopback `bind_ip`; a bind probe misses
/// exactly the orphan this module exists for. (2) A bind probe also trips on
/// sockets that merely own the number (another process's ephemeral source
/// port), which flaked unrelated parallel deploys. A connect to `bind_ip:P` is
/// answered only by a listener that would conflict at that address - a wildcard
/// holder or one on the same IP, never one on a neighbouring mesh IP.
pub(crate) fn is_held(bind_ip: Ipv4Addr, port: u16) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(bind_ip), port);
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250))
        // A connect to an unbound loopback port in the ephemeral range can
        // TCP-simultaneous-open with ITSELF and "succeed"; that is not a holder.
        .is_ok_and(|c| c.local_addr().ok() != Some(addr))
}

/// [`is_held`], confirmed after a short settle. A number the ledger remembers
/// was released the moment it was picked, so a listener that is merely passing
/// through it (another process's ephemeral bind, a socket still closing) must
/// not fail a deploy; a real squatter is still there a moment later.
pub(crate) async fn is_held_settled(bind_ip: Ipv4Addr, port: u16) -> bool {
    if !is_held(bind_ip, port) {
        return false;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    is_held(bind_ip, port)
}

/// Best-effort "who listens on `port`" for an error message only:
/// `pid 123 (name)`, or `pid unknown`.
pub(crate) fn describe_holder(port: u16) -> String {
    let out = std::process::Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fpc"])
        .output();
    let Ok(out) = out else {
        return "pid unknown".to_string();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let pid = text.lines().find_map(|l| l.strip_prefix('p'));
    let cmd = text.lines().find_map(|l| l.strip_prefix('c'));
    match (pid, cmd) {
        (Some(p), Some(c)) => format!("pid {p} ({c})"),
        (Some(p), None) => format!("pid {p}"),
        _ => "pid unknown".to_string(),
    }
}

#[cfg(target_os = "macos")]
mod imp {
    pub fn start_time(pid: u32) -> Option<String> {
        let pid = i32::try_from(pid).ok().filter(|p| *p > 0)?;
        // SAFETY: proc_pidinfo writes at most `size` bytes into the POD struct
        // we hand it; zeroed is a valid starting value.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        let rc = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if rc < size {
            return None;
        }
        Some(format!("{}.{}", info.pbi_start_tvsec, info.pbi_start_tvusec))
    }
}

#[cfg(target_os = "linux")]
mod imp {
    pub fn start_time(pid: u32) -> Option<String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // comm (field 2) may contain spaces/parens; fields resume after the last ')'.
        let rest = &stat[stat.rfind(')')? + 1..];
        // rest begins at field 3, so field 22 is index 19.
        rest.split_whitespace().nth(19).map(str::to_string)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod imp {
    pub fn start_time(_pid: u32) -> Option<String> {
        None
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn recording_a_dead_pid_removes_the_file_instead_of_leaving_a_stale_one() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("w")).unwrap();
        record(tmp.path(), "w", std::process::id());
        assert!(pid_path(tmp.path(), "w").exists());

        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        record(tmp.path(), "w", dead);
        assert!(!pid_path(tmp.path(), "w").exists());
    }
}

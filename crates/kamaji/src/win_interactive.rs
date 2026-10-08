//! The interactive-session bridge for native-exec on a WSL host (R918-F8).
//!
//! Every Windows process a native workload starts through WSL interop runs in
//! session 0, because kamaji is systemd-parented: no desktop, no window station
//! a GUI test can use, and no way to even *see* the logged-on user's windows.
//! [`win_interactive.sh`](./win_interactive.sh) is the way across — it hands one
//! command line to the interactive session as a one-shot `/IT` scheduled task,
//! waits, relays the output, and exits with the job's code (69 when nobody is
//! logged on). The script's header carries the mechanism and its traps.
//!
//! This module only puts it within reach: on a host where WSL interop is
//! registered, [`materialize`] writes the script into the backend's state dir
//! and the spawn path exports its path as [`ENV`]. A step opts in by calling
//! `"$YAH_WIN_INTERACTIVE" <windows command line>`; nothing is wrapped
//! implicitly, so a step that does not ask keeps exactly the session-0
//! behaviour it had.
//!
//! Task-scoped rather than a resident agent, on purpose: on us-west-002 the
//! interactive session is an RDP session that dies on logoff and with the box's
//! sleep cycle, and there is no wake path, so a resident agent would be dead
//! most of the time it was wanted. A per-job task degrades to an honest error.

use std::path::{Path, PathBuf};

/// The variable a native child reads the bridge's path from.
pub const ENV: &str = "YAH_WIN_INTERACTIVE";

/// The bridge itself, compiled in so the node needs nothing installed.
pub const BRIDGE: &str = include_str!("win_interactive.sh");

/// Registered by WSL for `.exe` interop; present exactly when a child could
/// launch a Windows binary at all.
const INTEROP_MARKER: &str = "/proc/sys/fs/binfmt_misc/WSLInterop";

/// Whether this host can run Windows binaries through WSL interop.
pub fn interop_available() -> bool {
    Path::new(INTEROP_MARKER).exists()
}

/// Where the bridge lives under a backend's `state_dir`. A dot-dir, so it can
/// never collide with a workload's own dir (a `MeshIdent` is DNS-shaped).
pub fn bridge_path(state_dir: &Path) -> PathBuf {
    state_dir.join(".win-interactive").join("win-interactive")
}

/// Write the bridge when `interop` says this host has Windows to bridge to.
///
/// Idempotent and cheap on the hot path: an up-to-date copy is left alone, so
/// a respawn costs one read. A stale copy (kamaji upgraded under a running
/// node) is replaced by write-then-rename, so a concurrently spawning child
/// never executes a half-written script. The bridge stages its jobs beside
/// itself, which is why it must live in kamaji's writable state dir rather
/// than anywhere ProtectSystem=strict leaves read-only.
pub async fn materialize(state_dir: &Path, interop: bool) -> std::io::Result<Option<PathBuf>> {
    if !interop {
        return Ok(None);
    }
    let path = bridge_path(state_dir);
    let current = tokio::fs::read(&path).await.ok();
    if current.as_deref() != Some(BRIDGE.as_bytes()) {
        let write_path = path.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            if let Some(dir) = write_path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            crate::atomic_file::write_atomic(&write_path, BRIDGE.as_bytes())
        })
        .await
        .map_err(std::io::Error::other)??;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = tokio::fs::metadata(&path).await?.permissions().mode();
        if mode & 0o755 != 0o755 {
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).await?;
        }
    }
    Ok(Some(path))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    #[tokio::test]
    async fn a_host_without_interop_gets_no_bridge() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(materialize(tmp.path(), false).await.unwrap(), None);
        assert!(!bridge_path(tmp.path()).exists());
    }

    #[tokio::test]
    async fn an_interop_host_gets_an_executable_current_bridge() {
        let tmp = tempfile::tempdir().unwrap();
        let path = materialize(tmp.path(), true).await.unwrap().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), BRIDGE);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o755);

        // A stale copy from an older kamaji is replaced, not trusted.
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        materialize(tmp.path(), true).await.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), BRIDGE);
    }

    /// A fake `System32`: `cmd.exe` exists, `query.exe` prints `rows`.
    fn fake_system32(rows: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, body: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        write("cmd.exe", "#!/bin/sh\nexit 0\n");
        write("query.exe", &format!("#!/bin/sh\nprintf '%s' '{rows}'\nexit 1\n"));
        dir
    }

    fn run_bridge(sys32: &Path, args: &[&str]) -> std::process::Output {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("win-interactive");
        std::fs::write(&script, BRIDGE).unwrap();
        Command::new("/bin/sh")
            .arg(&script)
            .args(args)
            .env("YAH_WIN_SYSTEM32", sys32)
            .output()
            .unwrap()
    }

    #[test]
    fn the_bridge_parses_as_posix_sh() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("win-interactive");
        std::fs::write(&script, BRIDGE).unwrap();
        let out = Command::new("/bin/sh").arg("-n").arg(&script).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn no_arguments_is_a_usage_error() {
        let sys32 = fake_system32("");
        assert_eq!(run_bridge(sys32.path(), &[]).status.code(), Some(64));
    }

    #[test]
    fn a_host_without_cmd_exe_is_a_bridge_failure_not_a_job_failure() {
        let empty = tempfile::tempdir().unwrap();
        let out = run_bridge(empty.path(), &["notepad.exe"]);
        assert_eq!(out.status.code(), Some(70));
        assert!(String::from_utf8_lossy(&out.stderr).contains("no Windows interop"));
    }

    /// The typed "nobody is logged on" answer. These are us-west-002's real
    /// rows with the RDP user gone: the services session and the console both
    /// exist, neither has a user, and a `Disc` session would have no desktop
    /// even if it did.
    #[test]
    fn no_active_user_session_exits_69_and_says_so() {
        let sys32 = fake_system32(
            " SESSIONNAME       USERNAME     ID  STATE   TYPE        DEVICE \r\n\
             >services                        0  Disc                        \r\n\
             \x20                 struc         2  Disc                        \r\n\
             \x20console                       3  Conn                        \r\n\
             \x20rdp-tcp                   65536  Listen                      \r\n",
        );
        let out = run_bridge(sys32.path(), &["notepad.exe"]);
        assert_eq!(out.status.code(), Some(69));
        assert!(String::from_utf8_lossy(&out.stderr).contains("no interactive session available"));
    }
}

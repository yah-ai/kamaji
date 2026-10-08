//! macOS TCC responsibility disclaim (R940-B1).
//!
//! macOS attributes a process's privacy access (Bluetooth, camera, microphone,
//! local network, …) to its *responsible process* — by default the app bundle
//! at the top of its spawn tree, not the binary asking. So a BLE binary started
//! from an agent's Bash under yah desktop is judged against yah's Info.plist,
//! and lacking `NSBluetoothAlwaysUsageDescription` there it is SIGABRTed in the
//! TCC namespace — even though its own embedded plist carries the key.
//!
//! Terminal, iTerm and Xcode avoid this with `responsibility_spawnattrs_setdisclaim`,
//! a private-but-stable libSystem SPI on `posix_spawnattr_t`: a child spawned
//! with it is its own responsible process, so its own plist governs (and the
//! prompt names it, not yah). Disclaim propagates — everything that child
//! spawns inherits the child as responsible, not yah.
//!
//! `std::process::Command` exposes no spawnattr, so [`disclaim_at_exec`] does it
//! from the last `pre_exec` hook: `std` has already done stdio, cwd, process
//! group and signal reset by then, and the hook replaces the final `execvp` with
//! `posix_spawn(POSIX_SPAWN_SETEXEC)` carrying the disclaim attr. On success it
//! never returns; on failure it reports the errno and `std` fails the spawn.
//!
//! Limitation: `Command::env_clear()` is not observable through `std`'s public
//! API, so the environment is rebuilt as inherited + `get_envs()` overrides.
//! No caller here clears the environment.

use std::process::Command;

/// Register the disclaiming exec on `cmd`. MUST be the last `pre_exec` hook
/// registered — it does not return on success, so any hook after it never runs.
/// A no-op off macOS, and a no-op (plain exec) if the SPI cannot be resolved.
#[cfg(target_os = "macos")]
pub fn disclaim_at_exec(cmd: &mut Command) -> std::io::Result<()> {
    use std::ffi::{CString, OsStr, OsString};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;

    type SetDisclaim = unsafe extern "C" fn(*mut libc::posix_spawnattr_t, libc::c_int) -> libc::c_int;
    // SAFETY: dlsym on RTLD_DEFAULT with a NUL-terminated literal.
    let sym = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"responsibility_spawnattrs_setdisclaim".as_ptr(),
        )
    };
    if sym.is_null() {
        tracing::warn!("responsibility_spawnattrs_setdisclaim unavailable; child stays attributed to its ancestor");
        return Ok(());
    }
    // SAFETY: the symbol's ABI is (posix_spawnattr_t *, int) -> int.
    let set_disclaim: SetDisclaim = unsafe { std::mem::transmute(sym) };

    let cstr = |s: &OsStr| {
        CString::new(s.as_bytes()).map_err(|_| std::io::Error::other("NUL byte in spawn argument"))
    };

    // Environment: inherited, then the command's overrides (None = removed).
    let mut env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    for (k, v) in cmd.get_envs() {
        env.retain(|(ek, _)| ek != k);
        if let Some(v) = v {
            env.push((k.to_owned(), v.to_owned()));
        }
    }

    // Resolve the program the way execvp would, against the CHILD's PATH and
    // cwd, since posix_spawn (unlike posix_spawnp) wants a path.
    let program = cmd.get_program().to_owned();
    let path = if program.as_bytes().contains(&b'/') {
        let p = std::path::PathBuf::from(&program);
        match (p.is_relative(), cmd.get_current_dir()) {
            (true, Some(dir)) => dir.join(p),
            _ => p,
        }
    } else {
        let search = env
            .iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "/usr/bin:/bin".into());
        std::env::split_paths(&search)
            .map(|d| d.join(&program))
            .find(|p| is_executable(p))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("{} not found on PATH", program.to_string_lossy()),
                )
            })?
    };

    let path_c = cstr(path.as_os_str())?;
    let argv_c: Vec<CString> = std::iter::once(cstr(&program))
        .chain(cmd.get_args().map(cstr))
        .collect::<Result<_, _>>()?;
    let envp_c: Vec<CString> = env
        .iter()
        .map(|(k, v)| {
            let mut kv = k.as_bytes().to_vec();
            kv.push(b'=');
            kv.extend_from_slice(v.as_bytes());
            CString::new(kv).map_err(|_| std::io::Error::other("NUL byte in environment"))
        })
        .collect::<Result<_, _>>()?;

    // Everything the child touches is built here, pre-fork; the hook only reads
    // it and makes two libc calls, so it is allocation-free.
    struct Prepared {
        path: CString,
        _argv: Vec<CString>,
        _envp: Vec<CString>,
        argv: Vec<*mut libc::c_char>,
        envp: Vec<*mut libc::c_char>,
        set_disclaim: SetDisclaim,
    }
    // SAFETY: the raw pointers point into the owned CStrings above and are only
    // dereferenced in the forked child.
    unsafe impl Send for Prepared {}
    unsafe impl Sync for Prepared {}
    let argv = argv_c
        .iter()
        .map(|c| c.as_ptr() as *mut _)
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();
    let envp = envp_c
        .iter()
        .map(|c| c.as_ptr() as *mut _)
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();
    let p = Prepared {
        path: path_c,
        _argv: argv_c,
        _envp: envp_c,
        argv,
        envp,
        set_disclaim,
    };

    // SAFETY: runs post-fork; only posix_spawnattr_* / posix_spawn on memory
    // prepared above. POSIX_SPAWN_SETEXEC makes posix_spawn an execve that
    // honours the attrs, so on success this never returns.
    unsafe {
        cmd.pre_exec(move || {
            // Capture `p` whole (its Send/Sync impl), not its raw-pointer fields.
            let p = &p;
            let mut attr: libc::posix_spawnattr_t = std::ptr::null_mut();
            let rc = libc::posix_spawnattr_init(&mut attr);
            if rc != 0 {
                return Err(std::io::Error::from_raw_os_error(rc));
            }
            libc::posix_spawnattr_setflags(&mut attr, libc::POSIX_SPAWN_SETEXEC as libc::c_short);
            (p.set_disclaim)(&mut attr, 1);
            let rc = libc::posix_spawn(
                std::ptr::null_mut(),
                p.path.as_ptr(),
                std::ptr::null(),
                &attr,
                p.argv.as_ptr(),
                p.envp.as_ptr(),
            );
            Err(std::io::Error::from_raw_os_error(rc))
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Off macOS there is no TCC and no responsible-process attribution.
#[cfg(not(target_os = "macos"))]
pub fn disclaim_at_exec(_cmd: &mut Command) -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// The disclaiming exec still runs the right program with the right args,
    /// env overrides, cwd and stdio — i.e. it is a drop-in for std's execvp.
    #[test]
    fn disclaimed_child_runs_with_args_env_and_cwd() {
        let dir = std::env::temp_dir();
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "printf '%s|%s|%s' \"$1\" \"$R940_PROBE\" \"$(pwd -P)\"", "sh", "arg1"])
            .env("R940_PROBE", "set")
            .current_dir(&dir);
        disclaim_at_exec(&mut cmd).unwrap();
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "{out:?}");
        let want = format!("arg1|set|{}", dir.canonicalize().unwrap().display());
        assert_eq!(String::from_utf8_lossy(&out.stdout), want);
    }

    /// The point of the module: a disclaimed child is its OWN responsible
    /// process; a plain child inherits ours. Read via the companion SPI
    /// `responsibility_get_pid_responsible_for_pid`.
    #[test]
    fn disclaimed_child_is_its_own_responsible_process() {
        type Resp = unsafe extern "C" fn(libc::pid_t) -> libc::pid_t;
        // SAFETY: dlsym with a literal; ABI is (pid_t) -> pid_t.
        let sym = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"responsibility_get_pid_responsible_for_pid".as_ptr(),
            )
        };
        assert!(!sym.is_null(), "responsibility SPI missing");
        let resp: Resp = unsafe { std::mem::transmute(sym) };

        let responsible_of = |disclaim: bool| {
            let mut cmd = Command::new("sleep");
            cmd.arg("5");
            if disclaim {
                disclaim_at_exec(&mut cmd).unwrap();
            }
            let mut child = cmd.spawn().unwrap();
            let pid = child.id() as libc::pid_t;
            // Let the exec land before asking.
            std::thread::sleep(std::time::Duration::from_millis(200));
            let r = unsafe { resp(pid) };
            child.kill().ok();
            child.wait().ok();
            (pid, r)
        };
        let (pid, r) = responsible_of(true);
        assert_eq!(r, pid, "disclaimed child must be responsible for itself");
        let (pid, r) = responsible_of(false);
        assert_ne!(r, pid, "a plain child inherits its ancestor's responsibility");
    }

    /// A missing program surfaces as a spawn error, not a hang or a zombie.
    #[test]
    fn missing_program_fails_the_spawn() {
        let mut cmd = Command::new("definitely-not-a-binary-r940");
        assert!(disclaim_at_exec(&mut cmd).is_err());
    }
}

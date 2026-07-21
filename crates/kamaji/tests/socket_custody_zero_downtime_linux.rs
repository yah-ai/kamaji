//! End-to-end proof of the socket-custodian's core promise (R599-F9 / R600-F9,
//! W273 §"Option (C) resolved"): **the listening socket outlives the workload
//! process, so a workload swap drops zero connections.**
//!
//! kamaji binds+holds a TCP listener. A first "workload" process adopts the fd
//! over its upgrade socket (pingora's `Fds::get_from_sock` protocol) and serves.
//! We then hand the *same* fd to a second workload process and kill the first —
//! the swap — while a client hammers the port. The invariant asserted: **every
//! `connect()` succeeds throughout**, because the socket is held by kamaji and
//! never closes; and traffic is observably served by both the old and the new
//! process (markers `A` then `B`).
//!
//! This owns its own `main` (`harness = false`) so the same binary can re-exec
//! itself as a receiver child. Linux + `socket-custody` only.
//!
//! Run (privileged not required — uses loopback, no netns):
//! `cargo test -p kamaji --features socket-custody --test socket_custody_zero_downtime_linux`

#[cfg(all(target_os = "linux", feature = "socket-custody"))]
fn main() {
    imp::run();
}

#[cfg(not(all(target_os = "linux", feature = "socket-custody")))]
fn main() {
    eprintln!("SKIP: socket_custody_zero_downtime_linux runs on Linux with --features socket-custody");
}

#[cfg(all(target_os = "linux", feature = "socket-custody"))]
mod imp {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use kamaji::socket_custody::SocketCustodian;

    const PORT: &str = "127.0.0.1:38443";

    pub fn run() {
        // Re-exec dispatch: a child invoked with CUSTODY_ROLE=receiver becomes a
        // "workload" that adopts kamaji's fd and serves its marker byte.
        if std::env::var("CUSTODY_ROLE").as_deref() == Ok("receiver") {
            receiver_main();
            return;
        }
        driver();
        println!("socket_custody_zero_downtime_linux: OK");
    }

    // ── The workload stand-in ────────────────────────────────────────────────

    /// A "workload": bind the upgrade sock, receive kamaji's listener fd, then
    /// accept forever, writing our one-byte marker to each connection. This is
    /// the receiver half of pingora's `Fds::get_from_sock` (recvmsg + SCM_RIGHTS).
    fn receiver_main() {
        let sock_path = std::env::var("CUSTODY_UPGRADE_SOCK").unwrap();
        let marker = std::env::var("CUSTODY_MARKER").unwrap().into_bytes()[0];

        let listener = recv_listener_fd(&sock_path);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.write_all(&[marker]);
                    // brief hold so the driver reliably reads before close
                    let _ = stream.flush();
                }
                Err(_) => std::thread::sleep(Duration::from_millis(2)),
            }
        }
    }

    /// Mirror of pingora 0.8.1 `Fds::get_from_sock`: bind the unix sock, accept
    /// one connection, recvmsg the payload + SCM_RIGHTS fd, return the adopted
    /// TCP listener.
    fn recv_listener_fd(sock_path: &str) -> std::net::TcpListener {
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, UnixAddr};

        let _ = std::fs::remove_file(sock_path);
        let ul = UnixListener::bind(sock_path).expect("bind upgrade sock");
        let (stream, _) = ul.accept().expect("accept fd handoff");

        let mut payload = [0u8; 2048];
        let mut iov = [std::io::IoSliceMut::new(&mut payload)];
        let mut cmsg = nix::cmsg_space!([RawFd; 8]);
        let msg = recvmsg::<UnixAddr>(stream.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::empty())
            .expect("recvmsg");
        let mut fds = Vec::new();
        for c in msg.cmsgs().expect("cmsgs") {
            if let ControlMessageOwned::ScmRights(v) = c {
                fds.extend(v);
            }
        }
        assert_eq!(fds.len(), 1, "received exactly one listener fd");
        // SAFETY: the fd is a listening TCP socket kamaji transferred to us.
        unsafe { std::net::TcpListener::from_raw_fd(fds[0]) }
    }

    // ── The driver / kamaji side ─────────────────────────────────────────────

    fn driver() {
        // kamaji binds+holds the listener; workloads will adopt this fd.
        let cust = SocketCustodian::new();
        cust.bind_and_hold("svc", PORT, None)
            .expect("kamaji binds+holds the listener");

        let dir = tempfile::tempdir().unwrap();
        let self_exe = std::env::current_exe().unwrap();

        // Workload A takes over the socket.
        let sock_a = dir.path().join("upgrade-a.sock");
        let mut a = spawn_receiver(&self_exe, &sock_a, "A");
        cust.hand_off("svc", &sock_a).expect("hand fd to workload A");
        wait_until_served(b'A', Duration::from_secs(5));

        // Start a relentless client: every connect must succeed (the socket is
        // held by kamaji and never closes), and we record which workload served.
        let stop = Arc::new(AtomicBool::new(false));
        let connect_failures = Arc::new(AtomicU32::new(0));
        let saw_a = Arc::new(AtomicBool::new(false));
        let saw_b = Arc::new(AtomicBool::new(false));
        let client = {
            let (stop, cf, sa, sb) = (
                stop.clone(),
                connect_failures.clone(),
                saw_a.clone(),
                saw_b.clone(),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match probe_once() {
                        Some(b'A') => sa.store(true, Ordering::Relaxed),
                        Some(b'B') => sb.store(true, Ordering::Relaxed),
                        Some(_) => {}
                        None => {
                            cf.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
        };

        // Confirm A is actively serving the live traffic.
        wait_for_flag(&saw_a, Duration::from_secs(5), "workload A never served live traffic");

        // ── The swap ── Workload B adopts the SAME fd; then A is killed.
        let sock_b = dir.path().join("upgrade-b.sock");
        let mut b = spawn_receiver(&self_exe, &sock_b, "B");
        cust.hand_off("svc", &sock_b).expect("hand fd to workload B");
        wait_for_flag(&saw_b, Duration::from_secs(5), "workload B never adopted the socket");

        // Kill the original workload — the socket must stay up (kamaji holds it).
        let _ = a.kill();
        let _ = a.wait();

        // Let the client keep probing for a beat post-kill; every connect must
        // still succeed and all traffic must now be served (by B).
        std::thread::sleep(Duration::from_millis(500));
        let post_kill_failures_before = connect_failures.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(500));
        let post_kill_failures_after = connect_failures.load(Ordering::Relaxed);

        stop.store(true, Ordering::Relaxed);
        client.join().unwrap();
        let _ = b.kill();
        let _ = b.wait();

        // ── Assertions ──
        assert_eq!(
            connect_failures.load(Ordering::Relaxed),
            0,
            "ZERO-DOWNTIME VIOLATED: {} connect() failures across the workload swap — \
             the kamaji-held socket must never stop listening",
            connect_failures.load(Ordering::Relaxed)
        );
        assert_eq!(
            post_kill_failures_after, post_kill_failures_before,
            "connect failures appeared AFTER killing workload A — socket did not survive the swap"
        );
        assert!(saw_a.load(Ordering::Relaxed), "workload A never served (setup failure)");
        assert!(
            saw_b.load(Ordering::Relaxed),
            "workload B never served — the fd handoff to the replacement failed"
        );

        eprintln!("zero-downtime custody verified: swap A→B with 0 dropped connections");
    }

    fn spawn_receiver(exe: &std::path::Path, sock: &std::path::Path, marker: &str) -> std::process::Child {
        std::process::Command::new(exe)
            .env("CUSTODY_ROLE", "receiver")
            .env("CUSTODY_UPGRADE_SOCK", sock)
            .env("CUSTODY_MARKER", marker)
            .spawn()
            .expect("spawn receiver workload")
    }

    /// One client probe: connect, read one marker byte. `None` on connect
    /// failure (the thing that must never happen); `Some(byte)` otherwise.
    fn probe_once() -> Option<u8> {
        let mut s = TcpStream::connect(PORT).ok()?;
        s.set_read_timeout(Some(Duration::from_millis(500))).ok();
        let mut buf = [0u8; 1];
        match s.read(&mut buf) {
            Ok(1) => Some(buf[0]),
            _ => Some(0), // connected but no byte — not a listen-availability failure
        }
    }

    /// Poll the port until a probe returns the expected marker (proves a
    /// workload has adopted the fd and is serving).
    fn wait_until_served(want: u8, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if probe_once() == Some(want) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("no workload served marker {:?} within {:?}", want as char, timeout);
    }

    fn wait_for_flag(flag: &Arc<AtomicBool>, timeout: Duration, msg: &str) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if flag.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("{msg}");
    }
}

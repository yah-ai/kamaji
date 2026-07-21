//! `SocketCustodian` — kamaji as the custodian of a workload's listening
//! socket (R599-F9).
//!
//! ## Why kamaji holds the socket
//!
//! A running passway (pingora, rustls backend) physically cannot hot-swap a
//! rotated TLS cert without a **process** handoff (pingora 0.8.1's rustls
//! `ServerConfig` is static — see `passway/src/tls.rs`). And the JIT
//! ("serverless") lifecycle wants a process to appear on the first connection
//! and be reaped when idle. Both need the same invariant: **the listening
//! socket must outlive the individual workload process.** The cleanest way to
//! guarantee that is to make the socket someone else's property — kamaji's.
//!
//! kamaji `bind()`s the listener **once** (optionally inside the workload's
//! mesh network namespace) and holds the `OwnedFd`. Workload processes come and
//! go; each new one adopts kamaji's fd instead of binding fresh, so the kernel
//! keeps the socket (and its accept queue) alive across the swap and no
//! connection is dropped. This is the shared primitive under **R599-F6** (JIT
//! lazy-fork + idle reap) and **R600-F9** (cert-rotation zero-downtime). See
//! W273 §"Option (C) resolved: kamaji as fd-custodian" and W272 §3.
//!
//! ## How the fd reaches the workload (pingora-compatible, pingora untouched)
//!
//! pingora already knows how to *receive* listening fds: a process started in
//! upgrade mode (passway: `PASSWAY_UPGRADE=true`) binds its
//! `PASSWAY_UPGRADE_SOCK` and waits as the **receiver** of pingora's
//! `transfer_fd` handoff (`Fds::get_from_sock`). During a normal pingora
//! upgrade the *old* process is the sender. kamaji simply plays that sender
//! role: it connects to the workload's upgrade socket and `sendmsg`s the held
//! fd(s) as `SCM_RIGHTS` control data, with the space-joined bind-address
//! strings as the message payload — the exact wire shape pingora's
//! `Fds::send_to_sock` produces. pingora's listener then adopts the fd whenever
//! the bind-address key matches (`l4.rs::listen`: `table.get(addr) ->
//! from_raw_fd`, else bind fresh), so the key **must** byte-match the
//! workload's configured listen address (e.g. `"0.0.0.0:443"`).
//!
//! We deliberately do **not** depend on `pingora-core` to call
//! `Fds::send_to_sock` directly: kamaji is a lean supervisor that is linked
//! *inlined* into the desktop app, and `pingora-core` drags in the entire
//! rustls/h2/boringssl stack. The sender is ~30 lines of `nix` and is pinned,
//! by the doc-comment and a round-trip wire test below, to pingora 0.8.1's
//! format (space-separated bind keys + one `sendmsg` carrying `ScmRights`).
//! Re-verify [`send_listener_fds`] against `transfer_fd/mod.rs` on a
//! pingora bump. The mesofact JIT runtime (R599-F6) is our own binary and can
//! use the same receiver protocol or a plain `LISTEN_FDS` inheritance.
//!
//! ## Netns custody
//!
//! On a fleet node the workload listens inside a WireGuard netns
//! (`MeshAssignment.netns_name`). A socket's netns is fixed at `socket()` time,
//! so once kamaji creates the listener **inside** that netns the fd works in
//! the workload regardless of the workload's own netns — no co-resident
//! "pause" container is required (contrast R600-F7 option B). But the netns
//! must stay *alive* for the bound socket to remain routable, so the custodian
//! also holds an **open fd to the netns** for as long as it holds sockets in
//! it. Entering the netns to bind is Linux-only and runs on a throwaway thread
//! so the async runtime's worker threads are never moved between namespaces.

use std::collections::HashMap;
use std::io;
use std::net::TcpListener;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Bind a plain TCP listener on `bind_addr` and return its owned fd.
///
/// The listener is left blocking; pingora sets non-blocking itself when it
/// adopts the fd (`from_raw_fd`). `bind_addr` is a `host:port` string — the
/// same one the workload is configured to listen on, since it becomes the
/// handoff key.
pub fn bind_listener(bind_addr: &str) -> io::Result<OwnedFd> {
    let listener = TcpListener::bind(bind_addr)?;
    Ok(OwnedFd::from(listener))
}

/// Bind a listener for `bind_addr` **inside** the network namespace named by
/// `netns_path` (e.g. `/var/run/netns/<name>` or `/proc/<pid>/ns/net`).
///
/// The `setns(2)` + `socket()`/`bind()` runs on a dedicated thread so the
/// caller's (tokio worker) thread is never moved between namespaces. The
/// returned socket keeps the target netns for its lifetime regardless of which
/// namespace the holder or the eventual workload runs in.
///
/// Requires `CAP_SYS_ADMIN`. Linux-only.
#[cfg(target_os = "linux")]
pub fn bind_listener_in_netns(bind_addr: &str, netns_path: &Path) -> io::Result<OwnedFd> {
    use nix::sched::{setns, CloneFlags};
    use std::os::fd::AsFd;

    let bind_addr = bind_addr.to_string();
    let netns_path = netns_path.to_path_buf();

    // Run the namespace switch + bind on a throwaway thread. When the thread
    // exits its netns association dies with it; the *socket* it created retains
    // the target netns (netns is fixed at socket() creation), which is exactly
    // what we return.
    std::thread::scope(|scope| {
        scope
            .spawn(move || -> io::Result<OwnedFd> {
                let ns = std::fs::File::open(&netns_path).map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("opening netns {}: {e}", netns_path.display()),
                    )
                })?;
                setns(ns.as_fd(), CloneFlags::CLONE_NEWNET)
                    .map_err(|e| io::Error::other(format!("setns(CLONE_NEWNET): {e}")))?;
                // Now in the target netns: bind the listener there.
                let listener = TcpListener::bind(&bind_addr)?;
                Ok(OwnedFd::from(listener))
            })
            .join()
            .map_err(|_| io::Error::other("netns bind thread panicked"))?
    })
}

/// Hand the held listener fd(s) to a workload process over its pingora upgrade
/// socket, using pingora 0.8.1's `transfer_fd` wire format.
///
/// `binds` is `(bind_address_key, fd)` pairs; the keys are space-joined into
/// the message payload and the fds are sent as one `SCM_RIGHTS` control
/// message, in matching order — exactly what pingora's receiver
/// (`Fds::get_from_sock`) expects. The workload must already be waiting on
/// `upgrade_sock` (started in upgrade mode); we retry the connect while it
/// comes up.
#[cfg(unix)]
pub fn send_listener_fds(upgrade_sock: &Path, binds: &[(&str, RawFd)]) -> io::Result<()> {
    use nix::sys::socket::{
        connect, sendmsg, socket, AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType,
        UnixAddr,
    };
    use std::time::Duration;

    if binds.is_empty() {
        return Ok(());
    }

    let payload = binds
        .iter()
        .map(|(key, _)| *key)
        .collect::<Vec<_>>()
        .join(" ");
    let raw_fds: Vec<RawFd> = binds.iter().map(|(_, fd)| *fd).collect();

    let addr = UnixAddr::new(upgrade_sock)
        .map_err(|e| io::Error::other(format!("upgrade sock addr {}: {e}", upgrade_sock.display())))?;

    let sock = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| io::Error::other(format!("socket(AF_UNIX): {e}")))?;

    // The workload may not have bound the upgrade sock yet — retry the connect
    // while it starts (mirrors pingora's send_fds_to ENOENT/ECONNREFUSED retry).
    const MAX_RETRY: usize = 10;
    const RETRY_INTERVAL: Duration = Duration::from_millis(200);
    let mut attempt = 0;
    loop {
        match connect(sock.as_raw_fd(), &addr) {
            Ok(()) => break,
            Err(nix::errno::Errno::ENOENT)
            | Err(nix::errno::Errno::ECONNREFUSED)
            | Err(nix::errno::Errno::EACCES)
                if attempt < MAX_RETRY =>
            {
                attempt += 1;
                std::thread::sleep(RETRY_INTERVAL);
            }
            Err(e) => {
                return Err(io::Error::other(format!(
                    "connect({}): {e}",
                    upgrade_sock.display()
                )))
            }
        }
    }

    let iov = [io::IoSlice::new(payload.as_bytes())];
    let cmsg = [ControlMessage::ScmRights(&raw_fds)];
    sendmsg::<UnixAddr>(sock.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .map_err(|e| io::Error::other(format!("sendmsg(SCM_RIGHTS): {e}")))?;
    Ok(())
}

/// One workload's held listening sockets (plus, on Linux, the fd that keeps its
/// mesh netns alive).
struct HeldSockets {
    /// `(bind_address_key, listener_fd)` in creation order. The keys are the
    /// handoff keys sent to each workload process.
    binds: Vec<(String, OwnedFd)>,
    /// Open fd to the workload's netns, held so the namespace (and therefore
    /// the bound sockets) stays alive while we're the custodian. `None` for
    /// host-network / inlined workloads.
    #[cfg(target_os = "linux")]
    _netns: Option<OwnedFd>,
}

/// Owns the listening sockets for the workloads kamaji is custodian for, keyed
/// by mesh identity. Sockets are closed when a workload is [`release`]d or when
/// the custodian is dropped.
///
/// [`release`]: SocketCustodian::release
#[derive(Default)]
pub struct SocketCustodian {
    held: Mutex<HashMap<String, HeldSockets>>,
}

impl std::fmt::Debug for SocketCustodian {
    /// Opaque — reports only how many workloads' sockets are held, never the
    /// fds or bind addresses (a listen fd is sensitive custody state).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let held = self.held.lock().map(|h| h.len()).unwrap_or(0);
        f.debug_struct("SocketCustodian")
            .field("workloads_held", &held)
            .finish()
    }
}

impl SocketCustodian {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind `bind_addr` (optionally inside `netns_path`) and hold it under
    /// `ident`. A second call for the same `(ident, bind_addr)` is rejected —
    /// the custodian binds each listener exactly once; subsequent workload
    /// (re)spawns reuse the held fd via [`hand_off`](Self::hand_off).
    pub fn bind_and_hold(
        &self,
        ident: &str,
        bind_addr: &str,
        netns_path: Option<&Path>,
    ) -> io::Result<()> {
        let fd = match netns_path {
            #[cfg(target_os = "linux")]
            Some(path) => bind_listener_in_netns(bind_addr, path)?,
            #[cfg(not(target_os = "linux"))]
            Some(_) => {
                return Err(io::Error::other(
                    "netns-scoped socket custody is only supported on Linux",
                ))
            }
            None => bind_listener(bind_addr)?,
        };

        // Hold the netns fd so the namespace outlives any single workload
        // process (Linux only; a socket bound in a torn-down netns is dead).
        #[cfg(target_os = "linux")]
        let netns_fd = match netns_path {
            Some(path) => Some(OwnedFd::from(std::fs::File::open(path)?)),
            None => None,
        };

        let mut held = self.held.lock().unwrap();
        let entry = held.entry(ident.to_string()).or_insert_with(|| HeldSockets {
            binds: Vec::new(),
            #[cfg(target_os = "linux")]
            _netns: None,
        });
        if entry.binds.iter().any(|(b, _)| b == bind_addr) {
            return Err(io::Error::other(format!(
                "socket custodian already holds {bind_addr} for workload {ident}"
            )));
        }
        entry.binds.push((bind_addr.to_string(), fd));
        #[cfg(target_os = "linux")]
        if entry._netns.is_none() {
            entry._netns = netns_fd;
        }
        Ok(())
    }

    /// True if the custodian is currently holding any socket for `ident`.
    pub fn holds(&self, ident: &str) -> bool {
        self.held.lock().unwrap().contains_key(ident)
    }

    /// Hand every held listener for `ident` to a workload process waiting on
    /// `upgrade_sock` (started in pingora upgrade mode). No-op-with-error if the
    /// custodian holds nothing for `ident` — the caller must
    /// [`bind_and_hold`](Self::bind_and_hold) first.
    #[cfg(unix)]
    pub fn hand_off(&self, ident: &str, upgrade_sock: &Path) -> io::Result<()> {
        let held = self.held.lock().unwrap();
        let entry = held.get(ident).ok_or_else(|| {
            io::Error::other(format!("socket custodian holds nothing for workload {ident}"))
        })?;
        let binds: Vec<(&str, RawFd)> = entry
            .binds
            .iter()
            .map(|(key, fd)| (key.as_str(), fd.as_raw_fd()))
            .collect();
        send_listener_fds(upgrade_sock, &binds)
    }

    /// Drop the held sockets (and netns fd) for `ident`, closing them. Idempotent.
    pub fn release(&self, ident: &str) {
        self.held.lock().unwrap().remove(ident);
    }

    /// The bind-address keys currently held for `ident`, if any.
    pub fn held_binds(&self, ident: &str) -> Option<Vec<String>> {
        self.held
            .lock()
            .unwrap()
            .get(ident)
            .map(|h| h.binds.iter().map(|(b, _)| b.clone()).collect())
    }
}

/// Path to a named network namespace under the `ip netns` convention.
pub fn netns_path(name: &str) -> PathBuf {
    Path::new("/var/run/netns").join(name)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixListener;

    /// Receiver mirroring pingora 0.8.1's `Fds::get_from_sock`: accept one
    /// connection, `recvmsg` the payload bytes + `SCM_RIGHTS` fds. Returns the
    /// (payload, fds) so a test can assert the wire contract.
    fn receive_fds(listener: &UnixListener) -> (String, Vec<RawFd>) {
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, UnixAddr};

        let (stream, _) = listener.accept().unwrap();
        let mut payload = [0u8; 2048];
        let mut iov = [io::IoSliceMut::new(&mut payload)];
        let mut cmsg_buf = nix::cmsg_space!([RawFd; 32]);
        let msg = recvmsg::<UnixAddr>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::empty(),
        )
        .unwrap();

        let mut fds = Vec::new();
        for cmsg in msg.cmsgs().unwrap() {
            if let ControlMessageOwned::ScmRights(v) = cmsg {
                fds.extend(v);
            }
        }
        let bytes = msg.bytes;
        let keys = String::from_utf8(payload[..bytes].to_vec()).unwrap();
        (keys, fds)
    }

    #[test]
    fn send_listener_fd_round_trips_pingora_wire_format() {
        // Kamaji binds and holds a real listener.
        let listener_fd = bind_listener("127.0.0.1:0").unwrap();
        let local = {
            // Confirm the bound port so we can assert the receiver got the SAME
            // socket (same port on the same host).
            let borrowed = unsafe { std::net::TcpListener::from_raw_fd(listener_fd.as_raw_fd()) };
            let addr = borrowed.local_addr().unwrap();
            std::mem::forget(borrowed); // don't close kamaji's fd
            addr
        };
        let key = local.to_string();

        // Stand in for the workload: bind the upgrade sock and wait as receiver.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("upgrade.sock");
        let ulistener = UnixListener::bind(&sock_path).unwrap();

        let sock_path_recv = sock_path.clone();
        let key_expect = key.clone();
        let recv = std::thread::spawn(move || {
            let _ = &sock_path_recv;
            receive_fds(&ulistener)
        });

        // Kamaji sends the held fd over the upgrade sock.
        send_listener_fds(
            &sock_path,
            &[(key.as_str(), listener_fd.as_raw_fd())],
        )
        .unwrap();

        let (got_keys, got_fds) = recv.join().unwrap();
        assert_eq!(got_keys, key_expect, "bind-address key must survive verbatim");
        assert_eq!(got_fds.len(), 1, "exactly one fd transferred");

        // The received fd must be the SAME listening socket (same local port).
        let received = unsafe { std::net::TcpListener::from_raw_fd(got_fds[0]) };
        assert_eq!(
            received.local_addr().unwrap().port(),
            local.port(),
            "receiver adopted kamaji's listening socket"
        );
        drop(received);
    }

    #[test]
    fn custodian_holds_and_releases() {
        let cust = SocketCustodian::new();
        assert!(!cust.holds("ingress"));

        cust.bind_and_hold("ingress", "127.0.0.1:0", None).unwrap();
        assert!(cust.holds("ingress"));
        assert_eq!(cust.held_binds("ingress").unwrap().len(), 1);

        // The custodian binds each listener exactly once.
        let held_key = cust.held_binds("ingress").unwrap()[0].clone();
        let dup = cust.bind_and_hold("ingress", &held_key, None);
        assert!(dup.is_err(), "re-binding the same key is rejected");

        cust.release("ingress");
        assert!(!cust.holds("ingress"));
        // Idempotent.
        cust.release("ingress");
    }

    #[test]
    fn hand_off_without_holding_errs() {
        let cust = SocketCustodian::new();
        let dir = tempfile::tempdir().unwrap();
        let err = cust
            .hand_off("nobody", &dir.path().join("x.sock"))
            .unwrap_err();
        assert!(err.to_string().contains("holds nothing"));
    }
}

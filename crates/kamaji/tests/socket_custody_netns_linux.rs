//! Linux integration test for the netns half of the socket-custodian
//! primitive (R599-F9). Proves [`bind_listener_in_netns`] actually binds the
//! listener *inside a different network namespace* than the caller — the
//! property the fleet custody path (R600-F9) relies on but which cannot be
//! exercised on macOS.
//!
//! Requires `CAP_SYS_ADMIN` (a `--privileged` / `--cap-add=SYS_ADMIN`
//! container, or root on a fleet node). When the process can't create a netns
//! the test **skips** rather than fails, so it's harmless in unprivileged CI.
//!
//! Run: `cargo test -p kamaji --features socket-custody --test socket_custody_netns_linux`
#![cfg(all(target_os = "linux", feature = "socket-custody"))]

use std::net::TcpListener;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Child, Command};

use kamaji::socket_custody::{bind_listener_in_netns, SocketCustodian};

/// Hold a fresh network namespace open for the duration of the test by parking
/// a `unshare --net sleep` child in it; its `/proc/<pid>/ns/net` is a stable
/// path into that netns. Returns `None` (skip) if we lack the privilege to
/// unshare a netns.
struct Netns {
    child: Child,
    path: String,
}

impl Netns {
    fn create() -> Option<Self> {
        let child = Command::new("unshare")
            .arg("--net")
            .arg("sleep")
            .arg("300")
            .spawn()
            .ok()?;
        let path = format!("/proc/{}/ns/net", child.id());

        // Give the child a moment to enter its new netns.
        std::thread::sleep(std::time::Duration::from_millis(300));

        let mut this = Netns { child, path };
        // If unshare silently failed (no privilege), the child's netns inode
        // equals ours → not actually isolated → skip.
        if this.child.try_wait().ok().flatten().is_some() {
            return None; // child already exited (unshare refused)
        }
        if same_netns_as_self(&this.path) {
            this.kill();
            return None;
        }
        Some(this)
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        self.kill();
    }
}

/// True if `netns_path` refers to the same network namespace as the caller,
/// compared by (dev, inode) of the nsfs node.
fn same_netns_as_self(netns_path: &str) -> bool {
    let (Ok(a), Ok(b)) = (
        std::fs::metadata("/proc/self/ns/net"),
        std::fs::metadata(netns_path),
    ) else {
        return true; // can't compare → treat as "not isolated", skip
    };
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[test]
fn bind_listener_in_netns_binds_in_a_foreign_namespace() {
    let Some(netns) = Netns::create() else {
        eprintln!(
            "SKIP: cannot create a network namespace (needs CAP_SYS_ADMIN — run with \
             --privileged). The netns bind path is unexercised in this environment."
        );
        return;
    };

    // Bind a listener on an ephemeral port INSIDE the foreign netns and hold it.
    let held = bind_listener_in_netns("0.0.0.0:0", Path::new(&netns.path))
        .expect("bind listener inside the foreign netns");
    let listener = TcpListener::from(held);
    let port = listener.local_addr().unwrap().port();
    assert_ne!(port, 0, "kernel assigned a concrete port");

    // The decisive assertion: the SAME port is still free in OUR netns. If
    // bind_listener_in_netns had (wrongly) bound in the caller's namespace, this
    // second bind would fail with EADDRINUSE. Success proves the listener lives
    // in a different network namespace.
    let ours = TcpListener::bind(("0.0.0.0", port));
    assert!(
        ours.is_ok(),
        "port {port} should be free in the caller's netns — the held listener \
         is isolated in the foreign netns; got {ours:?}"
    );

    // And the port is genuinely bound in the foreign netns (we still hold it).
    drop(ours);
    drop(listener);
}

#[test]
fn custodian_holds_a_netns_scoped_listener() {
    let Some(netns) = Netns::create() else {
        eprintln!("SKIP: no CAP_SYS_ADMIN for netns creation");
        return;
    };

    let cust = SocketCustodian::new();
    cust.bind_and_hold("ingress", "0.0.0.0:0", Some(Path::new(&netns.path)))
        .expect("custodian binds+holds a netns-scoped listener");
    assert!(cust.holds("ingress"));
    assert_eq!(cust.held_binds("ingress").unwrap(), vec!["0.0.0.0:0"]);

    cust.release("ingress");
    assert!(!cust.holds("ingress"));
}

//! Listen-port allocation — the one contract both supervisors answer through
//! (R844-F2 / W267).
//!
//! ## Why this exists
//!
//! Before this module, a workload's listen port was a *pin written by a human*
//! in a mirror file (`[providers.bundle] port = 8080`) and, when absent, a
//! node-wide fallback baked into kamaji's own process environment
//! (`KAMAJI_BUNDLE_PORT`, else 8080). Both are the same mistake wearing two
//! hats: a well-known port is a single node-wide slot, so exactly one bundle
//! could be served per node, and a second tenant landing on the same node
//! collided with the first. Co-tenancy — two bundles on one node, neither one
//! naming a port — is what this module is for.
//!
//! ## Two supervisors, one contract
//!
//! yah starts workloads through two different supervisors and both have to
//! answer "what port did it actually get?" the same way, or a service that runs
//! both locally and remotely learns its port from two mechanisms that can
//! disagree:
//!
//! - **Local tier** — the camp / desktop path (`cloud`'s `mesofact-static`
//!   reconciler spawning `mesofact-dev` on loopback). Ports here are
//!   disposable: the operator reaches the workload through a browser handle the
//!   reconciler prints, nothing persists across a camp restart, and a fresh
//!   port each run is fine. [`EphemeralPorts`].
//! - **Remote tier** — kamaji on a fleet node. Ports here are *published*: the
//!   resolved port flows back to yubaba, lands in a service record, and is
//!   rendered into an ingress upstream. A port that silently moves on restart
//!   leaves that upstream naming a dead port. [`LedgerPorts`].
//!
//! The difference between the two is persistence, not policy — which is exactly
//! why they are two implementations of one trait rather than two code paths.
//!
//! ## Declared always wins
//!
//! [`PortAllocator::resolve`] takes the workload's own `declared` port and
//! returns it unchanged when present. This preserves R599-F12's rule (a bundle
//! that declares `serve_bundle.port` binds exactly that) and is what makes the
//! mirror-pin removal a *safe* change rather than a behavioural one: while the
//! pin is still written, nothing about the resolved port changes; once it is
//! gone, allocation takes over. Both paths end at the same place — a resolved
//! port that the supervisor reports back.
//!
//! ## Stability across restart
//!
//! [`LedgerPorts`] persists `ident -> port` to a JSON file beside the
//! supervisor's other state. On restart, a workload that already has a ledger
//! entry gets its old port back if it is still bindable. That is what a
//! `keep-alive` workload needs: the rendered ingress upstream keeps pointing at
//! a live listener across a `systemctl restart kamaji`.
//!
//! `on-demand` (JIT) workloads need the same answer for a different reason:
//! kamaji itself is the socket custodian there, so the port cannot move while
//! kamaji lives, and the ledger is what keeps it from moving when kamaji does
//! not. Neither lifecycle reallocates on wake, so an ingress renderer never has
//! to re-resolve mid-flight — but the 15s service-record sweep carries the
//! resolved port on *every* pass anyway, so if a port ever does move (ledger
//! lost, old port taken by something else) the record is corrected rather than
//! left advertising a dead one.
//!
//! ## What this module deliberately does not do
//!
//! It does not ask yubaba where the ingress expects to connect. The operator
//! shape allowed for "possibly with a config query to yubaba", and the
//! measurement says it is not needed: the ingress renderer reads the port off
//! the service record, and the service record is written from the resolved port
//! this module hands back. A query in the other direction would be a second
//! source of truth for the same fact.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// How a supervisor decides what port a workload listens on.
///
/// Implementations differ only in whether the answer survives a supervisor
/// restart — see the module docs.
pub trait PortAllocator: Send + Sync {
    /// Resolve the listen port for `ident`.
    ///
    /// `declared` is the workload's own stated port; when `Some`, it is
    /// returned unchanged and no allocation happens (see module docs §Declared
    /// always wins). `bind_ip` is the address the workload will actually bind,
    /// because a port is only free *relative to an address* — probing loopback
    /// says nothing about whether the same port is free on the node's mesh
    /// address.
    fn resolve(&self, ident: &str, bind_ip: IpAddr, declared: Option<u16>) -> Result<u16>;

    /// Drop any reservation held for `ident`. Idempotent; an unknown ident is a
    /// no-op. Called on teardown so a torn-down workload's port returns to the
    /// pool instead of being held forever by a ledger nobody prunes.
    fn release(&self, ident: &str);
}

/// Ask the OS for a free port on `bind_ip` by binding `:0` and reading back
/// what the kernel assigned.
///
/// Inherently racy — the listener is closed before the workload binds, so
/// another process can take the port in between. That race is accepted here for
/// the same reason the local tier already accepts it (`cloud`'s
/// `mesofact_static.rs` does exactly this): the alternative is holding the
/// socket and passing the fd, which is the socket-custody path and is a much
/// heavier contract than "pick a number". The window is microseconds and the
/// failure mode is a bind error the supervisor already reports.
pub fn pick_free_port(bind_ip: IpAddr) -> Result<u16> {
    let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0))
        .with_context(|| format!("could not bind an ephemeral port on {bind_ip}"))?;
    Ok(listener
        .local_addr()
        .context("ephemeral listener has no local address")?
        .port())
}

/// `true` when `port` is currently bindable on `bind_ip`.
fn is_free(bind_ip: IpAddr, port: u16) -> bool {
    TcpListener::bind(SocketAddr::new(bind_ip, port)).is_ok()
}

/// The local tier's allocator: prefer the declared port, fall back to whatever
/// the OS hands out. Holds no state and persists nothing.
///
/// This is the shape `cloud::reconciler::mesofact_static` already implemented
/// inline for `mesofact-dev`; naming it here is what makes the local and remote
/// tiers one contract instead of two lookalike code paths.
#[derive(Debug, Clone, Copy, Default)]
pub struct EphemeralPorts;

impl PortAllocator for EphemeralPorts {
    fn resolve(&self, _ident: &str, bind_ip: IpAddr, declared: Option<u16>) -> Result<u16> {
        match declared {
            // A declared port that is actually free is honoured verbatim. A
            // declared port that is taken floats to an OS-assigned one rather
            // than failing the bring-up: locally the port is a browser handle,
            // not a published address, so the operator would rather have the
            // workload running somewhere than not running at all.
            Some(p) if p != 0 && is_free(bind_ip, p) => Ok(p),
            Some(p) if p != 0 => {
                let fallback = pick_free_port(bind_ip)?;
                tracing::info!(
                    preferred = p,
                    actual = fallback,
                    "declared port is taken; falling back to an OS-assigned port"
                );
                Ok(fallback)
            }
            _ => pick_free_port(bind_ip),
        }
    }

    fn release(&self, _ident: &str) {}
}

/// One persisted reservation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerEntry {
    port: u16,
}

/// On-disk shape of the port ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerFile {
    version: u32,
    /// `ident -> reservation`. A `BTreeMap` so the file is stable under
    /// rewrite — a supervisor that rewrites this on every deploy should not
    /// produce a different byte sequence for the same content.
    ports: BTreeMap<String, LedgerEntry>,
}

/// Schema version of [`LedgerFile`]. An unrecognized version degrades to "no
/// ledger" (warn, start empty) rather than refusing to boot: losing the
/// reservations costs a port reallocation that the service-record sweep then
/// corrects, whereas a supervisor that will not start costs the whole node.
const LEDGER_VERSION: u32 = 1;

/// The remote tier's allocator: same policy as [`EphemeralPorts`], plus an
/// `ident -> port` ledger on disk so a restarted supervisor gives a workload
/// back the port it had.
///
/// The in-memory map is the authority while the process lives; the file is
/// written after every mutation so a crash loses at most the reservation that
/// was mid-write.
pub struct LedgerPorts {
    path: PathBuf,
    reserved: Mutex<BTreeMap<String, u16>>,
}

impl LedgerPorts {
    /// File name of the port ledger, written inside the supervisor's state
    /// directory.
    pub const FILE_NAME: &'static str = "ports.json";

    /// Open (or start) a ledger at `<state_dir>/ports.json`.
    ///
    /// Every read failure — missing, unreadable, malformed, unknown version —
    /// starts empty rather than erroring, for the reason in [`LEDGER_VERSION`].
    pub fn open(state_dir: impl Into<PathBuf>) -> Self {
        let path = state_dir.into().join(Self::FILE_NAME);
        let reserved = load(&path);
        Self {
            path,
            reserved: Mutex::new(reserved),
        }
    }

    /// Where this ledger persists. Exposed for operators and tests.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The port currently reserved for `ident`, if any. Does not allocate.
    pub fn reserved_port(&self, ident: &str) -> Option<u16> {
        self.reserved.lock().ok()?.get(ident).copied()
    }

    fn save(&self, reserved: &BTreeMap<String, u16>) {
        let file = LedgerFile {
            version: LEDGER_VERSION,
            ports: reserved
                .iter()
                .map(|(k, &port)| (k.clone(), LedgerEntry { port }))
                .collect(),
        };
        if let Err(e) = write_atomic(&self.path, &file) {
            tracing::warn!(
                path = %self.path.display(),
                error = format!("{e:#}"),
                "ports: could not persist the port ledger; allocations hold in \
                 memory but a restart before the next successful write will \
                 reallocate"
            );
        }
    }
}

impl PortAllocator for LedgerPorts {
    fn resolve(&self, ident: &str, bind_ip: IpAddr, declared: Option<u16>) -> Result<u16> {
        // Declared wins outright, and is deliberately NOT written to the
        // ledger: the declaration is already durable (it rides the deploy
        // record), and recording it would make a later removal of the
        // declaration silently keep binding the old pinned port — exactly the
        // pin this ticket exists to remove, relocated to a file nobody reads.
        if let Some(port) = declared.filter(|&p| p != 0) {
            return Ok(port);
        }

        let mut reserved = self
            .reserved
            .lock()
            .map_err(|_| anyhow::anyhow!("port ledger mutex poisoned"))?;

        // A standing reservation for this ident wins, and it wins even when the
        // port is currently unbindable. That is not a nicety — it is required
        // by the on-demand tier: kamaji is the socket custodian there, so on a
        // redeploy the port is held by *this ident's own* listener at the
        // moment we resolve, and treating "not free" as "reallocate" would
        // move an on-demand workload's port on every single redeploy.
        //
        // The count check is what keeps that from also swallowing a genuine
        // squatter: if this ledger has promised the port to exactly one ident
        // — this one — then whoever holds it is us. If the port is somehow
        // double-booked, fall through and allocate a fresh one instead of
        // handing out a number two workloads believe they own.
        if let Some(&port) = reserved.get(ident) {
            if is_free(bind_ip, port) || reserved.values().filter(|&&p| p == port).count() == 1 {
                return Ok(port);
            }
        }

        let mut port = pick_free_port(bind_ip)?;
        // The OS can hand back a port this ledger has already promised to
        // another ident whose workload is not currently listening (e.g. mid
        // restart). Re-roll rather than double-book; bounded so a pathological
        // node fails loudly instead of spinning.
        for _ in 0..16 {
            if !reserved.values().any(|&p| p == port) {
                break;
            }
            port = pick_free_port(bind_ip)?;
        }
        anyhow::ensure!(
            !reserved.values().any(|&p| p == port),
            "could not find a port on {bind_ip} that the ledger has not already \
             reserved for another workload"
        );

        reserved.insert(ident.to_string(), port);
        let snapshot = reserved.clone();
        drop(reserved);
        self.save(&snapshot);
        Ok(port)
    }

    fn release(&self, ident: &str) {
        let Ok(mut reserved) = self.reserved.lock() else {
            return;
        };
        if reserved.remove(ident).is_none() {
            return;
        }
        let snapshot = reserved.clone();
        drop(reserved);
        self.save(&snapshot);
    }
}

fn load(path: &Path) -> BTreeMap<String, u16> {
    let Ok(bytes) = std::fs::read(path) else {
        return BTreeMap::new();
    };
    match serde_json::from_slice::<LedgerFile>(&bytes) {
        Ok(file) if file.version == LEDGER_VERSION => file
            .ports
            .into_iter()
            .map(|(ident, entry)| (ident, entry.port))
            .collect(),
        Ok(file) => {
            tracing::warn!(
                path = %path.display(),
                found = file.version,
                expected = LEDGER_VERSION,
                "ports: unrecognized port-ledger version; starting empty"
            );
            BTreeMap::new()
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "ports: unreadable port ledger; starting empty"
            );
            BTreeMap::new()
        }
    }
}

fn write_atomic(path: &Path, file: &LedgerFile) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create port-ledger dir {}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(file).context("serialize port ledger")?;
    std::fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    Ok(())
}

/// Loopback, the address every non-mesh supervisor binds. Convenience for
/// callers that have no mesh assignment.
pub const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declared_port_is_returned_unchanged_by_both_allocators() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        assert_eq!(
            EphemeralPorts.resolve("a", LOOPBACK, Some(31_337)).unwrap(),
            31_337,
            "an unused declared port is honoured verbatim"
        );
        assert_eq!(
            ledger.resolve("a", LOOPBACK, Some(31_337)).unwrap(),
            31_337
        );
        assert_eq!(
            ledger.reserved_port("a"),
            None,
            "a declared port is not recorded as a reservation — see resolve()'s \
             comment on why writing it would relocate the pin rather than remove it"
        );
    }

    #[test]
    fn undeclared_workloads_get_distinct_ports_on_one_node() {
        // The motivating case: two bundles, one node, neither naming a port.
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        let a = ledger.resolve("yah-marketing", LOOPBACK, None).unwrap();
        let b = ledger.resolve("noisetable-com", LOOPBACK, None).unwrap();
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b, "co-tenants must not be handed the same port");
    }

    #[test]
    fn resolving_the_same_ident_twice_is_stable_within_a_process() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        let first = ledger.resolve("yah-marketing", LOOPBACK, None).unwrap();
        let again = ledger.resolve("yah-marketing", LOOPBACK, None).unwrap();
        assert_eq!(first, again);
    }

    #[test]
    fn a_reservation_survives_a_supervisor_restart() {
        // The keep-alive requirement: an ingress upstream rendered from the
        // first run must still name a live listener after kamaji restarts.
        let dir = tempfile::tempdir().unwrap();
        let first = {
            let ledger = LedgerPorts::open(dir.path());
            ledger.resolve("yah-marketing", LOOPBACK, None).unwrap()
        };
        let reopened = LedgerPorts::open(dir.path());
        assert_eq!(
            reopened.reserved_port("yah-marketing"),
            Some(first),
            "the ledger on disk is what makes the port stable across restart"
        );
        assert_eq!(
            reopened.resolve("yah-marketing", LOOPBACK, None).unwrap(),
            first
        );
    }

    #[test]
    fn releasing_returns_the_port_to_the_pool_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = LedgerPorts::open(dir.path());
        ledger.resolve("gone", LOOPBACK, None).unwrap();
        ledger.release("gone");
        assert_eq!(ledger.reserved_port("gone"), None);
        assert_eq!(
            LedgerPorts::open(dir.path()).reserved_port("gone"),
            None,
            "release must reach disk, or a restart resurrects a dead reservation"
        );
        // Idempotent.
        ledger.release("gone");
        ledger.release("never-existed");
    }

    #[test]
    fn a_corrupt_ledger_starts_empty_instead_of_failing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LedgerPorts::FILE_NAME), b"{not json").unwrap();
        let ledger = LedgerPorts::open(dir.path());
        assert_eq!(ledger.reserved_port("anything"), None);
        // Still allocates — degrading to empty must not degrade to broken.
        assert_ne!(ledger.resolve("anything", LOOPBACK, None).unwrap(), 0);
    }

    #[test]
    fn an_unknown_ledger_version_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(LedgerPorts::FILE_NAME),
            br#"{"version":9999,"ports":{"yah-marketing":{"port":8080}}}"#,
        )
        .unwrap();
        assert_eq!(
            LedgerPorts::open(dir.path()).reserved_port("yah-marketing"),
            None
        );
    }

    #[test]
    fn ephemeral_allocator_hands_out_a_usable_port_when_nothing_is_declared() {
        let port = EphemeralPorts.resolve("dev", LOOPBACK, None).unwrap();
        assert_ne!(port, 0);
        // Freshly released by the probe, so it must be bindable again.
        assert!(is_free(LOOPBACK, port));
    }

    #[test]
    fn a_taken_declared_port_floats_on_the_local_tier() {
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let taken = held.local_addr().unwrap().port();
        let got = EphemeralPorts.resolve("dev", LOOPBACK, Some(taken)).unwrap();
        assert_ne!(
            got, taken,
            "the local tier floats off a taken port rather than failing bring-up"
        );
    }
}

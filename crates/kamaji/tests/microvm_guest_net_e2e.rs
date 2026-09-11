//! Guest **networking** against a real Firecracker guest (R605-F22 / W325 §5).
//!
//! `microvm_guest_e2e.rs` proves a guest boots, mounts, runs argv and reports a
//! status — with `MicroVmConfig.network = None` throughout. That left
//! `net::create_tap`, the `iptables` rules and the `ip=` kernel argument at
//! literally zero coverage against a live guest, and the guest init's
//! `resolv.conf` path covered only in the `dns = None` direction. This file is
//! the other half.
//!
//! It is a separate file from `microvm_guest_e2e.rs` rather than another `#[test]`
//! in it because it needs strictly more of the host: `CAP_NET_ADMIN`, `ip`,
//! `iptables`, an uplink with a default route, and — for the egress leg — a node
//! that can actually reach the internet. Each of those is a *separate* skip
//! reason, and folding them into the boot test would make that test skip on nodes
//! where it can run perfectly well.
//!
//! ## What it asserts, and why it is these three things
//!
//! 1. **The `/30` is live in both directions** — the guest opens a TCP connection
//!    back to the host end of its own TAP and reads a nonce off it. This is the
//!    leg that isolates "the kernel's `ip=` autoconfiguration took effect and the
//!    TAP forwards frames" from "NAT and DNS work", which otherwise fail
//!    identically: as a timeout with an empty artifact.
//! 2. **DNS resolves inside the guest**, through the resolver the *job document*
//!    carried — the `dns = Some(..)` direction of the init's `resolv.conf` write.
//! 3. **An outbound TCP connection completes** to the address that resolution
//!    returned, which is the claim R605 actually needs: a build that has to reach
//!    crates.io needs egress from the guest.
//!
//! ## Running it
//!
//! ```text
//! oss/kamaji/guest/build-guest-image.sh                  # produces vmlinux + rootfs.ext4
//! KAMAJI_MICROVM_DIR=/var/lib/yah/kamaji/microvm sudo -E \
//!   cargo test -p kamaji --features microvm-integration --test microvm_guest_net_e2e -- --nocapture
//! ```
//!
//! `sudo` is not a privilege *grant*: creating a TAP needs `CAP_NET_ADMIN` and
//! `kamaji.service` on a microVM node already runs as root, so this runs the test
//! process with the privilege the service has anyway rather than adding one to
//! the node.
//!
//! Part of R605-F22 — annotation in oss/kamaji/crates/kamaji/src/microvm.rs.

#![cfg(all(target_os = "linux", feature = "microvm-integration"))]

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kamaji::microvm::net::default_route_uplink;
use kamaji::microvm::{GuestNetwork, GuestSlot, MicroVmConfig, MicroVmRuntime};
use kamaji::{Kamaji, MeshAssignment, WorkloadStatus};
use workload_spec::{
    ImageRef, TierTag, VolumeMount, VolumeSource, WorkloadSpec, FORGE_MEMORY_REQUEST_MB,
};

/// The name the guest must resolve, and the port it must then reach.
///
/// `static.crates.io` rather than a generic liveness name because it is the
/// actual thing R605 needs a guest to reach — if this test passes against
/// something else and a cargo build still cannot fetch a crate, the test was
/// measuring the wrong host.
const EGRESS_HOST: &str = "static.crates.io";
const EGRESS_PORT: u16 = 443;

/// Where `build-guest-image.sh` put `vmlinux` and `rootfs.ext4`. Mirrors
/// `microvm_guest_e2e.rs` — `KAMAJI_MICROVM_DIR` is `kamaji-bin`'s own fallback
/// for `--microvm-dir`, so a provisioned node needs nothing extra set.
fn microvm_dir() -> PathBuf {
    std::env::var("KAMAJI_MICROVM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/yah/kamaji/microvm"))
}

/// Every reason this test cannot run, named individually.
///
/// Seven distinct reasons, each phrased as the thing to go fix. An operator who
/// provisioned a build node and expected guest networking to be exercised needs
/// to know *which* one is missing; "SKIP: prerequisites missing" would send them
/// to read this file instead.
fn why_not() -> Option<String> {
    let dir = microvm_dir();
    for (what, path) in [
        ("guest kernel", dir.join("vmlinux")),
        ("guest rootfs", dir.join("rootfs.ext4")),
    ] {
        if !path.exists() {
            return Some(format!(
                "no {what} at {} — run oss/kamaji/guest/build-guest-image.sh, or set \
                 KAMAJI_MICROVM_DIR",
                path.display()
            ));
        }
    }
    ensure_sbin_on_path();
    // `find_vmm` rather than a PATH lookup for firecracker: it is the same
    // resolution `kamaji-bin` uses, so this skips exactly when a node would fail
    // to attach the backend, and not on a node where the VMM is installed
    // somewhere a non-login shell's PATH does not reach.
    if let Err(e) = kamaji::microvm::find_vmm() {
        return Some(e.to_string());
    }
    for bin in ["mkfs.ext4", "debugfs", "ip", "iptables"] {
        if which(bin).is_none() {
            return Some(format!("{bin} is not on PATH"));
        }
    }
    if let Err(e) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm") {
        return Some(format!("/dev/kvm is not openable read-write: {e}"));
    }
    if !has_cap_net_admin() {
        return Some(
            "this process has no CAP_NET_ADMIN — creating a TAP and an iptables rule needs it. \
             Re-run under `sudo -E`; kamaji.service on a microVM node already runs as root, so \
             this is not a privilege the node has to be granted."
                .into(),
        );
    }
    if let Err(e) = default_route_uplink() {
        return Some(e.to_string());
    }
    // Last, because it is the only check that touches the network: if the *host*
    // cannot reach the egress target, a guest that cannot is not evidence of
    // anything about kamaji.
    if let Err(e) = resolve_egress_host() {
        return Some(format!(
            "the host itself cannot reach {EGRESS_HOST}:{EGRESS_PORT} ({e}) — a guest failing \
             to would say nothing about guest networking"
        ));
    }
    None
}

/// True when this process holds `CAP_NET_ADMIN` in its effective set.
///
/// Reading `CapEff` rather than checking for uid 0, because those are different
/// questions: a node that grants the capability to the kamaji binary through a
/// file capability rather than by running it as root is a *better* configuration,
/// and a uid check would skip this test on exactly that node.
fn has_cap_net_admin() -> bool {
    const CAP_NET_ADMIN: u64 = 12;
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .is_some_and(|caps| caps & (1 << CAP_NET_ADMIN) != 0)
}

/// Resolve the egress target on the host, and prove the host can reach it.
///
/// Returns the address, which the test then hands nothing — the *guest* does its
/// own resolution, which is the point. This is purely the precheck that keeps a
/// partitioned node skipping instead of failing.
fn resolve_egress_host() -> std::io::Result<SocketAddr> {
    let addr = (EGRESS_HOST, EGRESS_PORT)
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no IPv4 address for the egress host")
        })?;
    TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    Ok(addr)
}

fn ensure_sbin_on_path() {
    let path = std::env::var("PATH").unwrap_or_default();
    let missing: Vec<&str> = ["/usr/sbin", "/sbin"]
        .into_iter()
        .filter(|d| !path.split(':').any(|p| p == *d))
        .collect();
    if !missing.is_empty() {
        std::env::set_var("PATH", format!("{path}:{}", missing.join(":")));
    }
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    // Bound rather than returned directly: as a tail expression the borrow of
    // `path` outlives it.
    let found = path
        .split(':')
        .chain(["/usr/sbin", "/sbin"])
        .map(|dir| Path::new(dir).join(bin))
        .find(|p| p.is_file());
    found
}

/// The node's networking, scoped so this test cannot collide with `kamaji.service`.
///
/// Both the TAP prefix and the subnet are deliberately *not* the defaults. TAP
/// names and iptables rules are host-global: a service already running a guest on
/// `yahvm0` would have it deleted out from under it by `create_tap`'s idempotent
/// pre-delete, which on a build node is somebody's build vanishing for reasons
/// nothing logs. `yahtest0` is 8 characters, inside the kernel's 15-character
/// interface-name limit.
fn test_network(uplink: String) -> GuestNetwork {
    GuestNetwork {
        uplink,
        subnet_base: Ipv4Addr::new(172, 30, 240, 0),
        tap_prefix: "yahtest".into(),
        dns: Ipv4Addr::new(1, 1, 1, 1),
    }
}

fn node_config(state_dir: PathBuf, net: GuestNetwork) -> MicroVmConfig {
    let dir = microvm_dir();
    MicroVmConfig {
        vmm_bin: kamaji::microvm::find_vmm().expect("checked by why_not"),
        kernel_image: dir.join("vmlinux"),
        rootfs_image: dir.join("rootfs.ext4"),
        // R605-F23: only if the node staged one. These tests assert the guest
        // contract, not the toolchain, so they must pass on a node that has no
        // toolchain.ext4 — but they must also exercise the three-drive shape
        // wherever one is present, since that is what the fleet now runs.
        toolchain_image: Some(dir.join(kamaji::microvm::TOOLCHAIN_IMAGE_FILE)).filter(|p| p.exists()),
        state_dir,
        network: Some(net),
        max_guest_memory_mb: FORGE_MEMORY_REQUEST_MB,
        max_guest_vcpus: 2,
    }
}

/// The probe the guest runs, as a single `/bin/sh -c` line.
///
/// Written to record *everything* into the artifact rather than to fail fast:
/// the guest's only channel back is this file and the console, and a network
/// probe that stops at the first failure tells you which step broke while hiding
/// the state that would say why. So it always writes `resolv.conf`, the
/// interface, and the routing table, and the test prints the whole thing on any
/// failed assertion.
///
/// Resolution and connection are two steps on purpose. busybox here is
/// statically linked against the build host's glibc, where `getaddrinfo`'s DNS
/// path wants NSS modules that a static binary cannot dlopen — so a tool that
/// resolves *and* connects can fail for a reason that has nothing to do with the
/// guest's network. Resolving with `nslookup` (which speaks DNS itself) and
/// connecting to the address it returned separates the two, and proves the
/// stronger thing anyway: the address that came back over the wire is routable.
fn probe_script(host_ip: Ipv4Addr, port: u16) -> String {
    format!(
        r#"exec >/yah/produced/net.txt 2>&1
echo "== resolv.conf =="; cat /etc/resolv.conf
echo "== addr =="; ip -o addr 2>&1 || ifconfig -a 2>&1
echo "== route =="; ip route 2>&1 || route -n 2>&1

echo "== tap reachback =="
back=$(nc -w 8 {host_ip} {port} </dev/null 2>&1)
echo "GOT=$back"

echo "== nslookup =="
nslookup {EGRESS_HOST} 2>&1
# From the answer section onward only: the header names the *server's* address
# (and busybox writes it as `host:53`), which would otherwise be picked up as a
# successful resolution by a guest whose query never got an answer.
addr=$(nslookup {EGRESS_HOST} 2>/dev/null | sed -n '/^Name:/,$p' \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
if [ -z "$addr" ]; then
  echo "== ping fallback =="
  addr=$(ping -c 1 -w 5 {EGRESS_HOST} 2>&1 | sed -n '1s/.*(\([0-9.]*\)).*/\1/p')
fi
echo "RESOLVED=$addr"

echo "== egress =="
if [ -n "$addr" ] && nc -w 10 "$addr" {EGRESS_PORT} </dev/null >/dev/null 2>&1; then
  echo "EGRESS_OK=$addr:{EGRESS_PORT}"
else
  echo "EGRESS_FAIL=$addr:{EGRESS_PORT}"
fi
echo "PROBE_DONE"
"#,
        host_ip = host_ip,
        port = port,
    )
}

/// A forge-shaped spec that runs the probe.
fn probe_spec(forge_id: &str, produced_dir: &Path, script: String) -> WorkloadSpec {
    let mut spec = WorkloadSpec::for_forge(
        forge_id,
        ImageRef::parse_pinned(
            "ghcr.io/yah-ai/yah-rust:latest@sha256:\
             0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        TierTag("infra".into()),
        vec![],
    );
    spec.annotations.insert(
        workload_spec::NATIVE_EXEC_ANNOTATION.into(),
        workload_spec::MICROVM_EXEC_VALUE.into(),
    );
    spec.command = Some(vec!["/bin/sh".into(), "-c".into(), script]);
    spec.workdir = Some(PathBuf::from("/workspace"));
    spec.volumes = vec![VolumeMount {
        source: VolumeSource::Bind {
            host_path: produced_dir.to_path_buf(),
        },
        target: PathBuf::from("/yah/produced"),
        read_only: false,
    }];
    spec
}

/// The guest resolves a name and completes an outbound TCP connection.
#[tokio::test]
async fn a_guest_with_a_network_resolves_a_name_and_reaches_the_internet() {
    if let Some(reason) = why_not() {
        eprintln!("SKIP: {reason}");
        return;
    }

    let net = test_network(default_route_uplink().expect("checked by why_not"));
    // Slot 0 is what an empty runtime allocates, and `derive` is pure — so the
    // host end of the /30 is knowable before `deploy_workload` creates the TAP,
    // which is what lets the probe script be written with the address in it.
    let slot = GuestSlot::derive(&net, 0).expect("slot 0 derives");

    // The reachback listener. Bound on 0.0.0.0 rather than on `slot.host_ip`
    // because the TAP that carries that address does not exist yet — it is
    // created inside `deploy_workload`, several steps below this line.
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", 0))
        .await
        .expect("bind the reachback listener");
    let port = listener.local_addr().unwrap().port();
    let nonce = format!("r605f22-{}", std::process::id());
    let served = nonce.clone();
    let reachback = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            use tokio::io::AsyncWriteExt as _;
            let _ = sock.write_all(served.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });

    let scratch = tempfile::tempdir().expect("tempdir");
    let produced = scratch.path().join("produced");
    std::fs::create_dir_all(&produced).unwrap();
    let state_dir = scratch.path().join("state");

    let rt = MicroVmRuntime::new(node_config(state_dir.clone(), net.clone()))
        .expect("node config: vmlinux + rootfs.ext4 + firecracker all present");

    let spec = probe_spec(
        "r605f22-net",
        &produced,
        probe_script(slot.host_ip, port),
    );
    let ident = spec.expose.mesh.identity.clone();

    rt.deploy_workload(&spec, &MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1)))
        .await
        .expect("deploy a networked microVM workload — this is the CAP_NET_ADMIN leg");

    let console = state_dir.join(sanitized(&ident.0)).join("console.log");
    let status = wait_for_exit(&rt, &ident, Duration::from_secs(180), &console).await;

    let report = std::fs::read_to_string(produced.join("net.txt")).unwrap_or_default();
    let dump = || {
        format!(
            "\n--- guest net.txt ---\n{report}\n--- console.log ---\n{}",
            read_console(&console)
        )
    };

    assert_eq!(status, WorkloadStatus::Stopped, "guest did not finish cleanly{}", dump());
    assert!(
        report.contains("PROBE_DONE"),
        "the probe did not run to completion{}",
        dump()
    );

    // (a) The job document's resolver reached the guest — the `dns = Some(..)`
    //     direction of the init's resolv.conf write, which had no coverage.
    assert!(
        report.contains(&format!("nameserver {}", net.dns)),
        "the guest's /etc/resolv.conf does not carry the document's resolver{}",
        dump()
    );

    // (b) The /30 carries traffic in both directions. Asserted before egress
    //     because if this fails, NAT and DNS are not the problem — the `ip=`
    //     kernel argument or the TAP is, and every later assertion is noise.
    assert!(
        report.contains(&format!("GOT={nonce}")),
        "the guest could not open a TCP connection to the host end of its own TAP \
         ({}:{port}). If everything else here looks right, check the host's INPUT chain \
         policy — this leg is the only one that terminates *on* the host.{}",
        slot.host_ip,
        dump()
    );

    // (c) DNS resolution inside the guest, and (d) an outbound TCP connection to
    //     what it returned. These two are the ticket.
    assert!(
        report.contains("EGRESS_OK="),
        "the guest did not complete an outbound TCP connection to {EGRESS_HOST}:{EGRESS_PORT}. \
         A `RESOLVED=` with no address means DNS failed (check the MASQUERADE rule and \
         net.ipv4.ip_forward); a `RESOLVED=` with an address and EGRESS_FAIL means \
         resolution worked and routing did not.{}",
        dump()
    );

    rt.teardown_workload(&ident).await.unwrap();
    reachback.abort();

    // Teardown must leave the host as it found it: a TAP or an iptables rule per
    // build is a node that stops working after a few hundred of them.
    assert!(
        !tap_exists(&slot.tap),
        "teardown leaked the TAP device {} — the slot stays allocated until kamaji restarts",
        slot.tap
    );
    let leaked = iptables_rules_mentioning(&slot.tap);
    assert!(
        leaked.is_empty(),
        "teardown leaked iptables rules naming {}: {leaked:?}",
        slot.tap
    );
}

/// `cargo fetch` against the real crates.io, from inside a guest (R605-F23).
///
/// The leg that separates "a guest can compile" from "a guest can build real
/// software", and the last clause of R605-F23's verify criterion. R605-F22
/// proved a guest-resolved outbound TCP connect to static.crates.io; this
/// proves the whole stack above that — TLS, certificate verification against a
/// trust store, and the HTTP index protocol.
///
/// Certificate verification is the part that could not have worked before and
/// is the reason this is here rather than on F22. The rootfs carries four files
/// in `/etc` and none of them is a trust store, so a guest could open the
/// socket and still fail every fetch at verification — a failure that presents
/// as a network problem and is not one. The toolchain volume supplies
/// `/etc/ssl/certs/ca-certificates.crt`, assembled from the `ca-certificates`
/// package's Mozilla set.
///
/// `--offline` is deliberately absent: an offline fetch would assert nothing.
#[tokio::test]
async fn a_guest_fetches_a_crate_from_crates_io_over_tls() {
    if let Some(reason) = why_not() {
        eprintln!("SKIP: {reason}");
        return;
    }
    let toolchain = microvm_dir().join(kamaji::microvm::TOOLCHAIN_IMAGE_FILE);
    if !toolchain.exists() {
        eprintln!(
            "SKIP: no build toolchain at {} — run oss/kamaji/guest/build-toolchain-image.sh",
            toolchain.display()
        );
        return;
    }

    let scratch = tempfile::tempdir().expect("tempdir");
    let produced = scratch.path().join("produced");
    let src = scratch.path().join("src");
    std::fs::create_dir_all(&produced).unwrap();
    std::fs::create_dir_all(src.join("src")).unwrap();
    // One dependency, no transitive ones, chosen so a failure is about the
    // network and not about resolving a large graph. `cfg-if` has no deps.
    std::fs::write(
        src.join("Cargo.toml"),
        "[package]\nname = \"fetchprobe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
         [dependencies]\ncfg-if = \"1\"\n",
    )
    .unwrap();
    std::fs::write(src.join("src/main.rs"), "fn main() {}\n").unwrap();

    let state_dir = scratch.path().join("state");
    let net = test_network(default_route_uplink().expect("host has a default route"));
    let rt = MicroVmRuntime::new(node_config(state_dir.clone(), net)).expect("node config");

    // Every step reported rather than failing fast, for the reason probe_script
    // is written that way: the console and this file are the guest's only
    // channels, and a fetch that stops at the first error hides the state that
    // says which layer broke. CERTS= distinguishes "no trust store" from a TLS
    // handshake that failed for another reason, which is the single most likely
    // confusion here.
    let script = "\
        set -x; \
        echo \"CERTS=$(wc -l < /etc/ssl/certs/ca-certificates.crt 2>/dev/null || echo none)\" > /yah/produced/fetch.txt; \
        cd /src; \
        if cargo fetch >> /yah/produced/fetch.txt 2>&1; then echo FETCH_OK >> /yah/produced/fetch.txt; \
        else echo FETCH_FAIL >> /yah/produced/fetch.txt; fi; \
        if cargo build --release >> /yah/produced/fetch.txt 2>&1; then echo BUILD_OK >> /yah/produced/fetch.txt; \
        else echo BUILD_FAIL >> /yah/produced/fetch.txt; fi; \
        exit 0"
        .to_string();

    let mut spec = probe_spec("r605f23-cratesio", &produced, script);
    spec.volumes.push(VolumeMount {
        source: VolumeSource::Bind {
            host_path: src.clone(),
        },
        target: PathBuf::from("/src"),
        read_only: false,
    });
    let ident = spec.expose.mesh.identity.clone();
    let mesh = MeshAssignment::inlined(Ipv4Addr::new(127, 0, 0, 1));
    rt.deploy_workload(&spec, &mesh)
        .await
        .expect("deploy a networked microVM workload");

    let console = state_dir.join(sanitized(&ident.0)).join("console.log");
    let status = wait_for_exit(&rt, &ident, Duration::from_secs(600), &console).await;
    let report = std::fs::read_to_string(produced.join("fetch.txt")).unwrap_or_default();
    eprintln!("--- guest fetch report ---\n{report}");
    assert_eq!(status, WorkloadStatus::Stopped, "guest did not finish cleanly");

    assert!(
        !report.contains("CERTS=none"),
        "the guest has no /etc/ssl/certs/ca-certificates.crt — the toolchain volume is \
         attached but its trust store is missing, and every HTTPS fetch will fail at \
         verification rather than at connect.\n{report}"
    );
    assert!(
        report.contains("FETCH_OK"),
        "cargo could not fetch cfg-if from crates.io.\n{report}"
    );
    assert!(
        report.contains("BUILD_OK"),
        "cargo fetched from crates.io but could not build against what it fetched.\n{report}"
    );

    rt.teardown_workload(&ident).await.unwrap();
}

/// Whether an interface of this name is present, read from `/sys/class/net`.
fn tap_exists(tap: &str) -> bool {
    Path::new("/sys/class/net").join(tap).exists()
}

/// Every rule in `filter` or `nat` whose text names `tap`.
///
/// `iptables -S` rather than `-L`: the save form is what a rule was *added* as,
/// so a leaked rule prints in a shape somebody can paste into an `-D`.
fn iptables_rules_mentioning(tap: &str) -> Vec<String> {
    ["filter", "nat"]
        .iter()
        .flat_map(|table| {
            let out = std::process::Command::new("iptables")
                .args(["-t", table, "-S"])
                .output();
            let stdout = out.map(|o| o.stdout).unwrap_or_default();
            String::from_utf8_lossy(&stdout)
                .lines()
                .filter(|l| l.contains(tap))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

async fn wait_for_exit(
    rt: &MicroVmRuntime,
    ident: &workload_spec::MeshIdent,
    limit: Duration,
    console: &Path,
) -> WorkloadStatus {
    let started = Instant::now();
    loop {
        let state = rt
            .get_workload(ident)
            .await
            .expect("get_workload")
            .expect("deployed workload is inspectable");
        if state.status != WorkloadStatus::Running {
            eprintln!("guest finished in {:?}: {:?}", started.elapsed(), state.status);
            return state.status;
        }
        if started.elapsed() > limit {
            let _ = std::io::stderr().flush();
            panic!(
                "guest still Running after {limit:?}\n--- console.log ---\n{}",
                read_console(console)
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn read_console(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| format!("(no console log at {}: {e})", path.display()))
}

/// Mirror of `microvm::sanitize`, which is private.
fn sanitized(ident: &str) -> String {
    ident
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect()
}

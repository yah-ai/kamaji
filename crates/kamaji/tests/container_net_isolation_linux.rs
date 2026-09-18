//! Tenant isolation against a real kernel (R895-F3, W343 §"Tenant isolation").
//!
//! `container_net`'s unit tests pin the command sequences; nothing there proves
//! the kernel does what the sequences are for. This drives the REAL command
//! lists through [`container_net::apply`] and asserts with real packets.
//!
//! ## Where it runs
//!
//! Every node-level effect lands in a **private network namespace** the test
//! thread unshares first: the bridges, the host veth ends, every `ip rule`,
//! every iptables rule, `ip_forward` and `rp_filter`. The host's own tables are
//! never touched, so `iptables -F FORWARD` below flushes a chain nobody else
//! owns. What the host does see: the workload namespaces' files under
//! `/var/run/netns` (test-unique names, removed by teardown and by a drop guard
//! on panic), and — only if the operator loaded it — `br_netfilter`.
//!
//! Topology, inside the private "node" namespace:
//!
//! ```text
//!   ktn0            10.77.77.1/24   node bridge   s1 .2  s2 .3  (singleton)
//!   ktn0-<acme>     10.77.77.1/32   tenant bridge a1 .4  a2 .5
//!   ktn0-<globex>   10.77.77.1/32   tenant bridge b1 .6  b2 .7
//!   ktwan0  198.51.100.1/24 ── netns <tag>-wan   203.0.113.9 (the internet)
//!   ktmesh0 100.127.254.3/32 ── netns <tag>-mesh 100.127.254.9 (a mesh peer)
//! ```
//!
//! The mesh route lives in table 52 behind `ip rule 5270 lookup 52`, the shape a
//! tailscale node has, so a reply bypass that named `main` would fail here the
//! way it would on the fleet. `conf.all.rp_filter` is set to 2 (loose) so the
//! spoofing assertions prove the rpfilter match, not the sysctl.
//!
//! `phase_f4_grants` (R895-F4) deploys a granted pair from a real
//! `MeshPeer::CrossTenant`, in both deploy orders, routed and again under
//! br_netfilter, and names each kernel behaviour grants.rs relies on: `-i
//! <bridge>` in mangle PREROUTING, CONNMARK, RELATED ICMP on the connmark, and
//! a proxy ARP answer for the granted pair and for nobody else. In the second
//! order `P` has an identity no earlier chain carries, so only `P`'s own deploy
//! can find `W`'s grant. `phase_f4_no_grant_node` first proves that a node
//! whose workloads carry no grant has no tc, proxy or sysctl state from it.
//!
//! ## Running it
//!
//! ```text
//! cd oss/kamaji
//! cargo test -p kamaji --test container_net_isolation_linux --no-run   # as the build user
//! sudo modprobe br_netfilter        # optional: enables phase (c); unload after if it was not loaded
//! sudo target/debug/deps/container_net_isolation_linux-<hash> --nocapture
//! ```
//!
//! Built unprivileged and run as root, so the target dir never gets root-owned
//! files. Without root, `ip`, `iptables` or `nsenter` it prints a `SKIP:` line
//! naming what is missing and passes.

#![cfg(target_os = "linux")]

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd as _;
use std::process::Command;
use std::time::{Duration, Instant};

use kamaji::container_net::{self, Cmd, ContainerNet, FWMARK_GRANT, Ipv4Cidr, NetnsPlan};
use workload_spec::{MeshIdent, MeshPeer, NamespaceId, TenantId};

// Checks record and continue, so one run on a real kernel reports every
// failure rather than the first; the test fails at the end if any were seen.
static FAILS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
static REPORTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn fail(msg: String) {
    println!("FAIL: {msg}");
    FAILS.lock().unwrap().push(msg);
}

fn report(msg: String) {
    let n = FAILS.lock().unwrap().len();
    let before = REPORTED.swap(n, std::sync::atomic::Ordering::SeqCst);
    if n == before {
        println!("PASS {msg}");
    } else {
        println!("FAILED {msg} ({} failure(s) above)", n - before);
    }
}

macro_rules! check {
    ($cond:expr, $($msg:tt)+) => { if !$cond { fail(format!($($msg)+)); } };
}

macro_rules! check_eq {
    ($l:expr, $r:expr, $($msg:tt)+) => {{
        let (l, r) = (&$l, &$r);
        if l != r {
            fail(format!("{}: got {:?}, want {:?}", format!($($msg)+), l, r));
        }
    }};
}

macro_rules! pass {
    ($($msg:tt)+) => { report(format!($($msg)+)) };
}

const PORT: u16 = 47077;
const GW: Ipv4Addr = Ipv4Addr::new(10, 77, 77, 1);
const NODE_MESH: Ipv4Addr = Ipv4Addr::new(100, 127, 254, 3);
const MESH_PEER: Ipv4Addr = Ipv4Addr::new(100, 127, 254, 9);
const WAN_NODE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const WAN_PEER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const INTERNET: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
/// A source outside every range here, for the egress-spoof probe.
const FOREIGN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 77);

fn why_not() -> Option<String> {
    if unsafe { libc::geteuid() } != 0 {
        return Some("not root (needs CAP_NET_ADMIN and CAP_SYS_ADMIN: run the built test binary under sudo)".into());
    }
    for bin in ["ip", "iptables", "nsenter", "sysctl", "tc"] {
        let found = Command::new("sh")
            .args(["-c", &format!("command -v {bin}")])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !found {
            return Some(format!("`{bin}` is not on PATH"));
        }
    }
    None
}

#[test]
fn tenant_isolation_holds_on_a_real_kernel() {
    if let Some(reason) = why_not() {
        println!("SKIP: container_net_isolation_linux: {reason}");
        return;
    }
    // The whole scenario runs on one thread that owns a private network
    // namespace; every process it spawns inherits that namespace.
    let result = std::thread::spawn(|| {
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            panic!("unshare(CLONE_NEWNET): {}", std::io::Error::last_os_error());
        }
        Scenario::new().run();
    })
    .join();
    host_census_is_clean(&tag());
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    let fails = FAILS.lock().unwrap().clone();
    assert!(fails.is_empty(), "{} check(s) failed:\n{}", fails.len(), fails.join("\n"));
    println!("PASS: tenant_isolation_holds_on_a_real_kernel");
}

fn tag() -> String {
    format!("kn{}", std::process::id() % 100_000)
}

// ── Plumbing ────────────────────────────────────────────────────────────────

fn sh(args: &[&str]) -> String {
    let out = Command::new(args[0]).args(&args[1..]).output().expect("spawn");
    assert!(
        out.status.success(),
        "`{}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn sh_ok(args: &[&str]) -> bool {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn apply(rt: &tokio::runtime::Runtime, cmds: &[Cmd]) {
    rt.block_on(container_net::apply(cmds)).expect("container_net::apply");
}

/// Run `f` on a thread inside `/var/run/netns/<ns>`. Sockets keep the namespace
/// they were created in, so a socket made here can be used from any thread.
fn in_netns<T: Send + 'static>(ns: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let path = container_net::netns_path(ns);
    std::thread::spawn(move || {
        let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            panic!("setns {}: {}", path.display(), std::io::Error::last_os_error());
        }
        f()
    })
    .join()
    .expect("netns thread")
}

/// Removes the workload/wan/mesh namespace files even when an assertion panics.
struct NetnsGuard(Vec<String>);

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        for ns in &self.0 {
            let _ = Command::new("ip").args(["netns", "del", ns]).output();
        }
    }
}

struct Workload {
    plan: NetnsPlan,
    udp: UdpSocket,
    tcp: TcpListener,
}

/// Deploy one workload the way kamaji-bin's `build_container_netns` does:
/// `bridge_commands`, `setup_commands`, `grant_commands`, then
/// `apply_grant_neighbours`, from a plan whose [`container_net::Tenancy`]
/// carries the given `allow_from`.
fn deploy(
    rt: &tokio::runtime::Runtime,
    net: &ContainerNet,
    tag: &str,
    name: &str,
    octet: u8,
    tenant: &TenantId,
    allow_from: Vec<MeshPeer>,
) -> Workload {
    let ip = Ipv4Addr::new(10, 77, 77, octet);
    let tenancy = container_net::Tenancy {
        tenant: tenant.clone(),
        fq_identity: format!("{}/default/{tag}-{name}", tenant.0),
        allow_from,
    };
    let plan = net.plan(&format!("{tag}-{name}"), ip, &tenancy).expect("in range");
    apply(rt, &net.bridge_commands(&plan));
    apply(rt, &net.setup_commands(&plan));
    apply(rt, &container_net::grant_commands(&plan));
    rt.block_on(async {
        let lock = container_net::lock_node_state().await;
        container_net::apply_grant_neighbours(&plan, &lock).await
    })
    .expect("container_net::apply_grant_neighbours");
    let (udp, tcp) = in_netns(&plan.netns, move || {
        let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, PORT)).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, PORT)).unwrap();
        tcp.set_nonblocking(true).unwrap();
        (udp, tcp)
    });
    Workload { plan, udp, tcp }
}

struct Scenario {
    rt: tokio::runtime::Runtime,
    net: ContainerNet,
    tag: String,
    s1: Workload,
    s2: Workload,
    a1: Workload,
    a2: Workload,
    b1: Workload,
    b2: Workload,
    _guard: NetnsGuard,
}

impl Scenario {
    fn new() -> Self {
        let tag = tag();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let net = ContainerNet::new(Ipv4Cidr::parse("10.77.77.0/24").unwrap(), "ktn0");
        let wan = format!("{tag}-wan");
        let mesh = format!("{tag}-mesh");
        let names = ["s1", "s2", "a1", "a2", "b1", "b2"];
        let mut guard: Vec<String> = names.iter().map(|n| format!("{tag}-{n}")).collect();
        guard.extend([wan.clone(), mesh.clone()]);
        let guard = NetnsGuard(guard);

        println!("node netns: private; kernel {}", sh(&["uname", "-r"]).trim());
        sh(&["ip", "link", "set", "lo", "up"]);
        sh(&["sysctl", "-qw", "net.ipv4.conf.all.rp_filter=2"]);
        // A new netns inherits init_net's IPv4 `all`; a tailscale node has
        // src_valid_mark=1 there. Clear it so the run proves kamaji sets it.
        sh(&["sysctl", "-qw", "net.ipv4.conf.all.src_valid_mark=0"]);
        bridge_nf(false);
        external_peers(&wan, &mesh);

        // No grants here (allow_from empty), so grant_commands is the same 7
        // mangle calls production runs, apply_grant_neighbours runs nothing,
        // and neither touches isolation.
        let spawn = |name: &str, octet: u8, tenant: &TenantId| deploy(&rt, &net, &tag, name, octet, tenant, vec![]);
        let solo = TenantId::singleton();
        let acme = TenantId("acme".into());
        let globex = TenantId("globex".into());
        let s = Scenario {
            s1: spawn("s1", 2, &solo),
            s2: spawn("s2", 3, &solo),
            a1: spawn("a1", 4, &acme),
            a2: spawn("a2", 5, &acme),
            b1: spawn("b1", 6, &globex),
            b2: spawn("b2", 7, &globex),
            rt,
            net,
            tag,
            _guard: guard,
        };
        assert_ne!(s.a1.plan.bridge, s.b1.plan.bridge);
        assert_eq!(s.a1.plan.bridge, s.a2.plan.bridge);
        s
    }

    /// What the kernel is doing, for a failed check: the rule list, a FIB query
    /// for a1's reply to the mesh peer with and without the REPLY mark, and the
    /// counters on every table this module writes.
    fn dump(&self, what: &str) {
        let br = &self.a1.plan.bridge;
        let a1 = self.a1.plan.container_ip.to_string();
        let peer = MESH_PEER.to_string();
        println!("---- DIAGNOSTICS: {what}");
        let run = |args: &[&str]| {
            let out = Command::new(args[0]).args(&args[1..]).output().unwrap();
            println!("$ {}\n{}{}", args.join(" "), String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        };
        run(&["ip", "rule", "show"]);
        run(&["ip", "route", "get", &peer, "from", &a1, "iif", br]);
        run(&["ip", "route", "get", &peer, "from", &a1, "iif", br, "mark", "0x1000000"]);
        run(&["ip", "route", "show", "table", "52"]);
        for table in ["raw", "mangle", "filter", "nat"] {
            run(&["iptables", "-w", "-t", table, "-L", "-v", "-n", "-x"]);
        }
        run(&["sysctl", "net.ipv4.conf.all.rp_filter", &format!("net.ipv4.conf.{br}.rp_filter"), "net.ipv4.conf.ktmesh0.rp_filter"]);
        println!("---- END DIAGNOSTICS");
    }

    fn all(&self) -> [&Workload; 6] {
        [&self.s1, &self.s2, &self.a1, &self.a2, &self.b1, &self.b2]
    }

    fn run(mut self) {
        report_rule_add_behaviour();
        self.phase_a_same_tenant("a");
        self.phase_b_cross_tenant("b");
        self.phase_node_and_mesh();
        self.phase_ipv6();
        self.phase_grant_seam();
        self.phase_f4_no_grant_node();
        self.phase_f4_grants("routed");
        self.phase_c_br_netfilter();
        self.phase_d_flush();
        self.phase_e_reassert_under_probe();
        self.phase_g_gc();
        self.phase_f_teardown();
    }

    /// (g) R895-T5: a `Stop` carries an identity and no address, so the GC pass
    /// has to recover everything else from the kernel. Deploys a tenant of its
    /// own rather than reusing one of the six above, so the phase asserts
    /// against a bridge whose entire population it knows.
    fn phase_g_gc(&mut self) {
        let name = "g1";
        self._guard.0.push(format!("{}-{name}", self.tag));
        let victim = deploy(
            &self.rt,
            &self.net,
            &self.tag,
            name,
            200,
            &TenantId("gc-victim".into()),
            vec![],
        );
        let (gone, kept) = (victim.plan.bridge.clone(), self.a1.plan.bridge.clone());
        let addr = victim.plan.container_ip;
        check!(
            sh(&["ip", "-o", "link", "show"]).contains(&gone),
            "the victim tenant's bridge was never created"
        );

        // The production stop path, which is `ip netns del` and nothing else.
        drop(victim);
        apply(
            &self.rt,
            &container_net::teardown_by_workload(&format!("{}-{name}", self.tag)),
        );
        let swept = self
            .rt
            .block_on(async {
                let lock = container_net::lock_node_state().await;
                container_net::reconcile(&self.net, &lock).await
            })
            .expect("container_net::reconcile");
        check!(
            swept.bridges.contains(&gone) && !swept.bridges.contains(&kept),
            "collected {:?}; wanted {gone} and not {kept}",
            swept.bridges
        );
        check!(swept.addresses.contains(&addr), "{addr} was not swept: {swept:?}");

        let links = sh(&["ip", "-o", "link", "show"]);
        check!(!links.contains(&gone), "{gone} outlived its last workload:\n{links}");
        check!(links.contains(&kept), "{kept} was collected with tenant a still running:\n{links}");
        for (what, shown) in [
            ("ip rule", sh(&["ip", "rule", "show"])),
            ("ip route", sh(&["ip", "route", "show"])),
            ("iptables-save", sh(&["iptables-save"])),
        ] {
            check!(!shown.contains(&gone), "{what} still names {gone}:\n{shown}");
            check!(!shown.contains(&addr.to_string()), "{what} still names {addr}:\n{shown}");
            check!(shown.contains(&kept), "{what} lost {kept} with tenant a still running:\n{shown}");
        }
        let save = mangle_save();
        check!(
            !save.contains(&format!("yah-id-{addr}")) && !save.contains(&format!("yah-gr-{addr}")),
            "the stopped workload's mangle chains survived:\n{save}"
        );
        let proxies = sh(&["ip", "-4", "neigh", "show", "proxy"]);
        check!(
            !proxies.contains(&addr.to_string()),
            "a proxy entry for a stopped workload survived on a bridge that is still up:\n{proxies}"
        );

        // And the sweep was scoped: tenant a is untouched and still talking.
        let (a1, a2) = (&self.a1, &self.a2);
        check_eq!(
            tcp_observed_source(&a1.plan.netns, None, a2.plan.container_ip, Some(&a2.tcp)),
            Some(a1.plan.container_ip),
            "(g) TCP {} -> {} after the sweep",
            a1.plan.netns,
            a2.plan.netns
        );
        pass!(
            "(g): stopping a tenant's last workload collects its bridge, its prohibits, its \
             tagged rules, its host route and its grant state, and leaves another tenant's alone"
        );
    }

    // (a) same tenant reachable, source preserved; singleton likewise.
    fn phase_a_same_tenant(&self, label: &str) {
        for (from, to) in [(&self.a1, &self.a2), (&self.a2, &self.a1), (&self.b1, &self.b2), (&self.s1, &self.s2)] {
            let (fns, tns) = (&from.plan.netns, &to.plan.netns);
            let seen = tcp_observed_source(fns, None, to.plan.container_ip, Some(&to.tcp));
            check_eq!(seen, Some(from.plan.container_ip), "({label}) TCP {fns} -> {tns}, source preserved");
            check!(
                udp_delivered(fns, None, to.plan.container_ip, &to.udp, false),
                "({label}) UDP {fns} -> {tns}"
            );
        }
        pass!("({label}): same-tenant and same-singleton traffic reachable, source preserved");
    }

    // (b) singleton <-> tenant and tenant <-> tenant blocked, every variant.
    fn phase_b_cross_tenant(&self, label: &str) {
        let pairs = [
            (&self.s1, &self.a1, &self.a2),
            (&self.a1, &self.s1, &self.s2),
            (&self.a1, &self.b1, &self.b2),
            (&self.b1, &self.a1, &self.a2),
        ];
        for (attacker, victim, victim_mate) in pairs {
            let ns = &attacker.plan.netns;
            let dst = victim.plan.container_ip;
            check!(!udp_delivered(ns, None, dst, &victim.udp, false), "({label}) plain {ns} -> {dst}");
            check!(!udp_delivered(ns, None, dst, &victim.udp, true), "({label}) via .1 {ns} -> {dst}");
            check!(
                tcp_observed_source(ns, None, dst, Some(&victim.tcp)).is_none(),
                "({label}) tcp {ns} -> {dst}"
            );
            // Claim an address the victim's side legitimately talks to.
            let spoof = victim_mate.plan.container_ip;
            check!(
                !udp_delivered(ns, Some(spoof), dst, &victim.udp, true),
                "({label}) spoofed {spoof} {ns} -> {dst}"
            );
        }
        // Not vacuous: the victims still hear their own side.
        self.phase_a_same_tenant(label);
        pass!("({label}): singleton<->tenant and tenant<->tenant blocked (plain, via .1, TCP, spoofed source)");
    }

    // Operator decision A: node services, the mesh pool, egress, spoofed egress.
    fn phase_node_and_mesh(&self) {
        let node_gw = TcpListener::bind((GW, PORT + 1)).unwrap();
        let node_mesh = TcpListener::bind((NODE_MESH, PORT + 1)).unwrap();
        for l in [&node_gw, &node_mesh] {
            l.set_nonblocking(true).unwrap();
        }
        let a1 = &self.a1.plan.netns;
        let s1 = &self.s1.plan.netns;
        check!(tcp_to(a1, GW, PORT + 1, &node_gw).is_none(), "tenant reached node .1");
        check!(tcp_to(a1, NODE_MESH, PORT + 1, &node_mesh).is_none(), "tenant reached node mesh address");
        check!(tcp_to(s1, GW, PORT + 1, &node_gw).is_some(), "singleton lost node .1");
        check!(tcp_to(s1, NODE_MESH, PORT + 1, &node_mesh).is_some(), "singleton lost node mesh address");
        if sh_ok(&["sh", "-c", "command -v ping"]) {
            check!(
                sh_ok(&["ip", "netns", "exec", a1, "ping", "-c1", "-W2", &GW.to_string()]),
                "ICMP to .1 must stay allowed"
            );
        } else {
            println!("SKIP (icmp): no `ping` on PATH");
        }

        let mesh_ns = format!("{}-mesh", self.tag);
        let wan_ns = format!("{}-wan", self.tag);
        check!(peer_tcp(a1, &mesh_ns, MESH_PEER).is_none(), "tenant reached the mesh pool");
        check!(!peer_udp(a1, None, &mesh_ns, MESH_PEER), "tenant UDP reached the mesh pool");
        check_eq!(peer_tcp(s1, &mesh_ns, MESH_PEER), Some(NODE_MESH), "singleton mesh egress");
        check_eq!(peer_tcp(a1, &wan_ns, INTERNET), Some(WAN_NODE), "tenant internet egress (masqueraded)");
        // Mesh ingress to a tenant workload: the replies must leave.
        let ingress = ingress_tcp(&mesh_ns, &self.a1);
        if ingress != Some(MESH_PEER) {
            self.dump("mesh ingress to a1");
        }
        check_eq!(
            ingress,
            Some(MESH_PEER),
            "a mesh client could not complete a connection to a tenant workload"
        );
        check_eq!(ingress_tcp(&wan_ns, &self.a1), Some(WAN_PEER), "wan ingress to tenant");
        // Item 2: spoofed egress dies even with conf.all.rp_filter=2.
        check!(!peer_udp(a1, Some(FOREIGN), &wan_ns, INTERNET), "egress under a foreign source");
        check!(
            !peer_udp(a1, Some(self.s2.plan.container_ip), &wan_ns, INTERNET),
            "egress under another workload's source"
        );
        check!(peer_udp(a1, None, &wan_ns, INTERNET), "not vacuous: plain UDP egress works");
        pass!("(node/mesh): tenant cannot reach .1, node mesh address or 100.64/10; ICMP, egress and mesh ingress work; spoofed egress dropped with all.rp_filter=2");
    }

    /// W343 is v4-only, so every layer above is IPv4. A bridge and its veths
    /// get IPv6 link-local addresses by default, which would let a tenant
    /// workload reach node services on `::` over `fe80::<bridge>%eth0` and, on
    /// a v6-forwarding node, push packets into the mesh v6 range — both around
    /// the v4-only INPUT and mesh denials. kamaji disables IPv6 on the tenant
    /// bridge; this proves the bridge carries no v6 and neither path completes.
    fn phase_ipv6(&self) {
        let fwd = sysctl("net.ipv6.conf.all.forwarding");
        println!("  (ipv6) emulated node net.ipv6.conf.all.forwarding={fwd} at entry");
        // The singleton bridge is untouched and keeps its link-local; a tenant
        // bridge must have none.
        check!(v6_linklocal("ktn0").is_some(), "node bridge ktn0 lost its IPv6; the singleton must be unchanged");
        for w in [&self.a1, &self.b1] {
            let br = &w.plan.bridge;
            let ll = v6_linklocal(br);
            check!(ll.is_none(), "tenant bridge {br} carries IPv6 {ll:?}: disable_ipv6 not in effect");
        }

        // (1) A dual-stack node service on `::`, as sshd is by default.
        let node_v6 = TcpListener::bind((Ipv6Addr::UNSPECIFIED, PORT + 5)).unwrap();
        node_v6.set_nonblocking(true).unwrap();
        let a1 = &self.a1.plan.netns;
        let br = &self.a1.plan.bridge;
        // Only reachable pre-fix: post-fix the bridge has no link-local to name.
        if let Some(ll) = v6_linklocal(br) {
            check!(
                !tcp6_reaches(a1, &ll, "eth0", PORT + 5, &node_v6),
                "(ipv6/1) tenant workload reached node v6 service at {ll}%eth0"
            );
        }

        // (2) With the node forwarding IPv6, a v6 packet from a tenant workload
        // toward the mesh v6 range must not leave the bridge. ip6_rcv drops on
        // a disable_ipv6 device before the forward decision, so the same fix
        // closes both; the mesh v6 leg here makes that concrete.
        let mesh_ns = format!("{}-mesh", self.tag);
        sh(&["sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"]);
        let peer6: Ipv6Addr = "fd7a:115c:a1e0:ff::9".parse().unwrap();
        // `nodad`: a freshly added v6 address is DAD-tentative and unbindable
        // for ~1s, which would race the socket bind below.
        sh(&["ip", "-6", "addr", "add", "fd7a:115c:a1e0:ff::1/64", "dev", "ktmesh0", "nodad"]);
        sh(&["ip", "netns", "exec", &mesh_ns, "ip", "-6", "addr", "add", "fd7a:115c:a1e0:ff::9/64", "dev", "eth0", "nodad"]);
        let recv = in_netns(&mesh_ns, move || {
            // Bound to `[::]`, not the tentative address, for the same reason.
            let s = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, PORT + 3)).unwrap();
            s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            s
        });
        check!(
            !v6_push_to_mesh(a1, br, peer6, PORT + 3, &recv),
            "(ipv6/2) tenant workload pushed a v6 packet into the mesh at {peer6}"
        );
        sh(&["sysctl", "-qw", &format!("net.ipv6.conf.all.forwarding={fwd}")]);
        pass!("(ipv6): tenant bridges carry no IPv6, the singleton bridge unchanged; a v6 node service is unreachable and no v6 egress reaches the mesh even with forwarding on");
    }

    // The R895-F4 seam: a host-side GRANT mark lets exactly one pair through
    // every layer; a workload cannot forge the mark from inside.
    fn phase_grant_seam(&self) {
        let mesh_ns = format!("{}-mesh", self.tag);
        let (a1, a2, s1, b1) = (&self.a1.plan.netns, &self.a2.plan.netns, &self.s1.plan.netns, &self.b1.plan.netns);
        let (a1_ip, s1_ip, b1_ip) = (self.a1.plan.container_ip, self.s1.plan.container_ip, self.b1.plan.container_ip);

        // Forged inside the workload: SO_MARK, then a MARK rule in its netns.
        let forged = Some(FWMARK_GRANT);
        check!(!udp_probe(a1, None, s1_ip, PORT, &self.s1.udp, true, forged), "SO_MARK GRANT a1 -> s1");
        check!(!udp_probe(a1, None, b1_ip, PORT, &self.b1.udp, true, forged), "SO_MARK GRANT a1 -> b1");
        check!(!udp_probe(s1, None, a1_ip, PORT, &self.a1.udp, true, forged), "SO_MARK GRANT s1 -> a1");
        check!(!peer_udp_marked(a1, None, &mesh_ns, MESH_PEER, forged), "SO_MARK GRANT a1 -> mesh");
        let g = format!("{FWMARK_GRANT:#x}/{FWMARK_GRANT:#x}");
        let inner = ["-t", "mangle", "OUTPUT", "-j", "MARK", "--set-xmark", g.as_str()];
        let netns_iptables = |op: &str| {
            let mut args = vec!["ip", "netns", "exec", a1.as_str(), "iptables", "-w", inner[0], inner[1], op];
            args.extend(&inner[2..]);
            sh(&args);
        };
        netns_iptables("-A");
        check!(!udp_delivered(a1, None, s1_ip, &self.s1.udp, true), "netns MARK a1 -> s1");
        check!(!udp_delivered(a1, None, b1_ip, &self.b1.udp, true), "netns MARK a1 -> b1");
        check!(!peer_udp(a1, None, &mesh_ns, MESH_PEER), "netns MARK a1 -> mesh");
        netns_iptables("-D");
        pass!("(grant/forge): SO_MARK and an in-netns MARK rule carrying GRANT are scrubbed at the veth; still blocked in every direction");

        // Granted on the host: a1 <-> s1 both ways, and a1 -> the table-52 mesh peer.
        let (a1s, s1s, peer) = (a1_ip.to_string(), s1_ip.to_string(), MESH_PEER.to_string());
        // Emulates F4. The mesh peer's replies are matched on the conntrack
        // original tuple: at mangle PREROUTING their destination is still the
        // node's mesh address, because de-SNAT runs later in that hook.
        let grants: [Vec<&str>; 4] = [
            vec!["-s", &a1s, "-d", &s1s],
            vec!["-s", &s1s, "-d", &a1s],
            vec!["-s", &a1s, "-d", &peer],
            vec!["-s", &peer, "-m", "conntrack", "--ctorigsrc", &a1s],
        ];
        let host_mangle = |op: &str, matches: &[&str]| {
            let mut args = vec!["iptables", "-w", "-t", "mangle", op, "PREROUTING"];
            args.extend(matches);
            args.extend(["-j", "MARK", "--set-xmark", g.as_str()]);
            sh(&args);
        };
        for matches in &grants {
            host_mangle("-I", matches);
        }
        let route_a1 = prepare_attacker(a1, None, s1_ip, true);
        let route_s1 = prepare_attacker(s1, None, a1_ip, true);
        let route_a2 = prepare_attacker(a2, None, s1_ip, true);
        let route_b1 = prepare_attacker(b1, None, s1_ip, true);
        check_eq!(tcp_observed_source(a1, None, s1_ip, Some(&self.s1.tcp)), Some(a1_ip), "granted a1 -> s1");
        check_eq!(tcp_observed_source(s1, None, a1_ip, Some(&self.a1.tcp)), Some(s1_ip), "granted s1 -> a1");
        check_eq!(peer_tcp(a1, &mesh_ns, MESH_PEER), Some(NODE_MESH), "granted a1 -> mesh peer via table 52");
        // Same bridge as a1, or another tenant, without the mark: still closed.
        check!(tcp_observed_source(a2, None, s1_ip, Some(&self.s1.tcp)).is_none(), "ungranted a2 -> s1");
        check!(tcp_observed_source(b1, None, s1_ip, Some(&self.s1.tcp)).is_none(), "ungranted b1 -> s1");
        check!(peer_tcp(a2, &mesh_ns, MESH_PEER).is_none(), "ungranted a2 -> mesh");
        check!(peer_tcp(b1, &mesh_ns, MESH_PEER).is_none(), "ungranted b1 -> mesh");
        for cleanup in [route_a1, route_s1, route_a2, route_b1] {
            cleanup();
        }
        for matches in &grants {
            host_mangle("-D", matches);
        }
        check!(!udp_delivered(a1, None, s1_ip, &self.s1.udp, true), "grant removed, a1 -> s1 closed again");
        pass!("(grant/host): a GRANT-marked pair passes every layer (both ways, and to a table-52 destination); unmarked a2 and b1 stay blocked");
    }

    // (c) with br_netfilter, singleton workloads on one bridge keep their source.
    fn phase_c_br_netfilter(&self) {
        if !bridge_nf(true) {
            println!("SKIP (c): br_netfilter is not loaded (no net.bridge.bridge-nf-call-iptables in this netns); run `modprobe br_netfilter` first");
            return;
        }
        self.phase_a_same_tenant("c");
        self.phase_b_cross_tenant("c");
        pass!("(c): with bridge-nf-call-iptables=1, same-bridge sources preserved and isolation intact");
        // Docker nodes load br_netfilter, which runs mangle PREROUTING from the
        // bridge hook: prove F4's `-i <bridge>` rules still match exactly once.
        self.phase_f4_grants("br_netfilter");
    }

    /// R895-F4 on a real kernel: a cross-tenant grant built by grants.rs's own
    /// rules and applied by the production sequence (bridge, setup, grant), in
    /// both deploy orders. W (acme) admits P (globex) through a real
    /// `MeshPeer::CrossTenant`; P's tenant-mate P2 and singleton S get nothing.
    /// No test-side route or mark: workloads use exactly what kamaji gave them.
    /// Everything above deployed workloads without grants. Before any grant
    /// exists: no clsact qdisc, no proxy entry, bridges' proxy sysctls at the
    /// kernel defaults, and no ARP answer for another bridge's address.
    fn phase_f4_no_grant_node(&self) {
        let qdiscs = sh(&["tc", "qdisc", "show"]);
        check!(!qdiscs.contains("clsact"), "no-grant node carries a clsact qdisc:\n{qdiscs}");
        let proxies = sh(&["ip", "-4", "neigh", "show", "proxy"]);
        check!(proxies.trim().is_empty(), "no-grant node carries proxy neighbour entries:\n{proxies}");
        let mut bridges: Vec<&str> = self.all().iter().map(|w| w.plan.bridge.as_str()).collect();
        bridges.sort();
        bridges.dedup();
        for br in &bridges {
            check_eq!(sysctl(&format!("net.ipv4.conf.{br}.proxy_arp")), "0", "no-grant node: {br} proxy_arp");
            check_eq!(sysctl(&format!("net.ipv4.neigh.{br}.proxy_delay")), "80", "no-grant node: {br} proxy_delay");
        }
        for (from, to) in [(&self.s1, &self.a1), (&self.a1, &self.b1), (&self.b1, &self.s1)] {
            if let Some(mac) = arp_answer(&from.plan.netns, to.plan.container_ip) {
                fail(format!("no-grant node: {} got an ARP answer {mac} for {}", from.plan.netns, to.plan.container_ip));
            }
        }
        pass!("(f4 no-grant node) no clsact, no proxy entry, proxy_arp 0 / proxy_delay 80 on {bridges:?}, and no ARP answer across bridges (s1->a1, a1->b1, b1->s1)");
    }

    fn phase_f4_grants(&self, label: &str) {
        let (acme, globex, solo) = (TenantId("acme".into()), TenantId("globex".into()), TenantId::singleton());
        let tag = self.tag.as_str();
        let _guard = NetnsGuard(["fw", "fp", "fpb", "fp2", "fs", "fq"].iter().map(|n| format!("{tag}-{n}")).collect());
        let grant_to = |name: &str| {
            vec![MeshPeer::CrossTenant {
                tenant: globex.clone(),
                namespace: NamespaceId("default".into()),
                name: MeshIdent(format!("{tag}-{name}")),
            }]
        };
        let grant = grant_to("fp");
        let dep = |name: &str, octet: u8, tenant: &TenantId, allow_from: &[MeshPeer]| {
            deploy(&self.rt, &self.net, tag, name, octet, tenant, allow_from.to_vec())
        };
        let down = |w: Workload| apply(&self.rt, &self.net.teardown_commands(&w.plan));

        let p = dep("fp", 21, &globex, &[]);
        let p2 = dep("fp2", 22, &globex, &[]);
        let s = dep("fs", 23, &solo, &[]);
        let w = dep("fw", 20, &acme, &grant);
        check_eq!(
            w.plan.grants.iter().map(|g| (g.peer_bridge.clone(), g.peer_mark)).collect::<Vec<_>>(),
            vec![(p.plan.bridge.clone(), p.plan.identity_mark)],
            "({label}) W's plan grants exactly P"
        );
        self.f4_pair(&format!("{label}, P deployed before W"), &w, &p, &p2, &s);
        for x in [w, p, p2, s] {
            down(x);
        }

        // What the node remembers of the torn-down pair: neighbour entries on
        // the bridges naming MACs that no longer exist. apply_grant_neighbours
        // flushes a pair's addresses when it installs the pair; without that,
        // W-before-P below failed.
        let neigh = sh(&["ip", "neigh", "show"]);
        for l in neigh.lines().filter(|l| l.starts_with("10.77.77.2")) {
            println!("  (f4 {label}) node neighbour after teardown: {l}");
        }

        // W first, granting a P (`fpb`) whose identity no leftover chain
        // carries: W's deploy finds nobody, so P's own deploy must find W's
        // grant and install the pair.
        let grant = grant_to("fpb");
        let w = dep("fw", 20, &acme, &grant);
        let p = dep("fpb", 21, &globex, &[]);
        let p2 = dep("fp2", 22, &globex, &[]);
        let s = dep("fs", 23, &solo, &[]);
        self.f4_pair(&format!("{label}, W deployed before P"), &w, &p, &p2, &s);
        let w_ip = w.plan.container_ip;

        // Withdrawn: W redeploys (same name and address) without the grant.
        drop(w);
        let w = dep("fw", 20, &acme, &[]);
        check!(
            tcp_observed_source(&p.plan.netns, None, w_ip, Some(&w.tcp)).is_none(),
            "({label}) grant withdrawn, P -> W TCP still connects"
        );
        check!(!udp_delivered(&p.plan.netns, None, w_ip, &w.udp, false), "({label}) grant withdrawn, P -> W UDP delivered");
        let (refused, _) = udp_refused(&p.plan.netns, w_ip, PORT + 7);
        check!(!refused, "({label}) grant withdrawn, W's ICMP port unreachable still reaches P");
        if let Some(mac) = arp_answer(&p.plan.netns, w_ip) {
            fail(format!("({label}) grant withdrawn, P still gets an ARP answer {mac} for W"));
        }
        pass!("(f4 {label}) withdrawn: after W redeploys without the grant, P -> W is blocked again and P's ARP for W goes unanswered");

        // Re-addressed: W re-granted, P redeploys at .24, and a different
        // globex workload Q takes P's old .21.
        drop(w);
        let w = dep("fw", 20, &acme, &grant);
        let old = p.plan.container_ip;
        drop(p);
        let p = dep("fpb", 24, &globex, &[]);
        let q = dep("fq", 21, &globex, &[]);
        let q_ip = q.plan.container_ip;
        check_eq!(
            tcp_exchange(&p.plan.netns, w_ip, &w.tcp).map(|(src, _, reply)| (src, reply)),
            Some((p.plan.container_ip, true)),
            "({label}) P redeployed at {} -> W: the grant follows P's identity",
            p.plan.container_ip
        );
        check!(
            tcp_observed_source(&q.plan.netns, None, w_ip, Some(&w.tcp)).is_none(),
            "({label}) Q at P's old address {old} -> W TCP connected"
        );
        check!(!udp_delivered(&q.plan.netns, None, w_ip, &w.udp, false), "({label}) Q at {old} -> W UDP delivered");
        check!(!udp_delivered(&q.plan.netns, None, w_ip, &w.udp, true), "({label}) Q at {old} -> W UDP via .1 delivered");
        check!(
            tcp_observed_source(&w.plan.netns, None, q_ip, Some(&q.tcp)).is_none(),
            "({label}) W NEW -> Q at {old} TCP connected"
        );
        for (who, ns, target) in [("Q for W", &q.plan.netns, w_ip), ("W for Q", &w.plan.netns, q_ip)] {
            if let Some(mac) = arp_answer(ns, target) {
                fail(format!("({label}) {who}: Q at P's old address {old} got a proxy ARP answer {mac}"));
            }
        }
        let id_old = sh(&["iptables", "-w", "-t", "mangle", "-S", &format!("yah-id-{old}")]);
        check!(
            id_old.contains(&format!("{:#x}/{:#x}", q.plan.identity_mark, container_net::FWMARK_IDENTITY_MASK))
                && !id_old.contains(&format!("{:#x}/", p.plan.identity_mark)),
            "({label}) yah-id-{old} does not carry exactly Q's identity:\n{id_old}"
        );
        pass!("(f4 {label}) re-addressed: P at {} keeps its grant; Q deployed at P's old {old} inherits nothing", p.plan.container_ip);

        let pre = sh(&["iptables", "-w", "-t", "mangle", "-S", "PREROUTING"]);
        for octet in 20..=24u8 {
            let a = format!("10.77.77.{octet}/32");
            let n = |needle: String| pre.lines().filter(|l| l.contains(&needle)).count();
            let jumps = (n(format!("-s {a} -j yah-id-")), n(format!("-s {a} -j yah-gr-")), n(format!("-d {a} -j yah-gr-")));
            let want = if octet == 20 { (1, 1, 1) } else { (1, 0, 0) };
            check_eq!(jumps, want, "({label}) PREROUTING jumps for {a} (id, gr -s, gr -d):\n{pre}");
        }
        for x in [w, p, p2, s, q] {
            down(x);
        }
        pass!("(f4 {label}) one PREROUTING jump per chain per address after every redeploy");
    }

    /// The assertions on one granted pair: W admits P.
    fn f4_pair(&self, label: &str, w: &Workload, p: &Workload, p2: &Workload, s: &Workload) {
        let (w_ip, p_ip) = (w.plan.container_ip, p.plan.container_ip);
        let (id_p, gr_w) = (format!("yah-id-{p_ip}"), format!("yah-gr-{w_ip}"));
        let from_p = format!("-i {}", p.plan.bridge);

        let (p_mac, w_mac) = (arp_answer(&p.plan.netns, w_ip), arp_answer(&w.plan.netns, p_ip));
        check!(p_mac.is_some(), "({label}) P's ARP for W on {} got no proxy answer", p.plan.bridge);
        check!(w_mac.is_some(), "({label}) W's ARP for P on {} got no proxy answer", w.plan.bridge);
        pass!("(f4 {label}) proxy ARP answers the granted pair: P resolves W to {p_mac:?}, W resolves P to {w_mac:?}");

        let c0 = mangle_save();
        let tcp = tcp_exchange(&p.plan.netns, w_ip, &w.tcp);
        let c1 = mangle_save();
        if tcp.is_none() {
            self.dump(&format!("f4 {label}: granted P -> W"));
        }
        check_eq!(
            tcp.map(|(src, _, reply)| (src, reply)),
            Some((p_ip, true)),
            "({label}) granted P -> W: (source W observed, W's reply read by P)"
        );
        check!(udp_delivered(&p.plan.netns, None, w_ip, &w.udp, false), "({label}) granted P -> W UDP");
        pass!("(f4 {label}) granted: P -> W TCP connects, W sees P's own address, W's replies reach P");

        let id_hits = mangle_delta(&c0, &c1, &id_p, &[&from_p, "-j MARK"]);
        let grant_hits = mangle_delta(&c0, &c1, &gr_w, &[&from_p, "-j MARK"]);
        check!(
            id_hits > 0 && grant_hits > 0,
            "({label}) `-i {}` did not match routed traffic: {id_p} +{id_hits}, {gr_w} MARK +{grant_hits}\n{c1}",
            p.plan.bridge
        );
        pass!("(f4 {label}) `-i <bridge>` matches routed bridge traffic in mangle PREROUTING: {id_p} +{id_hits}, {gr_w} MARK +{grant_hits}");

        let connmark_hits = mangle_delta(&c0, &c1, &gr_w, &[&from_p, "-j CONNMARK"]);
        let reply_hits = mangle_delta(&c0, &c1, &gr_w, &["--ctdir REPLY"]);
        let marks = tcp.map(|(_, sport, _)| ct_marks("tcp", p_ip, w_ip, sport, PORT)).unwrap_or_default();
        check!(connmark_hits > 0, "({label}) {gr_w} CONNMARK never matched");
        check!(
            !marks.is_empty() && marks.iter().all(|m| m & FWMARK_GRANT != 0),
            "({label}) conntrack marks for P -> W:{PORT} are {marks:?}, want the GRANT bit"
        );
        check!(reply_hits > 0, "({label}) W's replies never matched {gr_w}'s connmark reply rule");
        pass!("(f4 {label}) CONNMARK --set-xmark: the connection carries GRANT (ct marks {marks:?}) and W's replies match it (reply rule +{reply_hits})");

        let c2 = mangle_save();
        let (refused, lport) = udp_refused(&p.plan.netns, w_ip, PORT + 7);
        let c3 = mangle_save();
        let related = mangle_delta(&c2, &c3, &gr_w, &["--ctdir REPLY"]);
        let umarks = ct_marks("udp", p_ip, w_ip, lport, PORT + 7);
        check!(refused, "({label}) P's UDP to W's closed port {} got no ICMP port unreachable back", PORT + 7);
        check!(related > 0, "({label}) the ICMP error never matched {gr_w}'s connmark reply rule");
        check!(
            !umarks.is_empty() && umarks.iter().all(|m| m & FWMARK_GRANT != 0),
            "({label}) conntrack marks for P -> W:{} UDP are {umarks:?}, want the GRANT bit",
            PORT + 7
        );
        pass!("(f4 {label}) RELATED ICMP inherits the connmark: W's port unreachable reaches P via the reply rule (+{related}, udp ct marks {umarks:?})");

        for (who, from) in [("P2", p2), ("S", s)] {
            let ns = &from.plan.netns;
            check!(tcp_observed_source(ns, None, w_ip, Some(&w.tcp)).is_none(), "({label}) {who} -> W TCP connected");
            check!(!udp_delivered(ns, None, w_ip, &w.udp, false), "({label}) {who} -> W UDP delivered");
            check!(!udp_delivered(ns, None, w_ip, &w.udp, true), "({label}) {who} -> W UDP via .1 delivered");
        }
        check!(tcp_observed_source(&w.plan.netns, None, p_ip, Some(&p.tcp)).is_none(), "({label}) W NEW -> P TCP connected");
        check!(!udp_delivered(&w.plan.netns, None, p_ip, &p.udp, false), "({label}) W NEW -> P UDP delivered");
        check!(!udp_delivered(&w.plan.netns, None, p_ip, &p.udp, true), "({label}) W NEW -> P UDP via .1 delivered");
        pass!("(f4 {label}) blocked: P's tenant-mate P2 -> W, singleton S -> W, and W opening a new connection to P (TCP; UDP plain and via .1)");

        let (s_ip, p2_ip) = (s.plan.container_ip, p2.plan.container_ip);
        for (who, ns, target) in [
            ("P2 for W", &p2.plan.netns, w_ip),
            ("S for W", &s.plan.netns, w_ip),
            ("P for S", &p.plan.netns, s_ip),
            ("W for P2", &w.plan.netns, p2_ip),
            ("W for S", &w.plan.netns, s_ip),
        ] {
            if let Some(mac) = arp_answer(ns, target) {
                fail(format!("({label}) {who}: a non-granted request got a proxy ARP answer {mac}"));
            }
        }
        pass!("(f4 {label}) no proxy ARP beyond the pair: P2 and S get none for W, P none for S, W none for P2 or S");
    }

    // (d) flush each layer's owner; the other must hold.
    fn phase_d_flush(&self) {
        let mesh_ns = format!("{}-mesh", self.tag);
        sh(&["iptables", "-w", "-F", "FORWARD"]);
        sh(&["iptables", "-w", "-t", "mangle", "-F"]);
        self.phase_b_cross_tenant("d: FORWARD+mangle flushed");
        check!(peer_tcp(&self.a1.plan.netns, &mesh_ns, MESH_PEER).is_none(), "(d) mesh egress after flush");
        check!(
            ingress_tcp(&mesh_ns, &self.a1).is_none(),
            "(d) with the reply mark flushed, mesh ingress should fail closed"
        );
        pass!("(d): after iptables -F FORWARD and -t mangle -F, cross-tenant and tenant->mesh stay blocked; mesh ingress fails closed");

        self.reassert_everything();
        for priority in 1200..=1204u32 {
            while sh_ok(&["ip", "rule", "del", "priority", &priority.to_string()]) {}
        }
        self.phase_b_cross_tenant("d: ip rules removed");
        pass!("(d): with every kamaji ip rule removed, the iptables layer alone holds");
        self.reassert_everything();
    }

    fn reassert_everything(&self) {
        for w in self.all() {
            apply(&self.rt, &self.net.bridge_commands(&w.plan));
            let rules: Vec<Cmd> = self
                .net
                .setup_commands(&w.plan)
                .into_iter()
                .filter(|c| c.args.starts_with(&["rule".to_string(), "add".to_string()]))
                .collect();
            apply(&self.rt, &rules);
        }
    }

    // (e) re-run the real bridge commands while a probe hammers the boundary.
    fn phase_e_reassert_under_probe(&self) {
        let rounds = 15;
        // e1: both layers present.
        self.hammer("e1", &self.a1, &self.s1, || {
            for w in self.all() {
                apply(&self.rt, &self.net.bridge_commands(&w.plan));
            }
        }, rounds);
        // e2: the singleton->a1 routing rule removed, so only the filter's
        // re-assert stands between s1 and a1.
        let del: Vec<Cmd> = self
            .net
            .teardown_commands(&self.a1.plan)
            .into_iter()
            .filter(|c| c.args.first().map(String::as_str) == Some("rule"))
            .collect();
        apply(&self.rt, &del);
        self.hammer("e2", &self.s1, &self.a1, || {
            for w in self.all() {
                apply(&self.rt, &self.net.bridge_commands(&w.plan));
            }
        }, rounds);
        self.reassert_everything();
        // e3: FORWARD flushed, so only the routing re-assert stands.
        sh(&["iptables", "-w", "-F", "FORWARD"]);
        let rules_only: Vec<Cmd> = self
            .net
            .bridge_commands(&self.a1.plan)
            .into_iter()
            .filter(|c| c.bin == "ip" && c.args.first().map(String::as_str) == Some("rule"))
            .collect();
        self.hammer("e3", &self.a1, &self.s1, || apply(&self.rt, &rules_only), rounds * 4);
        self.reassert_everything();

        // Idempotency on this kernel, whatever its duplicate behaviour.
        let rules = sh(&["ip", "rule", "show"]);
        for w in [&self.a1, &self.b1] {
            let br = &w.plan.bridge;
            let subnet = rules.lines().filter(|l| l.contains(&format!("iif {br}")) && l.contains("10.77.77.0/24")).count();
            let mesh = rules.lines().filter(|l| l.contains(&format!("iif {br}")) && l.contains("100.64.0.0/10")).count();
            check_eq!((subnet, mesh), (1, 1), "prohibits accumulated on {br}:\n{rules}");
        }
        let forward = sh(&["iptables", "-w", "-S", "FORWARD"]);
        let tagged = forward.lines().filter(|l| l.contains(&self.a1.plan.bridge) && l.contains("yah-isolation")).count();
        check_eq!(tagged, 4, "FORWARD drops accumulated:\n{forward}");
        pass!("(e): no cross-tenant packet through {rounds}+ re-asserts per layer; one copy of every rule after");
    }

    fn hammer(&self, label: &str, from: &Workload, to: &Workload, mut reassert: impl FnMut(), rounds: usize) {
        let ns = from.plan.netns.clone();
        let dst = to.plan.container_ip;
        let gw = GW.to_string();
        let _ = Command::new("ip").args(["-n", &ns, "route", "replace", &format!("{dst}/32"), "via", &gw]).output();
        let sock = in_netns(&ns, || UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let prober = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut sent = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = sock.send_to(b"hammer", (dst, PORT));
                    sent += 1;
                    std::thread::sleep(Duration::from_micros(200));
                }
                sent
            })
        };
        for _ in 0..rounds {
            reassert();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let sent = prober.join().unwrap();
        let _ = Command::new("ip").args(["-n", &ns, "route", "del", &format!("{dst}/32")]).output();
        let mut buf = [0u8; 64];
        let deadline = Instant::now() + Duration::from_millis(300);
        while Instant::now() < deadline {
            if let Ok((n, src)) = to.udp.recv_from(&mut buf) {
                check!(&buf[..n] != b"hammer", "({label}) a probe from {src} got through a re-assert");
            }
        }
        check!(sent > 100, "({label}) the probe barely ran: {sent} datagrams");
        println!("  ({label}) {sent} probes, 0 delivered");
    }

    // (f) per-workload teardown leaves nothing per-workload behind.
    fn phase_f_teardown(self) {
        for w in self.all() {
            apply(&self.rt, &self.net.teardown_commands(&w.plan));
        }
        let veths = sh(&["ip", "-o", "link", "show", "type", "veth"]);
        check!(!veths.lines().any(|l| !l.contains("ktwan0") && !l.contains("ktmesh0")), "veths left:\n{veths}");
        let rules = sh(&["ip", "rule", "show"]);
        check!(!rules.lines().any(|l| l.starts_with("1200:")), "per-workload rules left:\n{rules}");
        let routes = sh(&["ip", "route", "show"]);
        check!(!routes.lines().any(|l| l.starts_with("10.77.77.") && !l.starts_with("10.77.77.0/24")), "host routes left:\n{routes}");
        for w in self.all() {
            check!(!container_net::netns_path(&w.plan.netns).exists(), "{} left", w.plan.netns);
        }
        pass!("(f): teardown leaves no veth, per-workload rule, host route or workload netns (node-wide bridge state dies with the private netns)");
    }
}

// ── Probes ──────────────────────────────────────────────────────────────────

/// Send a nonce from `ns` (optionally from a claimed `src`, optionally routed
/// explicitly via `.1`) and report whether `receiver` got it.
fn udp_delivered(ns: &str, src: Option<Ipv4Addr>, dst: Ipv4Addr, receiver: &UdpSocket, via_gw: bool) -> bool {
    udp_probe(ns, src, dst, PORT, receiver, via_gw, None)
}

/// [`udp_delivered`] to any port, optionally with `SO_MARK` set on the sending
/// socket — the in-namespace forgery of a mark the host would honour.
fn udp_probe(
    ns: &str,
    src: Option<Ipv4Addr>,
    dst: Ipv4Addr,
    port: u16,
    receiver: &UdpSocket,
    via_gw: bool,
    mark: Option<u32>,
) -> bool {
    let cleanup = prepare_attacker(ns, src, dst, via_gw);
    let nonce = format!("n{}", rand_u32());
    let payload = nonce.clone();
    in_netns(ns, move || {
        let s = UdpSocket::bind((src.unwrap_or(Ipv4Addr::UNSPECIFIED), 0)).unwrap();
        if let Some(mark) = mark {
            let rc = unsafe {
                libc::setsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&mark as *const u32).cast(),
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            assert_eq!(rc, 0, "SO_MARK: {}", std::io::Error::last_os_error());
        }
        for _ in 0..3 {
            let _ = s.send_to(payload.as_bytes(), (dst, port));
        }
    });
    let got = drain_for(receiver, nonce.as_bytes(), Duration::from_millis(400));
    cleanup();
    got
}

fn prepare_attacker(ns: &str, src: Option<Ipv4Addr>, dst: Ipv4Addr, via_gw: bool) -> impl FnOnce() {
    let ns = ns.to_string();
    if let Some(src) = src {
        sh(&["ip", "-n", &ns, "addr", "add", &format!("{src}/32"), "dev", "eth0"]);
    }
    if via_gw {
        sh(&["ip", "-n", &ns, "route", "replace", &format!("{dst}/32"), "via", &GW.to_string()]);
    }
    move || {
        if let Some(src) = src {
            let _ = Command::new("ip").args(["-n", &ns, "addr", "del", &format!("{src}/32"), "dev", "eth0"]).output();
        }
        if via_gw {
            let _ = Command::new("ip").args(["-n", &ns, "route", "del", &format!("{dst}/32")]).output();
        }
    }
}

fn drain_for(receiver: &UdpSocket, nonce: &[u8], window: Duration) -> bool {
    let mut buf = [0u8; 256];
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        if let Ok((n, _)) = receiver.recv_from(&mut buf) {
            if &buf[..n] == nonce {
                return true;
            }
        }
    }
    false
}

fn rand_u32() -> u32 {
    let mut v = 0u32;
    unsafe { libc::getrandom((&mut v as *mut u32).cast(), 4, 0) };
    v
}

/// Connect from `ns` to `dst:PORT`; if `listener` is given, accept on it and
/// return the source address the server observed. `None` = no connection.
fn tcp_observed_source(ns: &str, src: Option<Ipv4Addr>, dst: Ipv4Addr, listener: Option<&TcpListener>) -> Option<Ipv4Addr> {
    let listener = listener.expect("listener");
    tcp_connect_and_accept(ns, src, SocketAddr::from((dst, PORT)), listener)
}

fn tcp_to(ns: &str, dst: Ipv4Addr, port: u16, listener: &TcpListener) -> Option<Ipv4Addr> {
    tcp_connect_and_accept(ns, None, SocketAddr::from((dst, port)), listener)
}

fn tcp_connect_and_accept(ns: &str, src: Option<Ipv4Addr>, dst: SocketAddr, listener: &TcpListener) -> Option<Ipv4Addr> {
    let connected = in_netns(ns, move || {
        let _ = src;
        TcpStream::connect_timeout(&dst, Duration::from_millis(700)).map(|mut s| {
            let _ = s.write_all(b"x");
            s
        })
    });
    let deadline = Instant::now() + Duration::from_millis(300);
    let mut seen = None;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, peer)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                let _ = stream.read(&mut [0u8; 1]);
                if let SocketAddr::V4(v4) = peer {
                    seen = Some(*v4.ip());
                }
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    match (connected.is_ok(), seen) {
        (true, Some(ip)) => Some(ip),
        (false, None) => None,
        (c, s) => panic!("inconsistent TCP probe to {dst} from {ns}: connected={c} accepted={s:?}"),
    }
}

/// A TCP listener in the external namespace `peer_ns` at `addr`, dialled from
/// the workload namespace `ns`. Returns the source the peer observed.
fn peer_tcp(ns: &str, peer_ns: &str, addr: Ipv4Addr) -> Option<Ipv4Addr> {
    let listener = in_netns(peer_ns, move || {
        let l = TcpListener::bind((addr, PORT + 2)).unwrap();
        l.set_nonblocking(true).unwrap();
        l
    });
    tcp_connect_and_accept(ns, None, SocketAddr::from((addr, PORT + 2)), &listener)
}

fn peer_udp(ns: &str, src: Option<Ipv4Addr>, peer_ns: &str, addr: Ipv4Addr) -> bool {
    peer_udp_marked(ns, src, peer_ns, addr, None)
}

fn peer_udp_marked(ns: &str, src: Option<Ipv4Addr>, peer_ns: &str, addr: Ipv4Addr, mark: Option<u32>) -> bool {
    let receiver = in_netns(peer_ns, move || {
        let s = UdpSocket::bind((addr, PORT + 3)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        s
    });
    udp_probe(ns, src, addr, PORT + 3, &receiver, false, mark)
}

/// Dial a workload's listener from an external namespace (wan or mesh).
fn ingress_tcp(peer_ns: &str, to: &Workload) -> Option<Ipv4Addr> {
    tcp_connect_and_accept(peer_ns, None, SocketAddr::from((to.plan.container_ip, PORT)), &to.tcp)
}

/// TCP from `ns` to `dst:PORT`, accepted on `listener`, then a reply written by
/// the accepting side and read back in `ns`. Returns (source the server saw,
/// client's source port, whether the reply arrived); `None` = no connection.
fn tcp_exchange(ns: &str, dst: Ipv4Addr, listener: &TcpListener) -> Option<(Ipv4Addr, u16, bool)> {
    let to = SocketAddr::from((dst, PORT));
    let client = in_netns(ns, move || TcpStream::connect_timeout(&to, Duration::from_millis(700)).ok());
    let deadline = Instant::now() + Duration::from_millis(300);
    let mut accepted = None;
    while Instant::now() < deadline {
        if let Ok(pair) = listener.accept() {
            accepted = Some(pair);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    match (client, accepted) {
        (None, None) => None,
        (Some(mut client), Some((mut server, SocketAddr::V4(peer)))) => {
            let _ = server.write_all(b"pong");
            let _ = client.set_read_timeout(Some(Duration::from_millis(500)));
            let mut buf = [0u8; 4];
            let reply = client.read_exact(&mut buf).is_ok() && &buf == b"pong";
            Some((*peer.ip(), peer.port(), reply))
        }
        (c, a) => panic!("inconsistent TCP exchange to {to} from {ns}: connected={} accepted={:?}", c.is_some(), a.map(|p| p.1)),
    }
}

/// A connected UDP socket in `ns` sends to `dst:port`, where nothing listens.
/// True iff the resulting ICMP port unreachable came back as ECONNREFUSED.
/// Also returns the socket's local port, to find its conntrack entry.
fn udp_refused(ns: &str, dst: Ipv4Addr, port: u16) -> (bool, u16) {
    in_netns(ns, move || {
        let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        s.connect((dst, port)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
        let local = s.local_addr().unwrap().port();
        let refused = |e: &std::io::Error| e.kind() == std::io::ErrorKind::ConnectionRefused;
        let mut buf = [0u8; 16];
        for _ in 0..3 {
            if s.send(b"probe").as_ref().is_err_and(refused) || s.recv(&mut buf).as_ref().is_err_and(refused) {
                return (true, local);
            }
        }
        (false, local)
    })
}

/// `iptables-save -c -t mangle` in the current netns.
/// The link-layer address `ns` resolves `addr` to after trying to send to it,
/// or `None` when its ARP goes unanswered. Clears `ns`'s entry first, so an
/// earlier probe's result cannot stand in for this one. The window covers the
/// first request and its first retry.
fn arp_answer(ns: &str, addr: Ipv4Addr) -> Option<String> {
    let target = addr.to_string();
    let _ = Command::new("ip").args(["-n", ns, "neigh", "flush", "to", &target]).output();
    in_netns(ns, move || {
        if let Ok(s) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
            let _ = s.send_to(b"arp", (addr, PORT + 9));
        }
    });
    let deadline = Instant::now() + Duration::from_millis(1500);
    loop {
        let shown = sh(&["ip", "-n", ns, "neigh", "show", "to", &target, "dev", "eth0"]);
        let mac = shown.split_whitespace().skip_while(|w| *w != "lladdr").nth(1);
        if let Some(mac) = mac {
            return Some(mac.to_string());
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn mangle_save() -> String {
    sh(&["iptables-save", "-c", "-t", "mangle"])
}

/// Packets counted by rules of `chain` whose text contains every needle.
fn mangle_count(save: &str, chain: &str, needles: &[&str]) -> u64 {
    let head = format!("-A {chain} ");
    save.lines()
        .filter_map(|l| {
            let (counters, rule) = l.strip_prefix('[')?.split_once("] ")?;
            if !rule.starts_with(&head) || !needles.iter().all(|n| rule.contains(n)) {
                return None;
            }
            counters.split(':').next()?.parse::<u64>().ok()
        })
        .sum()
}

fn mangle_delta(before: &str, after: &str, chain: &str, needles: &[&str]) -> u64 {
    mangle_count(after, chain, needles).saturating_sub(mangle_count(before, chain, needles))
}

/// Connmarks of this thread's netns conntrack entries whose original tuple is
/// `proto src:sport -> dst:dport`.
fn ct_marks(proto: &str, src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16) -> Vec<u32> {
    let path = "/proc/thread-self/net/nf_conntrack";
    let table = std::fs::read_to_string(path).unwrap_or_else(|e| {
        println!("  (f4) cannot read {path}: {e}");
        String::new()
    });
    let tuple = format!("src={src} dst={dst} sport={sport} dport={dport} ");
    table
        .lines()
        .filter(|l| l.split_whitespace().nth(2) == Some(proto) && l.contains(&tuple))
        .filter_map(|l| l.split_whitespace().find_map(|t| t.strip_prefix("mark=")).and_then(|m| m.parse().ok()))
        .collect()
}

/// One sysctl value in the current netns, trimmed.
fn sysctl(name: &str) -> String {
    sh(&["sysctl", "-n", name]).trim().to_string()
}

/// The scope-link (`fe80::`) address on `dev` in the current netns, without its
/// prefix length, or `None` when the device carries no IPv6 (disable_ipv6).
fn v6_linklocal(dev: &str) -> Option<String> {
    let out = sh(&["ip", "-6", "-o", "addr", "show", "dev", dev, "scope", "link"]);
    let mut it = out.split_whitespace();
    while let Some(t) = it.next() {
        if t == "inet6" {
            return it.next().map(|a| a.split('/').next().unwrap().to_string());
        }
    }
    None
}

/// Connect from `ns` to v6 `addr` scoped to interface `scope`, on `port`, and
/// accept on `listener` (bound in the current/node netns). True iff it both
/// connected and the listener accepted — the shape of the bypass.
fn tcp6_reaches(ns: &str, addr: &str, scope: &str, port: u16, listener: &TcpListener) -> bool {
    let addr = addr.to_string();
    let scope = scope.to_string();
    let connected = in_netns(ns, move || {
        let idx = std::ffi::CString::new(scope)
            .ok()
            .map(|c| unsafe { libc::if_nametoindex(c.as_ptr()) })
            .unwrap_or(0);
        let ip: Ipv6Addr = addr.parse().ok()?;
        let sa = std::net::SocketAddrV6::new(ip, port, 0, idx);
        TcpStream::connect_timeout(&SocketAddr::V6(sa), Duration::from_millis(700)).ok()
    });
    let _stream = match connected {
        Some(s) => s,
        None => return false,
    };
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
            let _ = s.read(&mut [0u8; 1]);
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Give `ns`'s eth0 a v6 ULA and a default v6 route via `bridge`'s link-local,
/// then send to `dst:port`. True iff `recv` got it. Best-effort setup: post-fix
/// the bridge has no link-local, so there is no next hop and nothing is sent.
fn v6_push_to_mesh(ns: &str, bridge: &str, dst: Ipv6Addr, port: u16, recv: &UdpSocket) -> bool {
    let ll = match v6_linklocal(bridge) {
        Some(a) => a,
        None => return false,
    };
    let src: Ipv6Addr = "fd7a:115c:a1e0:aa::a".parse().unwrap();
    let ip = |args: &[&str]| {
        let _ = Command::new("ip").args(args).output();
    };
    ip(&["-n", ns, "-6", "addr", "add", &format!("{src}/64"), "dev", "eth0", "nodad"]);
    // Link-local next hop: `ip route` wants `via <ll> dev eth0`, not the socket
    // `%eth0` scope form.
    ip(&["-n", ns, "-6", "route", "add", "default", "via", &ll, "dev", "eth0"]);
    let nonce = format!("v6-{}", rand_u32());
    let payload = nonce.clone();
    in_netns(ns, move || {
        if let Ok(s) = UdpSocket::bind(SocketAddr::from((src, 0))) {
            for _ in 0..3 {
                let _ = s.send_to(payload.as_bytes(), SocketAddr::from((dst, port)));
            }
        }
    });
    let got = drain_for(recv, nonce.as_bytes(), Duration::from_millis(400));
    ip(&["-n", ns, "-6", "addr", "del", &format!("{src}/64"), "dev", "eth0"]);
    got
}

// ── Topology and census ─────────────────────────────────────────────────────

/// `net.bridge.bridge-nf-call-iptables` in this netns. Returns whether the knob
/// exists (i.e. br_netfilter is loaded and namespaced on this kernel).
fn bridge_nf(on: bool) -> bool {
    let path = "/proc/sys/net/bridge/bridge-nf-call-iptables";
    if !std::path::Path::new(path).exists() {
        return false;
    }
    std::fs::write(path, if on { "1" } else { "0" }).is_ok()
}

fn external_peers(wan: &str, mesh: &str) {
    for (ns, node_if, node_addr, peer_addr) in [
        (wan, "ktwan0", format!("{WAN_NODE}/24"), format!("{WAN_PEER}/24")),
        (mesh, "ktmesh0", format!("{NODE_MESH}/32"), format!("{MESH_PEER}/32")),
    ] {
        sh(&["ip", "netns", "add", ns]);
        sh(&["ip", "link", "add", node_if, "type", "veth", "peer", "name", "ktpeer"]);
        sh(&["ip", "link", "set", "ktpeer", "netns", ns]);
        sh(&["ip", "addr", "add", &node_addr, "dev", node_if]);
        sh(&["ip", "link", "set", node_if, "up"]);
        sh(&["ip", "-n", ns, "link", "set", "lo", "up"]);
        sh(&["ip", "-n", ns, "link", "set", "ktpeer", "name", "eth0"]);
        sh(&["ip", "-n", ns, "addr", "add", &peer_addr, "dev", "eth0"]);
        sh(&["ip", "-n", ns, "link", "set", "eth0", "up"]);
    }
    // The internet: default route out of the node via wan.
    sh(&["ip", "-n", wan, "addr", "add", &format!("{INTERNET}/32"), "dev", "lo"]);
    sh(&["ip", "-n", wan, "route", "add", "10.77.77.0/24", "via", &WAN_NODE.to_string()]);
    sh(&["ip", "route", "add", "default", "via", &WAN_PEER.to_string()]);
    // The mesh, tailscale-shaped: table 52 behind priority 5270.
    sh(&["ip", "route", "add", &format!("{MESH_PEER}/32"), "dev", "ktmesh0", "table", "52"]);
    sh(&["ip", "route", "add", "100.64.0.0/10", "dev", "ktmesh0", "table", "52"]);
    sh(&["ip", "rule", "add", "priority", "5270", "lookup", "52"]);
    sh(&["ip", "-n", mesh, "route", "add", &format!("{NODE_MESH}/32"), "dev", "eth0"]);
    sh(&["ip", "-n", mesh, "route", "add", "10.77.77.0/24", "via", &NODE_MESH.to_string(), "dev", "eth0"]);
}

/// Print, and so record in the run log, what this kernel does with an identical
/// `ip rule add` — the behaviour `OnFailure::ExistsOk` is designed around.
fn report_rule_add_behaviour() {
    let add = ["ip", "rule", "add", "priority", "31000", "iif", "ktprobe", "prohibit"];
    sh(&add);
    let second = Command::new(add[0]).args(&add[1..]).output().unwrap();
    let copies = sh(&["ip", "rule", "show"]).lines().filter(|l| l.contains("ktprobe")).count();
    println!(
        "KERNEL: identical `ip rule add` -> {} ({copies} cop{} present)",
        if second.status.success() { "accepted".to_string() } else { String::from_utf8_lossy(&second.stderr).trim().to_string() },
        if copies == 1 { "y" } else { "ies" }
    );
    while sh_ok(&["ip", "rule", "del", "priority", "31000"]) {}
}

/// After the private netns is gone: nothing of this test on the host.
fn host_census_is_clean(tag: &str) {
    let netns = sh(&["ip", "netns", "list"]);
    assert!(!netns.contains(tag), "test netns left on the host:\n{netns}");
    let links = sh(&["ip", "-o", "link"]);
    assert!(!links.contains("ktn0") && !links.contains("ktwan0") && !links.contains("ktmesh0"), "test links on the host:\n{links}");
    let rules = sh(&["ip", "rule", "show"]);
    assert!(!rules.contains("10.77.77.") && !rules.contains("ktn0"), "test rules on the host:\n{rules}");
    let save = Command::new("iptables-save").output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    assert!(!save.contains("10.77.77.") && !save.contains("ktn0"), "test iptables rules on the host:\n{save}");
    println!("PASS (f/host): no test netns, link, ip rule or iptables rule on the host");
}

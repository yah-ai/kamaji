//! Cross-tenant grants: the explicit opt-in W206 requires on top of R895-F3's
//! tenant isolation (R895-F4, W343 §"Tenant isolation").
//!
//! A workload `W` that lists `MeshPeer::CrossTenant { tenant, namespace, name }`
//! in `expose.mesh.allow_from` admits connections from that one workload `P`
//! when both run on this node. Every isolation layer R895-F3 installs — the
//! `ip rule` prohibits and the FORWARD drops — exempts packets carrying
//! [`FWMARK_GRANT`]. This module sets that bit, in mangle PREROUTING, on exactly
//! the granted pair's packets: `P → W`, and `W → P` in the reply direction of a
//! connection a grant admitted. It installs no route, no `ip rule` and no
//! FORWARD rule, so an exempted packet takes the ordinary routing and filter
//! path like any other.
//!
//! ## Why marks, not addresses
//!
//! A grant names its peer by mesh identity, and nothing on the node maps an
//! identity to an address. Resolving it in yubaba and shipping addresses in
//! `Deploy` fails on ordering: whichever of `P` and `W` deploys second would
//! have to rewrite rules belonging to the first, and every redeploy of `P` moves
//! its address out from under `W`'s rules. So the mapping is built in the
//! kernel, and each piece of it is owned by exactly one address:
//!
//! - `yah-id-<addr>`: packets from `addr` on its own bridge, addressed inside
//!   the node's `/24`, carry that workload's [`identity_mark`] in
//!   [`FWMARK_IDENTITY_MASK`].
//! - `yah-gr-<addr>`: packets to `addr` from a granted peer's bridge carrying
//!   that peer's identity get [`FWMARK_GRANT`], and so does their connection
//!   (connmark). Packets from `addr` in the reply direction of such a connection
//!   get it too.
//!
//! A deploy flushes and rewrites both chains for its own address, so a new owner
//! of a reused address inherits nothing from the old one. The PREROUTING jumps
//! name only the address, so re-asserting them is exact. Identity jumps are
//! inserted (`-I`) and grant jumps appended (`-A`): every identity mark is set
//! before any grant check reads it in the same traversal, whatever order the
//! workloads deployed in.
//!
//! ## Reaching a peer on another bridge
//!
//! Marks alone do not make a granted pair talk. A workload holds its address
//! as `/24` on `eth0`, so it treats every address in the node's `/24` as
//! on-link: it ARPs for the peer on its own bridge, and the peer is not there.
//! Measured on us-west-003 (kernel 6.12, R895-F4's real-kernel phase): with
//! only the mangle rules, a granted `P → W` never reached PREROUTING — `P`'s
//! identity chain counted zero packets — in both deploy orders, routed and
//! under br_netfilter.
//!
//! So the node answers that one ARP, for the granted pair and nothing else. For
//! `P` on bridge `Bp` granted by `W` on bridge `Bw`:
//!
//! - a proxy neighbour entry for `W` on `Bp` (`ip neigh replace proxy`), and
//!   one for `P` on `Bw`;
//! - a tc flower filter on `Bp`'s clsact ingress that matches an ARP request
//!   `arp_sip P arp_tip W` and sets [`FWMARK_GRANT`] with `skbedit`, and the
//!   reverse (`arp_sip W arp_tip P`) on `Bw`. A bridge's ingress hook sees
//!   the frames the bridge passes up to the host, broadcast ARP included;
//! - `proxy_delay=0` on both bridges, so the answer is not held back for up to
//!   0.8s. It affects only proxy answers, and those exist on a bridge only for
//!   its grants.
//!
//! An answer needs both halves. `arp_process` answers for a proxy entry only
//! after looking the target up through the policy rules, and R895-F3's `iif
//! <bridge> to <node /24> fwmark 0/GRANT prohibit` (or `iif <node bridge> to
//! <addr>/32 …`) turns that lookup UNREACHABLE unless the request carries the
//! mark. So `P`'s tenant-mate asking for `W` gets no answer, and neither does
//! `P` asking for anyone but `W`. `proxy_arp` stays off on every bridge. An
//! answered ARP admits nothing by itself: the IP packet behind it needs its
//! own grant, and without one it meets the same prohibit and FORWARD drops. A
//! filter's handle is `(sender octet << 8) | target octet`, so it is exact to
//! replace and to delete, and it reads back from `tc filter show`.
//!
//! ### Who installs it
//!
//! Neither side can do it from its own spec. `W` knows `P` only by identity, and `P`
//! does not know it is granted at all. Only the node knows both addresses: its
//! mangle table already maps each address to an identity (`yah-id-<addr>`) and
//! each grant to the identity it admits (`yah-gr-<addr>`). So once its mangle
//! rules are written, every deploy reads the node's grant state back and
//! reconciles the ARP path for the pairs that name its own address, as either
//! side ([`apply_grant_neighbours`]). The reads are `iptables-save -t mangle`,
//! `ip -4 neigh show proxy`, and `tc filter show` on each bridge that holds a
//! proxy entry or would get one. Whichever of `P` and `W` deploys second finds
//! the other and installs the pair. A redeploy at a new address installs its
//! new pairs. A deploy that takes over an address removes whatever pairs the
//! previous holder's grants left there.
//!
//! This was chosen over having bridge setup re-apply the grants that name its
//! bridge. Bridge setup cannot know those grants without the same read, and it
//! would take its writes on every deploy onto that bridge, involved or not.
//! The read happens after the mangle writes and under one process-wide lock, so
//! concurrent deploys of `P` and `W` converge: whichever reads second sees
//! the other's chains.
//!
//! Installing a pair also flushes the node's neighbour entries for both of its
//! addresses. A redeploy brings a new veth and so a new MAC, while the node's
//! entry still names the old one. Measured on the same kernel: a pair that
//! passed with `P` deployed first failed right after both were torn down and
//! `W` was redeployed first. The SYN was granted and forwarded to the dead MAC,
//! and nothing came back until the stale entry aged out.
//!
//! ### What it costs, and who pays
//!
//! Every workload gets an identity chain, the singleton tenant's included: a
//! tenant workload may grant a singleton one, and the peer's deploy cannot know
//! whether anyone will. The operator accepted exactly that on 2026-09-14
//! (R895-F4, `ask_user` F4187): seven mangle calls per deploy and one
//! PREROUTING jump per workload, with no route, prohibit or drop. This departs
//! from W206's "a single-tenant node pays nothing". The rejected alternatives were refusing grants to
//! singleton-tenant peers, and marking singleton workloads only once a tenant
//! bridge exists, which silently misses every workload already running when the
//! first tenant arrives. The grant chain is populated only when the spec
//! declares a cross-tenant peer.
//!
//! A workload that neither carries a grant nor is named by one writes exactly
//! those seven commands, and nothing else on the node changes: no tc, no
//! sysctl, no neighbour flush. F4187 did not price the check that establishes this,
//! which costs every deploy two reads (`iptables-save -t mangle`, `ip -4 neigh
//! show proxy`), plus one `tc filter show` per bridge that already holds grant
//! ARP state. The ARP path's writes happen only on a deploy that carries a
//! grant or is named by one: proxy entries, tc filters, a clsact qdisc and
//! `proxy_delay` on the pair's bridges, and neighbour flushes. Only those
//! deploys can fail for lack of `tc` or of a kernel module (sch_ingress for
//! clsact, cls_flower, act_skbedit). The error names all three, and all three
//! autoload on Debian 6.12. If the read fails on a deploy that carries no
//! grant, the failure is logged and the deploy proceeds. A workload on that
//! node that is named by a grant then stays unreachable to its peer until one
//! side redeploys.
//!
//! ## Limits
//!
//! - **Co-resident pairs only.** An identity mark does not leave the node, and
//!   cross-node egress is masqueraded to the node's mesh address. Nothing here is
//!   needed for a peer on another node either: R895-F3 admits NEW mesh ingress
//!   into a tenant bridge, so such a peer — another tenant's workload included,
//!   masqueraded as its node — reaches `W` with no grant at all. That is W343's
//!   cross-node limit, mesh-ACL territory, and not something a grant closes.
//! - **Spoofing inside the peer's bridge.** The identity rule is keyed on source
//!   address and in-interface. A workload on `P`'s own bridge — `P`'s tenant —
//!   that takes `P`'s address gets `P`'s grants. The mark itself cannot be
//!   forged: `skb->mark` is scrubbed crossing the veth.
//! - **16-bit identities.** Two identities that fold to one value, on one bridge
//!   of one node, share grants. Recorded rather than guarded.
//! - **A stop leaves both chains, and its pairs' ARP path, behind.** A `Stop`
//!   carries no address ([`super::teardown_by_workload`]). They name an address
//!   nobody holds, and the next deploy to claim it rewrites them. Until then a
//!   granted peer still gets an ARP answer for the stopped address, which
//!   admits nothing, and a later deploy that reads the stale chains may
//!   install a pair toward it.
//! - **A read that fails on a deploy with no grant of its own is not fatal.**
//!   See the cost section above.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use anyhow::{Context as _, Result, bail};
use workload_spec::{MeshPeer, TenantId, WorkloadSpec};

use super::{
    Cmd, ContainerNet, FWMARK_GRANT, FWMARK_IDENTITY_MASK, Ipv4Cidr, NetnsPlan, OnFailure,
    fnv1a64,
};

/// What container networking reads from a workload's spec: whose it is, who it
/// is on the mesh, and which other tenants' workloads it admits.
///
/// A projection rather than the whole [`WorkloadSpec`] so that the wiring is a
/// function of exactly these three facts, and a test can state them without
/// building a spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenancy {
    pub tenant: TenantId,
    /// `<tenant>/<namespace>/<identity>`, as `WorkloadSpec::fq_mesh_identity`
    /// renders it.
    pub fq_identity: String,
    /// `expose.mesh.allow_from`. Only its `CrossTenant` entries are read.
    pub allow_from: Vec<MeshPeer>,
}

impl Tenancy {
    pub fn of(spec: &WorkloadSpec) -> Self {
        Tenancy {
            tenant: spec.tenant.clone(),
            fq_identity: spec.fq_mesh_identity(),
            allow_from: spec.expose.mesh.allow_from.clone(),
        }
    }
}

/// One cross-tenant peer a workload admits, resolved to what the kernel can
/// match on this node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Grant {
    /// The bridge the peer's packets arrive on — its tenant's
    /// ([`ContainerNet::bridge_for`]).
    pub peer_bridge: String,
    /// The peer's [`identity_mark`].
    pub peer_mark: u32,
}

/// The mark a workload's packets carry, from its fully qualified mesh identity
/// `<tenant>/<namespace>/<identity>` (`WorkloadSpec::fq_mesh_identity`).
///
/// Folded into `1..=`[`FWMARK_IDENTITY_MASK`]: `0` is what an unmarked packet
/// carries, so no identity may hash to it. FNV because the two halves of a
/// grant are computed by two different deploys, possibly by two kamaji builds
/// either side of a roll.
pub fn identity_mark(fq_identity: &str) -> u32 {
    let folded = fnv1a64(fq_identity.as_bytes()) % u64::from(FWMARK_IDENTITY_MASK);
    // `folded < 0xffff`, so the cast is exact and the `+ 1` cannot overflow.
    folded as u32 + 1
}

/// The cross-tenant peers a workload admits, as [`Grant`]s on this node.
///
/// A peer whose tenant lands on the workload's own bridge is dropped: nothing
/// isolates the two, so there is nothing to exempt. Sorted and deduplicated,
/// so the command sequence is a function of the set, not of how the manifest
/// listed it.
pub fn grants_for(net: &ContainerNet, tenancy: &Tenancy) -> Vec<Grant> {
    let own_bridge = net.bridge_for(&tenancy.tenant);
    let mut grants: Vec<Grant> = tenancy
        .allow_from
        .iter()
        .filter_map(|peer| match peer {
            MeshPeer::CrossTenant {
                tenant,
                namespace,
                name,
            } => Some(Grant {
                peer_bridge: net.bridge_for(tenant),
                // The same string `fq_mesh_identity` renders for the peer's own
                // spec; `a_grant_names_the_mark_its_peer_stamps` pins it.
                peer_mark: identity_mark(&format!("{}/{}/{}", tenant.0, namespace.0, name.0)),
            }),
            MeshPeer::Tier(_) => None,
        })
        .filter(|grant| grant.peer_bridge != own_bridge)
        .collect();
    grants.sort();
    grants.dedup();
    grants
}

fn identity_chain(addr: Ipv4Addr) -> String {
    // `yah-id-255.255.255.255` is 22 characters, inside iptables' 28.
    format!("yah-id-{addr}")
}

fn grant_chain(addr: Ipv4Addr) -> String {
    format!("yah-gr-{addr}")
}

fn mangle(args: &[&str], on_failure: OnFailure) -> Cmd {
    let mut all = vec!["-t", "mangle"];
    all.extend_from_slice(args);
    Cmd::iptables(&all, on_failure)
}

/// The mangle rules for one workload: its identity chain always, its grant
/// chain flushed always and populated from [`NetnsPlan::grants`].
///
/// Runs after the namespace is wired, as the third step beside
/// [`ContainerNet::bridge_commands`] and [`ContainerNet::setup_commands`], and
/// before [`apply_grant_neighbours`], which reads what this wrote. Each chain
/// is flushed before it is refilled, and each jump deleted before it is
/// re-added. The gap either leaves is fail-closed and confined to the address
/// being deployed, whose previous generation is already gone.
pub fn grant_commands(plan: &NetnsPlan) -> Vec<Cmd> {
    use OnFailure::{Fatal, Ignore};

    let addr = plan.container_ip.to_string();
    let subnet = plan.subnet.to_string();
    let bridge = plan.bridge.as_str();
    let identity = identity_chain(plan.container_ip);
    let granted = grant_chain(plan.container_ip);
    let identity_xmark = format!("{:#x}/{FWMARK_IDENTITY_MASK:#x}", plan.identity_mark);
    let grant_bit = grant_bit();

    let mut cmds = vec![
        // `-N` on an existing chain is an error, and that is the steady state.
        mangle(&["-N", &identity], Ignore),
        mangle(&["-F", &identity], Fatal),
        mangle(
            &[
                "-A", &identity, "-i", bridge, "-s", &addr, "-d", &subnet, "-j", "MARK",
                "--set-xmark", &identity_xmark,
            ],
            Fatal,
        ),
        mangle(&["-D", "PREROUTING", "-s", &addr, "-j", &identity], Ignore),
        mangle(&["-I", "PREROUTING", "-s", &addr, "-j", &identity], Fatal),
        // Flushed even with no grants: the address's previous owner may have
        // had some. Its leftover jumps then land in an empty chain.
        mangle(&["-N", &granted], Ignore),
        mangle(&["-F", &granted], Fatal),
    ];
    if plan.grants.is_empty() {
        return cmds;
    }
    for grant in &plan.grants {
        let peer = format!("{:#x}/{FWMARK_IDENTITY_MASK:#x}", grant.peer_mark);
        for target in ["MARK", "CONNMARK"] {
            cmds.push(mangle(
                &[
                    "-A", &granted, "-i", &grant.peer_bridge, "-d", &addr, "-m", "mark",
                    "--mark", &peer, "-j", target, "--set-xmark", &grant_bit,
                ],
                Fatal,
            ));
        }
    }
    // One reply rule covers every grant: the connmark says a grant admitted
    // the connection, and `--ctdir REPLY` says this packet answers it rather
    // than opening something of the workload's own.
    cmds.push(mangle(
        &[
            "-A", &granted, "-i", bridge, "-s", &addr, "-m", "conntrack", "--ctdir", "REPLY",
            "-m", "connmark", "--mark", &grant_bit, "-j", "MARK", "--set-xmark", &grant_bit,
        ],
        Fatal,
    ));
    for selector in ["-d", "-s"] {
        cmds.push(mangle(&["-D", "PREROUTING", selector, &addr, "-j", &granted], Ignore));
        cmds.push(mangle(&["-A", "PREROUTING", selector, &addr, "-j", &granted], Fatal));
    }
    cmds
}

fn grant_bit() -> String {
    format!("{FWMARK_GRANT:#x}/{FWMARK_GRANT:#x}")
}

/// The tc priority of every grant ARP filter on a bridge's clsact ingress.
const ARP_FILTER_PREF: &str = "895";

/// Named in the error of every failed ARP-path step, so a node missing one of
/// them is diagnosable from the refused deploy alone.
const ARP_PATH_NEEDS: &str = "the cross-tenant grant ARP path needs `tc` (iproute2) and the kernel \
     modules sch_ingress (clsact), cls_flower and act_skbedit, loaded or autoloadable";

/// Wire the ARP path for every granted pair that names this workload's address,
/// and remove whatever a previous holder of the address left
/// (see "Reaching a peer on another bridge" above).
///
/// The fourth step, after [`grant_commands`] has been applied: it reads the
/// node's mangle table back to find the pairs. A workload that neither carries
/// a grant nor is named by one runs no command here. A deploy that carries
/// a grant fails if the node's grant state cannot be read, and a deploy that
/// carries or is named by one fails if a write fails. Every such error names
/// what the path needs.
///
/// Read-then-write must not interleave with another deploy's or with a GC pass,
/// so the caller holds the node-state lock across both — see
/// [`lock_node_state`](super::lock_node_state). The guard is taken by reference
/// rather than acquired here because a deploy has to hold it from the first
/// `ip link add` onwards, not just for this step.
pub async fn apply_grant_neighbours(plan: &NetnsPlan, _lock: &super::NodeStateGuard) -> Result<()> {
    let addr = plan.container_ip;
    let carries = !plan.grants.is_empty();
    let state = async {
        let mangle = read("iptables-save", &["-t", "mangle"]).await?;
        let proxies = read("ip", &["-4", "neigh", "show", "proxy"]).await?;
        anyhow::Ok(NodeGrants::read(plan.subnet, &mangle, &proxies))
    };
    let mut node = match state.await {
        Ok(node) => node,
        Err(e) if !carries => {
            tracing::warn!(
                address = %addr,
                error = %format!("{e:#}"),
                "container-net: cannot read the node's grant state; this workload carries no grant, so it is wired without the ARP path"
            );
            return Ok(());
        }
        Err(e) => return Err(e.context("reading the node's cross-tenant grant state")),
    };
    let named = !node.pairs_naming(addr).is_empty();
    for bridge in node.bridges_to_read(addr) {
        match read("tc", &["filter", "show", "dev", &bridge, "ingress"]).await {
            Ok(shown) => node.read_filters(&bridge, &shown),
            Err(e) if carries || named => return Err(e.context(ARP_PATH_NEEDS)),
            Err(e) => tracing::warn!(
                bridge = %bridge,
                error = %format!("{e:#}"),
                "container-net: cannot list grant ARP filters; stale ones naming this address stay"
            ),
        }
    }
    super::apply(&node.neighbour_commands(plan))
        .await
        .context(ARP_PATH_NEEDS)
}

/// What one [`gc_grant_state`] pass removes from the grant layer.
pub(super) struct GrantGc {
    pub cmds: Vec<Cmd>,
    /// Addresses the grant layer still described whose workload is gone.
    pub departed: BTreeSet<Ipv4Addr>,
}

/// Read the node's grant state and plan the removal of everything in it that
/// names an address no longer held (R895-T5).
///
/// The counterpart of [`apply_grant_neighbours`], which reconciles the ARP path
/// around ONE address a deploy is wiring. This asks the same question of the
/// whole node at once, which is the only form a `Stop` can be answered in: a
/// granted pair writes a proxy entry and a `tc` filter on *each* side's bridge,
/// so the state a stopped workload leaves behind mostly sits on the surviving
/// peer's bridge, where nothing keyed on the dead address would ever look.
///
/// Takes no lock of its own — [`reconcile`](super::reconcile) holds the
/// [`NodeStateGuard`](super::NodeStateGuard) across the read and the write.
pub(super) async fn gc_grant_state(
    subnet: Ipv4Cidr,
    live: &BTreeSet<Ipv4Addr>,
    bridges: &BTreeSet<String>,
) -> Result<GrantGc> {
    let context = "reading the node's cross-tenant grant state";
    let mangle = read("iptables-save", &["-t", "mangle"]).await.context(context)?;
    let proxies = read("ip", &["-4", "neigh", "show", "proxy"]).await.context(context)?;
    let mut node = NodeGrants::read(subnet, &mangle, &proxies);
    // Per bridge and tolerated, unlike the two reads above: a bridge with no
    // clsact qdisc has no filters to list, and a GC that refused to run because
    // one bridge could not be read would leave the rest of the node dirty.
    for bridge in bridges {
        match read("tc", &["filter", "show", "dev", bridge, "ingress"]).await {
            Ok(shown) => node.read_filters(bridge, &shown),
            Err(e) => tracing::debug!(
                bridge = %bridge,
                error = %format!("{e:#}"),
                "container-net: cannot list grant ARP filters; any stale ones on this bridge stay"
            ),
        }
    }
    Ok(node.gc_commands(live))
}

/// A read-only command's stdout. A failure to spawn or a non-zero exit is an
/// error naming the command.
pub(super) async fn read(bin: &str, args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new(bin)
        .args(args)
        .output()
        .await
        .with_context(|| format!("spawning `{bin}`"))?;
    if !out.status.success() {
        bail!(
            "`{bin} {}` failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// One granted pair on this node: `peer` on `peer_bridge` is admitted by
/// `granting` on `granting_bridge`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Pair {
    peer: Ipv4Addr,
    peer_bridge: String,
    granting: Ipv4Addr,
    granting_bridge: String,
}

impl Pair {
    fn names(&self, addr: Ipv4Addr) -> bool {
        self.peer == addr || self.granting == addr
    }

    /// `(bridge, sender, target)`: each side's request for the other, on the
    /// bridge it arrives on.
    fn filters(&self) -> [(String, Ipv4Addr, Ipv4Addr); 2] {
        [
            (self.peer_bridge.clone(), self.peer, self.granting),
            (self.granting_bridge.clone(), self.granting, self.peer),
        ]
    }

    /// `(target, bridge)`: the proxy entries that let each side's bridge answer
    /// for the other.
    fn proxies(&self) -> [(Ipv4Addr, String); 2] {
        [
            (self.granting, self.peer_bridge.clone()),
            (self.peer, self.granting_bridge.clone()),
        ]
    }
}

/// The node's grant state as read back from the kernel, restricted to the
/// node's `/24`.
#[derive(Debug, Default)]
struct NodeGrants {
    subnet: Option<Ipv4Cidr>,
    /// `yah-id-<addr>`: each address's bridge and identity mark.
    residents: BTreeMap<Ipv4Addr, (String, u32)>,
    /// `yah-gr-<addr>`: the `(peer bridge, peer mark)` each address admits.
    grants: BTreeMap<Ipv4Addr, BTreeSet<(String, u32)>>,
    /// Proxy neighbour entries, `(target, bridge)`.
    proxies: BTreeSet<(Ipv4Addr, String)>,
    /// Grant ARP filters, `(bridge, sender, target)`, from the bridges read.
    filters: BTreeSet<(String, Ipv4Addr, Ipv4Addr)>,
}

/// `0x1a2b/0xffff` as an identity mark, or `None` for any other value/mask.
fn identity_of(spec: &str) -> Option<u32> {
    let (value, mask) = spec.split_once('/')?;
    let hex = |s: &str| u32::from_str_radix(s.strip_prefix("0x")?, 16).ok();
    let (value, mask) = (hex(value)?, hex(mask)?);
    (mask == FWMARK_IDENTITY_MASK && value != 0).then_some(value)
}

impl NodeGrants {
    /// Parse `iptables-save -t mangle` and `ip -4 neigh show proxy`. Token
    /// based, so it reads this module's own command order as well as the order
    /// `iptables-save` normalises rules into.
    fn read(subnet: Ipv4Cidr, mangle: &str, proxies: &str) -> Self {
        let mut node = NodeGrants {
            subnet: Some(subnet),
            ..NodeGrants::default()
        };
        for line in mangle.lines() {
            let Some(rule) = line.strip_prefix("-A ") else {
                continue;
            };
            let words: Vec<&str> = rule.split_whitespace().collect();
            let Some((chain, words)) = words.split_first() else {
                continue;
            };
            let (identity, addr) = match (chain.strip_prefix("yah-id-"), chain.strip_prefix("yah-gr-")) {
                (Some(addr), _) => (true, addr),
                (_, Some(addr)) => (false, addr),
                _ => continue,
            };
            let Some(addr) = addr.parse().ok().filter(|a| subnet.contains(*a)) else {
                continue;
            };
            let (mut iface, mut module, mut matched_mark, mut target, mut set_mark) =
                (None, "", None, "", None);
            for pair in words.windows(2) {
                match pair[0] {
                    "-i" => iface = Some(pair[1]),
                    "-m" => module = pair[1],
                    "--mark" if module == "mark" => matched_mark = identity_of(pair[1]),
                    "-j" => target = pair[1],
                    "--set-xmark" => set_mark = identity_of(pair[1]),
                    _ => {}
                }
            }
            let Some(iface) = iface else { continue };
            match (identity, target, matched_mark, set_mark) {
                (true, "MARK", None, Some(mark)) => {
                    node.residents.insert(addr, (iface.to_string(), mark));
                }
                (false, "MARK", Some(mark), _) => {
                    node.grants.entry(addr).or_default().insert((iface.to_string(), mark));
                }
                _ => {}
            }
        }
        for line in proxies.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            let dev = words.windows(2).find(|w| w[0] == "dev").map(|w| w[1]);
            let target = words.first().and_then(|a| a.parse::<Ipv4Addr>().ok());
            if let (Some(target), Some(dev)) = (target, dev) {
                if subnet.contains(target) {
                    node.proxies.insert((target, dev.to_string()));
                }
            }
        }
        node
    }

    /// Add one bridge's grant ARP filters from `tc filter show dev <bridge>
    /// ingress`, decoding sender and target from the handle.
    fn read_filters(&mut self, bridge: &str, shown: &str) {
        let Some(subnet) = self.subnet else { return };
        for line in shown.lines().filter(|l| l.starts_with("filter ")) {
            let words: Vec<&str> = line.split_whitespace().collect();
            let field = |name: &str| words.windows(2).find(|w| w[0] == name).map(|w| w[1]);
            if field("pref") != Some(ARP_FILTER_PREF) {
                continue;
            }
            let Some(handle) = field("handle")
                .and_then(|h| h.strip_prefix("0x"))
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .filter(|h| *h <= 0xffff)
            else {
                continue;
            };
            let host = |octet: u32| subnet.nth(octet & 0xff);
            self.filters
                .insert((bridge.to_string(), host(handle >> 8), host(handle)));
        }
    }

    /// Every granted pair whose both sides hold an identity chain.
    fn pairs(&self) -> BTreeSet<Pair> {
        let mut pairs = BTreeSet::new();
        for (granting, admitted) in &self.grants {
            let Some((granting_bridge, _)) = self.residents.get(granting) else {
                continue;
            };
            for (peer, (peer_bridge, peer_mark)) in &self.residents {
                if peer != granting
                    && peer_bridge != granting_bridge
                    && admitted.contains(&(peer_bridge.clone(), *peer_mark))
                {
                    pairs.insert(Pair {
                        peer: *peer,
                        peer_bridge: peer_bridge.clone(),
                        granting: *granting,
                        granting_bridge: granting_bridge.clone(),
                    });
                }
            }
        }
        pairs
    }

    fn pairs_naming(&self, addr: Ipv4Addr) -> BTreeSet<Pair> {
        self.pairs().into_iter().filter(|p| p.names(addr)).collect()
    }

    /// The bridges whose filters [`Self::neighbour_commands`] needs to see:
    /// those this address's pairs use, and those holding any proxy entry. A
    /// filter is only ever present beside a proxy entry on its bridge,
    /// so the latter covers every filter a previous holder left.
    fn bridges_to_read(&self, addr: Ipv4Addr) -> BTreeSet<String> {
        let mut bridges: BTreeSet<String> =
            self.proxies.iter().map(|(_, dev)| dev.clone()).collect();
        for pair in self.pairs_naming(addr) {
            bridges.extend([pair.peer_bridge, pair.granting_bridge]);
        }
        bridges
    }

    /// Reconcile the ARP path for the pairs naming `plan`'s address: delete
    /// filters and proxy entries naming it that no pair wants, then assert its
    /// pairs'. Empty when nothing names the address.
    fn neighbour_commands(&self, plan: &NetnsPlan) -> Vec<Cmd> {
        use OnFailure::{Fatal, Ignore};

        let addr = plan.container_ip;
        let pairs = self.pairs();
        let mine: Vec<&Pair> = pairs.iter().filter(|p| p.names(addr)).collect();
        let wanted_proxies: BTreeSet<_> = pairs.iter().flat_map(Pair::proxies).collect();
        let wanted_filters: BTreeSet<_> = mine.iter().flat_map(|p| p.filters()).collect();
        let mut cmds = Vec::new();

        let stale: Vec<_> = self
            .filters
            .iter()
            .filter(|(_, from, to)| *from == addr || *to == addr)
            .filter(|filter| !wanted_filters.contains(*filter))
            .collect();
        for (bridge, from, to) in &stale {
            cmds.push(Cmd::with("tc", filter_args("del", bridge, *from, *to), Ignore));
        }
        for (to, bridge) in &self.proxies {
            let left_by_stale = stale.iter().any(|(b, _, t)| b == bridge && t == to);
            if !wanted_proxies.contains(&(*to, bridge.clone())) && (*to == addr || left_by_stale) {
                let target = to.to_string();
                cmds.push(Cmd::best_effort("ip", &["neigh", "del", "proxy", &target, "dev", bridge]));
            }
        }
        if mine.is_empty() {
            return cmds;
        }

        let bridges: BTreeSet<&str> = wanted_filters.iter().map(|(b, _, _)| b.as_str()).collect();
        for bridge in bridges {
            let delay = format!("net.ipv4.neigh.{bridge}.proxy_delay=0");
            cmds.push(Cmd::new("sysctl", &["-w", &delay]));
            cmds.push(Cmd::new("tc", &["qdisc", "replace", "dev", bridge, "clsact"]));
        }
        for pair in &mine {
            for (to, bridge) in pair.proxies() {
                let target = to.to_string();
                cmds.push(Cmd::new("ip", &["neigh", "replace", "proxy", &target, "dev", &bridge]));
            }
        }
        for (bridge, from, to) in &wanted_filters {
            cmds.push(Cmd::with("tc", filter_args("replace", bridge, *from, *to), Fatal));
        }
        let flushed: BTreeSet<Ipv4Addr> = mine.iter().flat_map(|p| [p.peer, p.granting]).collect();
        for host in flushed {
            cmds.push(Cmd::best_effort("ip", &["neigh", "flush", "to", &host.to_string()]));
        }
        cmds
    }

    /// Remove every piece of grant state naming an address not in `live`
    /// (R895-T5).
    ///
    /// The mirror image of [`Self::neighbour_commands`]: that one knows one
    /// address and asserts what it should have, this one knows every address
    /// that should have nothing. A pair survives only if BOTH its workloads are
    /// still running — a half-live pair has nothing left to admit, and its
    /// remaining side's filter would otherwise match an address the next
    /// deploy hands to a different tenant.
    ///
    /// Everything here is `Ignore`/best-effort. `-X` on a chain still carrying
    /// a jump fails, which is why the jumps go first, and both are tolerated
    /// anyway: this runs against whatever state a crash or a roll left.
    fn gc_commands(&self, live: &BTreeSet<Ipv4Addr>) -> GrantGc {
        use OnFailure::Ignore;

        let departed: BTreeSet<Ipv4Addr> = self
            .residents
            .keys()
            .chain(self.grants.keys())
            .copied()
            .filter(|addr| !live.contains(addr))
            .collect();
        let surviving: BTreeSet<Pair> = self
            .pairs()
            .into_iter()
            .filter(|pair| live.contains(&pair.peer) && live.contains(&pair.granting))
            .collect();
        let wanted_proxies: BTreeSet<_> = surviving.iter().flat_map(Pair::proxies).collect();
        let wanted_filters: BTreeSet<_> = surviving.iter().flat_map(Pair::filters).collect();
        let mut cmds = Vec::new();

        // Both sets are already kamaji's own by construction — `read` keeps
        // only proxy entries inside the node's `/24`, and `read_filters` only
        // filters at this module's own `tc` preference.
        for filter in self.filters.difference(&wanted_filters) {
            let (bridge, from, to) = filter;
            cmds.push(Cmd::with("tc", filter_args("del", bridge, *from, *to), Ignore));
        }
        for proxy in self.proxies.difference(&wanted_proxies) {
            let (to, bridge) = proxy;
            let target = to.to_string();
            cmds.push(Cmd::best_effort(
                "ip",
                &["neigh", "del", "proxy", &target, "dev", bridge],
            ));
        }
        for addr in &departed {
            let identity = identity_chain(*addr);
            let granted = grant_chain(*addr);
            let target = addr.to_string();
            cmds.push(mangle(
                &["-D", "PREROUTING", "-s", &target, "-j", &identity],
                Ignore,
            ));
            for selector in ["-d", "-s"] {
                cmds.push(mangle(
                    &["-D", "PREROUTING", selector, &target, "-j", &granted],
                    Ignore,
                ));
            }
            for chain in [identity.as_str(), granted.as_str()] {
                cmds.push(mangle(&["-F", chain], Ignore));
                cmds.push(mangle(&["-X", chain], Ignore));
            }
            cmds.push(Cmd::best_effort("ip", &["neigh", "flush", "to", &target]));
        }
        GrantGc { cmds, departed }
    }
}

/// `tc filter <op>` for the grant ARP filter `from` asking for `to` on
/// `bridge`. `del` names only the filter; `replace` carries its match.
fn filter_args(op: &str, bridge: &str, from: Ipv4Addr, to: Ipv4Addr) -> Vec<String> {
    let handle = format!(
        "{:#x}",
        (u32::from(from.octets()[3]) << 8) | u32::from(to.octets()[3])
    );
    let mut args = super::strings(&[
        "filter", op, "dev", bridge, "ingress", "protocol", "arp", "pref", ARP_FILTER_PREF,
        "handle", &handle, "flower",
    ]);
    if op == "replace" {
        let (from, to) = (from.to_string(), to.to_string());
        args.extend(super::strings(&[
            "arp_op", "request", "arp_sip", &from, "arp_tip", &to, "action", "skbedit", "mark",
            &grant_bit(),
        ]));
    }
    args
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use workload_spec::{
        ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, NamespaceId, ResourceLimits,
        RestartPolicy, StopPolicy, TenantId, TierTag,
    };

    use super::super::Ipv4Cidr;
    use super::*;

    const W: &str = "10.128.3.7";
    const P: &str = "10.128.3.9";
    const Q: &str = "10.128.3.10";
    const S: &str = "10.128.3.11";

    fn spec(tenant: &str, namespace: &str, ident: &str, allow_from: Vec<MeshPeer>) -> WorkloadSpec {
        WorkloadSpec {
            name: ident.to_string(),
            image: ImageRef {
                registry: "docker.io".to_string(),
                repository: "library/alpine".to_string(),
                tag: "latest".to_string(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("tenant".to_string()),
            tenant: TenantId(tenant.to_string()),
            namespace: NamespaceId(namespace.to_string()),
            replicas: 1,
            command: None,
            entrypoint: None,
            workdir: None,
            user: None,
            env: vec![],
            secrets: vec![],
            volumes: vec![],
            resources: ResourceLimits {
                memory_mb: 64,
                cpu_millis: 128,
                memory_request_mb: None,
                cpu_limit_millis: None,
                pids_max: None,
                scratch_floor_mb: None,
            },
            depends_on: vec![],
            requires: vec![],
            healthcheck: None,
            restart_policy: RestartPolicy::Never,
            archetype: None,
            stop_policy: StopPolicy {
                signal: 15,
                grace_period: Millis::from_secs(5),
            },
            expose: ExposeSpec {
                mesh: MeshExpose {
                    identity: MeshIdent(ident.to_string()),
                    ports: MeshExpose::anonymous_ports([]),
                    allow_from,
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            durability: None,
            annotations: Default::default(),
            files: Vec::new(),
        }
    }

    fn cross(tenant: &str, namespace: &str, name: &str) -> MeshPeer {
        MeshPeer::CrossTenant {
            tenant: TenantId(tenant.to_string()),
            namespace: NamespaceId(namespace.to_string()),
            name: MeshIdent(name.to_string()),
        }
    }

    /// `acme/default/api`, granting `globex/prod/billing`.
    fn api() -> WorkloadSpec {
        spec("acme", "default", "api", vec![cross("globex", "prod", "billing")])
    }

    fn billing() -> WorkloadSpec {
        spec("globex", "prod", "billing", vec![])
    }

    fn ledger() -> WorkloadSpec {
        spec("globex", "prod", "ledger", vec![])
    }

    fn site() -> WorkloadSpec {
        spec(
            &TenantId::singleton().0,
            &NamespaceId::singleton().0,
            "site",
            vec![],
        )
    }

    fn bridge(tenant: &str) -> String {
        ContainerNet::defaults().bridge_for(&TenantId(tenant.to_string()))
    }

    fn plan(spec: &WorkloadSpec, addr: &str) -> NetnsPlan {
        ContainerNet::defaults()
            .plan(&spec.name, addr.parse().unwrap(), &Tenancy::of(spec))
            .expect("address is inside the default range")
    }

    fn grants_for(net: &ContainerNet, spec: &WorkloadSpec) -> Vec<Grant> {
        super::grants_for(net, &Tenancy::of(spec))
    }

    /// The mangle table as `iptables` would hold it: chain name to rules, each
    /// rule the argument list after the chain name. Only the verbs and matches
    /// this module emits are modelled; anything else panics rather than
    /// silently matching.
    struct Mangle {
        chains: BTreeMap<String, Vec<Vec<String>>>,
    }

    #[derive(Clone, Debug)]
    struct Packet {
        iface: String,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        reply: bool,
        mark: u32,
        connmark: u32,
    }

    fn packet(iface: &str, src: &str, dst: &str) -> Packet {
        Packet {
            iface: iface.to_string(),
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            reply: false,
            mark: 0,
            connmark: 0,
        }
    }

    fn masked(spec: &str) -> (u32, u32) {
        let (value, mask) = spec.split_once('/').expect("value/mask");
        let hex = |s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
        (hex(value), hex(mask))
    }

    fn addr_matches(spec: &str, addr: Ipv4Addr) -> bool {
        if spec.contains('/') {
            Ipv4Cidr::parse(spec).expect("cidr").contains(addr)
        } else {
            spec.parse::<Ipv4Addr>().unwrap() == addr
        }
    }

    impl Mangle {
        fn new() -> Self {
            let mut chains = BTreeMap::new();
            chains.insert("PREROUTING".to_string(), vec![]);
            Mangle { chains }
        }

        fn deploy(&mut self, spec: &WorkloadSpec, addr: &str) {
            self.apply(&grant_commands(&plan(spec, addr)));
        }

        /// The table as `-A <chain> <rule>` lines: what [`NodeGrants::read`]
        /// parses, in this module's argument order rather than
        /// `iptables-save`'s (the literal real-kernel shape is pinned in
        /// `the_node_state_parses_as_the_kernel_prints_it`).
        fn save(&self) -> String {
            self.chains
                .iter()
                .flat_map(|(chain, rules)| rules.iter().map(move |r| format!("-A {chain} {}\n", r.join(" "))))
                .collect()
        }

        fn apply(&mut self, cmds: &[Cmd]) {
            for cmd in cmds {
                assert_eq!(cmd.bin, "iptables", "{cmd}");
                assert_eq!(cmd.args[..3], ["-w", "-t", "mangle"], "{cmd}");
                let op = cmd.args[3].as_str();
                let chain = cmd.args[4].clone();
                let rule = cmd.args[5..].to_vec();
                let jump_ok = |chains: &BTreeMap<String, _>| {
                    let target = rule.iter().skip_while(|a| *a != "-j").nth(1).unwrap();
                    ["MARK", "CONNMARK"].contains(&target.as_str()) || chains.contains_key(target)
                };
                let ok = match op {
                    "-N" => {
                        let fresh = !self.chains.contains_key(&chain);
                        self.chains.entry(chain).or_default();
                        fresh
                    }
                    "-F" => self.chains.get_mut(&chain).map(Vec::clear).is_some(),
                    "-A" | "-I" => {
                        let ok = self.chains.contains_key(&chain) && jump_ok(&self.chains);
                        if ok {
                            let rules = self.chains.get_mut(&chain).unwrap();
                            if op == "-A" {
                                rules.push(rule);
                            } else {
                                rules.insert(0, rule);
                            }
                        }
                        ok
                    }
                    "-D" => match self.chains.get_mut(&chain) {
                        Some(rules) => match rules.iter().position(|r| *r == rule) {
                            Some(i) => {
                                rules.remove(i);
                                true
                            }
                            None => false,
                        },
                        None => false,
                    },
                    // The kernel refuses `-X` on a chain that is non-empty or
                    // still jumped to, which is why the GC flushes and unhooks
                    // first; modelled so a GC that got that order wrong fails
                    // here rather than looking clean.
                    "-X" => {
                        let empty = self.chains.get(&chain).is_some_and(Vec::is_empty);
                        let referenced = self.chains.values().flatten().any(|r| {
                            r.iter().skip_while(|a| *a != "-j").nth(1) == Some(&chain)
                        });
                        empty && !referenced && self.chains.remove(&chain).is_some()
                    }
                    other => panic!("unmodelled verb {other} in {cmd}"),
                };
                if !ok {
                    assert_eq!(
                        cmd.on_failure,
                        OnFailure::Ignore,
                        "a fatal command would fail here: {cmd}"
                    );
                }
            }
        }

        fn run(&self, mut p: Packet) -> Packet {
            self.traverse("PREROUTING", &mut p);
            p
        }

        fn traverse(&self, chain: &str, p: &mut Packet) {
            for rule in &self.chains[chain] {
                let mut args = rule.iter().map(String::as_str);
                let mut module = "";
                let mut matched = true;
                let mut target = None;
                while let Some(flag) = args.next() {
                    match flag {
                        "-i" => matched &= args.next().unwrap() == p.iface,
                        "-s" => matched &= addr_matches(args.next().unwrap(), p.src),
                        "-d" => matched &= addr_matches(args.next().unwrap(), p.dst),
                        "-m" => module = args.next().unwrap(),
                        "--mark" => {
                            let (value, mask) = masked(args.next().unwrap());
                            let held = match module {
                                "mark" => p.mark,
                                "connmark" => p.connmark,
                                other => panic!("--mark under -m {other}"),
                            };
                            matched &= held & mask == value;
                        }
                        "--ctdir" => {
                            assert_eq!(module, "conntrack");
                            matched &= (args.next().unwrap() == "REPLY") == p.reply;
                        }
                        "-j" => {
                            target = Some((args.next().unwrap(), args.next()));
                            break;
                        }
                        other => panic!("unmodelled match {other} in {rule:?}"),
                    }
                }
                if !matched {
                    continue;
                }
                match target.expect("every rule has a target") {
                    (jump @ ("MARK" | "CONNMARK"), Some("--set-xmark")) => {
                        let (value, mask) = masked(args.next().unwrap());
                        let slot = if jump == "MARK" { &mut p.mark } else { &mut p.connmark };
                        *slot = (*slot & !mask) ^ value;
                    }
                    (chain, None) => self.traverse(chain, p),
                    other => panic!("unmodelled target {other:?}"),
                }
            }
        }
    }

    fn granted(p: &Packet) -> bool {
        p.mark & FWMARK_GRANT != 0
    }

    #[test]
    fn identity_marks_are_never_zero_and_never_leave_their_bits() {
        for i in 0..20_000 {
            let mark = identity_mark(&format!("tenant-{i}/ns/workload-{}", i * 7));
            assert_ne!(mark, 0);
            assert_eq!(mark & !FWMARK_IDENTITY_MASK, 0, "mark {mark:#x}");
        }
        assert_eq!(identity_mark(""), identity_mark(""), "stable");
    }

    #[test]
    fn a_grant_names_the_mark_its_peer_stamps() {
        let net = ContainerNet::defaults();
        assert_eq!(
            grants_for(&net, &api()),
            vec![Grant {
                peer_bridge: net.bridge_for(&billing().tenant),
                peer_mark: identity_mark(&billing().fq_mesh_identity()),
            }]
        );
        assert_eq!(plan(&billing(), P).identity_mark, identity_mark(&billing().fq_mesh_identity()));
    }

    #[test]
    fn peers_that_share_the_workloads_bridge_grant_nothing() {
        let net = ContainerNet::defaults();
        let own_tenant = spec(
            "acme",
            "default",
            "api",
            vec![
                cross("acme", "other-ns", "worker"),
                MeshPeer::Tier(TierTag("private".to_string())),
            ],
        );
        assert!(grants_for(&net, &own_tenant).is_empty());

        let repeated = spec(
            "acme",
            "default",
            "api",
            vec![cross("globex", "prod", "billing"), cross("globex", "prod", "billing")],
        );
        assert_eq!(grants_for(&net, &repeated).len(), 1);
    }

    #[test]
    fn a_workload_without_grants_writes_only_its_identity_and_an_empty_grant_chain() {
        let cmds = grant_commands(&plan(&site(), S));
        let rendered: Vec<String> = cmds.iter().map(ToString::to_string).collect();
        let mark = identity_mark(&site().fq_mesh_identity());
        let solo = bridge(&TenantId::singleton().0);
        assert_eq!(
            rendered,
            vec![
                format!("iptables -w -t mangle -N yah-id-{S}"),
                format!("iptables -w -t mangle -F yah-id-{S}"),
                format!(
                    "iptables -w -t mangle -A yah-id-{S} -i {solo} -s {S} -d 10.128.3.0/24 -j MARK --set-xmark {mark:#x}/0xffff"
                ),
                format!("iptables -w -t mangle -D PREROUTING -s {S} -j yah-id-{S}"),
                format!("iptables -w -t mangle -I PREROUTING -s {S} -j yah-id-{S}"),
                format!("iptables -w -t mangle -N yah-gr-{S}"),
                format!("iptables -w -t mangle -F yah-gr-{S}"),
            ],
            "exactly the seven mangle calls ask_user F4187 approved, and nothing else"
        );
    }

    /// A node as far as grants go: the mangle model, the proxy neighbour table
    /// and the grant ARP filters. Driven by the production commands and read
    /// back through the production parsers, from text shaped as the kernel's
    /// tools print it.
    struct Node {
        mangle: Mangle,
        proxies: BTreeSet<(Ipv4Addr, String)>,
        filters: BTreeSet<(String, Ipv4Addr, Ipv4Addr)>,
    }

    impl Node {
        fn new() -> Self {
            Node { mangle: Mangle::new(), proxies: BTreeSet::new(), filters: BTreeSet::new() }
        }

        /// One deploy: grant_commands, then apply_grant_neighbours' read and
        /// plan. Returns the neighbour commands it ran.
        fn deploy(&mut self, spec: &WorkloadSpec, addr: &str) -> Vec<Cmd> {
            let plan = plan(spec, addr);
            self.mangle.apply(&grant_commands(&plan));
            let proxies: String = self.proxies.iter().map(|(a, dev)| format!("{a} dev {dev} proxy \n")).collect();
            let mut node = NodeGrants::read(plan.subnet, &self.mangle.save(), &proxies);
            for bridge in node.bridges_to_read(plan.container_ip) {
                node.read_filters(&bridge, &self.filter_show(&bridge));
            }
            let cmds = node.neighbour_commands(&plan);
            self.apply(&cmds);
            cmds
        }

        /// One GC pass (R895-T5): [`gc_grant_state`]'s reads answered from this
        /// model, the plan it produces applied back to it.
        fn collect(&mut self, live: &[&str]) -> Vec<Cmd> {
            let live: BTreeSet<Ipv4Addr> = live.iter().map(|a| a.parse().unwrap()).collect();
            let subnet = Ipv4Cidr::parse("10.128.3.0/24").expect("cidr");
            let proxies: String = self.proxies.iter().map(|(a, dev)| format!("{a} dev {dev} proxy \n")).collect();
            let mut node = NodeGrants::read(subnet, &self.mangle.save(), &proxies);
            // reconcile passes every bridge the node has; here that is every
            // bridge this model has ever put state on.
            let bridges: BTreeSet<String> = self
                .filters
                .iter()
                .map(|(bridge, _, _)| bridge.clone())
                .chain(self.proxies.iter().map(|(_, bridge)| bridge.clone()))
                .collect();
            for bridge in &bridges {
                node.read_filters(bridge, &self.filter_show(bridge));
            }
            let gc = node.gc_commands(&live);
            for cmd in &gc.cmds {
                if cmd.bin == "iptables" {
                    self.mangle.apply(std::slice::from_ref(cmd));
                } else {
                    self.apply(std::slice::from_ref(cmd));
                }
            }
            gc.cmds
        }

        fn filter_show(&self, bridge: &str) -> String {
            let mut shown = String::new();
            for (b, from, to) in &self.filters {
                if b == bridge {
                    let handle = (u32::from(from.octets()[3]) << 8) | u32::from(to.octets()[3]);
                    shown += &format!(
                        "filter protocol arp pref 895 flower chain 0 \nfilter protocol arp pref 895 flower chain 0 handle {handle:#x} \n  eth_type arp\n  arp_sip {from}\n  arp_tip {to}\n"
                    );
                }
            }
            shown
        }

        fn apply(&mut self, cmds: &[Cmd]) {
            for cmd in cmds {
                let a: Vec<&str> = cmd.args.iter().map(String::as_str).collect();
                let ok = match (cmd.bin, a.as_slice()) {
                    ("sysctl", ["-w", knob]) => knob.starts_with("net.ipv4.neigh.") && knob.ends_with(".proxy_delay=0"),
                    ("tc", ["qdisc", "replace", "dev", _, "clsact"]) => true,
                    ("ip", ["neigh", "flush", "to", _]) => true,
                    ("ip", ["neigh", "replace", "proxy", to, "dev", dev]) => {
                        self.proxies.insert((to.parse().unwrap(), dev.to_string()));
                        true
                    }
                    ("ip", ["neigh", "del", "proxy", to, "dev", dev]) => {
                        self.proxies.remove(&(to.parse().unwrap(), dev.to_string()))
                    }
                    ("tc", ["filter", op, "dev", dev, "ingress", "protocol", "arp", "pref", "895", "handle", handle, "flower", rest @ ..]) => {
                        let h = u32::from_str_radix(handle.trim_start_matches("0x"), 16).unwrap();
                        let host = |o: u32| Ipv4Addr::new(10, 128, 3, (o & 0xff) as u8);
                        let key = (dev.to_string(), host(h >> 8), host(h));
                        match *op {
                            "replace" => {
                                assert_eq!(
                                    rest,
                                    ["arp_op", "request", "arp_sip", &key.1.to_string(), "arp_tip", &key.2.to_string(), "action", "skbedit", "mark", "0x2000000/0x2000000"],
                                    "the handle encodes exactly the match: {cmd}"
                                );
                                self.filters.insert(key);
                                true
                            }
                            "del" => self.filters.remove(&key),
                            other => panic!("unmodelled tc filter {other}: {cmd}"),
                        }
                    }
                    _ => panic!("unmodelled neighbour command: {cmd}"),
                };
                if !ok {
                    assert_eq!(cmd.on_failure, OnFailure::Ignore, "a fatal command would fail here: {cmd}");
                }
            }
        }

        /// The pair `peer` (on `peer_bridge`) granted by `granting` (on
        /// `granting_bridge`), as filters and proxy entries.
        fn assert_arp_path(&self, pairs: &[(&str, &str, &str, &str)], why: &str) {
            let mut filters = BTreeSet::new();
            let mut proxies = BTreeSet::new();
            for (peer, peer_bridge, granting, granting_bridge) in pairs {
                let (p, w): (Ipv4Addr, Ipv4Addr) = (peer.parse().unwrap(), granting.parse().unwrap());
                filters.insert((peer_bridge.to_string(), p, w));
                filters.insert((granting_bridge.to_string(), w, p));
                proxies.insert((w, peer_bridge.to_string()));
                proxies.insert((p, granting_bridge.to_string()));
            }
            assert_eq!(self.filters, filters, "{why}: filters");
            assert_eq!(self.proxies, proxies, "{why}: proxy entries");
        }
    }

    fn fatal(cmds: &[Cmd]) -> bool {
        cmds.iter().any(|c| c.on_failure == OnFailure::Fatal)
    }

    #[test]
    fn a_stopped_workload_takes_its_chains_and_both_halves_of_its_grant_path() {
        let (acme, globex) = (bridge("acme"), bridge("globex"));
        let mut node = Node::new();
        node.deploy(&api(), W);
        node.deploy(&billing(), P);
        node.assert_arp_path(&[(P, &globex, W, &acme)], "both running");

        // billing stops. The filter on its own bridge would die with that
        // bridge, but the filter and proxy entry naming it on acme's bridge
        // would not — that half is what nothing keyed on P ever looks at, and
        // it is the reason a Stop cannot be answered address by address.
        let cmds = node.collect(&[W]);
        assert!(!cmds.is_empty() && !fatal(&cmds), "a GC pass only deletes: {cmds:#?}");
        node.assert_arp_path(&[], "billing stopped");

        let save = node.mangle.save();
        assert!(!save.contains(&format!("yah-id-{P}")), "billing's identity chain survived:\n{save}");
        assert!(!save.contains(&format!("yah-gr-{P}")), "billing's grant chain survived:\n{save}");
        assert!(save.contains(&format!("yah-id-{W}")), "api is still running:\n{save}");
        assert!(save.contains(&format!("yah-gr-{W}")), "api's grant chain is still its own:\n{save}");
    }

    #[test]
    fn a_pass_with_every_workload_still_live_changes_nothing() {
        let (acme, globex) = (bridge("acme"), bridge("globex"));
        let mut node = Node::new();
        node.deploy(&api(), W);
        node.deploy(&billing(), P);
        let before = node.mangle.save();
        assert!(node.collect(&[W, P]).is_empty(), "nothing has departed, so nothing is planned");
        assert_eq!(node.mangle.save(), before);
        node.assert_arp_path(&[(P, &globex, W, &acme)], "untouched");
    }

    #[test]
    fn draining_the_node_leaves_the_grant_layer_empty() {
        let mut node = Node::new();
        node.deploy(&api(), W);
        node.deploy(&billing(), P);
        node.collect(&[]);
        node.assert_arp_path(&[], "node drained");
        assert_eq!(
            node.mangle.save(),
            "",
            "not one chain or PREROUTING jump survives an empty node"
        );
    }

    #[test]
    fn a_node_without_grants_runs_no_neighbour_command() {
        let mut node = Node::new();
        for (spec, addr) in [(billing(), P), (ledger(), Q), (site(), S), (spec("acme", "default", "api", vec![]), W)] {
            let cmds = node.deploy(&spec, addr);
            assert!(cmds.is_empty(), "{} at {addr}: {cmds:#?}", spec.name);
        }
        node.assert_arp_path(&[], "no grant anywhere");
    }

    #[test]
    fn the_arp_path_is_exactly_the_granted_pair_in_either_deploy_order() {
        let (acme, globex) = (bridge("acme"), bridge("globex"));
        for granting_side_first in [true, false] {
            let order = if granting_side_first { "W first" } else { "W last" };
            let mut node = Node::new();
            if granting_side_first {
                let cmds = node.deploy(&api(), W);
                assert!(cmds.is_empty(), "{order}: W's peer is not here yet: {cmds:#?}");
            }
            for (spec, addr) in [(billing(), P), (ledger(), Q), (site(), S)] {
                let cmds = node.deploy(&spec, addr);
                let completes_the_pair = granting_side_first && addr == P;
                assert_eq!(fatal(&cmds), completes_the_pair, "{order}: {} at {addr}: {cmds:#?}", spec.name);
                assert_eq!(cmds.is_empty(), !completes_the_pair, "{order}: {} at {addr}: {cmds:#?}", spec.name);
            }
            if !granting_side_first {
                let cmds: Vec<String> = node.deploy(&api(), W).iter().map(ToString::to_string).collect();
                assert_eq!(
                    cmds,
                    vec![
                        format!("sysctl -w net.ipv4.neigh.{acme}.proxy_delay=0"),
                        format!("tc qdisc replace dev {acme} clsact"),
                        format!("sysctl -w net.ipv4.neigh.{globex}.proxy_delay=0"),
                        format!("tc qdisc replace dev {globex} clsact"),
                        format!("ip neigh replace proxy {W} dev {globex}"),
                        format!("ip neigh replace proxy {P} dev {acme}"),
                        format!("tc filter replace dev {acme} ingress protocol arp pref 895 handle 0x709 flower arp_op request arp_sip {W} arp_tip {P} action skbedit mark 0x2000000/0x2000000"),
                        format!("tc filter replace dev {globex} ingress protocol arp pref 895 handle 0x907 flower arp_op request arp_sip {P} arp_tip {W} action skbedit mark 0x2000000/0x2000000"),
                        format!("ip neigh flush to {W}"),
                        format!("ip neigh flush to {P}"),
                    ],
                    "{order}: the granting deploy's neighbour commands"
                );
            }
            node.assert_arp_path(&[(P, &globex, W, &acme)], order);
        }
    }

    #[test]
    fn withdrawal_readdressing_and_reuse_leave_no_arp_path_behind() {
        let (acme, globex) = (bridge("acme"), bridge("globex"));
        let mut node = Node::new();
        node.deploy(&api(), W);
        node.deploy(&billing(), P);
        node.assert_arp_path(&[(P, &globex, W, &acme)], "paired");

        // billing moves to Q while its old chain at P still names it: both
        // addresses are billing's until P is reused.
        assert!(fatal(&node.deploy(&billing(), Q)), "billing at Q is named by W's grant");
        node.assert_arp_path(&[(P, &globex, W, &acme), (Q, &globex, W, &acme)], "billing re-addressed, P stale");

        // ledger takes P: the stale pair goes, billing's new one stays.
        let cmds = node.deploy(&ledger(), P);
        assert!(!cmds.is_empty() && !fatal(&cmds), "ledger at P only cleans up: {cmds:#?}");
        node.assert_arp_path(&[(Q, &globex, W, &acme)], "P reused by ledger");

        // api redeploys at the same address without the grant.
        let cmds = node.deploy(&spec("acme", "default", "api", vec![]), W);
        assert!(!cmds.is_empty() && !fatal(&cmds), "withdrawal only cleans up: {cmds:#?}");
        node.assert_arp_path(&[], "grant withdrawn");

        // A different acme workload reusing W's address after a re-grant.
        node.deploy(&api(), W);
        node.assert_arp_path(&[(Q, &globex, W, &acme)], "re-granted");
        let cmds = node.deploy(&spec("acme", "default", "worker", vec![]), W);
        assert!(!fatal(&cmds), "{cmds:#?}");
        node.assert_arp_path(&[], "W reused by a workload with no grant");
    }

    #[test]
    fn a_singleton_peer_gets_the_path_on_the_node_bridge() {
        let (acme, solo) = (bridge("acme"), bridge(&TenantId::singleton().0));
        let granting = spec(
            "acme",
            "default",
            "api",
            vec![cross(&TenantId::singleton().0, &NamespaceId::singleton().0, "site")],
        );
        let mut node = Node::new();
        node.deploy(&granting, W);
        assert!(fatal(&node.deploy(&site(), S)), "the singleton peer completes the pair");
        node.assert_arp_path(&[(S, &solo, W, &acme)], "singleton peer");
    }

    #[test]
    fn the_node_state_parses_as_the_kernel_prints_it() {
        // Captured from us-west-003 (6.12.107+deb13-amd64, iptables v1.8.11
        // nf_tables, iproute2-6.15.0), 2026-09-14.
        let save = "\
# Generated by iptables-save v1.8.11 (nf_tables) on Tue Sep 15 00:14:41 2026
*mangle
:PREROUTING ACCEPT [0:0]
:yah-gr-10.9.9.6 - [0:0]
:yah-id-10.9.9.5 - [0:0]
-A PREROUTING -s 10.9.9.5/32 -j yah-id-10.9.9.5
-A yah-gr-10.9.9.6 -d 10.9.9.6/32 -i br0 -m mark --mark 0x1a2b/0xffff -j MARK --set-xmark 0x2000000/0x2000000
-A yah-gr-10.9.9.6 -d 10.9.9.6/32 -i br0 -m mark --mark 0x1a2b/0xffff -j CONNMARK --set-xmark 0x2000000/0x2000000
-A yah-gr-10.9.9.6 -s 10.9.9.6/32 -i br1 -m conntrack --ctdir REPLY -m connmark --mark 0x2000000/0x2000000 -j MARK --set-xmark 0x2000000/0x2000000
-A yah-id-10.9.9.5 -s 10.9.9.5/32 -d 10.9.9.0/24 -i br0 -j MARK --set-xmark 0x1a2b/0xffff
COMMIT
";
        let subnet = Ipv4Cidr::parse("10.9.9.0/24").unwrap();
        let mut node = NodeGrants::read(subnet, save, "10.9.9.6 dev br0 proxy \n");
        let addr = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(node.residents, BTreeMap::from([(addr("10.9.9.5"), ("br0".to_string(), 0x1a2b))]));
        assert_eq!(node.grants, BTreeMap::from([(addr("10.9.9.6"), BTreeSet::from([("br0".to_string(), 0x1a2b)]))]));
        assert_eq!(node.proxies, BTreeSet::from([(addr("10.9.9.6"), "br0".to_string())]));
        node.read_filters(
            "br0",
            "filter protocol arp pref 895 flower chain 0 \n\
             filter protocol arp pref 895 flower chain 0 handle 0x506 \n  eth_type arp\n  arp_sip 10.9.9.5\n  arp_tip 10.9.9.6\n  arp_op request\n  not_in_hw\n\
             \taction order 1: skbedit  mark 33554432/0x2000000 pipe\n\t index 2 ref 1 bind 1\n\n\
             filter protocol arp pref 1 matchall chain 0 handle 0x1 \n",
        );
        assert_eq!(node.filters, BTreeSet::from([("br0".to_string(), addr("10.9.9.5"), addr("10.9.9.6"))]));
    }

    #[test]
    fn a_grant_marks_exactly_the_granted_pair_in_either_deploy_order() {
        let (acme, globex, solo) = (bridge("acme"), bridge("globex"), bridge(&TenantId::singleton().0));
        for granting_side_first in [true, false] {
            let mut m = Mangle::new();
            let peers = [(billing(), P), (ledger(), Q), (site(), S)];
            if granting_side_first {
                m.deploy(&api(), W);
            }
            for (spec, addr) in &peers {
                m.deploy(spec, addr);
            }
            if !granting_side_first {
                m.deploy(&api(), W);
            }
            let order = if granting_side_first { "W first" } else { "W last" };

            let admitted = m.run(packet(&globex, P, W));
            assert!(granted(&admitted), "{order}: billing -> api");
            assert_eq!(admitted.connmark & FWMARK_GRANT, FWMARK_GRANT, "{order}: connection remembered");

            assert!(!granted(&m.run(packet(&globex, Q, W))), "{order}: ledger, billing's tenant but not billing");
            assert!(!granted(&m.run(packet(&solo, S, W))), "{order}: a singleton workload");
            assert!(!granted(&m.run(packet(&acme, P, W))), "{order}: billing's address from another bridge");
            assert!(!granted(&m.run(packet(&acme, W, P))), "{order}: api opening a connection to billing");
            assert!(!granted(&m.run(packet(&globex, P, S))), "{order}: billing -> a workload that granted nothing");

            let reply = Packet { reply: true, connmark: FWMARK_GRANT, ..packet(&acme, W, P) };
            assert!(granted(&m.run(reply.clone())), "{order}: api answering billing");
            let ungranted_reply = Packet { connmark: 0, ..reply };
            assert!(!granted(&m.run(ungranted_reply)), "{order}: api answering a connection no grant admitted");
        }
    }

    #[test]
    fn a_reused_address_or_a_dropped_grant_inherits_nothing() {
        let globex = bridge("globex");
        let mut m = Mangle::new();
        m.deploy(&api(), W);
        m.deploy(&billing(), P);
        assert!(granted(&m.run(packet(&globex, P, W))));

        // billing stops; ledger is allocated the address it held.
        m.deploy(&ledger(), P);
        assert!(!granted(&m.run(packet(&globex, P, W))), "ledger at billing's old address");

        // billing comes back somewhere else, and its grant follows it.
        m.deploy(&billing(), Q);
        assert!(granted(&m.run(packet(&globex, Q, W))), "billing at its new address");

        // api redeploys at the same address without the grant.
        m.deploy(&spec("acme", "default", "api", vec![]), W);
        assert!(!granted(&m.run(packet(&globex, Q, W))), "grant withdrawn");
        let reply = Packet { reply: true, connmark: FWMARK_GRANT, ..packet(&bridge("acme"), W, Q) };
        assert!(!granted(&m.run(reply)), "reply rule withdrawn with it");

        // Redeploys re-assert jumps rather than stacking them.
        let jumps = &m.chains["PREROUTING"];
        let mut unique = jumps.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(jumps.len(), unique.len(), "{jumps:?}");
    }
}

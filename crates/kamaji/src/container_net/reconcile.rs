//! Garbage-collect the node state whose workload is gone (R895-T5).
//!
//! A `Stop` carries a workload identity and nothing else — no address, no
//! tenant — so [`teardown_by_workload`](super::teardown_by_workload) can delete
//! the namespace and the veth pair that dies with it, and nothing else. What it
//! cannot reach outlives it on the node:
//!
//! - the stopped workload's `/32` host route and its
//!   [`WORKLOAD_RULE_PRIORITY`](super::WORKLOAD_RULE_PRIORITY) prohibit, both
//!   keyed on the address;
//! - its `yah-id-<addr>` / `yah-gr-<addr>` mangle chains and their PREROUTING
//!   jumps;
//! - the grant ARP state naming it — and in particular the half of a granted
//!   pair that lives on the *other* workload's bridge, which survives its own
//!   bridge's deletion;
//! - the whole per-tenant bridge once the node's last workload of that tenant
//!   stops: the link, its four prohibits, and its tagged `raw` / `mangle` /
//!   `filter` rules, every one of which is keyed `-i <bridge>` and so
//!   reattaches to whatever bridge the kernel next hands that name.
//!
//! ## Why the kernel is the bookkeeping
//!
//! The obvious alternative is a map from workload to plan, written at deploy
//! and read at stop. This module does not keep one, for the reason
//! [`ContainerNet::bridge_commands`](super::ContainerNet::bridge_commands)
//! already gives for being idempotent rather than tracked: node state that
//! could drift from the kernel's *will*, and it drifts in the direction nobody
//! notices — a kamaji that crashed between the deploy and the write, or was
//! upgraded, or restarted after a reboot that took the bridges with it. Every
//! fact this pass needs is legible in the kernel:
//!
//! - **What is live:** the host end of a workload's veth pair, `veth<octet>`,
//!   enslaved to one of this node's bridges. `ip netns del` destroys the peer
//!   end and the pair with it, so a present `veth<N>` is a running workload and
//!   an absent one is not. The octet is the address, because the node holds
//!   exactly one `/24` and an address is held by one workload at a time.
//! - **What the node thinks it has:** its own bridges' addresses give the
//!   `/24`; `iptables-save -t mangle` gives every address the grant layer
//!   describes; `ip route` gives every tenant workload's host route.
//!
//! So the pass is safe to run at any time, converges whatever state it finds,
//! and needs nothing to have survived the last kamaji.
//!
//! ## What it will not touch
//!
//! The shared egress NAT rule ([`nat_rule`](super::nat_rule)) names no bridge
//! and is one rule for the whole `/24` — deleting it with a bridge would take
//! egress away from every workload still running. `net.ipv4.ip_forward` is
//! node-wide and was very likely on before kamaji. The node bridge itself is
//! never deleted, only its residents' leftovers. And a bridge qualifies only
//! under [`ContainerNet::is_tenant_bridge`](super::ContainerNet::is_tenant_bridge),
//! which admits exactly the ten base32hex characters kamaji generates — a node
//! is shared with docker, tailscale and whatever an operator left behind.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use anyhow::{Context as _, Result};

use super::{ContainerNet, Ipv4Cidr, NodeStateGuard, apply, grants};

/// What one pass took off the node.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Reconciled {
    /// Per-tenant bridges deleted, because the node's last workload of that
    /// tenant had stopped.
    pub bridges: Vec<String>,
    /// Addresses whose leftovers were removed.
    pub addresses: Vec<Ipv4Addr>,
}

impl Reconciled {
    pub fn is_empty(&self) -> bool {
        self.bridges.is_empty() && self.addresses.is_empty()
    }
}

/// Sweep the node once.
///
/// Reads are fatal and writes are not: a pass that cannot see the node's links
/// would read every bridge as unoccupied and delete the lot, so a failed read
/// returns `Err` and changes nothing. Every command it does emit is
/// best-effort, because "already gone" is the expected answer for most of them.
///
/// The [`NodeStateGuard`] is the whole concurrency story — see
/// [`lock_node_state`](super::lock_node_state) for the deploy this would
/// otherwise race.
pub async fn reconcile(net: &ContainerNet, _lock: &NodeStateGuard) -> Result<Reconciled> {
    let links = grants::read("ip", &["-o", "link", "show"])
        .await
        .context("listing the node's links to decide what container state is still in use")?;
    let routes = grants::read("ip", &["-4", "route", "show"])
        .await
        .context("listing the node's routes to decide what container state is still in use")?;
    let addrs = grants::read("ip", &["-4", "-o", "addr", "show"])
        .await
        .context("reading the node's bridge addresses to recover its container /24")?;

    // No bridge carries an address in range: this node has never placed a
    // workload, or something already cleaned up after it. Either way the `/24`
    // is unknown and nothing below can be keyed without it.
    let Some(view) = NodeView::read(net, &links, &routes, &addrs) else {
        return Ok(Reconciled::default());
    };

    // The grant layer first: its `tc` filters hang off bridges the sweep below
    // may delete, and `tc filter del` on a device that is already gone is an
    // error rather than a no-op.
    let grant_gc = grants::gc_grant_state(view.subnet, &view.live, &view.bridges).await?;
    let mut departed = grant_gc.departed;
    // A tenant workload's host route names its address even when the grant
    // layer has nothing to say about it — a node rolled from a kamaji older
    // than R895-F4 has the routes and none of the chains.
    departed.extend(
        view.host_routes
            .iter()
            .copied()
            .filter(|addr| !view.live.contains(addr)),
    );

    let dead: Vec<String> = view
        .bridges
        .iter()
        .filter(|bridge| net.is_tenant_bridge(bridge) && !view.occupied.contains(*bridge))
        .cloned()
        .collect();

    let mut cmds = grant_gc.cmds;
    for addr in &departed {
        cmds.extend(net.address_gc_commands(*addr));
    }
    for bridge in &dead {
        cmds.extend(net.bridge_gc_commands(bridge, view.subnet));
    }
    if cmds.is_empty() {
        return Ok(Reconciled::default());
    }
    apply(&cmds)
        .await
        .context("garbage-collecting stopped workloads' container network state")?;
    Ok(Reconciled {
        bridges: dead,
        addresses: departed.into_iter().collect(),
    })
}

/// The node's container networking as the kernel describes it.
#[derive(Debug, PartialEq, Eq)]
struct NodeView {
    /// Recovered from whichever of this node's bridges carries an address in
    /// range — the node bridge holds the gateway as a `/24` and a tenant bridge
    /// as a `/32`, and either one names the same `/24`.
    subnet: Ipv4Cidr,
    /// Every bridge present that this node made, the node bridge included.
    bridges: BTreeSet<String>,
    /// Those with at least one `veth<octet>` enslaved.
    occupied: BTreeSet<String>,
    /// Addresses a running workload holds, by its host veth's octet.
    live: BTreeSet<Ipv4Addr>,
    /// Addresses with a `/32` host route onto one of this node's bridges.
    host_routes: BTreeSet<Ipv4Addr>,
}

impl NodeView {
    /// Parse `ip -o link show`, `ip -4 route show` and `ip -4 -o addr show`.
    ///
    /// `None` when no bridge of this node's carries an address in range, which
    /// is the one fact the rest is keyed on.
    fn read(net: &ContainerNet, links: &str, routes: &str, addrs: &str) -> Option<NodeView> {
        let mut view = NodeView {
            subnet: subnet_of(net, addrs)?,
            bridges: BTreeSet::new(),
            occupied: BTreeSet::new(),
            live: BTreeSet::new(),
            host_routes: BTreeSet::new(),
        };
        for line in links.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            let Some(name) = words.get(1).map(|w| device(w)) else {
                continue;
            };
            if name == net.bridge() || net.is_tenant_bridge(name) {
                view.bridges.insert(name.to_string());
            }
        }
        for line in links.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            let Some(name) = words.get(1).map(|w| device(w)) else {
                continue;
            };
            let master = words.windows(2).find(|w| w[0] == "master").map(|w| w[1]);
            // A `veth<N>` whose master is one of ours. Docker's veth names are
            // `veth` plus hex, which does not parse as a `u8`, and a foreign
            // interface that somehow did would still have to be enslaved to a
            // kamaji bridge to be read as a live workload.
            let (Some(octet), Some(master)) = (name.strip_prefix("veth").and_then(parse_octet), master)
            else {
                continue;
            };
            if view.bridges.contains(master) {
                view.occupied.insert(master.to_string());
                view.live.insert(view.subnet.nth(u32::from(octet)));
            }
        }
        for line in routes.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            let Some(addr) = words.first().and_then(|w| w.strip_suffix("/32")) else {
                continue;
            };
            let dev = words.windows(2).find(|w| w[0] == "dev").map(|w| w[1]);
            let Some(addr) = addr.parse::<Ipv4Addr>().ok().filter(|a| view.subnet.contains(*a))
            else {
                continue;
            };
            if dev.is_some_and(|dev| view.bridges.contains(dev)) {
                view.host_routes.insert(addr);
            }
        }
        Some(view)
    }
}

/// The `/24` this node addresses containers out of, recovered from its own
/// bridges rather than from a node mesh address a `Stop` does not carry.
fn subnet_of(net: &ContainerNet, addrs: &str) -> Option<Ipv4Cidr> {
    addrs.lines().find_map(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        let name = words.get(1).map(|w| device(w))?;
        if name != net.bridge() && !net.is_tenant_bridge(name) {
            return None;
        }
        let cidr = words.windows(2).find(|w| w[0] == "inet").map(|w| w[1])?;
        let addr: Ipv4Addr = cidr.split('/').next()?.parse().ok()?;
        net.range()
            .contains(addr)
            .then(|| Ipv4Cidr::enclosing_slash24(addr))
    })
}

/// The device name in an `ip -o` field: `yah0:` from a link line, `yah0` from
/// an address line, `veth2` from `veth2@if21:`.
fn device(field: &str) -> &str {
    let field = field.trim_end_matches(':');
    field.split_once('@').map_or(field, |(name, _)| name)
}

/// The host part of a `veth<N>` name, rejecting the forms `ContainerNet::plan`
/// never assigns: `.0` is the network, `.1` the gateway, `.255` the broadcast.
fn parse_octet(suffix: &str) -> Option<u8> {
    suffix
        .parse::<u8>()
        .ok()
        .filter(|octet| *octet >= 2 && *octet != 255)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ip -o link show` from us-east-001, 2026-09-15, trimmed to the lines
    /// that matter: the node bridge with one live workload on it, docker's
    /// bridge, and a docker veth whose name would parse as ours if the master
    /// were not checked.
    const LINKS: &str = "\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp2s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\\    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default\\    link/ether 02:42:1d:2a:3b:4c brd ff:ff:ff:ff:ff:ff
4: yah0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\\    link/ether b6:17:f8:1d:e2:79 brd ff:ff:ff:ff:ff:ff
22: veth2@if21: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master yah0 state UP mode DEFAULT group default qlen 1000\\    link/ether 2e:9f:81:46:f1:85 brd ff:ff:ff:ff:ff:ff link-netns noisetable-account
30: veth9@if29: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default qlen 1000\\    link/ether 3e:9f:81:46:f1:86 brd ff:ff:ff:ff:ff:ff";

    const ADDRS: &str = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: enp2s0    inet 51.81.85.145/24 scope global enp2s0\\       valid_lft forever preferred_lft forever
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever
4: yah0    inet 10.128.3.1/24 scope global yah0\\       valid_lft forever preferred_lft forever";

    fn net() -> ContainerNet {
        ContainerNet::defaults()
    }

    /// `yah0-<10 base32hex>`, the two tenant bridges the tests below use.
    const BR_A: &str = "yah0-0123456789";
    const BR_B: &str = "yah0-vvvvvvvvvv";

    fn link(index: u32, name: &str, master: Option<&str>) -> String {
        let master = master.map_or(String::new(), |m| format!(" master {m}"));
        format!("{index}: {name}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue{master} state UP mode DEFAULT group default qlen 1000\\    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff")
    }

    #[test]
    fn the_node_state_parses_as_the_kernel_prints_it() {
        let view = NodeView::read(&net(), LINKS, "", ADDRS).expect("yah0 carries the gateway");
        assert_eq!(view.subnet.to_string(), "10.128.3.0/24");
        assert_eq!(view.bridges, ["yah0".to_string()].into());
        assert_eq!(view.occupied, ["yah0".to_string()].into());
        assert_eq!(
            view.live,
            [Ipv4Addr::new(10, 128, 3, 2)].into(),
            "veth2 on yah0 is the live workload; veth9 on docker0 is not ours"
        );
    }

    #[test]
    fn a_node_with_no_addressed_bridge_is_not_swept() {
        assert!(
            NodeView::read(&net(), LINKS, "", "1: lo    inet 127.0.0.1/8 scope host lo").is_none(),
            "without a bridge address there is no /24, and every key below it would be a guess"
        );
    }

    #[test]
    fn a_tenant_bridge_is_occupied_by_its_veth_and_empty_without_one() {
        let links = format!(
            "{}\n{}\n{}\n{}",
            link(4, "yah0", None),
            link(5, BR_A, None),
            link(6, BR_B, None),
            link(7, "veth7@if6", Some(BR_A)),
        );
        let view = NodeView::read(&net(), &links, "", ADDRS).expect("yah0 carries the gateway");
        assert_eq!(
            view.bridges,
            ["yah0".to_string(), BR_A.to_string(), BR_B.to_string()].into()
        );
        assert_eq!(view.occupied, [BR_A.to_string()].into());
        assert_eq!(view.live, [Ipv4Addr::new(10, 128, 3, 7)].into());
    }

    #[test]
    fn a_bridge_name_kamaji_did_not_generate_is_never_a_gc_candidate() {
        let net = net();
        assert!(net.is_tenant_bridge(BR_A));
        for foreign in ["yah0-scratch", "yah0-0123456789a", "yah0-012345678", "yah0", "yah0-zzzzzzzzzz", "docker0"] {
            assert!(
                !net.is_tenant_bridge(foreign),
                "{foreign} is not a name tenant_bridge_suffix can emit"
            );
        }
    }

    #[test]
    fn a_host_route_names_a_tenant_workload_and_a_foreign_one_does_not() {
        let links = format!("{}\n{}", link(4, "yah0", None), link(5, BR_A, None));
        let routes = "\
default via 51.81.85.254 dev enp2s0
10.128.3.0/24 dev yah0 proto kernel scope link src 10.128.3.1
10.128.3.7/32 dev yah0-0123456789 scope link
10.128.3.9/32 dev docker0 scope link
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1";
        let view = NodeView::read(&net(), &links, routes, ADDRS).expect("yah0 carries the gateway");
        assert_eq!(
            view.host_routes,
            [Ipv4Addr::new(10, 128, 3, 7)].into(),
            "only a /32 onto one of this node's own bridges is a workload of ours"
        );
    }

    #[test]
    fn the_subnet_comes_from_a_tenant_bridges_slash_32_gateway_too() {
        // A node that has only ever run tenant workloads has no address on the
        // node bridge at all: bridge_commands addresses `plan.bridge`, and for
        // a tenant plan that is the tenant bridge, which holds the gateway as a
        // /32 so as not to claim the /24 as a connected route.
        let addrs = "4: yah0-0123456789    inet 10.128.3.1/32 scope global yah0-0123456789";
        assert_eq!(
            subnet_of(&net(), addrs).map(|s| s.to_string()),
            Some("10.128.3.0/24".to_string())
        );
    }

    #[test]
    fn a_veth_octet_outside_the_assignable_range_is_not_read_as_a_workload() {
        // `.0`, `.1` and `.255` are never planned, so a `veth0` / `veth1` /
        // `veth255` on one of our bridges is somebody else's and reading it as
        // live would pin an address no workload holds.
        for name in ["veth0", "veth1", "veth255", "vethc7", "veth1a2b3c4", "veth"] {
            assert_eq!(
                name.strip_prefix("veth").and_then(parse_octet),
                None,
                "{name} is not a host veth ContainerNet::plan assigns"
            );
        }
        assert_eq!("veth2".strip_prefix("veth").and_then(parse_octet), Some(2));
        assert_eq!("veth254".strip_prefix("veth").and_then(parse_octet), Some(254));
    }

    #[test]
    fn the_device_field_is_read_the_same_from_a_link_line_and_an_address_line() {
        assert_eq!(device("yah0:"), "yah0");
        assert_eq!(device("yah0"), "yah0");
        assert_eq!(device("veth2@if21:"), "veth2");
    }
}

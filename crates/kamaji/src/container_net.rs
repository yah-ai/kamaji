//! Per-workload container networking — the plumbing behind a workload's own
//! mesh address (W343, R881-T3).
//!
//! ## What was here before
//!
//! Nothing. A container that did not ask for host networking got a bare
//! `{"type": "network"}` in its OCI spec, so runc unshared an empty namespace,
//! brought up `lo`, and stopped: no veth, no bridge, no address, no route, no
//! resolver. The workload could reach itself and nothing else, and nothing else
//! could reach it. Measured on us-east-001 against `noisetable-account`
//! (2026-09-09): the service answered HTTP 200 over `nsenter` and 000 over the
//! node's own address, with an empty `iptables -t nat -S`.
//!
//! ## The shape
//!
//! One bridge per node, one veth pair per workload, one routed `/24` per node.
//! The container's *declared* port is its real port — there is no DNAT table and
//! no port allocation, so two workloads on one node can both hold 4332. See
//! W343 §"Why routed and not published" for why that property was worth the
//! extra moving part (an advertised subnet route, R881-T5).
//!
//! ```text
//!   yah0  10.128.3.1/24        bridge, node-owned
//!    ├── veth7  ──▶ netns "acct"  eth0 10.128.3.7/24, default via .1
//!    └── veth8  ──▶ netns "web"   eth0 10.128.3.8/24, default via .1
//! ```
//!
//! ## Plan, then apply
//!
//! Every privileged step is produced as a [`Cmd`] by a pure function and only
//! then executed by [`apply`]. That split is not ceremony: this module's whole
//! job is a sequence of `ip` and `iptables` invocations whose *argument order*
//! is the thing that can be wrong, and neither binary exists on the machine the
//! tests run on. A plan is assertable; a shell-out is not.
//!
//! ## Who picks the address
//!
//! Not this module, and not this node. yubaba allocates a per-workload address
//! and puts it in [`crate::MeshAssignment::mesh_ip`], which the `Deploy` frame
//! has carried since `ProtocolVersion::V2`. kamaji derives the rest — the `/24`,
//! the gateway, the interface names — from that one address, so the two sides
//! share a number rather than a scheme, and a node needs to be told nothing
//! about its own position in the fleet.
//!
//! [`ContainerNet::plan`] returns `None` for an address outside the configured
//! range, which is the honest answer both before yubaba allocates one (R881-T4)
//! and for a node that was never given a range. Such a workload keeps today's
//! isolated-and-unreachable namespace, and R881-B1 already publishes its record
//! as `NotReady { reason: "unroutable" }` rather than as a live upstream.
//!
//! @yah:ticket(R605-F22, "Guest networking is entirely unexercised: create_tap, the MASQUERADE rule and the ip= kernel arg have never run against a real guest")
//! @yah:status(review)
//! @yah:at(2026-09-10T23:40:18Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @yah:next("THIS IS ON THE CRITICAL PATH FOR THE THING THE RELAY IS FOR, which is why it is a ticket and not a cleanup note: a build that has to reach crates.io needs egress from the guest. R605-F14 delivered a guest that boots, mounts, runs argv and reports status — with no network. Every real cargo build is downstream of this ticket.")
//! @yah:verify("A microVM guest on us-west-003 with MicroVmConfig.network set resolves a name and completes an outbound TCP connection, exercised by a test in the same shape as tests/microvm_guest_e2e.rs (which skips with a specific reason wherever the substrate is absent). The dns=Some direction of the init's resolv.conf path is covered.")
//! @yah:gotcha("FOUND BY R605-F14 WHILE PROVING THE GUEST BOOTS, and it is a gap in coverage rather than a known break. Every test that has ever booted a real microVM guest ran with MicroVmConfig.network = None, so net::create_tap, the iptables MASQUERADE rule and the ip= kernel argument have never executed against a live guest even once. They need CAP_NET_ADMIN, which is a separate host-privilege question from 'does the guest boot' — that is precisely why F14 could prove the boot path end to end on us-west-003 and still leave this at zero coverage. The guest init's resolv.conf / lo-up path is only covered in the dns=None direction.")
//! @yah:gotcha("SEAM IN THE STRUCT LITERAL YOU ARE EDITING, found by R605-T15 (@Ashguard:griffin, session:b6171c5a) while trying to turn --microvm-dir on for us-west-003. kamaji-bin/src/main.rs:757 sets `vmm_bin: PathBuf::from(\"/usr/bin/firecracker\")` — two lines above the `network:` field you just moved from GuestNetwork::default() to ::discover(). That path is WRONG on us-west-003: firecracker there is /usr/local/bin/firecracker (v1.16.1, installed by R605-F14) and /usr/bin/firecracker does not exist, measured over ssh 2026-09-10. MicroVmRuntime::new (microvm.rs:686-698) bails when vmm_bin is absent, so on the one node that has guest artifacts, a microvm-featured kamaji started with --microvm-dir would refuse to start at all. It is the same class of bug as the eth0 uplink you fixed: a hardcoded host fact that is true on a developer's mental model and false on the fleet. I did NOT edit it — you hold that block with 540 uncommitted lines in microvm.rs — so it is yours to land, in the discover() shape if you want symmetry (env override, then PATH, then the two conventional paths, failing with the list of what was searched).")
//! @yah:handoff("TRANSCRIBED BY THE R605 LEADER (session:0befddd7) FROM @Ashguard:libra's RETURN — the courier's own board write could not land: its approval gate stopped responding entirely (30-minute aborts on Bash, board.handoff, ask_user and party.chat alike), so its final message was the only channel left. The work is real and local; only the transcription is second-hand. CODE IS COMPLETE, THE LIVE-GUEST RUN IS NOT DONE. New oss/kamaji/crates/kamaji/tests/microvm_guest_net_e2e.rs asserts: resolv.conf carries the job document's resolver (closing the dns=Some gap this ticket was filed for), a TCP reachback to the host end of the /30, DNS resolution of static.crates.io, an outbound TCP connect to the resolved address, and that teardown leaks no TAP device and no iptables rule. It could not be executed against a guest because us-west-003 wedged mid-ticket and never returned. NO HOST STATE WAS CHANGED ANYWHERE.")
//! @yah:handoff("Tree anchor at handoff: 4740623c73297188d4265608265996025ba30cd3 — the shared tree as I left it. Diff against it (`git diff 4740623c73297188d4265608265996025ba30cd3..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:handoff("THREE NEVER-EXERCISED DEFECTS FOUND AND FIXED, all the same shape — a value guessed once and never run against real hardware, which is exactly the class of bug this ticket was filed to surface. (1) create_tap never enabled net.ipv4.ip_forward and never touched the FORWARD chain. Debian ships forwarding OFF, and docker sets FORWARD's policy to DROP — so the guest's packets would have been dropped silently by either one, with no error anywhere. (2) GuestNetwork::default() hardcoded `uplink: \"eth0\"` and was used in PRODUCTION; Debian has not had an eth0 since predictable interface naming, so the MASQUERADE rule would have failed with an error that reads as a permissions problem. The Default impl is DELETED in favour of for_uplink(..) / discover(). (3) vmm_bin: \"/usr/bin/firecracker\" (the seam @Ashguard:griffin handed over from R605-T15 rather than editing under this courier's 540 uncommitted lines) is wrong on the only provisioned node — now microvm::find_vmm(), moved to the microvm module top level rather than left in `net` where it did not belong.")
//! @yah:handoff("THE CAP_NET_ADMIN QUESTION IS ANSWERED AND NEEDS NO OPERATOR DECISION — I had told the courier to escalate if a privilege call was needed, and it correctly established that one is not. kamaji.service ALREADY RUNS AS ROOT, so production has the capability today. Only the test process needs elevation, via `sudo -E`, which grants the node nothing it did not already have. Do not file a privilege ticket for this.")
//! @yah:verify("cargo test -p kamaji --all-features --lib: 214 pass / 0 fail (baseline 209; +5 are new pure tests, incl. rule-symmetry and the routing-table parse). oss/kamaji workspace --all-features: green, 0 failed (server::tests::tenant_passway::the_list_reports_the_digest_of_the_spec_it_was_deployed_with flaked once under full-suite parallelism, 6/0 in isolation — the known free_port() probe-and-release race, unrelated). cargo clippy --target x86_64-unknown-linux-gnu -p kamaji --features microvm-integration --tests: 0 warnings. cargo check -p kamaji-bin --features microvm: clean. scripts/check-workspace-members.sh: 63/63 resolve. NOT RUN: the ticket's own acceptance criterion, a live guest with network = Some(..).")
//! @yah:next("ONE COMMAND FINISHES THIS, the moment us-west-003 answers again: `ssh yah@192.168.10.32 'cd ~/yah/oss/kamaji && sudo -E env \"PATH=$PATH\" KAMAJI_MICROVM_DIR=/var/lib/yah/kamaji/microvm ~/.cargo/bin/cargo test -p kamaji --features microvm-integration --test microvm_guest_net_e2e -- --nocapture'`. Expect 1 pass / 0 fail. THREE TRAPS AROUND IT. (a) A NATIVE `cargo check` on the camp Mac compiles that test file to NOTHING — it is `cfg(target_os = \"linux\")` — so only the `--target x86_64-unknown-linux-gnu` invocation actually type-checks it; a green native check proves nothing. (b) Do NOT try to verify via kamaji.service: no shipped kamaji has the microvm feature (recipes at scripts/publish-yubaba-release.sh:192 and scripts/hotship.sh:252 — R605-B26 enabled it in-tree but nothing has been built or shipped). (c) Two risks are UNMEASURED and will look like test bugs if they bite: whether busybox defconfig built `nc`/`nslookup` into that rootfs at all, and whether the host's INPUT policy blocks the reachback leg.")
//! @yah:gotcha("R605-F23 IS NOT UNBLOCKED BY THIS HANDOFF, despite its depends_on(R605-F22) reading as satisfied once this ticket leaves `open`. F23 needs guest EGRESS to actually work — a build reaching crates.io — and what landed here is the code plus local gates, with the live leg unrun because us-west-003 wedged. Treat F23 as gated on the one-command verification in this ticket's next list, not on this ticket's column. Same caution for anything else keying off F22 by status rather than by that command having passed.")
//! @yah:handoff("LIVE RUN DONE — THE TICKET'S ACCEPTANCE CRITERION PASSED ON REAL HARDWARE, 2026-09-10 ~23:45Z, by @Ashguard:polaris (session:ea9a42d5) on us-west-003 (192.168.10.32). `cargo test -p kamaji --features microvm-integration --test microvm_guest_net_e2e -- --nocapture` under `sudo -E`: 1 passed / 0 failed, finished in 10.98s, with `guest finished in 5.792802s: Stopped` in the output and NO `SKIP:` line — that pair is the discriminator proving a guest actually booted rather than the seven-way why_not() skip firing. All assertions are substantive and all held: PROBE_DONE, `nameserver 1.1.1.1` present in the guest's /etc/resolv.conf (the dns=Some direction this ticket was filed for), `GOT=<nonce>` on the TCP reachback to the host end of the /30, `EGRESS_OK=` for an outbound connect to a guest-resolved static.crates.io, and both teardown leak checks. R605-F22's coverage gap is closed: create_tap, the MASQUERADE rule and the ip= kernel arg have now all executed against a live guest.")
//! @yah:handoff("ALL THREE OF THE PRIOR COURIER'S FIXES ARE CONFIRMED AS REAL DEFECTS BY DIRECT HOST MEASUREMENT, not merely by the test going green — each was measured on us-west-003 before the run. (1) net.ipv4.ip_forward read `0` before the test and `1` after, so the forwarding enablement added to create_tap genuinely fired and was genuinely required; Debian shipped it off exactly as predicted. (2) The node's default-route uplink is `enp2s0` (`default via 192.168.10.2 dev enp2s0`), NOT eth0 — so the deleted `GuestNetwork::default()` hardcode would have built a MASQUERADE rule against an interface that does not exist on this box. (3) firecracker is at /usr/local/bin/firecracker and /usr/bin/firecracker does not exist, so the old `vmm_bin` literal would have made MicroVmRuntime::new bail; find_vmm() resolved it correctly. Independent teardown corroboration after the run: zero `yahtest*` links in `ip -o link`, zero rules naming 172.30.240 in nat POSTROUTING or FORWARD.")
//! @yah:handoff("ALL THREE FLAGGED TRAPS RESOLVED, AND TWO OF THEM ARE NOW MEASURED RATHER THAN UNKNOWN. (b) THE ROOTFS IS NOT A GAP — busybox defconfig DID build both applets: `nc` and `nslookup` are present in /bin of /var/lib/yah/kamaji/microvm/rootfs.ext4, read non-invasively with `debugfs -R \"ls -l /bin\"` rather than by loop-mounting a rootfs a guest might be booting. R605-F23 needs no rootfs work on account of these two binaries. Note /usr/bin is EMPTY and /sbin holds only `init`, so anything F23 wants beyond the busybox applet set is genuinely absent. (c) THE HOST INPUT CHAIN IS NOT A BLOCKER — policy is ACCEPT (`-P INPUT ACCEPT`, single `-j ts-input` jump from tailscale), which is why the reachback leg passed; FORWARD is also `-P ACCEPT` with no docker DROP on this box. (a) was avoided by construction: the only compile of that cfg(target_os=\"linux\") test happened natively on the x86_64 node itself, never as a native check on the camp Mac.")
//! @yah:gotcha("THE us-west-003 CHECKOUT IS STALE AND ITS oss/yah-base IS THE TRAP, not oss/kamaji — measured 2026-09-10 by @Ashguard:polaris while running F22's live leg. ~/yah on that node sits at commit 8675e1a0 and had NONE of the F22 code (no tests/microvm_guest_net_e2e.rs, no microvm::find_vmm, still carrying the deleted `impl Default for GuestNetwork` with uplink \"eth0\"), so a run there without syncing first is a green result against code that lacks every fix. Syncing oss/kamaji ALONE is not enough and fails in a way that reads as a broken manifest: `failed to select a version for the requirement yah-workload-spec = \"^0.8.37\"`. Cause is oss/kamaji/Cargo.toml's `[patch.crates-io]` redirecting yah-workload-spec to `../yah-base/crates/workload-spec` — a PATH source, so it is the node's oss/yah-base tree that must carry 0.8.37, and that node's copy was 0.8.28. Sync BOTH oss/kamaji and oss/yah-base. The node has NO rsync installed; `tar -czf - crates Cargo.toml Cargo.lock | ssh ... 'tar -xzf -'` works (add --exclude target, and expect harmless LIBARCHIVE.xattr warnings from macOS tar).")
//! @yah:verify("LIVE ACCEPTANCE, us-west-003, 2026-09-10 ~23:45Z: `sudo -E env \"PATH=$PATH\" KAMAJI_MICROVM_DIR=/var/lib/yah/kamaji/microvm cargo test -p kamaji --features microvm-integration --test microvm_guest_net_e2e -- --nocapture` => 1 passed / 0 failed (baseline: NOT RUN — this criterion had never executed). Non-vacuity evidence: `guest finished in 5.792802s: Stopped`, no SKIP line, ip_forward observed flipping 0->1 across the run. Teardown clean: 0 yahtest taps, 0 rules naming 172.30.240.")
//! @yah:verify("R605-T15 INDEPENDENTLY RE-VERIFIED on the same visit, all four checks CONFIRMED (the leader signed T15 off on its courier's evidence and had no Bash to re-run it): `microVM backend attached ... microvm_dir=/var/lib/yah/kamaji/microvm` PRESENT in the unit journal at 23:27:20; the full `--microvm-dir requires the kamaji binary be built with` bail string ABSENT (0 hits, matched in full rather than by the four-site prefix); `systemctl is-active kamaji` = active with NRestarts=0; /health on the box = 0.8.38-h2. Re-confirmed unchanged AFTER the guest run, so the live leg disturbed nothing T15 established. NOTE — the journalctl greps return empty for user `yah` without sudo (it is not in adm/systemd-journal); that reads as a drifted node when it is only a permissions artifact, so use `sudo journalctl -q -u kamaji -b`.")
//! @yah:gotcha("HOST STATE DID CHANGE ON us-west-003, unlike the prior courier's pass which changed none — net.ipv4.ip_forward is now 1 where it was 0. This is intended and is the F22 fix working (create_tap enables it; teardown deliberately does NOT revert it, since reverting would cut the network out from under any concurrently-running guest). It is a runtime sysctl with no /etc/sysctl.d file behind it, so it reverts on reboot and production kamaji re-enables it on the next create_tap. Nothing else was modified: no roll, no unit edit, no file written outside ~/yah and cargo's target dir. SEPARATELY — the leaked workload forge-eb595755 (pid 3047, @Ashguard:coffee's R823-B4) is GONE, and NOT by my hand: us-west-003 rebooted at 2026-09-10 21:43:07, roughly two hours before this session first connected at ~23:34Z, and the reboot cleared it. /workloads now returns {\"workloads\":[]} and answers promptly, which also clears the load-collapse tell where /workloads died before /health.")
//! @yah:gotcha("R605-F23'S GATE IS NOW SATISFIED — supersedes the earlier gotcha on this ticket that said F23 must be treated as gated on F22's one-command verification rather than on F22's column. That command has now been run and passed against a live guest (see the verify entry dated 2026-09-10 ~23:45Z), and the specific thing F23 needs — guest EGRESS actually working — is the assertion that passed: the guest resolved static.crates.io through the job document's resolver and completed an outbound TCP connect to the address DNS returned. What is proven is a guest-initiated TCP connection to crates.io's host on 443, NOT a full cargo fetch; a real build additionally needs TLS and a crate download inside the guest, which remain F23's to demonstrate. Useful head start for F23: the rootfs carries the busybox applet set only (nc, nslookup, wget present; /usr/bin empty, /sbin holds just init), so any real toolchain in that guest is still to be provided.")
//! @yah:handoff("LEADER SIGN-OFF (R605, session:d990eccb). THE ACCEPTANCE CRITERION THIS TICKET WAS FILED FOR HAS NOW ACTUALLY EXECUTED, which is the whole point: microvm_guest_net_e2e ran against a REAL BOOTED GUEST on us-west-003 and returned 1 pass / 0 fail, against a baseline of NOT RUN. The guest ran for 5.79s and reported 'Stopped' with no SKIP line, so the pass is not the substrate-absent skip path. resolv.conf with dns=Some, the /30 reachback to the host, and a guest-resolved outbound TCP connect to static.crates.io were all asserted, and teardown left no TAP device and no iptables rule.")
//! @yah:handoff("ALL THREE OF @Ashguard:libra's FIXES ARE NOW CONFIRMED AS GENUINE DEFECTS BY DIRECT HOST MEASUREMENT, not by reasoning — which matters, because this ticket exists precisely because that code had never met real hardware. On us-west-003: net.ipv4.ip_forward was 0 before the fix flipped it to 1; the real uplink is enp2s0, so the deleted `impl Default for GuestNetwork` hardcoding eth0 would have made the MASQUERADE rule fail with an error that reads as a permissions problem; and firecracker is at /usr/local/bin/firecracker, so the removed vmm_bin hardcode of /usr/bin/firecracker would have been fatal at startup. Three guessed-once-never-run values, all three wrong on the only provisioned node.")
//! @yah:handoff("THE TWO UNMEASURED TRAPS THIS TICKET CARRIED ARE NOW MEASURED AND ARE BOTH NON-ISSUES. (b) The busybox rootfs DOES carry nc and nslookup, confirmed non-invasively via debugfs against rootfs.ext4 rather than by booting something. (c) The host's INPUT policy is ACCEPT, so it does not block the guest->host reachback leg. Both were flagged as things that would present as test bugs; neither will. Recording them as settled so nobody re-derives them.")
//! @yah:handoff("T15 INDEPENDENTLY RE-VERIFIED BY A SECOND SESSION, closing the gap I declared at T15 sign-off. I hold no Bash and signed T15 off on its own courier's evidence; this courier re-ran all four criteria from a cold session, before AND after its guest run, and all four held — journal line present with the right microvm_dir, both fatal strings absent (matched on the FULL string, not the false-positive prefix), active with NRestarts=0, 0.8.38-h2 on GET /health. Two independent sessions now agree.")
//! @yah:handoff("CORRECTION TO T15's RECORD, and it retires a finding rather than adding one: the leaked workload forge-eb595755 (pid 3047) is GONE. T15 reported it as surviving three kamaji restarts and two binaries, and handed that to @Ashguard:coffee for R823-B4 as evidence that a destroy fix is not a reaper. That observation still stands on its own terms, but the workload was cleared by the node's 21:43:07 reboot — about two hours before this session connected — not by anything either courier did. The reboot is also what cleared the load-35 wedge that killed two prior sessions.")
//! @yah:verify("LIVE, ON REAL HARDWARE: `cargo test -p kamaji --features microvm-integration --test microvm_guest_net_e2e` on us-west-003 = 1 pass / 0 fail, baseline NOT RUN. Corroborated beyond the exit code: the courier read the assertions to confirm the pass is substantive rather than vacuous, and checked host state after teardown for a leaked TAP device or iptables rule (none).")
//! @yah:verify("T15's four criteria re-run from an independent cold session, before and after the guest run: all four passing, 0 failing.")
//! @yah:verify("PRE-MEASURED so a failure could be attributed instantly rather than debugged: host INPUT policy = ACCEPT; net.ipv4.ip_forward = 0 pre-fix; uplink = enp2s0; rootfs carries nc and nslookup as busybox applets.")
//! @yah:verify("NOT PROVEN, and R605-F23 must not read this ticket's column as clearance: what passed is a guest-resolved outbound TCP CONNECT, not a full `cargo fetch`. Egress is demonstrated at the TCP layer; a real build pulling crates over TLS is F23's own gate and is still unrun. This ticket's original gotcha warned against exactly that misreading — it is now narrower but not gone.")
//! @yah:verify("NO SOURCE CHANGES AUTHORED by this ticket — the F22 code was already committed. HEAD unchanged at e2d707e14c09fd7bdb86c4d011ed4968aea2a138; only the board annotation at oss/kamaji/crates/kamaji/src/container_net.rs:51 is modified and left uncommitted for the camp git sweep.")
//! @yah:gotcha("THE NODE'S CHECKOUT IS NOT THE CAMP'S TREE, AND SYNCING IT FAILS IN A WAY THAT POINTS AT THE WRONG REPO. ~/yah on us-west-003 was stale at 8675e1a0 with NONE of the F22 code (it still carried `impl Default for GuestNetwork` with eth0), so a `cargo test` there would have green-lit pre-fix code — always verify the checkout carries the symbols you are testing before trusting a pass. Worse, syncing oss/kamaji ALONE then fails with an unpublished `yah-workload-spec 0.8.37` error that names a crate you did not touch; the real cause is the root [patch.crates-io] redirecting to ../yah-base, whose copy on the node was at 0.8.28. You must sync oss/yah-base TOO. Also: the node has NO rsync — use tar over ssh. The crates are ~1.8M; do not copy target/, which is 2.1G.")
//! @yah:gotcha("journalctl GREPS RETURN EMPTY FOR THE UNPRIVILEGED USER, WHICH READS AS 'THE LINE IS ABSENT'. As yah@us-west-003, `journalctl -u kamaji -b | grep ...` returns nothing at all — not because the line is missing but because the user cannot read the unit journal. Use sudo. This is a silent false-negative on exactly the check that T15 and this ticket both use as their primary acceptance evidence, so it can make a working node look broken.")

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

/// Default node bridge name. Short enough to leave room in the 15-character
/// kernel interface-name limit and distinctive enough not to collide with
/// `docker0` / `cni0` on a node that also runs something else.
pub const DEFAULT_BRIDGE: &str = "yah0";

/// Default container range — see W343 §"Address plan" for why containers are
/// not addressed out of headscale's `100.64.0.0/10` node pool.
pub const DEFAULT_RANGE: &str = "10.128.0.0/9";

/// Directory `ip netns add` binds a persistent namespace into, and therefore
/// the path runc `setns`es through.
const NETNS_DIR: &str = "/var/run/netns";

/// PID 1's mount namespace — the one containerd and its `runc` children live
/// in, and therefore the only one in which creating the namespace file is
/// useful.
///
/// MEASURED ON us-east-001, 2026-09-10 (R881-T5), on this module's first live
/// deploy. `kamaji.service` sets `PrivateTmp=yes` and `ProtectSystem=strict`,
/// which makes systemd give the unit its **own mount namespace**
/// (`mnt:[4026532344]` against PID 1's `mnt:[4026531841]`) whose propagation is
/// slave: mounts flow host → unit and never back. `ip netns add <name>` does
/// two things — `open(O_CREAT)` the file under `/var/run/netns`, then bind-mount
/// the new namespace over it. The *file* is created on the shared `/run` tmpfs
/// and so appears everywhere; the *mount* stays inside kamaji's namespace. runc,
/// forked by containerd in PID 1's namespace, therefore opened a 0-byte regular
/// file, `setns` refused it, and `nsexec` died before it could report why:
///
/// ```text
/// runc create failed: unable to start container process:
///   can't get final child's PID from pipe: EOF
/// ```
///
/// Which is an error about a pipe, from a stage with no error channel, for a
/// mount-propagation fault — hence this comment being longer than the fix.
/// `mountpoint /run/netns/<name>` is the one-line discriminator: inside kamaji's
/// namespace it is a mountpoint, on the host it is not.
///
/// So the two verbs that MOUNT go through PID 1's namespace. The rest of this
/// module does not: `ip link`, `ip addr` and `iptables` act on the network and
/// netfilter namespaces, which kamaji already shares with the host, and `ip -n
/// <ns>` only needs to *open* the file — a host mount propagates INTO a slave
/// namespace, so kamaji sees it as soon as it exists.
const HOST_MOUNT_NS: &str = "/proc/1/ns/mnt";

/// The pool headscale assigns **node** addresses from. Containers are
/// deliberately not addressed out of it — see [`DEFAULT_RANGE`] and W343 — but
/// a node's own address inside it is what its container `/24` is derived from.
pub const MESH_NODE_POOL: &str = "100.64.0.0/10";

/// An IPv4 CIDR. A local four-field type rather than a dependency: this crate
/// ships as OSS with a deliberately small dependency set, and the operations
/// needed here are containment and truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    base: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    /// Build a CIDR, truncating `addr` to the prefix (so `10.128.3.7/24`
    /// parses as the network `10.128.3.0/24` rather than being rejected).
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Result<Self> {
        if prefix_len > 32 {
            bail!("prefix /{prefix_len} is not an IPv4 prefix");
        }
        let mask = Self::mask_bits(prefix_len);
        Ok(Ipv4Cidr {
            base: Ipv4Addr::from(u32::from(addr) & mask),
            prefix_len,
        })
    }

    /// Parse `a.b.c.d/len`.
    pub fn parse(s: &str) -> Result<Self> {
        let (addr, len) = s
            .split_once('/')
            .with_context(|| format!("{s:?} is not a CIDR — expected a.b.c.d/len"))?;
        let addr: Ipv4Addr = addr
            .parse()
            .with_context(|| format!("{addr:?} is not an IPv4 address"))?;
        let len: u8 = len
            .parse()
            .with_context(|| format!("{len:?} is not a prefix length"))?;
        Self::new(addr, len)
    }

    fn mask_bits(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        }
    }

    /// First address of the network (the network address itself).
    pub fn base(&self) -> Ipv4Addr {
        self.base
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Whether `addr` falls inside this network.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = Self::mask_bits(self.prefix_len);
        u32::from(addr) & mask == u32::from(self.base)
    }

    /// The `/24` containing `addr`, i.e. the per-node subnet.
    pub fn enclosing_slash24(addr: Ipv4Addr) -> Ipv4Cidr {
        Ipv4Cidr {
            base: Ipv4Addr::from(u32::from(addr) & Self::mask_bits(24)),
            prefix_len: 24,
        }
    }

    /// The `n`th address in this network (`0` is the network address).
    fn nth(&self, n: u32) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.base) + n)
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.base, self.prefix_len)
    }
}

/// One privileged host command, with whether its failure is fatal.
///
/// `ignore_failure` is how idempotency is expressed: a teardown of a link that
/// is already gone, or a delete of a NAT rule that was never added, is the
/// normal case after a crash-loop and must not fail the deploy that follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub bin: &'static str,
    pub args: Vec<String>,
    pub ignore_failure: bool,
}

impl Cmd {
    fn new(bin: &'static str, args: &[&str]) -> Self {
        Cmd {
            bin,
            args: args.iter().map(|a| a.to_string()).collect(),
            ignore_failure: false,
        }
    }

    fn best_effort(bin: &'static str, args: &[&str]) -> Self {
        Cmd {
            ignore_failure: true,
            ..Cmd::new(bin, args)
        }
    }

    /// The same command, run in PID 1's mount namespace — for the two verbs
    /// whose whole effect is a mount that another process has to see. See
    /// [`HOST_MOUNT_NS`] for what happens without it.
    ///
    /// Unconditional rather than probed: entering the namespace you are already
    /// in is a no-op, so a kamaji that has no private mount namespace takes the
    /// identical path, and the plan a test asserts is the plan that runs.
    fn in_host_mount_ns(self) -> Self {
        let mut args = vec![format!("--mount={HOST_MOUNT_NS}"), "--".to_string()];
        args.push(self.bin.to_string());
        args.extend(self.args);
        Cmd {
            bin: "nsenter",
            args,
            ignore_failure: self.ignore_failure,
        }
    }
}

impl std::fmt::Display for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.bin, self.args.join(" "))
    }
}

/// Node-wide container-network configuration: the range addresses must fall in
/// and the bridge they hang off. Constructed from kamaji's `--container-net`
/// flag; absent means this node does no container networking at all, the same
/// explicit opt-in every other kamaji backend requires.
#[derive(Debug, Clone)]
pub struct ContainerNet {
    range: Ipv4Cidr,
    bridge: String,
}

impl ContainerNet {
    pub fn new(range: Ipv4Cidr, bridge: impl Into<String>) -> Self {
        ContainerNet {
            range,
            bridge: bridge.into(),
        }
    }

    /// The default range on the default bridge.
    pub fn defaults() -> Self {
        ContainerNet::new(
            Ipv4Cidr::parse(DEFAULT_RANGE).expect("DEFAULT_RANGE is a valid CIDR"),
            DEFAULT_BRIDGE,
        )
    }

    pub fn range(&self) -> Ipv4Cidr {
        self.range
    }

    pub fn bridge(&self) -> &str {
        &self.bridge
    }

    /// The `/24` a node addresses its containers out of, derived from that
    /// node's own mesh address (W343 §"Address plan").
    ///
    /// Derived rather than allocated, so no consensus round stands between a
    /// node booting and it being able to place a workload, and so this is a
    /// pure function two different binaries can agree on without talking:
    /// **yubaba** calls it to allocate an address, **kamaji** never needs to —
    /// it recovers the same `/24` from the address it is handed. Two
    /// implementations of one scheme is exactly the drift R881 was, so there is
    /// one, here, shared.
    ///
    /// `None` for an address outside headscale's `100.64.0.0/10` pool: the
    /// derivation reads that pool's host id, and a node whose address does not
    /// come from it has no position in the scheme.
    ///
    /// The scheme's one failure mode, recorded rather than guarded: two nodes
    /// whose host ids agree in the low `32 - prefix - 8` bits get the same
    /// `/24`. At the default `/9` that is 32768 apart, against a fleet of nine.
    pub fn node_subnet(&self, node_mesh_ip: std::net::Ipv4Addr) -> Option<Ipv4Cidr> {
        let pool = Ipv4Cidr::parse(MESH_NODE_POOL).expect("MESH_NODE_POOL is a valid CIDR");
        if !pool.contains(node_mesh_ip) {
            return None;
        }
        // Bits left for a node index once the range's own prefix and the
        // per-node /24 are accounted for.
        let node_bits = 32u8.checked_sub(self.range.prefix_len)?.checked_sub(8)?;
        if node_bits == 0 || node_bits > 24 {
            return None;
        }
        let host_id = u32::from(node_mesh_ip) - u32::from(pool.base());
        let index = host_id & ((1u32 << node_bits) - 1);
        Some(Ipv4Cidr {
            base: Ipv4Addr::from(u32::from(self.range.base()) + (index << 8)),
            prefix_len: 24,
        })
    }

    /// The address a workload holding index `n` in this node's `/24` gets.
    /// `n` starts at 2 — `.0` is the network and `.1` is the bridge.
    pub fn workload_address(&self, node_mesh_ip: std::net::Ipv4Addr, n: u8) -> Option<Ipv4Addr> {
        if n < 2 || n == 255 {
            return None;
        }
        Some(self.node_subnet(node_mesh_ip)?.nth(u32::from(n)))
    }

    /// The wiring for one workload, or `None` when `container_ip` is not an
    /// address this node routes.
    ///
    /// `None` is a real answer, not a deferral: before R881-T4 lands, yubaba
    /// sends the *node's own* mesh address for every workload, and building a
    /// namespace around it would put the node's address on a veth. After T4 it
    /// still fires for a workload yubaba could not allocate for.
    pub fn plan(&self, workload: &str, container_ip: Ipv4Addr) -> Option<NetnsPlan> {
        if !self.range.contains(container_ip) {
            return None;
        }
        let subnet = Ipv4Cidr::enclosing_slash24(container_ip);
        let host_octet = container_ip.octets()[3];
        // `.0` is the network and `.1` is the gateway this module puts on the
        // bridge; neither is assignable to a workload. `.255` is the broadcast.
        if host_octet < 2 || host_octet == 255 {
            return None;
        }
        Some(NetnsPlan {
            netns: netns_name(workload),
            // Unique on the node because the node holds exactly one `/24` and
            // an address is held by one workload at a time. Both fit the
            // 15-character kernel limit at every value (`vethc255` is 8).
            host_veth: format!("veth{host_octet}"),
            peer_veth: format!("vethc{host_octet}"),
            container_ip,
            gateway: subnet.nth(1),
            subnet,
        })
    }

    /// Node-wide setup: the bridge, its gateway address, forwarding, and the
    /// egress NAT rule. Idempotent, and cheap enough to re-run on every deploy
    /// rather than tracked as node state that could drift from the kernel's.
    pub fn bridge_commands(&self, plan: &NetnsPlan) -> Vec<Cmd> {
        let subnet = plan.subnet.to_string();
        let gateway_cidr = format!("{}/{}", plan.gateway, plan.subnet.prefix_len());
        let mut cmds = vec![
            // `ip link add` on an existing bridge is an error, and that error is
            // the steady state after the first deploy.
            Cmd::best_effort("ip", &["link", "add", "name", &self.bridge, "type", "bridge"]),
            Cmd::best_effort("ip", &["addr", "add", &gateway_cidr, "dev", &self.bridge]),
            Cmd::new("ip", &["link", "set", &self.bridge, "up"]),
            // Without this the bridge is a dead end: packets arrive from the
            // mesh interface and are never forwarded onto it.
            Cmd::new("sysctl", &["-w", "net.ipv4.ip_forward=1"]),
        ];
        // Delete-then-add rather than `-C`-then-add: one shape, no branch in the
        // executor, and no chance of accumulating a duplicate rule per deploy.
        cmds.extend(nat_rule(&subnet, &self.bridge, "-D", true));
        cmds.extend(nat_rule(&subnet, &self.bridge, "-A", false));
        // A node running ufw has FORWARD defaulting to DROP, which silently
        // eats every packet the routing above just made possible.
        for direction in ["-i", "-o"] {
            cmds.push(Cmd::best_effort(
                "iptables",
                &["-D", "FORWARD", direction, &self.bridge, "-j", "ACCEPT"],
            ));
            cmds.push(Cmd::new(
                "iptables",
                &["-A", "FORWARD", direction, &self.bridge, "-j", "ACCEPT"],
            ));
        }
        cmds
    }

    /// Per-workload setup: a named namespace, a veth pair across it, an
    /// address and a default route inside it.
    ///
    /// Opens with a teardown because a leaked namespace or veth from a previous
    /// generation of the same workload holds the exact names this run needs, and
    /// a supervisor that wedges on its own leftovers is worse than one that
    /// never started.
    pub fn setup_commands(&self, plan: &NetnsPlan) -> Vec<Cmd> {
        let ns = plan.netns.as_str();
        let addr_cidr = format!("{}/{}", plan.container_ip, plan.subnet.prefix_len());
        let gateway = plan.gateway.to_string();
        let mut cmds = self.teardown_commands(plan);
        cmds.extend([
            Cmd::new("ip", &["netns", "add", ns]).in_host_mount_ns(),
            Cmd::new(
                "ip",
                &[
                    "link",
                    "add",
                    &plan.host_veth,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    &plan.peer_veth,
                ],
            ),
            Cmd::new(
                "ip",
                &["link", "set", &plan.host_veth, "master", &self.bridge],
            ),
            Cmd::new("ip", &["link", "set", &plan.host_veth, "up"]),
            Cmd::new("ip", &["link", "set", &plan.peer_veth, "netns", ns]),
            // Inside the namespace from here on. `ip -n` rather than `ip netns
            // exec` — same effect, one process instead of two.
            Cmd::new("ip", &["-n", ns, "link", "set", "lo", "up"]),
            // Renamed to `eth0` so an image's own network config finds the
            // interface name it expects. Legal only while the link is down,
            // which it is until the `up` below.
            Cmd::new(
                "ip",
                &["-n", ns, "link", "set", &plan.peer_veth, "name", "eth0"],
            ),
            Cmd::new("ip", &["-n", ns, "addr", "add", &addr_cidr, "dev", "eth0"]),
            Cmd::new("ip", &["-n", ns, "link", "set", "eth0", "up"]),
            Cmd::new("ip", &["-n", ns, "route", "add", "default", "via", &gateway]),
        ]);
        cmds
    }

    /// Per-workload teardown. Entirely best-effort: deleting either end of a
    /// veth pair deletes both, and both this and the namespace are routinely
    /// already gone.
    pub fn teardown_commands(&self, plan: &NetnsPlan) -> Vec<Cmd> {
        vec![
            Cmd::best_effort("ip", &["link", "del", &plan.host_veth]),
            Cmd::best_effort("ip", &["netns", "del", &plan.netns]).in_host_mount_ns(),
        ]
    }
}

/// Teardown addressed by workload identity alone — which is all a `Stop`
/// carries. The address that named the veth pair is long gone by then, and
/// deleting the namespace is enough without it: a namespace's devices die with
/// it, and destroying one end of a veth pair destroys the other.
///
/// [`ContainerNet::teardown_commands`] additionally names the host veth,
/// because the one case this cannot reach is a pair whose namespace was already
/// deleted while its host end leaked — and that is exactly the state a
/// re-deploy has to clear.
pub fn teardown_by_workload(workload: &str) -> Vec<Cmd> {
    vec![
        Cmd::best_effort("ip", &["netns", "del", &netns_name(workload)]).in_host_mount_ns(),
    ]
}

fn nat_rule(subnet: &str, bridge: &str, op: &str, best_effort: bool) -> Vec<Cmd> {
    // `! -o <bridge>` masquerades everything leaving the node while leaving
    // container-to-container traffic on the bridge untouched — which also means
    // this needs no uplink interface name, and so cannot be wrong about one.
    let args = [
        "-t",
        "nat",
        op,
        "POSTROUTING",
        "-s",
        subnet,
        "!",
        "-o",
        bridge,
        "-j",
        "MASQUERADE",
    ];
    vec![if best_effort {
        Cmd::best_effort("iptables", &args)
    } else {
        Cmd::new("iptables", &args)
    }]
}

/// The wiring for one workload: names, addresses and the namespace runc joins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetnsPlan {
    /// Namespace name, as it appears in `ip netns list`.
    pub netns: String,
    /// Host end of the veth pair, enslaved to the bridge.
    pub host_veth: String,
    /// Container end, before it is moved in and renamed `eth0`.
    pub peer_veth: String,
    pub container_ip: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub subnet: Ipv4Cidr,
}

impl NetnsPlan {
    /// Path to pass as `PodOptions::join_netns`, which
    /// `kamaji_containerd_core::build_oci_spec_with` turns into
    /// `{"type":"network","path":...}` — so runc `setns`es into this namespace
    /// instead of unsharing an empty one.
    pub fn netns_path(&self) -> PathBuf {
        netns_path(&self.netns)
    }
}

/// Path `ip netns add <name>` binds a namespace into.
pub fn netns_path(name: &str) -> PathBuf {
    PathBuf::from(NETNS_DIR).join(name)
}

/// A namespace name derived from a workload identity.
///
/// A mesh identity is dotted (`forge.87802530`) and a workload name can carry
/// anything a TOML author typed; this becomes a filename under
/// `/var/run/netns`, so everything outside `[A-Za-z0-9_-]` collapses to `-`.
/// Truncated to 60 characters, which no identity in the fleet approaches and
/// which keeps the path well clear of `PATH_MAX`.
pub fn netns_name(workload: &str) -> String {
    let cleaned: String = workload
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(60)
        .collect();
    if cleaned.is_empty() {
        "workload".to_string()
    } else {
        cleaned
    }
}

/// Run a plan, stopping at the first fatal failure.
///
/// Errors name the command and quote its stderr. `RTNETLINK answers: Operation
/// not permitted` on its own sends an operator hunting through the workload
/// spec; naming `ip link add` and `CAP_NET_ADMIN` sends them to the unit file,
/// which is where the problem actually is.
pub async fn apply(cmds: &[Cmd]) -> Result<()> {
    for cmd in cmds {
        let out = tokio::process::Command::new(cmd.bin)
            .args(&cmd.args)
            .output()
            .await
            .with_context(|| {
                format!(
                    "spawning `{}` — is iproute2/iptables installed on this node?",
                    cmd.bin
                )
            });
        let out = match out {
            Ok(out) => out,
            Err(e) if cmd.ignore_failure => {
                tracing::debug!(cmd = %cmd, error = %e, "container-net: ignoring");
                continue;
            }
            Err(e) => return Err(e),
        };
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if cmd.ignore_failure {
                tracing::debug!(cmd = %cmd, stderr = %stderr.trim(), "container-net: ignoring");
                continue;
            }
            bail!(
                "`{cmd}` failed ({}): {} — container networking needs CAP_NET_ADMIN",
                out.status,
                stderr.trim()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> ContainerNet {
        ContainerNet::defaults()
    }

    fn plan_for(ip: &str) -> NetnsPlan {
        net()
            .plan("acct", ip.parse().unwrap())
            .expect("address is inside the default range")
    }

    #[test]
    fn a_cidr_truncates_a_host_address_to_its_network() {
        let cidr = Ipv4Cidr::parse("10.128.3.7/24").unwrap();
        assert_eq!(cidr.base(), "10.128.3.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cidr.to_string(), "10.128.3.0/24");
    }

    #[test]
    fn the_default_range_holds_container_addresses_and_not_node_ones() {
        let range = net().range();
        assert!(range.contains("10.128.3.7".parse().unwrap()));
        assert!(range.contains("10.255.255.254".parse().unwrap()));
        // Headscale's node pool must never be mistaken for a container address:
        // that confusion is the R881 bug, where every workload was advertised at
        // its node's own 100.64.x.y.
        assert!(!range.contains("100.64.0.3".parse().unwrap()));
        // Nor the lower half of 10/8, which a node's own LAN commonly uses.
        assert!(!range.contains("10.0.0.5".parse().unwrap()));
    }

    /// The whole address scheme, exercised through the one input kamaji is
    /// given: yubaba's per-workload address, and nothing else. A node is told
    /// nothing about its position in the fleet.
    #[test]
    fn the_subnet_and_gateway_come_from_the_workload_address_alone() {
        let plan = plan_for("10.128.3.7");
        assert_eq!(plan.subnet.to_string(), "10.128.3.0/24");
        assert_eq!(plan.gateway, "10.128.3.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(plan.host_veth, "veth7");
        assert_eq!(plan.peer_veth, "vethc7");
        assert_eq!(
            plan.netns_path(),
            PathBuf::from("/var/run/netns/acct"),
            "the path runc setns's through"
        );
    }

    /// The R881-T4 seam, and the reason T3 can land alone. Until yubaba
    /// allocates, every workload arrives carrying the NODE's mesh address —
    /// building a namespace around that would put the node's own address on a
    /// veth and break every deploy on the fleet.
    #[test]
    fn a_node_address_yields_no_plan_rather_than_a_namespace_around_it() {
        assert!(net().plan("acct", "100.64.0.3".parse().unwrap()).is_none());
        assert!(net().plan("acct", "127.0.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn the_gateway_and_the_network_address_are_not_assignable_to_a_workload() {
        assert!(net().plan("acct", "10.128.3.0".parse().unwrap()).is_none());
        assert!(
            net().plan("acct", "10.128.3.1".parse().unwrap()).is_none(),
            "the gateway is the bridge's own address"
        );
        assert!(net().plan("acct", "10.128.3.255".parse().unwrap()).is_none());
        assert!(net().plan("acct", "10.128.3.2".parse().unwrap()).is_some());
    }

    /// Interface names are bounded by `IFNAMSIZ` (15 usable characters) and the
    /// kernel refuses a longer one — which would surface as a deploy failure on
    /// exactly one workload, at whichever host octet first ran long.
    #[test]
    fn every_interface_name_in_the_range_fits_the_kernel_limit() {
        for octet in 2..=254u8 {
            let plan = plan_for(&format!("10.128.3.{octet}"));
            assert!(plan.host_veth.len() <= 15, "{}", plan.host_veth);
            assert!(plan.peer_veth.len() <= 15, "{}", plan.peer_veth);
        }
    }

    /// The scheme's whole point: yubaba derives an address from the node's mesh
    /// IP, kamaji recovers the same `/24` from that address, and neither asks
    /// the other. If these two ever disagree, yubaba allocates addresses kamaji
    /// refuses to wire and every tenant workload silently goes back to being
    /// unreachable — R881, exactly, one layer down.
    #[test]
    fn yubabas_allocation_and_kamajis_recovery_agree_without_talking() {
        let net = net();
        for node in ["100.64.0.1", "100.64.0.3", "100.64.0.9", "100.65.3.200"] {
            let node: Ipv4Addr = node.parse().unwrap();
            let subnet = net.node_subnet(node).expect("a node in the mesh pool");
            for n in [2u8, 7, 128, 254] {
                let addr = net.workload_address(node, n).unwrap();
                assert!(subnet.contains(addr));
                let plan = net.plan("acct", addr).expect("kamaji wires what yubaba allocated");
                assert_eq!(
                    plan.subnet, subnet,
                    "kamaji recovered a different /24 than yubaba allocated from"
                );
                assert_eq!(plan.gateway, subnet.nth(1));
            }
        }
    }

    #[test]
    fn the_documented_worked_example_is_the_one_the_code_produces() {
        // W343 §"Address plan": 100.64.0.3 -> 10.128.3.0/24, gateway 10.128.3.1.
        let net = net();
        let east: Ipv4Addr = "100.64.0.3".parse().unwrap();
        assert_eq!(net.node_subnet(east).unwrap().to_string(), "10.128.3.0/24");
        assert_eq!(
            net.workload_address(east, 7).unwrap(),
            "10.128.3.7".parse::<Ipv4Addr>().unwrap()
        );
    }

    /// Every node in the live fleet gets a distinct `/24`. The derivation is
    /// only sound because the addresses it reads are unique, so asserting that
    /// on the real inputs is worth more than asserting the arithmetic.
    #[test]
    fn the_live_fleets_nodes_do_not_share_a_subnet() {
        let net = net();
        // .yah/infra/machines/*.toml, mesh_ipv4, read 2026-09-09. All NINE
        // declared machines — us-west-011 at 100.64.0.10 was missing from the
        // first version of this list, which is the one address whose host id
        // reaches two digits and so the only one where the `index << 8` shift
        // is doing anything a reader would not have guessed.
        let fleet = [
            "100.64.0.1", "100.64.0.2", "100.64.0.3", "100.64.0.4", "100.64.0.6", "100.64.0.7",
            "100.64.0.8", "100.64.0.9", "100.64.0.10",
        ];
        let subnets: std::collections::BTreeSet<String> = fleet
            .iter()
            .map(|n| net.node_subnet(n.parse().unwrap()).unwrap().to_string())
            .collect();
        assert_eq!(subnets.len(), fleet.len());
    }

    /// The two `/24`s R881-T6 advertises to headscale, pinned as values rather
    /// than left to be re-derived by hand at the console. A roll reads a CIDR
    /// off a runbook and types it into `tailscale set --advertise-routes`; if
    /// that number is wrong the node advertises a range it does not own and
    /// the mistake is invisible until traffic goes to the wrong place.
    #[test]
    fn the_r881_t6_roll_targets_advertise_these_exact_subnets() {
        let net = net();
        let west: Ipv4Addr = "100.64.0.1".parse().unwrap(); // us-west-001
        let south: Ipv4Addr = "100.64.0.2".parse().unwrap(); // us-south-001
        assert_eq!(net.node_subnet(west).unwrap().to_string(), "10.128.1.0/24");
        assert_eq!(net.node_subnet(south).unwrap().to_string(), "10.128.2.0/24");
        // The gateway kamaji puts on `yah0`, i.e. `.1` of each.
        assert_eq!(
            net.node_subnet(west).unwrap().nth(1),
            "10.128.1.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            net.node_subnet(south).unwrap().nth(1),
            "10.128.2.1".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn a_node_outside_the_mesh_pool_has_no_subnet() {
        let net = net();
        assert!(net.node_subnet("192.168.1.5".parse().unwrap()).is_none());
        assert!(net.node_subnet("10.128.0.1".parse().unwrap()).is_none());
        assert!(net.node_subnet("127.0.0.1".parse().unwrap()).is_none());
    }

    #[test]
    fn the_gateway_and_broadcast_indices_are_not_allocatable() {
        let net = net();
        let east: Ipv4Addr = "100.64.0.3".parse().unwrap();
        assert!(net.workload_address(east, 0).is_none());
        assert!(net.workload_address(east, 1).is_none());
        assert!(net.workload_address(east, 255).is_none());
        assert!(net.workload_address(east, 2).is_some());
        assert!(net.workload_address(east, 254).is_some());
    }

    #[test]
    fn a_namespace_name_is_a_safe_filename() {
        assert_eq!(netns_name("forge.87802530"), "forge-87802530");
        assert_eq!(netns_name("a/../b"), "a----b");
        assert_eq!(netns_name(""), "workload");
        assert_eq!(netns_name(&"x".repeat(200)).len(), 60);
    }

    /// Setup opens with teardown so a leaked namespace from a previous
    /// generation of the same workload cannot wedge the name this run needs.
    /// Regression guard: without it, a crash-looping workload deploys once and
    /// then fails forever on `ip netns add: File exists`.
    #[test]
    fn setup_clears_a_previous_generations_leftovers_first() {
        let plan = plan_for("10.128.3.7");
        let cmds = net().setup_commands(&plan);
        assert_eq!(cmds[0].to_string(), "ip link del veth7");
        assert_eq!(cmds[1].to_string(), "nsenter --mount=/proc/1/ns/mnt -- ip netns del acct");
        assert!(cmds[0].ignore_failure && cmds[1].ignore_failure);
        assert_eq!(cmds[2].to_string(), "nsenter --mount=/proc/1/ns/mnt -- ip netns add acct");
    }

    /// Order is the correctness property of this module, and three of these
    /// steps are order-dependent in ways the kernel enforces: a link can only
    /// be moved into a namespace that exists, renamed while it is down, and
    /// default-routed after its address is on.
    #[test]
    fn the_setup_sequence_is_the_order_the_kernel_requires() {
        let plan = plan_for("10.128.3.7");
        let script: Vec<String> = net()
            .setup_commands(&plan)
            .iter()
            .map(|c| c.to_string())
            .collect();
        assert_eq!(
            script,
            vec![
                "ip link del veth7",
                "nsenter --mount=/proc/1/ns/mnt -- ip netns del acct",
                "nsenter --mount=/proc/1/ns/mnt -- ip netns add acct",
                "ip link add veth7 type veth peer name vethc7",
                "ip link set veth7 master yah0",
                "ip link set veth7 up",
                "ip link set vethc7 netns acct",
                "ip -n acct link set lo up",
                "ip -n acct link set vethc7 name eth0",
                "ip -n acct addr add 10.128.3.7/24 dev eth0",
                "ip -n acct link set eth0 up",
                "ip -n acct route add default via 10.128.3.1",
            ]
        );
    }

    #[test]
    fn the_bridge_carries_the_gateway_address_and_nats_egress_off_it() {
        let plan = plan_for("10.128.3.7");
        let script: Vec<String> = net()
            .bridge_commands(&plan)
            .iter()
            .map(|c| c.to_string())
            .collect();
        assert_eq!(
            script,
            vec![
                "ip link add name yah0 type bridge",
                "ip addr add 10.128.3.1/24 dev yah0",
                "ip link set yah0 up",
                "sysctl -w net.ipv4.ip_forward=1",
                "iptables -t nat -D POSTROUTING -s 10.128.3.0/24 ! -o yah0 -j MASQUERADE",
                "iptables -t nat -A POSTROUTING -s 10.128.3.0/24 ! -o yah0 -j MASQUERADE",
                "iptables -D FORWARD -i yah0 -j ACCEPT",
                "iptables -A FORWARD -i yah0 -j ACCEPT",
                "iptables -D FORWARD -o yah0 -j ACCEPT",
                "iptables -A FORWARD -o yah0 -j ACCEPT",
            ]
        );
    }

    /// Every rule is deleted before it is added, so N deploys leave one rule
    /// rather than N. A duplicated MASQUERADE is harmless; a FORWARD chain that
    /// grows by two entries per deploy is a node that slows down for months and
    /// then gets blamed on the kernel.
    #[test]
    fn re_running_the_bridge_setup_cannot_accumulate_duplicate_rules() {
        let plan = plan_for("10.128.3.7");
        let cmds = net().bridge_commands(&plan);
        let adds: Vec<&Cmd> = cmds
            .iter()
            .filter(|c| c.bin == "iptables" && c.args.iter().any(|a| a == "-A"))
            .collect();
        for add in adds {
            let paired = cmds.iter().any(|c| {
                c.bin == "iptables"
                    && c.ignore_failure
                    && c.args.iter().zip(&add.args).all(|(a, b)| a == b || a == "-D")
            });
            assert!(paired, "no delete paired with `{add}`");
        }
    }

    #[test]
    fn teardown_is_entirely_best_effort() {
        let plan = plan_for("10.128.3.7");
        let cmds = net().teardown_commands(&plan);
        assert!(cmds.iter().all(|c| c.ignore_failure));
        assert_eq!(
            cmds.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
            vec!["ip link del veth7", "nsenter --mount=/proc/1/ns/mnt -- ip netns del acct"]
        );
    }

    /// A `Stop` carries a workload id and nothing else, so teardown has to be
    /// reachable from the same string `setup` derived the namespace name from.
    /// If these two ever disagree, every stopped workload leaks a namespace and
    /// its address, and the leak is invisible until the node runs out of one.
    #[test]
    fn teardown_from_a_stop_names_the_same_namespace_setup_created() {
        let plan = net().plan("forge.87802530", "10.128.3.7".parse().unwrap()).unwrap();
        assert_eq!(plan.netns, "forge-87802530");
        assert_eq!(
            teardown_by_workload("forge.87802530")
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>(),
            vec!["nsenter --mount=/proc/1/ns/mnt -- ip netns del forge-87802530"]
        );
    }

    #[test]
    fn a_custom_range_and_bridge_are_honoured() {
        let net = ContainerNet::new(Ipv4Cidr::parse("172.20.0.0/14").unwrap(), "br-yah");
        let plan = net.plan("acct", "172.21.9.4".parse().unwrap()).unwrap();
        assert_eq!(plan.subnet.to_string(), "172.21.9.0/24");
        assert_eq!(plan.gateway, "172.21.9.1".parse::<Ipv4Addr>().unwrap());
        assert!(
            net.setup_commands(&plan)
                .iter()
                .any(|c| c.to_string() == "ip link set veth4 master br-yah")
        );
        assert!(net.plan("acct", "10.128.3.7".parse().unwrap()).is_none());
    }

    #[test]
    fn a_malformed_range_is_refused_rather_than_defaulted() {
        assert!(Ipv4Cidr::parse("10.128.0.0").is_err());
        assert!(Ipv4Cidr::parse("10.128.0.0/33").is_err());
        assert!(Ipv4Cidr::parse("not-an-address/9").is_err());
    }
}

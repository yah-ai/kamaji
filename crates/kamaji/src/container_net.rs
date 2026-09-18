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
//! ## Tenant isolation (W206, R895-F3)
//!
//! W206's rule: workloads of different tenants co-resident on one node must not
//! share a layer-2/3 network; workloads of the *same* tenant (any namespace)
//! may; and the single-tenant case costs nothing. W343 §"Tenant isolation"
//! holds the design argument; the mechanism is:
//!
//! - **The singleton tenant is today's wiring, unchanged.** Every workload whose
//!   `WorkloadSpec.tenant` is [`TenantId::singleton`] hangs off the node bridge
//!   (`yah0`), which carries the gateway as `/24`. No extra bridge, route or
//!   rule exists on a node that only ever sees that tenant.
//! - **Every other tenant gets its own bridge on the node** —
//!   [`ContainerNet::bridge_for`], `yah0-<50-bit hash>` — so it shares no
//!   layer 2 with anyone else. The bridge carries the *same* gateway as a
//!   `/32`, and each workload gets a `/32` host route onto it. The tenant shares
//!   the node's `/24` rather than being given a slice of it, so yubaba's
//!   allocator (W343 step 4) stays tenant-blind and kamaji still recovers
//!   everything from one address.
//! - **Layer 3 is closed twice, by two owners that fail independently.**
//!   1. *Routing* (`ip rule`, which no firewall tool flushes):
//!      `iif <tenant br> to <node /24> prohibit`, and per tenant workload
//!      `iif <node bridge> to <addr>/32 prohibit`. Traffic between two
//!      workloads on one bridge is bridged and never consults the FIB, and
//!      delivery to the node's own addresses hits the `local` table at
//!      priority 0 first, so neither rule touches traffic it should not.
//!   2. *Filter* (iptables FORWARD, generation-tagged so a redeploy never opens
//!      a gap): drops keyed on the interface, not on addresses.
//!
//!   An `iptables -F`, `iptables-restore` without `--noflush` or a
//!   `netfilter-persistent reload` removes layer 2 and leaves layer 1 standing,
//!   so a node whose FORWARD policy is ACCEPT is still closed. The filter is
//!   needed in *any* per-tenant design — the node forwards between its own
//!   connected subnets — which is why a per-tenant `/24` was not chosen: it
//!   would cost address plan and buy no isolation.
//! - **Anti-spoof does not trust the sysctl.** The kernel's effective
//!   `rp_filter` is `max(conf.all, conf.<iface>)`, so a node with `all=2` gets
//!   loose mode whatever the bridge says. A `raw PREROUTING -m rpfilter
//!   --invert -j DROP` on the tenant bridge enforces strict reverse-path on its
//!   own. Isolation does not depend on it — both layers above are keyed on
//!   interfaces — but without it a workload can egress under a source outside
//!   the `/24`, which the MASQUERADE rule does not rewrite, and can impersonate
//!   another workload's address to anything address-keyed off the node.
//! - **Node services and the operator mesh are closed to tenant bridges.**
//!   INPUT drops everything but ICMP and replies arriving on a tenant bridge,
//!   so `.1`, the node's mesh address (yubaba `:7443`) and every other node
//!   address are unreachable. `iif <tenant br> to 100.64.0.0/10 fwmark
//!   0/(GRANT|REPLY) prohibit` plus a FORWARD drop of non-reply traffic deny
//!   new connections into the mesh pool, while mesh clients that dial a tenant
//!   workload still get through: mangle marks their packets and the replies
//!   [`FWMARK_REPLY`], and kamaji asserts `net.ipv4.conf.all.src_valid_mark=1`,
//!   because the kernel's reverse-path check on a packet *entering* a tenant
//!   bridge reads the same prohibit (see `tenant_isolation`). A
//!   container's resolver is never a node address — see
//!   `kamaji_containerd_core::resolver_mount_source`, which binds upstream
//!   servers and discards loopback stubs — so INPUT carries no DNS exception.
//! - **IPv6 is off on tenant bridges.** W343 is v4-only, so every layer above
//!   is IPv4. `net.ipv6.conf.<tenant bridge>.disable_ipv6=1` (in
//!   [`tenant_isolation`]) flushes the bridge's link-local and makes `ip6_rcv`
//!   drop every v6 packet arriving on it, before INPUT and before the forward
//!   decision — so a workload cannot reach node services on `::` at
//!   `fe80::<bridge>%eth0` or push v6 into the mesh range, both of which were
//!   reproduced on a real kernel before the fix. The container namespace keeps
//!   IPv6 (it may bind `[::]` for its own v4 service); the boundary closes at
//!   the bridge, every workload's only L3 ingress. The singleton `yah0` is
//!   unchanged.
//!
//! Keyed on the tenant id rather than on "how many tenants are on this node
//! right now", because the second is not a pure function of one deploy: the
//! first cross-tenant arrival would have to re-wire workloads already running.
//!
//! Limits, stated plainly:
//! - **INPUT isolation is iptables-only.** Local delivery is decided by the
//!   `local` table at rule priority 0, before any policy rule can see the
//!   packet, so there is no routing-layer backstop for node services. A flush
//!   of INPUT reopens them.
//! - **The mesh deny depends on mangle for replies.** After a mangle flush the
//!   reply mark is gone and replies to mesh clients are prohibited: a visible
//!   ingress outage, never a leak.
//! - **A MagicDNS node breaks tenant DNS.** tailscaled's resolver is
//!   `100.100.100.100`, inside the mesh pool, so a tenant container bound to it
//!   cannot resolve. No fleet node was on MagicDNS when this was written.
//! - **Other nodes' container `/24`s are reachable** (the rest of
//!   `10.128.0.0/9`). Isolation between nodes is mesh-ACL territory, as is the
//!   explicit cross-tenant opt-in (`MeshPeer::CrossTenant`, R895-F4). Every
//!   layer here already honours its seam: a packet carrying [`FWMARK_GRANT`]
//!   is exempt from every prohibit and every FORWARD drop, so F4 only sets
//!   marks (contract at `tenant_isolation`).
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
//!
//! @yah:ticket(R895-F1, "Migrate MeshAssignment.netns_name consumers onto container_net's netns so one owner remains")
//! @yah:status(review)
//! @yah:at(2026-09-13T20:23:30Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R895)
//! @yah:next("Tier: Wizard — the code motion is small but the design question (where WireGuard lives relative to the bridge) decides the fleet's data plane. Consumers to migrate: socket_custody (containerd.rs:565 binds inside mesh.netns_name), jit.rs:287, sibling.rs:696 (forwards it over the wire). Target state: container_net's derived netns (netns_name(workload), this file :558) is the ONE namespace a workload lives in; a workload's address is the W343 routed 10.128.x.y, and the WG/mesh path reaches it via the node's advertised subnet route rather than a per-workload WG netns. SETTLE FIRST, by reading not guessing: whether any live workload still receives a Some(netns_name) from yubaba today (if none does, the migration is deleting a dead parameter plus repointing socket custody at container_net's namespace; if some do, sequence the roll — the field crosses the postcard wire, so removal is a coordinated protocol bump like R885-T6, not a hot ship). Acceptance names a call site: socket custody binding a listener inside a container_net-created namespace on the live deploy path, not a unit test of the path helper.")
//! @yah:gotcha("Protocol-version collision resolved with @Ashguard:vortex (R896, session:530c4610), 2026-09-13. R895-F1 takes V12 in oss/kamaji/crates/kamaji-proto/src/version.rs for the netns_name field removal; R896-F2 landed after it, took V13, and moved CURRENT to V13. CURRENT = Self::V13 is CORRECT — do not revert it to V12 when reading this ticket, that would silently undo R896-F2. V12's stanza and variant are untouched by them. Checked and agreed by both sides: YubabaToKamaji::Deploy (messages.rs:399-404) carries `mesh: Option<MeshAssignment>` as a SIBLING of `spec`, and R896-F2's name-keyed envelope wraps only `spec` — so MeshAssignment remains positional postcard and the V12 removal analysis is unaffected.")
//! @yah:gotcha("Do NOT file a followup for wrapping `mesh` in R896-F2's name-keyed envelope — it is already owned and tracked on the R896 side. @Ashguard:vortex deliberately left `mesh` positional because MeshAssignment was mid-flight under this ticket; wrapping it once V12 lands would make future MeshAssignment field changes free of a protocol bump. That intent is durably recorded on R896-F2 via its notify_on(R895-F1), which fires when this ticket reaches review. Duplicating it under R895 would put two owners on one change.")
//! @yah:handoff("LANDED — the dead parameter is gone and socket custody now takes its namespace from the site that creates it. (1) `netns_name` deleted from BOTH `MeshAssignment` structs (runtime `oss/kamaji/crates/kamaji/src/lib.rs`, wire mirror `oss/kamaji/crates/kamaji-proto/src/messages.rs`), from `MeshAssignment::inlined`, from both pass-through conversions (`kamaji-bin/src/server.rs` `runtime_mesh`, `kamaji/src/sibling.rs` `mesh_to_proto`) and from all four raw test literals (server.rs x3, `oss/yubaba/crates/yubaba/src/lib.rs` x1 — that one file is dirty under @Miravel:libra's R880, so it got exactly the one-line deletion and nothing else). (2) `ProtocolVersion::V12` added with a stanza in the V11/R885-T6 style naming the removal and citing R895-F1. NOTE FOR THE READER: `CURRENT` is `V13`, not V12 — @Ashguard's R896-F2 (tolerant name-keyed payload envelope) landed in version.rs beside this work and took the next number; both stanzas are in the file and its V13 text references V12 explicitly. R896-F2 wrapped only `spec` on `Deploy`; `mesh: Option&lt;MeshAssignment&gt;` is a sibling field and stays positional postcard, so the V12 removal reasoning is unaffected.")
//! @yah:handoff("THE CUSTODY REPOINT, one owner end to end. The namespace name now flows DOWN the deploy path from the site that created it, and is never re-derived. `kamaji-bin/src/server.rs` `build_container_netns` already returned the `NetnsPlan`'s path; `deploy_container` passes it to `ContainerdBackend::deploy(id, spec, netns)`, which now hands it to `deploy_custody(id, spec, netns)` instead of dropping it. There: a host-networked passway (the F5 ingress, the only in-tree custody consumer) binds in the host netns as before; any other passway binds inside the container_net namespace via the new `custody_bind_and_hold(ident, bind_addr, netns)`, and `passway_pod_options(spec, netns)` sets `join_netns` to the SAME path so the process and the fd it adopts share one network view. A non-host-networked passway with no namespace is REFUSED (InvalidSpec naming --container-net and R881-T4) rather than silently host-bound — binding on the host would hand the workload a listener on an address that is not its own. Nothing calls `container_net::netns_name(workload)` speculatively; the only caller remains `ContainerNet::plan()`.")
//! @yah:handoff("DISCOVERED WORK, all inside the blast radius and all done here. (a) `graceful_upgrade` had no namespace source — its frame carries no MeshAssignment and re-running `build_container_netns` would DELETE the namespace (setup_commands opens with a teardown) and with it the held socket. Fixed by asking the owner that already holds the namespace open: `SocketCustodian` now records the bind's netns path beside the fd it already held, exposed as `held_netns(ident)` (`kamaji/src/socket_custody.rs`), and graceful_upgrade threads that into `passway_pod_options` and into both redeploy fallbacks. (b) The INLINED containerd backend (`kamaji/src/containerd.rs`, the desktop shape) had `custody_netns(spec, mesh)` as its only netns source; with the field gone it creates no namespace at all, so `custody_netns` is deleted and `deploy_custody` refuses a non-host-networked passway with a message naming where isolated-netns custody does live. Previously that case bound the host socket silently. (c) `socket_custody::netns_path` deleted — a second spelling of `/var/run/netns/&lt;name&gt;` beside `container_net::netns_path`, and two spellings of one path is how custody came to bind in a namespace nothing created; a comment at the old site says so. (d) `jit.rs deploy_on_demand` binds in the host netns explicitly: a JIT workload is a forked host process, nothing creates a namespace for it, and an always-None parameter is the same dead parameter this ticket deletes. (e) Stale prose corrected: the socket_custody module header (was \"a WireGuard netns (MeshAssignment.netns_name)\"), `ContainerdBackend::deploy`'s \"a custody workload ignores it\" paragraph, and the dangling `kamaji::socket_custody::netns_path` reference inside R881-T3's @yah:assumes on server.rs.")
//! @yah:gotcha("THE HANDSHAKE REJECTS A SKEWED PEER, IT DOES NOT MISPARSE — asked because it decides the roll ordering, answered by reading both directions. Old yubaba -&gt; new kamaji: `handle_message` at kamaji-bin/src/server.rs:1409 is a strict `version != ProtocolVersion::CURRENT`, replying `ErrorCode::UnsupportedVersion` naming the version, which `kamaji::sibling::KamajiClient::connect` surfaces as `ClientError::Remote` from connect itself. New yubaba -&gt; old kamaji: the new discriminant is not in the old peer's `#[non_exhaustive]` enum, so the Hello frame fails to decode at server.rs:1368-1386 — `Error { code: Internal, message: \"decode failed: ...\" }` and the connection is dropped. Either direction fails at CONNECT, before any Deploy frame is parsed, so a `MeshAssignment` is never decoded across the skew. Consequence for the roll: this is a PAIRED ship (`scripts/hotship.sh --binaries yubaba,kamaji`); shipping one alone leaves the node's kamaji up and reporting healthy with NRestarts=0 while every yubaba call fails at connect — the exact failure kamaji-bin/src/main.rs's R605-F23 note already records for V9.")
//! @yah:gotcha("THE WIRING IS COMPLETE AND STILL DORMANT ON EVERY NODE, by design and unchanged by this ticket — do not read a green build as \"custody now binds in a routed namespace in production\". TWO SWITCHES, both off, both named at kamaji-bin/src/server.rs:2030-2033 (R881-T3): (1) `--container-net CIDR` / `$KAMAJI_CONTAINER_NET` is opt-in and no node's kamaji.service passes it; (2) even with the flag, `ContainerNet::plan()` returns None for every workload because yubaba still sends the NODE's own mesh address in `mesh_ip` for everybody — per-workload allocation is R881-T4 and is not done. With plan() -&gt; None, `build_container_netns` returns Ok(None) and every custody bind lands in the host netns exactly as before this change. The refusal path added here therefore fires for nobody today: the only in-tree custody consumer (the F5 passway ingress) is host-networked. Safe roll order is unchanged: R881-T4 first (or same release), then the flag, then R881-T5's route advertisement.")
//! @yah:verify("MEASURED, exit codes echoed rather than inferred. oss/kamaji: `cargo build --manifest-path oss/kamaji/Cargo.toml` exit 0; `cargo check --workspace --all-features --all-targets` exit 0 with only the two pre-existing warnings R881-T3's verify already names (yah-object-store `parse_list_v2` dead_code, kamaji-bin `events_tx`) plus a pre-existing default-features-only `control_sock_from_spec` dead_code; `cargo test --workspace --all-features` KAMAJI_TEST_EXIT 0, zero failures — kamaji lib 317, kamaji-bin lib 294, kamaji-proto 18, sibling_wire_e2e 2, and 20 smaller targets. Baseline for that comparison is R881-T3's recorded run of the same command (exit 0, zero failures); a pre-change baseline of my own was not taken, because this tree is shared and 225 paths dirty. oss/yubaba: `cargo check --workspace --all-targets` YUBABA_CHECK_EXIT 0; the one test literal touched there passes (`yubaba::bundle_deploy_tests::bundle_workload_is_kind_tagged_in_json_and_variant_indexed_on_the_wire`, 1 passed). New tests: `socket_custody::tests::a_host_bound_listener_reports_no_netns` (darwin, passes) pins the host arm of `held_netns`; the `Some` arm is asserted in `tests/socket_custody_netns_linux.rs::custodian_holds_a_netns_scoped_listener`, which is `#![cfg(target_os = \"linux\")]` and therefore COMPILED ONLY — `cargo zigbuild -p kamaji --features socket-custody --target x86_64-unknown-linux-gnu --test socket_custody_netns_linux` finished clean; it has never been executed, this is a Mac.")
//! @yah:gotcha("PRE-EXISTING ROOT-WORKSPACE BREAKAGE, NOT MINE AND NOT FIXED HERE (shared-tree rule — it is a live peer's in-flight change and does not block this ticket). `cargo check --workspace --all-targets` from the repo root fails with `error[E0063]: missing field `health` in initializer of `WorkloadEntry`` at crates/yah/cloud-admin/src/lib.rs:1557. That is `yah_fleet_metrics::WorkloadEntry`, an entirely different type from `kamaji_proto::WorkloadEntry` and untouched by R895-F1: crates/yah/fleet-metrics/src/lib.rs was modified 2026-09-13 01:51 while cloud-admin/src/lib.rs still dates to 2026-08-12, i.e. someone added the field and left this construction site stale. Whoever owns the fleet-metrics `health` field should sweep that literal. A transient second failure seen mid-run (kamaji-proto `tolerant.rs` referencing an undeclared serde_json) was @Ashguard's R896-F2 landing half a crate at a time and resolved itself once its Cargo.toml edit landed.")
//! @yah:verify("NOT FULLY VERIFIED, stated plainly: a dedicated `cargo check -p yah-hub --all-targets` / `-p desktop --all-targets` was submitted but sat queued behind other camps' builds on the shared root target dir past this session's end. What IS known: two complete `cargo check --workspace --all-targets` runs from the repo root surfaced no error in either crate — the only error was the unrelated yah-cloud-admin/fleet-metrics `health` one recorded in the gotcha above — and a tree-wide `rg netns_name` now matches nothing outside prose. Both crates reach `MeshAssignment` only through `MeshAssignment::inlined()` (crates/yah/hub/src/workload.rs:10,22; app/yah/desktop/src/shell_host.rs:220) or as a borrowed parameter (app/yah/desktop/src/kamaji.rs:402,450), and `inlined()`'s signature is unchanged, so neither should have a call site to move. Re-run those two checks to close it.")
//! @yah:handoff("LEADER SIGN-OFF (Ashguard:blade, R895 relay lead, 2026-09-13). Implementation by @Glimmerstone:polaris, independently re-verified by @Miravel:polaris on a separate session rather than taken on the implementer's word. Accepting. The ticket's acceptance criterion — socket custody binding inside a container_net-created namespace on the LIVE DEPLOY PATH rather than in a unit test of the path helper — is met: kamaji-bin threads build_container_netns's namespace through deploy_container -> ContainerdBackend::deploy -> deploy_custody -> custody_bind_and_hold/passway_pod_options, and nothing re-derives it. The SETTLE-FIRST question the ticket demanded be answered by reading was answered by exhaustive enumeration: no `Some(netns_name)` producer exists anywhere in the tree, so this was a dead-parameter deletion, not a live migration.")
//! @yah:verify("INDEPENDENT RE-VERIFICATION (session:c89c2d65, separate from the implementer). cargo check -p yah-hub --all-targets exit 0, clean — this closes the one gap the implementer left open. cargo check --manifest-path oss/yubaba/Cargo.toml --workspace --all-targets exit 0. cargo test --manifest-path oss/kamaji/Cargo.toml --workspace --all-features exit 0, zero real failures (kamaji lib 318, kamaji-bin lib 294, kamaji-proto lib 39, cheers_mock 18, ~15 integration targets). version.rs confirmed by reading: V12 variant and stanza present, CURRENT = Self::V13, R896-F2's V13 stanza intact. TWO HONEST DISCREPANCIES, neither material: the implementer's reported sub-counts were slightly off (317 vs actual 318; \"kamaji-proto 18\" was actually kamaji-proto 39 + cheers_mock 18) though its substantive exit-0/zero-failure claim held; and one interim run hit a single failure in tenant_passway::deploy_arms_the_declared_socket_and_stop_releases_it, a TCP-port TOCTOU race that passed in isolation and on rerun — confirmed pre-existing flake, not a regression.")
//! @yah:assumes("TWO THINGS SIGNED OFF WITHOUT DIRECT EXECUTION, stated plainly rather than buried. (1) `cargo check -p desktop --all-targets` currently FAILS, and was NOT green at sign-off. The errors are E0432/E0425 on LegacyServiceConfig/LegacyMirrorConfig in oss/yubaba/crates/cloud/{lib,config}.rs — i.e. they are R895-T2's in-flight deletion landing in the same tree, produced by this relay's own sibling courier @Miravel:griffin, and contain nothing about MeshAssignment or netns. Attribution was established by reading the errors and cross-checking camp.roster, not inferred. Desktop must be re-checked once R895-T2 lands; it cannot be independently green before then. (2) The Some-arm of the new SocketCustodian::held_netns is exercised only by tests/socket_custody_netns_linux.rs, which is #![cfg(target_os = \"linux\")] and has been COMPILED (cargo zigbuild, clean) but NEVER EXECUTED — this camp runs on macOS. The host arm is covered by a passing darwin test. So the namespace-scoped bind path is compile-verified and behaviour-unverified, and will stay that way until something runs it on Linux.")
//! @yah:verify("DESKTOP ASSUMPTION RESOLVED — my earlier attribution was WRONG, and the corrected facts make this ticket's verification STRONGER, not weaker. NOT REOPENING; here is the reasoning, explicitly overriding the verifying courier's recommendation that I should. What I recorded at sign-off was that `cargo check -p desktop` was red ONLY because of R895-T2's in-flight LegacyServiceConfig deletion. That was wrong: desktop is still red after T2's deletion is complete and green, and the cause is entirely outside the LegacyServiceConfig family. The sole distinct error is `error[E0382]: use of moved value: orig_job` at app/yah/desktop/src/agent.rs:6364:14 (1 in desktop lib, the same 1 in desktop lib-test). WHY THIS NEVERTHELESS CLEARS R895-F1: E0382 is a BORROW-CHECK error, and rustc runs borrowck only after the crate type-checks. So desktop type-resolved cleanly with this ticket's change in place — which is precisely the question F1 needed answered, since app/yah/desktop/src/shell_host.rs:220 constructs a MeshAssignment and a deleted field would have failed at type resolution (E0560/E0609), not at borrowck. A missing-type error is the shape F1 breakage would take; a move error is not. Confirmed further: zero occurrences of LegacyServiceConfig / LegacyMirrorConfig / legacy_services / compose / ServiceCommands anywhere in the build output, and desktop's dependency leg compiled `yah` (lib) at 26 warnings / 0 errors. The run also carried an explicit \"no skew\" verdict from the daemon, so its input closure was unchanged throughout and this is a measurement rather than a racing-tree artifact.")
//!
//! @arch:see(.yah/docs/working/W206-yubaba-namespace-tenancy-axes.md)

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use workload_spec::TenantId;

mod grants;
mod reconcile;
pub use grants::{
    Grant, Tenancy, apply_grant_neighbours, grant_commands, grants_for, identity_mark,
};
pub use reconcile::{Reconciled, reconcile};

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

/// What a failed [`Cmd`] means for the plan it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFailure {
    /// Stop the plan: the step's effect is required.
    Fatal,
    /// Carry on. This is how idempotency is expressed for deletes: a teardown
    /// of a link that is already gone, or a delete of a rule that was never
    /// added, is the normal case after a crash-loop and must not fail the
    /// deploy that follows it.
    Ignore,
    /// Carry on only when what the command adds is already there
    /// (`File exists`); any other failure is fatal. For `ip rule add`, whose
    /// duplicate behaviour is the kernel's call: a kernel that checks for an
    /// identical rule refuses the second copy with `EEXIST`, which is the
    /// desired state, and one that does not appends a duplicate and succeeds.
    /// Plans here are shaped so both converge (see [`reassert_prohibit`]).
    ExistsOk,
}

/// One privileged host command, with what its failure means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub bin: &'static str,
    pub args: Vec<String>,
    pub on_failure: OnFailure,
}

impl Cmd {
    fn with(bin: &'static str, args: Vec<String>, on_failure: OnFailure) -> Self {
        Cmd {
            bin,
            args,
            on_failure,
        }
    }

    fn new(bin: &'static str, args: &[&str]) -> Self {
        Cmd::with(bin, strings(args), OnFailure::Fatal)
    }

    fn best_effort(bin: &'static str, args: &[&str]) -> Self {
        Cmd::with(bin, strings(args), OnFailure::Ignore)
    }

    /// `iptables -w …`. Every iptables invocation here waits for the xtables
    /// lock: a tenant deploy issues a few dozen of them, concurrent deploys
    /// contend for that lock, and without `-w` the loser fails ("Another app is
    /// currently holding the xtables lock") instead of waiting its turn.
    fn iptables(args: &[&str], on_failure: OnFailure) -> Self {
        let mut all = vec!["-w".to_string()];
        all.extend(strings(args));
        Cmd::with("iptables", all, on_failure)
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
        Cmd::with("nsenter", args, self.on_failure)
    }
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| a.to_string()).collect()
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

    /// The bridge a tenant's workloads hang off on this node (W206, R895-F3).
    ///
    /// The singleton tenant gets the node bridge itself, which is what keeps a
    /// single-tenant node's wiring exactly as it was. Any other tenant gets
    /// `<first 4 of the node bridge>-<10 base32 chars>`: exactly the 15
    /// characters `IFNAMSIZ` allows, spent on hash rather than stem. The hash is
    /// FNV-1a 64 xor-folded to 50 bits ([`tenant_bridge_suffix`]).
    ///
    /// Two tenants whose ids collide share a bridge, and with it their
    /// isolation, so the width matters: at 50 bits a collision is expected
    /// around 2^25 tenants on one node, against the 2^16 of the 32-bit name
    /// this replaced. FNV rather than `DefaultHasher` because the name outlives
    /// the process that computed it — a bridge created by one kamaji build is
    /// found by the next.
    ///
    /// The widening changed the name of every non-singleton tenant's bridge
    /// (from `yah0-<8 hex>`). No migration exists because none is needed: no
    /// non-singleton tenant had deployed anywhere in the fleet when it changed.
    pub fn bridge_for(&self, tenant: &TenantId) -> String {
        if tenant.is_singleton() {
            return self.bridge.clone();
        }
        format!(
            "{}{}",
            self.tenant_bridge_prefix(),
            tenant_bridge_suffix(tenant.0.as_bytes())
        )
    }

    /// What every per-tenant bridge on this node is named with — the node
    /// bridge's first four characters and a `-`.
    fn tenant_bridge_prefix(&self) -> String {
        let stem: String = self.bridge.chars().take(4).collect();
        format!("{stem}-")
    }

    /// Is `name` a per-tenant bridge this node made?
    ///
    /// Deliberately exact rather than a prefix test: [`reconcile`] deletes what
    /// this admits, and the node is shared with docker, tailscale and whatever
    /// an operator left behind. Only the ten base32hex characters
    /// [`tenant_bridge_suffix`] emits qualify, so `yah0-scratch` is not a
    /// tenant bridge and is never touched.
    pub fn is_tenant_bridge(&self, name: &str) -> bool {
        let Some(suffix) = name.strip_prefix(&self.tenant_bridge_prefix()) else {
            return false;
        };
        suffix.len() == 10
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'v').contains(&b))
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
    ///
    /// `tenancy.tenant` picks the bridge ([`ContainerNet::bridge_for`]) and never
    /// the address: every tenant on a node draws from the same `/24`. Its
    /// identity and `allow_from` become the plan's cross-tenant grants
    /// ([`grants`], R895-F4).
    pub fn plan(
        &self,
        workload: &str,
        container_ip: Ipv4Addr,
        tenancy: &Tenancy,
    ) -> Option<NetnsPlan> {
        let tenant = &tenancy.tenant;
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
            bridge: self.bridge_for(tenant),
            tenant_isolated: !tenant.is_singleton(),
            identity_mark: identity_mark(&tenancy.fq_identity),
            grants: grants_for(self, tenancy),
        })
    }

    /// Node-wide setup for the bridge this plan hangs off: the bridge, its
    /// gateway address, forwarding, and the egress NAT rule — plus, for a
    /// per-tenant bridge, the isolation rules. Idempotent, and cheap enough to
    /// re-run on every deploy rather than tracked as node state that could drift
    /// from the kernel's.
    pub fn bridge_commands(&self, plan: &NetnsPlan) -> Vec<Cmd> {
        let bridge = plan.bridge.as_str();
        let subnet = plan.subnet.to_string();
        // The node bridge owns the `/24` as a connected route. A tenant bridge
        // must not also claim it — two connected routes for one prefix and the
        // kernel picks one bridge for everybody — so it holds the gateway as a
        // `/32` (still answering ARP for it) and each workload brings its own
        // host route in `setup_commands`.
        let gateway_cidr = if plan.tenant_isolated {
            format!("{}/32", plan.gateway)
        } else {
            format!("{}/{}", plan.gateway, plan.subnet.prefix_len())
        };
        let mut cmds = vec![
            // `ip link add` on an existing bridge is an error, and that error is
            // the steady state after the first deploy.
            Cmd::best_effort("ip", &["link", "add", "name", bridge, "type", "bridge"]),
            Cmd::best_effort("ip", &["addr", "add", &gateway_cidr, "dev", bridge]),
            Cmd::new("ip", &["link", "set", bridge, "up"]),
            // Without this the bridge is a dead end: packets arrive from the
            // mesh interface and are never forwarded onto it.
            Cmd::new("sysctl", &["-w", "net.ipv4.ip_forward=1"]),
        ];
        // The pre-R895-F3 rule keyed `! -o <bridge>` used to be deleted here as
        // a migration. RETIRED 2026-09-15 (R895-T5) once the fleet was measured
        // clean: every `--container-net` node runs a kamaji carrying F3, and
        // the two that still held the old rule — us-east-001 (10.128.3.0/24)
        // and us-west-011 (10.128.10.0/24) — were converged by hand to the
        // form below. Nothing on the fleet carries it now.
        //
        // Delete-then-add rather than `-C`-then-add: one shape, no branch in the
        // executor, and no chance of accumulating a duplicate rule per deploy.
        // The rule names no bridge, so every bridge on the node re-asserts the
        // same single rule rather than adding one of its own.
        cmds.push(nat_rule(&subnet, "-D", OnFailure::Ignore));
        cmds.push(nat_rule(&subnet, "-A", OnFailure::Fatal));
        // Isolation before the ACCEPTs below, so a brand-new tenant bridge is
        // never forwarding without its drops, even for the length of one run.
        if plan.tenant_isolated {
            cmds.extend(tenant_isolation(&subnet, bridge, &self.bridge));
        }
        // A node running ufw has FORWARD defaulting to DROP, which silently
        // eats every packet the routing above just made possible.
        for direction in ["-i", "-o"] {
            cmds.push(Cmd::iptables(
                &["-D", "FORWARD", direction, bridge, "-j", "ACCEPT"],
                OnFailure::Ignore,
            ));
            cmds.push(Cmd::iptables(
                &["-A", "FORWARD", direction, bridge, "-j", "ACCEPT"],
                OnFailure::Fatal,
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
                &["link", "set", &plan.host_veth, "master", &plan.bridge],
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
        if plan.tenant_isolated {
            let host_route = format!("{}/32", plan.container_ip);
            // The routing half of "the node bridge cannot reach this workload"
            // (tenant_isolation holds the other direction, and the filter half
            // of both). Before the route below: until the route exists the
            // address is not reachable on this bridge at all, so the rule is in
            // place from the first moment it is.
            cmds.push(workload_rule("add", &self.bridge, &host_route));
            // The tenant bridge holds no `/24`, so without this the node routes
            // the address to the node bridge (or nowhere) and neither ingress
            // nor egress replies reach the workload.
            cmds.push(Cmd::new(
                "ip",
                &["route", "replace", &host_route, "dev", &plan.bridge],
            ));
        }
        cmds
    }

    /// Per-workload teardown. Entirely best-effort: deleting either end of a
    /// veth pair deletes both, and both this and the namespace are routinely
    /// already gone.
    ///
    /// The `/32` route and rule deletes run for every tenant, singleton
    /// included, because they are the leftovers that cross tenants: an address
    /// last held by another tenant's workload still has a host route onto
    /// *that* tenant's bridge and a prohibit from the node bridge, and a
    /// singleton workload reusing it would inherit both. On a node that never
    /// saw a second tenant they delete nothing.
    pub fn teardown_commands(&self, plan: &NetnsPlan) -> Vec<Cmd> {
        let mut cmds = vec![
            Cmd::best_effort("ip", &["link", "del", &plan.host_veth]),
            Cmd::best_effort("ip", &["netns", "del", &plan.netns]).in_host_mount_ns(),
        ];
        cmds.extend(self.address_gc_commands(plan.container_ip));
        cmds
    }

    /// The leftovers keyed on an address rather than on a namespace: the `/32`
    /// host route onto a tenant bridge, and the node bridge's prohibit towards
    /// it.
    ///
    /// Shared by [`Self::teardown_commands`], which knows the address because
    /// it holds a plan, and by [`reconcile`], which recovers it from the node —
    /// a `Stop` carries no address, so without the second caller these outlive
    /// every workload that ever ran. Both are best-effort: on a node that never
    /// saw a second tenant they delete nothing.
    pub fn address_gc_commands(&self, addr: Ipv4Addr) -> Vec<Cmd> {
        let host_route = format!("{addr}/32");
        vec![
            Cmd::best_effort("ip", &["route", "del", &host_route]),
            workload_rule("del", &self.bridge, &host_route),
        ]
    }

    /// Undo [`Self::bridge_commands`] for a per-tenant bridge the node's last
    /// workload of that tenant has left (R895-T5).
    ///
    /// Every rule is deleted before the link is, and that order is the point:
    /// `ip rule del ... iif <bridge>` matches by name, and a prohibit whose
    /// interface has already gone is left behind detached, to reattach to
    /// whatever bridge the kernel next gives that name. The link goes last and
    /// takes with it the gateway address, the `clsact` qdisc, and any grant ARP
    /// filter or proxy entry still hanging off it.
    ///
    /// Two things it deliberately leaves. The egress NAT rule
    /// ([`nat_rule`]) is one rule for the whole `/24`, shared by every bridge
    /// on the node — deleting it here would take internet egress away from
    /// every workload still running. `net.ipv4.ip_forward` is node-wide and was
    /// very likely on before kamaji touched it.
    ///
    /// Never called for the node bridge, which is the singleton tenant's and
    /// outlives every workload.
    pub fn bridge_gc_commands(&self, bridge: &str, subnet: Ipv4Cidr) -> Vec<Cmd> {
        debug_assert!(bridge != self.bridge, "the node bridge is never collected");
        let subnet = subnet.to_string();
        let mut cmds = Vec::new();
        // The FORWARD ACCEPTs bridge_commands adds beside the isolation rules.
        for direction in ["-i", "-o"] {
            cmds.push(Cmd::iptables(
                &["-D", "FORWARD", direction, bridge, "-j", "ACCEPT"],
                OnFailure::Ignore,
            ));
        }
        for rule in isolation_rules(&subnet, bridge, &self.bridge) {
            cmds.extend(rule.withdraw());
        }
        for (selector, priorities) in isolation_prohibits(&subnet, bridge) {
            let selector: Vec<&str> = selector.iter().map(String::as_str).collect();
            cmds.extend(withdraw_prohibit(&selector, priorities));
        }
        cmds.push(Cmd::best_effort("ip", &["link", "del", bridge]));
        cmds
    }
}

/// Teardown addressed by workload identity alone — which is all a `Stop`
/// carries. The address that named the veth pair is long gone by then, and
/// deleting the namespace is enough without it: a namespace's devices die with
/// it, and destroying one end of a veth pair destroys the other.
///
/// What it cannot reach is a per-tenant workload's `/32` host route, which is
/// keyed on the address. That route outlives the stop, pointing at a live
/// tenant bridge for an address nobody holds: traffic to it is dropped either
/// way, and the next deploy to claim the address deletes it first
/// ([`ContainerNet::teardown_commands`]).
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

/// The node's one egress NAT rule: masquerade what leaves the `/24` for
/// anywhere outside it.
///
/// Keyed on the *destination*, never on an interface. Every bridge on a node
/// holds the same `/24`, and with `br_netfilter` loaded (docker sets it) frames
/// between two ports of one bridge traverse nat POSTROUTING too. The earlier
/// `! -o <bridge>` form gave each bridge its own rule, so a frame between two
/// workloads on `yah0` matched a tenant bridge's `! -o yah0-…` and was rewritten
/// to `.1` — the workload's address stopped being its own (W343), and any
/// address-keyed rule behind it (R895-F4's grants) saw the gateway instead.
///
/// `! -d` alone is enough, and `! -o` adds nothing beside it: kamaji routes no
/// destination outside the `/24` onto a bridge, and a destination inside it that
/// leaves by the uplink has no route to be NATted onto. Naming no interface also
/// means it needs no uplink name, and so cannot be wrong about one.
fn nat_rule(subnet: &str, op: &str, on_failure: OnFailure) -> Cmd {
    Cmd::iptables(
        &[
            "-t",
            "nat",
            op,
            "POSTROUTING",
            "-s",
            subnet,
            "!",
            "-d",
            subnet,
            "-j",
            "MASQUERADE",
        ],
        on_failure,
    )
}

/// The two comment tags a re-asserted iptables rule alternates between
/// ([`reassert_tagged`]). The run always ends on the second, so the first
/// exists only mid-run.
const ISOLATION_GENERATIONS: [&str; 2] = ["yah-isolation-a", "yah-isolation-b"];

// ── Policy-routing priorities (R895-F3) ─────────────────────────────────────
//
// The kernel walks rules in ascending priority: `local` at 0, `main` at 32766.
// Everything here sits well before `main`, and an exception always sits before
// the rule it excepts. Fixed values, not allocated: a rule is found again by
// the next kamaji only if it is where that kamaji looks.

/// Per tenant workload: `iif <node bridge> to <addr>/32 fwmark 0/GRANT
/// prohibit`.
pub const WORKLOAD_RULE_PRIORITY: u32 = 1200;

/// Per tenant bridge, two generations: `iif <br> to <node /24> fwmark 0/GRANT
/// prohibit`.
pub const SUBNET_RULE_PRIORITIES: [u32; 2] = [1201, 1202];

/// Per tenant bridge, two generations: `iif <br> to 100.64.0.0/10 fwmark
/// 0/(GRANT|REPLY) prohibit`.
pub const MESH_RULE_PRIORITIES: [u32; 2] = [1203, 1204];

/// The `fwmark` selector every prohibit carries: matches only packets whose
/// [`FWMARK_GRANT`] bit is clear. Spelled out because `ip rule` takes it as a
/// string and a const fn cannot format one.
const NOT_GRANTED: &str = "0/0x2000000";

// ── Packet-mark bits (R895-F3 / R895-F4) ────────────────────────────────────
//
// The bits of `skb->mark` kamaji owns. tailscale owns `0x00ff0000` and nothing
// here may touch it. Every match is masked and every write is `--set-xmark`
// with a mask, so kamaji never clobbers a bit it does not own.
//
// Assumed, and recorded on R895-F3: no fleet node runs something else that
// marks inside 0xffff — kube-proxy's 0x4000/0x8000, or wg-quick's fwmark 51820.

/// R895-F4's per-peer identity, `1..=0xffff`; `0` means unmarked.
pub const FWMARK_IDENTITY_MASK: u32 = 0x0000_ffff;
/// Set in mangle PREROUTING on an ESTABLISHED/RELATED packet arriving on a
/// tenant bridge. The mesh prohibit matches only packets with this bit clear.
pub const FWMARK_REPLY: u32 = 0x0100_0000;
/// R895-F4's "this pair is granted" bit.
pub const FWMARK_GRANT: u32 = 0x0200_0000;

/// W206's isolation for one tenant bridge, in every layer that owns a piece of
/// it. Idempotent and gap-free under re-runs; see [`reassert_tagged`] and
/// [`reassert_prohibit`] for how.
///
/// - **Routing** (survives any firewall flush): `iif <br> to <node /24> fwmark
///   0/GRANT prohibit`, and `iif <br> to 100.64.0.0/10 fwmark 0/(GRANT|REPLY)
///   prohibit`. The node bridge's half, one rule per tenant workload, is in
///   [`ContainerNet::setup_commands`] with the same `0/GRANT` mask. The mesh
///   rule leaves reply-marked packets alone so a mesh client that dialled a
///   tenant workload gets its answer. Exceptions are masks on the *prohibit*,
///   never a `fwmark X lookup main` bypass above it, because a bypass that
///   names a table reroutes: replies to `100.64.x`, and anything to another
///   node's `/24`, are routed by tailscale's own table, and `main`'s default
///   route would send them out the uplink instead. An exempt packet simply
///   falls through to whatever routes it normally. The `/24` prohibit carries
///   no reply exception: no legitimate reply crosses it, since nothing on the
///   node bridge or another tenant bridge can open a connection to this one.
/// - **Anti-spoof**: `raw PREROUTING -i <br> -m rpfilter --invert -j DROP`,
///   plus `rp_filter=1` on the bridge as a flush-surviving backstop wherever
///   `conf.all` does not raise it to loose.
/// - **Reply mark**: `mangle PREROUTING -i <br> -m conntrack --ctstate
///   ESTABLISHED,RELATED -j MARK --set-xmark REPLY/REPLY`, and the same mark on
///   `-s 100.64.0.0/10 -d <node /24>`, with `net.ipv4.conf.all.src_valid_mark=1`.
///   The second rule and the sysctl exist because of the kernel's reverse-path
///   check, measured on us-west-003 (kernel 6.12) before they did: a packet
///   forwarded *into* the tenant bridge is validated by a rule lookup with
///   iif = the tenant bridge and the source as destination, so an unmarked
///   mesh client's SYN matched the mesh prohibit and was dropped as a martian
///   (rp_filter is 2 on `tailscale0`). That lookup sees the packet's mark only
///   under `src_valid_mark`, which is why kamaji asserts it rather than
///   inheriting whatever the node has.
/// - **Filter** (FORWARD), all DROP, keyed on interfaces: `-i <br> -d <node /24>
///   ! -o <br>` (leaving), `-o <br> -s <node /24> ! -i <br>` (entering),
///   `-i <node bridge> -o <br>` (from the singleton bridge whatever source it
///   claims, since the node bridge has no anti-spoof of its own), and
///   `-i <br> -d 100.64.0.0/10` for anything not a reply. `! -o`/`! -i` keep
///   same-bridge traffic out, which matters with `br_netfilter` loaded, where
///   frames between two ports of one bridge traverse FORWARD too. `-I` so the
///   drops sit above every `-A ... ACCEPT`, including ones a later deploy
///   re-appends.
/// - **INPUT**: `-i <br> ! -p icmp` DROP for anything not a reply. INPUT has no
///   routing-layer backstop: local delivery is decided at priority 0.
/// - **IPv6**: `net.ipv6.conf.<br>.disable_ipv6=1`, first, because W343 is
///   v4-only and every rule above is IPv4. Without it the bridge's link-local
///   reopens INPUT (node services on `::`) and, on a v6-forwarding node, the
///   mesh deny. `ip6_rcv` drops on the device before either, so no ip6tables
///   rule is needed; the container netns keeps v6 for its own `[::]` binds.
///
/// **The R895-F4 contract.** Every prohibit (the `/24`, the mesh pool, the
/// per-workload rule) and every FORWARD drop (leaving, entering, from the node
/// bridge, into the mesh) exempts packets whose [`FWMARK_GRANT`] bit is set —
/// masked `fwmark 0/GRANT` on the rules, `-m mark ! --mark GRANT/GRANT` on the
/// drops. F4 therefore adds no rule to any layer here and depends on no rule
/// order: it sets `FWMARK_GRANT` (plus identity bits in
/// [`FWMARK_IDENTITY_MASK`]) in mangle PREROUTING on exactly the packets of a
/// granted pair, in both directions (connmark for replies is F4's call), and
/// these layers honour it. INPUT and anti-spoof have no exemption: grants are
/// workload-to-workload, and a granted workload still sends from its own
/// address. Two traps for whoever writes those mark rules: the inbound half of
/// a pair must be marked too, not only replies, since the reverse-path check
/// on a packet entering a tenant bridge reads the prohibits (see the reply
/// mark above); and a reply to a masqueraded connection still carries the
/// node's address as destination at mangle PREROUTING (de-SNAT runs later in
/// that hook), so match it on the conntrack original tuple or a connmark,
/// not on `-d <workload>`.
///
/// A workload cannot forge the bit. `skb->mark` is scrubbed when a packet
/// crosses a veth into another namespace (`__dev_forward_skb` ->
/// `skb_scrub_packet` with `xnet`), so `SO_MARK` on a workload's socket or a
/// MARK rule inside its own namespace reaches the host as `0`. The Linux
/// isolation test asserts both.
///
/// Destinations outside the `/24` and the mesh pool are untouched: internet
/// egress, and ingress from the mesh, are the point of the bridge.
///
/// @arch:see(.yah/docs/working/W343-per-workload-mesh-addressing.md)
///
/// @yah:ticket(R895-T5, "R895-F3/F4 followups: drop the legacy NAT delete after the roll, GC tenant bridges and grant state, MagicDNS resolver collision")
/// @yah:status(review)
/// @yah:at(2026-09-16T05:02:54Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R895)
/// @yah:assumes("R895-F3 and R895-F4 were signed off by the operator on 2026-09-14 and archived; their full handoff and verify history lives in the event shard (board_show R895-F3 / R895-F4).")
/// @yah:handoff("2026-09-14 @Ashguard:spade (session:214f1a5d), operator-authorized via session:feb9540d: paired yubaba+kamaji hotship of the working tree at HEAD 7313635038766d046e9c4044ceef10686b5111f4 plus dirty R895-F3/F4 files (kamaji-bin/src/server.rs, kamaji/src/container_net.rs, container_net/grants.rs, tests/container_net_isolation_linux.rs; the only dirty paths under oss/kamaji, oss/yubaba, oss/yah-base; diff sha1 5b283ac0). @Ashguard:dove (R908) confirmed clear first; server.rs also carries R908-T1 hunks that were already live on these nodes (h7/h8).")
/// @yah:handoff("Dev group via scripts/hotship.sh --nodes us-west-011,us-west-013,us-west-014 --binaries yubaba,kamaji: stamp 0.8.40-h9, order 013,014,011 (leader 011 last). Installed kamaji sha256 3a8795dd..., yubaba cbda151b... on all three. Then us-west-001 alone: stamp 0.8.40-h10 (prod leader, raft 1/2/3 live before and after), kamaji 7f2df3a6..., yubaba d09e0650.... Dry-runs were clean for both; no proto skew (both halves shipped), --allow-proto-skew not used.")
/// @yah:handoff("Step (1) of this ticket (delete the legacy NAT MASQUERADE -D line) is now unblocked on us-west-001/011/013/014 and STILL waits on us-east-001, which was not in this ship and still runs pre-F3 kamaji. No workload deploy was triggered, so the scoped grant code has not been exercised on a live isolated-netns deploy yet.")
/// @yah:verify("Post-ship 2026-09-14: us-west-011/013/014 /health = yubaba 0.8.40-h9 + kamaji_version 0.8.40-h9, clustered; us-west-001 /health = 0.8.40-h10/0.8.40-h10. systemctl is-active kamaji+yubaba = active on all four. Dev raft leader 11, peers 11/13/14 live; prod raft leader 1, peers 1/2/3 live. On-node sha256 of /usr/local/bin/{kamaji,yubaba} equals the local build output (011 and 001 read by hand; 013/014 verified by hotship's install check).")
/// @yah:verify("KAMAJI_CONTAINER_NET=10.128.0.0/9 set (unit Environment= and live /proc environ) on us-west-011 and us-west-001; NOT set on us-west-013 or us-west-014 (sudo worked, environ has no match, unit has no reference), so the grant code is inert there.")
/// @yah:verify("The build includes R895 code: the newest R895 source edit (container_net.rs 17:56:27) is older than the kamaji builds (aarch64 17:58:47, x86_64 18:01:33), and both binaries contain the R895-F4 string 'cross-tenant grants for' from server.rs. us-west-001 cloud-admin (containerd, from R908) survived the kamaji restart: 100.64.0.1:4325 returns 401 before and after. Note: `yubaba --version` on 001 prints 0.8.39 while /health reports 0.8.40-h10 (hash matches the build). This looks like the CLI version string not picking up the hotship stamp; not investigated.")
/// @yah:handoff("ALL THREE STEPS DONE. (1) The legacy `iptables -t nat -D POSTROUTING -s <subnet> ! -o <bridge> -j MASQUERADE` migration line is deleted from ContainerNet::bridge_commands and from both pinned test scripts — but only after the fleet was measured, because the ticket's stated gate was the wrong one. Every --container-net node (us-east-001, us-west-001/011/013/014) ALREADY ran a kamaji carrying R895-F3, verified by `grep -a yah-isolation-a /usr/local/bin/kamaji` on each rather than by a version string. What actually blocked the deletion was that us-east-001 and us-west-011 still PHYSICALLY held the old rule and had never re-run bridge_commands since the roll, so removing the line would have stranded it there forever. Operator authorised convergence (ask_user, 2026-09-15); both nodes were converged by hand in the order kamaji itself uses — add `! -d <subnet>`, then delete `! -o yah0` — with the live workload's egress checked either side.")
/// @yah:handoff("(2) THE GC IS A KERNEL-DERIVED RECONCILE PASS, NOT NODE-SIDE BOOKKEEPING — the ticket offered both and the kernel wins for the reason bridge_commands is already idempotent rather than tracked: bookkeeping drifts, and it drifts silently across a crash, an upgrade or a reboot. New container_net::reconcile (oss/kamaji/crates/kamaji/src/container_net/reconcile.rs) reads `ip -o link show`, `ip -4 route show` and `ip -4 -o addr show`; recovers the node's /24 from whichever of its own bridges carries an address (the node bridge holds it as a /24, a tenant bridge as a /32, either names the same /24); and takes liveness off the host veth — a `veth<octet>` enslaved to a kamaji bridge IS a running workload, because `ip netns del` destroys the pair. A departed address loses its /32 host route, its priority-1200 prohibit, its yah-id/yah-gr chains and PREROUTING jumps, and every grant proxy entry and tc flower filter naming it — INCLUDING the half that sits on the surviving peer's bridge, which is the piece nothing keyed on the dead address would ever look at. A tenant bridge with no enslaved veth loses its four prohibits, all nine tagged raw/mangle/filter rules in both generations, its two FORWARD ACCEPTs, and last the link. It deliberately keeps the shared /24 NAT rule (one rule for every bridge on the node) and net.ipv4.ip_forward. Wired into the Stop path in kamaji-bin/src/server.rs after teardown_by_workload, non-fatally.")
/// @yah:handoff("(2b) TWO FRAMEWORK CHANGES MADE THAT SAFE, both inside this relay's files. isolation_rules() / isolation_prohibits() now hold ONE owned description of what tenant isolation installs, read by both the assert and the withdraw — so a rule can no longer be added in a form the GC does not know how to remove, and `collecting_a_tenant_bridge_deletes_every_rule_its_setup_asserted` checks that mechanically (inverse of every add) instead of against a literal expected script, which is the test shape that would have passed while a new rule leaked. And container_net::NodeStateGuard / lock_node_state() is now the single lock over every read-then-write of node network state, taken by reference: apply_grant_neighbours no longer holds a private mutex, and the deploy holds the lock from the first `ip link add` to the last grant write. Without it a concurrent Stop's GC would delete a bridge a deploy had just created and not yet enslaved a veth to.")
/// @yah:handoff("(3) THE MAGICDNS COLLISION IS LATENT, MEASURED, AND NOW GUARDED RATHER THAN FIXED. No --container-net node resolves through MagicDNS: /etc/resolv.conf on all three flagged nodes is the systemd-resolved loopback stub, which resolver_mount_source already ranks out, and /run/systemd/resolve/resolv.conf — the file an isolated namespace actually gets — names 213.186.33.99 (us-east-001, us-west-001) or 1.1.1.1 + 9.9.9.9 (us-west-011). New container_net::mesh_pool_nameservers() names any nameserver inside 100.64.0.0/10, and the deploy path warns for a tenant-isolated plan, naming the workload and the resolver. A warn and not a refusal: no DNS is a degraded workload rather than an unreachable one, and turning that into 'this node runs no tenant workloads' is an operator's call, not a deploy's. The full fix, if a node ever does collide, is to teach kamaji_containerd_core::resolver_mount_source that a tenant-isolated netns cannot reach the mesh pool — that needs the isolation fact plumbed through PodOptions and ContainerdBackend::deploy, and the reasoning is written down at the warn site rather than left in a ticket.")
/// @yah:handoff("DISCOVERED WORK, FIXED HERE RATHER THAN FILED: the `tenant_passway::deploy_arms_the_declared_socket_and_stop_releases_it` failure that R895-F1's verify note recorded as a one-off flake is not one. Measured 2026-09-15: it failed 3 full `cargo test -p kamaji-bin --all-features --lib` runs in 4 while passing every time its module ran alone. TWO independent causes, both fixed in kamaji-bin/src/server.rs. The assertion bound the released port exactly once, immediately after an Ack that only ORDERS the teardown — the custodian's fd closes a scheduler tick or two later — now a bounded 500ms retry, which keeps the assertion honest because a release that never comes still fails. And free_port() could hand the same ephemeral port to two of the module's five concurrent callers, since bind(:0)-and-drop returns the port to the reuse pool immediately — now a process-wide issued-port set. 1 run in 4 became 8 runs in 10 (see the gotcha for what the remaining 2 are, which is a different test).")
/// @yah:verify("MEASURED, exit codes read back from files rather than inferred from a pipe. oss/kamaji `cargo test --workspace --all-features`: KAMAJI_TEST_EXIT=0, 814 tests passed, zero failures. 14 new unit tests, all passing: 8 in container_net::reconcile::tests (node-state parsing against real `ip -o link show` / `ip -4 -o addr show` output captured from us-east-001 the same day, the /24 recovered from a tenant bridge's /32 gateway, a docker veth that would parse as ours if the master were not checked, and `yah0-scratch` / `yah0-zzzzzzzzzz` refused as bridge names kamaji cannot have generated), 3 in container_net::grants::tests driven through the existing kernel model (a stopped workload takes both halves of its grant path; a pass with everything live emits no command at all; draining the node leaves the mangle table literally empty), and 3 in container_net::tests (GC as the mechanical inverse of setup, the shared NAT rule and ip_forward explicitly NOT collected, and the address leftovers identical whether reached from a plan or from a sweep). `cargo zigbuild -p kamaji --all-features --target x86_64-unknown-linux-gnu --test container_net_isolation_linux` finished clean.")
/// @yah:verify("FLEET, 2026-09-15, read over ssh on each node rather than assumed. BEFORE: us-east-001 held `-A POSTROUTING -s 10.128.3.0/24 ! -o yah0 -j MASQUERADE` and not the new form; us-west-011 held the same for 10.128.10.0/24; us-west-001/013/014 held neither. AFTER: us-east-001 = `-s 10.128.3.0/24 ! -d 10.128.3.0/24`, us-west-011 = `-s 10.128.10.0/24 ! -d 10.128.10.0/24`, and no node anywhere carries a `! -o` form. Both converged nodes still have working workload egress — `curl https://1.1.1.1` from inside the live netns returned http=301 on us-east-001 BEFORE and AFTER the change (connect 0.0025s and 0.0023s) and http=301 on us-west-011 after. Every node's kamaji binary carries R895-F3 and R895-F4 (`grep -a` hits for yah-isolation-a, yah-gr-, src_valid_mark and 'cross-tenant grants for'); versions are 0.8.40-h15 on us-east-001 and us-west-001, 0.8.40-h20 on us-west-011/013/014 — both NEWER than the h9/h10 ship this ticket's own handoff records, so somebody rolled after it.")
/// @yah:gotcha("THE GC HAS NEVER RUN ON A REAL KERNEL, and it deletes bridges on a live node. tests/container_net_isolation_linux.rs gained phase (g), which deploys a throwaway tenant, stops it through the production path (`teardown_by_workload`, an identity and no address), runs reconcile, and asserts its bridge, prohibits, tagged rules, host route, mangle chains and proxy entries are gone while another tenant's survive and that tenant's workloads still talk. It cross-compiles clean for x86_64-unknown-linux-gnu. That file is #![cfg(target_os = \"linux\")] and this camp runs macOS, so it has been COMPILED and NEVER EXECUTED — every claim about the GC's behaviour against a kernel is a compile-time claim. Run it under `sudo -E` on a Linux node before the first fleet roll that carries this code.")
/// @yah:gotcha("A SECOND FLAKE REMAINS in the same kamaji-bin test module and is NOT the one fixed on this ticket: `tenant_passway::the_list_reports_the_digest_of_the_spec_it_was_deployed_with` failed 1 run in 8 of the full 299-test suite, while the whole tenant_passway module passed 12 consecutive runs in isolation. So it collides with a test OUTSIDE the module, not within it, and the process-wide issued-port set added here cannot see that collider. Not chased further. It belongs with R901's 'verification instruments that lie' family.")
/// @yah:assumes("us-west-013 and us-west-014 have no KAMAJI_CONTAINER_NET in their unit or live environ, so they can hold no container-net state at all; they were checked for the legacy NAT rule anyway and had none. They count toward the step-(1) roll gate on the strength of their binary carrying R895-F3, not on having ever exercised it.")
fn tenant_isolation(subnet: &str, bridge: &str, node_bridge: &str) -> Vec<Cmd> {
    let rp_filter = format!("net.ipv4.conf.{bridge}.rp_filter=1");
    let disable_ipv6 = format!("net.ipv6.conf.{bridge}.disable_ipv6=1");

    let mut cmds = vec![
        // W343 is v4-only, so every layer below is IPv4. A bridge and its
        // enslaved veths otherwise get IPv6 link-local addresses by default,
        // which reopens the whole design over v6: a workload reaches node
        // services on `::` at `fe80::<bridge>%eth0` (bypassing INPUT) and, on a
        // v6-forwarding node, pushes packets into the mesh v6 range (bypassing
        // the mesh deny). Both were reproduced on us-west-003 (kernel 6.12)
        // before this line. disable_ipv6=1 flushes the bridge's link-local and
        // makes ip6_rcv drop every v6 packet arriving on it — upstream of INPUT
        // and of the forward decision, so both close — with no ip6tables
        // dependency. It runs before any veth is enslaved (setup_commands is
        // later), so no workload can reach the bridge in the gap after `link
        // set up`. Not applied inside the container netns: the bridge is every
        // workload's only L3 ingress, so the drop here closes every
        // cross-boundary v6 path, and disabling v6 in the namespace would break
        // a workload that binds `[::]` for its own v4 service. The singleton
        // `yah0` is never passed here, so it keeps IPv6 unchanged.
        Cmd::new("sysctl", &["-w", &disable_ipv6]),
        // The kernel validates a packet forwarded INTO this bridge by looking
        // up the policy rules with iif = this bridge (route.c `__mkroute_input`
        // passes the output device; fib_frontend.c `__fib_validate_source` uses
        // it as `flowi4_iif`), so the prohibits below see that reverse lookup
        // too. It carries the packet's mark only under `src_valid_mark`
        // (`IN_DEV_SRC_VMARK`, all OR iface); without it every exemption below
        // reads as mark 0 in that lookup, and mesh ingress and granted pairs
        // die as martians on any ingress interface with rp_filter on.
        Cmd::new("sysctl", &["-w", "net.ipv4.conf.all.src_valid_mark=1"]),
    ];
    // Routing first: from here on the bridge is closed whatever iptables does.
    for (selector, priorities) in isolation_prohibits(subnet, bridge) {
        let selector: Vec<&str> = selector.iter().map(String::as_str).collect();
        cmds.extend(reassert_prohibit(&selector, priorities));
    }

    cmds.push(Cmd::new("sysctl", &["-w", &rp_filter]));
    for rule in isolation_rules(subnet, bridge, node_bridge) {
        cmds.extend(rule.assert());
    }
    cmds
}

/// The two routing-layer prohibits [`tenant_isolation`] puts on one tenant
/// bridge, as `(selector, priorities)` — see that function's doc comment for
/// what each one closes.
///
/// Owned and shared with [`ContainerNet::bridge_gc_commands`] for the reason
/// [`isolation_rules`] is: a prohibit deleted by a second spelling of its
/// selector is a prohibit that outlives its bridge.
fn isolation_prohibits(subnet: &str, bridge: &str) -> Vec<(Vec<String>, [u32; 2])> {
    let not_granted_or_reply = format!("0/{:#x}", FWMARK_GRANT | FWMARK_REPLY);
    vec![
        (
            strings(&["iif", bridge, "to", subnet, "fwmark", NOT_GRANTED]),
            SUBNET_RULE_PRIORITIES,
        ),
        (
            strings(&[
                "iif",
                bridge,
                "to",
                MESH_NODE_POOL,
                "fwmark",
                &not_granted_or_reply,
            ]),
            MESH_RULE_PRIORITIES,
        ),
    ]
}

/// Every tagged iptables rule [`tenant_isolation`] installs for one tenant
/// bridge, in the order it installs them — the anti-spoof drop, the two reply
/// marks, the four FORWARD drops, and the INPUT drop. See that function's doc
/// comment for what each layer is for.
///
/// One list, read by both the deploy ([`TaggedRule::assert`]) and the GC
/// ([`TaggedRule::withdraw`]), so a rule cannot be added in a form the GC does
/// not know how to remove. That was the actual failure mode here: a rule keyed
/// on an interface outlives the interface, and a stale `-i <bridge>` DROP
/// silently reattaches to whatever bridge the kernel next gives that name.
fn isolation_rules(subnet: &str, bridge: &str, node_bridge: &str) -> Vec<TaggedRule> {
    let reply_xmark = format!("{FWMARK_REPLY:#x}/{FWMARK_REPLY:#x}");
    let grant = format!("{FWMARK_GRANT:#x}/{FWMARK_GRANT:#x}");
    let replies = ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED"];
    let not_replies = ["-m", "conntrack", "!", "--ctstate", "ESTABLISHED,RELATED"];
    let not_granted = ["-m", "mark", "!", "--mark", grant.as_str()];
    let drop = ["-j", "DROP"];
    let mark_reply = ["-j", "MARK", "--set-xmark", reply_xmark.as_str()];

    let mut rules = vec![TaggedRule::new(
        "raw",
        "PREROUTING",
        &["-i", bridge, "-m", "rpfilter", "--invert"],
        &drop,
    )];
    let mut mark_replies = vec!["-i", bridge];
    mark_replies.extend(replies);
    rules.push(TaggedRule::new(
        "mangle",
        "PREROUTING",
        &mark_replies,
        &mark_reply,
    ));
    // Inbound from the mesh to a container address, NEW included. Not for the
    // forward lookup, which has iif = the mesh interface and meets no prohibit,
    // but for the reverse-path check above, which would otherwise match the
    // mesh prohibit and drop every mesh client's first packet.
    rules.push(TaggedRule::new(
        "mangle",
        "PREROUTING",
        &["-s", MESH_NODE_POOL, "-d", subnet],
        &mark_reply,
    ));

    let leaving = vec!["-i", bridge, "-d", subnet, "!", "-o", bridge];
    let entering = vec!["-o", bridge, "-s", subnet, "!", "-i", bridge];
    let from_node_bridge = vec!["-i", node_bridge, "-o", bridge];
    let mut into_mesh = vec!["-i", bridge, "-d", MESH_NODE_POOL];
    into_mesh.extend(not_replies);
    for mut matches in [leaving, entering, from_node_bridge, into_mesh] {
        matches.extend(not_granted);
        rules.push(TaggedRule::new("filter", "FORWARD", &matches, &drop));
    }

    let mut to_node = vec!["-i", bridge, "!", "-p", "icmp"];
    to_node.extend(not_replies);
    rules.push(TaggedRule::new("filter", "INPUT", &to_node, &drop));
    rules
}

/// Re-assert one iptables rule with no moment where it is absent.
///
/// Not delete-then-insert, which the NAT and ACCEPT rules use: that leaves the
/// rule missing for the gap between the two, on every deploy. With identical
/// rules and an executor that cannot branch, no sequence can both keep one copy
/// present throughout and end on exactly one copy from either zero or one — so
/// the rule carries a generation tag ([`ISOLATION_GENERATIONS`]): insert `a`,
/// delete `b`, insert `b`, delete `a`. Some copy is present from the first
/// insert on, and the run ends with one `b` whether it found none or one. Needs
/// `xt_comment`, which kube-proxy and docker also rely on.
fn reassert_tagged(table: &str, chain: &str, matches: &[&str], target: &[&str]) -> Vec<Cmd> {
    let [old, new] = ISOLATION_GENERATIONS;
    let rule = |op, generation, on_failure| {
        tagged_rule(op, table, chain, matches, target, generation, on_failure)
    };
    vec![
        rule("-I", old, OnFailure::Fatal),
        rule("-D", new, OnFailure::Ignore),
        rule("-I", new, OnFailure::Fatal),
        rule("-D", old, OnFailure::Ignore),
    ]
}

/// One generation of one tagged rule. Shared by [`reassert_tagged`] and
/// [`TaggedRule::withdraw`] so that what the GC deletes is the same string
/// construction the deploy inserted, rather than a second spelling of it that
/// can drift a space or a flag and silently stop matching.
fn tagged_rule(
    op: &str,
    table: &str,
    chain: &str,
    matches: &[&str],
    target: &[&str],
    generation: &str,
    on_failure: OnFailure,
) -> Cmd {
    let mut args: Vec<&str> = Vec::new();
    if table != "filter" {
        args.extend(["-t", table]);
    }
    args.extend([op, chain]);
    args.extend(matches.iter().copied());
    args.extend(["-m", "comment", "--comment", generation]);
    args.extend(target.iter().copied());
    Cmd::iptables(&args, on_failure)
}

/// One tagged isolation rule, owned rather than borrowed so that a single list
/// of them can drive both the assert and the withdraw ([`isolation_rules`]).
struct TaggedRule {
    table: &'static str,
    chain: &'static str,
    matches: Vec<String>,
    target: Vec<String>,
}

impl TaggedRule {
    fn new(table: &'static str, chain: &'static str, matches: &[&str], target: &[&str]) -> Self {
        TaggedRule {
            table,
            chain,
            matches: strings(matches),
            target: strings(target),
        }
    }

    fn borrowed(&self) -> (Vec<&str>, Vec<&str>) {
        (
            self.matches.iter().map(String::as_str).collect(),
            self.target.iter().map(String::as_str).collect(),
        )
    }

    fn assert(&self) -> Vec<Cmd> {
        let (matches, target) = self.borrowed();
        reassert_tagged(self.table, self.chain, &matches, &target)
    }

    /// Remove both generations. Which one a bridge ends a run on is decided by
    /// where [`reassert_tagged`] was interrupted, so the GC cannot know and
    /// deletes both; every delete is `Ignore`, so the absent one costs a
    /// non-zero exit nobody reads.
    fn withdraw(&self) -> Vec<Cmd> {
        let (matches, target) = self.borrowed();
        ISOLATION_GENERATIONS
            .iter()
            .map(|generation| {
                tagged_rule(
                    "-D",
                    self.table,
                    self.chain,
                    &matches,
                    &target,
                    generation,
                    OnFailure::Ignore,
                )
            })
            .collect()
    }
}

/// Re-assert one `prohibit` policy rule with no moment where it is absent — the
/// same generation dance as [`reassert_tagged`], with the priority as the tag:
/// add at `a`, delete at `b`, add at `b`, delete at `a`.
///
/// Converges under either kernel behaviour for a duplicate `ip rule add`
/// ([`OnFailure::ExistsOk`]). Where the kernel refuses an identical rule, every
/// add is a no-op or a first copy, and any start state ends as exactly one rule
/// at `b`. Where it appends duplicates, a clean or steady node still ends on
/// exactly one; a run interrupted between its two adds can leave one extra
/// identical copy at `a`, which later runs keep bounded at one and which
/// prohibits nothing the rule at `b` does not.
fn reassert_prohibit(selector: &[&str], priorities: [u32; 2]) -> Vec<Cmd> {
    let [a, b] = priorities;
    vec![
        prohibit_rule("add", a, selector, OnFailure::ExistsOk),
        prohibit_rule("del", b, selector, OnFailure::Ignore),
        prohibit_rule("add", b, selector, OnFailure::ExistsOk),
        prohibit_rule("del", a, selector, OnFailure::Ignore),
    ]
}

fn prohibit_rule(op: &str, priority: u32, selector: &[&str], on_failure: OnFailure) -> Cmd {
    let mut args = strings(&["rule", op, "priority"]);
    args.push(priority.to_string());
    args.extend(strings(selector));
    args.push("prohibit".to_string());
    Cmd::with("ip", args, on_failure)
}

/// The inverse of [`reassert_prohibit`]: take both generations of one prohibit
/// off the node.
///
/// The selector is carried in full rather than deleting by priority alone,
/// because a priority is shared by every tenant bridge on the node — `ip rule
/// del priority 1201` would take whichever bridge's rule the kernel found
/// first. Each priority is deleted twice: [`reassert_prohibit`] documents that
/// a run interrupted between its two adds can leave one extra identical copy,
/// and a GC that left it would leave a prohibit naming a bridge that no longer
/// exists.
fn withdraw_prohibit(selector: &[&str], priorities: [u32; 2]) -> Vec<Cmd> {
    priorities
        .iter()
        .flat_map(|priority| {
            [
                prohibit_rule("del", *priority, selector, OnFailure::Ignore),
                prohibit_rule("del", *priority, selector, OnFailure::Ignore),
            ]
        })
        .collect()
}

/// The node bridge's routing-layer deny towards one tenant workload. Other
/// tenant bridges need no per-workload rule: their own `/24` prohibit covers
/// every address that is not theirs.
fn workload_rule(op: &str, node_bridge: &str, host_route: &str) -> Cmd {
    let priority = WORKLOAD_RULE_PRIORITY.to_string();
    let args = [
        "rule", op, "priority", &priority, "iif", node_bridge, "to", host_route, "fwmark",
        NOT_GRANTED, "prohibit",
    ];
    if op == "add" {
        Cmd::with("ip", strings(&args), OnFailure::ExistsOk)
    } else {
        Cmd::best_effort("ip", &args)
    }
}

/// 64-bit FNV-1a. Stable across builds and platforms, which is the whole
/// requirement: it names a bridge that persists between kamaji restarts.
fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, b| {
        (hash ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Ten base32hex characters (`0-9a-v`) of FNV-1a 64, xor-folded to 50 bits —
/// folding rather than truncating, since FNV's low bits are its least mixed.
fn tenant_bridge_suffix(tenant: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let hash = fnv1a64(tenant);
    let folded = (hash >> 50) ^ (hash & ((1 << 50) - 1));
    (0..10)
        .rev()
        .map(|i| char::from(ALPHABET[((folded >> (i * 5)) & 31) as usize]))
        .collect()
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
    /// The bridge the host veth is enslaved to: the node bridge for the
    /// singleton tenant, a per-tenant one otherwise.
    pub bridge: String,
    /// Whether [`NetnsPlan::bridge`] is a per-tenant bridge, and so carries a
    /// `/32` gateway, per-workload host routes and the isolation rules.
    pub tenant_isolated: bool,
    /// The mark this workload's packets carry inside the node's `/24`
    /// ([`identity_mark`], R895-F4).
    pub identity_mark: u32,
    /// The co-resident cross-tenant peers this workload admits
    /// ([`grant_commands`]).
    pub grants: Vec<Grant>,
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

/// Serializes every read-then-write of the node's container-network state.
///
/// Two callers read the kernel and then plan against what they read —
/// [`apply_grant_neighbours`] and [`reconcile`] — and a third
/// ([`ContainerNet::bridge_commands`] + [`ContainerNet::setup_commands`])
/// creates a bridge and then, as a separate command, the first veth that makes
/// it look occupied. Interleave a reconcile with that gap and the GC deletes a
/// bridge a deploy is halfway through building, which the deploy then fails on
/// with `Cannot find device`. One kamaji per node, so a process-wide lock is
/// the whole scope.
static NODE_STATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Proof that the holder has the node's container-network state to itself.
///
/// Taken by value rather than checked, so the type system asks the question
/// instead of a comment: the two entry points that read-then-write
/// ([`apply_grant_neighbours`], [`reconcile`]) cannot be called without one.
pub struct NodeStateGuard(#[allow(dead_code)] tokio::sync::MutexGuard<'static, ()>);

/// Take the node-state lock for the length of one deploy or one GC pass.
pub async fn lock_node_state() -> NodeStateGuard {
    NodeStateGuard(NODE_STATE.lock().await)
}

/// The nameservers in a `resolv.conf` that a tenant-isolated workload cannot
/// reach: those inside [`MESH_NODE_POOL`], which [`tenant_isolation`]'s mesh
/// prohibit denies (R895-T5).
///
/// The case this exists for is tailscale MagicDNS, whose resolver is
/// `100.100.100.100` — inside `100.64.0.0/10` by construction, because it is a
/// tailnet address. A node resolving through it hands every tenant workload a
/// nameserver that workload's own isolation forbids, and the symptom is a DNS
/// timeout on every lookup rather than anything naming the cause.
///
/// MEASURED 2026-09-15 on every `--container-net` node in the fleet
/// (us-east-001, us-west-001, us-west-011): each runs systemd-resolved with a
/// public upstream (`213.186.33.99`, or `1.1.1.1` + `9.9.9.9`) in
/// `/run/systemd/resolve/resolv.conf`, which is the file
/// `kamaji_containerd_core::resolver_mount_source` picks for an isolated
/// namespace. `/etc/resolv.conf` on all three is the systemd-resolved loopback
/// stub, which that function already ranks out. So no node collides today, and
/// this is the guard that says so out loud on the day one does.
pub fn mesh_pool_nameservers(resolv_conf: &str) -> Vec<Ipv4Addr> {
    let pool = Ipv4Cidr::parse(MESH_NODE_POOL).expect("MESH_NODE_POOL is a valid CIDR");
    resolv_conf
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.starts_with(';'))
        .filter_map(|line| line.strip_prefix("nameserver"))
        .filter_map(|rest| rest.strip_prefix(char::is_whitespace))
        .filter_map(|addr| {
            // An IPv6 zone index (`fe80::1%eth0`) names a host interface that
            // does not exist in the container's namespace; v6 is out of scope
            // for W343 either way, and only a v4 address can be in the pool.
            addr.trim().split('%').next()?.parse::<Ipv4Addr>().ok()
        })
        .filter(|addr| pool.contains(*addr))
        .collect()
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
            Err(e) if cmd.on_failure == OnFailure::Ignore => {
                tracing::debug!(cmd = %cmd, error = %e, "container-net: ignoring");
                continue;
            }
            Err(e) => return Err(e),
        };
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let tolerated = match cmd.on_failure {
                OnFailure::Fatal => false,
                OnFailure::Ignore => true,
                // iproute2 prints `RTNETLINK answers: File exists` for EEXIST.
                OnFailure::ExistsOk => stderr.contains("File exists"),
            };
            if tolerated {
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

    fn tenancy(tenant: TenantId, workload: &str) -> Tenancy {
        Tenancy {
            fq_identity: format!("{}/default/{workload}", tenant.0),
            tenant,
            allow_from: vec![],
        }
    }

    fn solo() -> Tenancy {
        tenancy(TenantId::singleton(), "acct")
    }

    fn plan_for(ip: &str) -> NetnsPlan {
        net()
            .plan("acct", ip.parse().unwrap(), &solo())
            .expect("address is inside the default range")
    }

    fn tenant_plan(workload: &str, ip: &str, tenant: &str) -> NetnsPlan {
        net()
            .plan(
                workload,
                ip.parse().unwrap(),
                &tenancy(TenantId(tenant.to_string()), workload),
            )
            .expect("address is inside the default range")
    }

    fn script(cmds: &[Cmd]) -> Vec<String> {
        cmds.iter().map(|c| c.to_string()).collect()
    }

    fn best_effort(cmd: &Cmd) -> bool {
        cmd.on_failure == OnFailure::Ignore
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
        assert!(net().plan("acct", "100.64.0.3".parse().unwrap(), &solo()).is_none());
        assert!(net().plan("acct", "127.0.0.1".parse().unwrap(), &solo()).is_none());
    }

    #[test]
    fn the_gateway_and_the_network_address_are_not_assignable_to_a_workload() {
        assert!(net().plan("acct", "10.128.3.0".parse().unwrap(), &solo()).is_none());
        assert!(
            net().plan("acct", "10.128.3.1".parse().unwrap(), &solo()).is_none(),
            "the gateway is the bridge's own address"
        );
        assert!(net().plan("acct", "10.128.3.255".parse().unwrap(), &solo()).is_none());
        assert!(net().plan("acct", "10.128.3.2".parse().unwrap(), &solo()).is_some());
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
                let plan = net
                    .plan("acct", addr, &solo())
                    .expect("kamaji wires what yubaba allocated");
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
        assert_eq!(cmds[2].to_string(), "ip route del 10.128.3.7/32");
        assert_eq!(
            cmds[3].to_string(),
            "ip rule del priority 1200 iif yah0 to 10.128.3.7/32 fwmark 0/0x2000000 prohibit"
        );
        assert!(cmds[..4].iter().all(best_effort));
        assert_eq!(cmds[..4].len(), 4);
        assert_eq!(cmds[4].to_string(), "nsenter --mount=/proc/1/ns/mnt -- ip netns add acct");
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
                "ip route del 10.128.3.7/32",
                "ip rule del priority 1200 iif yah0 to 10.128.3.7/32 fwmark 0/0x2000000 prohibit",
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
                "iptables -w -t nat -D POSTROUTING -s 10.128.3.0/24 ! -d 10.128.3.0/24 -j MASQUERADE",
                "iptables -w -t nat -A POSTROUTING -s 10.128.3.0/24 ! -d 10.128.3.0/24 -j MASQUERADE",
                "iptables -w -D FORWARD -i yah0 -j ACCEPT",
                "iptables -w -A FORWARD -i yah0 -j ACCEPT",
                "iptables -w -D FORWARD -o yah0 -j ACCEPT",
                "iptables -w -A FORWARD -o yah0 -j ACCEPT",
            ]
        );
    }

    /// Every rule an add can leave behind — iptables or `ip rule` — has a
    /// best-effort delete of the same rule in the run, so N deploys leave one
    /// rule rather than N. A duplicated MASQUERADE is harmless; a FORWARD chain
    /// that grows by two entries per deploy is a node that slows down for months
    /// and then gets blamed on the kernel.
    #[test]
    fn re_running_the_bridge_setup_cannot_accumulate_duplicate_rules() {
        for plan in [plan_for("10.128.3.7"), tenant_plan("acct", "10.128.3.7", "acme")] {
            let cmds = [net().bridge_commands(&plan), net().setup_commands(&plan)].concat();
            let adds = cmds.iter().filter(|c| {
                c.args.iter().any(|a| a == "-A" || a == "-I")
                    || c.args.starts_with(&["rule".to_string(), "add".to_string()])
            });
            for add in adds {
                let paired = cmds.iter().any(|c| {
                    c.bin == add.bin
                        && best_effort(c)
                        && c.args.len() == add.args.len()
                        && c.args
                            .iter()
                            .zip(&add.args)
                            .all(|(a, b)| a == b || a == "-D" || a == "del")
                });
                assert!(paired, "no delete paired with `{add}`");
            }
        }
    }

    #[test]
    fn teardown_is_entirely_best_effort() {
        let plan = plan_for("10.128.3.7");
        let cmds = net().teardown_commands(&plan);
        assert!(cmds.iter().all(best_effort));
        assert_eq!(
            script(&cmds),
            vec![
                "ip link del veth7",
                "nsenter --mount=/proc/1/ns/mnt -- ip netns del acct",
                "ip route del 10.128.3.7/32",
                "ip rule del priority 1200 iif yah0 to 10.128.3.7/32 fwmark 0/0x2000000 prohibit",
            ]
        );
    }

    /// A `Stop` carries a workload id and nothing else, so teardown has to be
    /// reachable from the same string `setup` derived the namespace name from.
    /// If these two ever disagree, every stopped workload leaks a namespace and
    /// its address, and the leak is invisible until the node runs out of one.
    #[test]
    fn teardown_from_a_stop_names_the_same_namespace_setup_created() {
        let plan = net()
            .plan("forge.87802530", "10.128.3.7".parse().unwrap(), &solo())
            .unwrap();
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
        let plan = net.plan("acct", "172.21.9.4".parse().unwrap(), &solo()).unwrap();
        assert_eq!(plan.subnet.to_string(), "172.21.9.0/24");
        assert_eq!(plan.gateway, "172.21.9.1".parse::<Ipv4Addr>().unwrap());
        assert!(
            net.setup_commands(&plan)
                .iter()
                .any(|c| c.to_string() == "ip link set veth4 master br-yah")
        );
        assert!(net.plan("acct", "10.128.3.7".parse().unwrap(), &solo()).is_none());
    }

    // ── R895-F3: tenant isolation (W206) ─────────────────────────────────────

    /// W206's degenerate case, pinned at the plan: a workload of the singleton
    /// tenant hangs off the node bridge, which holds the `/24`, and gets no
    /// host route and no isolation rule. The full sequences are asserted by the
    /// tests above, which is what makes "unchanged" checkable rather than
    /// claimed.
    #[test]
    fn the_singleton_tenant_is_wired_exactly_as_before_tenancy_existed() {
        let plan = plan_for("10.128.3.7");
        assert_eq!(plan.bridge, "yah0");
        assert!(!plan.tenant_isolated);
        let all = [net().bridge_commands(&plan), net().setup_commands(&plan)].concat();
        assert!(!script(&all).iter().any(|c| c.contains("DROP")
            || c.contains("rp_filter")
            || c.contains("route replace")
            || c.contains("rule add")
            || c.contains("mangle")
            || c.contains("INPUT")));
    }

    #[test]
    fn a_tenant_bridge_name_is_stable_distinct_and_fits_the_kernel_limit() {
        let net = net();
        let acme = TenantId("acme".to_string());
        assert_eq!(net.bridge_for(&solo().tenant), "yah0");
        // Published FNV-1a 64 test vectors, so the hash is FNV and not merely
        // self-consistent.
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
        // Pinned as values: the name has to survive a kamaji upgrade, so a
        // change here is a change in which bridge a running tenant is on.
        assert_eq!(net.bridge_for(&acme), "yah0-6jgfqfdnu6");
        assert_eq!(net.bridge_for(&TenantId("globex".into())), "yah0-91auqknbeu");
        assert_eq!(net.bridge_for(&acme).len(), 15, "the whole IFNAMSIZ budget");
        let long = ContainerNet::new(net.range(), "a-very-long-br15");
        assert_eq!(long.bridge_for(&acme), "a-ve-6jgfqfdnu6");
    }

    /// W206: the *tenant* is the isolation axis and the namespace is not, so two
    /// workloads of one tenant share a bridge whatever their names, and a second
    /// tenant on the same node gets a different one — from the same `/24`.
    #[test]
    fn same_tenant_shares_a_bridge_and_another_tenant_does_not() {
        let a1 = tenant_plan("yah.web", "10.128.3.7", "acme");
        let a2 = tenant_plan("noisetable.web", "10.128.3.8", "acme");
        let b = tenant_plan("web", "10.128.3.9", "globex");
        assert_eq!(a1.bridge, a2.bridge);
        assert_ne!(a1.bridge, b.bridge);
        assert_ne!(a1.bridge, "yah0");
        assert!(a1.tenant_isolated && b.tenant_isolated);
        assert_eq!(a1.subnet, b.subnet, "tenants share the node's /24");
        assert_eq!(a1.gateway, b.gateway);
    }

    #[test]
    fn a_tenant_bridge_holds_the_gateway_as_a_host_address_and_closes_the_subnet() {
        let plan = tenant_plan("acct", "10.128.3.7", "acme");
        let br = plan.bridge.clone();
        let prohibit = |selector: &str, a: u32, b: u32| {
            vec![
                format!("ip rule add priority {a} {selector} prohibit"),
                format!("ip rule del priority {b} {selector} prohibit"),
                format!("ip rule add priority {b} {selector} prohibit"),
                format!("ip rule del priority {a} {selector} prohibit"),
            ]
        };
        let tagged = |table: &str, chain: &str, matches: &str, target: &str| {
            let line = |op: &str, generation: &str| {
                format!("iptables -w {table}{op} {chain} {matches} -m comment --comment {generation} {target}")
            };
            vec![
                line("-I", "yah-isolation-a"),
                line("-D", "yah-isolation-b"),
                line("-I", "yah-isolation-b"),
                line("-D", "yah-isolation-a"),
            ]
        };
        let mut expected = vec![
            format!("ip link add name {br} type bridge"),
            // /32, not /24: a second connected /24 would steal the node
            // bridge's route.
            format!("ip addr add 10.128.3.1/32 dev {br}"),
            format!("ip link set {br} up"),
            "sysctl -w net.ipv4.ip_forward=1".to_string(),
            // The same rule yah0 asserts: one per node, not one per bridge.
            "iptables -w -t nat -D POSTROUTING -s 10.128.3.0/24 ! -d 10.128.3.0/24 -j MASQUERADE"
                .to_string(),
            "iptables -w -t nat -A POSTROUTING -s 10.128.3.0/24 ! -d 10.128.3.0/24 -j MASQUERADE"
                .to_string(),
            format!("sysctl -w net.ipv6.conf.{br}.disable_ipv6=1"),
            "sysctl -w net.ipv4.conf.all.src_valid_mark=1".to_string(),
        ];
        expected.extend(prohibit(
            &format!("iif {br} to 10.128.3.0/24 fwmark 0/0x2000000"),
            1201,
            1202,
        ));
        expected.extend(prohibit(
            &format!("iif {br} to 100.64.0.0/10 fwmark 0/0x3000000"),
            1203,
            1204,
        ));
        expected.push(format!("sysctl -w net.ipv4.conf.{br}.rp_filter=1"));
        expected.extend(tagged("-t raw ", "PREROUTING", &format!("-i {br} -m rpfilter --invert"), "-j DROP"));
        expected.extend(tagged(
            "-t mangle ",
            "PREROUTING",
            &format!("-i {br} -m conntrack --ctstate ESTABLISHED,RELATED"),
            "-j MARK --set-xmark 0x1000000/0x1000000",
        ));
        expected.extend(tagged(
            "-t mangle ",
            "PREROUTING",
            "-s 100.64.0.0/10 -d 10.128.3.0/24",
            "-j MARK --set-xmark 0x1000000/0x1000000",
        ));
        let ng = "-m mark ! --mark 0x2000000/0x2000000";
        expected.extend(tagged("", "FORWARD", &format!("-i {br} -d 10.128.3.0/24 ! -o {br} {ng}"), "-j DROP"));
        expected.extend(tagged("", "FORWARD", &format!("-o {br} -s 10.128.3.0/24 ! -i {br} {ng}"), "-j DROP"));
        expected.extend(tagged("", "FORWARD", &format!("-i yah0 -o {br} {ng}"), "-j DROP"));
        expected.extend(tagged(
            "",
            "FORWARD",
            &format!("-i {br} -d 100.64.0.0/10 -m conntrack ! --ctstate ESTABLISHED,RELATED {ng}"),
            "-j DROP",
        ));
        expected.extend(tagged(
            "",
            "INPUT",
            &format!("-i {br} ! -p icmp -m conntrack ! --ctstate ESTABLISHED,RELATED"),
            "-j DROP",
        ));
        expected.extend([
            format!("iptables -w -D FORWARD -i {br} -j ACCEPT"),
            format!("iptables -w -A FORWARD -i {br} -j ACCEPT"),
            format!("iptables -w -D FORWARD -o {br} -j ACCEPT"),
            format!("iptables -w -A FORWARD -o {br} -j ACCEPT"),
        ]);
        assert_eq!(script(&net().bridge_commands(&plan)), expected);
    }

    /// Every iptables invocation waits for the xtables lock, on every path.
    #[test]
    fn every_iptables_call_waits_for_the_xtables_lock() {
        for plan in [plan_for("10.128.3.7"), tenant_plan("acct", "10.128.3.7", "acme")] {
            let n = net();
            let all = [
                n.bridge_commands(&plan),
                n.setup_commands(&plan),
                n.teardown_commands(&plan),
            ]
            .concat();
            for cmd in all.iter().filter(|c| c.bin == "iptables") {
                assert_eq!(cmd.args[0], "-w", "`{cmd}`");
            }
        }
    }

    /// The layout R895-F4 builds against: everything precedes `main` (32766),
    /// no mark bit strays into tailscale's `0x00ff0000` or overlaps another
    /// owner's, and every prohibit and every FORWARD drop exempts GRANT — the
    /// whole of F4's contract with this module.
    #[test]
    fn the_rule_priorities_and_mark_bits_are_the_published_layout() {
        assert!(WORKLOAD_RULE_PRIORITY < SUBNET_RULE_PRIORITIES[0]);
        assert!(SUBNET_RULE_PRIORITIES[1] < MESH_RULE_PRIORITIES[0]);
        assert!(MESH_RULE_PRIORITIES[1] < 32766);
        const TAILSCALE: u32 = 0x00ff_0000;
        for bits in [FWMARK_IDENTITY_MASK, FWMARK_REPLY, FWMARK_GRANT] {
            assert_eq!(bits & TAILSCALE, 0, "{bits:#x}");
        }
        assert_eq!(FWMARK_IDENTITY_MASK & (FWMARK_REPLY | FWMARK_GRANT), 0);
        assert_eq!(FWMARK_REPLY & FWMARK_GRANT, 0);

        let plan = tenant_plan("acct", "10.128.3.7", "acme");
        let n = net();
        let all = [n.bridge_commands(&plan), n.setup_commands(&plan)].concat();
        let named = [WORKLOAD_RULE_PRIORITY]
            .into_iter()
            .chain(SUBNET_RULE_PRIORITIES)
            .chain(MESH_RULE_PRIORITIES)
            .collect::<Vec<_>>();
        for cmd in all.iter().filter(|c| c.args.first().map(String::as_str) == Some("rule")) {
            let priority: u32 = cmd.args[3].parse().unwrap();
            assert!(named.contains(&priority), "`{cmd}` uses an unnamed priority");
            let fwmark = cmd.args.iter().position(|a| a == "fwmark").expect("masked");
            let (value, mask) = cmd.args[fwmark + 1].split_once('/').unwrap();
            let mask = u32::from_str_radix(mask.trim_start_matches("0x"), 16).unwrap();
            assert_eq!(value, "0", "`{cmd}`");
            assert_ne!(mask & FWMARK_GRANT, 0, "`{cmd}` does not exempt GRANT");
        }
        let grant = format!("{FWMARK_GRANT:#x}/{FWMARK_GRANT:#x}");
        for cmd in all.iter().filter(|c| c.args.iter().any(|a| a == "FORWARD") && c.args.last().map(String::as_str) == Some("DROP")) {
            let exempt = cmd.args.windows(4).any(|w| w == ["mark", "!", "--mark", grant.as_str()]);
            assert!(exempt, "`{cmd}` does not exempt GRANT");
        }
    }

    /// `ip rule` as the kernel treats these commands, under either behaviour for
    /// an identical add: refused with EEXIST, or appended as a duplicate. `del`
    /// removes the first exact match and fails when there is none.
    fn run_rules(
        rules: &mut Vec<(u32, Vec<String>)>,
        cmds: &[&Cmd],
        refuses_duplicates: bool,
        mut step: impl FnMut(&[(u32, Vec<String>)]),
    ) {
        for cmd in cmds {
            let entry = (cmd.args[3].parse::<u32>().unwrap(), cmd.args[4..].to_vec());
            match cmd.args[1].as_str() {
                "add" if refuses_duplicates && rules.contains(&entry) => {
                    assert_eq!(cmd.on_failure, OnFailure::ExistsOk, "`{cmd}` would fail the deploy")
                }
                "add" => rules.push(entry),
                "del" => match rules.iter().position(|r| *r == entry) {
                    Some(i) => {
                        rules.remove(i);
                    }
                    None => assert!(best_effort(cmd), "`{cmd}` would fail the deploy"),
                },
                op => panic!("unexpected `{op}` in `{cmd}`"),
            }
            step(rules);
        }
    }

    /// The routing layer's re-assert, against both kernel behaviours and from
    /// every state an interrupted run can leave: each prohibit is present at
    /// every step of a redeploy, and the count converges (to one where the
    /// kernel refuses duplicates) or stays bounded at two (where it appends).
    #[test]
    fn a_redeploy_never_leaves_a_tenant_bridge_without_its_prohibits() {
        let plan = tenant_plan("acct", "10.128.3.7", "acme");
        let cmds = net().bridge_commands(&plan);
        let rule_cmds: Vec<&Cmd> = cmds.iter().filter(|c| c.args[0] == "rule").collect();
        let selectors: std::collections::BTreeSet<Vec<String>> =
            rule_cmds.iter().map(|c| c.args[4..].to_vec()).collect();
        assert_eq!(selectors.len(), 2, "the /24 and the mesh pool");
        for refuses_duplicates in [true, false] {
            for interrupted_after in 0..=rule_cmds.len() {
                let mut rules = Vec::new();
                run_rules(&mut rules, &rule_cmds[..interrupted_after], refuses_duplicates, |_| {});
                run_rules(&mut rules, &rule_cmds, refuses_duplicates, |_| {});
                for _ in 0..3 {
                    run_rules(&mut rules, &rule_cmds, refuses_duplicates, |now| {
                        for selector in &selectors {
                            assert!(
                                now.iter().any(|(_, s)| s == selector),
                                "{selector:?} absent mid-redeploy: {now:?}"
                            );
                        }
                    });
                    for selector in &selectors {
                        let copies = rules.iter().filter(|(_, s)| s == selector).count();
                        if refuses_duplicates {
                            assert_eq!(copies, 1, "{rules:?}");
                        } else {
                            assert!((1..=2).contains(&copies), "{rules:?}");
                        }
                    }
                }
            }
        }
    }

    /// Evaluates the `-s`/`-d`/`-o` matches of one POSTROUTING rule against a
    /// packet, as the kernel would. Panics on a match it does not model rather
    /// than ignoring it, so a new match cannot make a test pass by being skipped.
    fn masquerades(rule: &Cmd, src: Ipv4Addr, dst: Ipv4Addr, out: &str) -> bool {
        let mut args = rule.args.iter().map(String::as_str);
        let (mut matched, mut negate) = (true, false);
        while let Some(flag) = args.next() {
            if flag == "!" {
                negate = true;
                continue;
            }
            if flag == "-w" {
                continue;
            }
            let value = args.next().expect("every flag here takes a value");
            let hit = match flag {
                "-s" => Ipv4Cidr::parse(value).unwrap().contains(src),
                "-d" => Ipv4Cidr::parse(value).unwrap().contains(dst),
                "-o" => value == out,
                "-t" | "-A" | "-j" => continue,
                other => panic!("`{other}` in `{rule}` is not modelled"),
            };
            matched &= hit != negate;
            negate = false;
        }
        matched
    }

    /// Operator review of R895-F3. Every bridge on a node holds the same `/24`,
    /// and with `br_netfilter` loaded, frames between two ports of one bridge
    /// traverse nat POSTROUTING. So no MASQUERADE the node carries, from its
    /// node bridge or any tenant bridge, may match a packet addressed inside the
    /// `/24` — whichever interface it leaves by — or the workload's source
    /// address is rewritten to the gateway's.
    #[test]
    fn no_masquerade_on_a_node_can_match_traffic_addressed_inside_its_subnet() {
        let plans = [
            plan_for("10.128.3.7"),
            tenant_plan("web", "10.128.3.8", "acme"),
            tenant_plan("web", "10.128.3.9", "globex"),
        ];
        let rules: Vec<Cmd> = plans
            .iter()
            .flat_map(|p| net().bridge_commands(p))
            .filter(|c| c.args.last().map(String::as_str) == Some("MASQUERADE"))
            .filter(|c| !best_effort(c))
            .collect();
        assert_eq!(rules.len(), plans.len());
        let mut interfaces: Vec<&str> = plans.iter().map(|p| p.bridge.as_str()).collect();
        interfaces.push("eth0");
        let workload: Ipv4Addr = "10.128.3.7".parse().unwrap();
        for rule in &rules {
            for dst in ["10.128.3.7", "10.128.3.8", "10.128.3.1", "10.128.3.254"] {
                for out in &interfaces {
                    assert!(
                        !masquerades(rule, workload, dst.parse().unwrap(), out),
                        "`{rule}` rewrites {workload} -> {dst} leaving {out}"
                    );
                }
            }
            // Not vacuous: traffic leaving the /24 is still NATted.
            assert!(
                masquerades(rule, workload, "1.1.1.1".parse().unwrap(), "eth0"),
                "`{rule}` no longer NATs egress"
            );
        }
    }

    /// `(table/chain, op, rule)` of one `iptables -w [-t table] <op> <chain> …`.
    fn parse_iptables(cmd: &Cmd) -> (String, String, Vec<String>) {
        let mut args = cmd.args.iter().map(String::as_str).peekable();
        assert_eq!(args.next(), Some("-w"), "`{cmd}`");
        let mut table = "filter";
        if args.peek() == Some(&"-t") {
            args.next();
            table = args.next().unwrap();
        }
        let op = args.next().unwrap().to_string();
        let chain = args.next().unwrap();
        (format!("{table}/{chain}"), op, args.map(str::to_string).collect())
    }

    type Tables = std::collections::BTreeMap<String, Vec<Vec<String>>>;

    /// iptables as the kernel treats these commands: `-I` puts a rule at the
    /// top of its chain, `-D` removes the first exact match and fails when
    /// there is none.
    fn run_iptables(tables: &mut Tables, cmds: &[&Cmd], mut step: impl FnMut(&Tables)) {
        for cmd in cmds {
            let (chain, op, rule) = parse_iptables(cmd);
            let list = tables.entry(chain).or_default();
            match op.as_str() {
                "-I" => list.insert(0, rule),
                "-D" => match list.iter().position(|r| *r == rule) {
                    Some(i) => {
                        list.remove(i);
                    }
                    None => assert!(best_effort(cmd), "`{cmd}` would fail the deploy"),
                },
                op => panic!("unexpected `{op}` in `{cmd}`"),
            }
            step(tables);
        }
    }

    /// A rule with its generation tag removed: the rule the kernel enforces.
    fn untagged(rule: &[String]) -> Vec<String> {
        let mut rule = rule.to_vec();
        if let Some(i) = rule.windows(2).position(|w| w[0] == "-m" && w[1] == "comment") {
            rule.drain(i..i + 4);
        }
        rule
    }

    /// Every tenant deploy re-runs the isolation rules. A delete-then-insert
    /// would leave the tenant unisolated between the two on every deploy; this
    /// pins that some copy of each tagged rule — in raw, mangle, FORWARD and
    /// INPUT — is present at every step of a redeploy, and that re-runs still
    /// converge on exactly one copy.
    #[test]
    fn a_redeploy_never_leaves_a_tenant_bridge_without_its_drops() {
        let plan = tenant_plan("acct", "10.128.3.7", "acme");
        let cmds = net().bridge_commands(&plan);
        let tagged: Vec<&Cmd> = cmds
            .iter()
            .filter(|c| c.args.iter().any(|a| a == "--comment"))
            .collect();
        let enforced: std::collections::BTreeSet<(String, Vec<String>)> = tagged
            .iter()
            .map(|c| parse_iptables(c))
            .map(|(chain, _, rule)| (chain, untagged(&rule)))
            .collect();
        assert_eq!(enforced.len(), 8, "raw, two mangle, four FORWARD, INPUT: {enforced:?}");

        let mut tables = Tables::new();
        run_iptables(&mut tables, &tagged, |_| {});
        let total: usize = tables.values().map(Vec::len).sum();
        assert_eq!(total, 8, "the first deploy leaves one copy of each: {tables:?}");
        let steady = tables.clone();
        for _ in 0..3 {
            run_iptables(&mut tables, &tagged, |now| {
                for (chain, rule) in &enforced {
                    assert!(
                        now[chain].iter().any(|r| untagged(r) == *rule),
                        "{chain} {rule:?} absent mid-redeploy: {now:?}"
                    );
                }
            });
            assert_eq!(tables, steady, "a redeploy must not accumulate rules");
        }
    }

    /// The drops are inserted, so they sit above every `-A ... ACCEPT` — the
    /// tenant's own, and the node bridge's, which a later singleton deploy
    /// deletes and re-appends at the bottom of the chain.
    #[test]
    fn the_isolation_drops_are_inserted_above_every_accept() {
        let plan = tenant_plan("acct", "10.128.3.7", "acme");
        for cmd in net().bridge_commands(&plan) {
            if cmd.args.last().map(String::as_str) == Some("DROP") && !best_effort(&cmd) {
                assert_eq!(parse_iptables(&cmd).1, "-I", "`{cmd}` would land below the ACCEPTs");
            }
        }
    }

    /// Every rule a tenant bridge's setup asserts is deleted when that bridge
    /// is collected (R895-T5).
    ///
    /// Written as the inverse of `bridge_commands` rather than as a literal
    /// expected script, because the failure this guards against is a rule added
    /// in a later ticket and never removed: an expected-script test passes
    /// happily while the new rule leaks, and this one does not.
    #[test]
    fn collecting_a_tenant_bridge_deletes_every_rule_its_setup_asserted() {
        let net = net();
        let plan = tenant_plan("api", "10.128.3.7", "acme");
        let bridge = plan.bridge.clone();
        let asserted = script(&net.bridge_commands(&plan));
        let collected = script(&net.bridge_gc_commands(&bridge, plan.subnet));

        assert_eq!(
            collected.last().map(String::as_str),
            Some(format!("ip link del {bridge}").as_str()),
            "the link goes last, so every `iif {bridge}` rule is still matchable when it is deleted"
        );
        let mut checked = 0;
        for cmd in asserted
            .iter()
            .filter(|cmd| cmd.split_whitespace().any(|word| word == bridge))
        {
            // The bridge, its gateway address and its `up` are all undone by
            // deleting the link, which is asserted above.
            if cmd.starts_with("ip link ") || cmd.starts_with("ip addr ") {
                continue;
            }
            let inverse = if let Some(rest) = cmd.strip_prefix("ip rule add ") {
                format!("ip rule del {rest}")
            } else if cmd.contains(" -I ") {
                cmd.replacen(" -I ", " -D ", 1)
            } else if cmd.contains(" -A ") {
                cmd.replacen(" -A ", " -D ", 1)
            } else {
                // A sysctl, or a delete that is already its own inverse.
                continue;
            };
            assert!(
                collected.contains(&inverse),
                "the bridge GC never deletes `{cmd}` — looked for `{inverse}`"
            );
            checked += 1;
        }
        assert!(
            checked >= 20,
            "only {checked} asserted rules were matched; the filter above has stopped seeing them"
        );
    }

    #[test]
    fn the_shared_egress_nat_rule_outlives_any_one_bridge() {
        let net = net();
        let plan = tenant_plan("api", "10.128.3.7", "acme");
        let collected = script(&net.bridge_gc_commands(&plan.bridge, plan.subnet));
        assert!(
            !collected.iter().any(|cmd| cmd.contains("MASQUERADE")),
            "the NAT rule is one rule for the whole /24; collecting one tenant's bridge \
             must not take internet egress from every workload still running: {collected:#?}"
        );
        assert!(
            !collected.iter().any(|cmd| cmd.contains("ip_forward")),
            "ip_forward is node-wide and was very likely on before kamaji: {collected:#?}"
        );
    }

    #[test]
    fn an_addresss_leftovers_are_the_same_two_commands_from_a_plan_or_from_a_sweep() {
        let net = net();
        let plan = tenant_plan("api", "10.128.3.7", "acme");
        let from_sweep = script(&net.address_gc_commands(plan.container_ip));
        let from_teardown = script(&net.teardown_commands(&plan));
        assert_eq!(
            from_sweep,
            vec![
                "ip route del 10.128.3.7/32".to_string(),
                format!(
                    "ip rule del priority {WORKLOAD_RULE_PRIORITY} iif yah0 to 10.128.3.7/32 fwmark {NOT_GRANTED} prohibit"
                ),
            ]
        );
        assert!(
            from_teardown.ends_with(&from_sweep),
            "a stop that knows the address and a sweep that recovers it must clear the same \
             leftovers: {from_teardown:#?}"
        );
    }

    #[test]
    fn a_tenant_workload_is_routed_onto_its_bridge_by_a_host_route() {
        let plan = tenant_plan("acct", "10.128.3.7", "acme");
        let cmds = net().setup_commands(&plan);
        let setup = script(&cmds);
        assert!(setup.contains(&format!("ip link set veth7 master {}", plan.bridge)));
        // The node bridge's prohibit lands before the route that would make the
        // address reachable, and tolerates a copy left by an earlier run.
        assert_eq!(
            setup[setup.len() - 2],
            "ip rule add priority 1200 iif yah0 to 10.128.3.7/32 fwmark 0/0x2000000 prohibit"
        );
        assert_eq!(cmds[cmds.len() - 2].on_failure, OnFailure::ExistsOk);
        assert_eq!(
            setup.last().unwrap(),
            &format!("ip route replace 10.128.3.7/32 dev {}", plan.bridge)
        );
        // Inside the namespace nothing differs: the workload still sees a /24
        // and a gateway at .1, so its image needs to know nothing about tenancy.
        assert!(setup.contains(&"ip -n acct addr add 10.128.3.7/24 dev eth0".to_string()));
        assert!(setup.contains(&"ip -n acct route add default via 10.128.3.1".to_string()));
    }

    #[test]
    fn a_magicdns_resolver_is_named_as_denied_and_a_public_one_is_not() {
        // us-east-001 and us-west-001, /run/systemd/resolve/resolv.conf, read
        // 2026-09-15 — the file an isolated namespace actually gets.
        assert!(mesh_pool_nameservers("nameserver 213.186.33.99\nsearch .\n").is_empty());
        // us-west-011, same file, same day.
        assert!(
            mesh_pool_nameservers("nameserver 1.1.1.1\nnameserver 9.9.9.9\nsearch .\n").is_empty()
        );
        // /etc/resolv.conf on all three: the systemd-resolved stub. Loopback,
        // so not in the pool — a different unreachability, and one
        // `resolver_mount_source` already ranks out.
        assert!(mesh_pool_nameservers("nameserver 127.0.0.53\noptions edns0 trust-ad\n").is_empty());
        // What a node with MagicDNS on would carry.
        assert_eq!(
            mesh_pool_nameservers(
                "# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).\n\
                 nameserver 100.100.100.100\nsearch tail9a3f.ts.net .\n"
            ),
            vec![Ipv4Addr::new(100, 100, 100, 100)],
            "the MagicDNS resolver is a tailnet address, so it is inside the pool by construction"
        );
        // Commented out is not configured.
        assert!(mesh_pool_nameservers("#nameserver 100.100.100.100\n").is_empty());
        // The whole pool, not just the one address.
        assert_eq!(mesh_pool_nameservers("nameserver 100.64.0.1\n").len(), 1);
        assert!(mesh_pool_nameservers("nameserver 100.128.0.1\n").is_empty());
    }

    #[test]
    fn a_malformed_range_is_refused_rather_than_defaulted() {
        assert!(Ipv4Cidr::parse("10.128.0.0").is_err());
        assert!(Ipv4Cidr::parse("10.128.0.0/33").is_err());
        assert!(Ipv4Cidr::parse("not-an-address/9").is_err());
    }
}

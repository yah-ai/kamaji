//! Shared containerd backend core for Kamaji's two deployment shapes
//! (R592-T1).
//!
//! Kamaji ships the same containerd-backed workload lifecycle twice:
//!
//! - **Inlined** — [`kamaji::containerd`](../../kamaji/src/containerd.rs),
//!   behind `Arc<dyn Kamaji>`, for callers that embed Kamaji in their own
//!   process tree (the desktop app).
//! - **Sibling** — [`kamaji_bin::containerd`](../../kamaji-bin/src/containerd.rs),
//!   behind the W154 postcard-over-UDS protocol, for the cloud-tier
//!   `kamaji.service` daemon.
//!
//! `kamaji` and `kamaji-bin` do not depend on each other (verified before
//! this crate was added — both are leaves that separately depend on
//! `kamaji-proto` + `workload-spec`), so there was no existing direction to
//! extract shared code into one of the two. This crate is the "smallest
//! workable shape" fallback: a new, minimal workspace member both sides
//! depend on for the genuinely-identical pieces of the containerd backend —
//! OCI runtime-spec construction, image digest / rootfs-snapshot resolution,
//! and task-status querying. The higher-level deploy/teardown/list
//! sequencing stays in each crate because it's genuinely different there
//! (e.g. the inlined side keeps a `RestartLedger`; the sibling side runs
//! FIFO-backed journald log forwarders) — merging that would be a redesign,
//! not a refactor.
//!
//! ## R592-T1 capability-set finding
//!
//! Pre-merge, the inlined shape granted `CAP_KILL` + `CAP_NET_BIND_SERVICE`
//! in the OCI bounding/effective/permitted sets; the sibling shape granted
//! only `CAP_NET_BIND_SERVICE` (its own doc comment cites this as the W154
//! "Runtime parity contract" — the two were already supposed to match and
//! had drifted). [`GRANTED_CAPABILITY`] adopts the narrower, sibling-shape
//! set as the one true behavior: it's the documented contract, and it's the
//! safer of the two (strictly less privilege). The `containerd-integration`
//! feature is not enabled on any shipping desktop build today (the desktop
//! Cargo dep only turns on `docker-integration`), so this is a behavior
//! change on a currently-dormant code path, not a shipped one — flagged in
//! the R592-T1 handoff regardless.
//!
//! @yah:ticket(R590-B7, "kamaji workload containers have no network egress or DNS (loopback-only netns) — blocks rusty-v8-musl on-box green (git clone exit 128)")
//! @yah:status(review)
//! @yah:at(2026-07-12T00:14:41Z)
//! @yah:assignee(agent:claude)
//! @yah:parent(R590)
//! @yah:severity(blocks-on-box-green)
//! @yah:next("Give workload containers outbound network + DNS. Minimal path for the build-worker case: run in the HOST network namespace (or bind-mount /etc/resolv.conf + attach a veth/CNI bridge with NAT). The forge/build workload only needs egress to fetch sources. Fix site: the OCI spec builder in kamaji-containerd-core, which currently isolates the netns with only lo.")
//! @yah:verify("A diagnostic container on us-west-002 shows a routable interface + working /etc/resolv.conf and `curl -sS https://github.com` returns 200; then `yah qed run rusty-v8-musl` gets build-v8.sh past the clone into the actual compile.")
//! @yah:gotcha("PROVEN live on us-west-002 (2026-07-11) via a diagnostic container: inside a kamaji-deployed workload, /etc/resolv.conf = 'No such file or directory' and `ip addr` shows ONLY loopback (127.0.0.1/8, ::1) — no eth0, no host-network, no CNI. build-v8.sh reached 'cloning rusty_v8 v149.4.0' then died exit 128 (git clone cannot resolve/reach github). Matches the us-west-002 machine TOML note that CAP_NET_ADMIN + network-namespace/CNI setup is a FUTURE capability.")
//! @yah:handoff("FIXED + PROVEN LIVE (2026-07-11). Two edits: (1) oss/qed/crates/task/src/remote.rs build_workload_spec sets annotations[yah.network]=host on every remote forge workload (tier=infra, kamaji-guarded); (2) oss/kamaji/crates/kamaji-containerd-core/src/lib.rs build_oci_spec bind-mounts host /etc/resolv.conf read-only when wants_host_network() (raw runc doesn't synthesize it; builder image ships none). Rebuilt yah CLI + cross-built/redeployed kamaji 0.8.19 to us-west-002. RESULT: `yah qed run rusty-v8-musl-verify` -> container RUNNING with host netns -> build-v8.sh git-clone of rusty_v8 v149.4.0 SUCCEEDS, pulling v8src/buildtools/abseil-cpp/icu/... (previously exit 128 on the first clone). The native x86 V8 compile is underway (~1h49m). Cross-build env reminder: DOCKER_DEFAULT_PLATFORM=linux/amd64 + YAH_REPO_ROOT=<repo>.")
//!
//! @yah:ticket(R590-B8, "kamaji ignores image OCI config (ENTRYPOINT/ENV/CMD) — only reads rootfs.diff_ids; workloads must supply full argv+env")
//! @yah:at(2026-07-12T15:25:00Z)
//! @yah:status(review)
//! @yah:assignee(agent:claude)
//! @yah:parent(R590)
//! @yah:severity(blocks-on-box-green)
//! @yah:next("Merge the image OCI config into the container process spec per docker/OCI convention: process.args = image.Entrypoint ++ (workload argv or image.Cmd); process.env = image.Env overlaid by workload env; honor image.WorkingDir. Then P018 runs as authored (single-string argv under the image's bash -c entrypoint) and image-baked build vars apply without the pipeline restating them.")
//! @yah:verify("A container-run step with only `image` + a bare command (no explicit bash -c / env) runs with the image's entrypoint + env applied. .yah/qed/P018-rusty-v8-musl-verify.toml (the workaround that inlines both) can then be deleted and P018 runs green.")
//! @yah:gotcha("kamaji-containerd-core parses the image config but reads ONLY rootfs.diff_ids (~line 239-249); sets entrypoint:None (~517) and builds container env solely from the workload spec (~367). So the builder image's `ENTRYPOINT [\"bash\",\"-c\"]` and baked ENV (PATH, V8_FROM_SOURCE, GN, NINJA, CLANG_BASE_PATH, RUSTC_BOOTSTRAP) are DROPPED. P018-rusty-v8-musl.toml was authored assuming ENTRYPOINT+ENV merge; container exec failed 'no such file or directory' on the one-string argv until worked around.")
//!
//! @yah:ticket(R881-B7, "Isolated-netns containers get the host's LOOPBACK resolver stub bind-mounted, so every DNS lookup inside them times out")
//! @yah:status(review)
//! @yah:at(2026-09-11T07:02:48Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R881)
//! @yah:severity(high)
//! @yah:gotcha("R881-T3'S PREMISE IS WRONG FOR A LOOPBACK STUB RESOLVER, AND THE TEST BESIDE IT ALREADY NAMES THE HAZARD. lib.rs:1145-1152 justifies widening the resolv.conf bind past wants_host_network() with: \"a workload joining a namespace kamaji wired has a default route and egress NAT, so the host's resolver is exactly as reachable from inside it as from the host.\" That holds only when the host's nameserver is a ROUTABLE address. On Debian/Ubuntu with systemd-resolved — the fleet's OS — /etc/resolv.conf is the stub `nameserver 127.0.0.53`, and loopback is PER-NETNS. Bind-mounting it into an isolated netns hands the container a 127/8 address with nothing listening behind it. The test docstring at lib.rs:1817-1820 states the exact failure mode it produces: \"a resolv.conf pointing at an unreachable nameserver turns an instant failure into a DNS timeout on every lookup.\" That is what shipped — through the loopback door the author did not check, not the empty-netns door they did.")
//! @yah:gotcha("MEASURED LIVE, NOT INFERRED — us-east-001 (51.81.85.145), containerd ns `yah`, workload noisetable-account, pid 628063, 2026-09-10 by @Glimmerstone:griffin from the noisetable camp. Read-only; NOTHING was changed on the node and no file was edited in either repo. Inside the container's netns: `ip -4 addr` = lo + `eth0@if8 inet 10.128.3.2/24`, `ip route` = `default via 10.128.3.1 dev eth0` — so R881's addressing fix IS working and this is the next layer down, not a regression of it. Inside its mount ns: /etc/resolv.conf = `nameserver 127.0.0.53` + `search .`, i.e. the host's systemd-resolved stub-resolv.conf verbatim. Egress is FINE and that is the discriminator: from inside the netns, TCP connect to 34.149.236.64:587 (smtp.mailgun.org) SUCCEEDS, as does :443, and TCP 1.1.1.1:53 succeeds. Only name resolution fails. The user-visible symptom was `POST https://api.noisetable.com/api/v1/auth/magic-link/request` returning 502 {\"error\":\"mailer_transport\",\"message\":\"mailer transport: smtp: Connection error: failed to lookup address information: Try again\"} — EAI_AGAIN, the timeout shape, exactly as the test docstring predicts.")
//! @yah:next("FIX SITE IS ONE `if`: oss/kamaji/crates/kamaji-containerd-core/src/lib.rs:1153-1159. Today it is `let has_ip_egress = spec.wants_host_network() || pod.join_netns.is_some();` then an unconditional bind of /etc/resolv.conf. The bind is right for a HOST-networked workload (loopback there IS the host's, so 127.0.0.53 resolves) and wrong for an isolated netns. Suggested shape, but the design is the picker-upper's: when NOT wants_host_network(), parse the host /etc/resolv.conf and if every `nameserver` line is in 127.0.0.0/8, do not bind it — bind /run/systemd/resolve/resolv.conf instead, which systemd-resolved maintains with the REAL upstream servers and which exists on every fleet node. Fall back to synthesizing a file under the workload's state dir if neither is usable. Do NOT simply hardcode 1.1.1.1: kamaji already has a resolver-selection precedent on the microVM path (MicroVmConfig.network.dns, default 1.1.1.1, oss/kamaji/crates/kamaji/src/microvm.rs) and the container path should reuse that policy rather than invent a second one — plausibly by making the resolver a field the spec can set, which is also what an air-gapped or split-horizon node will need.")
//! @yah:verify("EXTEND THE EXISTING TEST RATHER THAN ADDING A PARALLEL ONE — `a_joined_netns_gets_the_host_resolver_and_a_bare_one_does_not` at lib.rs:1822 is the right home and its docstring already argues this ticket's case. It needs a third axis the OCI-spec-only assertion cannot reach today: WHICH file gets bound, given a host resolv.conf whose nameservers are all loopback. That means factoring the choice into a pure function (host resolv.conf contents + netns shape -> source path or None) so it is unit-testable without a node, then asserting: all-loopback + isolated netns -> /run/systemd/resolve/resolv.conf; all-loopback + host netns -> /etc/resolv.conf (unchanged, still correct); routable nameserver + isolated netns -> /etc/resolv.conf (unchanged); no usable source -> no mount, since runc refuses a missing source.")
//! @yah:verify("LIVE ACCEPTANCE, END TO END, AND IT NEEDS THE noisetable CAMP: after redeploying kamaji to us-east-001, `sudo nsenter -t $(sudo ctr -n yah t ls | grep account | awk '{print $2}') -n getent hosts smtp.mailgun.org` returns an address, and then `curl -sS -X POST https://api.noisetable.com/api/v1/auth/magic-link/request -H 'Content-Type: application/json' -H 'Origin: https://noisetable.com' -d '{\"email\":\"<an address you can read>\"}'` returns 2xx instead of the 502 above AND the mail arrives. That last leg is the real oracle: the Mailgun event log for noisetable.com currently shows ZERO events ever, so a non-502 with no delivered event would mean this ticket moved the failure rather than fixed it. Node access is `ssh -i ~/.ssh/yah debian@51.81.85.145` — a bare `ssh debian@...` is publickey-denied.")
//! @yah:verify("CROSS-REPO POINTER: the consumer-side ticket is noisetable R131-T12 (.yah/services/noisetable-api/mirrors/cloud.toml), currently in review believing the deploy is complete. It is not — sign-in is dead at the mail step for this reason. Whoever fixes this should say so there; that camp's operator was asking why no email had arrived when this was found.")
//! @yah:gotcha("BLAST RADIUS IS EVERY ISOLATED-NETNS CONTAINER ON THE FLEET, not one noisetable service. Any workload that resolves a name — fetching from crates.io, calling an external API, reaching an SMTP relay, talking to another service by hostname — is broken the same way the moment it stops being host-networked, and it fails as a slow timeout rather than a clean error, so it will read as flakiness. noisetable-account is merely the first one deployed in that shape, exactly as it was the first to hit R881 itself. Tier: Warrior — the diagnosis is finished and the fix site is one branch, but it needs a real test seam, a kamaji cross-build and a fleet redeploy to prove.")
//! @yah:handoff("CODE LANDED, ONE FILE, oss/kamaji/crates/kamaji-containerd-core/src/lib.rs. New pure `resolver_mount_source(host_networked, &HostResolvers) -> Option<&'static str>` plus `HostResolvers::read()` (the only IO) and consts HOST_RESOLV_CONF / SYSTEMD_RESOLVED_UPSTREAM. build_oci_spec_with's resolv.conf branch now binds whatever that returns instead of a hardcoded /etc/resolv.conf; `has_ip_egress` is unchanged. Candidates are RANKED, not first-hit: under host networking the host file always wins (its loopback IS the container's); in an isolated netns a file scores 2 when every nameserver is routable, 1 when only some are, and is discarded at 0 — so a mixed loopback+routable file loses to systemd-resolved's all-routable one, because each loopback entry costs a per-lookup timeout. Ties break on array order (/etc first). NOTHING IS SYNTHESIZED when no candidate is usable: no mount at all, which is a refused connection on the first lookup instead of a 5s timeout on every one. Deliberately did not invent a resolver address — that would be a second policy beside the microVM path's GuestNetwork::dns (kamaji/src/microvm.rs:553, default 1.1.1.1); if a node ever needs one (air-gapped, split-horizon) it belongs in the spec and both paths should read it from there, which is a workload-spec change this ticket does not need.")
//! @yah:verify("cargo test -p kamaji-containerd-core --features containerd-integration --lib: 37 passed / 0 failed, including the extended a_joined_netns_gets_the_host_resolver_and_a_bare_one_does_not. NOTE the feature flag is load-bearing — the crate is `#![cfg(feature = \"containerd-integration\")]` in full, so a bare `cargo test -p kamaji-containerd-core` compiles it to nothing and reports `0 passed` while looking green. clippy -p kamaji-containerd-core --features containerd-integration --all-targets: 0 warnings (one pre-existing needless_lifetimes on the test helper network_ns was fixed in passing).")
//! @yah:gotcha("TAILSCALE MAGICDNS IS THE ONE CASE THIS RANKING WAVES THROUGH ON REASONING RATHER THAN MEASUREMENT. oss/yubaba/crates/cloud/src/cloud_init.rs:454 notes that a node which accepts MagicDNS has tailscaled rewrite /etc/resolv.conf to 100.100.100.100 — not loopback, so it scores 2 and gets bound into the container unchanged. I believe it works: container_net's NAT rule (kamaji/src/container_net.rs:498-514) masquerades everything leaving the node that is not headed out the bridge, so a packet to 100.100.100.100 is SNATed to the host and tailscaled answers it on tailscale0. NOT MEASURED — us-east-001 is on the systemd stub, not MagicDNS, so no fleet node exercises it today. If a MagicDNS node ever shows container DNS timing out, this is the first thing to check.")
//! @yah:verify("THE RANKING'S CHOSEN CANDIDATE IS CONFIRMED REACHABLE FROM INSIDE THE CONTAINER'S NETNS — measured 2026-09-10 by @Glimmerstone:griffin from the noisetable camp, read-only, BEFORE any redeploy, so the landed code's premise is evidence rather than reasoning. On us-east-001 AND us-west-001, identically: /etc/resolv.conf = `nameserver 127.0.0.53` (scores 0, discarded) and /run/systemd/resolve/resolv.conf = `nameserver 213.186.33.99`, OVH's resolver, single entry, all-routable (scores 2, wins). The file is -rw-r--r-- systemd-resolve:systemd-resolve, 788 bytes, so a read-only bind needs no privilege. THE DECISIVE LEG, which a unit test on the OCI spec cannot reach: a real UDP DNS query for smtp.mailgun.org sent to 213.186.33.99:53 from INSIDE the live noisetable-account netns (nsenter -t <pid> -n, containerd ns `yah`) returned rcode=0 with 1 answer. So the SNAT reasoning holds for a real resolver on a real node, and a redeploy should fix this outright rather than trading a loopback stub for an unreachable upstream.")
//! @yah:gotcha("ALL THREE NODES NOW MEASURED — and south is the case that proves the ranking was the right design, not the binary is-it-loopback check the ticket originally suggested. My earlier \"south is unchecked\" gotcha is deleted rather than corrected beside itself; the ssh identity was fine, the USER was wrong — .yah/infra/machines/us-south-001.toml:97 says `ssh = \"root@45.32.194.254\"` (Vultr image), not the `debian@` that opens the two OVH boxes. Read as root 2026-09-10: south has NO /run/systemd/resolve/resolv.conf at all (ABSENT — systemd-resolved is not managing resolv.conf there), and /etc/resolv.conf carries four real nameservers: 108.61.10.10 (Vultr), 9.9.9.9 (Quad9), 2001:19f0:300:1704::6, 2620:fe::fe. No loopback stub anywhere. Under the landed ranking /etc/resolv.conf scores routable and systemd_upstream is None, so south correctly binds /etc/resolv.conf — the opposite candidate from east and west, chosen by the same rule. A binary loopback check would also have worked here; the ranking earns its keep on mixed files.")
//! @yah:next("ONE REFINEMENT WORTH MAKING WHILE YOU ARE IN THE PREDICATE — THE ROUTABILITY TEST IS ADDRESS-FAMILY-BLIND. It excludes loopback (127/8, ::1) and unspecified, so a global-scope IPv6 nameserver scores as routable. But a container netns has NO IPv6 AT ALL: measured inside the live noisetable-account netns on us-east-001, `ip -6 addr` shows only `::1/128` on lo and `ip -6 route` is EMPTY — container_net.rs wires an IPv4 veth and IPv4 NAT and nothing else. So an IPv6 nameserver bound into a container's resolv.conf is unreachable by construction on every node today, and it is scored as healthy. This is LATENT, NOT LIVE, and does not block the redeploy: east and west are all-loopback so their /etc/resolv.conf loses regardless, and south's file leads with two IPv4 entries that glibc (MAXNS=3, tried in order) reaches first. It bites when a file is ordered IPv6-first or its leading IPv4 resolver fails — precisely the per-lookup-timeout cost the ranking exists to avoid, arriving through the family axis instead of the loopback axis. Cheapest fix: count an IPv6 nameserver as non-routable while the container path is IPv4-only, or better, pass the netns's actual address families into the predicate so it stops being a standing assumption. Same shape of mistake as R881-T3's original premise: a nameserver that is routable from the HOST is not automatically reachable from the CONTAINER.")
//! @yah:next("LIVE ACCEPTANCE NEEDS A PAIRED SHIP, NOT A KAMAJI-ONLY ONE. kamaji and yubaba self-install as a pair (kamaji-proto version.rs says so: \"the skew window is a restart rather than a rolling fleet upgrade\"), and this tree's kamaji cannot talk to a released yubaba. So whoever finishes this either ships BOTH halves from a tree whose yubaba half is shippable (today it carries R850's in-flight recovery_journal and cloud-reconciler edits), or waits for the next release and verifies against that. The acceptance commands are unchanged and are in this ticket's verify list; the node-side checks that discriminate a real pass are `sudo nsenter -t $(sudo ctr -n yah t ls | grep account | awk '{print $2}') -m cat /etc/resolv.conf` showing a ROUTABLE nameserver (expect 213.186.33.99, us-east-001's upstream) instead of 127.0.0.53, and then `getent hosts smtp.mailgun.org` from inside.")
//! @yah:handoff("LIVE ACCEPTANCE ATTEMPTED AND ROLLED BACK — the fix is NOT proven live, and the reason is a protocol skew that has nothing to do with the fix. `scripts/hotship.sh --nodes us-east-001 --binaries kamaji` put 0.8.38-h4 (this tree) beside the node's released yubaba 0.8.37. The tree carries an unreleased kamaji-proto bump to V10 (R850-T4, uncommitted in oss/kamaji/crates/kamaji-proto/src/version.rs) that removes AckKind::Deploy and renumbers the rest, so the two halves misframed (`decode failed: frame too large: 542393671 > 1048576`) and yubaba silently fell back to its in-process containerd runtime, which wires no netns — see R881-B8, filed from this session. RESTORED to published bytes with `scripts/roll-node.sh us-east-001 --to 0.8.37 --yes`, then one `yah cloud workload rolling noisetable-account`; the kamaji journal shows `container network namespace wired ... address=10.128.3.2 gateway=10.128.3.1` at 06:57:28 UTC and the container is back to eth0 10.128.3.2 with the loopback-stub resolv.conf, i.e. exactly the pre-session state this ticket describes. Net change to the node: none.")
//! @yah:verify("HOST-SIDE PREMISE CONFIRMED ON THE REAL NODE, which is what makes the ranking correct rather than plausible: us-east-001's /etc/resolv.conf is a symlink to ../run/systemd/resolve/stub-resolv.conf carrying `nameserver 127.0.0.53` + `search .`, and /run/systemd/resolve/resolv.conf exists (root:systemd-resolve 0644) carrying `nameserver 213.186.33.99` + `search .`. So on this fleet the function's isolated-netns branch picks the upstream file and the host-networked branch keeps the stub — both exercised by the unit test, both grounded in a file I read on the node.")
//! @yah:handoff("GUARD ADDED SO THIS CANNOT RECUR — scripts/hotship.sh now refuses to ship exactly one of {kamaji, yubaba} when the tree's kamaji_proto::ProtocolVersion has moved past the last `release v*` commit's (new `--allow-proto-skew` overrides; `--no-restart` downgrades it to a warning, since staged bytes only bite on the next restart). The comparison is local and node-free: highest `V<n>` variant in oss/kamaji/crates/kamaji-proto/src/version.rs, working tree vs `git show <release-commit>:`. Operator-approved 2026-09-11. Verified by running it: `scripts/hotship.sh --nodes us-east-001 --binaries kamaji --dry-run` now exits 1 with \"This tree speaks ProtocolVersion V10; the last release (release v0.8.37) speaks V9\" and suggests `--binaries kamaji,yubaba`; `bash -n` clean. Rationale is in the script's own header under \"kamaji/yubaba pairing\" — the point is that the failure it prevents is SILENT on both sides and presents as a networking bug.")
//! @yah:handoff("PROVEN LIVE ON us-east-001, 2026-09-11 07:02 UTC, end to end. The operator authorized the paired ship after the kamaji-only attempt failed; `scripts/hotship.sh --nodes us-east-001 --binaries kamaji,yubaba` put 0.8.38-h5 on both halves (health reports version=0.8.38-h5 AND kamaji_version=0.8.38-h5, which is the tell that the sibling handshake agreed), then one `yah cloud workload rolling noisetable-account --path ~/ss/noisetable` redeployed the workload on the same pinned digest sha256:9237b7b1. NOTE the node now runs hotship bytes that are on no CDN manifest, and they carry other relays' in-flight work — R850's kamaji-proto V10 + recovery_journal and @Glimmerstone:polaris's native-exec cgroup confinement (native workloads on that box now get memory.max/cpu.max leaves). That is the operator's decision, recorded here so the next roll-node.sh run is understood as reverting it.")
//! @yah:verify("NOT PROVEN BY ME, and it is the one leg the ticket called the real oracle: that the message ARRIVES. I cannot read human@yah.dev's mailbox and the Mailgun event log needs the noisetable camp's credential — its log showed zero events ever, so a non-502 with no delivered event would mean the failure moved rather than went away. The operator can settle it by looking for a noisetable sign-in mail sent at 07:0x UTC 2026-09-11; if none arrived, this ticket is not done and the next suspect is Mailgun-side (domain verification / From: header, per the noisetable mirror's own gotcha), not DNS.")
//! @yah:gotcha("THE BUG WAS REAL AND THE FIX IS WHAT MOVED IT — the discriminator is that nothing else changed between the 502 and the 200: same image digest, same spec, same node, same Mailgun account. Only the bound resolver file differs.")
//! @yah:verify("LIVE EVIDENCE, in the order it was taken. (1) OCI spec of the running container, read with `ctr -n yah c info noisetable-account`: mount `{destination: /etc/resolv.conf, type: bind, source: /run/systemd/resolve/resolv.conf, options: [rbind, ro, nosuid, nodev]}` — the new branch, naming the upstream file, where every previous deploy named /etc/resolv.conf. Network namespace entry carries `path: /var/run/netns/noisetable-account`. (2) Inside the container's mount ns: /etc/resolv.conf = `nameserver 213.186.33.99` + `search .`, where it was `nameserver 127.0.0.53` before. (3) Inside its netns: `getent hosts smtp.mailgun.org` returns `34.149.236.64` — this is the exact command the ticket named and it had never returned an address. (4) `curl -X POST https://api.noisetable.com/api/v1/auth/magic-link/request -H 'Origin: https://noisetable.com' -d '{\"email\":\"human@yah.dev\"}'` => HTTP 200 {\"ok\":true}, against a baseline of 502 {\"error\":\"mailer_transport\",\"message\":\"... failed to lookup address information: Try again\"}. The mailer submits synchronously, so a 200 means the SMTP transport resolved, connected and was accepted.")

#![cfg(feature = "containerd-integration")]

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use containerd_client::{
    services::v1::{
        containers_client::ContainersClient,
        content_client::ContentClient,
        images_client::ImagesClient,
        snapshots::{snapshots_client::SnapshotsClient, MountsRequest, PrepareSnapshotRequest},
        tasks_client::TasksClient,
        version_client::VersionClient,
        CreateTaskRequest, DeleteTaskRequest, GetImageRequest, GetRequest, KillRequest,
        ReadContentRequest, WaitRequest,
    },
    tonic::{self, transport::Channel, Request},
    with_namespace,
};
use workload_spec::WorkloadSpec;

// ── Shared constants ──────────────────────────────────────────────────────────

/// Default containerd socket path (Linux production + Colima on macOS).
pub const DEFAULT_SOCKET: &str = "/run/containerd/containerd.sock";

/// Containerd namespace for all yah-managed workloads. Containerd's
/// namespace model provides tenant isolation without a separate daemon; both
/// deployment shapes use the same namespace so reconciliation and listing
/// agree on what "yah-managed" means.
pub const YAH_NAMESPACE: &str = "yah";

/// Directory prefix for container log files (`<LOG_BASE>/<namespace>/<container_id>/`).
pub const LOG_BASE: &str = "/var/log/yah";

/// The sole capability granted in the OCI bounding/effective/permitted sets
/// beyond the fully-dropped baseline — binds privileged (<1024) TCP ports
/// without a broader grant. See the module doc's "R592-T1 capability-set
/// finding" for why this is the narrower of the two pre-merge sets.
pub const GRANTED_CAPABILITY: &str = "CAP_NET_BIND_SERVICE";

/// The extra capabilities granted *only* to a `yah.sandbox=nested` workload
/// (R636-B2) — the pair `rootlesskit` needs to exec the setuid-root
/// `newuidmap` / `newgidmap` helpers that populate a user namespace's id
/// maps. Granting them also requires `noNewPrivileges = false`, which
/// [`build_oci_spec_with`] sets on the same condition; with `no_new_privs`
/// left on the kernel strips the helpers' setuid bit and they fail with
/// "Could not set caps".
///
/// This is deliberately not `CAP_SYS_ADMIN`: a *non*-rootless buildkitd would
/// need that instead, and it is a far wider grant. See
/// `workload_spec::WorkloadSpec::wants_nested_sandbox` for the measured
/// ladder showing each of the three relaxations is individually necessary.
pub const NESTED_SANDBOX_CAPABILITIES: [&str; 2] = ["CAP_SETUID", "CAP_SETGID"];

// ── Connection + client construction ──────────────────────────────────────────

/// Connect to a containerd UDS at `socket`, returning the raw `tonic`
/// channel. Callers wrap this in their own backend struct alongside their
/// own extra state (restart ledger, log-forwarder tracking, etc).
pub async fn connect(socket: impl AsRef<Path>) -> Result<Channel> {
    let path = socket.as_ref().to_path_buf();
    containerd_client::connect(&path)
        .await
        .with_context(|| format!("connecting to containerd socket {}", path.display()))
}

pub fn containers_client(channel: &Channel) -> ContainersClient<Channel> {
    ContainersClient::new(channel.clone())
}

pub fn tasks_client(channel: &Channel) -> TasksClient<Channel> {
    TasksClient::new(channel.clone())
}

pub fn images_client(channel: &Channel) -> ImagesClient<Channel> {
    ImagesClient::new(channel.clone())
}

pub fn version_client(channel: &Channel) -> VersionClient<Channel> {
    VersionClient::new(channel.clone())
}

pub fn content_client(channel: &Channel) -> ContentClient<Channel> {
    ContentClient::new(channel.clone())
}

pub fn snapshots_client(channel: &Channel) -> SnapshotsClient<Channel> {
    SnapshotsClient::new(channel.clone())
}

// ── Image / rootfs resolution ─────────────────────────────────────────────────

/// Image reference string used as the containerd image-store lookup key.
///
/// A **pinned** image resolves content-addressed as
/// `"ghcr.io/foo/bar:v1.2.3@sha256:..."`; an **unpinned** image (the all-zeros
/// [`workload_spec::ImageRef::UNPINNED_DIGEST`] sentinel — a dev build or a
/// not-yet-published catalog image such as the from-source build-worker image)
/// falls back to the tag-only `"ghcr.io/foo/bar:latest"`. Containerd stores a
/// tag-pulled image under its `registry/repo:tag` name, so the sentinel digest
/// must be dropped or `resolve_image_target_digest` never matches (R590-B5).
pub fn image_ref(spec: &WorkloadSpec) -> String {
    spec.image.pull_ref()
}

/// Compute the OCI rootfs chainID from a layer set's `diff_ids`, matching
/// containerd's `identity.ChainID`: fold sha256 over `"{prev} {next}"` of the
/// full `sha256:...` digest strings. The committed snapshot of an unpacked
/// image is keyed by this chainID — it's the `parent` for the active
/// snapshot a task runs on.
pub fn chain_id(diff_ids: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut iter = diff_ids.iter();
    let mut chain = match iter.next() {
        Some(first) => first.clone(),
        None => return String::new(),
    };
    for next in iter {
        let mut hasher = Sha256::new();
        hasher.update(format!("{chain} {next}").as_bytes());
        chain = format!("sha256:{:x}", hasher.finalize());
    }
    chain
}

/// Look up `image_ref` in containerd's image store and return its target
/// descriptor digest — callers walk that (manifest → config → diff_ids) to
/// prepare the rootfs snapshot via [`prepare_rootfs`]. Callers are expected
/// to have pre-pulled the image via `ctr images pull` or a provider
/// bootstrap; a missing image surfaces as an error naming the ref.
pub async fn resolve_image_target_digest(
    channel: &Channel,
    namespace: &str,
    image_ref: &str,
) -> Result<String> {
    let mut imgs = images_client(channel);
    let req = GetImageRequest {
        name: image_ref.to_string(),
    };
    let req = with_namespace!(req, namespace);
    let image = imgs
        .get(req)
        .await
        .with_context(|| format!("image not found in containerd: {image_ref} — pre-pull required"))?
        .into_inner()
        .image
        .ok_or_else(|| anyhow!("containerd returned no image record for {image_ref}"))?;
    Ok(image
        .target
        .ok_or_else(|| anyhow!("image {image_ref} has no target descriptor"))?
        .digest)
}

/// Read a content-store blob fully into memory by digest.
pub async fn read_blob(channel: &Channel, namespace: &str, digest: &str) -> Result<Vec<u8>> {
    let req = ReadContentRequest {
        digest: digest.to_string(),
        offset: 0,
        size: 0,
    };
    let req = with_namespace!(req, namespace);
    let mut stream = content_client(channel)
        .read(req)
        .await
        .with_context(|| format!("reading content blob {digest}"))?
        .into_inner();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.message().await? {
        buf.extend_from_slice(&chunk.data);
    }
    Ok(buf)
}

/// Resolve an image's rootfs `diff_ids` by walking (optional index →)
/// manifest → config in the content store. Handles both single-platform
/// manifests and multi-platform indexes (picks the linux/amd64 entry — the
/// only platform run on the cloud tier today).
pub async fn image_diff_ids(
    channel: &Channel,
    namespace: &str,
    target_digest: &str,
) -> Result<Vec<String>> {
    let blob = read_blob(channel, namespace, target_digest).await?;
    let doc: serde_json::Value = serde_json::from_slice(&blob)
        .with_context(|| format!("parsing image target {target_digest} as JSON"))?;

    // Index / manifest-list → pick the linux/amd64 manifest, then recurse.
    if let Some(manifests) = doc.get("manifests").and_then(|m| m.as_array()) {
        let pick = manifests
            .iter()
            .find(|m| {
                let p = m.get("platform");
                let arch = p
                    .and_then(|p| p.get("architecture"))
                    .and_then(|a| a.as_str());
                let os = p.and_then(|p| p.get("os")).and_then(|o| o.as_str());
                arch == Some("amd64") && os == Some("linux")
            })
            .or_else(|| manifests.first())
            .and_then(|m| m.get("digest"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| anyhow!("image index {target_digest} has no usable manifest"))?
            .to_string();
        return Box::pin(image_diff_ids(channel, namespace, &pick)).await;
    }

    // Manifest → config blob → rootfs.diff_ids.
    let config_digest = doc
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
        .ok_or_else(|| anyhow!("image manifest {target_digest} has no config descriptor"))?
        .to_string();
    let config_blob = read_blob(channel, namespace, &config_digest).await?;
    let config: serde_json::Value = serde_json::from_slice(&config_blob)
        .with_context(|| format!("parsing image config {config_digest}"))?;
    let diff_ids = config
        .get("rootfs")
        .and_then(|r| r.get("diff_ids"))
        .and_then(|d| d.as_array())
        .ok_or_else(|| anyhow!("image config {config_digest} has no rootfs.diff_ids"))?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect::<Vec<_>>();
    if diff_ids.is_empty() {
        bail!("image config {config_digest} has empty rootfs.diff_ids");
    }
    Ok(diff_ids)
}

/// The subset of an image's OCI config (`config` object) that shapes the
/// container process: entrypoint, cmd, env, working dir, user. Merged into the
/// runtime spec by [`build_oci_spec`] per docker/OCI convention (R590-B8) so a
/// workload inherits its image's baked `ENTRYPOINT`/`CMD`/`ENV`/`WORKDIR`
/// instead of having to restate them (the rusty-v8 builder relies on
/// `ENTRYPOINT ["bash","-c"]` + baked build vars).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageOciConfig {
    /// Image `Entrypoint` — the prefix of the final argv.
    pub entrypoint: Vec<String>,
    /// Image `Cmd` — the argv tail / default arguments.
    pub cmd: Vec<String>,
    /// Image `Env` entries, each `KEY=VALUE`.
    pub env: Vec<String>,
    /// Image `WorkingDir`, if set and non-empty.
    pub working_dir: Option<String>,
    /// Image `User`, if set and non-empty.
    pub user: Option<String>,
}

impl ImageOciConfig {
    /// Extract the `config` object from a parsed image config document.
    /// Missing/renamed fields degrade to empty — an image with no baked
    /// entrypoint/env simply contributes nothing to the merge.
    pub fn from_config_doc(doc: &serde_json::Value) -> Self {
        let cfg = doc.get("config");
        let str_vec = |key: &str| -> Vec<String> {
            cfg.and_then(|c| c.get(key))
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        let opt_str = |key: &str| -> Option<String> {
            cfg.and_then(|c| c.get(key))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from)
        };
        ImageOciConfig {
            entrypoint: str_vec("Entrypoint"),
            cmd: str_vec("Cmd"),
            env: str_vec("Env"),
            working_dir: opt_str("WorkingDir"),
            user: opt_str("User"),
        }
    }
}

/// Walk (optional index →) manifest → config in the content store and return
/// the parsed image **config document** (the JSON carrying both
/// `rootfs.diff_ids` and the `config` object). Shares the index/platform
/// selection with [`image_diff_ids`] (picks the linux/amd64 entry).
pub async fn image_config_doc(
    channel: &Channel,
    namespace: &str,
    target_digest: &str,
) -> Result<serde_json::Value> {
    let blob = read_blob(channel, namespace, target_digest).await?;
    let doc: serde_json::Value = serde_json::from_slice(&blob)
        .with_context(|| format!("parsing image target {target_digest} as JSON"))?;

    // Index / manifest-list → pick the linux/amd64 manifest, then recurse.
    if let Some(manifests) = doc.get("manifests").and_then(|m| m.as_array()) {
        let pick = manifests
            .iter()
            .find(|m| {
                let p = m.get("platform");
                let arch = p
                    .and_then(|p| p.get("architecture"))
                    .and_then(|a| a.as_str());
                let os = p.and_then(|p| p.get("os")).and_then(|o| o.as_str());
                arch == Some("amd64") && os == Some("linux")
            })
            .or_else(|| manifests.first())
            .and_then(|m| m.get("digest"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| anyhow!("image index {target_digest} has no usable manifest"))?
            .to_string();
        return Box::pin(image_config_doc(channel, namespace, &pick)).await;
    }

    // Manifest → config blob (the JSON document, returned whole).
    let config_digest = doc
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
        .ok_or_else(|| anyhow!("image manifest {target_digest} has no config descriptor"))?
        .to_string();
    let config_blob = read_blob(channel, namespace, &config_digest).await?;
    serde_json::from_slice(&config_blob)
        .with_context(|| format!("parsing image config {config_digest}"))
}

/// Fetch and parse an image's process-shaping OCI config (R590-B8). Best-effort
/// at the call site: a failure here should degrade to `None` (workload runs
/// with spec-only argv/env) rather than aborting the deploy.
pub async fn image_oci_config(
    channel: &Channel,
    namespace: &str,
    target_digest: &str,
) -> Result<ImageOciConfig> {
    let doc = image_config_doc(channel, namespace, target_digest).await?;
    Ok(ImageOciConfig::from_config_doc(&doc))
}

/// Prepare an active overlayfs snapshot for `container_id` rooted at the
/// image's committed layer chain, returning the rootfs mounts to hand to
/// `CreateTaskRequest`. Without this the task gets an empty rootfs and runc
/// fails to exec.
///
/// Idempotent: a redeploy whose snapshot already exists falls back to
/// `Mounts` (read the existing active snapshot's mounts) instead of erroring.
pub async fn prepare_rootfs(
    channel: &Channel,
    namespace: &str,
    container_id: &str,
    image_target_digest: &str,
) -> Result<Vec<containerd_client::types::Mount>> {
    let diff_ids = image_diff_ids(channel, namespace, image_target_digest).await?;
    let parent = chain_id(&diff_ids);

    let prepare = PrepareSnapshotRequest {
        snapshotter: "overlayfs".to_string(),
        key: container_id.to_string(),
        parent,
        labels: std::collections::HashMap::new(),
    };
    let prepare = with_namespace!(prepare, namespace);
    match snapshots_client(channel).prepare(prepare).await {
        Ok(resp) => Ok(resp.into_inner().mounts),
        Err(status) if status.code() == tonic::Code::AlreadyExists => {
            // Snapshot already active (idempotent redeploy) — read its mounts.
            let req = MountsRequest {
                snapshotter: "overlayfs".to_string(),
                key: container_id.to_string(),
            };
            let req = with_namespace!(req, namespace);
            let resp = snapshots_client(channel)
                .mounts(req)
                .await
                .with_context(|| format!("reading existing snapshot mounts for {container_id}"))?;
            Ok(resp.into_inner().mounts)
        }
        Err(status) => {
            Err(anyhow!(status).context(format!("preparing rootfs snapshot for {container_id}")))
        }
    }
}

// ── Task status ────────────────────────────────────────────────────────────────

/// Outcome of probing a container's task, keeping the two "empty" wire
/// conditions distinct so each deployment shape can map them per its own
/// semantics (they had drifted pre-R592-T1: the inlined shape treated a
/// status-without-process reply as unknown code 0 → `Failed`, the sibling
/// folded it into `Pending`).
pub enum TaskProbe {
    /// Task exists and reported a status code + pid. `exit_status` is the
    /// process exit code containerd records once the task has STOPPED (0 while
    /// still running); it lets callers tell a clean exit (0 → `Exited`) from a
    /// failed one (non-zero → `Failed`), which the coarse task-status code
    /// alone cannot — a non-zero exit is still containerd status STOPPED (R590-B12).
    Status {
        code: i32,
        pid: u32,
        exit_status: u32,
    },
    /// No task for this container (created-but-not-started), or containerd
    /// reported `NotFound` for the container itself.
    NoTask,
    /// Anomalous reply: task response arrived without a `process` payload.
    MissingProcess,
}

/// One round-trip to fetch a container's task status + pid.
pub async fn get_task_status(
    tasks: &mut TasksClient<Channel>,
    namespace: &str,
    container_id: &str,
) -> Result<TaskProbe> {
    let req = GetRequest {
        container_id: container_id.to_string(),
        exec_id: String::new(),
    };
    let req = with_namespace!(req, namespace);
    match tasks.get(req).await {
        Ok(resp) => match resp.into_inner().process {
            Some(p) => {
                // containerd task status codes: 3 == STOPPED. `Tasks.Get`
                // frequently reports `exit_status = 0` for a stopped task —
                // the real code rides the shim's exit event, not the Get
                // reply — so a failed one-shot looked like a clean exit
                // (R590-B12). `Tasks.Wait` returns the true exit status
                // immediately for an already-exited task (and doesn't reap
                // it, unlike Delete), so query it once the task is STOPPED.
                let exit_status = if p.status == 3 {
                    let wreq = WaitRequest {
                        container_id: container_id.to_string(),
                        exec_id: String::new(),
                    };
                    let wreq = with_namespace!(wreq, namespace);
                    match tasks.wait(wreq).await {
                        Ok(w) => w.into_inner().exit_status,
                        Err(_) => p.exit_status,
                    }
                } else {
                    p.exit_status
                };
                Ok(TaskProbe::Status {
                    code: p.status,
                    pid: p.pid,
                    exit_status,
                })
            }
            None => Ok(TaskProbe::MissingProcess),
        },
        Err(status) if status.code() == tonic::Code::NotFound => Ok(TaskProbe::NoTask),
        Err(e) => Err(anyhow!("task get failed: {e}")),
    }
}

// ── Task reaping (R854) ───────────────────────────────────────────────────────

/// Containerd task status code for a task whose process has exited
/// (`containerd.v1.types.Status::Stopped`). `Tasks.Delete` only succeeds on a
/// task in this state — deleting a RUNNING one is a `FailedPrecondition`.
const TASK_STATUS_STOPPED: i32 = 3;

/// `SIGKILL` — the hard-teardown signal. A graceful stop goes through the
/// spec's `stop_policy` signal well before anything reaches here.
const SIGKILL: u32 = 9;

/// How long [`reap_task`] will wait for a SIGKILL'd task to actually exit and
/// its record to be deletable.
///
/// A redeploy has to outlive the kernel delivering SIGKILL, the process
/// unwinding, and the shim reaping and publishing the exit — none of which is
/// instantaneous under load. Both backends previously "waited" with a blind
/// 500 ms sleep (inlined) or not at all (sibling), which is the R854 bug:
/// the delete raced the exit, failed, was discarded, and the *next* deploy's
/// `CreateTask` collided with the survivor ("task <ident>: already exists").
/// 15 s is far above the observed exit latency and still well under any
/// operator's patience for a deploy.
pub const TASK_REAP_TIMEOUT: Duration = Duration::from_secs(15);

/// SIGKILL a container's task, WAIT for it to actually die, and delete its
/// record — returning `Ok(())` only once containerd reports no task for
/// `container_id`.
///
/// This is the half of teardown a redeploy depends on: containerd's container
/// record and its task are separate objects, and deleting the container while
/// its task survives leaves an orphan the next `CreateTask` collides with. So
/// the postcondition here is checked, not assumed — the call returns an error
/// naming the surviving task's status rather than reporting a reap it did not
/// perform.
///
/// Idempotent: a container with no task (never started, already reaped, or
/// absent entirely) is `Ok(())` on the first probe, without signalling
/// anything.
pub async fn reap_task(
    tasks: &mut TasksClient<Channel>,
    namespace: &str,
    container_id: &str,
    timeout: Duration,
) -> Result<()> {
    let mut ops = ContainerdTaskOps { tasks, namespace };
    reap_task_with(&mut ops, container_id, timeout).await
}

/// What a `Tasks.Delete` attempt told the reap loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// Delete succeeded, or the record was already gone (`NotFound`) — either
    /// way the postcondition holds and no re-probe is needed.
    Reaped,
    /// Containerd refused (in practice `FailedPrecondition`: "task must be
    /// stopped before deletion") — the task is still there, try again.
    Refused,
}

/// The containerd task operations [`reap_task`] drives, behind a trait so the
/// retry/deadline logic — the part R854 got wrong — can be tested without a
/// containerd socket. The camp's build hosts have no containerd, so a loop
/// that only exists inside a gRPC call is a loop nothing ever checks.
#[allow(async_fn_in_trait)]
pub trait TaskOps {
    async fn probe(&mut self, container_id: &str) -> Result<TaskProbe>;
    /// SIGKILL the task. Best-effort by contract: a missing or already-dead
    /// task is not an error worth surfacing, since the loop re-probes anyway.
    async fn signal_kill(&mut self, container_id: &str);
    /// Block until the task's process exits, or `budget` elapses.
    async fn await_exit(&mut self, container_id: &str, budget: Duration);
    async fn delete(&mut self, container_id: &str) -> DeleteOutcome;
}

/// The reap loop itself, over any [`TaskOps`]. See [`reap_task`] for what it
/// guarantees; this shape exists so the guarantee is testable.
pub async fn reap_task_with<O: TaskOps>(
    ops: &mut O,
    container_id: &str,
    timeout: Duration,
) -> Result<()> {
    // Nothing to reap is the common case (first deploy of an ident) — don't
    // pay a kill round-trip for it. `MissingProcess` and a failed probe are
    // both "can't prove it's gone", so they fall through to the loop.
    if let Ok(TaskProbe::NoTask) = ops.probe(container_id).await {
        return Ok(());
    }

    let deadline = Instant::now() + timeout;
    // Assigned by the probe at the bottom of every pass, and only read after
    // it — the error message names what the survivor's status actually was.
    let mut last_status: Option<i32>;
    let mut backoff = Duration::from_millis(25);

    loop {
        // Repeated each pass: a task that raced into existence between probes
        // still gets signalled, and SIGKILL on an already-dead task is benign.
        ops.signal_kill(container_id).await;

        // Wait on the shim's exit event rather than polling it, bounded by
        // whatever is left of the deadline — a wait that never returns must
        // not hold the deploy open forever.
        if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            ops.await_exit(container_id, remaining).await;
        }

        if ops.delete(container_id).await == DeleteOutcome::Reaped {
            return Ok(());
        }

        match ops.probe(container_id).await {
            Ok(TaskProbe::NoTask) => return Ok(()),
            Ok(TaskProbe::Status { code, .. }) => last_status = Some(code),
            Ok(TaskProbe::MissingProcess) | Err(_) => last_status = None,
        }

        if Instant::now() >= deadline {
            let detail = match last_status {
                Some(TASK_STATUS_STOPPED) => {
                    "task is STOPPED but its record could not be deleted".to_string()
                }
                Some(code) => format!("task still present with status code {code}"),
                None => "task status could not be read".to_string(),
            };
            bail!("timed out after {timeout:?} reaping task for {container_id}: {detail}");
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(500));
    }
}

/// [`TaskOps`] against a live containerd `Tasks` service.
struct ContainerdTaskOps<'a> {
    tasks: &'a mut TasksClient<Channel>,
    namespace: &'a str,
}

impl TaskOps for ContainerdTaskOps<'_> {
    async fn probe(&mut self, container_id: &str) -> Result<TaskProbe> {
        get_task_status(self.tasks, self.namespace, container_id).await
    }

    async fn signal_kill(&mut self, container_id: &str) {
        let req = KillRequest {
            container_id: container_id.to_string(),
            exec_id: String::new(),
            // `all` reaches every process in the task's cgroup, not just pid 1
            // — a forked child holding the cgroup open keeps the task from
            // reaching STOPPED, which is exactly the state that blocks delete.
            all: true,
            signal: SIGKILL,
        };
        let req = with_namespace!(req, self.namespace);
        let _ = self.tasks.kill(req).await;
    }

    async fn await_exit(&mut self, container_id: &str, budget: Duration) {
        // `Tasks.Wait` returns immediately for an already-exited task and does
        // NOT reap it (unlike Delete), so calling it before the delete is safe.
        let req = WaitRequest {
            container_id: container_id.to_string(),
            exec_id: String::new(),
        };
        let req = with_namespace!(req, self.namespace);
        let _ = tokio::time::timeout(budget, self.tasks.wait(req)).await;
    }

    async fn delete(&mut self, container_id: &str) -> DeleteOutcome {
        let req = DeleteTaskRequest {
            container_id: container_id.to_string(),
        };
        let req = with_namespace!(req, self.namespace);
        match self.tasks.delete(req).await {
            Ok(_) => DeleteOutcome::Reaped,
            // Already gone is the postcondition we wanted.
            Err(status) if status.code() == tonic::Code::NotFound => DeleteOutcome::Reaped,
            Err(_) => DeleteOutcome::Refused,
        }
    }
}

/// `Tasks.Create`, self-healing over a stale task record (R854).
///
/// Returns the new task's pid. On `AlreadyExists` — a prior generation's task
/// outliving the teardown that was supposed to reap it — this reaps the
/// survivor via [`reap_task`] and retries the create exactly once, so a
/// back-to-back redeploy is idempotent instead of 500ing and leaving the
/// workload down. Any other error, and a second `AlreadyExists`, propagate:
/// one retry distinguishes a lost race from a genuine invariant break.
pub async fn create_task_reaping_stale(
    tasks: &mut TasksClient<Channel>,
    namespace: &str,
    req: CreateTaskRequest,
) -> Result<u32> {
    let container_id = req.container_id.clone();
    let retry_req = req.clone();

    let first = tasks.create(with_namespace!(req, namespace)).await;
    let err = match first {
        Ok(resp) => return Ok(resp.into_inner().pid),
        Err(status) if status.code() == tonic::Code::AlreadyExists => status,
        Err(status) => return Err(anyhow!(status)),
    };

    reap_task(tasks, namespace, &container_id, TASK_REAP_TIMEOUT)
        .await
        .with_context(|| {
            format!("task for {container_id} already exists ({err}) and could not be reaped")
        })?;

    tasks
        .create(with_namespace!(retry_req, namespace))
        .await
        .map(|resp| resp.into_inner().pid)
        .map_err(|e| {
            anyhow!(e).context(format!(
                "recreating task for {container_id} after reaping a stale one"
            ))
        })
}

// ── OCI runtime-spec building ──────────────────────────────────────────────────

/// Build the OCI `config.json` for a workload spec. Shared by both
/// deployment shapes so capability grants, namespace isolation, and the
/// `/sys` mount strategy cannot drift between them again (R592-T1).
///
/// `extra_env` lets a caller append deployment-shape-specific env entries
/// after the spec's literal env vars — e.g. the inlined shape injects
/// `YAH_MESH_IP=<mesh ip>` (the sibling shape has no mesh-assignment concept
/// yet and passes `&[]`).
/// Parse a numeric `"uid"` or `"uid:gid"` user string. Missing gid mirrors
/// uid (matching runc's own convention); non-numeric parts yield `(0, 0)`.
fn parse_numeric_user(user: &str) -> (u32, u32) {
    let (uid_s, gid_s) = match user.split_once(':') {
        Some((u, g)) => (u, g),
        None => (user, user),
    };
    match (uid_s.trim().parse::<u32>(), gid_s.trim().parse::<u32>()) {
        (Ok(uid), Ok(gid)) => (uid, gid),
        _ => (0, 0),
    }
}

/// The `KEY` portion of a `KEY=VALUE` env entry (the whole string if no `=`).
fn env_key(entry: &str) -> &str {
    entry.split_once('=').map(|(k, _)| k).unwrap_or(entry)
}

/// Merge env layers left-to-right with last-wins on key collision, preserving
/// each key's first-seen position. Used to overlay image `Env` with the
/// workload's literals and any deployment `extra_env` (R590-B8).
fn merge_env(layers: &[&[String]]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for layer in layers {
        for entry in layer.iter() {
            let key = env_key(entry);
            if let Some(pos) = out.iter().position(|e| env_key(e) == key) {
                out[pos] = entry.clone();
            } else {
                out.push(entry.clone());
            }
        }
    }
    out
}

/// Pod-placement overrides for a workload's OCI spec (R600-F7 / W273).
///
/// [`Default`] is the standalone shape every ordinary workload uses — a fresh
/// isolated netns (or the host netns under `yah.network=host`) and no extra
/// mounts. The passway ingress **graceful-upgrade** path (a zero-downtime cert
/// reload) sets these so a *replacement* passway container can share the live
/// one's pingora upgrade socket (and, for an isolated-netns workload, its
/// listening socket's network namespace) while pingora's `SCM_RIGHTS`
/// fd-handoff runs between the two. See [`build_oci_spec_with`].
#[derive(Debug, Default, Clone)]
pub struct PodOptions {
    /// Join this **existing** network namespace by path (e.g.
    /// `/proc/<pause-pid>/ns/net`) instead of creating a fresh isolated one —
    /// the "sandbox-held netns" custody for an isolated-netns workload (W273
    /// option B). Ignored under host networking: a host-networked workload has
    /// no `network` namespace entry to carry a path (the host netns is already
    /// the eternal custodian, so no join is needed).
    pub join_netns: Option<String>,
    /// Bind-mount host directory `.0` into the container at `.1` (read-write).
    /// Used to share the pingora `PASSWAY_UPGRADE_SOCK` directory across the
    /// outgoing + incoming passway containers so the `SIGQUIT`ed old process
    /// can reach the new one over the upgrade socket during the fd-handoff.
    pub shared_dir: Option<(String, String)>,
    /// Staged [`WorkloadSpec::files`] for this generation, bind-mounted
    /// read-only one file at a time (R870-F27). Always the return value of
    /// [`stage_spec_files`] — never re-derived here from `spec.files`, so a
    /// mount in this list is a file that is provably already on disk.
    pub spec_files: Vec<SpecFileMount>,
    /// `(host socket, container destination)` for the node's `yah-scryer`
    /// ingestion socket (R893-B17) — the value of
    /// `kamaji::observe::Collector::guest_bind`.
    ///
    /// A single FILE bind, not the socket's parent directory: `/run/yah` on a
    /// fleet node is also [`UPGRADE_SHARE_ROOT`], so binding the directory
    /// would hand every container every workload's pingora upgrade socket.
    /// Read-write, because `connect(2)` on an `AF_UNIX` socket requires write
    /// permission on the inode — a read-only bind would produce a reachable
    /// path that refuses every connection, which reads as a broken collector
    /// rather than as a wrong mount.
    ///
    /// `None` on a node with no collector configured, which is what every node
    /// did before that ticket.
    pub collector_socket: Option<(String, String)>,
}

// ── Graceful-upgrade pod planning (R600-F7) ─────────────────────────────────
//
// A zero-downtime cert reload swaps the passway *process* while its listening
// socket stays up. In containerd that means two container generations coexist
// for the handoff window: the outgoing one keeps serving until the incoming one
// has adopted its listening fd over the shared pingora upgrade socket, then the
// outgoing one is `SIGQUIT`ed and reaped. Because containerd container ids are
// immutable, the two generations ping-pong between two stable ids ([`PodSlot`]),
// and the backend tracks which slot is currently live per workload identity.

/// The literal env var (set by the passway ingress spec) that names pingora's
/// graceful-upgrade fd-handoff socket. Its presence marks a workload as a
/// graceful-upgrade (passway) workload; its parent directory is the mount point
/// for the shared upgrade-sock bind ([`PodOptions::shared_dir`]).
pub const PASSWAY_UPGRADE_SOCK_ENV: &str = "PASSWAY_UPGRADE_SOCK";

/// The env var kamaji sets on the *incoming* passway process (never on the
/// spec) so pingora starts in upgrade mode: it binds the upgrade socket and
/// waits to receive the outgoing process's listening fds instead of binding
/// fresh.
pub const PASSWAY_UPGRADE_ENV: &str = "PASSWAY_UPGRADE";

/// Host root under which each graceful-upgrade workload gets a per-ident
/// directory that is bind-mounted into every one of its container generations
/// (so they share the upgrade socket inode across mount namespaces).
pub const UPGRADE_SHARE_ROOT: &str = "/run/yah/kamaji";

/// One of the two ping-pong container slots a graceful-upgrade workload
/// alternates between. Slot [`A`](PodSlot::A) is the *bare* mesh identity, so a
/// freshly-deployed workload keeps the historical container id and every other
/// backend method (`get`/`teardown`/`restart`) is unaffected until the first
/// upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PodSlot {
    #[default]
    A,
    B,
}

impl PodSlot {
    /// The other slot — the one the next graceful upgrade lands the incoming
    /// container in.
    pub fn other(self) -> PodSlot {
        match self {
            PodSlot::A => PodSlot::B,
            PodSlot::B => PodSlot::A,
        }
    }

    /// The containerd container id for `ident` in this slot. Slot A is the bare
    /// ident; slot B suffixes it with `.b` (a containerd-legal id char).
    pub fn container_id(self, ident: &str) -> String {
        match self {
            PodSlot::A => ident.to_string(),
            PodSlot::B => format!("{ident}.b"),
        }
    }

    /// Stable one-char tag for this slot (`"a"`/`"b"`), used to give each
    /// generation its **own** upgrade-sock directory (see
    /// [`shared_upgrade_hostdir`]).
    pub fn tag(self) -> &'static str {
        match self {
            PodSlot::A => "a",
            PodSlot::B => "b",
        }
    }
}

/// Host directory bind-mounted into a passway container **generation** as the
/// parent of `PASSWAY_UPGRADE_SOCK`. kamaji creates it at deploy/upgrade time;
/// the container binds its upgrade socket there and kamaji `connect()`s to the
/// same inode via this host path to hand off the listening fd (`SCM_RIGHTS`
/// crosses the mount-namespace boundary).
///
/// The path is **per-generation** (`upgrade-<slot>`), not per-ident: pingora's
/// `get_from_sock` unlinks+rebinds the upgrade socket, so the incoming and
/// outgoing generations must not share one inode or the new bind would clobber
/// the old (R600-F9, W273 §"Handing the fd to a containerized passway").
pub fn shared_upgrade_hostdir(ident: &str, slot: PodSlot) -> std::path::PathBuf {
    Path::new(UPGRADE_SHARE_ROOT)
        .join(ident)
        .join(format!("upgrade-{}", slot.tag()))
}

/// The container-side parent directory of a workload's `PASSWAY_UPGRADE_SOCK`,
/// or `None` when the spec declares no upgrade socket (i.e. it is not a
/// graceful-upgrade / passway workload and needs no shared mount). E.g.
/// `PASSWAY_UPGRADE_SOCK=/run/passway/upgrade.sock` → `Some("/run/passway")`.
pub fn upgrade_sock_dir(spec: &WorkloadSpec) -> Option<String> {
    spec.env.iter().find_map(|e| {
        if e.name != PASSWAY_UPGRADE_SOCK_ENV {
            return None;
        }
        let workload_spec::EnvValue::Literal { value } = &e.value else {
            return None;
        };
        Path::new(value)
            .parent()
            .and_then(|p| p.to_str())
            .map(str::to_string)
    })
}

/// The basename of a workload's `PASSWAY_UPGRADE_SOCK`, or `None` when the spec
/// declares none. kamaji joins this onto the host-side generation directory
/// ([`shared_upgrade_hostdir`]) to reach the socket passway binds inside the
/// container. E.g. `PASSWAY_UPGRADE_SOCK=/run/passway/upgrade.sock` →
/// `Some("upgrade.sock")`.
pub fn upgrade_sock_basename(spec: &WorkloadSpec) -> Option<String> {
    spec.env.iter().find_map(|e| {
        if e.name != PASSWAY_UPGRADE_SOCK_ENV {
            return None;
        }
        let workload_spec::EnvValue::Literal { value } = &e.value else {
            return None;
        };
        Path::new(value)
            .file_name()
            .and_then(|f| f.to_str())
            .map(str::to_string)
    })
}

// ── Spec-carried config files (R870-F27) ────────────────────────────────────
//
// `WorkloadSpec::files` is config the node writes out before the workload
// starts — R870's inner door reads its *entire* mount table from one. The
// native backend writes them straight onto the host filesystem the child
// execs into. A container has no such filesystem until runc has assembled
// one, and the rootfs is an overlay snapshot kamaji never mounts, so the
// equivalent move is: stage each file in a per-generation host directory and
// bind-mount it, one file at a time, at the path the spec names.
//
// Per *file* rather than per *directory* deliberately. A directory bind at
// `/etc/passway` would replace whatever the image ships there, so a spec that
// adds one file would silently delete the image's siblings — and a workload
// whose files land in `/etc` would have its whole `/etc` replaced. A file
// bind touches exactly the declared path. runc creates a missing destination
// for a bind mount (it stats the source and touches a file or mkdirs a dir),
// so the path need not exist in the image.

/// Host directory holding one container generation's materialized
/// [`WorkloadSpec::files`], before they are bind-mounted in (R870-F27).
///
/// Keyed by **container id**, not by mesh identity, and that is the whole
/// reason it is not just `<ident>/files`: a graceful upgrade runs two
/// generations at once ([`PodSlot`]), and the outgoing one must keep reading
/// the table it was started against while the incoming one is staged with the
/// new one.
pub fn spec_files_hostdir(container_id: &str) -> std::path::PathBuf {
    Path::new(UPGRADE_SHARE_ROOT)
        .join(container_id)
        .join("files")
}

/// One materialized [`workload_spec::InlineFile`] — where it was staged on the
/// host, and where it is bind-mounted inside the container.
///
/// Produced only by [`stage_spec_files`], so a mount in this list is a file
/// that is already on disk. [`build_oci_spec_with`] renders
/// [`PodOptions::spec_files`] verbatim and never consults `spec.files` itself:
/// that keeps "the file exists" and "the container mounts it" from being two
/// independently-derived facts that can disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecFileMount {
    /// Absolute host path of the staged copy.
    pub host_path: String,
    /// Absolute in-container path the spec declared.
    pub container_path: String,
}

/// Where each of `spec`'s files is staged under `dir` — the pure half of
/// [`stage_spec_files`], separated so the path rules are testable without
/// touching a filesystem.
///
/// The staging layout mirrors the container tree (`/etc/passway/routes.json`
/// → `<dir>/etc/passway/routes.json`) rather than flattening to basenames,
/// which would collide two files named `config.json` in different
/// directories into one host path and mount the same bytes at both.
///
/// Refuses any path that is not absolute or that contains a `..`. Not
/// hygiene: `dir.join(relative)` with a `..` component escapes the staging
/// directory, so a spec could otherwise name `/etc/../../../../root/.ssh/…`
/// and have kamaji overwrite an arbitrary host file as root. `WorkloadSpec`
/// documents the field as absolute but does not validate it, and this is the
/// first backend for which the difference is exploitable.
///
/// A `.` component needs no refusal — path parsing drops it — but the
/// returned `container_path` is the *normalized* path rather than the
/// spec's literal spelling, so the bind's source and destination describe
/// the same file name for a reader comparing them.
pub fn plan_spec_files(dir: &Path, spec: &WorkloadSpec) -> Result<Vec<SpecFileMount>> {
    use std::path::Component;

    let mut out = Vec::with_capacity(spec.files.len());
    for file in &spec.files {
        let path = file.path.as_path();
        let mut rel = std::path::PathBuf::new();
        let mut components = path.components();
        match components.next() {
            Some(Component::RootDir) => {}
            _ => bail!(
                "workload {}: spec file path {} is not absolute; WorkloadSpec::files paths are \
                 absolute in-container paths",
                spec.name,
                path.display()
            ),
        }
        for component in components {
            match component {
                Component::Normal(part) => rel.push(part),
                _ => bail!(
                    "workload {}: spec file path {} contains a `.`, `..` or prefix component; \
                     only plain absolute paths are materializable (a `..` would escape the \
                     staging directory and write outside the container's view)",
                    spec.name,
                    path.display()
                ),
            }
        }
        if rel.as_os_str().is_empty() {
            bail!(
                "workload {}: spec file path {} names the root directory, not a file",
                spec.name,
                path.display()
            );
        }
        let host_path = dir.join(&rel);
        let container_path = Path::new("/").join(&rel);
        let utf8 = |p: &Path| -> Result<String> {
            p.to_str().map(str::to_string).ok_or_else(|| {
                anyhow!(
                    "workload {}: spec file path {} is not valid UTF-8",
                    spec.name,
                    path.display()
                )
            })
        };
        out.push(SpecFileMount {
            host_path: utf8(&host_path)?,
            container_path: utf8(&container_path)?,
        });
    }
    Ok(out)
}

/// Write `spec`'s [`WorkloadSpec::files`] into the staging directory `dir` and
/// return the bind mounts that expose them (R870-F27).
///
/// `dir` is **emptied first**, so the staging tree is exactly what the current
/// spec declares. That is the container-side counterpart of the native
/// backend's whole-file writes: a redeploy that *drops* a file must not leave
/// the previous deploy's copy on disk, both because a later spec re-declaring
/// that path would otherwise race a stale inode and because these files are
/// config, not scratch.
///
/// Failure is fatal to the deploy rather than logged and stepped over — a door
/// started against an absent route table comes up healthy and routes wrongly,
/// which is the outcome the whole mechanism exists to remove.
///
/// **Ownership is the kamaji process's**, not the container user's. The staged
/// file carries the `mode` the spec asks for, and a bind mount preserves it,
/// so a spec that pairs a restrictive `mode` with a non-root
/// [`WorkloadSpec::user`] produces a file the workload cannot read. Same
/// constraint as the native backend, deliberately: the backends diverging on
/// who owns a materialized file is a worse trap than the one it would fix.
pub async fn stage_spec_files(dir: &Path, spec: &WorkloadSpec) -> Result<Vec<SpecFileMount>> {
    let planned = plan_spec_files(dir, spec)?;

    match tokio::fs::remove_dir_all(dir).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(
                anyhow!(e).context(format!("clearing spec-file staging dir {}", dir.display()))
            )
        }
    }
    if planned.is_empty() {
        return Ok(planned);
    }

    for (mount, file) in planned.iter().zip(&spec.files) {
        let host_path = Path::new(&mount.host_path);
        if let Some(parent) = host_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating {} for a staged spec file", parent.display()))?;
        }
        tokio::fs::write(host_path, &file.content)
            .await
            .with_context(|| format!("staging spec file {}", host_path.display()))?;
        #[cfg(unix)]
        if let Some(mode) = file.mode {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(host_path, std::fs::Permissions::from_mode(mode))
                .await
                .with_context(|| {
                    format!("chmod {mode:o} on staged spec file {}", host_path.display())
                })?;
        }
    }
    Ok(planned)
}

/// Remove a container generation's spec-file staging directory. Best-effort:
/// called from teardown, where a missing directory is the ordinary case (most
/// workloads declare no files) and a failure must not fail the teardown.
pub async fn discard_spec_files(container_id: &str) {
    let dir = spec_files_hostdir(container_id);
    let _ = tokio::fs::remove_dir_all(&dir).await;
    // The per-container parent is shared with the upgrade-sock dirs; it goes
    // only when it is empty, which `remove_dir` gives us for free.
    if let Some(parent) = dir.parent() {
        let _ = tokio::fs::remove_dir(parent).await;
    }
}

/// The literal env var naming passway's TLS listen address. kamaji binds this
/// address once (custodian) and hands the fd to passway; the string must
/// byte-match what passway configures pingora with, because pingora keys its
/// inherited-fd table on the exact listen-address string (`add_tls_with_settings`
/// → `Fds` key). See [`passway_listen_addr`].
pub const PASSWAY_LISTEN_ENV: &str = "PASSWAY_LISTEN";

/// passway's default listen address when `PASSWAY_LISTEN` is unset (matches
/// passway `main.rs`'s `env_or("PASSWAY_LISTEN", "0.0.0.0:443")`).
pub const DEFAULT_PASSWAY_LISTEN: &str = "0.0.0.0:443";

/// The listen address kamaji binds+holds as socket-custodian for a passway
/// workload — the `PASSWAY_LISTEN` literal from the spec, or
/// [`DEFAULT_PASSWAY_LISTEN`] when unset. This is the fd-handoff **key** that
/// must byte-match passway's pingora listener (R600-F9).
pub fn passway_listen_addr(spec: &WorkloadSpec) -> String {
    spec.env
        .iter()
        .find_map(|e| {
            if e.name != PASSWAY_LISTEN_ENV {
                return None;
            }
            match &e.value {
                workload_spec::EnvValue::Literal { value } => Some(value.clone()),
                _ => None,
            }
        })
        .unwrap_or_else(|| DEFAULT_PASSWAY_LISTEN.to_string())
}

// ── Resolver selection (R881-B7) ────────────────────────────────────────────
//
// Which host file a container's `/etc/resolv.conf` is bound from is not a
// constant, because `/etc/resolv.conf` on a systemd-resolved host — every
// fleet node — is the *stub* file: `nameserver 127.0.0.53`. Loopback is
// per-netns. Bound into a container that unshared its own network namespace,
// that hands the workload an address with nothing listening behind it, and
// glibc turns every lookup into a timeout rather than an error (measured on
// us-east-001 against `noisetable-account`, 2026-09-10: egress to
// 34.149.236.64:587 and to 1.1.1.1:53 both fine, every name EAI_AGAIN).
//
// systemd-resolved maintains a second file, `/run/systemd/resolve/resolv.conf`,
// carrying the REAL upstream servers rather than the stub — routable from
// anywhere the workload has egress. So the choice is a ranking over candidate
// host files, not a single path.
//
// No resolver is ever *synthesized* here. A container with no usable host
// source gets no mount at all, which is a refused connection on the first
// lookup instead of a five-second timeout on every one. Picking an address
// out of the air would be a second resolver policy beside the microVM path's
// (`GuestNetwork::dns`, default 1.1.1.1, kamaji/src/microvm.rs:553) — if a
// node ever needs one (air-gapped, split-horizon), the resolver belongs in
// the spec and both paths should read it from there.

/// The host's own resolver file. Correct for a host-networked workload by
/// construction: it shares the host's loopback, so a stub nameserver resolves.
pub const HOST_RESOLV_CONF: &str = "/etc/resolv.conf";

/// systemd-resolved's upstream-server file — the same data the stub at
/// [`HOST_RESOLV_CONF`] proxies, but as routable addresses.
pub const SYSTEMD_RESOLVED_UPSTREAM: &str = "/run/systemd/resolve/resolv.conf";

/// The candidate resolver files as read from the host, in preference order.
/// Split from [`resolver_mount_source`] so the choice itself is a pure
/// function and testable on a machine that is not a fleet node.
#[derive(Debug, Default, Clone)]
pub struct HostResolvers {
    /// Contents of `/etc/resolv.conf`, or `None` if it does not exist.
    pub etc: Option<String>,
    /// Contents of `/run/systemd/resolve/resolv.conf`, or `None`.
    pub systemd_upstream: Option<String>,
}

impl HostResolvers {
    /// Read both candidates from the host. Unreadable is the same answer as
    /// absent: runc refuses a mount with a missing source either way.
    pub fn read() -> Self {
        Self {
            etc: std::fs::read_to_string(HOST_RESOLV_CONF).ok(),
            systemd_upstream: std::fs::read_to_string(SYSTEMD_RESOLVED_UPSTREAM).ok(),
        }
    }
}

/// `(routable, total)` nameservers in a `resolv.conf`. A nameserver is
/// routable from another netns when it is neither loopback (127/8, `::1` —
/// the systemd-resolved stub's shape) nor unspecified.
fn nameserver_counts(contents: &str) -> (usize, usize) {
    let mut routable = 0;
    let mut total = 0;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let Some(addr) = rest.strip_prefix(char::is_whitespace) else {
            continue;
        };
        // Strip an IPv6 zone index (`fe80::1%eth0`) — it names a host
        // interface that does not exist in the container's namespace anyway.
        let addr = addr.trim().split('%').next().unwrap_or("").trim();
        total += 1;
        if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
            if !ip.is_loopback() && !ip.is_unspecified() {
                routable += 1;
            }
        }
    }
    (routable, total)
}

/// Which host file to bind at the container's `/etc/resolv.conf`, or `None`
/// for no mount at all.
///
/// Under host networking the host's own file is always right — the container
/// shares the host's loopback, so even a stub nameserver resolves. In an
/// isolated namespace a file is ranked by how many of its nameservers survive
/// the namespace boundary: all-routable beats partly-routable beats none, and
/// a file whose every nameserver is loopback is not a resolver at all from in
/// there. See the module note above this function for why nothing is
/// synthesized when no candidate is usable.
pub fn resolver_mount_source(host_networked: bool, hosts: &HostResolvers) -> Option<&'static str> {
    let candidates = [
        (HOST_RESOLV_CONF, hosts.etc.as_deref()),
        (SYSTEMD_RESOLVED_UPSTREAM, hosts.systemd_upstream.as_deref()),
    ];
    candidates
        .into_iter()
        .filter_map(|(path, contents)| {
            let contents = contents?;
            if host_networked {
                return Some((2, path));
            }
            let (routable, total) = nameserver_counts(contents);
            match routable {
                0 => None,
                n if n == total => Some((2u8, path)),
                _ => Some((1u8, path)),
            }
        })
        // `min_by_key` keeps the FIRST of equally-ranked candidates, so the
        // array's preference order breaks ties.
        .min_by_key(|(rank, _)| std::cmp::Reverse(*rank))
        .map(|(_, path)| path)
}

/// Standalone-workload OCI spec — the common case (no pod placement). Thin
/// wrapper over [`build_oci_spec_with`] with [`PodOptions::default()`].
pub fn build_oci_spec(
    spec: &WorkloadSpec,
    extra_env: &[String],
    image_config: Option<&ImageOciConfig>,
) -> serde_json::Value {
    build_oci_spec_with(spec, extra_env, image_config, &PodOptions::default())
}

/// Build the OCI `config.json` for a workload spec, with optional pod
/// placement ([`PodOptions`]) for the passway graceful-upgrade path.
pub fn build_oci_spec_with(
    spec: &WorkloadSpec,
    extra_env: &[String],
    image_config: Option<&ImageOciConfig>,
    pod: &PodOptions,
) -> serde_json::Value {
    let img_entrypoint = image_config.map(|c| c.entrypoint.as_slice()).unwrap_or(&[]);
    let img_cmd = image_config.map(|c| c.cmd.as_slice()).unwrap_or(&[]);
    let img_env = image_config.map(|c| c.env.as_slice()).unwrap_or(&[]);
    let img_workdir = image_config.and_then(|c| c.working_dir.as_deref());
    let img_user = image_config.and_then(|c| c.user.as_deref());

    // Docker/OCI argv convention (R590-B8): the container argv is
    // (workload.entrypoint OR image.Entrypoint) ++ (workload.command OR
    // image.Cmd). A workload that overrides neither runs the image's baked
    // ENTRYPOINT+CMD — the rusty-v8 builder relies on `ENTRYPOINT ["bash","-c"]`
    // plus a single-string command from the recipe. Previously spec.entrypoint
    // was ignored and the image's config dropped entirely.
    let mut args: Vec<String> = spec
        .entrypoint
        .clone()
        .unwrap_or_else(|| img_entrypoint.to_vec());
    args.extend(spec.command.clone().unwrap_or_else(|| img_cmd.to_vec()));

    // Env: image `Env` first, overlaid by the workload's literal env, then any
    // deployment `extra_env` (e.g. `YAH_MESH_IP`). Non-literal (FromSecret /
    // FromMesh) values are dropped here — yubaba admission resolves them to
    // literals before deploy; if one survives it's a bug caught upstream.
    let spec_env: Vec<String> = spec
        .env
        .iter()
        .filter_map(|e| {
            if let workload_spec::EnvValue::Literal { value } = &e.value {
                Some(format!("{}={}", e.name, value))
            } else {
                None
            }
        })
        .collect();
    let env = merge_env(&[img_env, &spec_env, extra_env]);

    // Honor `WorkloadSpec.user` (numeric `"uid"` or `"uid:gid"`), falling back
    // to the image's baked `User`, then root. Previously hardcoded to 0:0 with
    // the spec field silently ignored — found live on us-east-001 when
    // nginx-unprivileged needed to start as uid 101 (run as root it chowns its
    // temp dirs, which a CAP_NET_BIND_SERVICE-only container cannot). Named
    // users are not resolvable without reading the image's /etc/passwd, which
    // this builder never mounts — non-numeric values fall back to root.
    let (uid, gid) = spec
        .user
        .as_deref()
        .or(img_user)
        .map(parse_numeric_user)
        .unwrap_or((0, 0));

    // Working dir: workload override, else image `WorkingDir`, else `/`.
    let cwd = spec
        .workdir
        .as_ref()
        .and_then(|p| p.to_str())
        .or(img_workdir)
        .unwrap_or("/")
        .to_string();

    // Capabilities / `no_new_privs` / fd budget: the baseline is
    // [`GRANTED_CAPABILITY`] alone with `no_new_privs` on. A workload that
    // stands up its own unprivileged container sandbox (rootless BuildKit —
    // `yah.sandbox=nested`, guarded to tier=infra by each caller before this
    // function runs) gets exactly the three relaxations `rootlesskit` needs to
    // exec the setuid-root `newuidmap`/`newgidmap` helpers.
    // See `WorkloadSpec::wants_nested_sandbox` for the measured evidence that
    // each of the three is individually load-bearing.
    //
    // The fd budget goes up with it. That part is *headroom, not a measured
    // requirement*: a small build completes fine at the 1024 baseline, but the
    // workload is running a whole container runtime (content store, snapshots,
    // one exec per concurrent RUN) rather than a single service, and the real
    // rusty-v8 build it exists for is orders of magnitude larger than anything
    // that has been run against the 1024 limit.
    let nested_sandbox = spec.wants_nested_sandbox();
    let caps: serde_json::Value = if nested_sandbox {
        serde_json::json!([GRANTED_CAPABILITY, NESTED_SANDBOX_CAPABILITIES[0], NESTED_SANDBOX_CAPABILITIES[1]])
    } else {
        serde_json::json!([GRANTED_CAPABILITY])
    };
    let nofile: u32 = if nested_sandbox { 65_536 } else { 1024 };

    let process = serde_json::json!({
        "terminal": false,
        "user": { "uid": uid, "gid": gid },
        "args": args,
        "env": env,
        "cwd": cwd,
        "capabilities": {
            "bounding":  caps.clone(),
            "effective": caps.clone(),
            "permitted": caps,
            "ambient":   [],
        },
        "rlimits": [{
            "type": "RLIMIT_NOFILE",
            "hard": nofile,
            "soft": nofile,
        }],
        "noNewPrivileges": !nested_sandbox,
    });

    // Namespaces: isolated by default. Host networking is a guarded opt-in
    // (yah.network=host on tier=infra, enforced by each caller before this
    // function runs): OMIT the network namespace so runc leaves the
    // container in the host netns, letting it bind host ports directly.
    // pid/ipc/uts/mount stay isolated regardless.
    let mut namespaces = vec![serde_json::json!({ "type": "pid" })];
    if !spec.wants_host_network() {
        // A fresh isolated netns by default; if the caller supplies an existing
        // netns path (the "sandbox-held netns" custodian, R600-F7 option B),
        // set `path` so runc `setns`es into it instead of unsharing a new one.
        // That keeps the listening socket's namespace alive across a passway
        // process swap. Host-networked workloads skip the entry entirely (the
        // host netns is already the eternal custodian).
        match &pod.join_netns {
            Some(path) => {
                namespaces.push(serde_json::json!({ "type": "network", "path": path }))
            }
            None => namespaces.push(serde_json::json!({ "type": "network" })),
        }
    }
    namespaces.push(serde_json::json!({ "type": "ipc" }));
    namespaces.push(serde_json::json!({ "type": "uts" }));
    namespaces.push(serde_json::json!({ "type": "mount" }));

    // /sys: a fresh `sysfs` mount requires owning the network namespace,
    // which fails when the container shares the host netns (host
    // networking). Bind-mount the host /sys read-only instead in that case.
    let sys_mount = if spec.wants_host_network() {
        serde_json::json!({
            "destination": "/sys", "type": "bind", "source": "/sys",
            "options": ["rbind","nosuid","noexec","nodev","ro"]
        })
    } else {
        serde_json::json!({
            "destination": "/sys", "type": "sysfs", "source": "sysfs",
            "options": ["nosuid","noexec","nodev","ro"]
        })
    };

    // Base pseudo-filesystems, then the spec's volume mounts. `spec.volumes`
    // was previously ignored outright (same silent-drop as `spec.user`,
    // found in the same us-east-001 live deploy — the bind-mounted site dir
    // never appeared in the container and nginx served its default page).
    // Bind mounts are already gated to tier="infra" by
    // `workload_spec::validate::shape`; named volumes resolve to a
    // kamaji-managed directory (created by runc's mount only if it already
    // exists — creation-on-first-use lands with a real consumer).
    let mut mounts = vec![
        serde_json::json!({ "destination": "/proc",  "type": "proc",   "source": "proc",   "options": [] }),
        serde_json::json!({ "destination": "/dev",   "type": "tmpfs",  "source": "tmpfs",  "options": ["nosuid","strictatime","mode=755","size=65536k"] }),
        sys_mount,
        serde_json::json!({ "destination": "/tmp",   "type": "tmpfs",  "source": "tmpfs",  "options": ["nosuid","nodev","mode=1777"] }),
    ];

    // R590-B7: DNS for a workload that has IP egress. Raw runc (unlike
    // docker/containerd-CRI) does not synthesize /etc/resolv.conf, and workload
    // images typically ship none — so name resolution fails (a build's `git
    // clone github.com` dies before the first packet). Bind-mount the host
    // resolver read-only. Skipped when the host has no /etc/resolv.conf, since
    // runc refuses a mount with a missing source.
    //
    // R881-T3 widened the condition from `wants_host_network()` alone. The old
    // comment said an isolated netns "has no upstream resolver to inherit",
    // which was true only because an isolated netns had no route at all: a
    // workload joining a namespace kamaji wired (`join_netns`) has a default
    // route and egress NAT, so the host's resolver is exactly as reachable from
    // inside it as from the host. Without this, such a workload gets an address
    // and IP egress and still cannot resolve a name — which reads as a
    // networking bug and is a missing file.
    //
    // R881-B7: *which* host file, though, depends on the namespace. The host's
    // `/etc/resolv.conf` is the systemd-resolved stub (`nameserver 127.0.0.53`)
    // on every fleet node, and loopback does not survive the netns boundary —
    // binding it into an isolated namespace is what turned every lookup into a
    // timeout. [`resolver_mount_source`] ranks the candidates instead.
    let has_ip_egress = spec.wants_host_network() || pod.join_netns.is_some();
    if has_ip_egress {
        if let Some(source) =
            resolver_mount_source(spec.wants_host_network(), &HostResolvers::read())
        {
            mounts.push(serde_json::json!({
                "destination": "/etc/resolv.conf", "type": "bind", "source": source,
                "options": ["rbind","ro","nosuid","nodev"]
            }));
        }
    }
    for volume in &spec.volumes {
        let rw_opt = if volume.read_only { "ro" } else { "rw" };
        match &volume.source {
            workload_spec::VolumeSource::Bind { host_path } => {
                mounts.push(serde_json::json!({
                    "destination": volume.target,
                    "type": "bind",
                    "source": host_path,
                    "options": ["rbind", rw_opt, "nosuid", "nodev"],
                }));
            }
            workload_spec::VolumeSource::Named { name } => {
                mounts.push(serde_json::json!({
                    "destination": volume.target,
                    "type": "bind",
                    "source": format!("/var/lib/yah/kamaji/volumes/{name}"),
                    "options": ["rbind", rw_opt, "nosuid", "nodev"],
                }));
            }
            workload_spec::VolumeSource::Tmpfs { size_mb } => {
                mounts.push(serde_json::json!({
                    "destination": volume.target,
                    "type": "tmpfs",
                    "source": "tmpfs",
                    "options": ["nosuid", "nodev", format!("size={}m", size_mb)],
                }));
            }
        }
    }

    // Shared upgrade-sock bind mount (R600-F7): a host directory bind-mounted
    // into the passway container so the outgoing + incoming passway processes
    // (each in its own mount namespace) see the *same* `PASSWAY_UPGRADE_SOCK`
    // inode. Without this the `SIGQUIT`ed old process cannot reach the new one
    // and pingora's fd-handoff silently degrades to a fresh bind (dropping
    // connections). Read-write: pingora unlinks+rebinds the sock on each
    // generation.
    if let Some((host_dir, container_dir)) = &pod.shared_dir {
        mounts.push(serde_json::json!({
            "destination": container_dir,
            "type": "bind",
            "source": host_dir,
            "options": ["rbind", "rw", "nosuid", "nodev"],
        }));
    }

    // The node's scryer ingestion socket (R893-B17), so a containerized
    // workload's `YAH_SCRYER_SOCKET` names a path that exists inside its own
    // mount namespace. See `PodOptions::collector_socket` for why this is a
    // file bind rather than a directory one, and why it is read-write.
    if let Some((host_socket, container_socket)) = &pod.collector_socket {
        mounts.push(serde_json::json!({
            "destination": container_socket,
            "type": "bind",
            "source": host_socket,
            "options": ["rbind", "rw", "nosuid", "nodev"],
        }));
    }

    // Spec-carried config files (R870-F27), staged on the host by
    // [`stage_spec_files`]. LAST in the list on purpose: runc mounts in
    // order, so a file declared *inside* a directory this workload also
    // mounts (a volume at `/etc/passway`, the shared upgrade-sock dir) has to
    // land after its parent or the parent mount buries it.
    //
    // Read-only. These are the deployed spec's bytes; the node rewrites them
    // on every deploy and every respawn, so a workload that edited one would
    // have its edit reverted underneath it at an unpredictable moment. `ro`
    // turns that silent surprise into an `EROFS` at the write.
    for file in &pod.spec_files {
        mounts.push(serde_json::json!({
            "destination": file.container_path,
            "type": "bind",
            "source": file.host_path,
            "options": ["rbind", "ro", "nosuid", "nodev"],
        }));
    }

    serde_json::json!({
        "ociVersion": "1.0.2",
        "process": process,
        "root": { "path": "rootfs", "readonly": false },
        "hostname": &spec.name,
        "mounts": mounts,
        "linux": {
            "namespaces": namespaces,
            "resources": {
                "memory": { "limit": (spec.resources.memory_mb as i64) * 1024 * 1024 },
                "cpu": { "shares": spec.resources.cpu_shares() },
            },
            "cgroupsPath": format!("/yah/{}", spec.name),
        },
    })
}

/// Every `(destination, source)` pair an OCI spec's **bind** mounts name.
///
/// Read off the built spec rather than re-derived from the `WorkloadSpec`, so
/// it cannot drift from [`build_oci_spec_with`]: a mount added there is
/// enumerated here the same day. `tmpfs`/`proc`/`sysfs` mounts have no host
/// source and are skipped.
pub fn bind_mount_sources(oci_spec: &serde_json::Value) -> Vec<(String, String)> {
    oci_spec["mounts"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|m| m["type"] == "bind")
        .filter_map(|m| {
            Some((
                m["destination"].as_str()?.to_string(),
                m["source"].as_str()?.to_string(),
            ))
        })
        .collect()
}

/// The bind sources in `oci_spec` that do not exist on this host.
///
/// `Path::exists` follows symlinks, which is what `runc` does too — it
/// `stat(2)`s the source, so a dangling symlink is as fatal as an absent file.
pub fn missing_bind_sources(oci_spec: &serde_json::Value) -> Vec<(String, String)> {
    bind_mount_sources(oci_spec)
        .into_iter()
        .filter(|(_, source)| !std::path::Path::new(source).exists())
        .collect()
}

/// Refuse a deploy whose OCI spec names a bind source this host does not have.
///
/// **Call this before tearing the incumbent down.** `runc` checks the same
/// thing at container-create time and fails with `bind mount source stat: no
/// such file or directory` — by which point a destroy-then-create deploy has
/// already destroyed. That is R932-B1: on 2026-09-22 the node's `yah-scryer`
/// ingestion socket was missing (a systemd drop-in had dropped the
/// `--ingest-socket` flag eleven days earlier), the collector bind kamaji
/// injects into *every* container named it, and `noisetable-account` was torn
/// down and could not be recreated. The mount was not in the workload's spec,
/// so no amount of spec validation would have caught it; the host is the only
/// place the answer lives.
///
/// The error names every missing source and the destination it was for, so an
/// operator reads which mount to go fix rather than which container failed.
pub fn check_bind_sources(oci_spec: &serde_json::Value) -> Result<(), String> {
    let missing = missing_bind_sources(oci_spec);
    if missing.is_empty() {
        return Ok(());
    }
    let detail = missing
        .iter()
        .map(|(dest, source)| format!("{source} (for {dest})"))
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "bind mount source missing on this host: {detail}. runc would refuse to create the \
         container; nothing was torn down"
    ))
}

#[cfg(test)]
mod reap_tests {
    //! R854 — the reap loop's contract, exercised through [`TaskOps`] so it
    //! runs on a machine with no containerd. The live bug these pin down: the
    //! old code killed the task, waited a fixed 500 ms (or not at all), fired
    //! one delete, discarded its result, and reported success — so a task
    //! slower than that survived, and the next deploy's `CreateTask` collided
    //! with it.

    use super::*;

    /// A task that reports RUNNING and refuses deletion for its first
    /// `refusals` delete attempts, then stops and lets itself be reaped.
    struct SlowExit {
        refusals: usize,
        kills: usize,
        deletes: usize,
        gone: bool,
    }

    impl SlowExit {
        fn new(refusals: usize) -> Self {
            Self {
                refusals,
                kills: 0,
                deletes: 0,
                gone: false,
            }
        }
    }

    impl TaskOps for SlowExit {
        async fn probe(&mut self, _: &str) -> Result<TaskProbe> {
            Ok(if self.gone {
                TaskProbe::NoTask
            } else {
                // 2 == RUNNING.
                TaskProbe::Status {
                    code: 2,
                    pid: 4242,
                    exit_status: 0,
                }
            })
        }

        async fn signal_kill(&mut self, _: &str) {
            self.kills += 1;
        }

        async fn await_exit(&mut self, _: &str, _: Duration) {}

        async fn delete(&mut self, _: &str) -> DeleteOutcome {
            self.deletes += 1;
            if self.deletes > self.refusals {
                self.gone = true;
                DeleteOutcome::Reaped
            } else {
                DeleteOutcome::Refused
            }
        }
    }

    /// A task that never dies — nothing kills it, nothing deletes it.
    struct Immortal {
        status: i32,
        kills: usize,
    }

    impl TaskOps for Immortal {
        async fn probe(&mut self, _: &str) -> Result<TaskProbe> {
            Ok(TaskProbe::Status {
                code: self.status,
                pid: 7,
                exit_status: 0,
            })
        }

        async fn signal_kill(&mut self, _: &str) {
            self.kills += 1;
        }

        async fn await_exit(&mut self, _: &str, _: Duration) {}

        async fn delete(&mut self, _: &str) -> DeleteOutcome {
            DeleteOutcome::Refused
        }
    }

    /// No task at all — the first-deploy case.
    struct NoTask {
        kills: usize,
    }

    impl TaskOps for NoTask {
        async fn probe(&mut self, _: &str) -> Result<TaskProbe> {
            Ok(TaskProbe::NoTask)
        }

        async fn signal_kill(&mut self, _: &str) {
            self.kills += 1;
        }

        async fn await_exit(&mut self, _: &str, _: Duration) {}

        async fn delete(&mut self, _: &str) -> DeleteOutcome {
            unreachable!("must not delete a task that was never there");
        }
    }

    #[tokio::test]
    async fn retries_until_the_task_is_actually_gone() {
        // Three refused deletes is what the old fixed-sleep shape reported as
        // a successful teardown; the loop has to keep going instead.
        let mut ops = SlowExit::new(3);
        reap_task_with(&mut ops, "yah-cloud-admin", Duration::from_secs(5))
            .await
            .expect("task eventually reaped");
        assert_eq!(ops.deletes, 4, "kept retrying the delete until it took");
        assert!(ops.kills >= 4, "re-signalled on every pass");
        assert!(ops.gone);
    }

    #[tokio::test]
    async fn reports_the_survivor_instead_of_a_phantom_success() {
        let mut ops = Immortal { status: 2, kills: 0 };
        let err = reap_task_with(&mut ops, "yah-cloud-admin", Duration::from_millis(150))
            .await
            .expect_err("a task that never dies must not report a reap");
        let msg = format!("{err:#}");
        assert!(msg.contains("yah-cloud-admin"), "names the container: {msg}");
        assert!(msg.contains("status code 2"), "names the status: {msg}");
        assert!(ops.kills >= 1);
    }

    #[tokio::test]
    async fn a_stopped_but_undeletable_task_says_so() {
        let mut ops = Immortal {
            status: TASK_STATUS_STOPPED,
            kills: 0,
        };
        let err = reap_task_with(&mut ops, "stuck", Duration::from_millis(150))
            .await
            .expect_err("undeletable record is a failure");
        assert!(
            format!("{err:#}").contains("STOPPED but its record could not be deleted"),
            "distinguishes a stuck record from a live process: {err:#}"
        );
    }

    #[tokio::test]
    async fn no_task_is_a_silent_no_op() {
        let mut ops = NoTask { kills: 0 };
        reap_task_with(&mut ops, "fresh", Duration::from_secs(5))
            .await
            .expect("nothing to reap");
        assert_eq!(ops.kills, 0, "must not SIGKILL on a first deploy");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, NamespaceId, ResourceLimits,
        RestartPolicy, StopPolicy, TenantId, TierTag, WorkloadSpec,
    };

    fn test_spec(name: &str) -> WorkloadSpec {
        WorkloadSpec {
            name: name.to_string(),
            image: ImageRef {
                registry: "docker.io".to_string(),
                repository: "library/alpine".to_string(),
                tag: "latest".to_string(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".to_string()),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            replicas: 1,
            command: Some(vec!["sleep".to_string(), "30".to_string()]),
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
                    identity: MeshIdent(name.to_string()),
                    ports: MeshExpose::anonymous_ports([]),
                    allow_from: vec![],
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

    fn with_host_network(mut spec: WorkloadSpec) -> WorkloadSpec {
        spec.annotations.insert(
            workload_spec::HOST_NETWORK_ANNOTATION.into(),
            workload_spec::HOST_NETWORK_VALUE.into(),
        );
        spec
    }

    fn with_nested_sandbox(mut spec: WorkloadSpec) -> WorkloadSpec {
        spec.annotations.insert(
            workload_spec::NESTED_SANDBOX_ANNOTATION.into(),
            workload_spec::NESTED_SANDBOX_VALUE.into(),
        );
        spec
    }

    fn caps(oci: &serde_json::Value) -> Vec<String> {
        oci["process"]["capabilities"]["bounding"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_string())
            .collect()
    }

    fn netns_present(oci: &serde_json::Value) -> bool {
        oci["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["type"] == "network")
    }

    fn args_of(oci: &serde_json::Value) -> Vec<String> {
        oci["process"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    fn env_of(oci: &serde_json::Value) -> Vec<String> {
        oci["process"]["env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    // ── R590-B8: image OCI config merge ──────────────────────────────────────

    #[test]
    fn from_config_doc_extracts_process_fields() {
        let doc = serde_json::json!({
            "config": {
                "Entrypoint": ["bash", "-c"],
                "Cmd": ["default-arg"],
                "Env": ["PATH=/usr/bin", "V8_FROM_SOURCE=1"],
                "WorkingDir": "/build",
                "User": "1000:1000",
            },
            "rootfs": { "diff_ids": ["sha256:abc"] },
        });
        let cfg = ImageOciConfig::from_config_doc(&doc);
        assert_eq!(cfg.entrypoint, vec!["bash", "-c"]);
        assert_eq!(cfg.cmd, vec!["default-arg"]);
        assert_eq!(cfg.env, vec!["PATH=/usr/bin", "V8_FROM_SOURCE=1"]);
        assert_eq!(cfg.working_dir.as_deref(), Some("/build"));
        assert_eq!(cfg.user.as_deref(), Some("1000:1000"));
    }

    #[test]
    fn from_config_doc_missing_fields_degrade_to_empty() {
        let cfg = ImageOciConfig::from_config_doc(&serde_json::json!({ "config": {} }));
        assert!(cfg.entrypoint.is_empty());
        assert!(cfg.env.is_empty());
        assert_eq!(cfg.working_dir, None);
        // Empty-string WorkingDir/User are treated as unset (opt_str filter).
        let cfg = ImageOciConfig::from_config_doc(
            &serde_json::json!({ "config": { "WorkingDir": "", "User": "" } }),
        );
        assert_eq!(cfg.working_dir, None);
        assert_eq!(cfg.user, None);
    }

    /// The rusty-v8-musl rusty-v8 shape: image supplies `ENTRYPOINT ["bash","-c"]` + baked
    /// build ENV, the workload supplies only a single-string command. The merged
    /// argv must be `bash -c <command>` and the baked env must survive.
    #[test]
    fn image_entrypoint_and_env_merge_with_workload_command() {
        let img = ImageOciConfig {
            entrypoint: vec!["bash".into(), "-c".into()],
            cmd: vec!["ignored-default".into()],
            env: vec!["PATH=/usr/bin".into(), "V8_FROM_SOURCE=1".into()],
            working_dir: Some("/build".into()),
            user: None,
        };
        let mut spec = test_spec("svc");
        spec.command = Some(vec!["build-v8.sh x86_64-unknown-linux-musl /out.tgz".into()]);
        spec.entrypoint = None;
        spec.workdir = None;
        spec.env = vec![workload_spec::EnvVar {
            name: "EXTRA".into(),
            value: workload_spec::EnvValue::Literal { value: "1".into() },
        }];

        let oci = build_oci_spec(&spec, &[], Some(&img));
        // entrypoint (image) ++ command (workload); image Cmd is NOT appended
        // because the workload overrode the argv tail.
        assert_eq!(
            args_of(&oci),
            vec![
                "bash",
                "-c",
                "build-v8.sh x86_64-unknown-linux-musl /out.tgz"
            ]
        );
        let env = env_of(&oci);
        assert!(env.contains(&"PATH=/usr/bin".to_string()), "env: {env:?}");
        assert!(
            env.contains(&"V8_FROM_SOURCE=1".to_string()),
            "env: {env:?}"
        );
        assert!(env.contains(&"EXTRA=1".to_string()), "env: {env:?}");
        assert_eq!(oci["process"]["cwd"], "/build");
    }

    #[test]
    fn workload_overrides_win_over_image_config() {
        let img = ImageOciConfig {
            entrypoint: vec!["bash".into(), "-c".into()],
            cmd: vec!["img-cmd".into()],
            env: vec!["PATH=/image/bin".into(), "KEEP=1".into()],
            working_dir: Some("/image-wd".into()),
            user: Some("0".into()),
        };
        let mut spec = test_spec("svc");
        spec.entrypoint = Some(vec!["/sbin/init".into()]);
        spec.command = Some(vec!["--flag".into()]);
        spec.workdir = Some("/wd".into());
        spec.env = vec![workload_spec::EnvVar {
            name: "PATH".into(),
            value: workload_spec::EnvValue::Literal {
                value: "/wl/bin".into(),
            },
        }];

        let oci = build_oci_spec(&spec, &[], Some(&img));
        assert_eq!(args_of(&oci), vec!["/sbin/init", "--flag"]);
        assert_eq!(oci["process"]["cwd"], "/wd");
        let env = env_of(&oci);
        // PATH overridden (last-wins), appears exactly once; KEEP survives.
        assert_eq!(
            env.iter().filter(|e| e.starts_with("PATH=")).count(),
            1,
            "env: {env:?}"
        );
        assert!(env.contains(&"PATH=/wl/bin".to_string()), "env: {env:?}");
        assert!(env.contains(&"KEEP=1".to_string()), "env: {env:?}");
    }

    #[test]
    fn no_image_config_preserves_spec_only_behavior() {
        // The pre-B8 behavior: args = spec.command, env = spec literals, cwd "/".
        let mut spec = test_spec("svc");
        spec.command = Some(vec!["sleep".into(), "30".into()]);
        let oci = build_oci_spec(&spec, &[], None);
        assert_eq!(args_of(&oci), vec!["sleep", "30"]);
        assert_eq!(oci["process"]["cwd"], "/");
    }

    fn sys_mount(oci: &serde_json::Value) -> serde_json::Value {
        oci["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["destination"] == "/sys")
            .expect("/sys mount must be present")
            .clone()
    }

    #[test]
    fn image_ref_emits_tag_and_digest() {
        let mut spec = test_spec("svc");
        spec.image.digest = "sha256:deadbeef".into();
        assert_eq!(
            image_ref(&spec),
            "docker.io/library/alpine:latest@sha256:deadbeef"
        );
    }

    #[test]
    fn image_ref_unpinned_falls_back_to_tag_only() {
        // An unpinned image (all-zeros sentinel — a not-yet-published builder
        // image) must resolve by tag: containerd holds a tag-pulled image
        // under `registry/repo:tag`, and `…@sha256:0000…` never matches
        // (R590-B5). `test_spec` already seeds the sentinel digest.
        let spec = test_spec("svc");
        assert_eq!(image_ref(&spec), "docker.io/library/alpine:latest");
    }

    #[test]
    fn chain_id_single_layer_is_identity() {
        let d = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(chain_id(&[d.to_string()]), d);
    }

    #[test]
    fn chain_id_folds_multiple_layers() {
        let a = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let b = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let chain = chain_id(&[a.to_string(), b.to_string()]);
        assert!(chain.starts_with("sha256:"));
        assert_eq!(chain.len(), "sha256:".len() + 64);
        assert_ne!(chain, a);
        assert_ne!(chain, b);
        assert_eq!(chain, chain_id(&[a.to_string(), b.to_string()]));
    }

    #[test]
    fn chain_id_empty_is_empty() {
        assert_eq!(chain_id(&[]), "");
    }

    /// R636-B2 baseline half: an ordinary workload keeps the tight sandbox.
    /// This is the assertion the ticket's second `@yah:verify` asks for — the
    /// widening must be provably opt-in, not provable "by inspection".
    #[test]
    fn oci_spec_baseline_sandbox_is_unchanged_without_the_annotation() {
        let oci = build_oci_spec(&test_spec("svc"), &[], None);
        assert_eq!(
            caps(&oci),
            vec![GRANTED_CAPABILITY.to_string()],
            "a workload without yah.sandbox=nested must keep the CAP_NET_BIND_SERVICE-only set"
        );
        assert_eq!(
            oci["process"]["noNewPrivileges"], true,
            "no_new_privs must stay on for every workload that did not ask for the grant"
        );
        assert_eq!(oci["process"]["rlimits"][0]["hard"], 1024);
        // Host networking is a *different* escape hatch and must not drag the
        // capability grant along with it.
        let host_net = build_oci_spec(&with_host_network(test_spec("svc")), &[], None);
        assert_eq!(caps(&host_net), vec![GRANTED_CAPABILITY.to_string()]);
        assert_eq!(host_net["process"]["noNewPrivileges"], true);
    }

    /// R636-B2 grant half: `yah.sandbox=nested` adds exactly CAP_SETUID +
    /// CAP_SETGID and turns `no_new_privs` off — the measured-minimal set
    /// rootless BuildKit's `rootlesskit` needs to exec `newuidmap`/`newgidmap`.
    /// Notably *not* CAP_SYS_ADMIN, and the ambient set stays empty.
    #[test]
    fn oci_spec_nested_sandbox_grants_setuid_setgid_and_drops_no_new_privs() {
        let oci = build_oci_spec(&with_nested_sandbox(test_spec("forge-build")), &[], None);
        assert_eq!(
            caps(&oci),
            vec![
                GRANTED_CAPABILITY.to_string(),
                "CAP_SETUID".to_string(),
                "CAP_SETGID".to_string(),
            ],
        );
        assert_eq!(
            oci["process"]["capabilities"]["effective"],
            oci["process"]["capabilities"]["bounding"],
        );
        assert_eq!(
            oci["process"]["capabilities"]["permitted"],
            oci["process"]["capabilities"]["bounding"],
        );
        assert_eq!(
            oci["process"]["capabilities"]["ambient"],
            serde_json::json!([]),
            "ambient must stay empty — the helpers are setuid binaries, not ambient-cap consumers"
        );
        assert!(
            !caps(&oci).iter().any(|c| c == "CAP_SYS_ADMIN"),
            "the grant must never widen to CAP_SYS_ADMIN"
        );
        assert_eq!(
            oci["process"]["noNewPrivileges"], false,
            "with no_new_privs on, the kernel strips newuidmap's setuid bit \
             and rootlesskit fails with 'Could not set caps'"
        );
        assert_eq!(
            oci["process"]["rlimits"][0]["hard"], 65_536,
            "headroom for a workload running its own container runtime — not a \
             measured requirement (a small build passes at the 1024 baseline)"
        );
    }

    /// The grant must not change anything else about the sandbox — same
    /// namespaces, same mounts. Only the three process-level knobs move.
    #[test]
    fn oci_spec_nested_sandbox_leaves_namespaces_and_mounts_alone() {
        let plain = build_oci_spec(&test_spec("svc"), &[], None);
        let nested = build_oci_spec(&with_nested_sandbox(test_spec("svc")), &[], None);
        assert_eq!(plain["linux"]["namespaces"], nested["linux"]["namespaces"]);
        assert_eq!(plain["mounts"], nested["mounts"]);
        assert!(
            netns_present(&nested),
            "the grant is orthogonal to networking — it must not leak the netns"
        );
    }

    #[test]
    fn oci_spec_isolates_network_by_default() {
        let oci = build_oci_spec(&test_spec("svc"), &[], None);
        assert!(
            netns_present(&oci),
            "default workload must get an isolated netns"
        );
    }

    #[test]
    fn oci_spec_host_network_omits_netns() {
        let oci = build_oci_spec(&with_host_network(test_spec("svc")), &[], None);
        assert!(
            !netns_present(&oci),
            "yah.network=host must share the host netns"
        );
        let types: Vec<&str> = oci["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["type"].as_str().unwrap())
            .collect();
        for ns in ["pid", "ipc", "uts", "mount"] {
            assert!(types.contains(&ns), "namespace {ns} must remain isolated");
        }
    }

    fn network_ns(oci: &serde_json::Value) -> Option<&serde_json::Value> {
        oci["linux"]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["type"] == "network")
    }

    // ── R600-F7: pod placement (shared upgrade sock + sandbox-held netns) ─────

    #[test]
    fn pod_join_netns_sets_path_on_the_network_namespace() {
        let pod = PodOptions {
            join_netns: Some("/proc/4242/ns/net".into()),
            ..Default::default()
        };
        let oci = build_oci_spec_with(&test_spec("passway-ingress"), &[], None, &pod);
        let net = network_ns(&oci).expect("isolated workload keeps a network namespace");
        assert_eq!(
            net["path"], "/proc/4242/ns/net",
            "the replacement container must join the custodian's netns, not unshare a fresh one"
        );
    }

    #[test]
    fn pod_join_netns_is_ignored_under_host_networking() {
        // A host-networked workload (the F5 passway ingress) has no network
        // namespace entry to carry a path — the host netns is already the
        // eternal custodian, so the join is a no-op rather than an error.
        let pod = PodOptions {
            join_netns: Some("/proc/4242/ns/net".into()),
            ..Default::default()
        };
        let oci = build_oci_spec_with(&with_host_network(test_spec("svc")), &[], None, &pod);
        assert!(
            network_ns(&oci).is_none(),
            "host networking must not gain a network namespace from join_netns"
        );
    }

    /// R881-T3: a workload joining a namespace kamaji wired has a default route
    /// and egress NAT, so the host resolver is as reachable from inside it as
    /// from the host — and without this bind it gets an address, gets IP egress,
    /// and still cannot resolve a name. A workload that unshares an *empty*
    /// namespace must still not get the file: there is no route to the resolver
    /// there, and a resolv.conf pointing at an unreachable nameserver turns an
    /// instant failure into a DNS timeout on every lookup.
    ///
    /// R881-B7 adds the axis the OCI spec alone cannot reach: *which* file. The
    /// premise above holds only for a routable nameserver, and every fleet node
    /// runs systemd-resolved, whose `/etc/resolv.conf` is the loopback stub —
    /// so the bind this test was written to demand shipped the very timeout its
    /// last sentence warns about. The choice is a pure function so the loopback
    /// case is assertable without a node.
    #[test]
    fn a_joined_netns_gets_the_host_resolver_and_a_bare_one_does_not() {
        fn binds_resolver(oci: &serde_json::Value) -> Option<String> {
            oci["mounts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["destination"] == "/etc/resolv.conf")
                .map(|m| m["source"].as_str().unwrap().to_string())
        }
        let spec = test_spec("acct");
        assert!(
            binds_resolver(&build_oci_spec_with(&spec, &[], None, &PodOptions::default())).is_none(),
            "an empty namespace has no route to a resolver"
        );

        // ── which file, given what the host has ──────────────────────────────
        let stub = HostResolvers {
            etc: Some("nameserver 127.0.0.53\nsearch .\n".into()),
            systemd_upstream: Some("nameserver 213.186.33.99\nnameserver 1.1.1.1\n".into()),
        };
        assert_eq!(
            resolver_mount_source(false, &stub),
            Some(SYSTEMD_RESOLVED_UPSTREAM),
            "a 127/8 stub is not a resolver from inside an isolated netns — \
             systemd-resolved's upstream file is"
        );
        assert_eq!(
            resolver_mount_source(true, &stub),
            Some(HOST_RESOLV_CONF),
            "host networking shares the host's loopback, so the stub resolves there"
        );
        let routable = HostResolvers {
            etc: Some("# generated\nnameserver 213.186.33.99\n".into()),
            systemd_upstream: None,
        };
        assert_eq!(
            resolver_mount_source(false, &routable),
            Some(HOST_RESOLV_CONF),
            "a host file that is already routable is bound unchanged"
        );
        assert_eq!(
            resolver_mount_source(
                false,
                &HostResolvers {
                    etc: Some("nameserver ::1\n".into()),
                    systemd_upstream: Some("nameserver 127.0.0.1\n".into()),
                }
            ),
            None,
            "no usable source means no mount — runc refuses a missing source, and \
             an absent resolv.conf fails instantly where an unreachable one hangs"
        );
        // A file listing both survives the boundary, but every loopback entry in
        // it costs a per-lookup timeout — so an all-routable candidate wins.
        let mixed = HostResolvers {
            etc: Some("nameserver 127.0.0.53\nnameserver 9.9.9.9\n".into()),
            systemd_upstream: Some("nameserver 9.9.9.9\n".into()),
        };
        assert_eq!(
            resolver_mount_source(false, &mixed),
            Some(SYSTEMD_RESOLVED_UPSTREAM)
        );
        assert_eq!(
            resolver_mount_source(
                false,
                &HostResolvers {
                    etc: mixed.etc.clone(),
                    systemd_upstream: None
                }
            ),
            Some(HOST_RESOLV_CONF),
            "partly routable still beats no resolver at all"
        );

        // Host-dependent by construction — the production condition is "the host
        // has a usable resolver file to bind", since runc refuses a mount with a
        // missing source. Asserting the condition rather than the outcome keeps
        // this honest on a machine that has neither candidate.
        let pod = PodOptions {
            join_netns: Some("/var/run/netns/acct".into()),
            ..Default::default()
        };
        assert_eq!(
            binds_resolver(&build_oci_spec_with(&spec, &[], None, &pod)).as_deref(),
            resolver_mount_source(false, &HostResolvers::read())
        );
    }

    /// R893-B17. The env half of the collector contract is useless without
    /// this: `YAH_SCRYER_SOCKET=/run/yah/scryer.sock` inside a container names
    /// nothing at all unless the host socket is bound there.
    #[test]
    fn the_collector_socket_is_a_single_rw_file_bind() {
        let pod = PodOptions {
            collector_socket: Some((
                "/run/yah/scryer.sock".into(),
                "/run/yah/scryer.sock".into(),
            )),
            ..Default::default()
        };
        let oci = build_oci_spec_with(&test_spec("inner-door"), &[], None, &pod);
        let mounts = oci["mounts"].as_array().unwrap();
        let sock = mounts
            .iter()
            .find(|m| m["destination"] == "/run/yah/scryer.sock")
            .expect("the collector socket must be bind-mounted into the container");
        assert_eq!(sock["type"], "bind");
        assert_eq!(sock["source"], "/run/yah/scryer.sock");
        let opts: Vec<&str> = sock["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        // `connect(2)` needs write permission on the socket inode; `ro` here
        // would produce a reachable path that refuses every connection.
        assert!(opts.contains(&"rw"), "a read-only socket bind cannot be connected to");
        assert!(opts.contains(&"rbind"));
        // The bind must NOT be the parent directory: /run/yah also holds
        // UPGRADE_SHARE_ROOT, i.e. every workload's pingora upgrade socket.
        assert!(
            !mounts.iter().any(|m| m["destination"] == "/run/yah"),
            "binding the socket's parent directory would expose UPGRADE_SHARE_ROOT"
        );
    }

    #[test]
    fn a_node_without_a_collector_gets_no_extra_mount() {
        let oci = build_oci_spec_with(
            &test_spec("inner-door"),
            &[],
            None,
            &PodOptions::default(),
        );
        assert!(
            !oci["mounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["destination"] == "/run/yah/scryer.sock")
        );
    }

    #[test]
    fn pod_shared_dir_appends_a_rw_bind_mount() {
        let pod = PodOptions {
            shared_dir: Some((
                "/run/yah/kamaji/passway-ingress/upgrade".into(),
                "/run/passway".into(),
            )),
            ..Default::default()
        };
        let oci = build_oci_spec_with(&test_spec("passway-ingress"), &[], None, &pod);
        let mounts = oci["mounts"].as_array().unwrap();
        let shared = mounts
            .iter()
            .find(|m| m["destination"] == "/run/passway")
            .expect("shared upgrade-sock dir must be bind-mounted");
        assert_eq!(shared["type"], "bind");
        assert_eq!(shared["source"], "/run/yah/kamaji/passway-ingress/upgrade");
        let opts: Vec<&str> = shared["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        assert!(opts.contains(&"rbind"));
        assert!(
            opts.contains(&"rw"),
            "pingora unlinks+rebinds the upgrade sock, so the dir must be writable"
        );
    }

    /// R870-F27 — the staging layout mirrors the container tree, so two files
    /// sharing a basename cannot collide onto one host path.
    #[test]
    fn staged_spec_files_mirror_the_container_tree() {
        let mut spec = test_spec("inner-door");
        spec.files = vec![
            workload_spec::InlineFile {
                path: "/etc/passway/routes.json".into(),
                content: "{}".into(),
                mode: Some(0o600),
            },
            workload_spec::InlineFile {
                path: "/etc/other/routes.json".into(),
                content: "[]".into(),
                mode: None,
            },
        ];
        let planned = plan_spec_files(Path::new("/run/yah/kamaji/inner-door/files"), &spec).unwrap();
        assert_eq!(
            planned,
            vec![
                SpecFileMount {
                    host_path: "/run/yah/kamaji/inner-door/files/etc/passway/routes.json".into(),
                    container_path: "/etc/passway/routes.json".into(),
                },
                SpecFileMount {
                    host_path: "/run/yah/kamaji/inner-door/files/etc/other/routes.json".into(),
                    container_path: "/etc/other/routes.json".into(),
                },
            ],
            "same basename in two directories must stage to two host paths"
        );
    }

    /// A `.` component is dropped by path parsing rather than refused, and
    /// both halves of the bind report the normalized path.
    #[test]
    fn a_dot_component_normalizes_rather_than_refusing() {
        let mut spec = test_spec("inner-door");
        spec.files = vec![workload_spec::InlineFile {
            path: "/etc/./passway/routes.json".into(),
            content: "{}".into(),
            mode: None,
        }];
        let planned = plan_spec_files(Path::new("/run/yah/kamaji/inner-door/files"), &spec).unwrap();
        assert_eq!(planned[0].container_path, "/etc/passway/routes.json");
        assert_eq!(
            planned[0].host_path,
            "/run/yah/kamaji/inner-door/files/etc/passway/routes.json"
        );
    }

    /// The path rule that is a security boundary, not tidiness: `dir.join()`
    /// on a `..` component escapes the staging dir and has kamaji (root) write
    /// wherever the spec points.
    #[test]
    fn a_traversing_or_relative_spec_file_path_is_refused() {
        for bad in [
            "/etc/../../../../root/.ssh/authorized_keys",
            "/etc/passway/../../root/.ssh/authorized_keys",
            "etc/passway/routes.json",
            "",
            "/",
        ] {
            let mut spec = test_spec("inner-door");
            spec.files = vec![workload_spec::InlineFile {
                path: bad.into(),
                content: String::new(),
                mode: None,
            }];
            assert!(
                plan_spec_files(Path::new("/run/yah/kamaji/inner-door/files"), &spec).is_err(),
                "{bad} must be refused, not staged"
            );
        }
    }

    /// The whole point of the ticket: the OCI spec a containerd deploy hands
    /// runc carries one read-only file bind per declared spec file, and they
    /// come after every other mount.
    #[test]
    fn staged_spec_files_become_trailing_read_only_file_binds() {
        let pod = PodOptions {
            shared_dir: Some((
                "/run/yah/kamaji/inner-door/upgrade-a".into(),
                "/run/passway".into(),
            )),
            spec_files: vec![SpecFileMount {
                host_path: "/run/yah/kamaji/inner-door/files/etc/passway/routes.json".into(),
                container_path: "/etc/passway/routes.json".into(),
            }],
            ..Default::default()
        };
        let oci = build_oci_spec_with(&test_spec("inner-door"), &[], None, &pod);
        let mounts = oci["mounts"].as_array().unwrap();
        let last = mounts.last().unwrap();
        assert_eq!(
            last["destination"], "/etc/passway/routes.json",
            "spec files mount last so a parent mount cannot bury them"
        );
        assert_eq!(last["type"], "bind");
        assert_eq!(
            last["source"],
            "/run/yah/kamaji/inner-door/files/etc/passway/routes.json"
        );
        let opts: Vec<&str> = last["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        assert!(opts.contains(&"rbind"));
        assert!(
            opts.contains(&"ro"),
            "the node rewrites these every deploy; a container write would be silently reverted"
        );
    }

    /// A spec that declares no files adds no mounts — the field is `default`
    /// on every pre-R870 spec, so this is the overwhelmingly common shape.
    #[test]
    fn no_spec_files_means_no_extra_mounts() {
        let spec = test_spec("plain");
        let before = build_oci_spec_with(&spec, &[], None, &PodOptions::default());
        assert!(plan_spec_files(Path::new("/run/yah/kamaji/plain/files"), &spec)
            .unwrap()
            .is_empty());
        assert_eq!(
            before["mounts"].as_array().unwrap().len(),
            build_oci_spec_with(&spec, &[], None, &PodOptions::default())["mounts"]
                .as_array()
                .unwrap()
                .len()
        );
    }

    /// The staging directory is keyed by container id, so the two generations
    /// of a graceful upgrade cannot overwrite each other's config.
    #[test]
    fn spec_files_hostdir_is_per_generation() {
        assert_eq!(
            spec_files_hostdir(&PodSlot::A.container_id("inner-door")),
            Path::new("/run/yah/kamaji/inner-door/files")
        );
        assert_eq!(
            spec_files_hostdir(&PodSlot::B.container_id("inner-door")),
            Path::new("/run/yah/kamaji/inner-door.b/files")
        );
    }

    /// `stage_spec_files` replaces the directory wholesale: a redeploy that
    /// drops a file must not leave the previous deploy's copy behind, or a
    /// later spec re-declaring that path races a stale inode.
    #[tokio::test]
    async fn staging_clears_the_previous_deploy_before_writing() {
        let tmp = std::env::temp_dir().join(format!("kcc-stage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);

        let mut spec = test_spec("inner-door");
        spec.files = vec![
            workload_spec::InlineFile {
                path: "/etc/passway/routes.json".into(),
                content: "first".into(),
                mode: Some(0o600),
            },
            workload_spec::InlineFile {
                path: "/etc/passway/gone.json".into(),
                content: "stale".into(),
                mode: None,
            },
        ];
        let staged = stage_spec_files(&tmp, &spec).await.unwrap();
        assert_eq!(staged.len(), 2);
        assert_eq!(
            std::fs::read_to_string(&staged[0].host_path).unwrap(),
            "first"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&staged[0].host_path)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "declared mode reaches the staged file");
        }

        let gone = staged[1].host_path.clone();
        spec.files.pop();
        spec.files[0].content = "second".into();
        let restaged = stage_spec_files(&tmp, &spec).await.unwrap();
        assert_eq!(restaged.len(), 1);
        assert_eq!(
            std::fs::read_to_string(&restaged[0].host_path).unwrap(),
            "second"
        );
        assert!(
            !Path::new(&gone).exists(),
            "a dropped spec file must not survive the redeploy"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn pod_slots_ping_pong_between_two_stable_ids() {
        assert_eq!(PodSlot::default(), PodSlot::A, "fresh deploy is slot A");
        assert_eq!(PodSlot::A.other(), PodSlot::B);
        assert_eq!(PodSlot::B.other(), PodSlot::A);
        // Slot A keeps the bare ident so pre-upgrade behavior is unchanged.
        assert_eq!(PodSlot::A.container_id("passway-ingress"), "passway-ingress");
        assert_eq!(PodSlot::B.container_id("passway-ingress"), "passway-ingress.b");
    }

    #[test]
    fn shared_upgrade_hostdir_is_per_generation_under_the_ident_root() {
        // Each generation gets its own dir so the incoming passway's upgrade-sock
        // rebind can't clobber the outgoing one's inode (R600-F9).
        assert_eq!(
            shared_upgrade_hostdir("passway-ingress", PodSlot::A),
            std::path::PathBuf::from("/run/yah/kamaji/passway-ingress/upgrade-a")
        );
        assert_eq!(
            shared_upgrade_hostdir("passway-ingress", PodSlot::B),
            std::path::PathBuf::from("/run/yah/kamaji/passway-ingress/upgrade-b")
        );
    }

    #[test]
    fn upgrade_sock_basename_is_the_socket_filename() {
        let mut spec = test_spec("passway-ingress");
        spec.env = vec![workload_spec::EnvVar {
            name: PASSWAY_UPGRADE_SOCK_ENV.into(),
            value: workload_spec::EnvValue::Literal {
                value: "/run/passway/upgrade.sock".into(),
            },
        }];
        assert_eq!(
            upgrade_sock_basename(&spec).as_deref(),
            Some("upgrade.sock")
        );
        // Non-passway workload declares no upgrade sock.
        assert_eq!(upgrade_sock_basename(&test_spec("svc")), None);
    }

    #[test]
    fn passway_listen_addr_reads_spec_env_or_defaults() {
        // Default when PASSWAY_LISTEN is unset — matches passway main.rs.
        assert_eq!(passway_listen_addr(&test_spec("svc")), "0.0.0.0:443");

        // Spec override is used verbatim (it's the fd-handoff key that must
        // byte-match pingora's listener).
        let mut spec = test_spec("passway-ingress");
        spec.env = vec![workload_spec::EnvVar {
            name: PASSWAY_LISTEN_ENV.into(),
            value: workload_spec::EnvValue::Literal {
                value: "0.0.0.0:8443".into(),
            },
        }];
        assert_eq!(passway_listen_addr(&spec), "0.0.0.0:8443");
    }

    #[test]
    fn upgrade_sock_dir_derives_the_container_mount_point() {
        let mut spec = test_spec("passway-ingress");
        spec.env = vec![workload_spec::EnvVar {
            name: PASSWAY_UPGRADE_SOCK_ENV.into(),
            value: workload_spec::EnvValue::Literal {
                value: "/run/passway/upgrade.sock".into(),
            },
        }];
        assert_eq!(upgrade_sock_dir(&spec).as_deref(), Some("/run/passway"));
    }

    #[test]
    fn upgrade_sock_dir_is_none_for_a_non_passway_workload() {
        // No PASSWAY_UPGRADE_SOCK env → not a graceful-upgrade workload → no
        // shared mount is injected (the common case).
        assert_eq!(upgrade_sock_dir(&test_spec("svc")), None);
    }

    #[test]
    fn default_pod_options_match_the_standalone_spec() {
        // build_oci_spec is the PodOptions::default() wrapper — the two must be
        // byte-identical so ordinary workloads are unaffected.
        let spec = test_spec("svc");
        assert_eq!(
            build_oci_spec(&spec, &[], None),
            build_oci_spec_with(&spec, &[], None, &PodOptions::default()),
        );
    }

    #[test]
    fn oci_spec_default_sys_is_fresh_sysfs() {
        let sys = sys_mount(&build_oci_spec(&test_spec("svc"), &[], None));
        assert_eq!(sys["type"], "sysfs");
        assert_eq!(sys["source"], "sysfs");
    }

    #[test]
    fn oci_spec_host_network_binds_host_sys_ro() {
        let sys = sys_mount(&build_oci_spec(
            &with_host_network(test_spec("svc")),
            &[],
            None,
        ));
        assert_eq!(sys["type"], "bind");
        assert_eq!(sys["source"], "/sys");
        let opts: Vec<&str> = sys["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o.as_str().unwrap())
            .collect();
        assert!(opts.contains(&"rbind"), "host /sys bind must be recursive");
        assert!(opts.contains(&"ro"), "host /sys bind must be read-only");
    }

    #[test]
    fn oci_spec_drops_capabilities_to_net_bind_only() {
        let oci = build_oci_spec(&test_spec("svc"), &[], None);
        let caps = &oci["process"]["capabilities"];
        assert_eq!(
            caps["bounding"],
            serde_json::json!(["CAP_NET_BIND_SERVICE"])
        );
        assert_eq!(caps["ambient"], serde_json::json!([]));
        assert_eq!(oci["process"]["noNewPrivileges"], serde_json::json!(true));
    }

    #[test]
    fn oci_spec_carries_spec_volumes_after_the_base_mounts() {
        let mut spec = test_spec("svc");
        spec.volumes = vec![workload_spec::VolumeMount {
            source: workload_spec::VolumeSource::Bind {
                host_path: "/var/lib/yah/sites/x".into(),
            },
            target: "/usr/share/nginx/html".into(),
            read_only: true,
            from_secret_mount: false,
        }];
        let oci = build_oci_spec(&spec, &[], None);
        let mounts = oci["mounts"].as_array().unwrap();
        let bind = mounts.last().unwrap();
        assert_eq!(bind["type"], "bind");
        assert_eq!(bind["source"], "/var/lib/yah/sites/x");
        assert_eq!(bind["destination"], "/usr/share/nginx/html");
        assert!(bind["options"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("ro")));
    }

    #[test]
    fn oci_spec_defaults_to_root_when_user_unset() {
        let oci = build_oci_spec(&test_spec("svc"), &[], None);
        assert_eq!(
            oci["process"]["user"],
            serde_json::json!({"uid": 0, "gid": 0})
        );
    }

    #[test]
    fn oci_spec_honors_numeric_spec_user() {
        let mut spec = test_spec("svc");
        spec.user = Some("101:102".into());
        let oci = build_oci_spec(&spec, &[], None);
        assert_eq!(
            oci["process"]["user"],
            serde_json::json!({"uid": 101, "gid": 102})
        );

        // Bare uid mirrors into gid; named users fall back to root.
        spec.user = Some("101".into());
        assert_eq!(
            build_oci_spec(&spec, &[], None)["process"]["user"],
            serde_json::json!({"uid": 101, "gid": 101})
        );
        spec.user = Some("appuser".into());
        assert_eq!(
            build_oci_spec(&spec, &[], None)["process"]["user"],
            serde_json::json!({"uid": 0, "gid": 0})
        );
    }

    #[test]
    fn oci_spec_carries_literal_env_plus_extra() {
        let mut spec = test_spec("svc");
        spec.env.push(workload_spec::EnvVar {
            name: "FOO".into(),
            value: workload_spec::EnvValue::Literal {
                value: "bar".into(),
            },
        });
        spec.env.push(workload_spec::EnvVar {
            name: "MESH_IP".into(),
            value: workload_spec::EnvValue::FromMesh {
                ident: MeshIdent("self".into()),
                kind: workload_spec::MeshLookup::Url,
            },
        });
        // build_oci_spec is a pure mapper — it does NOT validate. It just
        // filters non-literal env; callers validate upstream.
        let oci = build_oci_spec(&spec, &["YAH_MESH_IP=10.64.0.1".to_string()], None);
        let env = oci["process"]["env"].as_array().unwrap();
        assert_eq!(env.len(), 2);
        assert_eq!(env[0].as_str().unwrap(), "FOO=bar");
        assert_eq!(env[1].as_str().unwrap(), "YAH_MESH_IP=10.64.0.1");
    }

    // ---- R932-B1: the bind-source preflight ----------------------------------

    /// A path no host has. Absolute so it cannot be affected by the cwd the
    /// test runner happens to have.
    const ABSENT: &str = "/nonexistent/r932b1/definitely-not-here.sock";

    #[test]
    fn bind_mount_sources_skips_every_mount_that_has_no_host_source() {
        let mut spec = test_spec("plain");
        // A tmpfs volume beside a bind one, so the spec carries both shapes of
        // the thing the filter has to tell apart.
        spec.volumes = vec![
            workload_spec::VolumeMount {
                source: workload_spec::VolumeSource::Bind {
                    host_path: std::env::temp_dir(),
                },
                target: "/data".into(),
                read_only: false,
                from_secret_mount: false,
            },
            workload_spec::VolumeMount {
                source: workload_spec::VolumeSource::Tmpfs { size_mb: 8 },
                target: "/scratch".into(),
                read_only: false,
                from_secret_mount: false,
            },
        ];
        let oci = build_oci_spec(&spec, &[], None);
        let binds = bind_mount_sources(&oci);

        // /proc, /dev, /tmp, /dev/shm & co. are proc/tmpfs/sysfs mounts with a
        // pseudo source; none of them may be handed to a `stat`.
        let mounts = oci["mounts"].as_array().unwrap();
        let bind_count = mounts.iter().filter(|m| m["type"] == "bind").count();
        assert_eq!(binds.len(), bind_count, "every bind mount must be listed");
        assert!(
            bind_count < mounts.len(),
            "the spec also has non-bind mounts, which must be skipped"
        );
        assert!(
            binds.iter().any(|(dest, _)| dest == "/data"),
            "the bind volume must be listed; got {binds:?}"
        );
        assert!(
            !binds.iter().any(|(dest, _)| dest == "/scratch"),
            "the tmpfs volume has no host source; got {binds:?}"
        );
    }

    #[test]
    fn check_bind_sources_passes_when_every_source_is_present() {
        let mut spec = test_spec("present");
        spec.volumes = vec![workload_spec::VolumeMount {
            source: workload_spec::VolumeSource::Bind {
                host_path: std::env::temp_dir(),
            },
            target: "/data".into(),
            read_only: false,
            from_secret_mount: false,
        }];
        let oci = build_oci_spec(&spec, &[], None);
        assert_eq!(check_bind_sources(&oci), Ok(()));
    }

    /// The production failure, reproduced at the layer that can now refuse it:
    /// the bind is one kamaji *injects*, so the workload's own spec is clean
    /// and only the built mount plan knows the path.
    #[test]
    fn an_injected_collector_socket_that_is_missing_refuses_the_deploy() {
        let pod = PodOptions {
            collector_socket: Some((ABSENT.to_string(), "/run/yah/scryer.sock".to_string())),
            ..Default::default()
        };
        let oci = build_oci_spec_with(&test_spec("noisetable-account"), &[], None, &pod);

        let err = check_bind_sources(&oci).unwrap_err();
        assert!(err.contains(ABSENT), "the host path must be named: {err}");
        assert!(
            err.contains("/run/yah/scryer.sock"),
            "the destination must be named so the operator knows which mount: {err}"
        );
        assert!(
            err.contains("nothing was torn down"),
            "the message has to say the incumbent survived: {err}"
        );

        // And the same spec passes the moment the socket is there — the check
        // is about the host, not about the shape of the mount.
        let pod = PodOptions {
            collector_socket: Some((
                std::env::temp_dir().to_string_lossy().into_owned(),
                "/run/yah/scryer.sock".to_string(),
            )),
            ..Default::default()
        };
        let oci = build_oci_spec_with(&test_spec("noisetable-account"), &[], None, &pod);
        assert_eq!(check_bind_sources(&oci), Ok(()));
    }

    #[test]
    fn a_declared_bind_volume_with_no_host_path_refuses_the_deploy() {
        let mut spec = test_spec("declared");
        spec.volumes = vec![workload_spec::VolumeMount {
            source: workload_spec::VolumeSource::Bind {
                host_path: ABSENT.into(),
            },
            target: "/data".into(),
            read_only: true,
            from_secret_mount: false,
        }];
        let oci = build_oci_spec(&spec, &[], None);
        let err = check_bind_sources(&oci).unwrap_err();
        assert!(err.contains(ABSENT), "{err}");
        assert!(err.contains("/data"), "{err}");
    }

    #[test]
    fn every_missing_source_is_named_not_just_the_first() {
        let oci = serde_json::json!({
            "mounts": [
                { "destination": "/a", "type": "bind", "source": ABSENT },
                { "destination": "/b", "type": "tmpfs", "source": "tmpfs" },
                { "destination": "/c", "type": "bind", "source": "/nonexistent/r932b1/other" },
            ]
        });
        let err = check_bind_sources(&oci).unwrap_err();
        assert!(err.contains(ABSENT), "{err}");
        assert!(err.contains("/nonexistent/r932b1/other"), "{err}");
        assert!(
            !err.contains("tmpfs"),
            "a tmpfs mount has no host source to be missing: {err}"
        );
    }

    #[test]
    fn a_spec_with_no_mounts_at_all_is_not_an_error() {
        assert_eq!(check_bind_sources(&serde_json::json!({})), Ok(()));
        assert_eq!(
            check_bind_sources(&serde_json::json!({ "mounts": [] })),
            Ok(())
        );
    }
}

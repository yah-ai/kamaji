//! MicroVM backend (R605-F8 / W325 §5) — run a workload in its own KVM guest.
//!
//! The other three backends all share the host kernel with the workload: the
//! native backend shares everything, and a container adds namespaces and a
//! cgroup on top of the same kernel. This one does not. A microVM workload
//! boots its own kernel on virtual hardware, so the isolation boundary is the
//! hypervisor rather than the host kernel's namespace implementation.
//!
//! W325 wants that for one specific reason: it is what lets a build share a
//! node with production. Every alternative in that document — carve out a VM,
//! buy a box, move the tag — answers "where do builds go?" by finding builds
//! somewhere else to be. Isolation answers it by making "next to a raft voter"
//! an acceptable place for a build to be.
//!
//! ## Two shapes: a job, or a service
//!
//! This backend ran only one shape until R605-F31 — [`LifecycleArchetype::Job`],
//! a forge run that starts, does work, produces artifacts and exits — and this
//! heading said so. It now runs both, because "a long-lived VM" is a workload
//! the fleet wants (a dev-cluster member living inside a node's hypervisor) and
//! the alternative was supervising those outside kamaji as host systemd units,
//! i.e. having two supervisors on one node that know nothing about each other.
//!
//! The shape is read off [`WorkloadSpec::effective_archetype`] by
//! [`VmShape::of_spec`] — `Job` stays job-shaped, `Server`/`Appliance` are
//! service-shaped — and it is the *only* input that decides which of these the
//! guest gets. Nothing here is a flag or a fallback:
//!
//! | | job-shaped | service-shaped |
//! |---|---|---|
//! | **root device** | the node's one `rootfs.ext4`, **read-only** | a private copy of the node's `service-rootfs.ext4` under the workload's VM dir, **writable** (R605-F32) |
//! | **PID 1** | kamaji-guest-init, which is the job runner | systemd in the service image, with kamaji-guest-init as the job-runner unit |
//! | **durable guest state** | none by design | the scratch disk **and the root** — see [`RootDisk`] |
//! | **VMM process exit** | the job finished; read its verdict and stop | the instance ended; restart per [`RestartPolicy`] |
//! | [`restart_workload`](MicroVmRuntime::restart_workload) | refused, naming why | re-boots the guest in place |
//! | **artifacts** | copied back out of the scratch disk on halt | not copied — a service is not a producer |
//! | **TAP device** | freed when the guest halts | kept across restarts, freed at teardown |
//!
//! The read-only root is the one line here that is a **correctness property and
//! not hardening**: one image serves every job on the node, so a writable one
//! would let job N leave state for job N+1. That survives verbatim for jobs. A
//! service does not relax it — it *sidesteps* it, by not sharing an image at
//! all: its root is a private copy, so no other workload can observe what it
//! writes, and `rootfs.ext4` on the node is still never written by anyone.
//! `the_rootfs_is_read_only_and_the_workspace_is_not` and
//! `a_service_gets_its_own_root_and_never_writes_the_nodes` pin both halves.
//!
//! A service durably keeps **both** surfaces: the scratch disk, which this
//! backend neither rebuilds nor extracts between restarts, and — since R605-F33
//! finished the guest half — its root, which the init now keeps as the real
//! block device rather than overlaying a tmpfs onto. [`RootDisk`] carries the
//! history and why the two halves landed a day apart.
//!
//! The restart loop itself is **not** implemented here. It is
//! [`crate::supervise`], shared with [`crate::native`], and this module supplies
//! only the four operations that genuinely differ between forking a binary and
//! booting a guest. That is the whole reason this heading no longer says the
//! backend "deliberately does not implement the restart loop `crate::native`
//! carries": there is now one loop and two backends, rather than a loop on one
//! side and a disclaimer on the other.
//!
//! [`LifecycleArchetype::Job`]: workload_spec::LifecycleArchetype::Job
//! [`RestartPolicy`]: workload_spec::RestartPolicy
//!
//! ## The four things a microVM needs that a container does not
//!
//! W325 §5 called these "the real cost, and it is not Rust". They are, in the
//! order this module deals with them:
//!
//! 1. **A kernel and a rootfs.** There is no image to pull — `spec.image` is
//!    identity metadata here exactly as it is for native exec. A job-shaped
//!    guest boots the node's configured kernel with the node's configured
//!    rootfs attached **read-only**, so no job can leave anything behind in it
//!    for the next one; a service-shaped guest boots the same kernel with a
//!    private writable copy of the node's *service* image, which no other
//!    workload can see. See [`MicroVmConfig`] and [`RootDisk`]. The kernel's
//!    format and command line are per-arch — see [`GuestArch`].
//! 2. **A way in and out for files.** A container gets a bind mount; a guest
//!    kernel cannot see the host filesystem at all. Each job gets a scratch
//!    ext4 disk built from its bind-mount sources, attached as the second block
//!    device, and copied back out after the guest halts. See [`workspace`].
//! 3. **Network that reaches crates.io.** A TAP device per guest, NAT'd out the
//!    node's uplink. Addressing is a `/30` per slot so two concurrent builds on
//!    one node cannot collide. See [`GuestSlot`].
//! 4. **Somewhere to put the argv.** The guest has no idea what it was booted
//!    to do, so kamaji writes [`MicroVmJob`] as `/job.json` at the root of the
//!    scratch disk and the rootfs's init reads it. That JSON is the contract
//!    between this file and the rootfs image; it is versioned by
//!    [`JOB_SCHEMA_VERSION`] for exactly that reason. The guest answers on the
//!    same channel — [`JobStatus`] at [`JOB_STATUS_FILE`] — because the VMM's
//!    exit code cannot carry the job's, which that constant explains.
//!
//! The guest half of that contract is `crates/kamaji-guest-init`, and the kernel
//! and rootfs it lives in are built by `oss/kamaji/guest/build-guest-image.sh`.
//! The pair is exercised end to end by `tests/microvm_guest_e2e.rs`, which needs
//! a host with `/dev/kvm` and skips elsewhere.
//!
//! ## Privileges
//!
//! This backend needs more than the others, and pretending otherwise would just
//! move the failure later:
//!
//! | need | why | failure if absent |
//! |---|---|---|
//! | `/dev/kvm` read-write | ask the kernel for a VM | probe reports unavailable ([`crate::probe`]) |
//! | `CAP_NET_ADMIN` | create the TAP device and address it (native ioctls, see [`net::create_tap`]) | deploy fails naming the ioctl that refused |
//! | `iptables` | NAT the guest out of the uplink | kamaji starts with guests air-gapped, saying why ([`GuestNetwork::discover`]) |
//! | `mkfs.ext4`, `debugfs` (e2fsprogs) | build and unpack the scratch disk | deploy fails naming the missing binary |
//!
//! Note what is *not* on that list: root. The scratch disk is built with
//! `mkfs.ext4 -d` and unpacked with `debugfs -R rdump`, neither of which needs
//! a loop mount, and both of which run as an ordinary user. W325 §4 measured
//! that the fleet's `debian` service user is not in group `kvm`; that is a
//! one-line `usermod` per node, not a reason to run this as root.
//!
//! ## What is exercised where
//!
//! Everything in this module that decides *what* to run — slot arithmetic, the
//! Firecracker config document, the job contract, memory clamping, argv — is
//! pure and unit-tested on any host. Everything that *does* it — `mkfs.ext4`,
//! the TAP ioctls, `iptables`, spawning the VMM — is Linux-only, and is
//! verified on a node. The split is deliberate: the parts that are wrong
//! *quietly* are the pure ones.
//!
//! @arch:see(.yah/docs/working/W325-isolated-x86-build-capacity.md)
//!
//! @yah:ticket(R605-F14, "Build the microVM guest side: kernel + rootfs + an init that reads /job.json")
//! @yah:status(review)
//! @yah:at(2026-09-10T08:27:15Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @yah:next("THE CONTRACT IS ALREADY PINNED, so this is an implementation job and not a design one. kamaji::microvm::MicroVmJob is the document kamaji writes to /job.json at the root of the scratch disk, and the exact serialized bytes are locked by the golden test the_job_document_serializes_to_the_shape_the_guest_init_parses. Code the init against that fixture, not against the Rust struct: the two sides ship separately (a rootfs image built months apart from the kamaji binary that boots it), so only the JSON shape is the contract. JOB_SCHEMA_VERSION is 1; the init should refuse a schema it does not recognise rather than guess.")
//! @yah:verify("A node with --microvm-dir populated boots a guest that reads /job.json, bind-mounts each GuestMount slug at its target, runs argv, writes to /yah/produced and halts. kamaji reports the workload Stopped and the artifacts appear under /var/lib/yah/qed/produced/<forge-id> on the host.")
//! @yah:next("THE ROOTFS MUST BE BUILT READ-ONLY-CLEAN. kamaji attaches it with is_read_only: true and one image serves every job on the node, so the init cannot write anywhere outside /workspace. That is a correctness property (job N must not leave state for job N+1), not hardening, and the_rootfs_is_read_only_and_the_workspace_is_not pins it from the kamaji side.")
//! @yah:next("Tier: Warrior -- an image build plus a small init, on unfamiliar ground (Firecracker guest conventions), and it needs a Linux host with KVM to test at all. The camp Mac cannot run any of it, which is exactly why R605-F8 stopped here.")
//! @yah:gotcha("THE KERNEL MUST BE AN UNCOMPRESSED ELF vmlinux, not a bzImage -- Firecracker boots the former only. kamaji passes it as boot-source.kernel_image_path from <microvm-dir>/vmlinux, and expects the rootfs at <microvm-dir>/rootfs.ext4; MicroVmRuntime::new refuses to construct if either path is absent, so a node with the wrong filename advertises no microVM backend rather than failing every build.")
//! @yah:assumes("That a guest booting with panic=1 reboot=k exits the VMM process on halt, which is what kamaji's supervisor treats as job completion. Read from Firecracker's documented behaviour, NOT measured here -- there is no KVM on the camp Mac. If it turns out a halted guest leaves firecracker resident, the supervisor never fires and every microVM job hangs until teardown; that is the first thing to check on the first real boot.")
//! @yah:handoff("GUEST SIDE IS BUILT AND PROVEN ON REAL HARDWARE. New crate oss/kamaji/crates/kamaji-guest-init (static x86_64-unknown-linux-musl PID 1: reads job.json off the scratch disk, refuses an unknown schema, assembles a writable root, bind-mounts each GuestMount slug at its target, runs argv, records the result, resets the VM) plus oss/kamaji/guest/build-guest-image.sh which produces <out>/vmlinux + <out>/rootfs.ext4 from sha256-pinned sources. Proven end to end on us-west-003 through kamaji's OWN MicroVmRuntime::deploy_workload by the new oss/kamaji/crates/kamaji/tests/microvm_guest_e2e.rs: 2 pass / 0 fail. A forge-shaped spec's artifact reaches the host produced dir with the document's env and workdir honoured, and kamaji reports Stopped ~600ms after deploy.")
//! @yah:handoff("THE @yah:assumes IS DISCHARGED, AND HALF OF IT WAS WRONG. Measured with firecracker v1.16.1 on us-west-003, not read from docs. TRUE HALF: a guest that resets under `reboot=k` does exit the VMM -- `Firecracker exiting successfully. exit_code=0`, zero resident firecracker processes, ~1.2s total wall. So the supervisor's completion signal fires and microVM jobs do not hang. FALSE IMPLICATION: firecracker also exits 0 when the guest KERNEL PANICS (observed on the very first boot, which panicked with no root device) because panic=1 reboots through the same i8042 reset. So the VMM exit code cannot distinguish a passing job from a failing one or from a guest that never ran the job at all.")
//! @yah:handoff("THAT MADE R605-F8's SUPERVISOR REPORT EVERY FAILED BUILD AS Stopped, and it is fixed in this pass rather than filed. Guest half: the init writes JobStatus to job-status.json on the scratch disk after reaping the job. Host half (microvm.rs): new JOB_STATUS_FILE const + JobStatus type + workspace::read_job_status (debugfs dump; note debugfs exits 0 for a missing file, so the READ is what detects absence), and the supervisor's clean-VMM-exit arm now folds exit_code into the status. Fail closed: an absent or unparseable status document is Failed, because a guest that halted without recording one did not demonstrably run the job. There is no deployed rootfs image anywhere yet, so nothing had to be kept compatible.")
//! @yah:handoff("THE KERNEL CONFIG IS FIRECRACKER'S OWN, VENDORED VERBATIM, AND THAT IS THE LOAD-BEARING DECISION. kernel/base-x86_64-6.1.config is firecracker v1.16.1's resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config, sha256-checked by the build script so a local edit to a 3556-line generated file is caught; kernel/microvm.config is the delta over it and is ONE symbol. The first attempt was a from-nothing config over `make tinyconfig` (17MB vmlinux, 1min build) and it did not boot: `virtio_blk: probe of virtio0 failed with error -22` then `VFS: Cannot open root device vda`. Bisected to a measured fact -- taking firecracker's config and turning off CONFIG_PCI ALONE reproduces it exactly, even though a Firecracker guest has no PCI bus and kamaji already passes pci=off. MECHANISM NOT ESTABLISHED: the only interrupt-related symbols lost with PCI=n are CONFIG_GENERIC_MSI_IRQ and CONFIG_GENERIC_MSI_IRQ_DOMAIN (both selected by PCI_MSI), which makes them candidates and not a cause; neither can be re-enabled from a fragment without patching Kconfig, so it was left as a named candidate. Cost of the vendor base: vmlinux is 44MB rather than 17MB. Worth it.")
//! @yah:handoff("MEASURED GUEST CMDLINE, worth not re-deriving: `console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux pci=off root=/dev/vda ro virtio_mmio.device=4K@0xc0001000:5 virtio_mmio.device=4K@0xc0002000:6`. Two consequences. (1) Firecracker appends `root=/dev/vda ro` ITSELF from the drive marked is_root_device, so kamaji's vmm_config neither has nor needs a root= -- do not add one. (2) It advertises its virtio devices as virtio_mmio.device= cmdline arguments, NOT through ACPI, so CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES is required and is the one delta in kernel/microvm.config. Without it the devices are never registered and the guest panics with the same visible error as the PCI problem, from an unrelated cause.")
//! @yah:handoff("NODE STATE CHANGED ON us-west-003 (192.168.10.32, chosen because it is x86_64 with KVM, a raft NON-voter and not the public-site host -- us-west-001 and us-east-001 were excluded on the leader's instruction, and us-west-002/013 are the known-offline pair from R605-B11). Installed: firecracker v1.16.1 at /usr/local/bin/firecracker (tarball sha256 verified against upstream's published .sha256.txt), apt build deps (bc bison flex libelf-dev libssl-dev e2fsprogs xz-utils bzip2 file), rustup target x86_64-unknown-linux-musl, and the built artifacts at /var/lib/yah/kamaji/microvm/{vmlinux,rootfs.ext4} (sha256 vmlinux c06534654e6503b8fc22fc0264c626f478d3968144800ef33b50d60a409ecf1a, rootfs 0ea9aacfe2227e8784f771a9cf3317bb2c7beb46a6167893bb86d28372e07b69). Also ran `usermod -aG kvm yah` -- that is R605-T15's fix applied to THIS node's service user; the machine file notes kamaji.service there runs as root so it did not strictly need it, but a cargo test running as `yah` did. kamaji.service was NOT restarted.")
//! @yah:handoff("THE ROOTFS IS DELIBERATELY MINIMAL: busybox 1.37.0 built from source, static, plus /sbin/init and a checked-in /etc. That is enough for the `/bin/sh -c ...` argv shape a forge step uses and is NOT a build toolchain -- no cargo, no git, no cc. A real cargo forge run in a guest needs a toolchain image, which is separable work and was not attempted. Build inputs are all in oss/kamaji/guest/ (README.md explains the bump procedure); out/ is gitignored (~75MB of derived artifacts).")
//! @yah:next("THE ONE REMAINING LEG, and it is why this is a handoff rather than a review: the kamaji.service DEPLOYED on us-west-003 has no --microvm-dir, so the long-running service still refuses a microvm-marked deploy by design. The edit is adding `--microvm-dir /var/lib/yah/kamaji/microvm` to ExecStart plus a RESTART of kamaji.service (not a reload). Left to the operator/node track on purpose: it is a fleet unit edit plus a service restart, and the machine file documents kamaji restart as workload-losing. It is cheap right now though -- at 2026-09-10T08:16Z /workloads showed 8 Exited, 7 Failed, 1 Pending and NOTHING Running. Everything downstream of that flag is already proven: kamaji-bin builds MicroVmConfig as dir.join(vmlinux) / dir.join(rootfs.ext4) at kamaji-bin/src/main.rs:748, which is exactly the config tests/microvm_guest_e2e.rs constructs.")
//! @yah:next("THEN the @yah:verify's last clause: a real forge dispatch through yubaba so artifacts land under /var/lib/yah/qed/produced/<forge-id>. The deploy -> boot -> mounts -> argv -> Stopped -> artifacts-on-host half of that sentence is asserted by the e2e test; what is unproven is the yubaba/forge dispatch above it, including whether a forge spec reaches a node with the microvm annotation set at all.")
//! @yah:next("GUEST NETWORKING IS ENTIRELY UNEXERCISED. Every test ran with MicroVmConfig.network = None, so net::create_tap, the iptables MASQUERADE rule and the ip= kernel argument have never run against a real guest -- they need CAP_NET_ADMIN, which is a separate host-privilege question from `does the guest boot`. A build that has to reach crates.io needs this leg, and the guest init's resolv.conf / lo-up path is only covered in the dns=None direction.")
//! @yah:next("THE GUEST HAS NO BUILD TOOLCHAIN (busybox + init only). Before a real cargo forge run the rootfs needs cargo/rustc/git/cc -- either a second layer in build-guest-image.sh or a mounted toolchain volume. Worth deciding which, since a toolchain baked into a read-only image is version-pinned per node while a mounted one is not.")
//! @yah:gotcha("DO NOT TURN OFF CONFIG_PCI in the guest kernel config. It is the obvious economy -- a Firecracker guest has no PCI bus and kamaji passes pci=off -- and it is measured to break virtio_blk's probe (-22) and leave the guest with no root device. build-guest-image.sh lists CONFIG_PCI in REQUIRED_SYMBOLS so the next person to have that idea gets a build failure instead of a boot failure.")
//! @yah:gotcha("kamaji's microVM backend spawns `mkfs.ext4` and `debugfs` BY BARE NAME, and on Debian they live in /usr/sbin -- which systemd's default PATH includes (so kamaji.service finds them) and a non-login `ssh host cargo test` does not. The symptom is kamaji's own message `mkfs.ext4 failed -- is e2fsprogs installed on this node?` on a node where it plainly is. tests/microvm_guest_e2e.rs::ensure_sbin_on_path exists for exactly this.")
//! @yah:gotcha("build-guest-image.sh only runs on x86_64 Linux -- it compiles an x86_64 kernel. The camp Mac cannot build or boot any of this, which is the constraint that stopped R605-F8. us-west-003 is the node that can.")
//! @yah:gotcha("`mkfs.ext4 -d` records the BUILDING user's uid/gid on every file it copies in, so guest files are owned by whoever ran the build (observed 1000:993 inside the guest). Harmless while the job runs as root, which it does -- but a future non-root guest job would trip over it.")
//! @yah:handoff("Tree anchor at handoff: 4740623c73297188d4265608265996025ba30cd3 — the shared tree as I left it. Diff against it (`git diff 4740623c73297188d4265608265996025ba30cd3..HEAD`) to see what landed under you, and quote this SHA rather than 'HEAD' in any revert/restore instruction.")
//! @yah:verify("cargo test -p kamaji --all-features --lib: 209 pass / 0 fail (baseline 208; +1 is the_guest_status_document_parses_the_shape_the_init_writes)")
//! @yah:verify("cargo test -p kamaji-guest-init: 8 pass / 0 fail (new crate; the golden fixture from the kamaji side, plus schema-refusal, additive-field tolerance and validation)")
//! @yah:verify("cargo test --workspace --all-features in oss/kamaji: all green, 0 failed across every package")
//! @yah:verify("cargo clippy -p kamaji-guest-init --all-targets: 0 warnings")
//! @yah:verify("ON A KVM HOST: KAMAJI_MICROVM_DIR=<dir> cargo test -p kamaji --features microvm-integration --test microvm_guest_e2e -- --nocapture: 2 pass / 0 fail on us-west-003. Skips with a specific reason (which artifact, which binary, or /dev/kvm) anywhere without the substrate.")
//! @yah:verify("scripts/check-workspace-members.sh: all 63 members resolve. scripts/check-nul-bytes.sh: ok.")
//! @yah:handoff("LEADER SIGN-OFF (R605, session:0befddd7): moved handoff -> review. The courier set handoff on the grounds that the kamaji.service ExecStart edit + restart remained. That leg is real but it is a FLEET action on someone else's ticket, not unfinished guest work, and this ticket's own title — build the microVM guest side: kernel + rootfs + an init that reads /job.json — is delivered and proven on real hardware. Leaving it at handoff parked four separable work items on one ticket nobody would re-claim as a unit, and blocked R605-F16, which depends_on F14 and for which handoff is not a terminal state.")
//! @yah:next("RETIRING THE FILING-TIME BRIEF, which is now stale: the first three next entries were the ticket's original instructions (code the init against the golden fixture, build the rootfs read-only-clean, Tier: Warrior). All three were followed and are recorded in the handoff. The remaining four have been filed as real, claimable tickets instead of left here — see the entry below.")
//! @yah:next("THE FOUR REMAINING LEGS ARE NOW TICKETS, not entries on this closed ticket — claim these, not this: R605-T15 absorbed the kamaji.service `--microvm-dir` ExecStart edit + restart (and records that us-west-003's usermod is already done). R605-T24 proves a real forge dispatch reaches a guest through yubaba, which is the one unproven clause of this ticket's verify criterion — it depends_on T15. R605-F22 covers guest networking, which has NEVER run against a live guest (every boot so far was network = None) and gates any build that must reach crates.io. R605-F23 decides baked-layer vs mounted-volume for the build toolchain the minimal busybox rootfs deliberately lacks — it depends_on F22.")
//!
//! @yah:ticket(R605-F23, "The guest rootfs has no build toolchain, so it cannot yet run a real forge step — decide baked layer vs mounted volume")
//! @yah:status(review)
//! @yah:at(2026-09-11T00:19:11Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @yah:verify("A real cargo forge step — not a shell echo — completes inside a microVM guest on us-west-003 and its artifact reaches the host produced dir. Note this ticket also depends on guest egress (R605-F22) if the build resolves any crates.io dependency.")
//! @yah:gotcha("R605-F14 built the rootfs DELIBERATELY MINIMAL: busybox 1.37.0 static, /sbin/init, and a checked-in /etc. That is exactly enough for the `/bin/sh -c ...` argv shape a forge step uses, and it is NOT a build toolchain — no cargo, no rustc, no git, no cc. So the e2e proof that a guest boots, mounts, runs argv and lands artifacts on the host is real, and a real cargo forge run in a guest is still impossible. Do not read F14's green e2e as 'builds work in microVMs yet'.")
//! @yah:depends_on(R605-F22)
//! @yah:handoff("DECIDED: MOUNTED, AS A SECOND READ-ONLY DRIVE. The ticket called this \"a genuine fork with no obvious default\"; it is a false dichotomy and the framing is why. The fork looks real only if mounted implies mutable. It does not: Firecracker takes a list of drives, kamaji already attaches the rootfs with is_read_only:true, and the toolchain volume is attached exactly the same way — so the guest can no more write to it than to a baked layer. The correctness property the read-only rootfs exists for (\"job N must not leave state for job N+1\") is about JOB-WRITABLE state, and a read-only drive has none. Pinned as an assertion at microvm.rs `the_toolchain_volume_is_as_read_only_as_the_rootfs`, so if a future change makes it writable the fork becomes real again and that test goes red.")
//! @yah:handoff("THE SIZE ESTIMATE IN THIS TICKET WAS WRONG BY 15x, AND THAT IS THE STRONGEST EVIDENCE FOR THE CALL. Measured on us-west-003 2026-09-10, not estimated: a usable Rust + C build environment is 1166 MB (1003 MiB of content) against a 30 MB rootfs. The ticket priced baking it in at \"a ~75MB image rebuild\". Breakdown: a default rustup profile is 1.8 GB of which 900 MB is rust-docs that no guest will read; the minimal usable Rust subset (cargo + rustc + shared libs + one target std) is 356 MB, 576 MB with both gnu and musl std; the Debian C closure (gcc 14.2.0-19, binutils 2.44-3, libc6-dev, make, pkg-config, ca-certificates — 64 packages resolved) adds ~250 MB. So baking would grow the artifact redistributed on every busybox, kernel or init change from 30 MB to 1.2 GB, and couple the cadence of a Rust release to that of a kernel CVE. Two independently versioned, independently hashed files is the cheaper shape by a wide margin.")
//! @yah:handoff("THE THIRD PROBLEM — WHERE A BUILD WRITES — AND WHAT WAS CHOSEN. Neither half of the ticket's fork addressed it and it would have blocked any real build. Two of the three surfaces a build wants were already right and one was not. (1) Root: ALREADY WRITABLE, and this was a discovery rather than a change — kamaji-guest-init has assembled an overlayfs root since F14 (read-only image as lower, tmpfs as upper, pivot_root into the result), so mount points are creatable and nothing reaches the image. (2) A job's SOURCE TREE is bind-mounted from the scratch disk, so cargo's default `target/` beside the sources is already on disk and in the place a forge step collecting target/release/foo expects. This is why CARGO_TARGET_DIR is deliberately NOT set — redirecting it would move artifacts out from under every such step. (3) CARGO_HOME and TMPDIR were the real hole: they default to $HOME/.cargo and /tmp, which in this guest are the overlay's tmpfs upper and a tmpfs, i.e. GUEST RAM. A registry cache and rustc temporaries are hundreds of MB against a guest sized in single-digit GB, so left alone the first real build dies of OOM inside the linker. Both are now defaulted onto the scratch disk (boot.rs `build_scratch`), which is the one writable surface that is both large (8 GiB floor) and genuinely per-job — kamaji builds it fresh at deploy and it dies with the guest. A tmpfs would satisfy job-N/job-N+1 equally and is what the obvious reading suggests; it is rejected on SIZE, not on correctness. Job-supplied env still wins, as with every other default.")
//! @yah:handoff("HOW THE TOOLCHAIN REACHES THE GUEST: A SECOND OVERLAYFS LOWER LAYER, not a PATH entry. This is the one design point that is non-obvious and it was found by failing. cargo and rustc are glibc-DYNAMIC (measured: ldd on the node's rustc lists libc/libm/libpthread/libgcc_s/librt/libdl plus the /lib64/ld-linux-x86-64.so.2 interpreter), and an ELF interpreter path is baked into the executable and is not searched — so a `/toolchain/bin` on PATH fails with \"No such file or directory\" naming a file that is plainly present. Folding the image in as the overlay's second lower layer instead makes everything appear at its natural absolute path: /usr/bin/cc, /lib64/ld-linux-x86-64.so.2, /usr/local/bin/cargo. No wrappers, no relocation, no LD_LIBRARY_PATH — a build sees an ordinary Debian userland because that is literally what the layer is. Order is lowerdir=/:/toolchain and NOT the reverse: overlayfs resolves left to right, so the busybox image wins every collision and its /bin applets and checked-in /etc stay authoritative, while directories MERGE rather than shadow so /etc/ssl/certs from the toolchain is still visible through the rootfs's own /etc. Both layers read-only, tmpfs still the only writable part. One trap found and fixed in build-toolchain-image.sh: Debian has been usr-merged since bookworm, so every .deb puts its payload under /usr and the `/lib -> usr/lib` and `/lib64 -> usr/lib64` symlinks live in base-files, which is not in the closure — without them the loader path resolves to nothing.")
//! @yah:verify("PASS ON REAL HARDWARE, us-west-003, 2026-09-11T00:10-00:25Z. Baseline: before this ticket microvm_guest_e2e had 2 tests (R605-F14's) and microvm_guest_net_e2e had 1 (R605-F22's); both suites still pass unchanged. Now: microvm_guest_e2e 3 passed / 0 failed, microvm_guest_net_e2e 2 passed / 0 failed, kamaji lib 115 passed / 0 failed (3 of those new). `cargo check --workspace --all-targets --features microvm-integration` on oss/kamaji is clean — no errors, no unused warnings. THE TICKET'S OWN CRITERION, met literally: new test `a_real_cargo_build_runs_in_a_guest_and_its_binary_lands_on_the_host` drives the real MicroVmRuntime::deploy_workload and its guest console reads `cargo 1.98.0` / `rustc 1.98.0` / `cc (Debian 14.2.0-19) 14.2.0`, then `Compiling guestbuild v0.1.0 (/src)` -> `Finished release profile in 0.16s`; the binary is copied to /yah/produced, EXECUTED in the guest, and both the binary and its output reach the host produced dir. Whole guest lifetime 709ms, which is genuinely that fast — the same crate compiles in 0.17s on the host. The console also shows `build toolchain on /dev/vdc` with the manifest, i.e. the third drive attached and probed as designed.")
//! @yah:verify("THE crates.io CLAUSE IS ALSO CLOSED, which this ticket's verify criterion flagged as conditional on R605-F22. New test `a_guest_fetches_a_crate_from_crates_io_over_tls` in microvm_guest_net_e2e.rs, PASSES: a guest with a TAP ran `cargo fetch` (NOT --offline) against the real crates.io and got `Updating crates.io index` -> `Downloaded cfg-if v1.0.4` -> FETCH_OK, then compiled against what it fetched -> BUILD_OK. That is the whole stack above what F22 proved: F22 established a guest-resolved outbound TCP connect to static.crates.io; this adds TLS, certificate verification and the HTTP index protocol. Certificate verification is the part that could NOT have worked before — the rootfs carries four files in /etc and none is a trust store, so a guest could open the socket and still fail every fetch at verification, a failure that presents as a network problem and is not one. The toolchain volume supplies /etc/ssl/certs/ca-certificates.crt, assembled in the builder from the ca-certificates package's Mozilla set exactly as update-ca-certificates would (the .deb ships the PEMs and leaves the bundle to a postinst that never runs here). The test reports CERTS=<line count> first precisely to tell \"no trust store\" apart from a handshake that failed for another reason; it read CERTS=3697.")
//! @yah:handoff("PROVENANCE, the ticket's second consequence. Each guest image builder now writes a `<image>.sha256` sidecar, and MicroVmRuntime::new reads it at kamaji startup and logs image+digest for BOTH the rootfs and the toolchain (microvm.rs `log_provenance`). A sidecar rather than hashing in-process for two reasons: the toolchain is 1.2 GB and this is on kamaji's startup path, and `microvm-integration` is deliberately a feature whose own Cargo.toml comment says it \"adds no Rust deps beyond libc\" — pulling in sha2 would spend the backend's whole dependency budget on one log line. An unidentifiable image warns rather than refuses (a node that can build beats a node that will not start) and the warning names the regeneration command. The toolchain image ALSO carries /kamaji-toolchain.json internally — rust version, targets, prefix, and all 64 Debian package versions — which is both the guest's proof that a drive IS the toolchain and the thing echoed to the console at every boot. us-west-003's machine file now records both digests, what each artifact is, and the fact that the deployed kamaji does not attach the toolchain yet.")
//! @yah:gotcha("THE DEPLOYED kamaji ON us-west-003 DOES NOT ATTACH toolchain.ext4, so do not read this ticket as \"forge builds work in production now\". 0.8.38-h2 predates F23: its MicroVmConfig has no toolchain_image field, so a forge dispatched through yubaba today still boots a TWO-drive guest with no compiler — exactly the pre-F23 behaviour, silently. The image is staged at /var/lib/yah/kamaji/microvm/toolchain.ext4 and proven, but picking it up needs a kamaji built from a tree carrying F23. The sequence from R605-B26 is unchanged and this does not shortcut it: R605-F22 lands, then build, then a PAIRED yubaba+kamaji hotship (ProtocolVersion::CURRENT is V9; a skewed pair fails every call at connect while still reporting active with NRestarts=0), never kamaji alone, and never scripts/roll-node.sh against this node. Everything F23 asserts is asserted through kamaji's OWN MicroVmRuntime::deploy_workload, which is the same boundary R605-F14 was proven at and the same one R605-T24 exists to extend upward through yubaba.")
//! @yah:gotcha("THE ROOTFS WAS REBUILT AND AN OLD ONE SILENTLY HAS NO COMPILER. rootfs.ext4 on us-west-003 is now sha256 bf8d367f351ddee1920a6ca4354779c08a74db1af0465eb43a7a0394888aa6ec. The only change is one empty directory — /toolchain, added to ROOTFS_DIRS — but it is load-bearing: it is where the init mounts the toolchain volume so it can become an overlay lower layer. A node running an OLDER rootfs with a NEWER kamaji boots fine, attaches the third drive, fails to mount it, and logs \"no build-toolchain volume attached\", i.e. it degrades quietly to a guest that can run programs but not compile them. Ship the rootfs and the toolchain together. Two smaller traps found while building the image, both now guarded in the script rather than left as lore: `dpkg-deb --show` takes a SINGLE archive and silently reports only the first when handed a glob, which produced a manifest claiming 1 package where there are 64 (caught by reading the line the guest init logs at boot, not by the script failing — the script now loops and asserts >= 2); and `cc` is a dpkg alternative created by a postinst that never runs here, so without an explicit symlink the cc crate fails looking for a compiler sitting next to it under another name.")
//! @yah:gotcha("us-west-003 IS BACK UP, contradicting R605's standing x86-capacity gotcha. Measured 2026-09-10T23:50Z: rebooted ~2h earlier, load average 0.02 on 16 threads, 343G free on /. The gotcha describing it as wedged at load ~35 and refusing ssh was true when written and is now stale — every measurement in this ticket was taken on that box. ORPHAN-GC BIT THIS TICKET and the occurrence is recorded on R770 with a live reproducer left in place: `cargo-orphan-gc: Permission denied (os error 13)` on exactly one crate unit, reproducible, NOT the missing-file class R770 is written around, and `cargo orphan-gc log` names nothing. Worked around for one run with RUSTC_WRAPPER=/home/yah/yah/.cargo/rustc-wrapper.sh (bypasses orphan-gc, keeps sccache) rather than cleaning the target dir, deliberately so the evidence survives; @Ashguard:libra is live on R770 and was messaged directly. Separately, an earlier session had run cargo as root in ~/yah/oss/kamaji leaving root-owned dirs under target/debug/.fingerprint; `sudo chown -R yah:yah target` cleared that, which is a different and honestly-reported error from the orphan-gc one.")
//! @yah:cleanup("The toolchain image takes its C half from the BUILD NODE's own apt repository (apt-get download + dpkg-deb -x, unprivileged, no root, no chroot). That is reproducible in the sense that matters — the 64 resolved package versions are recorded in the image manifest and travel with the bytes — but it is not hermetic across nodes the way the sha256-pinned Rust tarballs are: building on a node with a different apt state yields a different image. Pinning against snapshot.debian.org would close that. Not done here because it changes nothing the fleet can currently observe (one build node), and the manifest makes any drift attributable after the fact.")
//! @yah:cleanup("The image ships rustc + cargo only — no clippy, no rustfmt, no rust-docs. A forge step that runs `cargo clippy` or `cargo fmt --check` inside a guest will fail with command-not-found. Adding them is two component names in build-toolchain-image.sh's install_rust and roughly +30 MB; left out because it is a different ticket's requirement and this image is already the largest artifact the fleet distributes. Worth knowing before someone routes a lint step at a microVM node and reads the failure as a toolchain bug.")
//! @yah:next("RETIRING THE FILING-TIME BRIEF — the decision it asked for is MADE and the entry was removed so nobody re-litigates it. It said the baked-vs-mounted fork was \"a genuine fork with no obvious default\" and priced baking at \"a ~75MB image rebuild\". Both premises were wrong and the handoff entries say why: mounted does not imply mutable (the volume is attached is_read_only:true, exactly like the rootfs), and the real size is 1166 MB. Resolved as MOUNTED, second read-only drive, implemented and proven on real hardware. Its one still-live clause is also handled: mkfs.ext4 -d does record the BUILDING user's uid/gid on every file copied in, and it remains harmless because jobs run as root — the toolchain image is built by the `yah` user on us-west-003 and its files carry that uid inside the guest, with no effect on a read-only mount.")
//! @yah:gotcha("CORRECTION TO THE ORPHAN-GC GOTCHA ABOVE — IT IS ROOT-CAUSED AND FIXED, not unattributed. @Ashguard:libra (R770) diagnosed it from the state this ticket preserved, which is the whole argument for not cleaning up before attributing. Cause: the earlier `sudo cargo` at 23:36Z did not only touch target/, it also wrote into the INVOKING USER's orphan-gc state dir, leaving six root-owned mode-644 files under ~/.cargo/orphan-gc/workspaces/<ws>/{families,locks}/. `Store::lock_family` opens locks/<key>.lock with .write(true), so as the `yah` user that is EACCES on exactly three units — which is precisely why one crate failed while every dependency was fine, why it reproduced across runs, and why running the same wrapper chain by hand worked (by hand it was not taking the family lock for that key). Two fixes landed in oss/orphan-gc: bookkeeping errors now degrade to passthrough instead of failing the compile (a GC tool must not kill a build over its own metadata), and every filesystem error now names its file, which is why this arrived as one contentless line. REPAIRED HERE: `sudo chown -R yah:yah ~/.cargo/orphan-gc` on us-west-003, 0 root-owned files left; rebuilt through the normal wrapper chain with NO RUSTC_WRAPPER bypass and the whole thing is green (microvm_guest_e2e 3/3, kamaji lib 115/115), so every result on this ticket also holds through the real build path. NOTE the fleet's orphan-gc binary is still the pre-fix one, so a future `sudo cargo` on that node recurs identically. Also new: `cargo orphan-gc attribute <path-or-filename>` answers \"did this tool delete this file\" by name, and root CLAUDE.md's triage step 1 now points at it instead of `orphan-gc log`.")
//! @yah:handoff("LEADER SIGN-OFF (R605, session:d990eccb). THE FORK IS RESOLVED AND IMPLEMENTED: MOUNTED, as a second READ-ONLY drive. The ticket framed bake-vs-mount as 'a genuine fork with no obvious default'; it was a false dichotomy resting on a hidden assumption that mounted implies mutable. The correctness property the read-only rootfs exists to protect (microvm.rs:583-587 — one rootfs serves every job, so job N must not leave state for job N+1) is about JOB-WRITABLE state. A drive attached is_read_only:true is exactly as safe as a baked layer while keeping the update path at 'replace one file on the node'. I made this call as leader rather than escalating it, because it is an engineering tradeoff with no product content.")
//! @yah:handoff("THE MEASUREMENT VINDICATES IT BY AN ORDER OF MAGNITUDE, and this is the single most useful number this ticket produced: THE TOOLCHAIN IS 1166 MB. The ticket estimated '~75MB image rebuild' and used that figure to argue baking was affordable — it was wrong by 15x. Baking would have taken the artifact redistributed to every build node on every busybox or kernel change from 30 MB to 1.2 GB. Any future argument to bake has to start by beating that number.")
//! @yah:handoff("SURPRISE 1, AND IT IS THE REAL ENGINEERING CONTENT HERE: THE TOOLCHAIN CANNOT BE A PATH ENTRY. cargo and rustc are glibc-DYNAMIC and an ELF interpreter path is baked into the binary, not searched — so dropping a toolchain directory into a busybox-static rootfs with no libc and extending PATH does not work, no matter where the drive is mounted. It goes in as the guest overlay's SECOND LOWER LAYER (lowerdir=/:/toolchain), which puts everything at its natural absolute path. Attaching the third drive was easy; REACHING it was the problem, and that is the part a future reader will otherwise re-derive.")
//! @yah:handoff("SURPRISE 2 — THE WRITABLE-SCRATCH PROBLEM I FLAGGED AS A BLOCKER WAS TWO-THIRDS ALREADY SOLVED. The guest root has been an overlay with a tmpfs upper since R605-F14, and a job's source tree is already bind-mounted from the scratch disk, so target/ was already on disk. The actual hole was narrower than I thought: CARGO_HOME and TMPDIR defaulted into guest RAM. Both now default onto the per-job scratch disk. CARGO_TARGET_DIR was deliberately LEFT ALONE — setting it would move artifacts out from under any forge step that collects target/release/…, which is a real regression hiding behind an apparently tidy change.")
//! @yah:handoff("SCOPE EXTENDED ON PURPOSE, and it retires a conditional in this ticket's own verify: the criterion said 'this ticket also depends on guest egress (R605-F22) IF the build resolves any crates.io dependency'. That clause is now CLOSED rather than left asserted — a guest ran a real `cargo fetch` (not --offline) against crates.io through DNS, TLS and cert verification against a 3697-line trust store, then compiled against what it downloaded. R605-F22 had proven egress only at the TCP-connect layer and explicitly flagged the full-fetch leg as unproven; it is now proven.")
//! @yah:handoff("DISCOVERED WORK DONE OUTSIDE THIS TICKET, reported rather than hidden. (1) A manifest defect the console exposed: `dpkg-deb --show` reads only its FIRST argument, so the toolchain manifest recorded ONE Debian package instead of 64. Fixed; all 64 now recorded. (2) An orphan-gc failure was hit and, per CLAUDE.md's standing instruction, the evidence was PRESERVED rather than cleaned — @Ashguard:libra was live on R770 debugging exactly that attribution problem, root-caused it from the preserved state (root-owned lock files in ~/.cargo/orphan-gc/, NOT in target/), and the repair was applied and re-verified through the normal wrapper chain with no bypass. The occurrence is recorded on R770.")
//! @yah:verify("ON REAL HARDWARE (us-west-003), against named baselines: microvm_guest_e2e 2 -> 3 passing (the new test compiles and runs a real crate inside a guest); microvm_guest_net_e2e 1 -> 2 passing (the new test does a live cargo fetch from crates.io over TLS); kamaji lib 115/115; `cargo check --workspace` clean, no errors and no unused warnings across the kamaji workspace. All re-verified through the normal orphan-gc wrapper chain with NO bypass after the R770 repair — the bypass used mid-run to preserve evidence was not left in place.")
//! @yah:verify("THE GUEST-SIDE PROOF IS NOT A SMOKE TEST: cargo 1.98.0 + rustc 1.98.0 + cc (Debian 14.2.0-19) ran INSIDE the guest, 'Compiling guestbuild' -> 'Finished', with the resulting binary copied out to the host and executed, exit 0. The courier initially distrusted a 709ms runtime as too fast and made the test print the compiler's own output rather than accept the exit code — that is the right instinct and it is why this result is trustworthy.")
//! @yah:verify("PROVENANCE IS PINNED as required: sha256 sidecars for the image artifacts, logged at kamaji startup. The kamaji crate is deliberately dependency-free for this backend, so this went through a sidecar rather than by adding a sha2 dependency — worth knowing before anyone 'simplifies' it.")
//! @yah:verify("NOT SHIPPED, AND THIS GATES R605-T24. Code is committed at 88533e01f7f578b1520b633d05846973fa47f608, but the kamaji DEPLOYED on us-west-003 (0.8.38-h2) PREDATES it and still boots two-drive guests with no compiler. So a guest booted by the running service today still cannot build. Reaching production needs a paired yubaba+kamaji hotship from this tree — never kamaji alone, ProtocolVersion::CURRENT is V9 and a skewed pair fails every call at connect while still reporting active with NRestarts=0.")
//! @yah:verify("A PEER'S WIP-COMMIT SWEPT THESE CHANGES IN MID-TICKET. The courier verified its own work survived BY CONTENT rather than off `git status`, which is the correct move on this shared tree. Everything is in 88533e01 except the ~26 lines of board annotation, which the camp git plugin sweeps.")
//!
//! @yah:ticket(R605-F31, "Service-shaped VM archetype in kamaji: make long-lived VMs a first-class workload, not a job that happens not to exit")
//! @yah:status(review)
//! @yah:at(2026-09-11T01:19:04Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @yah:next("OPERATOR DECISION 2026-09-10 CREATED THIS TICKET and it is the gating item for R605-F16's whole track. Offered the smaller option — supervise dev-cluster VM members as host-level systemd units outside kamaji, zero kamaji change — the operator chose instead to make 'long-lived VM workload' a real product capability, consistent with the standing direction that 'our cloud is meant to do' metal+VM mixing. So this is an architecture change in oss/kamaji, funded on purpose.")
//! @yah:next("THE CORE OF IT: microvm.rs is job-shaped BY DESIGN at four places, and each has to become archetype-dependent rather than constant. (1) The module heading at microvm.rs:15-22 states it outright — 'Shape: a job, not a service ... It deliberately does not implement the restart loop crate::native carries'; crate::native is the thing to read for how a restart loop already works here. (2) restart_workload at microvm.rs:1013-1018 bails unconditionally with 'Backend::MicroVm does not restart workload {}: it is job-shaped (LifecycleArchetype::Job, RestartPolicy::Never)'. (3) The rootfs is attached is_read_only: true at microvm.rs:583-587 for a REAL correctness reason — one rootfs image serves every job on the node, so a writable one lets job N leave state for job N+1. That property MUST survive for job-shaped VMs; it is relaxed only for service-shaped ones, so read-only-ness becomes a function of the archetype. Do NOT simply flip it. (4) Boot args at microvm.rs:568-569 carry panic=1 reboot=k so the guest EXITS and VMM process death is the completion signal — a service must not be reaped on reboot, so the completion-detection model changes too.")
//! @yah:next("START BY READING crate::native, not by writing code. It already carries the restart loop this ticket needs, and the module heading at microvm.rs:15-22 names it as the thing microvm deliberately does not do. The cheapest correct outcome is that the two backends share a supervision model rather than growing a second, subtly different one — this workspace is pre-1.0, so changing the shared abstraction beats adding a parallel path beside it.")
//! @yah:next("SCOPE BOUNDARY, because this ticket can eat the world: deliver the ARCHETYPE and the SUPERVISION, on x86_64 where a guest already boots and is proven end to end (R605-F14, R605-F22). The arm64 guest image is a SEPARATE ticket and a separate piece of work. Proving the archetype on the arch that already works is the cheap way to de-risk it; doing both at once means a failure has two possible causes.")
//! @yah:next("Tier: Wizard — this is a design change to a supervision model with a live correctness property (job N must not leave state for job N+1) that a careless edit silently destroys, and the read-only rootfs is the only thing currently enforcing it.")
//! @yah:gotcha("NOTHING GATES THE microVM BACKEND BY ARCH, which becomes a live hazard the moment this work reaches arm64. `rg target_arch oss/kamaji/crates/` returns NOTHING — there is no cfg(target_arch) anywhere in the crate. So a kamaji built with --features microvm on an aarch64 node attaches the backend and hands firecracker an x86 cmdline: microvm.rs:568-569 hardcodes `console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux`, where i8042.* names an x86 controller and reboot=k is the i8042 keyboard reset, pinned by test at microvm.rs:1919-1926. INFERRED and needing measurement: aarch64 firecracker resets via PSCI, so reboot=k is likely wrong there. Measured 2026-09-10 by R605-F16's triage.")
//! @yah:gotcha("THE ONLY NODE WHERE ANY OF THIS CAN BE TESTED IS us-west-003, AND IT HAS A LANDMINE. It runs tree build 0.8.38-h2 with /etc/systemd/system/kamaji.service.d/10-microvm.conf setting KAMAJI_MICROVM_DIR. NO PUBLISHED kamaji carries the microvm feature, and that env var on a feature-off binary is FATAL AT STARTUP (kamaji-bin/src/main.rs:827 bails before the socket binds); Restart=on-failure + StartLimitBurst=5 then gives up in 60s, leaving the node with no workload supervisor. So: do NOT run scripts/roll-node.sh against it, and NEVER ship kamaji without yubaba from the same tree — ProtocolVersion::CURRENT is V9 and a skewed pair fails every call at connect with HandshakeRefused while still reporting active with NRestarts=0. Use scripts/hotship.sh --binaries yubaba,kamaji.")
//! @yah:gotcha("THE NODE'S CHECKOUT IS NOT THE CAMP'S TREE and syncing it fails misleadingly. ~/yah on us-west-003 was stale at 8675e1a0; verify it carries the symbols you are testing before trusting any result. Syncing oss/kamaji ALONE fails with an unpublished `yah-workload-spec 0.8.37` error naming a crate you never touched — the cause is the root [patch.crates-io] redirect to ../yah-base, whose copy on the node is stale, so sync oss/yah-base TOO. The node has NO rsync; use tar over ssh, and do not copy target/ (2.1G vs ~1.8M of crates). Also: ssh needs `-i ~/.ssh/yah -o IdentitiesOnly=yes` or it fails 'Permission denied (publickey)' in a way that reads as the box being down, and journalctl as the unprivileged user returns EMPTY rather than an error — use sudo or you will conclude a working thing is broken.")
//! @yah:gotcha("A LIVE PEER APPENDED TO THE kamaji-proto ENUMS WHILE THIS TICKET WAS IN FLIGHT, 2026-09-10 — @Ashguard:dove (session:1e4618c6) working R870-B24. This is a seam, not a break; their kamaji workspace was green when they ran it (cargo test --workspace all pass, kamaji-bin lib 244). WHAT LANDED: kamaji-proto/src/messages.rs gained `YubabaToKamaji::Describe { request_id, id }` and `KamajiToYubaba::WorkloadDescription { request_id, id, spec: Option<Workload> }`, both appended LAST, with WorkloadDescription classified as a correlated reply in reply_request_id(); NO ProtocolVersion bump, so V9 stays R605-T27's, because appending a variant keeps postcard indices stable. kamaji-bin/src/server.rs: `Registry.digests` became `Registry.specs: HashMap<WorkloadId, DeployedSpec>` (the whole Workload plus its precomputed digest), and `set_spec_digest`/`remove_spec_digest` became `set_deployed_spec`/`remove_deployed_spec`/`deployed_spec`; stamp_spec_digests is behaviourally unchanged. kamaji/src/sibling.rs gained `KamajiClient::describe(&id)`. EXPLICITLY UNTOUCHED BY THEM and therefore safe for this ticket: microvm.rs, kamaji/src/lib.rs, native.rs, supervise.rs, kamaji-bin/src/main.rs. THREE CONSEQUENCES. (1) If the archetype work appends to either enum, RE-READ THE ENUM AT EDIT TIME and append after theirs — two independent \"appended last\" edits shift postcard indices against each other, and the resulting skew fails every yubaba->kamaji call at connect with HandshakeRefused while systemctl still reports active with NRestarts=0, i.e. it does NOT look like a restart loop. (2) Any new reply variant MUST be classified in reply_request_id() or it is SILENTLY dropped as a push (R746-B11). (3) Think hard before bumping ProtocolVersion: V9 is what us-west-003 runs as 0.8.38-h2 and that is the only node this can be tested on, so a bump forces a paired yubaba+kamaji re-ship (scripts/hotship.sh --binaries yubaba,kamaji, never kamaji alone) before anything works there.")
//! @yah:handoff("DONE AND PROVEN ON REAL HARDWARE (us-west-003, firecracker v1.16.1, guest kernel 6.1.187, 2026-09-11T01:15-01:30Z). All four job-shaped sites are now archetype-dependent, driven by ONE value: VmShape::of_spec(spec), which reads WorkloadSpec::effective_archetype() — Job stays job-shaped, Server/Appliance are service-shaped. Nothing is a flag, an Option param or a fallback.")
//! @yah:handoff("THE SUPERVISION IS SHARED, NOT DUPLICATED — this was the brief's cheapest-correct-outcome and it is what landed. New oss/kamaji/crates/kamaji/src/supervise.rs holds the restart-loop state machine that used to live inside native.rs (Ctrl<I>, park, supervise, backoff_delay, now_ms, ALWAYS_RESTART_DELAY), lifted verbatim and made generic over a `Supervised` trait with five members: start / wait / stop / settle / discard. native.rs lost 299 lines and gained a 65-line `NativeProcess` impl; microvm.rs gained a `GuestBoot` impl. The policy decision, the exponential backoff, the Restarting publication, the parked phase and the control-message handling are now identical between the two backends BY CONSTRUCTION rather than by inspection. native's own suite (always_policy_respawns_after_exit, on_failure_gives_up_after_max_attempts, restart_workload_replaces_running_process, graceful_upgrade_swaps_process_and_signals_old, ...) passes unchanged, which is the evidence the lift preserved behaviour.")
//! @yah:handoff("SITE 3 (the read-only rootfs) WAS NOT FLIPPED, AND THAT IS THE SUBSTANCE. Flipping is_read_only for services would not relax the property for services — it would DESTROY it for everyone, since the same file is what a job on the same node boots half a second later, and two service guests would be two concurrent writers to one ext4 image. So a service gets a DIFFERENT image: new `RootDisk` type, `RootDisk::for_shape` returns the node's shared rootfs.ext4 read-only for a Job and <vm_dir>/rootfs.ext4 writable for a Service, and `RootDisk::provision` seeds that private copy from the node image on first deploy and DELIBERATELY KEEPS an existing one on redeploy (a service's root belongs to the workload, and re-copying the pristine image would erase it). 30 MB per service — R605-F23's measurement, with the 1166 MB toolchain still in its own read-only volume. Pinned from both sides: the_rootfs_is_read_only_and_the_workspace_is_not now also asserts the job's root path IS the node image, and a_service_gets_its_own_root_and_never_writes_the_nodes asserts the service's is NOT.")
//! @yah:handoff("SITE 4 (panic=1 reboot=k): THE ARGS ARE DELIBERATELY IDENTICAL FOR BOTH SHAPES AND THE COMPLETION MODEL IS WHAT CHANGED — read this before \"fixing\" the absence. What the pair buys is that the host always finds out the guest is gone; what differs is the interpretation, and that now lives in GuestBoot::settle. A job's VMM exit is the job finishing (extract artifacts, free the TAP, read the guest's verdict, park). A service's VMM exit is one INSTANCE ending: no extraction (a service is not a producer and reading the disk would race the next boot for the block device), no TAP teardown (the next boot needs the same device on the same /30; teardown frees it), and the RestartPolicy decides what follows. Removing panic=1 for services would buy exactly one thing: a panicked service guest that hangs forever reporting Running. Pinned by a_service_boots_with_the_same_args_because_only_the_reading_changes.")
//! @yah:handoff("TWO THINGS FOUND AND FIXED IN THIS PASS THAT THE BRIEF DID NOT NAME. (1) teardown_workload signalled the VMM pid directly and polled a shared AtomicU32; with a restart loop in play that RACES the supervisor, which would see the exit, consult the policy and boot a replacement nobody held a handle on. It now goes through Ctrl::Teardown like native's, so there is one owner of the process. (2) A service's guest boots repeatedly, so a stale job-status.json from a killed instance would be read as the next one's verdict — reporting a crashed service as cleanly Stopped, the exact class of lie JOB_STATUS_FILE exists to prevent. New workspace::clear_job_status runs `debugfs -w -R \"rm /job-status.json\"` before every re-boot (same -w route write_job already uses, no new dependency); a failure warns and degrades to a stale read rather than killing the workload. Also: deploy now REFUSES a job-shaped spec carrying a non-Never restart_policy, naming both fields, rather than silently demoting it — nothing the fleet dispatches hits this, since WorkloadSpec::for_forge already sets Never.")
//! @yah:gotcha("THE WRITABLE ROOT IS THE HOST HALF OF A PROPERTY WHOSE GUEST HALF IS NOT BUILT — do not read microvm.rs as claiming a service's / is durable, because it is not, and the doc comments were corrected mid-ticket to stop claiming it. MEASURED by reading oss/kamaji/crates/kamaji-guest-init/src/boot.rs:312-335: the init pivots UNCONDITIONALLY into an overlayfs with a TMPFS upper layer, so the writable block device this ticket attaches is the overlay's LOWER layer and the guest never writes to it. Confirmed live — the guest cmdline on us-west-003 reads `root=/dev/vda rw`, so the flag genuinely reaches the guest, and writes to / still vanish on reset. WHAT IS DURABLE FOR A SERVICE TODAY is the scratch disk at /workspace, which this backend now neither rebuilds nor extracts between restarts; that is proven (a_services_scratch_disk_survives_its_restarts). The guest half is filed as R605-F33 with the design (probe for a writable root, use a directory on it as upperdir, fall back to tmpfs on EROFS — no JOB_SCHEMA_VERSION bump) and with the reason it is separate: it means rebuilding and re-staging the rootfs image every other R605 proof was measured against, on the only testable node.")
//! @yah:gotcha("NO PROTOCOL CHANGE, NO kamaji-bin CHANGE, NO SYSTEMD SANDBOX CHANGE — all three were checked rather than assumed, and all three are the answer a future reader will want. (1) ProtocolVersion stays V9: the archetype already rides the WorkloadSpec on the wire and the shape is derived host-side in kamaji, so nothing was appended to YubabaToKamaji/KamajiToYubaba and us-west-003's 0.8.38-h2 pairing is untouched. (2) kamaji-bin routes by the yah.exec=microvm annotation and validate_microvm_spec does not gate on archetype, so a service-shaped microVM spec already reaches MicroVmRuntime — untested above kamaji, which is the honest limit. (3) R605-T24's ProtectSystem=strict trap does NOT recur: the only new host path written is <microvm-dir>/vms/<ident>/rootfs.ext4, and kamaji-bin/src/main.rs:795 sets state_dir = <microvm-dir>/vms with KAMAJI_MICROVM_DIR=/var/lib/yah/kamaji/microvm, already inside kamaji.service's ReadWritePaths AND StateDirectory (/var/lib/yah/kamaji). Verified by reading app/yah/cli/resources/kamaji.service:139,175.")
//! @yah:verify("PASS ON REAL HARDWARE AGAINST A NAMED BASELINE. BASELINE: before this ticket no microVM workload on this backend had ever been restarted — restart_workload bailed unconditionally and the supervisor had no loop — and R605-T24 recorded kamaji lib at 115 passed / 0 failed (--features microvm-integration). NOW: new oss/kamaji/crates/kamaji/tests/microvm_service_e2e.rs, 3 passed / 0 failed on us-west-003 in 14.57s (firecracker v1.16.1, guest kernel 6.1.187). a_service_guest_is_restarted_instead_of_reaped saw 3 DISTINCT VMM pids in 2.93s with Restarting published and visible through get_workload (the surface kamaji-bin uses), and the node's shared rootfs.ext4 was sha256-identical before and after. a_job_guest_is_still_reaped_and_never_restarted is the regression half — the job reports Stopped, STAYS Stopped across 8 polls over 4s (vs a 1s ALWAYS_RESTART_DELAY), and still refuses an explicit restart naming \"job-shaped\". a_services_scratch_disk_survives_its_restarts read the guest's appends back with debugfs after teardown and found one line per completed boot, which also proves clear_job_status's new `debugfs rm` does not damage the filesystem — a corrupted one would have failed the next guest's mount.")
//! @yah:verify("REGRESSION SUITES, ALL GREEN. On us-west-003: microvm_guest_e2e 3 passed / 0 failed — R605-F14's own proof, re-run to confirm the job path is untouched, and confirmed with --nocapture that they RAN rather than SKIPped (each prints its guest's finish time; the cargo-build one is fast because its target dir is warm, not because it skipped). kamaji lib on the node 120 passed / 0 failed. On the camp Mac: kamaji lib 120 passed / 0 failed with --features microvm-integration (= T24's 115 baseline + the 5 new unit tests), 139 passed / 0 failed with microvm+native, oss/kamaji `cargo test --workspace --all-features` 0 failed across every target (kamaji lib 222, kamaji-bin lib 315, docker_live 5), and `cargo check --workspace --all-targets` clean at the yah repo root, which consumes kamaji through the root [patch.crates-io] path. clippy adds NO new warning on either feature set (microvm-only is clean; the one remaining is pre-existing too_many_arguments on jit.rs:312, untouched).")
//! @yah:verify("WHAT WAS NOT DONE, stated plainly. (1) arm64 — out of scope by the brief; R605-F32 owns the guest image, and vmm_config's doc comment now names the x86-only cmdline tokens and points there. (2) The dispatch path ABOVE kamaji is unexercised for a service-shaped microVM spec: everything here drove MicroVmRuntime in-process on the node, exactly as F14/F22/F23 did. Nothing blocks it (no annotation or validation gates on archetype) but nobody has run a service-shaped VM through yubaba. (3) A service's / is not durable — R605-F33. (4) Nothing was shipped to the node's running kamaji: the tests build and run out of ~/yah on us-west-003 against a tempdir state_dir, the service is untouched, and no roll-node.sh or hotship was performed.")
//! @yah:handoff("LEADER SIGN-OFF (R605, session:d990eccb). DELIVERED, AND IT TOOK THE HARDER, CORRECT ROUTE AT THE ONE PLACE THE BRIEF LEFT ROOM TO CHEAT. All four job-shaped sites in microvm.rs are now archetype-dependent off a single value (VmShape::of_spec reading WorkloadSpec::effective_archetype) rather than four independent conditionals — which is what keeps them from drifting apart later.")
//! @yah:handoff("THE RESTART LOOP WAS LIFTED, NOT COPIED, which was the whole point of pointing the courier at crate::native first. microvm.rs:15-22 said the backend 'deliberately does not implement the restart loop crate::native carries'; the cheap answer was to give microvm its own copy. Instead the loop moved OUT of native.rs into a new shared oss/kamaji/crates/kamaji/src/supervise.rs, and both backends now implement a `Supervised` trait against it. That is the pre-1.0 instruction in CLAUDE.md applied correctly — change the shared abstraction rather than add a parallel path beside it — and it means the next backend that needs supervision inherits it instead of forking a third copy.")
//! @yah:handoff("SITE 3 WAS DELIBERATELY NOT FLIPPED, AND THIS IS THE BEST DECISION IN THE TICKET. The brief said read-only-ness should become a function of the archetype. The courier found a better answer: flipping is_read_only for service-shaped VMs would have made the node's ONE SHARED rootfs.ext4 writable, destroying the job guarantee for every OTHER workload on that node — the archetype of the workload being deployed cannot be allowed to weaken an invariant held by its neighbours. Instead a service boots a PRIVATE WRITABLE COPY of the node rootfs (new RootDisk type), so the shared image stays read-only and job N still cannot leave state for job N+1. Verified on hardware by sha256: the node rootfs is unchanged after a service ran. I flagged this site as the one a careless edit silently destroys; the courier found the subtler version of that same trap and routed around it.")
//! @yah:handoff("THE HONEST GAP, STATED RATHER THAN PAPERED OVER: THERE IS NO DURABLE SERVICE ROOT YET. kamaji-guest-init pivots UNCONDITIONALLY into an overlayfs with a tmpfs upper layer (boot.rs:312-335, read from source and confirmed live), so a writable root device does not survive a reset — the private RootDisk gives a service its own image, but the guest throws writes into RAM on top of it. The courier caught this MID-TICKET and corrected doc comments it had already written rather than letting them ship as a lie, which is the behaviour to reinforce. A service's durable channel today is the scratch disk. The guest half is filed as R605-F33 with its design and its cost. This matters for R605-F32: a raft member needs a durable --raft-dir, so F33 is on F32's critical path even though F32 does not name it.")
//! @yah:handoff("SHARED-TREE DISCIPLINE, unprompted and exactly right: the courier checked camp.roster for a live peer on microvm.rs BEFORE editing, and when staging it deliberately EXCLUDED sibling.rs because that file carries @Ashguard:dove's in-flight KamajiClient::describe from R870-B24. It also established that no proto change was needed at all — the archetype rides the existing WorkloadSpec and the shape is derived host-side — so the enum-append hazard I steered it about never materialised and ProtocolVersion stays V9. That is the outcome I asked for and it was reached by making the change unnecessary rather than by sequencing it carefully.")
//! @yah:verify("ON REAL HARDWARE (us-west-003, firecracker v1.16.1), against a baseline that is a genuine zero: BEFORE this ticket no microVM workload had ever been restarted — restart_workload bailed unconditionally and there was no supervisor at all. New tests/microvm_service_e2e.rs = 3 passed / 0 failed, showing THREE DISTINCT VMM PIDS with Restarting published, i.e. a real halt -> exit -> re-boot cycle observed on the console rather than inferred from a return code.")
//! @yah:verify("THE JOB PATH IS PROVEN UNREGRESSED ON THE SAME NODE, which is the thing that could have been silently broken: microvm_guest_e2e stays 3 passed / 0 failed and genuinely RAN rather than skipping, and the job path is confirmed still reaped and never restarted. The node's rootfs sha256 is unchanged after a service workload ran — that is the direct evidence the job guarantee survived.")
//! @yah:verify("UNIT AND WORKSPACE: kamaji lib 120 passed / 0 failed (baseline 115 from R605-T24, plus 5 new unit tests). oss/kamaji --workspace --all-features: 0 failures. The yah root workspace checks clean with no new clippy warning.")
//! @yah:verify("A SELF-CAUGHT TEST BUG worth recording, because it is the kind that produces a false negative: the courier's first service-e2e assertion failed and it correctly diagnosed its own off-by-one — the scratch disk DOES persist; the 3rd instance is torn down mid-run before it can write — rather than concluding the feature was broken.")
//! @yah:verify("NO PROTO, NO kamaji-bin, NO SYSTEMD SANDBOX CHANGE was needed and none was made. ProtocolVersion stays V9, so us-west-003's 0.8.38-h2 pairing is undisturbed and no re-ship is forced.")
//! @yah:verify("UNCOMMITTED BY CAMP POLICY (git policy is 'defer'), against tree anchor e896d28a. The courier left the exact staging command for the operator's sweep, scoped to this ticket's five files and deliberately excluding sibling.rs.")

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncBufReadExt;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::task::JoinHandle;
use workload_spec::{EnvValue, RestartPolicy, VolumeSource, WorkloadSpec};

use crate::supervise::{supervise, Completion, Ctrl, Exit, Supervised};
use crate::{
    Backend, DeployResult, Kamaji, LogEvent, LogOpts, LogStream, LogStreamKind, MeshAssignment,
    MeshIdent, RuntimeHealth, WorkloadState, WorkloadStatus,
};

/// Version of the [`MicroVmJob`] document written to the scratch disk.
///
/// The rootfs image and this file are separately deployed — a node can be
/// running a rootfs built months before the kamaji that boots it — so the guest
/// init is expected to refuse a `schema` it does not recognise rather than
/// guess. Bump on any incompatible change to the document.
pub const JOB_SCHEMA_VERSION: u32 = 1;

/// Filename of the job document at the root of the scratch disk.
pub const JOB_FILE: &str = "job.json";

/// Filename of the guest's *reply*, beside [`JOB_FILE`] on the scratch disk.
///
/// # Why the job's exit status needs a file of its own
///
/// Because the VMM's exit status cannot carry it, which was measured on
/// us-west-003 with firecracker v1.16.1 rather than assumed (R605-F14). A guest
/// ends by resetting the machine — that is what makes the VMM process exit, and
/// therefore the only completion signal this backend's supervisor has. But the
/// reset is the same event whether the job passed, the job failed, or the guest
/// kernel panicked: `panic=1` reboots too. Firecracker exits `0` in all three
/// cases.
///
/// So without this file every failed build on this backend would be reported as
/// `Stopped`, which is worse than reporting nothing — a build system whose green
/// means "the VM shut down" is a build system that cannot fail.
pub const JOB_STATUS_FILE: &str = "job-status.json";

/// Where the scratch disk is mounted inside the guest.
///
/// Fixed rather than configurable: it is half of a two-sided contract with the
/// rootfs's init, and a value only one side can change is not a contract.
pub const GUEST_WORKSPACE_MOUNT: &str = "/workspace";

/// Filename of the build-toolchain volume under the node's `--microvm-dir`.
///
/// Discovered by name rather than configured by a flag, exactly like `vmlinux`
/// and `rootfs.ext4`: a node either has staged a toolchain or it has not, and an
/// operator who has to remember a second flag to make the one they staged take
/// effect has a node that silently cannot build. Absent is a legitimate state —
/// see [`MicroVmConfig::toolchain_image`].
pub const TOOLCHAIN_IMAGE_FILE: &str = "toolchain.ext4";

/// Marker at the root of the toolchain volume, and the guest's proof that a
/// drive *is* the toolchain.
///
/// The guest init probes drives rather than trusting a device name, for the same
/// reason it probes for [`JOB_FILE`]: `/dev/vdc` is a consequence of the order
/// drives happen to be listed in, and a hardcoded device name is a silent
/// failure the moment that order changes. Written by
/// `oss/kamaji/guest/build-toolchain-image.sh`; carries the Rust version and the
/// exact Debian package versions the image was assembled from.
pub const TOOLCHAIN_MANIFEST_FILE: &str = "kamaji-toolchain.json";

/// Filename of the node's service root image inside the microVM directory,
/// beside `vmlinux`, `rootfs.ext4` and [`TOOLCHAIN_IMAGE_FILE`]. See
/// [`MicroVmConfig::service_rootfs_image`].
pub const SERVICE_ROOTFS_IMAGE_FILE: &str = "service-rootfs.ext4";

/// Grace period between asking the VMM to stop and killing it.
const TERM_GRACE: Duration = Duration::from_secs(10);

/// Slack added to the scratch disk over the size of its input tree, so a build
/// has somewhere to put its output. Builds are the workload this exists for and
/// they produce far more than they consume, hence the multiplier rather than a
/// flat addition.
const WORKSPACE_SIZE_MULTIPLIER: u64 = 4;

/// Floor on the scratch disk, for the common case of an empty input tree.
const WORKSPACE_MIN_BYTES: u64 = 8 * 1024 * 1024 * 1024;

// ── Workload shape ───────────────────────────────────────────────────────────

/// Which lifecycle shape this backend was asked to boot (R605-F31).
///
/// Deliberately a two-valued type over [`LifecycleArchetype`]'s three, because
/// every difference in this file is between "runs to completion" and "is meant
/// to still be there tomorrow", and `Server` vs `Appliance` — where the
/// scheduler *may* move it — is a question for the scheduler, not for the
/// hypervisor. Collapsing the two here means a future fourth archetype has to
/// be answered once, in [`Self::of_spec`], instead of at every site.
///
/// [`LifecycleArchetype`]: workload_spec::LifecycleArchetype
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmShape {
    /// Starts, does work, produces artifacts, exits. The VMM process ending is
    /// the completion signal, and there is nothing to restart.
    Job,
    /// Long-lived. The VMM process ending is an *instance* ending, and what
    /// happens next is the spec's [`RestartPolicy`](workload_spec::RestartPolicy)'s
    /// decision — which is the supervisor's job, not the dispatcher's.
    Service,
}

impl VmShape {
    /// Read the shape off the spec, through the one seam that answers "can I
    /// kill and reschedule this?" for every other consumer in the fleet.
    ///
    /// Going through [`WorkloadSpec::effective_archetype`] rather than reading
    /// `archetype` or `restart_policy` directly is what keeps a spec written
    /// before that field existed meaning here exactly what it means to the
    /// reconciler and the scheduler — including the forge convention, where
    /// `RestartPolicy::Never` with no volumes infers `Job`.
    pub fn of_spec(spec: &WorkloadSpec) -> Self {
        match spec.effective_archetype() {
            workload_spec::LifecycleArchetype::Job => Self::Job,
            workload_spec::LifecycleArchetype::Server
            | workload_spec::LifecycleArchetype::Appliance => Self::Service,
        }
    }
}

/// The root block device one guest boots, and whether it may write to it.
///
/// # Why a service does not simply get the rootfs flipped writable
///
/// Because the flag is not the property. `is_read_only: true` on the node's
/// `rootfs.ext4` exists because **one image serves every workload on the node**,
/// and a writable one lets workload N leave state for workload N+1. Flipping it
/// for service-shaped guests would not relax that property for services — it
/// would *destroy* it for everyone, since the very same file is what a job on
/// the same node boots half a second later, and two service guests would be two
/// concurrent writers to one ext4 image.
///
/// So a service gets its own image instead: a copy of the node's, in the
/// workload's own VM directory, attached writable. Nothing is shared, so there
/// is nothing to contaminate; the node's image is still never written by
/// anybody. The copy is cheap on the measurement that R605-F23 took on
/// us-west-003 — the rootfs is **30 MB**, with the 1166 MB of build toolchain
/// living in a separate, still-read-only volume.
///
/// # What this buys, and when it started buying it
///
/// **Writes to `/` inside the guest survive a reset — as of R605-F33**, and for
/// one boot-to-boot cycle only this host half existed. F31 landed the writable
/// attachment on its own because it is the half that has to be *right*: flipping
/// a shared image writable is the edit that silently destroys the job guarantee,
/// and this is the shape that cannot. For that day it bought nothing observable,
/// because `kamaji-guest-init` pivoted unconditionally into an overlayfs with a
/// tmpfs upper, so the device attached here was the overlay's *lower* layer.
///
/// F33 is the guest half: the init probes for a writable root (a read-write
/// remount of `/`, which a job's read-only attachment refuses by construction)
/// and, when it finds one, keeps the real device as the root instead of stacking
/// an overlay on it. No job-document field changed and `JOB_SCHEMA_VERSION` did
/// not move, so no rootfs image can skew against a kamaji binary — but a rootfs
/// image *older* than F33 gives a service an ephemeral `/` again, silently.
/// `a_services_root_survives_its_restarts` is what catches that.
///
/// The **scratch disk** at [`GUEST_WORKSPACE_MOUNT`] is still durable and still
/// the right place for bulk state: this backend neither rebuilds nor extracts it
/// between a service's restarts, and it is sized for a build where the root is
/// sized for a root.
///
/// # Which image a service's root starts as (R605-F32)
///
/// [`MicroVmConfig::service_rootfs_image`], never the job image. F31 seeded
/// from the job image because the job image was the only one a node had; the
/// shape now picks the *source* exactly as it already picked the attachment,
/// so a node can boot builds in a minimal image and members in a full one.
#[derive(Debug, Clone)]
pub struct RootDisk {
    /// Image the guest boots as `/dev/vda`.
    pub path: PathBuf,
    /// Whether Firecracker attaches it read-only.
    pub read_only: bool,
    /// The node image [`Self::path`] is first copied from, for a service; `None`
    /// for a job, which boots the node image in place.
    pub seed: Option<PathBuf>,
}

impl RootDisk {
    /// Filename of a service's private root, inside its own VM directory.
    ///
    /// The same basename as the node's image on purpose: an operator staring at
    /// a VM dir should be able to see that the thing next to `workspace.ext4`
    /// and `vm-config.json` is a root filesystem, and the directory it is in is
    /// already what distinguishes it.
    pub const SERVICE_ROOT_FILE: &'static str = "rootfs.ext4";

    /// Which root image `shape` boots, given the node's config and the
    /// workload's own state directory.
    ///
    /// Fails for a service on a node that stages no service image — see
    /// [`MicroVmConfig::service_rootfs_image`] for why that is a refusal and
    /// not a fall back to the job image.
    pub fn for_shape(cfg: &MicroVmConfig, shape: VmShape, vm_dir: &Path) -> Result<Self> {
        Ok(match shape {
            VmShape::Job => Self {
                path: cfg.rootfs_image.clone(),
                read_only: true,
                seed: None,
            },
            VmShape::Service => {
                let seed = cfg.service_rootfs_image.clone().ok_or_else(|| {
                    anyhow!(
                        "this node stages no service root image, so it cannot boot a \
                         service-shaped (server/appliance) microVM — stage one as \
                         <microvm-dir>/{SERVICE_ROOTFS_IMAGE_FILE} (oss/kamaji/guest/\
                         build-guest-image.sh --only service-rootfs)"
                    )
                })?;
                Self {
                    path: vm_dir.join(Self::SERVICE_ROOT_FILE),
                    read_only: false,
                    seed: Some(seed),
                }
            }
        })
    }

    /// Put the bytes where [`Self::path`] says they are.
    ///
    /// A no-op for a job (the node's image is already there) and for a service
    /// that has one — and that second case is the load-bearing one. A redeploy
    /// of the same identity onto the same node **keeps** the existing root,
    /// because for a service-shaped guest the root is state that belongs to the
    /// workload, and re-copying the pristine node image over it would silently
    /// erase whatever the appliance had accumulated. That is the same promise
    /// `LifecycleArchetype::Appliance` already makes everywhere else in the
    /// fleet: stable identity, and a volume that follows it.
    pub async fn provision(&self) -> Result<()> {
        let Some(seed) = &self.seed else {
            return Ok(());
        };
        if tokio::fs::try_exists(&self.path).await.unwrap_or(false) {
            tracing::info!(
                root = %self.path.display(),
                "reusing this service guest's existing root — its state is its root"
            );
            return Ok(());
        }
        tokio::fs::copy(seed, &self.path).await.with_context(|| {
            format!(
                "seeding a private root for a service-shaped guest: copying {} to {}",
                seed.display(),
                self.path.display()
            )
        })?;
        tracing::info!(
            from = %seed.display(),
            root = %self.path.display(),
            "seeded a service guest's private writable root from the node's service image"
        );
        Ok(())
    }
}

// ── Node configuration ───────────────────────────────────────────────────────

/// Everything about a microVM that belongs to the **node** rather than to the
/// workload.
///
/// The split is the same one the containerd backend draws between "which
/// registry am I" and "which image did you ask for": a workload asks for
/// isolation, and the node answers with the kernel, rootfs and network it has.
/// A spec cannot name a kernel — that would let a dispatched workload choose
/// the code its own supervisor boots.
#[derive(Debug, Clone)]
pub struct MicroVmConfig {
    /// Path to the `firecracker` binary.
    pub vmm_bin: PathBuf,
    /// Uncompressed guest kernel, always named `vmlinux` on disk. On x86_64
    /// that is the ELF vmlinux (not a `bzImage`); on aarch64 it is the arm64
    /// boot `Image`, which is what Firecracker loads there (R605-F32).
    pub kernel_image: PathBuf,
    /// The **job** root filesystem image, attached **read-only** and shared
    /// by every job-shaped guest on the node.
    pub rootfs_image: PathBuf,
    /// The image a **service-shaped** guest's private root is seeded from
    /// (R605-F32), or `None` on a node that stages none.
    ///
    /// A separate image rather than the job one, because the two shapes want
    /// different operating systems: a job wants the minimal image whose init
    /// IS the job runner, and a long-lived guest that hosts a cluster member
    /// wants a real init, so the node provisioning path a metal box runs
    /// (systemd units, apt, sshd) runs inside it unchanged. A node that stages
    /// none **refuses** service-shaped deploys rather than seeding them from
    /// [`Self::rootfs_image`]: that fallback would quietly boot a member in an
    /// image that cannot host one. A node that wants busybox services can
    /// stage the job image here too, which is a configuration, not a fallback.
    pub service_rootfs_image: Option<PathBuf>,
    /// Build-toolchain volume, attached **read-only** as a second data drive, or
    /// `None` on a node that has not staged one.
    ///
    /// # Why this is a drive and not a layer in [`Self::rootfs_image`]
    ///
    /// R605-F23 framed the choice as "bake it into the read-only image" vs
    /// "mount a volume", and treated mounted as implying mutable — which is what
    /// made the fork look genuine, since the read-only rootfs exists to stop job
    /// N leaving state for job N+1. But that property is about *job-writable*
    /// state, and a drive attached `is_read_only: true` has none: the guest
    /// cannot write to this image any more than it can write to the rootfs.
    ///
    /// What separating them buys is the update path, and the measurement is what
    /// settles it rather than the argument. MEASURED on us-west-003, 2026-09-10:
    /// the rootfs is **30 MB**, and a usable Rust + C build environment is
    /// **1166 MB** (1003 MiB of content — rustc, cargo, std for gnu and musl,
    /// gcc, binutils, glibc headers and a trust store; a default rustup profile
    /// alone is 1.8 GB, of which 900 MB is documentation no guest will read).
    ///
    /// R605-F23 priced baking it in at "a ~75MB image rebuild". The real number
    /// is fifteen times that, and it is the strongest evidence for the call:
    /// baking would grow the artifact redistributed on every busybox, kernel or
    /// init change from 30 MB to 1.2 GB, and couple the cadence of a Rust
    /// release to that of a kernel CVE. Two independently versioned,
    /// independently hashed files is the cheaper shape by a wide margin.
    ///
    /// `None` is legitimate and is the pre-F23 state: the guest still boots,
    /// still mounts, still runs argv — it just has no compiler, which is exactly
    /// what the minimal busybox rootfs already meant.
    pub toolchain_image: Option<PathBuf>,
    /// Per-workload scratch: VM configs, scratch disks, captured console.
    pub state_dir: PathBuf,
    /// Guest networking, or `None` for an air-gapped guest.
    ///
    /// `None` is a legitimate configuration (an untrusted job that must not
    /// reach the network) but it is *not* the useful one for builds: a cargo
    /// build needs crates.io, which is why W325 flags the host-network
    /// annotation the container path already needs.
    pub network: Option<GuestNetwork>,
    /// Hard ceiling on guest RAM, in MiB. See [`guest_memory_mb`] — this is the
    /// number that keeps a 32 GiB *ceiling* in a spec from being read as a
    /// 32 GiB *allocation* on an 11 GiB node.
    pub max_guest_memory_mb: u32,
    /// Hard ceiling on guest vCPUs.
    pub max_guest_vcpus: u32,
}

/// Host-side networking for guests on this node.
#[derive(Debug, Clone)]
pub struct GuestNetwork {
    /// Host uplink to NAT guest traffic out of (e.g. `eth0`).
    pub uplink: String,
    /// Base of the guest address space. Each slot takes a `/30` from here, so
    /// this should be a private range no fleet route uses — the default
    /// `172.30.0.0` was picked to sit clear of both the LAN (`192.168.*`) and
    /// the tailnet (`100.64.0.0/10`).
    pub subnet_base: Ipv4Addr,
    /// Prefix for TAP device names. Kept short: Linux caps interface names at
    /// 15 characters and the slot index is appended.
    pub tap_prefix: String,
    /// Resolver handed to the guest via its job document.
    pub dns: Ipv4Addr,
}

impl GuestNetwork {
    /// The node's guest networking, NAT'd out of `uplink`.
    ///
    /// There is deliberately no `Default`. This type used to have one, and its
    /// `uplink` was the literal `"eth0"` — a name that has not been a Debian
    /// interface name since predictable naming landed, and which the node this
    /// backend was written for does not have. Nothing caught it because guest
    /// networking had never run (R605-F22): a MASQUERADE rule naming an
    /// interface that does not exist fails, `create_tap` fails with it, and the
    /// resulting "iptables MASQUERADE failed" reads as a permissions problem on
    /// a path where permissions are genuinely the usual suspect. A default that
    /// is right on no real node is worse than no default, so it is gone and
    /// callers say which uplink they mean — or ask [`Self::discover`].
    pub fn for_uplink(uplink: impl Into<String>) -> Self {
        Self {
            uplink: uplink.into(),
            subnet_base: Ipv4Addr::new(172, 30, 0, 0),
            tap_prefix: "yahvm".into(),
            dns: Ipv4Addr::new(1, 1, 1, 1),
        }
    }

    /// The node's guest networking, with the uplink taken from the host's own
    /// IPv4 default route.
    ///
    /// This is what a node should use: the interface guest traffic will actually
    /// leave by is a property of the host's routing table, not something a
    /// build-runtime should be guessing from a naming convention.
    ///
    /// It also refuses when `iptables` is not installed, because guest NAT is
    /// still a shell-out to it (the TAP itself is not — see
    /// [`net::create_tap`]). Without that check, a node missing it attaches the
    /// backend, advertises guest networking, and fails every networked deploy;
    /// with it, the node starts with guests air-gapped and its startup log
    /// names the missing binary.
    pub fn discover() -> Result<Self> {
        let uplink = net::default_route_uplink()?;
        net::find_on_path("iptables")?;
        Ok(Self::for_uplink(uplink))
    }
}

// ── Guest addressing ─────────────────────────────────────────────────────────

/// The host-side network identity of one concurrently-running guest.
///
/// One `/30` per slot: `.0` network, `.1` host end of the TAP, `.2` guest,
/// `.3` broadcast. A `/30` per guest rather than one shared bridge because
/// guests on a build node have no business talking to each other — the point of
/// this backend is that a build is isolated, and two builds sharing a broadcast
/// domain would undo a meaningful part of that for no gain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestSlot {
    pub index: u32,
    pub tap: String,
    pub host_ip: Ipv4Addr,
    pub guest_ip: Ipv4Addr,
    pub mac: String,
}

impl GuestSlot {
    /// Derive slot `index`'s addressing from the node's [`GuestNetwork`].
    ///
    /// Pure arithmetic on purpose: this is the function whose being wrong would
    /// show up as two concurrent builds mysteriously interfering, which is the
    /// hardest possible failure to attribute after the fact.
    pub fn derive(net: &GuestNetwork, index: u32) -> Result<Self> {
        // 64 /30s = 256 addresses = the last two octets of the base must be
        // zero for the arithmetic below to stay inside a /24 per 64 slots.
        let base = u32::from(net.subnet_base);
        let offset = index
            .checked_mul(4)
            .ok_or_else(|| anyhow!("microVM slot index {index} overflows the guest subnet"))?;
        let network = base
            .checked_add(offset)
            .ok_or_else(|| anyhow!("microVM slot index {index} overflows the guest subnet"))?;
        let host_ip = Ipv4Addr::from(network + 1);
        let guest_ip = Ipv4Addr::from(network + 2);

        let tap = format!("{}{index}", net.tap_prefix);
        if tap.len() > 15 {
            bail!(
                "TAP name {tap:?} exceeds the 15-character kernel limit — shorten \
                 GuestNetwork::tap_prefix (currently {:?})",
                net.tap_prefix
            );
        }

        Ok(Self {
            index,
            tap,
            host_ip,
            guest_ip,
            mac: mac_for(guest_ip),
        })
    }

    /// Kernel command-line fragment configuring the guest's interface at boot.
    ///
    /// Static configuration through `ip=` rather than DHCP in the guest: a
    /// build image that has to run a DHCP client before it can do anything is a
    /// build image with one more thing that can hang, and the address is
    /// already known to both sides here.
    pub fn kernel_ip_arg(&self) -> String {
        format!(
            "ip={}::{}:255.255.255.252::eth0:off",
            self.guest_ip, self.host_ip
        )
    }
}

/// A locally-administered MAC derived from the guest's address.
///
/// Deterministic so a slot's MAC is stable across reboots of the same job, and
/// derived from the IP so a packet capture on the host can be read without a
/// lookup table. `06:` is the locally-administered unicast prefix.
fn mac_for(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("06:00:{:02x}:{:02x}:{:02x}:{:02x}", o[0], o[1], o[2], o[3])
}

// ── The guest contract ───────────────────────────────────────────────────────

/// What kamaji tells the guest to do — written as `/job.json` on the scratch
/// disk, read by the rootfs's init.
///
/// This is a **cross-artifact contract**, which is why it is a declared struct
/// with a schema version rather than a few kernel-cmdline arguments. The
/// cmdline route is tempting (Firecracker passes `boot_args` straight through)
/// and wrong: it is length-limited, it cannot express a map, and every value on
/// it is world-readable inside the guest via `/proc/cmdline` — which for a
/// forge run means the resolved secrets in `env`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroVmJob {
    /// Always [`JOB_SCHEMA_VERSION`]; the guest refuses what it does not know.
    pub schema: u32,
    /// Workload identity, for the guest's own logging.
    pub workload: String,
    /// Argv, resolved from `entrypoint` + `command` with container semantics.
    pub argv: Vec<String>,
    /// Environment. `BTreeMap` so the document is byte-stable for a given spec,
    /// which is what makes the fixture test below meaningful.
    pub env: BTreeMap<String, String>,
    /// Working directory inside the guest.
    pub workdir: Option<String>,
    /// Where the scratch disk is mounted; always [`GUEST_WORKSPACE_MOUNT`].
    pub workspace_mount: String,
    /// Guest resolver, when the node gave this guest a network.
    pub dns: Option<Ipv4Addr>,
    /// What the guest must bind-mount where, so the spec's declared volume
    /// targets appear at the paths the step was written against.
    pub mounts: Vec<GuestMount>,
}

/// One volume, as the guest sees it.
///
/// The guest init bind-mounts `<workspace_mount>/<slug>` onto `target`. That
/// indirection is what makes a microVM run the *same* spec a container run
/// would: a forge step writes to `/yah/produced` either way and does not have
/// to know which substrate it landed on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMount {
    /// Directory on the scratch disk, relative to [`GUEST_WORKSPACE_MOUNT`].
    pub slug: String,
    /// Absolute path in the guest the step expects to find it at.
    pub target: String,
    pub read_only: bool,
}

/// The guest's report on the job it was booted to run — the return leg of the
/// contract [`MicroVmJob`] opens.
///
/// Written by the guest init to [`JOB_STATUS_FILE`] on the scratch disk after the
/// job's process is reaped and before the VM resets. Deserialized here, so like
/// [`MicroVmJob`] the shape is the contract and unknown fields are tolerated: the
/// init records its own version in the document, and a newer image adding a field
/// must not make its jobs unreportable on an older kamaji.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobStatus {
    /// Always [`JOB_SCHEMA_VERSION`], for the same reason the job document
    /// carries one — the two artifacts ship independently.
    pub schema: u32,
    /// Echoed from the job document, so a status file cannot be silently
    /// attributed to the wrong workload.
    pub workload: String,
    /// The job process's own exit code, or `128 + signal` if it was killed.
    pub exit_code: i32,
    /// One line of human-readable detail, for the supervisor's failure reason.
    #[serde(default)]
    pub detail: String,
}

impl MicroVmJob {
    /// Build the job document for `spec`.
    ///
    /// Refuses unresolved `env` for the same reason
    /// `validate_native_exec_spec` does: this backend can only write literals
    /// into the document, and a silently-absent credential fails the build
    /// somewhere far from its cause.
    ///
    /// NO DEPLOY-TIME INJECTION HAPPENS HERE, and that is a property of the
    /// backend rather than an omission (R893-B17 re-checked it). This shape
    /// carries only the spec's literals: no `YAH_MESH_IP`, no
    /// `PORT` / `PORT_<NAME>`, and no `YAH_SERVICE_IDENT` /
    /// `YAH_SCRYER_SOCKET`. A guest has its own kernel and no view of the
    /// host's filesystem, so there is no path and no bind that could make a
    /// host `AF_UNIX` socket reachable from inside it — reaching a microVM
    /// workload's telemetry needs a network-addressed collector, which is a
    /// different contract. (Note for anyone reading R893-S10's spike or the
    /// `@yah:next` on `scryer::ingestion`: both say kamaji injects the
    /// mesh-IP/port contract on "native, docker, containerd and microvm". The
    /// first three are true; this one was not, and is not.)
    pub fn of_spec(
        spec: &WorkloadSpec,
        plan: &[workspace::PlannedMount],
        dns: Option<Ipv4Addr>,
    ) -> Result<Self> {
        let mut argv: Vec<String> = Vec::new();
        if let Some(entry) = &spec.entrypoint {
            argv.extend(entry.iter().cloned());
        }
        if let Some(cmd) = &spec.command {
            argv.extend(cmd.iter().cloned());
        }
        if argv.is_empty() {
            bail!(
                "workload {}: Backend::MicroVm needs `entrypoint` and/or `command` to name the \
                 guest binary (image is identity metadata only — nothing is pulled)",
                spec.name
            );
        }

        let mut env = BTreeMap::new();
        for var in &spec.env {
            match &var.value {
                EnvValue::Literal { value } => {
                    env.insert(var.name.clone(), value.clone());
                }
                EnvValue::FromSecret { secret, .. } => bail!(
                    "workload {}: env {} carries an unresolved FromSecret({secret}) — yubaba \
                     must resolve before Deploy; the guest would run without it",
                    spec.name,
                    var.name
                ),
                EnvValue::FromMesh { ident, .. } => bail!(
                    "workload {}: env {} carries an unresolved FromMesh({}) — yubaba must \
                     resolve before Deploy; the guest would run without it",
                    spec.name,
                    var.name,
                    ident.0
                ),
            }
        }

        Ok(Self {
            schema: JOB_SCHEMA_VERSION,
            workload: spec.name.clone(),
            argv,
            env,
            workdir: spec
                .workdir
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            workspace_mount: GUEST_WORKSPACE_MOUNT.to_string(),
            dns,
            mounts: plan
                .iter()
                .map(|m| GuestMount {
                    slug: m.slug.clone(),
                    target: m.target.to_string_lossy().into_owned(),
                    read_only: m.read_only,
                })
                .collect(),
        })
    }
}

// ── Firecracker configuration document ───────────────────────────────────────

/// The `--config-file` document handed to Firecracker.
///
/// Firecracker can be driven two ways: this file, or an HTTP API over a unix
/// socket. The file is chosen because it makes the whole VM definition one
/// auditable artifact on disk next to the job's logs — an operator debugging a
/// failed build can read exactly what was booted — and because the API route
/// would mean carrying an HTTP client to configure a machine that never changes
/// after boot.
///
/// Field names are Firecracker's, hence the `rename`s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmmConfig {
    #[serde(rename = "boot-source")]
    pub boot_source: BootSource,
    pub drives: Vec<Drive>,
    #[serde(rename = "machine-config")]
    pub machine_config: MachineConfig,
    #[serde(rename = "network-interfaces", skip_serializing_if = "Vec::is_empty")]
    pub network_interfaces: Vec<NetworkInterface>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MachineConfig {
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub iface_id: String,
    pub host_dev_name: String,
    pub guest_mac: String,
}

/// The CPU architecture of a guest, which is always the host's (R605-F32).
///
/// Not a node setting and not a spec field: KVM runs guests of the host's own
/// arch only, so the kamaji binary's compile target IS the guest's arch, and
/// [`Self::host`] reads it off `cfg!(target_arch)`. It is a value rather than a
/// pair of `#[cfg]`'d constants so that both command lines stay testable on
/// whichever arch the tests happen to run on — the x86 set is pinned on the
/// arm64 camp Mac, and the arm64 set on an x86 CI box.
///
/// # What differs, and how it was decided
///
/// Only the platform-reset half of the command line. `console=ttyS0` and
/// `panic=1` are shared: Firecracker exposes a 16550A UART as the first serial
/// port on both arches (through the device tree on arm64, which is why the
/// guest kernel needs `CONFIG_SERIAL_OF_PLATFORM` there), and `panic=1` is the
/// half of the completion contract [`vmm_config`] explains — a panicked guest
/// must reset rather than hang reporting `Running`.
///
/// The x86 set's `reboot=k i8042.noaux i8042.nomux pci=off` all name x86
/// hardware: `reboot=k` selects the reset through the i8042 keyboard
/// controller's port, which is the event Firecracker's x86 VMM treats as the
/// guest going away, and the `i8042.*` pair stops the guest probing that
/// controller's aux/mux ports, which Firecracker does not emulate. On arm64
/// there is no i8042 at all, and the reset is a PSCI `SYSTEM_RESET` call that
/// KVM hands Firecracker as a system event — selected by the guest kernel's
/// PSCI driver, not by anything on the command line. See
/// [`Self::base_boot_args`] for what was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestArch {
    X86_64,
    Aarch64,
}

impl GuestArch {
    /// The arch of every guest this kamaji can boot.
    ///
    /// An error, not a default, on any other arch: falling back to one of the
    /// two command lines below is exactly the hazard R605-F31 recorded, where a
    /// kamaji on a new arch hands Firecracker another arch's reset path and the
    /// symptom is a guest that never reports finishing.
    pub fn host() -> Result<Self> {
        if cfg!(target_arch = "x86_64") {
            Ok(Self::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Ok(Self::Aarch64)
        } else {
            bail!(
                "microVM backend: no guest boot recipe for {} — guests are booted for x86_64 \
                 and aarch64 only (oss/kamaji/guest/build-guest-image.sh)",
                std::env::consts::ARCH
            )
        }
    }

    /// The command line every guest of this arch boots with, before the
    /// per-slot `ip=` argument.
    ///
    /// x86_64 is byte-for-byte what R605-F14 measured booting on us-west-003
    /// and what every x86 proof since was taken against.
    ///
    /// aarch64 was measured by R605-F32 on us-west-014 (Raspberry Pi 5,
    /// Firecracker v1.16.0, guest kernel 6.1.187 built from
    /// `kernel/base-aarch64-6.1.config`), booting each candidate line with
    /// only the root drive attached so the init halts at once and the reset
    /// path is the only thing under test:
    ///
    /// - Firecracker itself appends `pci=off root=/dev/vda ro
    ///   earlycon=uart,mmio,0x40002000` on aarch64, so `pci=off` is the VMM's
    ///   to give — and the arm64 kernel answers it with `PCI: Unknown option
    ///   'off'` regardless.
    /// - The x86 line boots and resets cleanly too: `reboot=k` and `i8042.*`
    ///   are accepted and inert. Their absence here is because they name
    ///   hardware this guest does not have, not because they break it.
    /// - The reset is PSCI with or without `reboot=k`: `reboot: Restarting
    ///   system`, then Firecracker logs `Received KVM_SYSTEM_EVENT: type: 2`
    ///   and exits 0 — the VMM exit the supervisor reads as an instance end.
    /// - `panic=1` is load-bearing exactly as on x86: `init=/nonexistent`
    ///   panics, reboots after one second, and the VMM exits 0; the same
    ///   boot without `panic=1` was still running when killed at 25s.
    pub fn base_boot_args(self) -> &'static str {
        match self {
            Self::X86_64 => "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux",
            Self::Aarch64 => "console=ttyS0 panic=1",
        }
    }
}

/// Build the VM definition for one guest.
///
/// # Why the boot args are the same for both shapes
///
/// `panic=1 reboot=k` is the load-bearing pair: it makes the guest **exit**
/// rather than sit at a panic prompt, so the VMM process ending is a signal the
/// supervisor can act on. Without it a wedged guest would hang until teardown
/// and look identical to a slow build.
///
/// R605-F31 expected to have to make these archetype-dependent too, and they
/// are not, which is worth stating so the next reader does not read the absence
/// as an oversight. What the pair buys is that *the host always finds out*; what
/// changes between a job and a service is the **interpretation**, and that lives
/// in [`GuestBoot::settle`], not in the cmdline. For a job, the VMM exiting is
/// the job finishing. For a service, the VMM exiting is one instance ending and
/// the [`RestartPolicy`](workload_spec::RestartPolicy) decides what follows — so
/// a service guest that panics is reset, observed, and booted again with
/// backoff, which is strictly better supervision than a guest looping inside
/// itself where the host can neither see it nor rate-limit it. Removing
/// `panic=1` for services would buy exactly one thing: a panicked service guest
/// that hangs forever and reports `Running`.
///
/// The rest of the command line is per-arch, and why is [`GuestArch`]'s story.
pub fn vmm_config(
    cfg: &MicroVmConfig,
    spec: &WorkloadSpec,
    slot: Option<&GuestSlot>,
    workspace_disk: &Path,
    root: &RootDisk,
) -> Result<VmmConfig> {
    let mut boot_args = String::from(GuestArch::host()?.base_boot_args());
    if let Some(slot) = slot {
        boot_args.push(' ');
        boot_args.push_str(&slot.kernel_ip_arg());
    }

    let mut drives = vec![
        Drive {
            drive_id: "rootfs".into(),
            path_on_host: root.path.to_string_lossy().into_owned(),
            is_root_device: true,
            // Read-only-ness is a correctness property, not a hardening bonus,
            // and it is a property of the IMAGE BEING SHARED rather than of the
            // flag: the node's one rootfs.ext4 serves every job on the node, so
            // a writable one would let job N leave state for job N+1 — the
            // exact cross-contamination this backend exists to prevent.
            //
            // A service-shaped guest is therefore not handed this flag flipped.
            // It is handed a DIFFERENT image — its own private copy, which no
            // other workload can observe — and `read_only: false` is safe there
            // for the reason the shared image could never have made it safe.
            // See `RootDisk`.
            is_read_only: root.read_only,
        },
        Drive {
            drive_id: "workspace".into(),
            path_on_host: workspace_disk.to_string_lossy().into_owned(),
            is_root_device: false,
            is_read_only: false,
        },
    ];
    if let Some(toolchain) = &cfg.toolchain_image {
        drives.push(Drive {
            drive_id: "toolchain".into(),
            path_on_host: toolchain.to_string_lossy().into_owned(),
            is_root_device: false,
            // The whole basis of R605-F23's resolution. One image serves every
            // workload on the node, so it is attached the way a shared image
            // has to be attached, and "mounted" costs nothing against "baked
            // in" on the correctness axis they were argued to differ on.
            //
            // Unconditional across both shapes, unlike the root device, and for
            // the reason above rather than by omission: the toolchain volume IS
            // shared — there is one per node, not one per workload — so the
            // argument that lets a service write its own private root says
            // nothing at all about this one.
            is_read_only: true,
        });
    }

    Ok(VmmConfig {
        boot_source: BootSource {
            kernel_image_path: cfg.kernel_image.to_string_lossy().into_owned(),
            boot_args,
        },
        drives,
        machine_config: MachineConfig {
            vcpu_count: guest_vcpus(cfg, spec),
            mem_size_mib: guest_memory_mb(cfg, spec)?,
        },
        network_interfaces: slot
            .map(|s| {
                vec![NetworkInterface {
                    iface_id: "eth0".into(),
                    host_dev_name: s.tap.clone(),
                    guest_mac: s.mac.clone(),
                }]
            })
            .unwrap_or_default(),
    })
}

/// How much RAM the guest actually gets, in MiB.
///
/// # Why this is not just `spec.resources.memory_mb`
///
/// Because that field means something different on every other backend, and
/// taking it literally here would break every forge run on the fleet.
///
/// On a container backend `memory_mb` is a **cgroup ceiling** — an upper bound
/// the workload is killed for exceeding, costing nothing until it is
/// approached. `WorkloadSpec::for_forge` sets it to 32 GiB (`R590-B10`, so the
/// rusty-v8 build's >12 GB peak fits). On a VM the same number would be an
/// **allocation**: Firecracker would ask the host for a 32 GiB guest on nodes
/// W325 §4 measured at 11682 MB total. Every build would fail to boot.
///
/// So the ceiling is treated as what it is — a ceiling — and clamped to what
/// the node will actually hand out:
///
/// - **floor**: `memory_request_mb()`, the number admission already proved the
///   node has free (2 GiB for forge). Going below it would boot a guest the
///   scheduler's own arithmetic says is too small.
/// - **cap**: `max_guest_memory_mb`, set per node by the operator.
///
/// If the floor exceeds the cap the deploy is refused naming both numbers,
/// rather than booting a guest that is going to OOM: a build that dies at 90%
/// with a SIGKILL is far more expensive to diagnose than a deploy that refuses.
///
/// This divergence is the price of the shared spec shape, and it is worth
/// paying — the alternative is a `WorkloadSpec` field only one backend reads.
pub fn guest_memory_mb(cfg: &MicroVmConfig, spec: &WorkloadSpec) -> Result<u32> {
    let floor = spec.memory_request_mb().max(1);
    if floor > cfg.max_guest_memory_mb {
        bail!(
            "workload {} requests {} MiB but this node caps a microVM guest at {} MiB; \
             refusing rather than booting a guest that cannot hold the job. Raise the node's \
             max_guest_memory_mb, or place this workload on a larger node",
            spec.name,
            floor,
            cfg.max_guest_memory_mb
        );
    }
    Ok(spec
        .resources
        .memory_mb
        .clamp(floor, cfg.max_guest_memory_mb))
}

/// How many vCPUs the guest gets: `cpu_millis` rounded up to whole CPUs, at
/// least one, capped by the node.
///
/// Rounded **up** because a VM cannot be given a fraction of a CPU the way a
/// cgroup can be given a fraction of a quota — the guest scheduler needs whole
/// CPUs to schedule onto — and rounding down would silently hand a
/// 1500-millicore build a single core.
pub fn guest_vcpus(cfg: &MicroVmConfig, spec: &WorkloadSpec) -> u32 {
    let want = spec.resources.cpu_millis.div_ceil(1000).max(1);
    want.min(cfg.max_guest_vcpus.max(1))
}

// ── Runtime ──────────────────────────────────────────────────────────────────

/// One booted guest: the VMM process running it, and the pid to signal.
///
/// The supervisor's unit of work — [`crate::supervise`]'s `Instance` for this
/// backend, exactly as `SpawnedChild` is for [`crate::native`].
struct BootedGuest {
    child: tokio::process::Child,
    pid: u32,
}

/// Everything [`crate::supervise::supervise`] needs to boot this workload's
/// guest again, and to make sense of it when it ends.
///
/// Note what is *not* here: the spec. Every decision that depended on it —
/// argv, env, memory, vCPUs, drives, network — was resolved at deploy into
/// `vm-config.json` and the job document on the scratch disk, and a reboot
/// re-reads those files rather than re-deriving them. That is not a shortcut;
/// it is what makes the machine an operator can read off disk the same machine
/// the supervisor actually boots.
struct GuestBoot {
    workload: String,
    shape: VmShape,
    vmm_bin: PathBuf,
    config_path: PathBuf,
    console_path: PathBuf,
    workspace_disk: PathBuf,
    plan: Vec<workspace::PlannedMount>,
    slot: Option<GuestSlot>,
    net: Option<GuestNetwork>,
}

/// One live guest's host-side bookkeeping.
struct VmHandle {
    slot: Option<GuestSlot>,
    mesh_ip: Ipv4Addr,
    vm_dir: PathBuf,
    console_path: PathBuf,
    /// What this workload is, which is what decides whether
    /// [`MicroVmRuntime::restart_workload`] means anything for it.
    shape: VmShape,
    pid: Arc<AtomicU32>,
    status: watch::Receiver<WorkloadStatus>,
    /// Control channel to the supervisor task, which owns the VMM process.
    ///
    /// Teardown goes through here rather than signalling the pid directly
    /// (which is what this backend did before R605-F31): with a restart loop in
    /// play, signalling behind the supervisor's back races it — the supervisor
    /// would see the exit, consult the policy and boot a replacement, while
    /// teardown sat waiting for a pid that had already been superseded.
    ctrl: mpsc::Sender<Ctrl<BootedGuest>>,
    /// Supervisor task; detached on drop.
    #[allow(dead_code)]
    task: JoinHandle<()>,
}

impl GuestBoot {
    /// Start the VMM on this workload's machine definition.
    ///
    /// `truncate` distinguishes the initial boot from a re-boot, and follows
    /// [`crate::native`]'s convention exactly: the first boot truncates the
    /// console capture, every later one appends, so a crash-looping service's
    /// history survives the loop that produced it.
    async fn boot(&self, truncate: bool) -> Result<BootedGuest> {
        let console = if truncate {
            std::fs::File::create(&self.console_path)
        } else {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.console_path)
        }
        .with_context(|| format!("opening {}", self.console_path.display()))?;

        // R885-B10 — THE THIRD FORK PATH, and the one deliberately NOT attached
        // to a cgroup leaf. `native` (keep-alive) and `jit` (on-demand) both put
        // their children inside `<delegated-root>/<workload-id>/<generation>/`
        // before `exec`; this one does not, and the reason is that the ceiling
        // is already expressed somewhere else: a microVM's memory is the
        // `mem_size_mib` written into its machine config, enforced by the VMM
        // and by the guest kernel's own view of RAM, and the vCPU count is the
        // cpu allocation. Wrapping a `memory.max` around the VMM process would
        // put a second, independent ceiling on the same workload, and the one
        // that fired first would be an OOM kill of the whole VM with no OOM
        // inside the guest to explain it.
        //
        // This is a stated exclusion, not an oversight — if a later ticket
        // decides the VMM *should* also sit in a leaf (for `pids.max`, or to
        // bound VMM overhead above the guest's RAM), the mechanism to use is
        // `CgroupHandle::attach_at_exec`, the same one both other paths use. Do
        // not grow a second one here.
        let child = tokio::process::Command::new(&self.vmm_bin)
            .arg("--no-api")
            .arg("--config-file")
            .arg(&self.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(console.try_clone()?))
            .stderr(Stdio::from(console))
            .kill_on_drop(false)
            .spawn()
            .with_context(|| {
                format!(
                    "spawning {} — is firecracker installed and is /dev/kvm openable?",
                    self.vmm_bin.display()
                )
            })?;
        let pid = child.id().unwrap_or(0);
        Ok(BootedGuest { child, pid })
    }

    /// Free this guest's TAP device, warning rather than failing.
    ///
    /// A leak here costs the slot until kamaji restarts, which is worth a loud
    /// log and not worth failing a workload over.
    async fn release_tap(&self) {
        if let (Some(slot), Some(net)) = (self.slot.as_ref(), self.net.as_ref()) {
            if let Err(e) = net::delete_tap(slot, net).await {
                tracing::warn!(workload = %self.workload, tap = %slot.tap, error = %e,
                    "leaked a TAP device: the slot stays allocated until kamaji restarts");
            }
        }
    }

    /// R605-T24: log the terminal status, and specifically its REASON.
    ///
    /// Every arm of [`Self::settle_job`] composes a careful sentence naming what
    /// went wrong, and until T24 not one of them was ever written anywhere: the
    /// reason travelled only inside [`WorkloadStatus::Failed`], and by the time
    /// it crossed the wire it had been flattened to the `WorkloadEntry` shape —
    /// a bare `"Failed"` string with no reason field at all. So a caller
    /// dispatching a forge through yubaba saw `status=Failed`, the node's
    /// journal said nothing beyond "microVM booted" and "microVM torn down", and
    /// the sentence that would have explained it was dropped on the floor.
    ///
    /// INFO, not WARN: a job that fails is this backend's ordinary business, and
    /// the line is the run's epitaph either way.
    fn log_outcome(&self, status: &WorkloadStatus) {
        match status {
            WorkloadStatus::Failed { reason, .. } => tracing::info!(
                workload = %self.workload, shape = ?self.shape, %reason, "microVM instance failed"
            ),
            other => tracing::info!(
                workload = %self.workload, shape = ?self.shape, status = ?other,
                "microVM instance finished"
            ),
        }
    }

    /// A job's guest has halted: this is the end of the workload.
    async fn settle_job(&self, exit: Exit) -> Completion {
        // Artifacts come back out *after* the guest halts, not during: the
        // scratch disk is a block device the guest owns exclusively while it
        // runs, and reading a live ext4 from the host would see a half-written
        // filesystem.
        let extracted = workspace::extract_disk(&self.workspace_disk, &self.plan).await;
        // The guest will not boot again, so the device is dead weight from here.
        self.release_tap().await;

        let (succeeded, exit_code, terminal) = match (exit, extracted) {
            // The VMM exiting cleanly means the *machine* stopped, and says
            // nothing about the job: a reset is a reset whether the build
            // passed, failed, or panicked the guest kernel, so firecracker
            // exits 0 for all three (measured — see JOB_STATUS_FILE). The
            // guest's own status document is the only thing that can tell them
            // apart, so a clean VMM exit is where reading it belongs.
            (Ok(st), Ok(())) if st.success() => {
                match workspace::read_job_status(&self.workspace_disk).await {
                    Ok(js) if js.exit_code == 0 => (true, 0, WorkloadStatus::Stopped),
                    Ok(js) => (
                        false,
                        js.exit_code,
                        WorkloadStatus::Failed {
                            oom_killed: false,
                            // The guest's own `detail` already names the exit
                            // code or the signal, so repeating the number here
                            // would read "the job exited 3 ... job exited 3".
                            // It is `#[serde(default)]` though, so an empty one
                            // must still produce a reason worth reading.
                            reason: if js.detail.is_empty() {
                                format!("the job exited {} inside the guest", js.exit_code)
                            } else {
                                format!("the job failed inside the guest: {}", js.detail)
                            },
                        },
                    ),
                    Err(e) => (
                        false,
                        -1,
                        WorkloadStatus::Failed {
                            oom_killed: false,
                            reason: format!("the guest did not report a job status: {e:#}"),
                        },
                    ),
                }
            }
            (Ok(st), Ok(())) => (
                false,
                st.code().unwrap_or(-1),
                WorkloadStatus::Failed {
                    oom_killed: false,
                    reason: format!("microVM exited with {st}"),
                },
            ),
            (Ok(_), Err(e)) => (
                false,
                -1,
                WorkloadStatus::Failed {
                    oom_killed: false,
                    reason: format!("guest finished but its artifacts could not be read back: {e:#}"),
                },
            ),
            (Err(e), _) => (
                false,
                -1,
                WorkloadStatus::Failed {
                    oom_killed: false,
                    reason: format!("waiting on the VMM failed: {e}"),
                },
            ),
        };
        self.log_outcome(&terminal);
        Completion {
            succeeded,
            exit_code,
            terminal,
        }
    }

    /// A service's guest has gone away: this is the end of an *instance*.
    ///
    /// Two things the job path does are deliberately not done here.
    ///
    /// **Artifacts are not copied back out.** A service is not a producer; its
    /// state lives on the scratch disk it keeps across restarts (and, once
    /// R605-F33 lands the guest half, on its own root). Extracting between two
    /// boots would cost the copy
    /// on every crash and race the next boot for the block device it is about to
    /// open.
    ///
    /// **The TAP device is not freed.** The next boot needs the same device on
    /// the same `/30`; tearing it down between restarts would mean re-creating
    /// it and re-installing the NAT rules on every crash, and would drop the
    /// guest's address in between. [`MicroVmRuntime::teardown_workload`] frees
    /// it, which is the point at which the guest really is not coming back.
    ///
    /// What is the *same* is the verdict: the guest's own status document, for
    /// the reason [`JOB_STATUS_FILE`] gives — the VMM's exit code structurally
    /// cannot carry it, and that is a property of firecracker rather than of
    /// what the guest was running. A stale document from a previous instance
    /// would be read as this one's, which is why [`Self::start`] clears it
    /// before every re-boot.
    async fn settle_service(&self, exit: Exit) -> Completion {
        let (succeeded, exit_code, terminal) = match exit {
            Ok(st) if st.success() => {
                match workspace::read_job_status(&self.workspace_disk).await {
                    Ok(js) if js.exit_code == 0 => (true, 0, WorkloadStatus::Stopped),
                    Ok(js) => (
                        false,
                        js.exit_code,
                        WorkloadStatus::Failed {
                            oom_killed: false,
                            reason: if js.detail.is_empty() {
                                format!("the guest's process exited {}", js.exit_code)
                            } else {
                                format!("the guest's process failed: {}", js.detail)
                            },
                        },
                    ),
                    // A guest that reset without reporting panicked, was killed,
                    // or never reached the end of its init. Not a success: a
                    // service that resets silently must back off under
                    // `OnFailure` rather than be credited with a clean run.
                    Err(e) => (
                        false,
                        -1,
                        WorkloadStatus::Failed {
                            oom_killed: false,
                            reason: format!("the guest reset without reporting a status: {e:#}"),
                        },
                    ),
                }
            }
            Ok(st) => (
                false,
                st.code().unwrap_or(-1),
                WorkloadStatus::Failed {
                    oom_killed: false,
                    reason: format!("microVM exited with {st}"),
                },
            ),
            Err(e) => (
                false,
                -1,
                WorkloadStatus::Failed {
                    oom_killed: false,
                    reason: format!("waiting on the VMM failed: {e}"),
                },
            ),
        };
        self.log_outcome(&terminal);
        Completion {
            succeeded,
            exit_code,
            terminal,
        }
    }
}

#[async_trait]
impl Supervised for GuestBoot {
    type Instance = BootedGuest;

    fn pid(&self, inst: &BootedGuest) -> u32 {
        inst.pid
    }

    async fn wait(&self, inst: &mut BootedGuest) -> Exit {
        inst.child.wait().await
    }

    /// Boot the guest again from the machine definition already on disk.
    ///
    /// Only ever called for a service — a job's `RestartPolicy::Never` means the
    /// supervisor never asks, and [`MicroVmRuntime::restart_workload`] refuses
    /// to ask on its behalf.
    async fn start(&self) -> Result<BootedGuest> {
        // Drop the previous instance's verdict before booting, so the next
        // exit's status document cannot be this one's. A failure here degrades
        // to a stale read, not to a dead workload, so it warns and continues.
        if let Err(e) = workspace::clear_job_status(&self.workspace_disk).await {
            tracing::warn!(
                workload = %self.workload, error = %format!("{e:#}"),
                "could not clear the previous instance's status document; a guest that resets \
                 without writing a new one may be reported with the previous verdict"
            );
        }
        self.boot(false).await
    }

    /// SIGTERM to Firecracker is a guest power-off, not a guest signal: there is
    /// nothing inside to catch it. That is why teardown is not the normal
    /// completion path for either shape — the normal path is the guest going
    /// away on its own, which the supervisor sees as the VMM process exiting.
    async fn stop(&self, inst: &mut BootedGuest) {
        if matches!(inst.child.try_wait(), Ok(Some(_))) {
            return;
        }
        signal_pid(inst.pid, libc::SIGTERM);
        if tokio::time::timeout(TERM_GRACE, inst.child.wait())
            .await
            .is_err()
        {
            let _ = inst.child.start_kill();
            let _ = inst.child.wait().await;
        }
    }

    async fn settle(&self, exit: Exit) -> Completion {
        match self.shape {
            VmShape::Job => self.settle_job(exit).await,
            VmShape::Service => self.settle_service(exit).await,
        }
    }
}

/// Firecracker microVM backend. One instance runs any number of guests, each in
/// its own `/30` slot.
pub struct MicroVmRuntime {
    cfg: MicroVmConfig,
    vms: Mutex<HashMap<String, VmHandle>>,
}

impl MicroVmRuntime {
    /// Per-workload scratch root; a guest's console is
    /// `<state_dir>/<mesh ident>/console.log` (R729-F2 follows it by path,
    /// since the `vms` map forgets a guest at teardown).
    pub fn state_dir(&self) -> &Path {
        &self.cfg.state_dir
    }

    /// Construct the backend, checking the node's configuration up front.
    ///
    /// Deliberately fallible, and deliberately *not* the same check as
    /// [`crate::probe::probe_microvm`]. The probe answers "can this host run a
    /// VM at all" (a host capability); this answers "is this node configured to
    /// run one" (operator setup). Both have to hold, they fail for unrelated
    /// reasons, and an operator gets a much better message from the one that
    /// actually broke.
    ///
    /// Checking at construction rather than at first deploy means a node with a
    /// typo'd rootfs path advertises no microVM backend and never wins a
    /// placement, instead of accepting builds and failing every one of them.
    pub fn new(cfg: MicroVmConfig) -> Result<Self> {
        // A kamaji on an arch with no guest recipe advertises no backend,
        // rather than accepting workloads and booting each with another
        // arch's command line (R605-F31's recorded hazard).
        GuestArch::host()?;
        for (what, path) in [
            ("VMM binary", &cfg.vmm_bin),
            ("guest kernel", &cfg.kernel_image),
            ("guest rootfs", &cfg.rootfs_image),
        ] {
            if !path.exists() {
                bail!(
                    "microVM backend: {what} not found at {} — the node needs a guest kernel \
                     and rootfs on disk; there is no image to pull for a microVM workload",
                    path.display()
                );
            }
        }
        // The toolchain volume is the one piece of guest material whose absence
        // is a legitimate configuration, so it is not in the loop above. A path
        // that was *named* and does not exist is still an error: that is an
        // operator who staged a toolchain and typo'd it, and the alternative is
        // a node that wins build placements and fails every one of them with a
        // missing-compiler error far from its cause.
        if let Some(toolchain) = &cfg.toolchain_image {
            if !toolchain.exists() {
                bail!(
                    "microVM backend: toolchain volume not found at {} — remove it from the \
                     node's config to run guests without a build toolchain, or stage one with \
                     oss/kamaji/guest/build-toolchain-image.sh",
                    toolchain.display()
                );
            }
        }
        // Same rule as the toolchain: absent is a configuration (this node runs
        // jobs only), named-but-missing is an operator's typo.
        if let Some(service) = &cfg.service_rootfs_image {
            if !service.exists() {
                bail!(
                    "microVM backend: service root image not found at {} — remove it from the \
                     node's config to run job-shaped guests only, or stage one with \
                     oss/kamaji/guest/build-guest-image.sh --only service-rootfs",
                    service.display()
                );
            }
        }
        if cfg.max_guest_memory_mb == 0 {
            bail!("microVM backend: max_guest_memory_mb is 0 — no guest could be booted");
        }
        log_provenance("rootfs", &cfg.rootfs_image);
        if let Some(service) = &cfg.service_rootfs_image {
            log_provenance("service rootfs", service);
        }
        if let Some(toolchain) = &cfg.toolchain_image {
            log_provenance("toolchain", toolchain);
        }
        Ok(Self {
            cfg,
            vms: Mutex::new(HashMap::new()),
        })
    }

    /// The node configuration this backend was built with.
    pub fn config(&self) -> &MicroVmConfig {
        &self.cfg
    }

    /// Lowest slot index not currently in use.
    ///
    /// Lowest-free rather than monotonic so a node that has run thousands of
    /// builds still uses `yahvm0`, which keeps TAP names inside the kernel's
    /// 15-character limit indefinitely and keeps the address space small enough
    /// to reason about.
    async fn allocate_slot(&self) -> Result<Option<GuestSlot>> {
        let Some(net) = &self.cfg.network else {
            return Ok(None);
        };
        let vms = self.vms.lock().await;
        let taken: Vec<u32> = vms
            .values()
            .filter_map(|h| h.slot.as_ref().map(|s| s.index))
            .collect();
        let index = (0u32..).find(|i| !taken.contains(i)).expect("u32 exhausted");
        GuestSlot::derive(net, index).map(Some)
    }
}

#[async_trait]
impl Kamaji for MicroVmRuntime {
    fn backend(&self) -> Backend {
        Backend::MicroVm
    }

    async fn deploy_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> Result<DeployResult> {
        if spec.replicas > 1 {
            return Err(anyhow!(
                "workload {}: Backend::MicroVm boots one guest per workload (got replicas={})",
                spec.name,
                spec.replicas
            ));
        }

        // R870-F23: spec-carried config files this backend does not write.
        crate::reject_unmaterializable_files(spec, crate::Backend::MicroVm)?;

        // Signed-recipe admission (R555-F4 / W235 §(c)), at the same point in
        // the sequence the other backends check it. A guest is a strong
        // boundary around the *host*, and no boundary at all around the
        // credentials the job document is about to carry into it, so the argv
        // still has to be one the node agreed to run.
        workload_spec::admission::check(spec)
            .map_err(|e| anyhow!("workload {} not admitted: {e}", spec.name))?;

        // Job or service (R605-F31). Every decision below that differs between
        // the two reads this one value, and nothing else.
        let shape = VmShape::of_spec(spec);

        // A job-shaped guest that asks to be restarted is a spec that
        // contradicts itself, and it is refused here rather than silently
        // demoted. `restart_workload` explains the substance: re-running a job
        // means a fresh guest with a fresh workspace, so a supervisor that
        // re-booted this one would hand the retry the previous run's output
        // disk. The forge convention (`WorkloadSpec::for_forge`) already sets
        // `Never`, so nothing the fleet dispatches today reaches this.
        if shape == VmShape::Job && !matches!(spec.restart_policy, RestartPolicy::Never) {
            return Err(anyhow!(
                "workload {}: Backend::MicroVm was handed a job-shaped spec ({:?}) with \
                 restart_policy {:?}. A job's retry needs a fresh workspace, so restarting this \
                 guest in place would re-run it over the last run's output. Set \
                 restart_policy = never, or declare archetype = server/appliance if this really \
                 is a long-lived VM",
                spec.name,
                spec.effective_archetype(),
                spec.restart_policy,
            ));
        }

        let ident = spec.expose.mesh.identity.clone();
        let vm_dir = self.cfg.state_dir.join(sanitize(&ident.0));
        // Which root this guest boots, decided before anything is torn down or
        // allocated: a service on a node with no service image is refused here
        // with the running instance (if any) left alone.
        let root = RootDisk::for_shape(&self.cfg, shape, &vm_dir)
            .with_context(|| format!("workload {}", spec.name))?;

        // Idempotent, like every other backend's deploy.
        self.teardown_workload(&ident).await?;

        let slot = self.allocate_slot().await?;
        tokio::fs::create_dir_all(&vm_dir)
            .await
            .with_context(|| format!("creating microVM state dir {}", vm_dir.display()))?;

        // 1. Scratch disk: the workload's input tree in, and for a job its
        //    artifacts out. Rebuilt on every deploy for both shapes — it is the
        //    declared-inputs channel, so a redeploy must present what the
        //    current spec declares. A service's *durable* state is its root
        //    (step 3), which is exactly what is not rebuilt.
        let disk = vm_dir.join("workspace.ext4");
        let plan = workspace::plan(spec);
        workspace::build_disk(&plan, &disk, spec.scratch_floor_mb())
            .await
            .with_context(|| format!("building scratch disk for workload {}", spec.name))?;

        // 2. The job document, written *into* that disk — the guest has no
        //    other way to be told what it was booted for.
        //
        //    Identical for both shapes, deliberately. The document is a
        //    cross-artifact contract with a rootfs image that ships separately
        //    (see JOB_SCHEMA_VERSION), a service needs exactly what a job needs
        //    from it — argv, env, mounts, a resolver — and teaching the guest
        //    about archetypes would mean a schema bump that every rootfs image
        //    already in the fleet would refuse. The shape is the host's
        //    business; the guest's job is the same either way.
        let job = MicroVmJob::of_spec(
            spec,
            &plan,
            slot.as_ref().and(self.cfg.network.as_ref()).map(|n| n.dns),
        )?;
        workspace::write_job(&disk, &job)
            .await
            .with_context(|| format!("writing {JOB_FILE} into {}", disk.display()))?;

        // 3. Root device: the node's shared read-only job image for a job, this
        //    workload's own writable copy for a service (seeded from the node's
        //    service image if it has none yet, kept as-is if it has).
        root.provision().await?;

        // 4. Host networking for this slot.
        if let (Some(slot), Some(net)) = (slot.as_ref(), self.cfg.network.as_ref()) {
            net::create_tap(slot, net).await.with_context(|| {
                format!(
                    "creating TAP {} for workload {} — this needs CAP_NET_ADMIN",
                    slot.tap, spec.name
                )
            })?;
        }

        // 5. The machine definition, kept on disk next to the logs. A restart
        //    re-reads this file rather than re-deriving it, so what an operator
        //    can read here is what the supervisor actually boots.
        let config_path = vm_dir.join("vm-config.json");
        let vmm = vmm_config(&self.cfg, spec, slot.as_ref(), &disk, &root)?;
        tokio::fs::write(&config_path, serde_json::to_vec_pretty(&vmm)?)
            .await
            .with_context(|| format!("writing {}", config_path.display()))?;

        // 6. Boot, and hand the guest to the shared supervisor.
        //
        //    The first boot happens here rather than inside the supervisor so a
        //    boot failure (no firecracker, no /dev/kvm) surfaces to the caller
        //    instead of dying in a background task — the same reason the native
        //    backend fork+execs its first child synchronously.
        let boot = GuestBoot {
            workload: spec.name.clone(),
            shape,
            vmm_bin: self.cfg.vmm_bin.clone(),
            config_path,
            // The guest console is the workload's log, so it is captured the
            // same way the native backend captures stdout.
            console_path: vm_dir.join("console.log"),
            workspace_disk: disk,
            plan,
            slot: slot.clone(),
            net: self.cfg.network.clone(),
        };
        let console_path = boot.console_path.clone();
        let initial = boot.boot(true).await?;
        let vm_pid = initial.pid;

        let pid = Arc::new(AtomicU32::new(vm_pid));
        let (status_tx, status_rx) = watch::channel(WorkloadStatus::Running);
        let (ctrl_tx, ctrl_rx) = mpsc::channel(8);
        // One restart loop, shared with the native backend (crate::supervise).
        // For a job the policy is `Never` — checked above — and the supervisor's
        // handling of `Never` (settle, publish the terminal status, park) is
        // precisely the behaviour this backend had when it had no supervisor at
        // all, which is why the job path's observable semantics are unchanged.
        let task = tokio::spawn(supervise(
            boot,
            spec.restart_policy.clone(),
            initial,
            Arc::clone(&pid),
            status_tx,
            ctrl_rx,
        ));

        tracing::info!(
            workload = %spec.name, shape = ?shape, pid = vm_pid,
            root = %root.path.display(), root_read_only = root.read_only,
            "microVM booted"
        );

        self.vms.lock().await.insert(
            ident.0.clone(),
            VmHandle {
                slot,
                mesh_ip: mesh.mesh_ip,
                vm_dir,
                console_path,
                shape,
                pid,
                status: status_rx,
                ctrl: ctrl_tx,
                task,
            },
        );

        Ok(DeployResult {
            container_id: format!("microvm-{vm_pid}"),
            mesh_ip: mesh.mesh_ip,
            task_pid: vm_pid,
            hydrate: None,
            // R844-F2: the guest owns its own network stack, so the declared
            // port is the bound port — nothing for this backend to resolve.
            ports: Default::default(),
        })
    }

    async fn list_workloads(&self) -> Result<Vec<WorkloadState>> {
        let vms = self.vms.lock().await;
        Ok(vms
            .iter()
            .map(|(ident, h)| WorkloadState {
                ident: MeshIdent(ident.clone()),
                container_id: format!("microvm-{}", h.pid.load(Ordering::SeqCst)),
                status: h.status.borrow().clone(),
                mesh_ip: Some(h.mesh_ip),
                ports: Default::default(),
            })
            .collect())
    }

    async fn get_workload(&self, ident: &MeshIdent) -> Result<Option<WorkloadState>> {
        let vms = self.vms.lock().await;
        Ok(vms.get(&ident.0).map(|h| WorkloadState {
            ident: ident.clone(),
            container_id: format!("microvm-{}", h.pid.load(Ordering::SeqCst)),
            status: h.status.borrow().clone(),
            mesh_ip: Some(h.mesh_ip),
            ports: Default::default(),
        }))
    }

    /// The guest's serial console, which for a microVM workload *is* its log.
    ///
    /// There is no per-stream split: a guest has one console, and inventing a
    /// stdout/stderr distinction the hardware does not make would be a lie the
    /// caller could not detect. Everything is reported as
    /// [`LogStreamKind::Stdout`]; a caller asking only for stderr gets nothing
    /// rather than a duplicate of stdout.
    async fn stream_logs(&self, ident: &MeshIdent, opts: LogOpts) -> Result<LogStream> {
        let console_path = {
            let vms = self.vms.lock().await;
            vms.get(&ident.0)
                .ok_or_else(|| anyhow!("no microVM workload with identity {}", ident.0))?
                .console_path
                .clone()
        };

        if matches!(opts.stream, Some(LogStreamKind::Stderr)) {
            return Ok(Box::pin(tokio_stream::iter(Vec::new())));
        }

        let mut events: Vec<LogEvent> = Vec::new();
        if let Ok(file) = tokio::fs::File::open(&console_path).await {
            let mut lines = tokio::io::BufReader::new(file).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                events.push(LogEvent::plain(
                    ident.clone(),
                    LogStreamKind::Stdout,
                    line,
                ));
            }
        }
        if let Some(tail) = opts.tail {
            let tail = tail as usize;
            if events.len() > tail {
                events.drain(..events.len() - tail);
            }
        }
        Ok(Box::pin(tokio_stream::iter(events)))
    }

    /// Re-boot a service's guest in place; refused for a job, naming why.
    ///
    /// The refusal is the substance, not the leftover. Restart means "run this
    /// again", and for a job that is a *new run with a fresh workspace* — the
    /// scratch disk this guest halted with holds the last run's output, and
    /// re-booting into it would produce a result neither clean nor reproducible.
    /// The dispatcher decides to retry a job; the supervisor does not decide for
    /// it.
    ///
    /// None of that is true of a service. Its scratch disk is state it is meant
    /// to keep, its root is its own, and "bring it back" is exactly what a
    /// supervisor is for — so for a service this does what the native backend's
    /// has always done: hand the live supervisor a `Restart` and wait for the
    /// new pid.
    async fn restart_workload(&self, ident: &MeshIdent) -> Result<()> {
        let (shape, ctrl) = {
            let vms = self.vms.lock().await;
            let Some(h) = vms.get(&ident.0) else {
                return Err(anyhow!("no microVM workload with identity {}", ident.0));
            };
            (h.shape, h.ctrl.clone())
        };

        if shape == VmShape::Job {
            bail!(
                "Backend::MicroVm does not restart workload {} in place: it is job-shaped \
                 (LifecycleArchetype::Job, RestartPolicy::Never), and re-running a build means a \
                 fresh guest with a fresh workspace. Tear down and deploy again",
                ident.0
            );
        }

        let (ack_tx, ack_rx) = oneshot::channel();
        ctrl.send(Ctrl::Restart(ack_tx))
            .await
            .map_err(|_| anyhow!("supervisor for {} is gone", ident.0))?;
        ack_rx
            .await
            .map_err(|_| anyhow!("supervisor for {} dropped before restart ack", ident.0))??;
        Ok(())
    }

    async fn teardown_workload(&self, ident: &MeshIdent) -> Result<()> {
        let Some(handle) = self.vms.lock().await.remove(&ident.0) else {
            return Ok(()); // idempotent
        };

        // Through the supervisor, not around it. The supervisor owns the VMM
        // process; signalling the pid ourselves would race a service's restart
        // loop, which would see the exit, consult the policy and boot a
        // replacement we then had no handle on. `Ctrl::Teardown` stops the
        // instance AND ends supervision, in that order, with one owner.
        //
        // A dead supervisor (its task already returned) is not an error — that
        // is a torn-down workload, which is what was asked for.
        let (ack_tx, ack_rx) = oneshot::channel();
        if handle.ctrl.send(Ctrl::Teardown(ack_tx)).await.is_ok() {
            let _ = tokio::time::timeout(TERM_GRACE * 2, ack_rx).await;
        }

        if let (Some(slot), Some(net)) = (handle.slot.as_ref(), self.cfg.network.as_ref()) {
            if let Err(e) = net::delete_tap(slot, net).await {
                tracing::warn!(tap = %slot.tap, error = %e, "TAP teardown failed");
            }
        }

        // The VM directory is left in place deliberately: it holds the console
        // capture and the exact machine definition that was booted, which is
        // the whole record of a build that has just been torn down. Reclaiming
        // it belongs to whatever prunes the state dir, not to teardown.
        tracing::info!(vm_dir = %handle.vm_dir.display(), "microVM torn down");
        Ok(())
    }

    /// Health is "can this process still get a VM out of the kernel".
    ///
    /// Probes `/dev/kvm` directly rather than going through
    /// [`BackendAvailability::probe`], which would also connect-test the docker
    /// and containerd sockets — up to half a second of timeouts to answer a
    /// question about neither. Re-probed on every call, not cached from
    /// construction: group membership and device permissions are exactly the
    /// things an operator changes on a running node, and a cached `ok` would
    /// keep this reporting healthy right through the change that broke it.
    ///
    /// [`BackendAvailability::probe`]: crate::probe::BackendAvailability::probe
    async fn health(&self) -> Result<RuntimeHealth> {
        let kvm = crate::probe::probe_microvm(Path::new(crate::probe::KVM_DEVICE));
        Ok(RuntimeHealth {
            ok: kvm.available,
            version: None,
            detail: if kvm.available {
                None
            } else {
                Some(kvm.detail.clone())
            },
        })
    }
}

/// Suffix of the sha256 sidecar each guest-image builder writes beside its
/// output.
pub const PROVENANCE_SUFFIX: &str = ".sha256";

/// Log which bytes a piece of guest material actually is.
///
/// # Why a sidecar instead of hashing the image here
///
/// Because the toolchain volume is ~830 MB and this runs on kamaji's startup
/// path, and because `microvm-integration` is deliberately a feature that "adds
/// no Rust deps beyond libc" — pulling in `sha2` to hash a file at boot would
/// spend the dependency budget of the whole backend on one log line. The
/// builders already know the digest at the moment they produce the bytes, so
/// they write it down; this reads it.
///
/// Provenance matters more for the toolchain than for the rootfs, which is the
/// one real cost of R605-F23 choosing a separate volume over a baked layer: two
/// files can drift apart per-node in a way one file cannot. An unidentifiable
/// image is warned about rather than refused — a node that can build is more
/// useful than a node that will not start — but the warning names the fix.
fn log_provenance(what: &str, image: &Path) {
    let sidecar = {
        let mut p = image.as_os_str().to_os_string();
        p.push(PROVENANCE_SUFFIX);
        PathBuf::from(p)
    };
    match std::fs::read_to_string(&sidecar) {
        Ok(sha) => tracing::info!(
            image = %image.display(),
            sha256 = %sha.trim(),
            "microVM guest {what}"
        ),
        Err(e) => tracing::warn!(
            image = %image.display(),
            sidecar = %sidecar.display(),
            error = %e,
            "microVM guest {what} is unidentifiable — no sha256 sidecar; regenerate it with \
             `sha256sum <image> | cut -d' ' -f1 > <image>{PROVENANCE_SUFFIX}` so this node's \
             guest material can be matched against a build"
        ),
    }
}

fn signal_pid(pid: u32, sig: i32) {
    // SAFETY: kill(2) with a pid this process spawned; an ESRCH from an
    // already-reaped child is the expected benign case and is ignored.
    unsafe {
        libc::kill(pid as libc::pid_t, sig);
    }
}

/// Filesystem-safe form of a mesh identity, for use as a directory name.
fn sanitize(ident: &str) -> String {
    ident
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect()
}

// ── Scratch disk ─────────────────────────────────────────────────────────────

/// Building and unpacking the per-job ext4 scratch disk.
///
/// A container gets a bind mount; a guest kernel has no route to the host
/// filesystem, so the files have to be *copied* in and out through a block
/// device. Both directions go through `e2fsprogs` rather than a loop mount:
///
/// - in: `mkfs.ext4 -d <dir>` populates a fresh image from a directory tree.
/// - out: `debugfs -R "rdump / <dir>"` walks the image and writes it back.
///
/// Neither needs root, which is the entire reason for this shape — `mount -o
/// loop` would, and needing root to unpack a build's artifacts would put the
/// most attacker-adjacent step of the whole pipeline on the wrong side of the
/// privilege line.
pub mod workspace {
    use super::*;

    /// One volume's round trip: host directory → scratch disk → guest path →
    /// back to the host directory.
    ///
    /// The `slug` is the join between all four, and it exists because the guest
    /// cannot be given the host's layout. Naming the scratch subdirectory after
    /// the *target* rather than the source keeps the mapping legible when
    /// debugging a failed build (`0-yah-produced` is obviously `/yah/produced`),
    /// and the ordinal prefix makes it collision-free even when two targets
    /// slugify the same.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PlannedMount {
        pub host_path: PathBuf,
        pub target: PathBuf,
        pub slug: String,
        pub read_only: bool,
    }

    /// Plan the volume round trip for `spec`.
    ///
    /// Only `Bind` sources take part. A `Named` volume is node-managed storage
    /// this backend has no concept of, and `Tmpfs` is memory the guest
    /// allocates for itself — both are skipped rather than erroring, because a
    /// spec carrying one is asking for something a VM provides differently, not
    /// something it cannot have.
    ///
    /// Read-only mounts are still *copied in*, because the guest needs the
    /// bytes; the flag rides through to the guest's own bind mount and, more
    /// importantly, to [`extract_disk`], which will not copy a read-only
    /// volume's contents back over the host's. That is the one place the flag
    /// protects something the host cares about.
    pub fn plan(spec: &WorkloadSpec) -> Vec<PlannedMount> {
        spec.volumes
            .iter()
            .filter_map(|v| match &v.source {
                VolumeSource::Bind { host_path } => Some((host_path, &v.target, v.read_only)),
                _ => None,
            })
            .enumerate()
            .map(|(i, (host_path, target, read_only))| PlannedMount {
                host_path: host_path.clone(),
                target: target.clone(),
                slug: format!("{i}-{}", slugify(target)),
                read_only,
            })
            .collect()
    }

    /// A path rendered as one filesystem-safe component.
    fn slugify(path: &Path) -> String {
        let s: String = path
            .to_string_lossy()
            .trim_matches('/')
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
            .collect();
        if s.is_empty() {
            "root".to_string()
        } else {
            s
        }
    }

    /// Size the scratch image: the largest of the workload's declared floor,
    /// what the input tree implies, and [`WORKSPACE_MIN_BYTES`].
    ///
    /// # Every input here is a floor, and that is now said out loud
    ///
    /// `scratch_floor_mb` is [`WorkloadSpec::scratch_floor_mb`] — the
    /// `yah.limits.scratch-floor-mb` annotation, `None` when the workload
    /// declares none. Until R885-T6 this argument was
    /// `ResourceLimits::ephemeral_storage_mb`, a field whose own doc comment
    /// called it a **cap** on the writable layer. This function has always read
    /// it as a **floor**, i.e. the exact opposite, and it was right to: the
    /// builds this backend exists to isolate check out multi-gigabyte source
    /// trees, `for_forge` set the field to 512 MiB, and obeying that as a cap
    /// would have failed every forge run at its first `git clone`. The field is
    /// gone and the floor is spelled `floor`; nothing about the arithmetic
    /// below changed, only the name of the thing it reads.
    ///
    /// This is the mirror image of [`super::guest_memory_mb`]'s problem and the
    /// treatment is deliberately opposite. Memory is a real allocation, so an
    /// over-large spec value must be clamped *down* to what the node has.
    /// Scratch is a sparse file, so a small declared floor is raised *up* to
    /// what a build needs, and costs only the blocks actually written.
    ///
    /// [`WorkloadSpec::scratch_floor_mb`]: workload_spec::WorkloadSpec::scratch_floor_mb
    pub fn disk_size_bytes(input_bytes: u64, scratch_floor_mb: Option<u32>) -> u64 {
        let declared = u64::from(scratch_floor_mb.unwrap_or(0)).saturating_mul(1024 * 1024);
        input_bytes
            .saturating_mul(WORKSPACE_SIZE_MULTIPLIER)
            .max(declared)
            .max(WORKSPACE_MIN_BYTES)
    }

    /// Total bytes in a directory tree, following no symlinks.
    pub fn tree_bytes(root: &Path) -> u64 {
        fn walk(path: &Path, acc: &mut u64) {
            let Ok(entries) = std::fs::read_dir(path) else {
                return;
            };
            for entry in entries.flatten() {
                let Ok(meta) = entry.metadata() else { continue };
                if meta.is_dir() {
                    walk(&entry.path(), acc);
                } else {
                    *acc = acc.saturating_add(meta.len());
                }
            }
        }
        let mut acc = 0;
        walk(root, &mut acc);
        acc
    }

    /// Create the scratch image at `image`, populated per `plan`.
    ///
    /// Every mount is staged into one tree first: `mkfs.ext4 -d` takes a single
    /// directory, and a job's several volumes have to arrive as one filesystem.
    pub async fn build_disk(
        plan: &[PlannedMount],
        image: &Path,
        scratch_floor_mb: Option<u32>,
    ) -> Result<()> {
        let staging = image.with_extension("staging");
        let _ = tokio::fs::remove_dir_all(&staging).await;
        tokio::fs::create_dir_all(&staging).await?;

        let mut input_bytes = 0u64;
        for mount in plan {
            let dest = staging.join(&mount.slug);
            // Created even when the host side does not exist yet: yubaba's
            // `ensure_forge_state_dirs` makes the produced dir at deploy, but a
            // guest that finds no mount point at all fails at its first write,
            // and an empty directory is the correct thing for the *first* run
            // of a volume that has never held anything.
            tokio::fs::create_dir_all(&dest).await?;
            if !mount.host_path.exists() {
                continue;
            }
            input_bytes = input_bytes.saturating_add(tree_bytes(&mount.host_path));
            // Trailing `/.` copies contents into the (already-created) slug dir.
            run(
                "cp",
                &[
                    "-a".as_ref(),
                    format!("{}/.", mount.host_path.display()).as_ref(),
                    dest.as_os_str(),
                ],
            )
            .await?;
        }

        let size = disk_size_bytes(input_bytes, scratch_floor_mb);
        let file = std::fs::File::create(image)
            .with_context(|| format!("creating {}", image.display()))?;
        // Sparse: the image is sized for the build's *worst case*, and a
        // hole-punched file costs only what is written into it.
        file.set_len(size)
            .with_context(|| format!("sizing {} to {size} bytes", image.display()))?;
        drop(file);

        run(
            "mkfs.ext4",
            &[
                "-F".as_ref(),
                "-q".as_ref(),
                "-d".as_ref(),
                staging.as_os_str(),
                image.as_os_str(),
            ],
        )
        .await
        .context("mkfs.ext4 failed — is e2fsprogs installed on this node?")?;

        let _ = tokio::fs::remove_dir_all(&staging).await;
        Ok(())
    }

    /// Write the job document into an already-built image.
    pub async fn write_job(image: &Path, job: &MicroVmJob) -> Result<()> {
        let tmp = image.with_extension("job.json");
        tokio::fs::write(&tmp, serde_json::to_vec_pretty(job)?).await?;
        let script = format!("write {} {}", tmp.display(), JOB_FILE);
        run(
            "debugfs",
            &["-w".as_ref(), "-R".as_ref(), script.as_ref(), image.as_os_str()],
        )
        .await
        .context("debugfs write failed — is e2fsprogs installed on this node?")?;
        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    /// Read the guest's [`JobStatus`] back out of the scratch disk.
    ///
    /// Called only after the VMM has exited, like [`extract_disk`], and for the
    /// same reason: the guest owns this filesystem exclusively while it runs.
    ///
    /// An absent or unparseable document is an **error**, not a `None`. A guest
    /// that halted without recording a status did not demonstrably run the job —
    /// it may have panicked before exec, or been booted from a rootfs image whose
    /// init predates this file — and in both cases reporting the workload as
    /// cleanly `Stopped` would be a lie the caller cannot detect. See
    /// [`JOB_STATUS_FILE`] for why the VMM's own exit code cannot answer this.
    pub async fn read_job_status(image: &Path) -> Result<JobStatus> {
        let tmp = image.with_extension("status.json");
        let _ = tokio::fs::remove_file(&tmp).await;
        // `debugfs -R dump` exits 0 even when the named file is not in the image,
        // so the read below — not the exit status — is what detects an absent
        // document.
        let script = format!("dump /{JOB_STATUS_FILE} {}", tmp.display());
        run(
            "debugfs",
            &["-R".as_ref(), script.as_ref(), image.as_os_str()],
        )
        .await
        .context("debugfs dump failed — is e2fsprogs installed on this node?")?;
        let raw = tokio::fs::read(&tmp).await.with_context(|| {
            format!(
                "the guest halted without writing /{JOB_STATUS_FILE} to {} — it did not reach \
                 the end of its init, so whether the job ran at all is unknown",
                image.display()
            )
        })?;
        let _ = tokio::fs::remove_file(&tmp).await;
        let status: JobStatus = serde_json::from_slice(&raw).with_context(|| {
            format!("/{JOB_STATUS_FILE} is not a guest status document: {:?}", String::from_utf8_lossy(&raw))
        })?;
        if status.schema != JOB_SCHEMA_VERSION {
            bail!(
                "the guest wrote /{JOB_STATUS_FILE} at schema {} but this kamaji speaks {} — the \
                 node's rootfs image and this binary are skewed",
                status.schema,
                JOB_SCHEMA_VERSION
            );
        }
        Ok(status)
    }

    /// Remove a previous instance's [`JOB_STATUS_FILE`] from the scratch disk
    /// (R605-F31).
    ///
    /// The job path never needs this: a job's guest boots exactly once, so there
    /// is no previous document to mistake for this one's. A **service**'s guest
    /// boots again after every restart, and one that is killed before its init
    /// can write a new document would otherwise leave the supervisor reading the
    /// previous instance's verdict and attributing it to this one — reporting a
    /// crashed service as having exited cleanly, which is the same class of lie
    /// [`JOB_STATUS_FILE`] exists to prevent.
    ///
    /// `debugfs rm` unlinks and deallocates, the same `-w` route
    /// [`write_job`] already uses, so this adds no dependency. Like every
    /// `debugfs` call here it exits 0 on a file that is not in the image, which
    /// is the wanted behaviour for the first restart.
    pub async fn clear_job_status(image: &Path) -> Result<()> {
        let script = format!("rm /{JOB_STATUS_FILE}");
        run(
            "debugfs",
            &["-w".as_ref(), "-R".as_ref(), script.as_ref(), image.as_os_str()],
        )
        .await
        .context("debugfs rm failed — is e2fsprogs installed on this node?")
    }

    /// Copy the guest's output back over the host-side bind sources.
    ///
    /// Called only after the VMM process has exited — see the supervisor.
    ///
    /// Read-only mounts are skipped: the guest was handed a copy it was told
    /// not to write, and copying it back would let a guest that ignored the
    /// flag silently overwrite host state the spec declared immutable. This is
    /// the one asymmetry between the two directions, and it is deliberate — a
    /// read-only volume is a promise to the *host*, and the host is the side
    /// that has to keep it, since the guest is precisely what is not trusted.
    pub async fn extract_disk(image: &Path, plan: &[PlannedMount]) -> Result<()> {
        let writable: Vec<&PlannedMount> = plan.iter().filter(|m| !m.read_only).collect();
        if writable.is_empty() {
            return Ok(());
        }
        let dump = image.with_extension("out");
        let _ = tokio::fs::remove_dir_all(&dump).await;
        tokio::fs::create_dir_all(&dump).await?;

        let script = format!("rdump / {}", dump.display());
        run(
            "debugfs",
            &["-R".as_ref(), script.as_ref(), image.as_os_str()],
        )
        .await
        .context("debugfs rdump failed — the guest's artifacts are still in the image")?;

        for mount in writable {
            let from = dump.join(&mount.slug);
            if !from.exists() {
                continue;
            }
            tokio::fs::create_dir_all(&mount.host_path).await.ok();
            // Trailing `/.` copies the *contents*: the host side of a bind
            // mount already exists (yubaba created it), and replacing the
            // directory would break anything already holding the path.
            run(
                "cp",
                &[
                    "-a".as_ref(),
                    format!("{}/.", from.display()).as_ref(),
                    mount.host_path.as_os_str(),
                ],
            )
            .await?;
        }
        let _ = tokio::fs::remove_dir_all(&dump).await;
        Ok(())
    }
}

// ── Host networking ──────────────────────────────────────────────────────────

/// TAP device lifecycle for a guest slot.
///
/// Each guest gets its own TAP with the host end of a `/30` on it, plus a
/// MASQUERADE rule so the guest can reach the registry and crates.io. This
/// needs `CAP_NET_ADMIN`; the errors say so, because "RTNETLINK answers:
/// Operation not permitted" on its own sends an operator to the wrong place.
pub mod net {
    use super::*;

    /// The kernel's IPv4 routing table, in the form every Linux exposes it.
    const PROC_ROUTE: &str = "/proc/net/route";

    /// The interface carrying the host's IPv4 default route.
    ///
    /// Read from `/proc` rather than parsed out of `ip route`: this is called on
    /// the startup path, `/proc/net/route`'s columns have been stable for the
    /// lifetime of the kernel, and it means one fewer subprocess whose output
    /// format is a moving target.
    ///
    /// Lowest metric wins, because a box with both a wired and a wireless
    /// default route has two and the kernel will pick the cheaper one — a NAT
    /// rule on the other is a rule on a path no guest packet takes.
    pub fn default_route_uplink() -> Result<String> {
        let table = std::fs::read_to_string(PROC_ROUTE)
            .with_context(|| format!("reading {PROC_ROUTE}"))?;
        parse_default_route(&table)
    }

    /// The parsing half of [`default_route_uplink`], split out so it can be
    /// tested against a real `/proc/net/route` body on a host that has none.
    fn parse_default_route(table: &str) -> Result<String> {
        let mut defaults: Vec<(u32, String)> = table
            .lines()
            .skip(1)
            .filter_map(|line| {
                let mut f = line.split_whitespace();
                let iface = f.next()?;
                let destination = f.next()?;
                // Columns: Iface Destination Gateway Flags RefCnt Use Metric …
                let metric = f.nth(4)?.parse().unwrap_or(u32::MAX);
                (destination == "00000000").then(|| (metric, iface.to_string()))
            })
            .collect();
        defaults.sort();
        defaults.into_iter().next().map(|(_, i)| i).ok_or_else(|| {
            anyhow!(
                "no IPv4 default route in {PROC_ROUTE} — there is no uplink to NAT guest \
                 traffic out of, so this node cannot give a guest a network"
            )
        })
    }

    /// The host's IPv4 forwarding switch.
    ///
    /// Written through `/proc` rather than by shelling out to `sysctl`, for the
    /// same reason the TAP is made with ioctls rather than `ip`: every host
    /// binary this backend depends on is one a minimal or A/B-updated node can
    /// be missing.
    const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

    /// Resolve `bin` against `PATH`, failing with a message naming it.
    ///
    /// The startup-time half of [`run`]'s "is it installed on this node?":
    /// asked once, when the backend attaches, instead of at the first deploy
    /// that needs it.
    pub fn find_on_path(bin: &str) -> Result<PathBuf> {
        std::env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .filter(|d| !d.is_empty())
            .map(|d| Path::new(d).join(bin))
            .find(|p| p.is_file())
            .ok_or_else(|| {
                anyhow!(
                    "no `{bin}` on PATH — guest NAT needs it, so this node cannot give a \
                     guest a network (on Debian it is the `{bin}` package, which docker.io \
                     depends on)"
                )
            })
    }

    /// Create and bring up the TAP for `slot`, and NAT it out `net.uplink`.
    ///
    /// Four pieces of host state, all of which have to be right before a packet
    /// leaves the guest — R605-F22 found that the first two were not enough,
    /// because a routed guest is not the same thing as a guest with an address:
    ///
    /// 1. the TAP device, with the host end of the `/30` on it,
    /// 2. a NAT rule so the guest's RFC1918 source address survives the uplink,
    /// 3. **IPv4 forwarding**, which is off by default on Debian and without
    ///    which the host drops every guest packet silently, and
    /// 4. **`FORWARD` accepts** for the pair, because a node whose `FORWARD`
    ///    policy is `DROP` — which is any node with docker installed — drops
    ///    them just as silently with forwarding on.
    ///
    /// Piece 1 is ioctls against `/dev/net/tun` and an `AF_INET` socket, not
    /// `ip tuntap` / `ip addr` / `ip link` (R605-F36). The Pi appliances are
    /// A/B-updated images, and us-west-014's system slot shipped without
    /// iproute2 at all, so a backend that shelled out to `ip` would attach on
    /// that node and then fail every networked deploy. The kernel interface
    /// the `ip` commands used is three ioctls; depending on the binary bought
    /// nothing but that failure. NAT is still `iptables` (see
    /// [`GuestNetwork::discover`] for how its absence is reported) because
    /// nf_tables over netlink is not a contained replacement.
    pub async fn create_tap(slot: &GuestSlot, net: &GuestNetwork) -> Result<()> {
        // Idempotent: a leaked TAP from a previous kamaji generation must not
        // wedge the slot forever. Destroying a nonexistent device is a no-op
        // we deliberately ignore.
        let _ = delete_tap(slot, net).await;

        tap::create(&slot.tap)?;
        tap::assign(&slot.tap, slot.host_ip)?;

        enable_ip_forwarding()
            .await
            .context("could not enable IPv4 forwarding — the guest would boot and reach nothing")?;

        run("iptables", &masquerade_rule("-A", slot, net))
            .await
            .context("iptables MASQUERADE failed — the guest will boot but reach nothing")?;
        for rule in forward_rules("-I", slot, net) {
            run("iptables", &rule).await.context(
                "iptables FORWARD accept failed — the guest will boot but reach nothing",
            )?;
        }
        Ok(())
    }

    /// Remove the TAP and every rule `create_tap` added. Best-effort and
    /// idempotent: teardown runs on paths where some of this was never created.
    pub async fn delete_tap(slot: &GuestSlot, net: &GuestNetwork) -> Result<()> {
        for rule in forward_rules("-D", slot, net) {
            let _ = run("iptables", &rule).await;
        }
        let _ = run("iptables", &masquerade_rule("-D", slot, net)).await;
        tap::destroy(&slot.tap)
    }

    /// The TAP device itself, through the kernel's own interface.
    ///
    /// What `ip tuntap add|del` and `ip addr add` + `ip link set up` did,
    /// minus the binary: `TUNSETIFF` names and creates the device on a
    /// `/dev/net/tun` fd, `TUNSETPERSIST` keeps it after that fd closes (so
    /// Firecracker can attach by name, exactly as it did to an `ip`-made one),
    /// and the address, netmask and `IFF_UP` are `SIOCSIF*` on any `AF_INET`
    /// socket. Flags match `ip tuntap add mode tap`: `IFF_TAP | IFF_NO_PI`.
    /// Firecracker re-attaches with `IFF_VNET_HDR` added, which the kernel
    /// accepts on a persistent device — it only refuses a multi-queue
    /// mismatch.
    #[cfg(target_os = "linux")]
    mod tap {
        use std::ffi::CString;
        use std::io;
        use std::net::Ipv4Addr;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        use anyhow::{anyhow, bail, Context, Result};

        const TUN_DEV: &str = "/dev/net/tun";
        /// The /30 every slot's host end sits on.
        const SLOT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 252);

        /// An `ifreq` naming `name`, payload zeroed.
        fn ifreq(name: &str) -> Result<libc::ifreq> {
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) {
                bail!("{name:?} is not a valid interface name (1-15 bytes, no NUL)");
            }
            // SAFETY: ifreq is plain old data — an all-zero value is a valid
            // empty request.
            let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
            for (dst, src) in req.ifr_name.iter_mut().zip(bytes) {
                *dst = *src as libc::c_char;
            }
            Ok(req)
        }

        fn ioctl(fd: &OwnedFd, op: libc::Ioctl, req: &mut libc::ifreq, what: &str) -> Result<()> {
            // SAFETY: every op used here takes a `struct ifreq *`, and `req`
            // is a live, correctly-sized one for the duration of the call.
            if unsafe { libc::ioctl(fd.as_raw_fd(), op, req as *mut libc::ifreq) } < 0 {
                let err = io::Error::last_os_error();
                let hint = if err.raw_os_error() == Some(libc::EPERM) {
                    " — this needs CAP_NET_ADMIN"
                } else {
                    ""
                };
                return Err(anyhow!("{what} failed: {err}{hint}"));
            }
            Ok(())
        }

        /// A `/dev/net/tun` fd bound to `name` as a TAP. If no such device
        /// exists the kernel creates one, owned by this fd.
        fn attach(name: &str) -> Result<OwnedFd> {
            let path = CString::new(TUN_DEV).expect("static path has no NUL");
            // SAFETY: a valid C string and flags; the result is checked.
            let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
            if raw < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("opening {TUN_DEV} — is the tun module present?"));
            }
            // SAFETY: `raw` is a freshly opened fd that nothing else owns.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut req = ifreq(name)?;
            req.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
            ioctl(&fd, libc::TUNSETIFF, &mut req, &format!("TUNSETIFF {name}"))?;
            Ok(fd)
        }

        fn set_persist(fd: &OwnedFd, name: &str, on: bool) -> Result<()> {
            // SAFETY: TUNSETPERSIST takes its argument by value, not by pointer.
            if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETPERSIST, libc::c_ulong::from(on)) } < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("TUNSETPERSIST({on}) {name}"));
            }
            Ok(())
        }

        /// Create persistent TAP `name`.
        pub fn create(name: &str) -> Result<()> {
            let fd = attach(name)?;
            set_persist(&fd, name, true)
        }

        /// Remove TAP `name`. A device that does not exist is not an error:
        /// attaching creates a non-persistent one, which vanishes when the fd
        /// drops.
        pub fn destroy(name: &str) -> Result<()> {
            let fd = attach(name)?;
            set_persist(&fd, name, false)
        }

        /// Give `name` the host end of its slot's /30 and bring it up.
        pub fn assign(name: &str, host_ip: Ipv4Addr) -> Result<()> {
            // SAFETY: plain socket(2); the result is checked.
            let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if raw < 0 {
                return Err(io::Error::last_os_error()).context("socket(AF_INET) for TAP setup");
            }
            // SAFETY: `raw` is a freshly created fd that nothing else owns.
            let sock = unsafe { OwnedFd::from_raw_fd(raw) };

            let mut req = ifreq(name)?;
            req.ifr_ifru.ifru_addr = sockaddr(host_ip);
            ioctl(&sock, libc::SIOCSIFADDR as libc::Ioctl, &mut req, &format!("SIOCSIFADDR {name}"))?;

            let mut req = ifreq(name)?;
            req.ifr_ifru.ifru_netmask = sockaddr(SLOT_NETMASK);
            ioctl(&sock, libc::SIOCSIFNETMASK as libc::Ioctl, &mut req, &format!("SIOCSIFNETMASK {name}"))?;

            let mut req = ifreq(name)?;
            ioctl(&sock, libc::SIOCGIFFLAGS as libc::Ioctl, &mut req, &format!("SIOCGIFFLAGS {name}"))?;
            // SAFETY: SIOCGIFFLAGS just filled the flags member of the union.
            unsafe { req.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short };
            ioctl(&sock, libc::SIOCSIFFLAGS as libc::Ioctl, &mut req, &format!("SIOCSIFFLAGS {name}"))
        }

        fn sockaddr(ip: Ipv4Addr) -> libc::sockaddr {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: u32::from(ip).to_be() },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in and sockaddr are both 16 bytes, and an
            // AF_INET sockaddr is by definition a sockaddr_in.
            unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sin) }
        }
    }

    /// TAP devices are a Linux kernel interface; a guest only ever runs there.
    #[cfg(not(target_os = "linux"))]
    mod tap {
        use anyhow::{bail, Result};
        use std::net::Ipv4Addr;

        pub fn create(name: &str) -> Result<()> {
            bail!("cannot create TAP {name}: TAP devices are Linux-only")
        }
        pub fn destroy(_name: &str) -> Result<()> {
            Ok(())
        }
        pub fn assign(name: &str, _host_ip: Ipv4Addr) -> Result<()> {
            bail!("cannot address TAP {name}: TAP devices are Linux-only")
        }
    }

    /// Turn on IPv4 forwarding if it is off.
    ///
    /// Read-then-write rather than an unconditional write so that a node whose
    /// operator already enabled it — the overwhelmingly common case on anything
    /// that has ever run a container — is not touched at all, and so the write
    /// that *does* happen is attributable to kamaji.
    ///
    /// This is deliberately host-global, and it is the one piece of state here
    /// that outlives the guest: `delete_tap` does not turn it back off, because
    /// kamaji cannot know whether it or something else on the node is relying on
    /// it, and a teardown that silently breaks the node's other routing is worse
    /// than a switch left on.
    async fn enable_ip_forwarding() -> Result<()> {
        let current = tokio::fs::read_to_string(IP_FORWARD)
            .await
            .with_context(|| format!("reading {IP_FORWARD}"))?;
        if current.trim() == "1" {
            return Ok(());
        }
        tokio::fs::write(IP_FORWARD, b"1\n")
            .await
            .with_context(|| format!("writing {IP_FORWARD} — this needs CAP_NET_ADMIN"))?;
        tracing::info!("enabled net.ipv4.ip_forward for microVM guest networking");
        Ok(())
    }

    /// The NAT rule, built once so the `-A` and `-D` forms cannot drift apart.
    ///
    /// A rule added with one argument list and deleted with a different one
    /// leaks on every teardown, and iptables reports nothing when `-D` matches
    /// no rule — so the two halves being one function is the only thing that
    /// keeps them honest.
    fn masquerade_rule(op: &str, slot: &GuestSlot, net: &GuestNetwork) -> Vec<String> {
        vec![
            "-t".into(),
            "nat".into(),
            op.into(),
            "POSTROUTING".into(),
            "-s".into(),
            format!("{}/30", slot.guest_ip),
            "-o".into(),
            net.uplink.clone(),
            "-j".into(),
            "MASQUERADE".into(),
        ]
    }

    /// The two `FORWARD` accepts: guest → uplink, and the replies back.
    ///
    /// Return traffic is matched on connection state rather than accepted
    /// outright, so the rule opens the path the guest asked for and not a path
    /// into the guest from the uplink.
    fn forward_rules(op: &str, slot: &GuestSlot, net: &GuestNetwork) -> [Vec<String>; 2] {
        let subnet = format!("{}/30", slot.guest_ip);
        [
            vec![
                op.into(),
                "FORWARD".into(),
                "-s".into(),
                subnet.clone(),
                "-i".into(),
                slot.tap.clone(),
                "-o".into(),
                net.uplink.clone(),
                "-j".into(),
                "ACCEPT".into(),
            ],
            vec![
                op.into(),
                "FORWARD".into(),
                "-d".into(),
                subnet,
                "-i".into(),
                net.uplink.clone(),
                "-o".into(),
                slot.tap.clone(),
                "-m".into(),
                "conntrack".into(),
                "--ctstate".into(),
                "RELATED,ESTABLISHED".into(),
                "-j".into(),
                "ACCEPT".into(),
            ],
        ]
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn slot() -> GuestSlot {
            GuestSlot::derive(&GuestNetwork::for_uplink("eth0"), 0).unwrap()
        }

        /// Verbatim from us-west-003's class of host: predictable interface
        /// names, a default route, and a directly-connected subnet route that
        /// must not be mistaken for one.
        const ROUTE_TABLE: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
enp2s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
enp2s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";

        /// The uplink is the default route's interface, not the first line.
        ///
        /// This is the parse that replaced a hardcoded `eth0`, and the failure
        /// it has to avoid is subtle: picking the *subnet* route's interface
        /// happens to give the right answer on a single-homed box, so a wrong
        /// implementation passes everywhere until it does not.
        #[test]
        fn the_uplink_is_the_interface_carrying_the_default_route() {
            assert_eq!(parse_default_route(ROUTE_TABLE).unwrap(), "enp2s0");
        }

        /// Two default routes: the cheaper one carries the traffic.
        #[test]
        fn the_lowest_metric_default_route_wins() {
            let dual = format!("{ROUTE_TABLE}wlp3s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n");
            assert_eq!(parse_default_route(&dual).unwrap(), "enp2s0");
            // Same two routes with the expensive one listed first: the answer
            // must come from the metric column and not from file order.
            let reordered =
                "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                 wlp3s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                 enp2s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
            assert_eq!(parse_default_route(reordered).unwrap(), "enp2s0");
        }

        /// A node with no route out says so, rather than naming an interface
        /// that cannot carry guest traffic.
        #[test]
        fn a_host_with_no_default_route_is_an_error_and_not_a_guess() {
            let no_default = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                              enp2s0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
            let err = parse_default_route(no_default).unwrap_err().to_string();
            assert!(err.contains("no IPv4 default route"), "got {err}");
        }

        /// The add and delete forms must differ in exactly one token.
        ///
        /// This is the property that stops a teardown leaking rules into the
        /// host's `FORWARD` chain forever — `iptables -D` against a spec that
        /// does not match reports nothing, so a drift between the two lists is
        /// silent at the point it happens and shows up months later as a chain
        /// with a thousand dead entries.
        #[test]
        fn every_rule_is_deleted_with_the_argument_list_it_was_added_with() {
            let (s, net) = (slot(), GuestNetwork::for_uplink("eth0"));
            let pairs = std::iter::once((masquerade_rule("-A", &s, &net), masquerade_rule("-D", &s, &net)))
                .chain(forward_rules("-I", &s, &net).into_iter().zip(forward_rules("-D", &s, &net)));
            for (add, del) in pairs {
                assert_eq!(add.len(), del.len(), "add/delete disagree in length");
                let differing: Vec<_> = add
                    .iter()
                    .zip(&del)
                    .filter(|(a, d)| a != d)
                    .collect();
                assert_eq!(
                    differing.len(),
                    1,
                    "add and delete differ in more than the operation: {differing:?}"
                );
                assert!(del.contains(&"-D".to_string()), "delete form is not a -D: {del:?}");
            }
        }

        /// The native TAP path does what `ip tuntap add` + `ip addr add` +
        /// `ip link set up` did, with no iproute2 involved (R605-F36).
        ///
        /// Runs for real only as root on Linux (CI containers run privileged,
        /// a node runs kamaji as root); skips elsewhere, saying so. The
        /// kernel's connected route is the readback: it exists only once the
        /// address and the /30 netmask are both on the device.
        #[cfg(target_os = "linux")]
        #[test]
        fn a_tap_is_created_addressed_and_removed_without_iproute2() {
            // SAFETY: geteuid has no preconditions.
            if unsafe { libc::geteuid() } != 0 || !Path::new("/dev/net/tun").exists() {
                eprintln!("SKIP: needs root and /dev/net/tun");
                return;
            }
            let name = "yahtaptest0";
            let sys = Path::new("/sys/class/net").join(name);
            let _ = tap::destroy(name);

            tap::create(name).expect("create");
            assert!(sys.exists(), "TUNSETPERSIST must keep the device after the fd closes");
            tap::assign(name, Ipv4Addr::new(172, 30, 255, 1)).expect("assign");

            let flags = std::fs::read_to_string(sys.join("flags")).unwrap();
            let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap();
            assert_eq!(flags & libc::IFF_UP as u32, libc::IFF_UP as u32, "device must be up");
            // 172.30.255.0/30, little-endian hex as /proc/net/route prints it.
            let routes = std::fs::read_to_string(PROC_ROUTE).unwrap();
            assert!(
                routes.lines().any(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    f.first() == Some(&name) && f.get(1) == Some(&"00FF1EAC") && f.get(7) == Some(&"FCFFFFFF")
                }),
                "no connected 172.30.255.0/30 route on {name}:\n{routes}"
            );

            tap::destroy(name).expect("destroy");
            assert!(!sys.exists(), "destroy must remove the persistent device");
            tap::destroy(name).expect("destroying an absent TAP is a no-op");
        }

        /// Return traffic is state-matched, not blanket-accepted.
        #[test]
        fn the_return_forward_rule_does_not_open_a_path_into_the_guest() {
            let (s, net) = (slot(), GuestNetwork::for_uplink("eth0"));
            let [out, back] = forward_rules("-I", &s, &net);
            // Outbound is scoped to the guest's own /30 leaving on the uplink.
            assert!(out.windows(2).any(|w| w == ["-i", s.tap.as_str()]));
            assert!(out.windows(2).any(|w| w == ["-o", net.uplink.as_str()]));
            // Inbound only for connections the guest already established.
            assert!(back.windows(2).any(|w| w == ["--ctstate", "RELATED,ESTABLISHED"]));
            assert!(back.windows(2).any(|w| w == ["-o", s.tap.as_str()]));
        }
    }
}

/// Where a Firecracker install lands when `PATH` does not say.
///
/// `/usr/local/bin` first because that is where an install-from-tarball puts
/// it — which is how every Firecracker on this fleet got there, upstream
/// shipping no Debian package.
const VMM_FALLBACK_DIRS: [&str; 3] = ["/usr/local/bin", "/usr/bin", "/opt/firecracker/bin"];

/// Locate the `firecracker` binary.
///
/// R605-F22: this replaced a hardcoded `/usr/bin/firecracker` in
/// `kamaji-bin`, which does not exist on the one node in this fleet that has
/// guest artifacts staged — Firecracker ships no Debian package, so the
/// install path is `/usr/local/bin/firecracker`. `MicroVmRuntime::new`
/// refuses to construct on an absent `vmm_bin`, so the effect of the wrong
/// constant was that a kamaji started with `--microvm-dir` on a correctly
/// provisioned node would refuse to start at all. Same shape as the `eth0`
/// uplink default: a path guessed once, never exercised, wrong everywhere.
///
/// The node's own `microvm_dir` is searched first, then `PATH`, then the
/// fallback dirs. The microVM dir already holds every other piece of guest
/// material (kernel, rootfs, service and toolchain images), and on the Pi
/// appliances it is the only one of these locations guaranteed to be on the
/// data disk: their system slot is a flashed A/B image, and when us-west-014's
/// SD card died and was reflashed (2026-09-22) its `/usr/local/bin/firecracker`
/// symlink went with the card while the binary it pointed at survived on the
/// NVMe (R605-F36). us-west-011/013 still keep `/usr/local/bin` on the SD. A
/// VMM staged beside the kernel survives whatever the kernel survives. A node that installs it system-wide (us-west-003) is
/// unaffected, since its dir holds no `firecracker`.
pub fn find_vmm(microvm_dir: &Path) -> Result<PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    let found = std::iter::once(microvm_dir)
        .chain(path.split(':').filter(|d| !d.is_empty()).map(Path::new))
        .chain(VMM_FALLBACK_DIRS.iter().map(Path::new))
        .map(|dir| dir.join("firecracker"))
        .find(|p| p.is_file());
    found.ok_or_else(|| {
        anyhow!(
            "no `firecracker` in {}, on PATH, or in {} — a microVM node needs the VMM \
             installed; upstream ships no Debian package, so stage the release tarball's \
             binary in the microVM dir (or install it into /usr/local/bin)",
            microvm_dir.display(),
            VMM_FALLBACK_DIRS.join(", ")
        )
    })
}

/// Run a host command, failing with its stderr rather than just its exit code.
///
/// Every privileged step in this module goes through here so that a node
/// missing `e2fsprogs`, or a kamaji without `CAP_NET_ADMIN`, produces a message
/// naming the tool and quoting what it said — the two failures this backend is
/// most likely to hit on a fresh node, and the two that are most opaque when
/// reported as "exit status 1".
async fn run<S: AsRef<std::ffi::OsStr>>(bin: &str, args: &[S]) -> Result<()> {
    let out = tokio::process::Command::new(bin)
        .args(args)
        .output()
        .await
        .with_context(|| format!("spawning `{bin}` — is it installed on this node?"))?;
    if !out.status.success() {
        bail!(
            "`{bin}` failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{EnvVar, ImageRef, ResourceLimits, TierTag};

    fn cfg() -> MicroVmConfig {
        MicroVmConfig {
            vmm_bin: PathBuf::from("/usr/bin/firecracker"),
            kernel_image: PathBuf::from("/var/lib/yah/microvm/vmlinux"),
            rootfs_image: PathBuf::from("/var/lib/yah/microvm/rootfs.ext4"),
            service_rootfs_image: Some(PathBuf::from("/var/lib/yah/microvm/service-rootfs.ext4")),
            toolchain_image: None,
            state_dir: PathBuf::from("/var/lib/yah/microvm/vms"),
            network: Some(GuestNetwork::for_uplink("eth0")),
            max_guest_memory_mb: 8192,
            max_guest_vcpus: 4,
        }
    }

    /// The same node, with a build toolchain staged.
    fn cfg_with_toolchain() -> MicroVmConfig {
        MicroVmConfig {
            toolchain_image: Some(PathBuf::from("/var/lib/yah/microvm/toolchain.ext4")),
            ..cfg()
        }
    }

    fn spec(name: &str) -> WorkloadSpec {
        let mut spec = WorkloadSpec::for_forge(
            name,
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
        spec.command = Some(vec!["cargo".into(), "build".into(), "--release".into()]);
        spec
    }

    /// The same workload, declared as something meant to still be there
    /// tomorrow (R605-F31).
    ///
    /// Declared explicitly rather than inferred, because the point of the
    /// archetype field is that a workload gets to *say* what it is: the
    /// inference `LifecycleArchetype::infer` applies to specs written before the
    /// field existed reads `RestartPolicy::Never` + no volumes as `Job`, which
    /// is exactly what a forge spec is and exactly what this is not.
    fn service_spec(name: &str) -> WorkloadSpec {
        let mut spec = spec(name);
        spec.archetype = Some(workload_spec::LifecycleArchetype::Server);
        spec.restart_policy = RestartPolicy::Always;
        spec
    }

    /// The VM dir a workload's private state lives in, for the root helpers.
    fn vm_dir() -> PathBuf {
        PathBuf::from("/var/lib/yah/microvm/vms/b")
    }

    /// What a job-shaped guest boots: the node's one shared image, read-only.
    fn job_root() -> RootDisk {
        RootDisk::for_shape(&cfg(), VmShape::Job, &vm_dir()).unwrap()
    }

    /// What a service-shaped guest boots: its own copy, writable.
    fn service_root() -> RootDisk {
        RootDisk::for_shape(&cfg(), VmShape::Service, &vm_dir()).unwrap()
    }

    /// A constructible backend rooted in `tmp` — the guest material only has to
    /// *exist* for `MicroVmRuntime::new`, which is what these tests need.
    fn runtime_on(tmp: &tempfile::TempDir) -> MicroVmRuntime {
        let mut c = cfg();
        for p in [
            "firecracker",
            "vmlinux",
            "rootfs.ext4",
            SERVICE_ROOTFS_IMAGE_FILE,
        ] {
            std::fs::write(tmp.path().join(p), b"").unwrap();
        }
        c.vmm_bin = tmp.path().join("firecracker");
        c.kernel_image = tmp.path().join("vmlinux");
        c.rootfs_image = tmp.path().join("rootfs.ext4");
        c.service_rootfs_image = Some(tmp.path().join(SERVICE_ROOTFS_IMAGE_FILE));
        c.state_dir = tmp.path().join("vms");
        MicroVmRuntime::new(c).unwrap()
    }

    /// Register a workload of `shape` without booting a hypervisor, returning
    /// the control channel a real supervisor would be reading.
    ///
    /// The lifecycle branches this backend gained in R605-F31 are decided from
    /// the registry entry, not from anything a guest does, so they are testable
    /// on a host with no `/dev/kvm` — which is every host in this camp.
    async fn register(
        rt: &MicroVmRuntime,
        ident: &str,
        shape: VmShape,
    ) -> mpsc::Receiver<Ctrl<BootedGuest>> {
        let (ctrl_tx, ctrl_rx) = mpsc::channel(1);
        let (status_tx, status_rx) = watch::channel(WorkloadStatus::Running);
        // Kept alive for the life of the handle, as the real supervisor's is.
        let task = tokio::spawn(async move {
            status_tx.closed().await;
        });
        rt.vms.lock().await.insert(
            ident.to_string(),
            VmHandle {
                slot: None,
                mesh_ip: Ipv4Addr::new(100, 64, 0, 9),
                vm_dir: rt.cfg.state_dir.join(ident),
                console_path: rt.cfg.state_dir.join(ident).join("console.log"),
                shape,
                pid: Arc::new(AtomicU32::new(0)),
                status: status_rx,
                ctrl: ctrl_tx,
                task,
            },
        );
        ctrl_rx
    }

    // ── Slot arithmetic ─────────────────────────────────────────────────────

    #[test]
    fn slots_take_non_overlapping_slash_30s() {
        let net = GuestNetwork::for_uplink("eth0");
        let a = GuestSlot::derive(&net, 0).unwrap();
        let b = GuestSlot::derive(&net, 1).unwrap();

        assert_eq!(a.host_ip, Ipv4Addr::new(172, 30, 0, 1));
        assert_eq!(a.guest_ip, Ipv4Addr::new(172, 30, 0, 2));
        assert_eq!(b.host_ip, Ipv4Addr::new(172, 30, 0, 5));
        assert_eq!(b.guest_ip, Ipv4Addr::new(172, 30, 0, 6));

        // The property that actually matters: no address is in two slots, so
        // two concurrent builds on one node cannot see each other's traffic.
        assert_ne!(a.guest_ip, b.host_ip);
        assert_ne!(a.host_ip, b.guest_ip);
        assert_ne!(a.tap, b.tap);
        assert_ne!(a.mac, b.mac);
    }

    #[test]
    fn slot_addresses_never_collide_across_the_first_hundred() {
        let net = GuestNetwork::for_uplink("eth0");
        let mut seen = std::collections::HashSet::new();
        for i in 0..100 {
            let s = GuestSlot::derive(&net, i).unwrap();
            assert!(seen.insert(s.host_ip), "host ip reused at slot {i}");
            assert!(seen.insert(s.guest_ip), "guest ip reused at slot {i}");
            assert!(seen.insert(Ipv4Addr::from(u32::from(s.guest_ip) + 1)), "broadcast reused at slot {i}");
        }
    }

    #[test]
    fn an_over_long_tap_prefix_is_refused_rather_than_truncated() {
        // Linux caps IFNAMSIZ at 16 including the NUL. A truncated name would
        // silently alias two slots onto one device — the exact collision the
        // /30 scheme exists to prevent — so this fails at derive time.
        let net = GuestNetwork {
            tap_prefix: "a-very-long-prefix".into(),
            ..GuestNetwork::for_uplink("eth0")
        };
        let err = GuestSlot::derive(&net, 0).unwrap_err().to_string();
        assert!(err.contains("15-character"), "got {err}");
    }

    #[test]
    fn kernel_ip_arg_points_the_guest_at_its_own_host_end() {
        let slot = GuestSlot::derive(&GuestNetwork::for_uplink("eth0"), 2).unwrap();
        assert_eq!(
            slot.kernel_ip_arg(),
            "ip=172.30.0.10::172.30.0.9:255.255.255.252::eth0:off"
        );
    }

    // ── Resource translation ────────────────────────────────────────────────

    #[test]
    fn a_forge_ceiling_is_clamped_to_what_the_node_can_actually_hand_out() {
        // The regression this exists for: `for_forge` sets a 32 GiB cgroup
        // ceiling, and the OVH nodes have 11682 MB of RAM in total. Read
        // literally, every forge microVM would fail to boot.
        let spec = spec("v8-build");
        assert!(
            spec.resources.memory_mb > cfg().max_guest_memory_mb,
            "test is vacuous unless the spec ceiling exceeds the node cap"
        );
        assert_eq!(guest_memory_mb(&cfg(), &spec).unwrap(), 8192);
    }

    #[test]
    fn a_guest_is_never_smaller_than_the_request_admission_already_approved() {
        let mut spec = spec("tiny");
        spec.resources.memory_mb = 64;
        // for_forge's placement floor is 2 GiB, and admission already found
        // that much free on the node — booting a 64 MiB guest would be
        // narrower than the scheduler's own arithmetic.
        assert_eq!(guest_memory_mb(&cfg(), &spec).unwrap(), 2048);
    }

    #[test]
    fn a_request_above_the_node_cap_is_refused_at_deploy_not_at_oom() {
        let mut cfg = cfg();
        cfg.max_guest_memory_mb = 1024;
        let spec = spec("too-big");
        let err = guest_memory_mb(&cfg, &spec).unwrap_err().to_string();
        assert!(err.contains("1024"), "message must name the node cap: {err}");
        assert!(err.contains("2048"), "message must name the request: {err}");
    }

    #[test]
    fn vcpus_round_up_and_cap() {
        let mut spec = spec("cpu");
        spec.resources = ResourceLimits {
            memory_mb: 4096,
            cpu_millis: 1500,
            memory_request_mb: None,
            cpu_limit_millis: None,
            pids_max: None,
            scratch_floor_mb: None,
        };
        // 1.5 cores rounds up to 2: a VM cannot be scheduled onto a fraction.
        assert_eq!(guest_vcpus(&cfg(), &spec), 2);

        spec.resources.cpu_millis = 99_000;
        assert_eq!(guest_vcpus(&cfg(), &spec), 4, "node cap applies");

        spec.resources.cpu_millis = 0;
        assert_eq!(guest_vcpus(&cfg(), &spec), 1, "never zero vCPUs");
    }

    // ── The VM definition ───────────────────────────────────────────────────

    #[test]
    fn the_rootfs_is_read_only_and_the_workspace_is_not() {
        let slot = GuestSlot::derive(&GuestNetwork::for_uplink("eth0"), 0).unwrap();
        let vm = vmm_config(&cfg(), &spec("b"), Some(&slot), Path::new("/w/workspace.ext4"), &job_root()).unwrap();

        let root = vm.drives.iter().find(|d| d.is_root_device).unwrap();
        assert!(
            root.is_read_only,
            "a writable shared rootfs lets job N leave state for job N+1"
        );
        assert_eq!(
            root.path_on_host, "/var/lib/yah/microvm/rootfs.ext4",
            "a job boots the NODE's image — that sharing is why it must stay read-only"
        );
        let work = vm.drives.iter().find(|d| d.drive_id == "workspace").unwrap();
        assert!(!work.is_read_only);
        assert!(!work.is_root_device);
    }

    /// The other half of the property above (R605-F31).
    ///
    /// A service is allowed a writable root, and the reason it is allowed one is
    /// **not** that the rule was relaxed — it is that a service does not share
    /// the image the rule is about. Both halves are asserted together here
    /// because checking only `is_read_only == false` would pass just as happily
    /// if someone had flipped the flag on the node's shared image, which is the
    /// single edit that silently destroys the guarantee.
    #[test]
    fn a_service_gets_its_own_root_and_never_writes_the_nodes() {
        let vm = vmm_config(
            &cfg(),
            &service_spec("s"),
            None,
            Path::new("/w/d.ext4"),
            &service_root(),
        )
        .unwrap();

        let root = vm.drives.iter().find(|d| d.is_root_device).unwrap();
        assert!(!root.is_read_only, "a service's root is the workload's, not the node's");
        assert_eq!(
            root.path_on_host, "/var/lib/yah/microvm/vms/b/rootfs.ext4",
            "the writable root is a PRIVATE copy inside the workload's own VM dir"
        );
        assert_ne!(
            root.path_on_host,
            cfg().rootfs_image.to_string_lossy(),
            "the node's shared image must never be the thing a guest writes to"
        );
    }

    /// R605-F32: a service's private root starts as the node's SERVICE image,
    /// and a job still boots the job image in place with nothing to seed.
    #[test]
    fn a_service_root_is_seeded_from_the_service_image_not_the_job_image() {
        assert_eq!(
            service_root().seed.as_deref(),
            Some(Path::new("/var/lib/yah/microvm/service-rootfs.ext4"))
        );
        assert_eq!(job_root().seed, None, "a job boots the node image in place");
    }

    /// No service image staged means no service-shaped guest — refused, never
    /// seeded from the job image, which cannot host what a service is for.
    #[test]
    fn a_node_with_no_service_image_refuses_a_service_rather_than_falling_back() {
        let jobs_only = MicroVmConfig {
            service_rootfs_image: None,
            ..cfg()
        };
        let err = RootDisk::for_shape(&jobs_only, VmShape::Service, &vm_dir())
            .unwrap_err()
            .to_string();
        assert!(err.contains(SERVICE_ROOTFS_IMAGE_FILE), "{err}");
        // Jobs are unaffected by the absence.
        assert!(RootDisk::for_shape(&jobs_only, VmShape::Job, &vm_dir()).is_ok());
    }

    /// Named but missing is an operator's typo, refused at construction like a
    /// missing toolchain — not a node that silently runs jobs only.
    #[test]
    fn a_named_but_missing_service_image_refuses_construction() {
        let tmp = tempfile::tempdir().unwrap();
        for p in ["firecracker", "vmlinux", "rootfs.ext4"] {
            std::fs::write(tmp.path().join(p), b"").unwrap();
        }
        let c = MicroVmConfig {
            vmm_bin: tmp.path().join("firecracker"),
            kernel_image: tmp.path().join("vmlinux"),
            rootfs_image: tmp.path().join("rootfs.ext4"),
            service_rootfs_image: Some(tmp.path().join(SERVICE_ROOTFS_IMAGE_FILE)),
            state_dir: tmp.path().join("vms"),
            ..cfg()
        };
        let err = match MicroVmRuntime::new(c) {
            Ok(_) => panic!("a missing service image must refuse construction"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("service root image not found"), "{err}");
    }

    /// Seeding copies the service image once, and a redeploy KEEPS the root —
    /// it is the workload's state, and re-seeding would erase it.
    #[tokio::test]
    async fn provisioning_seeds_once_and_never_overwrites_a_services_root() {
        let tmp = tempfile::tempdir().unwrap();
        let svc_image = tmp.path().join(SERVICE_ROOTFS_IMAGE_FILE);
        std::fs::write(&svc_image, b"pristine service image").unwrap();
        let c = MicroVmConfig {
            service_rootfs_image: Some(svc_image),
            ..cfg()
        };
        let vm = tmp.path().join("vms/s");
        std::fs::create_dir_all(&vm).unwrap();
        let root = RootDisk::for_shape(&c, VmShape::Service, &vm).unwrap();

        root.provision().await.unwrap();
        assert_eq!(std::fs::read(&root.path).unwrap(), b"pristine service image");

        std::fs::write(&root.path, b"state the appliance accumulated").unwrap();
        root.provision().await.unwrap();
        assert_eq!(
            std::fs::read(&root.path).unwrap(),
            b"state the appliance accumulated"
        );
    }

    /// The shape comes from the archetype, through the one seam the rest of the
    /// fleet uses to ask the same question.
    #[test]
    fn the_shape_is_read_off_the_archetype_not_off_a_flag() {
        // A forge spec: Never + no volumes infers Job, per the pre-R572
        // convention `effective_archetype` preserves.
        assert_eq!(VmShape::of_spec(&spec("b")), VmShape::Job);
        assert_eq!(VmShape::of_spec(&service_spec("s")), VmShape::Service);

        // Appliance is service-shaped too: the Server/Appliance distinction is
        // the scheduler's question (may this move?), not the hypervisor's.
        let mut appliance = spec("a");
        appliance.archetype = Some(workload_spec::LifecycleArchetype::Appliance);
        appliance.restart_policy = RestartPolicy::Always;
        assert_eq!(VmShape::of_spec(&appliance), VmShape::Service);
    }

    /// R605-F23's whole argument, as an assertion.
    ///
    /// The ticket treated "mounted toolchain" as reintroducing the mutable
    /// per-node state the read-only rootfs exists to eliminate. It does not, and
    /// this is the line that keeps it not doing so: if a future change ever
    /// makes the toolchain volume writable, the correctness property the rootfs
    /// is read-only *for* is gone, and the baked-vs-mounted fork becomes real
    /// again.
    #[test]
    fn the_toolchain_volume_is_as_read_only_as_the_rootfs() {
        let vm = vmm_config(&cfg_with_toolchain(), &spec("b"), None, Path::new("/w/d.ext4"), &job_root()).unwrap();

        let tc = vm
            .drives
            .iter()
            .find(|d| d.drive_id == "toolchain")
            .expect("a node with a staged toolchain attaches it");
        assert!(
            tc.is_read_only,
            "a writable toolchain volume lets job N leave state for job N+1 — the exact \
             property that made the rootfs read-only, and the exact reason R605-F23 thought \
             mounting was the worse half of the fork"
        );
        assert!(!tc.is_root_device);
        assert_eq!(tc.path_on_host, "/var/lib/yah/microvm/toolchain.ext4");
    }

    #[test]
    fn a_node_without_a_toolchain_attaches_two_drives_and_still_boots() {
        // Absent is a legitimate configuration, not a degraded one: it is what
        // every node ran before R605-F23, and the guest still mounts and still
        // runs argv. The drive list must not grow a hole for it.
        let vm = vmm_config(&cfg(), &spec("b"), None, Path::new("/w/d.ext4"), &job_root()).unwrap();
        assert_eq!(vm.drives.len(), 2);
        assert!(vm.drives.iter().all(|d| d.drive_id != "toolchain"));
    }

    /// The guest finds the toolchain by probing for its manifest, but it probes
    /// `/dev/vdb`, `/dev/vdc`, `/dev/vdd` in that order — which only terminates
    /// cheaply if the toolchain really is the third drive. Ordering here is a
    /// contract with `kamaji-guest-init`, not an implementation detail.
    #[test]
    fn the_toolchain_is_the_third_drive_after_the_rootfs_and_the_scratch_disk() {
        let vm = vmm_config(&cfg_with_toolchain(), &spec("b"), None, Path::new("/w/d.ext4"), &job_root()).unwrap();
        let ids: Vec<&str> = vm.drives.iter().map(|d| d.drive_id.as_str()).collect();
        assert_eq!(ids, ["rootfs", "workspace", "toolchain"]);
    }

    #[test]
    fn boot_args_make_a_panicking_guest_exit_rather_than_hang() {
        // `panic=1` (plus, on x86, `reboot=k`) is what turns "the VMM process
        // ended" into a completion signal. Without it a crashed guest is
        // indistinguishable from a slow build until teardown.
        let vm = vmm_config(&cfg(), &spec("b"), None, Path::new("/w/d.ext4"), &job_root()).unwrap();
        assert!(vm.boot_source.boot_args.contains("panic=1"));
        assert!(vm.boot_source.boot_args.contains("console=ttyS0"));
        assert!(vm
            .boot_source
            .boot_args
            .starts_with(GuestArch::host().unwrap().base_boot_args()));
    }

    /// The x86 command line is byte-for-byte the one every x86 proof from
    /// R605-F14 to F33 was taken against. R605-F32 moved it behind
    /// [`GuestArch`]; this is what proves the move changed nothing for x86,
    /// and it runs on every host, the arm64 camp Mac included.
    #[test]
    fn the_x86_command_line_is_exactly_what_f14_measured() {
        assert_eq!(
            GuestArch::X86_64.base_boot_args(),
            "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux"
        );
    }

    /// The aarch64 command line is the one R605-F32 measured booting and
    /// resetting cleanly on us-west-014, and it carries none of the x86
    /// hardware names — the hazard R605-F31 recorded was exactly an arm64
    /// kamaji handing Firecracker the x86 set.
    #[test]
    fn the_aarch64_command_line_is_what_f32_measured_and_names_no_x86_hardware() {
        let args = GuestArch::Aarch64.base_boot_args();
        assert_eq!(args, "console=ttyS0 panic=1");
        for x86_only in ["reboot=k", "i8042", "pci=off"] {
            assert!(!args.contains(x86_only), "{x86_only} names x86 hardware: {args}");
        }
    }

    /// The guest arch is the compile target's, not a default.
    #[test]
    fn the_guest_arch_is_the_hosts() {
        let expect = match std::env::consts::ARCH {
            "x86_64" => GuestArch::X86_64,
            "aarch64" => GuestArch::Aarch64,
            other => panic!("no microVM guest recipe for {other}; this test needs one"),
        };
        assert_eq!(GuestArch::host().unwrap(), expect);
    }

    /// R605-F31 expected the boot args to become archetype-dependent and they
    /// did not, so the *sameness* is pinned rather than left to be rediscovered.
    ///
    /// A service needs `panic=1 reboot=k` for the same reason a job does — the
    /// host has to find out that the guest is gone. What differs is what the
    /// host then does about it, and that is the supervisor's restart policy, not
    /// a kernel command line. Removing them for services would buy exactly one
    /// thing: a panicked service guest that hangs forever reporting `Running`.
    #[test]
    fn a_service_boots_with_the_same_args_because_only_the_reading_changes() {
        let job = vmm_config(&cfg(), &spec("b"), None, Path::new("/w/d.ext4"), &job_root()).unwrap();
        let svc = vmm_config(
            &cfg(),
            &service_spec("s"),
            None,
            Path::new("/w/d.ext4"),
            &service_root(),
        )
        .unwrap();
        assert_eq!(job.boot_source.boot_args, svc.boot_source.boot_args);
        assert_eq!(job.boot_source.kernel_image_path, svc.boot_source.kernel_image_path);
    }

    #[test]
    fn an_air_gapped_node_emits_no_network_interface() {
        let mut cfg = cfg();
        cfg.network = None;
        let vm = vmm_config(&cfg, &spec("b"), None, Path::new("/w/d.ext4"), &job_root()).unwrap();
        assert!(vm.network_interfaces.is_empty());
        // And the guest is not handed an `ip=` it has no interface for.
        assert!(!vm.boot_source.boot_args.contains("ip="));

        let json = serde_json::to_string(&vm).unwrap();
        assert!(
            !json.contains("network-interfaces"),
            "firecracker rejects an empty interface list; it must be omitted"
        );
    }

    #[test]
    fn the_config_document_uses_firecrackers_field_names() {
        // These are an external contract with a binary that will reject
        // anything else, and nothing else in the build would catch a rename.
        let slot = GuestSlot::derive(&GuestNetwork::for_uplink("eth0"), 0).unwrap();
        let vm = vmm_config(&cfg(), &spec("b"), Some(&slot), Path::new("/w/d.ext4"), &job_root()).unwrap();
        let json = serde_json::to_value(&vm).unwrap();
        for key in ["boot-source", "drives", "machine-config", "network-interfaces"] {
            assert!(json.get(key).is_some(), "missing top-level key {key}");
        }
        assert!(json["boot-source"]["kernel_image_path"].is_string());
        assert!(json["machine-config"]["mem_size_mib"].is_u64());
        assert_eq!(json["network-interfaces"][0]["host_dev_name"], "yahvm0");
    }

    // ── The guest contract ──────────────────────────────────────────────────

    #[test]
    fn the_job_document_carries_argv_env_and_the_schema_version() {
        let mut s = spec("job");
        s.entrypoint = Some(vec!["/bin/sh".into(), "-c".into()]);
        s.command = Some(vec!["cargo build".into()]);
        s.env.push(EnvVar {
            name: "CARGO_HOME".into(),
            value: EnvValue::Literal {
                value: "/workspace/.cargo".into(),
            },
        });

        let job = MicroVmJob::of_spec(&s, &[], Some(Ipv4Addr::new(1, 1, 1, 1))).unwrap();
        assert_eq!(job.schema, JOB_SCHEMA_VERSION);
        assert_eq!(job.argv, vec!["/bin/sh", "-c", "cargo build"]);
        assert_eq!(job.env.get("CARGO_HOME").unwrap(), "/workspace/.cargo");
        assert_eq!(job.workspace_mount, GUEST_WORKSPACE_MOUNT);

        // Round-trips: the guest's init parses exactly these bytes.
        let back: MicroVmJob = serde_json::from_slice(&serde_json::to_vec(&job).unwrap()).unwrap();
        assert_eq!(back, job);
    }

    /// The exact bytes the guest's init will parse.
    ///
    /// A golden fixture rather than field-by-field assertions because the other
    /// side of this contract is **not in this repository** — it is a rootfs
    /// image built and deployed separately, possibly months apart from this
    /// binary. Field assertions would let a rename slip through as long as both
    /// sides of the Rust compiled; only the serialized shape is the contract.
    ///
    /// If this test fails, the question is not "update the fixture" — it is
    /// whether [`JOB_SCHEMA_VERSION`] needs a bump and whether any deployed
    /// rootfs still reads the old shape.
    #[test]
    fn the_job_document_serializes_to_the_shape_the_guest_init_parses() {
        let mut s = spec("forge-abc");
        s.entrypoint = None;
        s.command = Some(vec!["/bin/sh".into(), "-c".into(), "cargo build".into()]);
        s.env.clear();
        s.env.push(EnvVar {
            name: "CARGO_HOME".into(),
            value: EnvValue::Literal {
                value: "/workspace/.cargo".into(),
            },
        });
        s.workdir = Some(PathBuf::from("/src"));

        let plan = workspace::plan(&spec_with_volumes("forge-abc"));
        let job = MicroVmJob::of_spec(&s, &plan, Some(Ipv4Addr::new(1, 1, 1, 1))).unwrap();

        let expected = serde_json::json!({
            "schema": 1,
            "workload": "forge-forge-abc",
            "argv": ["/bin/sh", "-c", "cargo build"],
            "env": { "CARGO_HOME": "/workspace/.cargo" },
            "workdir": "/src",
            "workspace_mount": "/workspace",
            "dns": "1.1.1.1",
            "mounts": [
                { "slug": "0-yah-produced", "target": "/yah/produced", "read_only": false },
                { "slug": "1-etc-certs", "target": "/etc/certs", "read_only": true },
            ],
        });
        assert_eq!(serde_json::to_value(&job).unwrap(), expected);
    }

    /// The other direction of the same contract, and the same discipline: these
    /// are the bytes `kamaji-guest-init` was **observed** to write, transcribed
    /// from a real guest's scratch disk rather than produced by serializing this
    /// struct. Round-tripping our own `JobStatus` here would assert nothing about
    /// the image that actually writes the file.
    ///
    /// `init_version` is deliberately present and deliberately absent from
    /// [`JobStatus`]: it is the guest's own build stamp, useful in a console log
    /// and not something the supervisor acts on, so tolerating it is the
    /// forward-compatibility this document needs.
    #[test]
    fn the_guest_status_document_parses_the_shape_the_init_writes() {
        let observed = br#"{"detail":"job exited 0","exit_code":0,"init_version":"0.8.36","schema":1,"workload":"forge-forge-abc"}"#;
        let status: JobStatus = serde_json::from_slice(observed).expect("the init's own bytes");
        assert_eq!(status.schema, JOB_SCHEMA_VERSION);
        assert_eq!(status.workload, "forge-forge-abc");
        assert_eq!(status.exit_code, 0);
        assert_eq!(status.detail, "job exited 0");

        // A signalled job arrives as 128+n, the shell convention, so it cannot be
        // confused with a job that chose that code — and it must be Failed.
        let killed = br#"{"detail":"job killed by signal 9","exit_code":137,"schema":1,"workload":"forge-forge-abc"}"#;
        let status: JobStatus = serde_json::from_slice(killed).unwrap();
        assert_eq!(status.exit_code, 137);
    }

    #[test]
    fn an_unresolved_secret_fails_the_deploy_instead_of_the_build() {
        let mut s = spec("job");
        s.env.push(EnvVar {
            name: "CODESIGN_KEY".into(),
            value: EnvValue::FromSecret {
                secret: "apple-id".into(),
                key: "password".into(),
            },
        });
        let err = MicroVmJob::of_spec(&s, &[], None).unwrap_err().to_string();
        assert!(err.contains("apple-id"), "got {err}");
        assert!(err.contains("yubaba must resolve"), "got {err}");
    }

    #[test]
    fn a_spec_with_no_argv_is_refused_because_nothing_is_pulled() {
        let mut s = spec("job");
        s.entrypoint = None;
        s.command = None;
        let err = MicroVmJob::of_spec(&s, &[], None).unwrap_err().to_string();
        assert!(err.contains("identity metadata"), "got {err}");
    }

    // ── Scratch disk sizing ─────────────────────────────────────────────────

    #[test]
    fn disk_size_floors_then_scales() {
        // for_forge's 512 MiB scratch floor must NOT win — that is the exact
        // value that would fail every real build at its first checkout.
        assert_eq!(workspace::disk_size_bytes(0, Some(512)), WORKSPACE_MIN_BYTES);
        let big = 10 * 1024 * 1024 * 1024u64;
        assert_eq!(workspace::disk_size_bytes(big, Some(512)), big * 4);
        // But a spec that genuinely asks for more than the heuristic gets it.
        assert_eq!(
            workspace::disk_size_bytes(0, Some(64 * 1024)),
            64 * 1024 * 1024 * 1024
        );
        // No overflow panic on an absurd input.
        assert!(workspace::disk_size_bytes(u64::MAX, Some(u32::MAX)) >= WORKSPACE_MIN_BYTES);
    }

    /// R885-T6 acceptance: deleting `ResourceLimits::ephemeral_storage_mb` must
    /// not change the disk any real workload is given.
    ///
    /// The regression this guards is silent and expensive — a forge run handed a
    /// smaller scratch disk fails at its first checkout, which is the failure
    /// the deleted field would have caused if it had ever been obeyed as the
    /// cap it claimed to be. Asserted against the live `for_forge` spec through
    /// the real accessor rather than against a hand-written number, so it still
    /// holds if `FORGE_SCRATCH_FLOOR_MB` is later changed.
    #[test]
    fn deleting_the_field_did_not_change_what_for_forge_is_given() {
        // `spec()` is built on the real `WorkloadSpec::for_forge`.
        let spec = spec("forge-r885-t6");

        // The declaration survived the field's deletion, at the same value.
        assert_eq!(
            spec.scratch_floor_mb(),
            Some(workload_spec::FORGE_SCRATCH_FLOOR_MB),
            "for_forge must still declare its scratch floor, via the annotation"
        );

        // And it still sizes to exactly what it sized to before: the backend's
        // own 8 GiB floor dominates, for an empty tree and for a real one.
        assert_eq!(
            workspace::disk_size_bytes(0, spec.scratch_floor_mb()),
            WORKSPACE_MIN_BYTES
        );
        let tree = 3 * 1024 * 1024 * 1024u64;
        assert_eq!(
            workspace::disk_size_bytes(tree, spec.scratch_floor_mb()),
            tree * WORKSPACE_SIZE_MULTIPLIER
        );

        // A workload that declares nothing is not punished for it — the
        // backend floor is the whole answer, identical to a declared floor
        // below it. `None` must never read as "zero, so give it nothing".
        assert_eq!(workspace::disk_size_bytes(0, None), WORKSPACE_MIN_BYTES);
        assert_eq!(
            workspace::disk_size_bytes(0, None),
            workspace::disk_size_bytes(0, spec.scratch_floor_mb())
        );

        // The floor is still load-bearing above the backend default, which is
        // the only reason to keep the mechanism at all.
        assert_eq!(
            workspace::disk_size_bytes(0, Some(32 * 1024)),
            32 * 1024 * 1024 * 1024
        );
    }

    fn spec_with_volumes(name: &str) -> WorkloadSpec {
        use workload_spec::VolumeMount;
        let mut s = spec(name);
        s.volumes = vec![
            VolumeMount {
                source: VolumeSource::Bind {
                    host_path: PathBuf::from("/var/lib/yah/qed/produced/abc"),
                },
                target: PathBuf::from("/yah/produced"),
                read_only: false,
                from_secret_mount: false,
            },
            VolumeMount {
                source: VolumeSource::Tmpfs { size_mb: 64 },
                target: PathBuf::from("/tmp"),
                read_only: false,
                from_secret_mount: false,
            },
            VolumeMount {
                source: VolumeSource::Named {
                    name: "cargo-cache".into(),
                },
                target: PathBuf::from("/cache"),
                read_only: false,
                from_secret_mount: false,
            },
            VolumeMount {
                source: VolumeSource::Bind {
                    host_path: PathBuf::from("/etc/yah/certs"),
                },
                target: PathBuf::from("/etc/certs"),
                read_only: true,
                from_secret_mount: false,
            },
        ];
        s
    }

    #[test]
    fn only_bind_mounts_are_planned() {
        let plan = workspace::plan(&spec_with_volumes("vols"));
        assert_eq!(plan.len(), 2, "tmpfs and named volumes are not the guest's");
        assert_eq!(plan[0].host_path, PathBuf::from("/var/lib/yah/qed/produced/abc"));
        assert_eq!(plan[1].host_path, PathBuf::from("/etc/yah/certs"));
    }

    #[test]
    fn a_planned_mount_lands_at_the_target_the_spec_declared() {
        // The property that makes one spec run on either substrate: a forge
        // step writes to /yah/produced whether it got a container or a guest.
        // Slugging by the *source* basename would put it at
        // /workspace/abc instead, and the step would never find it.
        let plan = workspace::plan(&spec_with_volumes("vols"));
        let job = MicroVmJob::of_spec(&spec_with_volumes("vols"), &plan, None).unwrap();
        let produced = job
            .mounts
            .iter()
            .find(|m| m.target == "/yah/produced")
            .expect("the produced dir must reach the guest at its declared target");
        assert_eq!(produced.slug, "0-yah-produced");
        assert!(!produced.read_only);
    }

    #[test]
    fn slugs_are_unique_even_when_two_targets_render_the_same() {
        use workload_spec::VolumeMount;
        let mut s = spec("collide");
        s.volumes = vec![
            VolumeMount {
                source: VolumeSource::Bind {
                    host_path: PathBuf::from("/a"),
                },
                target: PathBuf::from("/x/y"),
                read_only: false,
                from_secret_mount: false,
            },
            VolumeMount {
                source: VolumeSource::Bind {
                    host_path: PathBuf::from("/b"),
                },
                target: PathBuf::from("/x-y"),
                read_only: false,
                from_secret_mount: false,
            },
        ];
        let plan = workspace::plan(&s);
        assert_ne!(
            plan[0].slug, plan[1].slug,
            "two mounts sharing a scratch directory would overwrite each other"
        );
    }

    #[test]
    fn a_read_only_volume_is_carried_in_but_never_copied_back() {
        // The flag protects the host, so the host is the side that enforces it
        // — the guest is exactly the party that cannot be trusted to.
        let plan = workspace::plan(&spec_with_volumes("vols"));
        let ro = plan.iter().find(|m| m.read_only).unwrap();
        assert_eq!(ro.host_path, PathBuf::from("/etc/yah/certs"));
        let writable: Vec<_> = plan.iter().filter(|m| !m.read_only).collect();
        assert_eq!(writable.len(), 1);
    }

    #[test]
    fn tree_bytes_counts_a_real_tree() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("a/b")).unwrap();
        std::fs::write(tmp.path().join("a/one"), vec![0u8; 100]).unwrap();
        std::fs::write(tmp.path().join("a/b/two"), vec![0u8; 250]).unwrap();
        assert_eq!(workspace::tree_bytes(tmp.path()), 350);
    }

    // ── Construction ────────────────────────────────────────────────────────

    #[test]
    fn a_missing_rootfs_fails_construction_not_the_first_build() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut c = cfg();
        c.vmm_bin = tmp.path().join("firecracker");
        std::fs::write(&c.vmm_bin, b"").unwrap();
        c.kernel_image = tmp.path().join("vmlinux");
        std::fs::write(&c.kernel_image, b"").unwrap();
        c.rootfs_image = tmp.path().join("absent.ext4");

        let err = match MicroVmRuntime::new(c) {
            Ok(_) => panic!("expected construction to fail on the absent rootfs"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("guest rootfs"), "got {err}");
        assert!(
            err.contains("no image to pull"),
            "the message must say why there is no fallback: {err}"
        );
    }

    #[test]
    fn backend_tag_is_microvm() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rt = runtime_on(&tmp);
        assert_eq!(rt.backend(), Backend::MicroVm);
    }

    #[test]
    fn sanitize_keeps_an_identity_usable_as_a_directory_name() {
        assert_eq!(sanitize("forge-abc123"), "forge-abc123");
        // The property, not the exact string: no separator and no `..`
        // survives, so an identity cannot escape the state dir.
        let escaped = sanitize("svc/../etc");
        assert!(!escaped.contains('/') && !escaped.contains(".."), "got {escaped}");
    }

    #[tokio::test]
    async fn restart_is_refused_with_the_reason_not_a_silent_noop() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rt = runtime_on(&tmp);
        let _ctrl = register(&rt, "forge-1", VmShape::Job).await;

        let err = rt
            .restart_workload(&MeshIdent("forge-1".into()))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("job-shaped"), "got {err}");
    }

    /// The refusal above is now a property of the *workload*, not of the
    /// backend, and this is the assertion that says so (R605-F31).
    ///
    /// Dispatching straight into the live supervisor rather than reproducing a
    /// "service restarts too" branch here: what is being pinned is that a
    /// service's restart reaches the shared restart loop at all, which is the
    /// thing the job-shaped bail used to make impossible for every workload on
    /// this backend.
    #[tokio::test]
    async fn a_service_restart_reaches_the_supervisor_instead_of_being_refused() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rt = runtime_on(&tmp);
        let mut ctrl_rx = register(&rt, "vm-1", VmShape::Service).await;

        // Stand in for the supervisor: take the one control message and ack it
        // with the pid a real re-boot would have produced.
        let sup = tokio::spawn(async move {
            match ctrl_rx.recv().await {
                Some(Ctrl::Restart(ack)) => {
                    let _ = ack.send(Ok(4242));
                    true
                }
                _ => false,
            }
        });

        rt.restart_workload(&MeshIdent("vm-1".into()))
            .await
            .expect("a service-shaped guest is restartable");
        assert!(sup.await.unwrap(), "the supervisor saw a Restart");
    }

    /// An identity this backend never booted is not a shape question at all.
    #[tokio::test]
    async fn restarting_an_unknown_workload_names_the_identity() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rt = runtime_on(&tmp);

        let err = rt
            .restart_workload(&MeshIdent("never-booted".into()))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no microVM workload"), "got {err}");
        assert!(err.contains("never-booted"), "got {err}");
    }

    #[tokio::test]
    async fn teardown_of_an_unknown_workload_is_a_noop() {
        let tmp = tempfile::TempDir::new().unwrap();
        let rt = runtime_on(&tmp);
        rt.teardown_workload(&MeshIdent("never-deployed".into()))
            .await
            .expect("teardown must be idempotent");
    }
}

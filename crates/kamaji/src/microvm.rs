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
//! ## Shape: a job, not a service
//!
//! This backend is built for [`LifecycleArchetype::Job`] — a forge run that
//! starts, does work, produces artifacts and exits. It deliberately does **not**
//! implement the restart loop [`crate::native`] carries: a build that fails is
//! finished, and re-running it is the dispatcher's decision (with a fresh
//! workspace), not the supervisor's. [`MicroVmRuntime::restart_workload`] says
//! so rather than pretending.
//!
//! [`LifecycleArchetype::Job`]: workload_spec::LifecycleArchetype::Job
//!
//! ## The four things a microVM needs that a container does not
//!
//! W325 §5 called these "the real cost, and it is not Rust". They are, in the
//! order this module deals with them:
//!
//! 1. **A kernel and a rootfs.** There is no image to pull — `spec.image` is
//!    identity metadata here exactly as it is for native exec. The guest boots
//!    the node's configured kernel with the node's configured rootfs attached
//!    **read-only**, so no job can leave anything behind in it for the next one.
//!    See [`MicroVmConfig`].
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
//!    [`JOB_SCHEMA_VERSION`] for exactly that reason.
//!
//! ## Privileges
//!
//! This backend needs more than the others, and pretending otherwise would just
//! move the failure later:
//!
//! | need | why | failure if absent |
//! |---|---|---|
//! | `/dev/kvm` read-write | ask the kernel for a VM | probe reports unavailable ([`crate::probe`]) |
//! | `CAP_NET_ADMIN` | create the TAP device and its route | deploy fails naming the `ip` command that refused |
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
//! `ip tuntap`, spawning the VMM — is a shell-out to a Linux tool, and is
//! verified on a node. The split is deliberate: the parts that are wrong
//! *quietly* are the pure ones.
//!
//! @arch:see(.yah/docs/working/W325-isolated-x86-build-capacity.md)
//!
//! @yah:ticket(R605-F14, "Build the microVM guest side: kernel + rootfs + an init that reads /job.json")
//! @yah:at(2026-08-27T03:39:37Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R605)
//! @yah:next("THE CONTRACT IS ALREADY PINNED, so this is an implementation job and not a design one. kamaji::microvm::MicroVmJob is the document kamaji writes to /job.json at the root of the scratch disk, and the exact serialized bytes are locked by the golden test the_job_document_serializes_to_the_shape_the_guest_init_parses. Code the init against that fixture, not against the Rust struct: the two sides ship separately (a rootfs image built months apart from the kamaji binary that boots it), so only the JSON shape is the contract. JOB_SCHEMA_VERSION is 1; the init should refuse a schema it does not recognise rather than guess.")
//! @yah:verify("A node with --microvm-dir populated boots a guest that reads /job.json, bind-mounts each GuestMount slug at its target, runs argv, writes to /yah/produced and halts. kamaji reports the workload Stopped and the artifacts appear under /var/lib/yah/qed/produced/<forge-id> on the host.")
//! @yah:next("THE ROOTFS MUST BE BUILT READ-ONLY-CLEAN. kamaji attaches it with is_read_only: true and one image serves every job on the node, so the init cannot write anywhere outside /workspace. That is a correctness property (job N must not leave state for job N+1), not hardening, and the_rootfs_is_read_only_and_the_workspace_is_not pins it from the kamaji side.")
//! @yah:next("Tier: Warrior -- an image build plus a small init, on unfamiliar ground (Firecracker guest conventions), and it needs a Linux host with KVM to test at all. The camp Mac cannot run any of it, which is exactly why R605-F8 stopped here.")
//! @yah:gotcha("THE KERNEL MUST BE AN UNCOMPRESSED ELF vmlinux, not a bzImage -- Firecracker boots the former only. kamaji passes it as boot-source.kernel_image_path from <microvm-dir>/vmlinux, and expects the rootfs at <microvm-dir>/rootfs.ext4; MicroVmRuntime::new refuses to construct if either path is absent, so a node with the wrong filename advertises no microVM backend rather than failing every build.")
//! @yah:assumes("That a guest booting with panic=1 reboot=k exits the VMM process on halt, which is what kamaji's supervisor treats as job completion. Read from Firecracker's documented behaviour, NOT measured here -- there is no KVM on the camp Mac. If it turns out a halted guest leaves firecracker resident, the supervisor never fires and every microVM job hangs until teardown; that is the first thing to check on the first real boot.")

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
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use workload_spec::{EnvValue, VolumeSource, WorkloadSpec};

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

/// Where the scratch disk is mounted inside the guest.
///
/// Fixed rather than configurable: it is half of a two-sided contract with the
/// rootfs's init, and a value only one side can change is not a contract.
pub const GUEST_WORKSPACE_MOUNT: &str = "/workspace";

/// Grace period between asking the VMM to stop and killing it.
const TERM_GRACE: Duration = Duration::from_secs(10);

/// Slack added to the scratch disk over the size of its input tree, so a build
/// has somewhere to put its output. Builds are the workload this exists for and
/// they produce far more than they consume, hence the multiplier rather than a
/// flat addition.
const WORKSPACE_SIZE_MULTIPLIER: u64 = 4;

/// Floor on the scratch disk, for the common case of an empty input tree.
const WORKSPACE_MIN_BYTES: u64 = 8 * 1024 * 1024 * 1024;

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
    /// Uncompressed guest kernel (`vmlinux`). Firecracker boots an ELF kernel,
    /// not a `bzImage`.
    pub kernel_image: PathBuf,
    /// Guest root filesystem image, attached **read-only**.
    pub rootfs_image: PathBuf,
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

impl Default for GuestNetwork {
    fn default() -> Self {
        Self {
            uplink: "eth0".into(),
            subnet_base: Ipv4Addr::new(172, 30, 0, 0),
            tap_prefix: "yahvm".into(),
            dns: Ipv4Addr::new(1, 1, 1, 1),
        }
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

impl MicroVmJob {
    /// Build the job document for `spec`.
    ///
    /// Refuses unresolved `env` for the same reason
    /// `validate_native_exec_spec` does: this backend can only write literals
    /// into the document, and a silently-absent credential fails the build
    /// somewhere far from its cause.
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

/// Build the VM definition for one job.
///
/// `panic=1 reboot=k` is the load-bearing pair: it makes the guest **exit**
/// rather than sit at a panic prompt, which is what turns "the VMM process
/// ended" into a usable completion signal for the supervisor. Without it a
/// crashed guest would hang until teardown and look identical to a slow build.
pub fn vmm_config(
    cfg: &MicroVmConfig,
    spec: &WorkloadSpec,
    slot: Option<&GuestSlot>,
    workspace_disk: &Path,
) -> Result<VmmConfig> {
    let mut boot_args =
        String::from("console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux");
    if let Some(slot) = slot {
        boot_args.push(' ');
        boot_args.push_str(&slot.kernel_ip_arg());
    }

    Ok(VmmConfig {
        boot_source: BootSource {
            kernel_image_path: cfg.kernel_image.to_string_lossy().into_owned(),
            boot_args,
        },
        drives: vec![
            Drive {
                drive_id: "rootfs".into(),
                path_on_host: cfg.rootfs_image.to_string_lossy().into_owned(),
                is_root_device: true,
                // Read-only is a correctness property, not a hardening bonus:
                // one rootfs image serves every job on the node, so a writable
                // one would let job N leave state for job N+1 — the exact
                // cross-contamination this backend exists to prevent.
                is_read_only: true,
            },
            Drive {
                drive_id: "workspace".into(),
                path_on_host: workspace_disk.to_string_lossy().into_owned(),
                is_root_device: false,
                is_read_only: false,
            },
        ],
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

/// One live guest's host-side bookkeeping.
struct VmHandle {
    slot: Option<GuestSlot>,
    mesh_ip: Ipv4Addr,
    vm_dir: PathBuf,
    console_path: PathBuf,
    pid: Arc<AtomicU32>,
    status: watch::Receiver<WorkloadStatus>,
    /// Supervisor task; detached on drop.
    #[allow(dead_code)]
    task: JoinHandle<()>,
}

/// Firecracker microVM backend. One instance runs any number of guests, each in
/// its own `/30` slot.
pub struct MicroVmRuntime {
    cfg: MicroVmConfig,
    vms: Mutex<HashMap<String, VmHandle>>,
}

impl MicroVmRuntime {
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
        if cfg.max_guest_memory_mb == 0 {
            bail!("microVM backend: max_guest_memory_mb is 0 — no guest could be booted");
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

        // Signed-recipe admission (R555-F4 / W235 §(c)), at the same point in
        // the sequence the other backends check it. A guest is a strong
        // boundary around the *host*, and no boundary at all around the
        // credentials the job document is about to carry into it, so the argv
        // still has to be one the node agreed to run.
        workload_spec::admission::check(spec)
            .map_err(|e| anyhow!("workload {} not admitted: {e}", spec.name))?;

        let ident = spec.expose.mesh.identity.clone();
        // Idempotent, like every other backend's deploy.
        self.teardown_workload(&ident).await?;

        let slot = self.allocate_slot().await?;
        let vm_dir = self.cfg.state_dir.join(sanitize(&ident.0));
        tokio::fs::create_dir_all(&vm_dir)
            .await
            .with_context(|| format!("creating microVM state dir {}", vm_dir.display()))?;

        // 1. Scratch disk: the job's input tree in, its artifacts out.
        let disk = vm_dir.join("workspace.ext4");
        let plan = workspace::plan(spec);
        workspace::build_disk(&plan, &disk, spec.resources.ephemeral_storage_mb)
            .await
            .with_context(|| format!("building scratch disk for workload {}", spec.name))?;

        // 2. The job document, written *into* that disk — the guest has no
        //    other way to be told what it was booted for.
        let job = MicroVmJob::of_spec(
            spec,
            &plan,
            slot.as_ref().and(self.cfg.network.as_ref()).map(|n| n.dns),
        )?;
        workspace::write_job(&disk, &job)
            .await
            .with_context(|| format!("writing {JOB_FILE} into {}", disk.display()))?;

        // 3. Host networking for this slot.
        if let (Some(slot), Some(net)) = (slot.as_ref(), self.cfg.network.as_ref()) {
            net::create_tap(slot, net).await.with_context(|| {
                format!(
                    "creating TAP {} for workload {} — this needs CAP_NET_ADMIN",
                    slot.tap, spec.name
                )
            })?;
        }

        // 4. The machine definition, kept on disk next to the logs.
        let config_path = vm_dir.join("vm-config.json");
        let vmm = vmm_config(&self.cfg, spec, slot.as_ref(), &disk)?;
        tokio::fs::write(&config_path, serde_json::to_vec_pretty(&vmm)?)
            .await
            .with_context(|| format!("writing {}", config_path.display()))?;

        // 5. Boot. The guest console is the workload's log, so it is captured
        //    the same way the native backend captures stdout.
        let console_path = vm_dir.join("console.log");
        let console = std::fs::File::create(&console_path)
            .with_context(|| format!("creating {}", console_path.display()))?;
        let mut child = tokio::process::Command::new(&self.cfg.vmm_bin)
            .arg("--no-api")
            .arg("--config-file")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(console.try_clone()?))
            .stderr(Stdio::from(console))
            .kill_on_drop(false)
            .spawn()
            .with_context(|| {
                format!(
                    "spawning {} — is firecracker installed and is /dev/kvm openable?",
                    self.cfg.vmm_bin.display()
                )
            })?;

        let vm_pid = child.id().unwrap_or(0);
        let pid = Arc::new(AtomicU32::new(vm_pid));
        let (status_tx, status_rx) = watch::channel(WorkloadStatus::Running);

        let supervisor_slot = slot.clone();
        let supervisor_net = self.cfg.network.clone();
        let supervisor_disk = disk.clone();
        let supervisor_plan = plan.clone();
        let supervisor_pid = Arc::clone(&pid);
        let name = spec.name.clone();
        let task = tokio::spawn(async move {
            let outcome = child.wait().await;
            supervisor_pid.store(0, Ordering::SeqCst);

            // Artifacts come back out *after* the guest halts, not during: the
            // scratch disk is a block device the guest owns exclusively while
            // it runs, and reading a live ext4 from the host would see a
            // half-written filesystem.
            let extracted = workspace::extract_disk(&supervisor_disk, &supervisor_plan).await;

            if let (Some(slot), Some(net)) = (supervisor_slot.as_ref(), supervisor_net.as_ref()) {
                if let Err(e) = net::delete_tap(slot, net).await {
                    tracing::warn!(workload = %name, tap = %slot.tap, error = %e,
                        "leaked a TAP device: the slot stays allocated until kamaji restarts");
                }
            }

            let status = match (outcome, extracted) {
                (Ok(st), Ok(())) if st.success() => WorkloadStatus::Stopped,
                (Ok(st), Ok(())) => WorkloadStatus::Failed {
                    reason: format!("microVM exited with {st}"),
                },
                (Ok(_), Err(e)) => WorkloadStatus::Failed {
                    reason: format!("guest finished but its artifacts could not be read back: {e:#}"),
                },
                (Err(e), _) => WorkloadStatus::Failed {
                    reason: format!("waiting on the VMM failed: {e}"),
                },
            };
            let _ = status_tx.send(status);
        });

        self.vms.lock().await.insert(
            ident.0.clone(),
            VmHandle {
                slot,
                mesh_ip: mesh.mesh_ip,
                vm_dir,
                console_path,
                pid,
                status: status_rx,
                task,
            },
        );

        Ok(DeployResult {
            container_id: format!("microvm-{vm_pid}"),
            mesh_ip: mesh.mesh_ip,
            task_pid: vm_pid,
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

    /// Not supported, on purpose.
    ///
    /// Restart means "run this again", and for a job that is a new run with a
    /// fresh workspace — the scratch disk this guest halted with holds a failed
    /// build's output, and rebooting into it would produce a result neither
    /// clean nor reproducible. The dispatcher decides to retry; the supervisor
    /// does not decide for it.
    async fn restart_workload(&self, ident: &MeshIdent) -> Result<()> {
        bail!(
            "Backend::MicroVm does not restart workload {} in place: it is job-shaped \
             (LifecycleArchetype::Job, RestartPolicy::Never), and re-running a build means a \
             fresh guest with a fresh workspace. Tear down and deploy again",
            ident.0
        )
    }

    async fn teardown_workload(&self, ident: &MeshIdent) -> Result<()> {
        let Some(handle) = self.vms.lock().await.remove(&ident.0) else {
            return Ok(()); // idempotent
        };

        let pid = handle.pid.load(Ordering::SeqCst);
        if pid != 0 {
            // SIGTERM to Firecracker is a guest power-off, not a guest signal:
            // there is nothing inside to catch it. That is acceptable for a job
            // being torn down (its artifacts are already lost either way) and
            // is why teardown is not the normal completion path — the normal
            // path is the guest halting on its own, which the supervisor sees
            // as the VMM process exiting.
            signal_pid(pid, libc::SIGTERM);
            let deadline = std::time::Instant::now() + TERM_GRACE;
            while std::time::Instant::now() < deadline {
                if handle.pid.load(Ordering::SeqCst) == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if handle.pid.load(Ordering::SeqCst) != 0 {
                signal_pid(pid, libc::SIGKILL);
            }
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

    /// Size the scratch image: the largest of what the spec asks for, what the
    /// input tree implies, and [`WORKSPACE_MIN_BYTES`].
    ///
    /// # Why `ephemeral_storage_mb` is a floor and not the answer
    ///
    /// It is the field that *means* this — "cap on the writable layer + tmpfs
    /// footprint" — and on the container path nothing enforces it, so it has
    /// drifted: `WorkloadSpec::for_forge` sets **512 MiB**, and the builds this
    /// backend exists to isolate check out multi-gigabyte source trees. Taking
    /// it literally would hand every forge run a 512 MiB disk and fail every
    /// one of them at the first `git clone`.
    ///
    /// This is the mirror image of [`super::guest_memory_mb`]'s problem and the
    /// treatment is deliberately opposite. Memory is a real allocation, so an
    /// over-large spec value must be clamped *down* to what the node has.
    /// Scratch is a sparse file, so an under-set spec value is raised *up* to
    /// what a build needs, and costs only the blocks actually written. Neither
    /// field can simply be believed; each is wrong in a different direction.
    pub fn disk_size_bytes(input_bytes: u64, ephemeral_storage_mb: u32) -> u64 {
        let requested = u64::from(ephemeral_storage_mb).saturating_mul(1024 * 1024);
        input_bytes
            .saturating_mul(WORKSPACE_SIZE_MULTIPLIER)
            .max(requested)
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
        ephemeral_storage_mb: u32,
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

        let size = disk_size_bytes(input_bytes, ephemeral_storage_mb);
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

    /// Create and bring up the TAP for `slot`, and NAT it out `net.uplink`.
    pub async fn create_tap(slot: &GuestSlot, net: &GuestNetwork) -> Result<()> {
        // Idempotent: a leaked TAP from a previous kamaji generation must not
        // wedge the slot forever. `ip tuntap del` on a nonexistent device is a
        // no-op we deliberately ignore.
        let _ = delete_tap(slot, net).await;

        run("ip", &["tuntap".as_ref(), "add".as_ref(), slot.tap.as_ref(), "mode".as_ref(), "tap".as_ref()])
            .await
            .context("ip tuntap add failed — this needs CAP_NET_ADMIN")?;
        run(
            "ip",
            &[
                "addr".as_ref(),
                "add".as_ref(),
                format!("{}/30", slot.host_ip).as_ref(),
                "dev".as_ref(),
                slot.tap.as_ref(),
            ],
        )
        .await?;
        run("ip", &["link".as_ref(), "set".as_ref(), slot.tap.as_ref(), "up".as_ref()]).await?;
        run(
            "iptables",
            &[
                "-t".as_ref(),
                "nat".as_ref(),
                "-A".as_ref(),
                "POSTROUTING".as_ref(),
                "-s".as_ref(),
                format!("{}/30", slot.guest_ip).as_ref(),
                "-o".as_ref(),
                net.uplink.as_ref(),
                "-j".as_ref(),
                "MASQUERADE".as_ref(),
            ],
        )
        .await
        .context("iptables MASQUERADE failed — the guest will boot but reach nothing")?;
        Ok(())
    }

    /// Remove the TAP and its NAT rule. Best-effort and idempotent.
    pub async fn delete_tap(slot: &GuestSlot, net: &GuestNetwork) -> Result<()> {
        let _ = run(
            "iptables",
            &[
                "-t".as_ref(),
                "nat".as_ref(),
                "-D".as_ref(),
                "POSTROUTING".as_ref(),
                "-s".as_ref(),
                format!("{}/30", slot.guest_ip).as_ref(),
                "-o".as_ref(),
                net.uplink.as_ref(),
                "-j".as_ref(),
                "MASQUERADE".as_ref(),
            ],
        )
        .await;
        run("ip", &["tuntap".as_ref(), "del".as_ref(), slot.tap.as_ref(), "mode".as_ref(), "tap".as_ref()]).await
    }
}

/// Run a host command, failing with its stderr rather than just its exit code.
///
/// Every privileged step in this module goes through here so that a node
/// missing `e2fsprogs`, or a kamaji without `CAP_NET_ADMIN`, produces a message
/// naming the tool and quoting what it said — the two failures this backend is
/// most likely to hit on a fresh node, and the two that are most opaque when
/// reported as "exit status 1".
async fn run(bin: &str, args: &[&std::ffi::OsStr]) -> Result<()> {
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
            state_dir: PathBuf::from("/var/lib/yah/microvm/vms"),
            network: Some(GuestNetwork::default()),
            max_guest_memory_mb: 8192,
            max_guest_vcpus: 4,
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

    // ── Slot arithmetic ─────────────────────────────────────────────────────

    #[test]
    fn slots_take_non_overlapping_slash_30s() {
        let net = GuestNetwork::default();
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
        let net = GuestNetwork::default();
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
            ..GuestNetwork::default()
        };
        let err = GuestSlot::derive(&net, 0).unwrap_err().to_string();
        assert!(err.contains("15-character"), "got {err}");
    }

    #[test]
    fn kernel_ip_arg_points_the_guest_at_its_own_host_end() {
        let slot = GuestSlot::derive(&GuestNetwork::default(), 2).unwrap();
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
            ephemeral_storage_mb: 512,
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
        let slot = GuestSlot::derive(&GuestNetwork::default(), 0).unwrap();
        let vm = vmm_config(&cfg(), &spec("b"), Some(&slot), Path::new("/w/workspace.ext4")).unwrap();

        let root = vm.drives.iter().find(|d| d.is_root_device).unwrap();
        assert!(
            root.is_read_only,
            "a writable shared rootfs lets job N leave state for job N+1"
        );
        let work = vm.drives.iter().find(|d| d.drive_id == "workspace").unwrap();
        assert!(!work.is_read_only);
        assert!(!work.is_root_device);
    }

    #[test]
    fn boot_args_make_a_panicking_guest_exit_rather_than_hang() {
        // `panic=1 reboot=k` is what turns "the VMM process ended" into a
        // completion signal. Without it a crashed guest is indistinguishable
        // from a slow build until teardown.
        let vm = vmm_config(&cfg(), &spec("b"), None, Path::new("/w/d.ext4")).unwrap();
        assert!(vm.boot_source.boot_args.contains("panic=1"));
        assert!(vm.boot_source.boot_args.contains("reboot=k"));
        assert!(vm.boot_source.boot_args.contains("console=ttyS0"));
    }

    #[test]
    fn an_air_gapped_node_emits_no_network_interface() {
        let mut cfg = cfg();
        cfg.network = None;
        let vm = vmm_config(&cfg, &spec("b"), None, Path::new("/w/d.ext4")).unwrap();
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
        let slot = GuestSlot::derive(&GuestNetwork::default(), 0).unwrap();
        let vm = vmm_config(&cfg(), &spec("b"), Some(&slot), Path::new("/w/d.ext4")).unwrap();
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
        // for_forge's 512 MiB `ephemeral_storage_mb` must NOT win — that is the
        // exact value that would fail every real build at its first checkout.
        assert_eq!(workspace::disk_size_bytes(0, 512), WORKSPACE_MIN_BYTES);
        let big = 10 * 1024 * 1024 * 1024u64;
        assert_eq!(workspace::disk_size_bytes(big, 512), big * 4);
        // But a spec that genuinely asks for more than the heuristic gets it.
        assert_eq!(
            workspace::disk_size_bytes(0, 64 * 1024),
            64 * 1024 * 1024 * 1024
        );
        // No overflow panic on an absurd input.
        assert!(workspace::disk_size_bytes(u64::MAX, u32::MAX) >= WORKSPACE_MIN_BYTES);
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
            },
            VolumeMount {
                source: VolumeSource::Tmpfs { size_mb: 64 },
                target: PathBuf::from("/tmp"),
                read_only: false,
            },
            VolumeMount {
                source: VolumeSource::Named {
                    name: "cargo-cache".into(),
                },
                target: PathBuf::from("/cache"),
                read_only: false,
            },
            VolumeMount {
                source: VolumeSource::Bind {
                    host_path: PathBuf::from("/etc/yah/certs"),
                },
                target: PathBuf::from("/etc/certs"),
                read_only: true,
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
            },
            VolumeMount {
                source: VolumeSource::Bind {
                    host_path: PathBuf::from("/b"),
                },
                target: PathBuf::from("/x-y"),
                read_only: false,
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
        let mut c = cfg();
        for p in ["firecracker", "vmlinux", "rootfs.ext4"] {
            std::fs::write(tmp.path().join(p), b"").unwrap();
        }
        c.vmm_bin = tmp.path().join("firecracker");
        c.kernel_image = tmp.path().join("vmlinux");
        c.rootfs_image = tmp.path().join("rootfs.ext4");
        c.state_dir = tmp.path().join("vms");
        let rt = MicroVmRuntime::new(c).unwrap();
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
        let mut c = cfg();
        for p in ["firecracker", "vmlinux", "rootfs.ext4"] {
            std::fs::write(tmp.path().join(p), b"").unwrap();
        }
        c.vmm_bin = tmp.path().join("firecracker");
        c.kernel_image = tmp.path().join("vmlinux");
        c.rootfs_image = tmp.path().join("rootfs.ext4");
        c.state_dir = tmp.path().join("vms");
        let rt = MicroVmRuntime::new(c).unwrap();

        let err = rt
            .restart_workload(&MeshIdent("forge-1".into()))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("job-shaped"), "got {err}");
    }

    #[tokio::test]
    async fn teardown_of_an_unknown_workload_is_a_noop() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut c = cfg();
        for p in ["firecracker", "vmlinux", "rootfs.ext4"] {
            std::fs::write(tmp.path().join(p), b"").unwrap();
        }
        c.vmm_bin = tmp.path().join("firecracker");
        c.kernel_image = tmp.path().join("vmlinux");
        c.rootfs_image = tmp.path().join("rootfs.ext4");
        c.state_dir = tmp.path().join("vms");
        let rt = MicroVmRuntime::new(c).unwrap();
        rt.teardown_workload(&MeshIdent("never-deployed".into()))
            .await
            .expect("teardown must be idempotent");
    }
}

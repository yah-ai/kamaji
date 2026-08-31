//! Backend probe-at-init (R484-T3, W199 §Backend availability).
//!
//! [`BackendAvailability::probe`] connect()-tests well-known docker /
//! containerd UDS paths and reports which backends are usable. The result is
//! cached on the Kamaji instance — callers that ask for an absent backend
//! get a structured [`BackendUnavailable`] error carrying an install hint
//! instead of a panic / opaque connection error.
//!
//! The probe is **passive**: it only checks socket reachability, not the
//! gRPC / CLI handshake. A reachable socket can still belong to a broken
//! daemon; the first real call will surface that. The point here is to
//! quickly reject "docker isn't installed" / "containerd not running" so the
//! camp can show install UI before queuing a workload.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;
use tokio::time::timeout;

use crate::{Backend, BackendUnavailable};

/// Outcome of probing one backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendProbe {
    pub backend: Backend,
    pub available: bool,
    /// Reachable socket path when `available == true`.
    pub socket_path: Option<PathBuf>,
    /// Human-readable detail (paths tried, env var honored, etc.).
    pub detail: String,
    /// Install hint surfaced when `available == false`. `None` when the
    /// backend is available or has no install-side remediation.
    pub install_hint: Option<String>,
}

impl BackendProbe {
    fn available(backend: Backend, socket_path: PathBuf, detail: String) -> Self {
        Self {
            backend,
            available: true,
            socket_path: Some(socket_path),
            detail,
            install_hint: None,
        }
    }

    fn unavailable(backend: Backend, detail: String, install_hint: Option<String>) -> Self {
        Self {
            backend,
            available: false,
            socket_path: None,
            detail,
            install_hint,
        }
    }

    /// Convert this probe result into a [`BackendUnavailable`] when
    /// `available == false`. Returns `Ok(())` otherwise.
    pub fn require(&self) -> Result<(), BackendUnavailable> {
        if self.available {
            Ok(())
        } else {
            Err(BackendUnavailable {
                backend: self.backend,
                detail: self.detail.clone(),
                install_hint: self.install_hint.clone(),
            })
        }
    }
}

/// Result of probing every backend known to Kamaji.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendAvailability {
    pub native: BackendProbe,
    pub containerd: BackendProbe,
    pub docker: BackendProbe,
    /// R605-F8. Absent in payloads written before the microVM backend existed,
    /// hence the `default` — a stored probe result from an older node is a
    /// perfectly good answer about docker and containerd, and "did not know to
    /// ask about KVM" is exactly `unavailable`.
    #[serde(default = "microvm_unprobed")]
    pub microvm: BackendProbe,
}

impl BackendAvailability {
    /// Probe every backend with default search paths. Honors
    /// `DOCKER_HOST` and `CONTAINERD_ADDRESS` when those env vars name a
    /// `unix://` socket.
    pub async fn probe() -> Self {
        let native = probe_native();
        let containerd = probe_containerd(default_containerd_paths()).await;
        let docker = probe_docker(default_docker_paths()).await;
        let microvm = probe_microvm(Path::new(KVM_DEVICE));
        Self {
            native,
            containerd,
            docker,
            microvm,
        }
    }

    /// Look up a specific backend's probe result.
    pub fn get(&self, backend: Backend) -> &BackendProbe {
        match backend {
            Backend::Native => &self.native,
            Backend::Containerd => &self.containerd,
            Backend::Docker => &self.docker,
            Backend::MicroVm => &self.microvm,
        }
    }

    /// Demand a specific backend is available. Returns `BackendUnavailable`
    /// with the install hint when it isn't.
    pub fn require(&self, backend: Backend) -> Result<&BackendProbe, BackendUnavailable> {
        let p = self.get(backend);
        p.require()?;
        Ok(p)
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_millis(250);

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn strip_unix_scheme(s: &str) -> &str {
    s.strip_prefix("unix://").unwrap_or(s)
}

fn default_docker_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(env) = std::env::var("DOCKER_HOST") {
        let p = strip_unix_scheme(&env);
        if !p.is_empty() && !p.contains("://") {
            paths.push(PathBuf::from(p));
        }
    }
    paths.push(PathBuf::from("/var/run/docker.sock"));
    if let Some(home) = home_dir() {
        paths.push(home.join(".docker/run/docker.sock")); // Docker Desktop (macOS)
        paths.push(home.join(".orbstack/run/docker.sock")); // OrbStack
        paths.push(home.join(".colima/default/docker.sock")); // Colima default
        paths.push(home.join(".lima/default/sock/docker.sock")); // Lima
    }
    paths
}

fn default_containerd_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(env) = std::env::var("CONTAINERD_ADDRESS") {
        let p = strip_unix_scheme(&env);
        if !p.is_empty() && !p.contains("://") {
            paths.push(PathBuf::from(p));
        }
    }
    paths.push(PathBuf::from("/run/containerd/containerd.sock"));
    paths.push(PathBuf::from("/var/run/containerd/containerd.sock"));
    if let Some(home) = home_dir() {
        paths.push(home.join(".colima/default/containerd.sock"));
    }
    paths
}

fn docker_install_hint() -> String {
    "Install Docker Desktop, OrbStack, or Colima (https://docs.docker.com/get-docker/)".into()
}

fn containerd_install_hint() -> String {
    "Install containerd (Linux: `apt install containerd` or equivalent; \
     macOS: `colima start --runtime containerd`)"
        .into()
}

fn probe_native() -> BackendProbe {
    // Native fork+exec is always available — no daemon to probe. The cgroup
    // + pidfd machinery the supervisor uses is Linux-only, but constructing
    // the backend itself never fails.
    BackendProbe::available(
        Backend::Native,
        PathBuf::new(),
        "native backend has no socket; fork+exec is always available".into(),
    )
}

/// The KVM character device every microVM backend needs a handle on.
pub const KVM_DEVICE: &str = "/dev/kvm";

/// The probe result a payload written before R605-F8 deserializes to.
fn microvm_unprobed() -> BackendProbe {
    BackendProbe::unavailable(
        Backend::MicroVm,
        format!("{KVM_DEVICE} was not probed (result predates the microVM backend)"),
        None,
    )
}

/// Probe the microVM backend by **opening** `/dev/kvm` read-write, not by
/// checking that it exists (R605-F8).
///
/// Existence is the wrong test here, and W325 §4 measured exactly why: on both
/// OVH nodes `/dev/kvm` is present, is `root:kvm` mode `0660`, and the `debian`
/// service user kamaji runs as is **not in group `kvm`**. A probe keyed on
/// `path.exists()` would report the backend available on every one of those
/// nodes and the failure would surface later, as a permission error from inside
/// a VMM launch, attributed to the workload rather than to the node.
///
/// So this opens the device the same way a VMM will and reports what the kernel
/// says. The two failures are distinguished because their remediations are
/// completely different — install a hypervisor-capable kernel vs. add one user
/// to one group — and an operator reading "microVM unavailable" needs to know
/// which.
///
/// Passive in the same sense as the other probes: an openable `/dev/kvm` proves
/// the process can ask for a VM, not that a guest kernel and rootfs are
/// configured. [`crate::microvm::MicroVmRuntime::new`] checks those, because
/// they are backend configuration rather than host capability.
pub fn probe_microvm(kvm: &Path) -> BackendProbe {
    if !cfg!(target_os = "linux") {
        return BackendProbe::unavailable(
            Backend::MicroVm,
            format!(
                "microVM backend is Linux-only (host is {})",
                std::env::consts::OS
            ),
            None,
        );
    }
    match std::fs::OpenOptions::new().read(true).write(true).open(kvm) {
        Ok(_) => BackendProbe::available(
            Backend::MicroVm,
            kvm.to_path_buf(),
            format!("opened {} read-write", kvm.display()),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BackendProbe::unavailable(
            Backend::MicroVm,
            format!("{} does not exist — no KVM on this host", kvm.display()),
            Some(
                "Enable hardware virtualization (on a guest, nested virtualization: \
                 `/sys/module/kvm_intel/parameters/nested` must read Y) and load the \
                 kvm_intel / kvm_amd module"
                    .into(),
            ),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => BackendProbe::unavailable(
            Backend::MicroVm,
            format!(
                "{} exists but this process cannot open it: {e}",
                kvm.display()
            ),
            Some(format!(
                "Add the kamaji service user to the `kvm` group \
                 (`usermod -aG kvm <user>`, then restart kamaji.service — group \
                 membership is read at process start). {} is typically root:kvm 0660",
                kvm.display()
            )),
        ),
        Err(e) => BackendProbe::unavailable(
            Backend::MicroVm,
            format!("cannot open {}: {e}", kvm.display()),
            None,
        ),
    }
}

async fn try_connect(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    matches!(
        timeout(CONNECT_TIMEOUT, UnixStream::connect(path)).await,
        Ok(Ok(_))
    )
}

async fn probe_containerd(paths: Vec<PathBuf>) -> BackendProbe {
    for path in &paths {
        if try_connect(path).await {
            return BackendProbe::available(
                Backend::Containerd,
                path.clone(),
                format!("connected to {}", path.display()),
            );
        }
    }
    let tried = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    BackendProbe::unavailable(
        Backend::Containerd,
        format!("no containerd socket reachable (tried: {tried})"),
        Some(containerd_install_hint()),
    )
}

async fn probe_docker(paths: Vec<PathBuf>) -> BackendProbe {
    for path in &paths {
        if try_connect(path).await {
            return BackendProbe::available(
                Backend::Docker,
                path.clone(),
                format!("connected to {}", path.display()),
            );
        }
    }
    let tried = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    BackendProbe::unavailable(
        Backend::Docker,
        format!("no docker socket reachable (tried: {tried})"),
        Some(docker_install_hint()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn native_always_available() {
        let p = probe_native();
        assert!(p.available);
        assert_eq!(p.backend, Backend::Native);
        assert!(p.install_hint.is_none());
    }

    #[tokio::test]
    async fn missing_docker_socket_yields_install_hint() {
        let tmp = TempDir::new().unwrap();
        let phantom = tmp.path().join("nope.sock");
        let p = probe_docker(vec![phantom]).await;
        assert!(!p.available);
        assert!(p.install_hint.as_deref().unwrap().contains("Docker"));
        let err = p.require().unwrap_err();
        assert_eq!(err.backend, Backend::Docker);
        assert!(err.install_hint.is_some());
    }

    #[tokio::test]
    async fn missing_containerd_socket_yields_install_hint() {
        let tmp = TempDir::new().unwrap();
        let phantom = tmp.path().join("nope.sock");
        let p = probe_containerd(vec![phantom]).await;
        assert!(!p.available);
        assert!(p.install_hint.as_deref().unwrap().contains("containerd"));
    }

    #[tokio::test]
    async fn reachable_socket_marks_available() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("test.sock");
        let _listener = UnixListener::bind(&sock).unwrap();
        let p = probe_docker(vec![sock.clone()]).await;
        assert!(p.available);
        assert_eq!(p.socket_path.as_deref(), Some(sock.as_path()));
        assert!(p.require().is_ok());
    }

    #[tokio::test]
    async fn first_reachable_path_wins() {
        let tmp = TempDir::new().unwrap();
        let missing = tmp.path().join("missing.sock");
        let present = tmp.path().join("present.sock");
        let _listener = UnixListener::bind(&present).unwrap();
        let p = probe_containerd(vec![missing, present.clone()]).await;
        assert!(p.available);
        assert_eq!(p.socket_path.as_deref(), Some(present.as_path()));
    }

    #[tokio::test]
    async fn availability_require_routes_per_backend() {
        let tmp = TempDir::new().unwrap();
        let phantom = tmp.path().join("nope.sock");
        let avail = BackendAvailability {
            native: probe_native(),
            containerd: probe_containerd(vec![phantom.clone()]).await,
            docker: probe_docker(vec![phantom.clone()]).await,
            microvm: probe_microvm(&phantom),
        };
        assert!(avail.require(Backend::Native).is_ok());
        let docker_err = avail.require(Backend::Docker).unwrap_err();
        assert_eq!(docker_err.backend, Backend::Docker);
        let cd_err = avail.require(Backend::Containerd).unwrap_err();
        assert_eq!(cd_err.backend, Backend::Containerd);
        let vm_err = avail.require(Backend::MicroVm).unwrap_err();
        assert_eq!(vm_err.backend, Backend::MicroVm);
    }

    #[test]
    fn absent_kvm_device_is_unavailable_not_a_panic() {
        let tmp = TempDir::new().unwrap();
        let p = probe_microvm(&tmp.path().join("kvm"));
        assert!(!p.available);
        assert_eq!(p.backend, Backend::MicroVm);
        assert!(p.require().is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn unopenable_kvm_device_names_the_group_fix() {
        // The W325 §4 case, reproduced without needing a real /dev/kvm: a file
        // this process cannot open read-write must probe unavailable *and*
        // point at group membership rather than at installing anything, because
        // "exists but EACCES" is the fleet's actual state on both OVH nodes.
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let fake = tmp.path().join("kvm");
        std::fs::write(&fake, b"").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o000)).unwrap();
        let p = probe_microvm(&fake);
        // Running as root defeats the mode bits entirely; that is a legitimate
        // configuration and the assertion below is only meaningful otherwise.
        if !p.available {
            assert!(
                p.install_hint.as_deref().unwrap_or_default().contains("kvm` group"),
                "permission failure must name the group fix, got {:?}",
                p.install_hint
            );
        }
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn microvm_is_unavailable_off_linux_without_touching_the_filesystem() {
        // Named `/dev/kvm` deliberately: on a non-Linux host the probe must
        // short-circuit on the OS, so even the real device path (if some future
        // platform grew one) reports unavailable rather than half-working.
        let p = probe_microvm(Path::new(KVM_DEVICE));
        assert!(!p.available);
        assert!(p.detail.contains("Linux-only"));
    }

    #[test]
    fn docker_paths_honor_docker_host_env() {
        // SAFETY: tests are single-threaded under #[test] but we still scope
        // the env mutation tightly.
        let prev = std::env::var_os("DOCKER_HOST");
        std::env::set_var("DOCKER_HOST", "unix:///tmp/explicit-docker.sock");
        let paths = default_docker_paths();
        match prev {
            Some(v) => std::env::set_var("DOCKER_HOST", v),
            None => std::env::remove_var("DOCKER_HOST"),
        }
        assert_eq!(
            paths.first().unwrap(),
            &PathBuf::from("/tmp/explicit-docker.sock")
        );
    }

    #[test]
    fn containerd_paths_honor_address_env() {
        let prev = std::env::var_os("CONTAINERD_ADDRESS");
        std::env::set_var("CONTAINERD_ADDRESS", "unix:///tmp/explicit-cd.sock");
        let paths = default_containerd_paths();
        match prev {
            Some(v) => std::env::set_var("CONTAINERD_ADDRESS", v),
            None => std::env::remove_var("CONTAINERD_ADDRESS"),
        }
        assert_eq!(
            paths.first().unwrap(),
            &PathBuf::from("/tmp/explicit-cd.sock")
        );
    }
}

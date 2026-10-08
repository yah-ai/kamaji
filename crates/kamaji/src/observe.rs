//! The deploy-time observability contract: where a workload's local collector
//! is, and what this workload is called (R893-B17).
//!
//! Two env vars, one owner. `yah-log`'s service layer
//! (`crates/yah/log/src/service_layer.rs`) and passway's span exporter
//! (`oss/passway/crates/passway/src/trace.rs`, R893-F16) both read the *same*
//! pair and both hold no sink at all unless BOTH are present:
//!
//! - [`SERVICE_IDENT_ENV`] — this workload's mesh identity, which becomes
//!   `EventScope::Service(MeshIdent)` on every line and `service.name` on every
//!   span.
//! - [`SCRYER_SOCKET_ENV`] — the path of the local `yah-scryer` ingestion
//!   socket, as seen *from inside the workload*.
//!
//! Before this module the pair was documented as injected and injected
//! nowhere — scryer's own module docs asserted "yubaba injects
//! `YAH_SERVICE_IDENT` + `YAH_SCRYER_SOCKET` into workload env" while a repo-wide
//! grep found only readers. kamaji owns workload env, not yubaba, so the
//! injection lives here, beside the `YAH_MESH_IP` / `PORT` contract it mirrors.
//!
//! ## Why this is not just two `cmd.env()` calls
//!
//! The socket is a **filesystem path**, so unlike `YAH_MESH_IP` its correct
//! value depends on which mount namespace the workload runs in:
//!
//! | Backend | Namespace | What it gets |
//! |---|---|---|
//! | native, JIT fork | the host's | the host path, verbatim |
//! | docker, containerd | its own | [`GUEST_SOCKET_PATH`], with the host socket bind-mounted there |
//! | microVM | a different kernel | **nothing** — see below |
//!
//! Injecting the host path into a container would name a path that does not
//! exist inside it, which is the same silent-nowhere failure this ticket exists
//! to remove, one layer down. So [`Collector::env_for`] takes the namespace and
//! [`Collector::guest_bind`] hands the container backends the bind they must
//! also install; neither is optional if the other is done.
//!
//! A microVM guest has its own kernel and no view of the host filesystem at
//! all, so there is no path and no bind that could make a host `AF_UNIX` socket
//! reachable. It is left out **deliberately**, not by omission: reaching a
//! microVM workload's telemetry needs a network-addressed collector, which is a
//! different contract than this one. (That backend also injects neither
//! `YAH_MESH_IP` nor `PORT` today, so it is already outside the deploy-env
//! contract rather than being taken out of it here.)
//!
//! ## Spec always wins
//!
//! [`Collector::env_for`] omits any variable the spec declares itself, so an
//! operator pinning `YAH_SCRYER_SOCKET` in a workload manifest keeps their
//! value on every backend. That has to be decided here rather than per-backend,
//! because the backends layer injected and literal env in different orders
//! (native/docker put the spec last and let it win; containerd puts deploy env
//! last, so it skips names the spec already carries). Deciding it once means
//! the precedence cannot drift between them again.

use std::path::{Path, PathBuf};

use workload_spec::WorkloadSpec;

/// The workload's own mesh identity. Read by `yah-log` to scope its events and
/// by passway to fill `service.name`.
pub const SERVICE_IDENT_ENV: &str = "YAH_SERVICE_IDENT";

/// Path of the `yah-scryer` ingestion socket **as the workload sees it**.
pub const SCRYER_SOCKET_ENV: &str = "YAH_SCRYER_SOCKET";

/// Where the host's ingestion socket is bind-mounted inside a container.
///
/// Fixed rather than mirroring the host path: an image is built once and runs
/// on nodes that may put the socket anywhere, and the value still reaches the
/// workload through [`SCRYER_SOCKET_ENV`] either way — so the only thing a
/// varying container path would buy is a bind destination that differs per
/// node. Under `/run` because that is where the rest of kamaji's per-node
/// runtime state lives (`kamaji_containerd_core::UPGRADE_SHARE_ROOT`).
pub const GUEST_SOCKET_PATH: &str = "/run/yah/scryer.sock";

/// Which mount namespace the workload being deployed will run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountNs {
    /// The node's own — a native fork or a JIT child. The host path is the
    /// workload's path.
    Host,
    /// The workload's own, with [`Collector::guest_bind`] installed.
    Own,
}

/// This node's answer to "where is my local collector".
///
/// [`Collector::disabled`] (the [`Default`]) injects nothing at all, which is
/// what every node did before R893-B17 and what a node without a running
/// `yah-scryer --ingest-socket` must keep doing: a workload pointed at a socket
/// nobody is listening on gets connection refusals on its telemetry path
/// forever, which is strictly worse than knowing it is untraced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collector {
    host_socket: Option<PathBuf>,
}

impl Collector {
    /// No local collector — inject nothing.
    pub fn disabled() -> Self {
        Self { host_socket: None }
    }

    /// The local collector's ingestion socket, as a path on the **host**.
    pub fn at(host_socket: impl Into<PathBuf>) -> Self {
        Self {
            host_socket: Some(host_socket.into()),
        }
    }

    /// [`Collector::at`] / [`Collector::disabled`] from an optional path — the
    /// shape an opt-in CLI flag produces.
    pub fn from_option(host_socket: Option<impl Into<PathBuf>>) -> Self {
        match host_socket {
            Some(p) => Self::at(p),
            None => Self::disabled(),
        }
    }

    /// The host-side socket path, or `None` when no collector is configured.
    pub fn host_socket(&self) -> Option<&Path> {
        self.host_socket.as_deref()
    }

    /// `(host source, container destination)` for the bind a container backend
    /// must install so [`GUEST_SOCKET_PATH`] resolves inside the workload.
    ///
    /// Read-write, and that is load-bearing: `connect(2)` on an `AF_UNIX`
    /// socket requires write permission on the socket inode, so a read-only
    /// bind would render a reachable path unusable — the failure would look
    /// like a broken collector rather than a wrong mount.
    pub fn guest_bind(&self) -> Option<(String, String)> {
        self.host_socket
            .as_ref()
            .map(|p| (p.to_string_lossy().into_owned(), GUEST_SOCKET_PATH.to_string()))
    }

    /// The env pairs this workload gets, in a `ns` mount namespace.
    ///
    /// Empty when no collector is configured, and any variable the spec
    /// declares itself is omitted so the operator's value survives on every
    /// backend regardless of that backend's layering order.
    pub fn env_for(&self, spec: &WorkloadSpec, ns: MountNs) -> Vec<(String, String)> {
        let Some(host) = &self.host_socket else {
            return Vec::new();
        };
        let socket = match ns {
            MountNs::Host => host.to_string_lossy().into_owned(),
            MountNs::Own => GUEST_SOCKET_PATH.to_string(),
        };
        [
            (SERVICE_IDENT_ENV, spec.expose.mesh.identity.0.clone()),
            (SCRYER_SOCKET_ENV, socket),
        ]
        .into_iter()
        .filter(|(k, _)| !spec.env.iter().any(|e| e.name == *k))
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::{
        EnvValue, EnvVar, ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, NamespaceId,
        ResourceLimits, RestartPolicy, StopPolicy, TenantId, TierTag,
    };

    fn spec(ident: &str) -> WorkloadSpec {
        WorkloadSpec {
            name: ident.to_string(),
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
                    identity: MeshIdent(ident.to_string()),
                    ports: MeshExpose::anonymous_ports([]),
                    allow_from: vec![],
                },
                public: None,
                operator: None,
            },
            labels: Default::default(),
            durability: None,
            db: Vec::new(),
            capabilities: Vec::new(),
            annotations: Default::default(),
            files: Vec::new(),
        }
    }

    #[test]
    fn a_disabled_collector_injects_nothing_in_either_namespace() {
        let c = Collector::disabled();
        assert!(c.env_for(&spec("door"), MountNs::Host).is_empty());
        assert!(c.env_for(&spec("door"), MountNs::Own).is_empty());
        assert_eq!(c.guest_bind(), None);
    }

    #[test]
    fn a_host_namespace_workload_gets_the_host_path_verbatim() {
        let c = Collector::at("/run/yah/scryer.sock");
        assert_eq!(
            c.env_for(&spec("door"), MountNs::Host),
            vec![
                ("YAH_SERVICE_IDENT".to_string(), "door".to_string()),
                (
                    "YAH_SCRYER_SOCKET".to_string(),
                    "/run/yah/scryer.sock".to_string()
                ),
            ]
        );
    }

    /// The whole reason `env_for` takes a namespace: a container cannot see the
    /// host path, so injecting it would name a file that is not there.
    #[test]
    fn an_own_namespace_workload_gets_the_guest_path_and_a_matching_bind() {
        let c = Collector::at("/var/run/yah/scryer-1.sock");
        let env = c.env_for(&spec("door"), MountNs::Own);
        assert_eq!(env[1].1, GUEST_SOCKET_PATH);
        assert_eq!(
            c.guest_bind(),
            Some((
                "/var/run/yah/scryer-1.sock".to_string(),
                GUEST_SOCKET_PATH.to_string()
            ))
        );
        // The destination the env names and the destination the bind installs
        // are the same string, or the container connects to nothing.
        assert_eq!(env[1].1, c.guest_bind().unwrap().1);
    }

    #[test]
    fn a_spec_that_names_either_variable_keeps_its_own_value() {
        let c = Collector::at("/run/yah/scryer.sock");
        let mut s = spec("door");
        s.env.push(EnvVar {
            name: "YAH_SCRYER_SOCKET".to_string(),
            value: EnvValue::Literal {
                value: "/tmp/mine.sock".to_string(),
            },
        });
        let env = c.env_for(&s, MountNs::Host);
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].0, "YAH_SERVICE_IDENT");
    }

    #[test]
    fn the_service_ident_is_the_mesh_identity_not_the_workload_name() {
        let mut s = spec("door");
        s.name = "some-deployment-name".to_string();
        s.expose.mesh.identity = MeshIdent("inner.door".to_string());
        let env = Collector::at("/s.sock").env_for(&s, MountNs::Host);
        assert_eq!(env[0].1, "inner.door");
    }
}

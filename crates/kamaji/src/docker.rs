//! `runtime::docker` — `ContainerRuntime` impl backed by the Docker CLI.
//!
//! Targets pond (OrbStack) and any Linux dev box with a Docker-compatible socket.
//! Enabled by the `docker-integration` cargo feature (no extra deps — the gate
//! exists for consistency with `containerd-integration`, not for binary size).
//!
//! ## Why docker CLI over bollard
//!
//! Shell-out avoids the bollard dependency (a meaningful Tokio + hyper stack).
//! `docker inspect` returns structured JSON whose schema is stable across
//! Docker/OrbStack/Podman. Parsing JSON output is safer than parsing
//! human-readable text; per-call process overhead is invisible inside the
//! container spin-up budget (seconds).
//!
//! ## Status mapping
//!
//! | `.State.Restarting` / `.State.Status` | `WorkloadStatus`              |
//! |----------------------------------------|-------------------------------|
//! | `Restarting=true` (any status)          | `Restarting { … }`            |
//! | `"restarting"` (any `Restarting` flag)  | `Restarting { … }`            |
//! | `"running"`                             | `Running`                     |
//! | `"created"`                             | `Pending`                     |
//! | `"paused"` / `"removing"`              | `Stopping`                    |
//! | `"exited"`, `ExitCode = 0`             | `Stopped`                     |
//! | `"exited"`, `ExitCode ≠ 0`            | `Failed { reason }`           |
//! | `"dead"` / unknown                      | `Failed { reason }`           |
//!
//! ## Restart ownership (R626-F2)
//!
//! `deploy_workload` renders `spec.restart_policy` into `docker run --restart`
//! (see [`restart_flag`]), so **dockerd owns resurrection**. Before R626-F2 it
//! did not: the flag was omitted and each caller ran its own resurrect loop,
//! which also made the `Restarting` row below unreachable in practice —
//! `.State.Restarting` / `RestartCount` are only ever populated when a restart
//! policy is set.
//!
//! `RestartCount` and `ExitCode` are read directly from the docker daemon —
//! no in-yubaba ledger is needed (R471-S1 verdict). This is the key difference
//! from `runtime::containerd`, which must synthesise restart state from its own
//! `RestartLedger` because containerd has no native restart-count signal.
//!
//! @yah:relay(R626, "Unify persistent-service supervision under kamaji (wire the docker/OrbStack backend) + camp-daemon-managed desired state (scale 0↔N)")
//! @yah:at(2026-07-22T19:13:56Z)
//! @yah:status(open)
//! @yah:gotcha("The obvious first guess is wrong: OrbStack containers are NOT supervised by kamaji today. They run under yubaba's pond tier via the docker-CLI ContainerRuntime (oss/yubaba/crates/yubaba/src/pond.rs). kamaji's containerd backend is a different path — don't start by reading it.")
//! @yah:gotcha("pond.rs already treats PondPhase::Failed as terminal specifically to 'prevent a concurrent reconciler from resurrecting a dead workload' (pond.rs:136) — a narrow precedent for desired-state. Read it, but do NOT generalize Failed into the stop mechanism: a deliberate stop is not a failure and must not be reported as one.")
//! @yah:assumes("That kamaji/src/docker.rs is functionally complete and current — asserted from its module doc + API surface, NOT exercised. It is feature-gated and unwired, so it may never have run against a live OrbStack daemon. Verify end-to-end before building on it.")
//! @yah:assumes("That every pond slot is a persistent service that SHOULD be kamaji-managed (the operator's framing). Check each slot before migrating — a one-shot/build-time container would not belong under a persistent-service supervisor.")
//!
//! @arch:see(.yah/docs/working/W235-remote-qed.md)

#![cfg(feature = "docker-integration")]

use std::collections::HashMap;
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tokio::process::Command;
use workload_spec::{MeshIdent, WorkloadSpec};

use crate::{
    Backend, DeployResult, Kamaji, LogEvent, LogOpts, LogStream, LogStreamKind, MeshAssignment,
    RuntimeHealth, WorkloadState, WorkloadStatus,
};

// ── docker inspect JSON types ─────────────────────────────────────────────────

/// The slice of `docker inspect` output this impl cares about.
#[derive(Debug, Deserialize)]
struct DockerInspect {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "State")]
    state: DockerState,
    /// Top-level restart counter maintained by dockerd/moby's restart-policy
    /// engine. Not present inside `.State` — it lives at the container root.
    #[serde(rename = "RestartCount")]
    restart_count: u32,
    #[serde(rename = "Config")]
    config: DockerConfig,
}

#[derive(Debug, Deserialize)]
struct DockerState {
    /// Canonical status string: `"created"` | `"running"` | `"paused"` |
    /// `"restarting"` | `"removing"` | `"exited"` | `"dead"`.
    #[serde(rename = "Status")]
    status: String,
    /// `true` while dockerd is sleeping between restart attempts.
    #[serde(rename = "Restarting")]
    restarting: bool,
    /// Exit code of the most recent task instance. Meaningful only when
    /// `Status == "exited"` or during a restart cycle.
    #[serde(rename = "ExitCode")]
    exit_code: i32,
    /// UTC ISO8601 timestamp of the last task exit. Docker uses
    /// `"0001-01-01T00:00:00Z"` as the zero value when the container has
    /// never exited.
    #[serde(rename = "FinishedAt")]
    finished_at: String,
    /// Host pid of the container's root process. Docker reports `0` when the
    /// container isn't running (created / exited / dead), which
    /// [`DockerState::host_pid`] maps to `None`.
    #[serde(rename = "Pid")]
    pid: i32,
}

impl DockerState {
    /// Host pid of the container's root process, or `None` when no process is
    /// running. Docker's zero-value for `.State.Pid` is `0`, and a negative
    /// value would be nonsense — both collapse to `None`.
    fn host_pid(&self) -> Option<u32> {
        u32::try_from(self.pid).ok().filter(|p| *p != 0)
    }
}

#[derive(Debug, Deserialize)]
struct DockerConfig {
    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, String>>,
}

/// Docker label carrying the supervisor-facing workload id (`spec.name`).
///
/// Containers are *named* by mesh identity, but yubaba addresses workloads by
/// id, and the two are not the same string for forge runs (R590-B9). Recording
/// the id on the container makes a Stop resolvable from the daemon alone — no
/// in-supervisor map that a kamaji restart would lose.
pub const WORKLOAD_ID_LABEL: &str = "yah.workload_id";

// ── Docker-specific rendering annotations (R626-F2) ───────────────────────────
//
// `WorkloadSpec` is the cross-backend wire type: it describes mesh exposure,
// not host-side docker plumbing. A dev/pond container nonetheless needs three
// things that only exist on a docker daemon — published host ports, a user
// bridge network, and DNS aliases on it. Rather than widen the shared schema
// with fields every non-docker backend must ignore, the docker backend reads
// them from `spec.annotations`, which the type already documents as
// "yah-specific metadata, opaque to yubaba". Backends that don't understand
// them simply don't render them.

/// `yah.docker.publish` — comma-separated `host:container` port pairs, e.g.
/// `"9000:9000,9001:9001"`. Rendered as `docker run -p host:container`.
///
/// Only the docker backend publishes host ports at all; on containerd the mesh
/// plane is the addressing surface, so there is nothing to translate.
pub const PUBLISH_ANNOTATION: &str = "yah.docker.publish";

/// `yah.docker.network` — user-defined bridge network to attach to
/// (`docker run --network <name>`). Created idempotently at deploy time.
/// Absent means the daemon default (`bridge`).
pub const NETWORK_ANNOTATION: &str = "yah.docker.network";

/// `yah.docker.network_alias` — comma-separated DNS aliases registered on the
/// network (`--network-alias`). Ignored when [`NETWORK_ANNOTATION`] is absent,
/// which matches docker's own rule.
pub const NETWORK_ALIAS_ANNOTATION: &str = "yah.docker.network_alias";

// ── DockerWorkload ────────────────────────────────────────────────────────────

/// A workload's [`WorkloadState`] plus the host pid of its container's root
/// process.
///
/// The shared [`WorkloadState`] has no pid field (it is the mesh-facing view,
/// and the containerd/native backends surface pids by other routes), but a
/// supervisor listing docker workloads wants both in one pass — kamaji-bin's
/// `List` renders `WorkloadEntry { state, pid }` and its cross-backend dedupe
/// treats "names a live pid" as the liveness signal (R599-B11). Returned by
/// [`DockerRuntime::list_workloads_detailed`], which costs exactly the same
/// `docker inspect` calls as [`Kamaji::list_workloads`].
#[derive(Debug, Clone)]
pub struct DockerWorkload {
    pub state: WorkloadState,
    /// Host pid of the container's root process (`.State.Pid`). `None` when the
    /// container exists but no process is running.
    pub pid: Option<u32>,
    /// The supervisor-facing **workload id** (`spec.name`), read from the
    /// `yah.workload_id` label.
    ///
    /// This is NOT always the mesh identity: a forge run is `spec.name =
    /// "forge-<uuid>"` (DNS-label-safe) but `expose.mesh.identity =
    /// "forge.<uuid>"` (dotted) — the R590-B9 divergence. Yubaba deploys and
    /// stops by the id, so a supervisor must be able to find the container from
    /// it. Falls back to the mesh identity for containers deployed before this
    /// label existed.
    pub workload_id: String,
}

// ── DockerRuntime ─────────────────────────────────────────────────────────────

/// `ContainerRuntime` impl backed by the `docker` CLI.
///
/// Acquire via [`DockerRuntime::new`] (inherit `DOCKER_HOST` from environment)
/// or [`DockerRuntime::with_host`] (explicit socket/host).
///
/// Cheaply cloneable — the struct contains only a `String`.
#[derive(Clone)]
pub struct DockerRuntime {
    /// `DOCKER_HOST` value for every CLI invocation. Empty string means
    /// "inherit from environment", which picks up OrbStack's socket on macOS
    /// and the system socket on Linux.
    docker_host: String,
}

impl DockerRuntime {
    /// Use the system-default docker socket (inherit `DOCKER_HOST`).
    pub fn new() -> Self {
        Self {
            docker_host: String::new(),
        }
    }

    /// Use a specific docker host (e.g. `"unix:///var/run/docker.sock"`).
    pub fn with_host(docker_host: impl Into<String>) -> Self {
        Self {
            docker_host: docker_host.into(),
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new("docker");
        if !self.docker_host.is_empty() {
            cmd.env("DOCKER_HOST", &self.docker_host);
        }
        cmd.kill_on_drop(true);
        cmd
    }

    /// Build the image reference handed to `docker`. Pinned images pull
    /// content-addressed (`repo:tag@digest`); unpinned images (all-zeros
    /// sentinel) fall back to tag-only — docker holds a locally-built or
    /// tag-pulled image under `repo:tag`, not under the sentinel digest
    /// (R590-B5, matches the containerd `kcc::image_ref` path).
    fn image_ref(spec: &WorkloadSpec) -> String {
        spec.image.pull_ref()
    }

    /// Container name derived from the mesh identity. Used as the `--name`
    /// flag and as the argument to `docker inspect / stop / rm`.
    fn container_name(ident: &MeshIdent) -> &str {
        &ident.0
    }

    /// Run `docker inspect <name>` and return the parsed result.
    /// Returns `Ok(None)` when the container doesn't exist.
    async fn inspect(&self, name: &str) -> Result<Option<DockerInspect>> {
        let out = self
            .cmd()
            .args(["inspect", name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("spawning docker inspect {name}"))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if is_missing_container(&stderr) {
                return Ok(None);
            }
            return Err(anyhow!("docker inspect {name} failed: {}", stderr.trim()));
        }

        let json = String::from_utf8_lossy(&out.stdout);
        let list: Vec<DockerInspect> = serde_json::from_str(&json)
            .with_context(|| format!("parsing docker inspect JSON for {name}"))?;
        Ok(list.into_iter().next())
    }

    /// Translate a `DockerInspect` record into a `WorkloadState`.
    fn inspect_to_state(di: DockerInspect, ident: MeshIdent) -> WorkloadState {
        Self::inspect_to_workload(di, ident).state
    }

    /// Translate a `DockerInspect` record into a [`DockerWorkload`] — the
    /// `WorkloadState` plus the container's host pid.
    fn inspect_to_workload(di: DockerInspect, ident: MeshIdent) -> DockerWorkload {
        let pid = di.state.host_pid();
        let labels = di.config.labels.unwrap_or_default();
        let mesh_ip = labels.get("yah.mesh_ip").and_then(|s| s.parse().ok());
        let workload_id = labels
            .get(WORKLOAD_ID_LABEL)
            .cloned()
            .unwrap_or_else(|| ident.0.clone());
        let status = map_docker_state(&di.state, di.restart_count);
        DockerWorkload {
            state: WorkloadState {
                ident,
                container_id: di.id,
                status,
                mesh_ip,
                // R844-F2: namespaced container — the declared port is the
                // bound port, so this backend resolves nothing.
                ports: Default::default(),
            },
            pid,
            workload_id,
        }
    }

    /// Find the workload backing `key`, which may be **either** the mesh
    /// identity or the workload id (`spec.name`) — the two differ for forge
    /// runs (R590-B9), and a supervisor is handed the id.
    ///
    /// Tries the direct container-name lookup first (containers are named by
    /// mesh identity, so that is one `docker inspect`), then falls back to
    /// scanning the labelled containers for a matching `yah.workload_id`.
    pub async fn resolve(&self, key: &str) -> Result<Option<DockerWorkload>> {
        if let Some(di) = self.inspect(key).await? {
            let ident = Self::ident_of(&di, key);
            return Ok(Some(Self::inspect_to_workload(di, ident)));
        }
        Ok(self
            .list_workloads_detailed()
            .await?
            .into_iter()
            .find(|w| w.workload_id == key))
    }

    /// Tear down the workload backing `key` (mesh identity *or* workload id).
    ///
    /// Idempotent: a `key` no container matches is a no-op, which is what makes
    /// kamaji's "route every Stop to every backend" pattern safe. Use this
    /// rather than [`Kamaji::teardown_workload`] when the caller holds a
    /// workload id, or the stop silently succeeds while the container keeps
    /// running.
    pub async fn teardown_by_key(&self, key: &str) -> Result<()> {
        let ident = match self.resolve(key).await? {
            Some(w) => w.state.ident,
            None => return Ok(()),
        };
        self.teardown_workload(&ident).await
    }

    /// Like [`Kamaji::list_workloads`], but each entry also carries the
    /// container's host pid. Same daemon round-trips — the pid comes from the
    /// `docker inspect` this already runs per container.
    pub async fn list_workloads_detailed(&self) -> Result<Vec<DockerWorkload>> {
        let mut out = Vec::new();
        for name in self.yah_container_names().await? {
            if let Some(di) = self.inspect(&name).await? {
                let ident = Self::ident_of(&di, &name);
                out.push(Self::inspect_to_workload(di, ident));
            }
        }
        Ok(out)
    }

    /// Names of every container carrying the `yah.ident` label — the label
    /// [`Kamaji::deploy_workload`] writes, which is what makes a container a
    /// yah workload rather than an unrelated tenant of the same daemon.
    async fn yah_container_names(&self) -> Result<Vec<String>> {
        let out = self
            .cmd()
            .args([
                "ps",
                "-a",
                "--filter",
                "label=yah.ident",
                "--format",
                "{{.Names}}",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context("docker ps for yah workloads")?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(anyhow!("docker ps failed: {}", stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&out.stdout);
        Ok(stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect())
    }

    /// Build the full `docker run` argv for `spec`. Pure — no daemon contact —
    /// so the rendering rules are unit-testable without a docker host.
    ///
    /// Renders, in order: identity/bookkeeping labels, the spec's own labels,
    /// resource caps, the restart policy, published ports, network + aliases,
    /// volumes, env, then the image and command override.
    fn run_args(
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
        image: &str,
        name: &str,
    ) -> Result<Vec<String>> {
        let ident = &spec.expose.mesh.identity;
        let mut args: Vec<String> = vec![
            "run".into(),
            "-d".into(),
            "--name".into(),
            name.to_string(),
            // Labels for identity + mesh bookkeeping.
            "--label".into(),
            format!("yah.ident={}", ident.0),
            // The supervisor-facing workload id. Distinct from `yah.ident` for
            // forge runs (`forge-<uuid>` vs `forge.<uuid>`, R590-B9); yubaba
            // deploys and stops by THIS value, so it has to be recoverable from
            // the daemon or a Stop can't find the container.
            "--label".into(),
            format!("{WORKLOAD_ID_LABEL}={}", spec.name),
            "--label".into(),
            format!("yah.mesh_ip={}", mesh.mesh_ip),
        ];

        // Spec-declared labels. Sorted so the argv is deterministic (HashMap
        // iteration order is not) — tests and log diffs depend on that.
        let mut labels: Vec<(&String, &String)> = spec.labels.iter().collect();
        labels.sort();
        for (k, v) in labels {
            args.push("--label".into());
            args.push(format!("{k}={v}"));
        }

        // Memory ceiling + CPU weight. Docker's --cpu-shares sets the cgroup
        // relative weight (matches containerd semantics); we derive it from the
        // millicore request (1000m ≈ 1024 shares).
        //
        // Zero means *unenforced*, and the flag is omitted rather than passed
        // as `0`: pond's slots (MinIO, miniflare, the SSR runtime) have always
        // run uncapped on a developer's laptop, and rendering `--memory 0m`
        // there would be a behaviour change dressed up as a no-op.
        if spec.resources.memory_mb > 0 {
            args.push("--memory".into());
            args.push(format!("{}m", spec.resources.memory_mb));
        }
        if spec.resources.cpu_millis > 0 {
            args.push("--cpu-shares".into());
            args.push(spec.resources.cpu_shares().to_string());
        }

        // Restart supervision is the daemon's job, not a caller's loop.
        args.push("--restart".into());
        args.push(restart_flag(&spec.restart_policy));

        // Published host ports (docker-only; see PUBLISH_ANNOTATION).
        for (host, container) in parse_publish(spec)? {
            args.push("-p".into());
            args.push(format!("{host}:{container}"));
        }

        // User-defined bridge + DNS aliases on it. Docker rejects
        // `--network-alias` without a user-defined network, so aliases are
        // dropped (not an error) when no network is declared — same rule the
        // pond ContainerRunSpec renderer follows.
        if let Some(net) = docker_network(spec) {
            args.push("--network".into());
            args.push(net.to_string());
            for alias in network_aliases(spec) {
                args.push("--network-alias".into());
                args.push(alias.to_string());
            }
        }

        // Volume mounts.
        for v in &spec.volumes {
            let target = v.target.to_string_lossy();
            match &v.source {
                workload_spec::VolumeSource::Bind { host_path } => {
                    args.push("-v".into());
                    args.push(format!(
                        "{}:{target}{}",
                        host_path.to_string_lossy(),
                        if v.read_only { ":ro" } else { "" }
                    ));
                }
                workload_spec::VolumeSource::Named { name } => {
                    args.push("-v".into());
                    args.push(format!(
                        "{name}:{target}{}",
                        if v.read_only { ":ro" } else { "" }
                    ));
                }
                workload_spec::VolumeSource::Tmpfs { size_mb } => {
                    // tmpfs is always writable by definition; read_only has no
                    // docker equivalent here and is ignored.
                    args.push("--tmpfs".into());
                    args.push(format!("{target}:size={size_mb}m"));
                }
            }
        }

        // Mesh IP surfaced to the workload as an env var.
        args.push("--env".into());
        args.push(format!("YAH_MESH_IP={}", mesh.mesh_ip));

        // "What port did I get?" — one contract (R844-T13). Container-side ports
        // are the declared ones (the namespace is the workload's own), but a
        // workload must not have to know which backend started it to know which
        // variable to read.
        for (k, v) in crate::ports::port_env(&crate::declared_port_names(&spec.expose.mesh)) {
            args.push("--env".into());
            args.push(format!("{k}={v}"));
        }

        // Literal env vars from the spec. Last, so a spec-level value overrides
        // both the mesh IP and the port contract — `docker run` takes the final
        // `--env` for a repeated name.
        for e in &spec.env {
            if let workload_spec::EnvValue::Literal { value } = &e.value {
                args.push("--env".into());
                args.push(format!("{}={}", e.name, value));
            }
        }

        // Image ref + optional command override.
        args.push(image.to_string());
        if let Some(cmd) = &spec.command {
            args.extend(cmd.iter().cloned());
        }

        Ok(args)
    }

    /// Idempotently create a user-defined bridge network. `Ok(true)` when this
    /// call created it, `Ok(false)` when it already existed — including the
    /// inspect/create race, which two concurrent deploys onto the same pond
    /// cell will hit.
    pub async fn ensure_network(&self, name: &str) -> Result<bool> {
        let exists = self
            .cmd()
            .args(["network", "inspect", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .with_context(|| format!("spawning docker network inspect {name}"))?;
        if exists.success() {
            return Ok(false);
        }

        let create = self
            .cmd()
            .args(["network", "create", name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("spawning docker network create {name}"))?;
        if create.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&create.stderr);
        if stderr.to_ascii_lowercase().contains("already exists") {
            return Ok(false);
        }
        Err(anyhow!(
            "docker network create {name} failed: {}",
            stderr.trim()
        ))
    }

    /// Mesh identity for an inspected container: the `yah.ident` label when
    /// present, else the container name (which `deploy_workload` derives from
    /// the identity anyway).
    fn ident_of(di: &DockerInspect, name: &str) -> MeshIdent {
        MeshIdent(
            di.config
                .labels
                .as_ref()
                .and_then(|l| l.get("yah.ident"))
                .cloned()
                .unwrap_or_else(|| name.to_string()),
        )
    }
}

impl Default for DockerRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ── ContainerRuntime impl ─────────────────────────────────────────────────────

#[async_trait]
impl Kamaji for DockerRuntime {
    fn backend(&self) -> Backend {
        Backend::Docker
    }

    async fn deploy_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> Result<DeployResult> {
        // Signed-recipe admission (R555-F4 / W235 §(c)). This backend serves
        // pond and dev hosts rather than the shared fleet, so it is not where
        // the RCE surface lives — but a gate a workload can dodge by naming a
        // different backend is not a gate, and the check is one line.
        workload_spec::admission::check(spec)
            .map_err(|e| anyhow!("workload {} not admitted: {e}", spec.name))?;

        // R844-F21: a name-only port asks this backend to allocate, and it
        // cannot — see `crate::reject_unresolved_ports`. `yah.docker.publish`
        // is the only host port this backend ever opens, and it is an explicit
        // `host:container` map an operator wrote, not a number to invent.
        crate::reject_unresolved_ports(&spec.name, &spec.expose.mesh, crate::Backend::Docker)?;

        let ident = &spec.expose.mesh.identity;
        let name = Self::container_name(ident).to_string();
        let image = Self::image_ref(spec);

        // Idempotent: clear any prior container with the same name.
        let _ = self.teardown_workload(ident).await;

        // Ensure the image is present locally.
        let pull = self
            .cmd()
            .args(["pull", &image])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker pull {image}"))?;
        if !pull.status.success() {
            let stderr = String::from_utf8_lossy(&pull.stderr);
            return Err(anyhow!("docker pull {image} failed: {}", stderr.trim()));
        }

        // The user-defined bridge, when the spec asks for one, must exist before
        // `docker run --network` can attach to it.
        if let Some(net) = docker_network(spec) {
            self.ensure_network(net).await?;
        }

        let args = Self::run_args(spec, mesh, &image, &name)?;
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let run = self
            .cmd()
            .args(&argv[..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker run {name}"))?;
        if !run.status.success() {
            let stderr = String::from_utf8_lossy(&run.stderr);
            return Err(anyhow!("docker run {name} failed: {}", stderr.trim()));
        }

        // Read back the container ID from inspect.
        let di = self
            .inspect(&name)
            .await?
            .ok_or_else(|| anyhow!("container {name} not found after docker run"))?;
        let container_id = di.id.clone();
        // `.State.Pid` is the host pid of the container's root process. It is 0
        // when the container isn't running — which right after a successful
        // `docker run -d` means it exited immediately — and 0 is also
        // `DeployResult`'s "pid unavailable" sentinel, so the two agree.
        let task_pid = di.state.host_pid().unwrap_or(0);

        tracing::info!(
            name = %name,
            container_id = %container_id,
            task_pid,
            mesh_ip = %mesh.mesh_ip,
            "docker workload deployed"
        );

        Ok(DeployResult {
            container_id,
            mesh_ip: mesh.mesh_ip,
            task_pid,
            ports: Default::default(),
        })
    }

    async fn list_workloads(&self) -> Result<Vec<WorkloadState>> {
        // Enumerate all containers (running or stopped) that carry the
        // `yah.ident` label — the label is written by `deploy_workload`.
        // Callers that also want each container's host pid use
        // [`DockerRuntime::list_workloads_detailed`], which this delegates to.
        Ok(self
            .list_workloads_detailed()
            .await?
            .into_iter()
            .map(|w| w.state)
            .collect())
    }

    async fn get_workload(&self, ident: &MeshIdent) -> Result<Option<WorkloadState>> {
        let name = Self::container_name(ident);
        match self.inspect(name).await? {
            Some(di) => Ok(Some(Self::inspect_to_state(di, ident.clone()))),
            None => Ok(None),
        }
    }

    async fn stream_logs(&self, ident: &MeshIdent, opts: LogOpts) -> Result<LogStream> {
        let name = Self::container_name(ident).to_string();
        let ident_clone = ident.clone();

        // Build `docker logs [--tail N] <name>`.
        // follow mode is deferred — `docker logs -f` would require spawning a
        // long-running process and streaming its stdout; for F3 the key use
        // case (crash-loop log inspection) only needs the historical drain.
        let mut args: Vec<String> = vec!["logs".into()];
        match opts.tail {
            Some(n) => {
                args.push("--tail".into());
                args.push(n.to_string());
            }
            None => {
                args.push("--tail".into());
                args.push("all".into());
            }
        }
        args.push(name.clone());

        let out = self
            .cmd()
            .args(args.iter().map(String::as_str))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker logs {name}"))?;

        // If docker itself failed (e.g. container doesn't exist yet during the
        // first restart cycle) return an empty stream rather than an error —
        // callers expect a stream, not a hard failure.
        if !out.status.success() {
            return Ok(Box::pin(tokio_stream::empty()));
        }

        let include_stdout = opts
            .stream
            .map(|s| s == LogStreamKind::Stdout)
            .unwrap_or(true);
        let include_stderr = opts
            .stream
            .map(|s| s == LogStreamKind::Stderr)
            .unwrap_or(true);

        // Timestamp events at capture time (docker logs stdout/stderr don't
        // carry per-line timestamps by default).
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut events: Vec<LogEvent> = Vec::new();

        // docker logs routes container stdout → CLI stdout, container stderr →
        // CLI stderr, making it easy to tag each line with the right kind.
        if include_stdout {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                events.push(LogEvent {
                    timestamp_ms: now_ms,
                    ident: ident_clone.clone(),
                    stream: LogStreamKind::Stdout,
                    message: line.to_string(),
                    correlation_id: None,
                });
            }
        }
        if include_stderr {
            let stderr = String::from_utf8_lossy(&out.stderr);
            for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
                events.push(LogEvent {
                    timestamp_ms: now_ms,
                    ident: ident_clone.clone(),
                    stream: LogStreamKind::Stderr,
                    message: line.to_string(),
                    correlation_id: None,
                });
            }
        }

        Ok(Box::pin(tokio_stream::iter(events)))
    }

    /// Docker graceful upgrade (R600-F4). The dev/pond docker backend does not
    /// wire the shared upgrade-socket + network-namespace plumbing that
    /// pingora's cross-container fd-handoff needs (its `deploy_workload` renders
    /// no volumes), so a true zero-downtime swap is not available here. This
    /// re-deploys the (already re-rendered) spec — the container comes back with
    /// the new cert files — and logs that the reload drops in-flight
    /// connections. The zero-downtime handoff (sandbox-held netns or
    /// kamaji-held listening fd) is R600-F7; dev/pond passway tolerates the
    /// brief blip.
    async fn graceful_upgrade_workload(
        &self,
        spec: &WorkloadSpec,
        mesh: &MeshAssignment,
    ) -> Result<DeployResult> {
        tracing::warn!(
            ident = %spec.expose.mesh.identity.0,
            "Backend::Docker graceful_upgrade_workload performs a connection-dropping \
             reload (re-deploy) — pingora zero-downtime fd-handoff is a containerd/native \
             capability; the new cert goes live but existing connections are dropped"
        );
        self.deploy_workload(spec, mesh).await
    }

    async fn restart_workload(&self, ident: &MeshIdent) -> Result<()> {
        let name = Self::container_name(ident);
        let out = self
            .cmd()
            .args(["restart", name])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker restart {name}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(anyhow!("docker restart {name} failed: {}", stderr.trim()));
        }
        tracing::info!(name = %name, "docker workload restarted");
        Ok(())
    }

    async fn teardown_workload(&self, ident: &MeshIdent) -> Result<()> {
        let name = Self::container_name(ident);

        // Stop gracefully first (5 s grace, matching containerd's default).
        // "No such container" is swallowed — teardown is idempotent.
        let stop = self
            .cmd()
            .args(["stop", "-t", "5", name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker stop {name}"))?;
        if !stop.status.success() {
            let stderr = String::from_utf8_lossy(&stop.stderr);
            if !is_missing_container(&stderr) {
                return Err(anyhow!("docker stop {name} failed: {}", stderr.trim()));
            }
        }

        // Force-remove the container record.
        let rm = self
            .cmd()
            .args(["rm", "-f", name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .await
            .with_context(|| format!("docker rm {name}"))?;
        if !rm.status.success() {
            let stderr = String::from_utf8_lossy(&rm.stderr);
            if !is_missing_container(&stderr) {
                return Err(anyhow!("docker rm {name} failed: {}", stderr.trim()));
            }
        }

        tracing::info!(name = %name, "docker workload torn down");
        Ok(())
    }

    async fn health(&self) -> Result<RuntimeHealth> {
        let out = self
            .cmd()
            .args(["version", "--format", "{{.Server.Version}}"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await;

        match out {
            Ok(o) if o.status.success() => {
                let version = String::from_utf8_lossy(&o.stdout).trim().to_string();
                Ok(RuntimeHealth {
                    ok: true,
                    version: if version.is_empty() {
                        None
                    } else {
                        Some(version)
                    },
                    detail: None,
                })
            }
            Ok(o) => {
                let detail = String::from_utf8_lossy(&o.stderr).trim().to_string();
                Ok(RuntimeHealth {
                    ok: false,
                    version: None,
                    detail: if detail.is_empty() {
                        None
                    } else {
                        Some(detail)
                    },
                })
            }
            Err(e) => Ok(RuntimeHealth {
                ok: false,
                version: None,
                detail: Some(e.to_string()),
            }),
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// The `docker run --restart` value implementing a [`RestartPolicy`].
///
/// `Always` deliberately renders as **`unless-stopped`**, not `always`. Both
/// restart the container on any exit; they differ on one case, and it is the
/// case this whole relay is about: after an explicit `docker stop`, `always`
/// resurrects the container the next time the daemon starts, while
/// `unless-stopped` leaves it stopped. A deliberate stop is operator intent,
/// and intent has to survive a daemon (or laptop) restart — otherwise
/// "supervised" and "stoppable" are mutually exclusive. Crash restarts, the
/// thing `Always` actually promises, are identical under both.
fn restart_flag(policy: &workload_spec::RestartPolicy) -> String {
    use workload_spec::RestartPolicy as P;
    match policy {
        P::Always => "unless-stopped".into(),
        // Docker counts attempts itself and gives up after `max_attempts`,
        // leaving the container exited — the same terminal state kamaji's
        // status mapping reports as Failed. Docker's own backoff is fixed
        // (100ms doubling), so `backoff` is not representable here; the
        // containerd backend, which synthesises restarts from its own ledger,
        // is where a custom curve applies.
        P::OnFailure { max_attempts, .. } => format!("on-failure:{max_attempts}"),
        P::Never => "no".into(),
    }
}

/// Host→container port pairs from the [`PUBLISH_ANNOTATION`], in declaration
/// order. Absent annotation means no published ports.
///
/// Errors on a malformed entry rather than silently dropping it: a pond slot
/// whose host port never got published fails its readiness probe minutes later
/// with a far less obvious message.
fn parse_publish(spec: &WorkloadSpec) -> Result<Vec<(u16, u16)>> {
    let Some(raw) = spec.annotations.get(PUBLISH_ANNOTATION) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        let (host, container) = entry.split_once(':').ok_or_else(|| {
            anyhow!("{PUBLISH_ANNOTATION} entry {entry:?} is not `host:container`")
        })?;
        let host: u16 = host
            .trim()
            .parse()
            .with_context(|| format!("{PUBLISH_ANNOTATION} host port in {entry:?}"))?;
        let container: u16 = container
            .trim()
            .parse()
            .with_context(|| format!("{PUBLISH_ANNOTATION} container port in {entry:?}"))?;
        out.push((host, container));
    }
    Ok(out)
}

/// User-defined bridge network from [`NETWORK_ANNOTATION`], if declared.
fn docker_network(spec: &WorkloadSpec) -> Option<&str> {
    spec.annotations
        .get(NETWORK_ANNOTATION)
        .map(String::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty())
}

/// DNS aliases from [`NETWORK_ALIAS_ANNOTATION`], in declaration order.
fn network_aliases(spec: &WorkloadSpec) -> Vec<&str> {
    spec.annotations
        .get(NETWORK_ALIAS_ANNOTATION)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|a| !a.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Translate a docker daemon state snapshot into a `WorkloadStatus`.
///
/// The docker daemon itself maintains `RestartCount` and surfaces the
/// `Restarting` flag — no in-yubaba ledger is needed (R471-S1 verdict).
fn map_docker_state(state: &DockerState, restart_count: u32) -> WorkloadStatus {
    // Check the Restarting flag first — it's set while dockerd is sleeping
    // between restart attempts. The Status string may lag behind in some
    // versions; treat either signal as authoritative.
    if state.restarting || state.status == "restarting" {
        return WorkloadStatus::Restarting {
            last_exit_code: state.exit_code,
            restart_count,
            last_finished_at_unix_ms: parse_docker_timestamp_ms(&state.finished_at),
        };
    }
    match state.status.as_str() {
        "running" => WorkloadStatus::Running,
        "created" => WorkloadStatus::Pending,
        "paused" | "removing" => WorkloadStatus::Stopping,
        "exited" if state.exit_code == 0 => WorkloadStatus::Stopped,
        "exited" => WorkloadStatus::Failed {
            reason: format!("exited with code {}", state.exit_code),
        },
        "dead" => WorkloadStatus::Failed {
            reason: "container is dead".into(),
        },
        other => WorkloadStatus::Failed {
            reason: format!("unknown docker status: {other}"),
        },
    }
}

/// Parse Docker's UTC ISO8601 timestamp into Unix milliseconds.
///
/// Returns 0 for the sentinel zero value (`"0001-01-01…"`) or on any parse
/// failure. This value is used only for display (`"Restarting (N) · M ago"`
/// chips), so precision vs a proper calendar library is acceptable.
fn parse_docker_timestamp_ms(s: &str) -> u64 {
    if s.is_empty() || s.starts_with("0001") {
        return 0;
    }
    // Format: "YYYY-MM-DDTHH:MM:SS[.nnnnnnnZ]" — always UTC.
    let s = s.trim_end_matches('Z');
    let (date_part, time_part) = match s.split_once('T') {
        Some(p) => p,
        None => return 0,
    };

    let mut dp = date_part.splitn(3, '-');
    let year: u64 = dp.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let month: u64 = dp.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let day: u64 = dp.next().and_then(|p| p.parse().ok()).unwrap_or(0);

    // Strip fractional seconds before splitting on ':'.
    let time_no_frac = time_part.split('.').next().unwrap_or("");
    let mut tp = time_no_frac.splitn(3, ':');
    let hour: u64 = tp.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let min: u64 = tp.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let sec: u64 = tp.next().and_then(|p| p.parse().ok()).unwrap_or(0);

    if year < 1970 || month == 0 || month > 12 || day == 0 {
        return 0;
    }

    // Days from 1 Jan 1970 to 1 Jan `year`.
    let years_since_epoch = year - 1970;
    // One extra day per 4 years (rough Gregorian approximation; sufficient for display).
    let leap_days = years_since_epoch / 4;

    // Days in each month (non-leap). Index 0 is unused (months are 1-based).
    let days_in_month: [u64; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let days_through_month: u64 = days_in_month[..month as usize].iter().sum::<u64>();
    let day_of_year = days_through_month + day - 1;

    let total_days = years_since_epoch * 365 + leap_days + day_of_year;
    let total_secs = total_days * 86_400 + hour * 3_600 + min * 60 + sec;
    total_secs * 1_000
}

/// True when docker CLI stderr indicates the named container doesn't exist.
fn is_missing_container(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("no such container") || lower.contains("no such object")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use workload_spec::MeshIdent;

    /// True when a docker daemon is reachable. Used to skip live tests in CI.
    async fn docker_available() -> bool {
        let out = Command::new("docker")
            .args(["version"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        matches!(out, Ok(s) if s.success())
    }

    fn state(status: &str, restarting: bool, exit_code: i32) -> DockerState {
        DockerState {
            status: status.into(),
            restarting,
            exit_code,
            finished_at: "2024-01-15T10:25:03.123456789Z".into(),
            pid: if status == "running" { 4242 } else { 0 },
        }
    }

    // ── map_docker_state unit tests ───────────────────────────────────────────

    #[test]
    fn restarting_flag_overrides_status() {
        // Even if Status=="running", Restarting=true means the daemon is
        // sleeping before the next restart attempt.
        let ws = map_docker_state(&state("running", true, 137), 3);
        match ws {
            WorkloadStatus::Restarting {
                last_exit_code,
                restart_count,
                last_finished_at_unix_ms,
            } => {
                assert_eq!(last_exit_code, 137);
                assert_eq!(restart_count, 3);
                assert!(last_finished_at_unix_ms > 0);
            }
            other => panic!("expected Restarting, got {other:?}"),
        }
    }

    #[test]
    fn restarting_status_string_matches() {
        let s = DockerState {
            status: "restarting".into(),
            restarting: false, // flag may lag — status string is authoritative
            exit_code: 2,
            finished_at: "0001-01-01T00:00:00Z".into(),
            pid: 0,
        };
        let ws = map_docker_state(&s, 1);
        assert!(
            matches!(
                ws,
                WorkloadStatus::Restarting {
                    restart_count: 1,
                    last_exit_code: 2,
                    ..
                }
            ),
            "got {ws:?}"
        );
    }

    #[test]
    fn running_maps_to_running() {
        assert_eq!(
            map_docker_state(&state("running", false, 0), 0),
            WorkloadStatus::Running
        );
    }

    #[test]
    fn created_maps_to_pending() {
        assert_eq!(
            map_docker_state(&state("created", false, 0), 0),
            WorkloadStatus::Pending
        );
    }

    #[test]
    fn paused_maps_to_stopping() {
        assert_eq!(
            map_docker_state(&state("paused", false, 0), 0),
            WorkloadStatus::Stopping
        );
    }

    #[test]
    fn exited_zero_maps_to_stopped() {
        assert_eq!(
            map_docker_state(&state("exited", false, 0), 0),
            WorkloadStatus::Stopped
        );
    }

    #[test]
    fn exited_nonzero_maps_to_failed() {
        assert!(matches!(
            map_docker_state(&state("exited", false, 1), 0),
            WorkloadStatus::Failed { .. }
        ));
    }

    #[test]
    fn dead_maps_to_failed() {
        assert!(matches!(
            map_docker_state(&state("dead", false, 0), 0),
            WorkloadStatus::Failed { .. }
        ));
    }

    // ── host_pid ──────────────────────────────────────────────────────────────

    #[test]
    fn running_container_reports_its_host_pid() {
        assert_eq!(state("running", false, 0).host_pid(), Some(4242));
    }

    #[test]
    fn zero_pid_means_no_running_process() {
        // Docker reports `.State.Pid == 0` for created / exited / dead
        // containers — a listing must not present that as a live pid.
        assert_eq!(state("exited", false, 0).host_pid(), None);
        assert_eq!(state("created", false, 0).host_pid(), None);
    }

    #[test]
    fn negative_pid_is_rejected() {
        let mut s = state("running", false, 0);
        s.pid = -1;
        assert_eq!(s.host_pid(), None);
    }

    /// The full inspect → `DockerWorkload` path carries the pid and the mesh
    /// identity from the `yah.ident` label, not the container name.
    #[test]
    fn inspect_to_workload_carries_pid_and_label_ident() {
        let di = DockerInspect {
            id: "deadbeef".into(),
            state: state("running", false, 0),
            restart_count: 0,
            config: DockerConfig {
                labels: Some(HashMap::from([
                    ("yah.ident".to_string(), "yah-marketing".to_string()),
                    ("yah.mesh_ip".to_string(), "100.64.0.7".to_string()),
                ])),
            },
        };
        let w = DockerRuntime::inspect_to_workload(di, MeshIdent("yah-marketing".into()));
        assert_eq!(w.pid, Some(4242));
        assert_eq!(w.state.status, WorkloadStatus::Running);
        assert_eq!(w.state.container_id, "deadbeef");
        assert_eq!(w.state.mesh_ip, Some("100.64.0.7".parse().unwrap()));
    }

    /// R590-B9: a forge workload's id (`forge-<uuid>`) and mesh identity
    /// (`forge.<uuid>`) differ. The workload id comes off its own label, not
    /// from the identity, so a Stop keyed on the id can find the container.
    #[test]
    fn workload_id_comes_from_its_label_not_the_identity() {
        let di = DockerInspect {
            id: "deadbeef".into(),
            state: state("running", false, 0),
            restart_count: 0,
            config: DockerConfig {
                labels: Some(HashMap::from([
                    ("yah.ident".to_string(), "forge.abc".to_string()),
                    (WORKLOAD_ID_LABEL.to_string(), "forge-abc".to_string()),
                ])),
            },
        };
        let w = DockerRuntime::inspect_to_workload(di, MeshIdent("forge.abc".into()));
        assert_eq!(w.workload_id, "forge-abc");
        assert_eq!(w.state.ident.0, "forge.abc");
    }

    /// Containers deployed before the `yah.workload_id` label existed still
    /// resolve — falling back to the mesh identity is correct for every
    /// workload whose name and identity agree, which is all of them but forge.
    #[test]
    fn workload_id_falls_back_to_identity_when_label_absent() {
        let di = DockerInspect {
            id: "deadbeef".into(),
            state: state("running", false, 0),
            restart_count: 0,
            config: DockerConfig {
                labels: Some(HashMap::from([(
                    "yah.ident".to_string(),
                    "passway".to_string(),
                )])),
            },
        };
        let w = DockerRuntime::inspect_to_workload(di, MeshIdent("passway".into()));
        assert_eq!(w.workload_id, "passway");
    }

    /// `yah.ident` wins over the container name; a label-less container falls
    /// back to the name so it still lists under a stable identity.
    #[test]
    fn ident_of_prefers_label_then_falls_back_to_name() {
        let with_label = DockerInspect {
            id: "a".into(),
            state: state("running", false, 0),
            restart_count: 0,
            config: DockerConfig {
                labels: Some(HashMap::from([(
                    "yah.ident".to_string(),
                    "forge.abc".to_string(),
                )])),
            },
        };
        assert_eq!(
            DockerRuntime::ident_of(&with_label, "forge-abc").0,
            "forge.abc"
        );

        let no_label = DockerInspect {
            id: "b".into(),
            state: state("running", false, 0),
            restart_count: 0,
            config: DockerConfig { labels: None },
        };
        assert_eq!(DockerRuntime::ident_of(&no_label, "orphan").0, "orphan");
    }

    // ── run_args rendering (R626-F2) ──────────────────────────────────────────

    fn test_spec(name: &str) -> WorkloadSpec {
        use workload_spec::*;
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.to_string(),
            image: ImageRef {
                registry: "docker.io".into(),
                repository: "library/alpine".into(),
                tag: "latest".into(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".into()),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
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
                ephemeral_storage_mb: 128,
            },
            depends_on: vec![],
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
            annotations: Default::default(),
        }
    }

    fn render(spec: &WorkloadSpec) -> Vec<String> {
        DockerRuntime::run_args(
            spec,
            &MeshAssignment::inlined("127.0.0.1".parse().unwrap()),
            "alpine:latest",
            &spec.expose.mesh.identity.0,
        )
        .expect("render")
    }

    /// Value following the (first) occurrence of `flag` in the argv.
    fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    }

    /// All values following each occurrence of `flag`.
    fn flag_values<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
        args.iter()
            .enumerate()
            .filter(|(_, a)| a.as_str() == flag)
            .filter_map(|(i, _)| args.get(i + 1))
            .map(String::as_str)
            .collect()
    }

    /// The blocker R626-F2 was gated on: without `--restart`, deleting pond's
    /// resurrect loops would leave nothing restarting a crashed container.
    #[test]
    fn every_deploy_carries_a_restart_flag() {
        let spec = test_spec("passway");
        assert_eq!(flag_value(&render(&spec), "--restart"), Some("no"));
    }

    /// `Always` renders `unless-stopped` so an explicit stop survives a daemon
    /// restart — the desired-state property R626 exists for.
    #[test]
    fn always_renders_unless_stopped_not_always() {
        use workload_spec::RestartPolicy;
        assert_eq!(restart_flag(&RestartPolicy::Always), "unless-stopped");
    }

    #[test]
    fn on_failure_carries_the_attempt_cap() {
        use workload_spec::{BackoffPolicy, RestartPolicy};
        let p = RestartPolicy::OnFailure {
            max_attempts: 3,
            backoff: BackoffPolicy {
                initial_ms: 100,
                max_ms: 1000,
                multiplier: 2.0,
            },
        };
        assert_eq!(restart_flag(&p), "on-failure:3");
    }

    #[test]
    fn never_renders_no() {
        use workload_spec::RestartPolicy;
        assert_eq!(restart_flag(&RestartPolicy::Never), "no");
    }

    #[test]
    fn nonzero_resource_limits_render() {
        let args = render(&test_spec("capped"));
        assert_eq!(flag_value(&args, "--memory"), Some("64m"));
        assert_eq!(flag_value(&args, "--cpu-shares"), Some("131"));
    }

    /// Zero means unenforced — pond's slots run uncapped, and `--memory 0m`
    /// is not the same statement as omitting the flag.
    #[test]
    fn zero_resource_limits_are_omitted() {
        let mut spec = test_spec("uncapped");
        spec.resources.memory_mb = 0;
        spec.resources.cpu_millis = 0;
        let args = render(&spec);
        assert!(flag_value(&args, "--memory").is_none(), "{args:?}");
        assert!(flag_value(&args, "--cpu-shares").is_none(), "{args:?}");
    }

    /// R844-T13: the container reads the same `PORT` / `PORT_HTTP` a native
    /// child does, and a spec literal still wins — `docker run` takes the final
    /// `--env` for a repeated name, which is why the contract is emitted first.
    #[test]
    fn the_port_env_contract_renders_and_yields_to_a_spec_literal() {
        let mut spec = test_spec("web");
        spec.expose.mesh.ports = workload_spec::MeshExpose::anonymous_ports([8080]);
        let args = render(&spec);
        let env = flag_values(&args, "--env");
        assert!(env.contains(&"PORT=8080"), "{env:?}");
        assert!(env.contains(&"PORT_HTTP=8080"), "{env:?}");

        spec.env = vec![workload_spec::EnvVar {
            name: "PORT".into(),
            value: workload_spec::EnvValue::Literal {
                value: "9999".into(),
            },
        }];
        let args = render(&spec);
        let env = flag_values(&args, "--env");
        let last_port = env.iter().filter(|e| e.starts_with("PORT=")).next_back();
        assert_eq!(last_port, Some(&"PORT=9999"), "{env:?}");
    }

    #[test]
    fn published_ports_render_in_declaration_order() {
        let mut spec = test_spec("minio");
        spec.annotations
            .insert(PUBLISH_ANNOTATION.into(), "9000:9000, 9001:9001".into());
        assert_eq!(
            flag_values(&render(&spec), "-p"),
            ["9000:9000", "9001:9001"]
        );
    }

    #[test]
    fn no_publish_annotation_publishes_nothing() {
        assert!(flag_values(&render(&test_spec("minio")), "-p").is_empty());
    }

    /// A malformed port pair is an error, not a silent drop — a pond slot whose
    /// host port never got published fails a readiness probe minutes later with
    /// a much worse message.
    #[test]
    fn malformed_publish_entry_is_an_error() {
        let mut spec = test_spec("minio");
        spec.annotations
            .insert(PUBLISH_ANNOTATION.into(), "9000".into());
        let err = DockerRuntime::run_args(
            &spec,
            &MeshAssignment::inlined("127.0.0.1".parse().unwrap()),
            "alpine:latest",
            "minio",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("host:container"), "got {err}");
    }

    #[test]
    fn network_and_aliases_render_together() {
        let mut spec = test_spec("minio");
        spec.annotations
            .insert(NETWORK_ANNOTATION.into(), "yah-pond-svc-pond".into());
        spec.annotations
            .insert(NETWORK_ALIAS_ANNOTATION.into(), "minio,object-store".into());
        let args = render(&spec);
        assert_eq!(flag_value(&args, "--network"), Some("yah-pond-svc-pond"));
        assert_eq!(
            flag_values(&args, "--network-alias"),
            ["minio", "object-store"]
        );
    }

    /// Docker rejects `--network-alias` without a user-defined network, so an
    /// alias with no network is dropped rather than rendered into a run that
    /// would fail.
    #[test]
    fn aliases_without_a_network_are_dropped() {
        let mut spec = test_spec("minio");
        spec.annotations
            .insert(NETWORK_ALIAS_ANNOTATION.into(), "minio".into());
        let args = render(&spec);
        assert!(flag_values(&args, "--network-alias").is_empty());
        assert!(flag_value(&args, "--network").is_none());
    }

    #[test]
    fn bind_named_and_tmpfs_volumes_each_render() {
        use workload_spec::{VolumeMount, VolumeSource};
        let mut spec = test_spec("minio");
        spec.volumes = vec![
            VolumeMount {
                source: VolumeSource::Bind {
                    host_path: "/var/lib/pond/minio".into(),
                },
                target: "/data".into(),
                read_only: false,
            },
            VolumeMount {
                source: VolumeSource::Named {
                    name: "assets".into(),
                },
                target: "/assets".into(),
                read_only: true,
            },
            VolumeMount {
                source: VolumeSource::Tmpfs { size_mb: 64 },
                target: "/scratch".into(),
                read_only: false,
            },
        ];
        let args = render(&spec);
        assert_eq!(
            flag_values(&args, "-v"),
            ["/var/lib/pond/minio:/data", "assets:/assets:ro"]
        );
        assert_eq!(flag_values(&args, "--tmpfs"), ["/scratch:size=64m"]);
    }

    /// Spec labels ride alongside the identity labels, and render in a stable
    /// order despite `labels` being a HashMap.
    #[test]
    fn spec_labels_render_sorted_after_identity_labels() {
        let mut spec = test_spec("minio");
        spec.labels.insert("zeta".into(), "1".into());
        spec.labels.insert("alpha".into(), "2".into());
        let args = render(&spec);
        let labels = flag_values(&args, "--label");
        assert_eq!(
            labels,
            [
                "yah.ident=minio",
                "yah.workload_id=minio",
                "yah.mesh_ip=127.0.0.1",
                "alpha=2",
                "zeta=1",
            ]
        );
    }

    /// Every option must precede the image ref, or docker parses it as an
    /// argument to the container's command instead.
    #[test]
    fn image_and_command_come_last() {
        let mut spec = test_spec("minio");
        spec.command = Some(vec!["server".into(), "/data".into()]);
        spec.annotations
            .insert(PUBLISH_ANNOTATION.into(), "9000:9000".into());
        let args = render(&spec);
        let image_at = args.iter().position(|a| a == "alpine:latest").unwrap();
        assert_eq!(&args[image_at + 1..], ["server", "/data"]);
        assert!(
            args[..image_at].contains(&"-p".to_string()),
            "options must precede the image: {args:?}"
        );
    }

    // ── parse_docker_timestamp_ms unit tests ──────────────────────────────────

    #[test]
    fn zero_timestamp_returns_zero() {
        assert_eq!(parse_docker_timestamp_ms("0001-01-01T00:00:00Z"), 0);
        assert_eq!(parse_docker_timestamp_ms(""), 0);
    }

    #[test]
    fn known_timestamp_is_positive_and_in_range() {
        // "2024-01-15T10:25:03Z" is well past the epoch and before today.
        let ms = parse_docker_timestamp_ms("2024-01-15T10:25:03Z");
        assert!(ms > 1_000_000_000_000, "expected ms > 1e12, got {ms}");
        // Sanity upper bound: 2030-01-01 in ms ≈ 1.9e12
        assert!(ms < 2_000_000_000_000, "expected ms < 2e12, got {ms}");
    }

    #[test]
    fn fractional_seconds_accepted() {
        let ms = parse_docker_timestamp_ms("2024-01-15T10:25:03.123456789Z");
        assert!(ms > 1_000_000_000_000, "got {ms}");
    }

    // ── is_missing_container ──────────────────────────────────────────────────

    #[test]
    fn missing_container_detection() {
        assert!(is_missing_container("Error: No such container: foo"));
        assert!(is_missing_container(
            "Error response from daemon: No such object: bar"
        ));
        assert!(!is_missing_container("Error: permission denied"));
    }

    // ── live docker tests (skip when daemon unreachable) ──────────────────────

    #[tokio::test]
    async fn health_returns_ok_when_docker_reachable() {
        if !docker_available().await {
            eprintln!("SKIP: docker not reachable");
            return;
        }
        let rt = DockerRuntime::new();
        let h = rt.health().await.unwrap();
        assert!(h.ok, "expected healthy docker daemon: {:?}", h.detail);
        assert!(h.version.is_some(), "expected version string");
    }

    #[tokio::test]
    async fn get_workload_returns_none_for_nonexistent() {
        if !docker_available().await {
            eprintln!("SKIP: docker not reachable");
            return;
        }
        let rt = DockerRuntime::new();
        let ident = MeshIdent("r471-f3-nonexistent-sentinel".to_string());
        let result = rt.get_workload(&ident).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_workloads_does_not_error() {
        if !docker_available().await {
            eprintln!("SKIP: docker not reachable");
            return;
        }
        // May or may not have yah.ident containers — just assert no error.
        let rt = DockerRuntime::new();
        let _ = rt.list_workloads().await.unwrap();
    }

    #[tokio::test]
    async fn teardown_is_idempotent_for_missing_container() {
        if !docker_available().await {
            eprintln!("SKIP: docker not reachable");
            return;
        }
        let rt = DockerRuntime::new();
        let ident = MeshIdent("r471-f3-teardown-idempotent-sentinel".to_string());
        // Should not error even when the container has never existed.
        rt.teardown_workload(&ident).await.unwrap();
    }
}

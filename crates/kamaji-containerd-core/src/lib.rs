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

    // R590-B7: DNS for host-networked workloads. Sharing the host netns gives
    // the container IP egress, but raw runc (unlike docker/containerd-CRI) does
    // not synthesize /etc/resolv.conf, and workload images typically ship none —
    // so name resolution fails (a build's `git clone github.com` dies before the
    // first packet). Bind-mount the host resolver read-only. Only under host
    // networking: an isolated netns has no upstream resolver to inherit, and the
    // bind is skipped when the host has no /etc/resolv.conf (runc would refuse a
    // mount with a missing source).
    if spec.wants_host_network() && std::path::Path::new("/etc/resolv.conf").exists() {
        mounts.push(serde_json::json!({
            "destination": "/etc/resolv.conf", "type": "bind", "source": "/etc/resolv.conf",
            "options": ["rbind","ro","nosuid","nodev"]
        }));
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
        RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag, WorkloadSpec,
    };

    fn test_spec(name: &str) -> WorkloadSpec {
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
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
                ephemeral_storage_mb: 128,
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
            annotations: Default::default(),
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

    fn network_ns<'a>(oci: &'a serde_json::Value) -> Option<&'a serde_json::Value> {
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
}

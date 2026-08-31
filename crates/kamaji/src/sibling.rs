//! Sibling-deployment client (W199 shape 2): postcard-over-UDS
//! [`KamajiClient`] for callers that talk to a separate
//! `kamaji.service` process.
//!
//! ## Why
//!
//! Per [W199](../../../../.yah/docs/working/W199-kamaji-universal-supervisor.md),
//! Kamaji has two deployment shapes:
//!
//! - **Inlined** — same process as the caller; caller holds
//!   `Arc<dyn Kamaji>` directly (see [`crate::inlined`]).
//! - **Sibling** — separate process supervised by the host's PID 1
//!   (systemd / container PID 1 / launchd). Caller holds a
//!   [`KamajiClient`] that speaks the [`kamaji_proto`] wire format
//!   over a unix domain socket. This module owns the caller side.
//!
//! Carved out of yubaba as part of R484-T4. Yubaba previously hosted this at
//! `crates/yah/yubaba/src/constable_client.rs`; the file is now a re-export
//! shim there.
//!
//! ## Shape
//!
//! - Single persistent `tokio::net::UnixStream`, owned by a
//!   [`KamajiClient`].
//! - Requests serialize as `YubabaToKamaji` postcard frames; responses
//!   deserialize from `KamajiToYubaba`. The codec is shared with
//!   `app/yah/kamaji`'s server.
//! - The socket halves are owned by two background tasks — a **reader** that
//!   demuxes replies to waiters by [`RequestId`], and a **writer** fed by an
//!   mpsc queue. Callers never touch the socket; they park on a `oneshot`.
//! - On connect, the client exchanges `Hello`/`Welcome` to verify the
//!   protocol version and capture Kamaji's build version for tracing.
//!
//! ## Why a demux actor, not a serial mutex
//!
//! This client used to hold a `Mutex<Inner>` across `write_frame` then
//! `read_frame`, correlating by position rather than by `RequestId`. That is
//! **not cancel-safe**, and the failure is permanent rather than transient:
//! drop the calling future between the write and the read — which is exactly
//! what axum does to a handler when an HTTP client times out or disconnects —
//! and the request id is consumed while Kamaji's reply stays queued in the
//! socket. Every later call then reads the *previous* call's reply. The
//! connection is off-by-one forever, `check_rid` can only report it
//! (`expected 89, got 88`), and nothing short of a yubaba restart clears it.
//!
//! Owning both halves in tasks fixes both directions. A cancelled caller drops
//! its `oneshot::Receiver`, so its reply is discarded instead of being handed
//! to the next caller; and because the actual `write_all` happens in the writer
//! task rather than in the caller's future, a cancel can never leave a partial
//! frame on the wire.
//!
//! Demuxing by id is also what lets pushed messages coexist with replies:
//! `WorkloadStarted` / `WorkloadExited` carry no `RequestId` at all, so under
//! the old positional scheme the first one Kamaji ever sent would have been
//! delivered to some unrelated caller as its reply.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use kamaji_proto::{
    decode_frame, encode_frame, DrainBudget, Error as CodecError, ErrorCode, KamajiToYubaba,
    ProbeStatus, ProtocolVersion, RequestId, WorkloadEntry, WorkloadId, YubabaToKamaji,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{unix::OwnedReadHalf, unix::OwnedWriteHalf, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Default yubaba ↔ Kamaji socket path used when no override is provided.
///
/// Matches the production layout in W154 §"The supervisor split". `app/yah/
/// kamaji` defaults to the same path via its `KAMAJI_SOCK` env var
/// fallback, so a stock systemd-managed deploy needs no extra plumbing.
pub const DEFAULT_SOCKET: &str = "/run/yah/kamaji.sock";

/// Errors surfaced by [`KamajiClient`] calls.
///
/// Distinct from the underlying codec errors so the yubaba HTTP layer can
/// branch on connectivity vs. protocol-level rejections.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// I/O failure on the UDS — connection dropped, socket missing, partial
    /// write. Yubaba treats this as "Kamaji is unreachable" and may fall
    /// back to the legacy in-process runtime where one is configured.
    #[error("kamaji UDS I/O: {0}")]
    Io(#[from] std::io::Error),

    /// Codec rejected a frame — almost always a Kamaji bug.
    #[error("kamaji wire codec: {0}")]
    Codec(#[from] CodecError),

    /// Connection closed mid-request (EOF on read).
    #[error("kamaji closed the connection mid-request")]
    PeerClosed,

    /// Kamaji returned `Error { code, message }` for our request.
    #[error("kamaji error: {code:?}: {message}")]
    Remote { code: ErrorCode, message: String },

    /// Response payload was the wrong variant for the request kind. Tag is
    /// a debug rendering of the unexpected variant.
    #[error("kamaji replied with unexpected variant: {0}")]
    Unexpected(String),

    /// Kamaji handshake rejected our protocol version.
    #[error("kamaji rejected handshake (version {wanted:?})")]
    HandshakeRefused { wanted: ProtocolVersion },
}

/// Waiters for in-flight requests, keyed by the id they were sent with.
///
/// The reader task removes an entry when it delivers, and a caller's
/// [`PendingGuard`] removes it if the caller goes away first — so a cancelled
/// request leaves nothing behind for the next reply to land on.
#[derive(Debug, Default)]
struct Shared {
    pending: Mutex<HashMap<RequestId, oneshot::Sender<KamajiToYubaba>>>,
    /// Set once either task exits. Read before enqueuing so a request onto a
    /// dead connection fails fast instead of parking forever.
    dead: AtomicBool,
}

impl Shared {
    /// Mark the connection dead and drop every waiter's sender, which wakes
    /// each parked caller with [`ClientError::PeerClosed`].
    fn shutdown(&self) {
        self.dead.store(true, Ordering::Release);
        self.pending.lock().unwrap().clear();
    }

    /// Fail every waiter with a copy of an error Kamaji sent without a
    /// `RequestId`. See [`reader_loop`] for why this is a broadcast.
    fn fail_all(&self, code: ErrorCode, message: &str) {
        let waiters: Vec<_> = self.pending.lock().unwrap().drain().collect();
        for (rid, tx) in waiters {
            let _ = tx.send(KamajiToYubaba::Error {
                request_id: Some(rid),
                code,
                message: message.to_string(),
            });
        }
    }
}

/// Removes a caller's pending entry on drop, including when the drop is a
/// cancellation. Delivery already removed it, so the common path is a no-op.
struct PendingGuard<'a> {
    shared: &'a Shared,
    rid: RequestId,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.shared.pending.lock().unwrap().remove(&self.rid);
    }
}

/// Kamaji-side metadata learned during the handshake. Used for tracing
/// and operator visibility (`GET /health` could surface the kamaji build
/// version later).
#[derive(Debug, Clone)]
pub struct ConstableInfo {
    pub version: ProtocolVersion,
    pub kamaji_version: String,
}

/// UDS client for talking to a sibling Kamaji process.
///
/// Construct with [`KamajiClient::connect`]; share via `Arc<...>` if
/// multiple handlers need it.
#[derive(Debug)]
pub struct KamajiClient {
    socket: PathBuf,
    next_request_id: AtomicU64,
    info: ConstableInfo,
    shared: Arc<Shared>,
    /// Encoded frames queued for the writer task. Unbounded so enqueuing has
    /// no `.await` in it, which is what keeps [`KamajiClient::request`]'s send
    /// leg uncancellable.
    outbound: mpsc::UnboundedSender<Vec<u8>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for KamajiClient {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl KamajiClient {
    /// Open the socket, exchange `Hello`/`Welcome`, and return a ready
    /// client. Errors if the socket isn't there, Kamaji rejects the
    /// protocol version, or the handshake reply is malformed.
    pub async fn connect(socket: impl Into<PathBuf>) -> Result<Self, ClientError> {
        let socket = socket.into();
        let stream = UnixStream::connect(&socket).await?;
        let (mut rd, mut wr) = stream.into_split();
        // Carried into the reader task: the handshake read may have pulled the
        // leading bytes of a following frame off the socket already.
        let mut buf = Vec::with_capacity(4096);

        // Handshake — write Hello, read Welcome (or Error). Runs inline on the
        // caller's future rather than in the tasks, so a refused version or a
        // dead socket surfaces from `connect` itself.
        let hello = YubabaToKamaji::Hello {
            version: ProtocolVersion::CURRENT,
        };
        write_frame(&mut wr, &hello).await?;
        let reply = read_frame(&mut rd, &mut buf).await?;
        let info = match reply {
            KamajiToYubaba::Welcome {
                version,
                kamaji_version,
            } => ConstableInfo {
                version,
                kamaji_version,
            },
            KamajiToYubaba::Error { code, message, .. } => {
                return Err(ClientError::Remote { code, message });
            }
            other => return Err(ClientError::Unexpected(format!("{other:?}"))),
        };

        info!(
            socket = %socket.display(),
            kamaji_version = %info.kamaji_version,
            "kamaji handshake complete"
        );

        let shared = Arc::new(Shared::default());
        let (outbound, rx) = mpsc::unbounded_channel();
        let tasks = vec![
            tokio::spawn(reader_loop(rd, buf, Arc::clone(&shared))),
            tokio::spawn(writer_loop(wr, rx, Arc::clone(&shared))),
        ];

        Ok(Self {
            socket,
            next_request_id: AtomicU64::new(1),
            info,
            shared,
            outbound,
            tasks,
        })
    }

    /// Path this client connected to. Useful for tracing.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Kamaji build + protocol version captured during handshake.
    pub fn info(&self) -> &ConstableInfo {
        &self.info
    }

    /// True once the reader or writer task has exited — a request sent now
    /// would fail immediately with [`ClientError::PeerClosed`]. Used by
    /// [`KamajiSibling`]'s reconnect watchdog to detect a dropped sibling
    /// without waiting for a caller to notice first.
    pub fn is_dead(&self) -> bool {
        self.shared.dead.load(Ordering::Acquire)
    }

    fn next_request_id(&self) -> RequestId {
        RequestId(self.next_request_id.fetch_add(1, Ordering::Relaxed))
    }

    /// `YubabaToKamaji::List` — every workload Kamaji is supervising.
    pub async fn list(&self) -> Result<Vec<WorkloadEntry>, ClientError> {
        let request_id = self.next_request_id();
        let reply = self
            .request(YubabaToKamaji::List { request_id }, request_id)
            .await?;
        match reply {
            KamajiToYubaba::WorkloadList { entries, .. } => Ok(entries),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `YubabaToKamaji::Deploy` with an arbitrary [`Workload`] envelope.
    ///
    /// The general form of a deploy: the caller picks the variant, so this
    /// carries `Workload::MesofactStatic` (the W272 bundle path, R599) as
    /// readily as `Workload::Container`. [`Kamaji::deploy_workload`] is the
    /// container-shaped convenience wrapper over this.
    ///
    /// Admission — validation, mesh-IP allocation, secret materialization,
    /// ownership rows — stays on yubaba's side of this call. Kamaji supervises
    /// what it is handed; it does not re-litigate whether the workload should
    /// run.
    ///
    /// `mesh` carries that admission's mesh-plane placement (R599-F12). Pass
    /// `None` when the deployment has no mesh IP plane — a pond or desktop node
    /// — and kamaji binds loopback. Passing the
    /// [`MeshAssignment::inlined`](crate::MeshAssignment::inlined) sentinel is
    /// *not* the way to say that: it would read on the wire as a real
    /// instruction to bind a loopback-ish address, so callers holding a sentinel
    /// should send `None` instead.
    ///
    /// [`Kamaji::deploy_workload`]: crate::Kamaji::deploy_workload
    pub async fn deploy_envelope(
        &self,
        id: &WorkloadId,
        workload: &workload_spec::Workload,
        mesh: Option<&crate::MeshAssignment>,
    ) -> Result<(), ClientError> {
        let request_id = self.next_request_id();
        let reply = self
            .request(
                YubabaToKamaji::Deploy {
                    request_id,
                    id: id.clone(),
                    spec: workload.clone(),
                    mesh: mesh.map(mesh_to_proto),
                },
                request_id,
            )
            .await?;
        match reply {
            KamajiToYubaba::Ack {
                kind: kamaji_proto::AckKind::Deploy,
                ..
            } => Ok(()),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `YubabaToKamaji::Stop` — SIGTERM-with-grace floor. Returns when
    /// Kamaji acks the stop request; the workload may still be reaping
    /// when this returns.
    pub async fn stop(&self, id: &WorkloadId) -> Result<(), ClientError> {
        let request_id = self.next_request_id();
        let reply = self
            .request(
                YubabaToKamaji::Stop {
                    request_id,
                    id: id.clone(),
                },
                request_id,
            )
            .await?;
        match reply {
            KamajiToYubaba::Ack { .. } => Ok(()),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `YubabaToKamaji::Drain` — structured drain with a deadline budget.
    /// Returns `(accepted, reason)` from Kamaji's synchronous `DrainAck`.
    pub async fn drain(
        &self,
        id: &WorkloadId,
        budget: DrainBudget,
    ) -> Result<(bool, Option<String>), ClientError> {
        let request_id = self.next_request_id();
        let reply = self
            .request(
                YubabaToKamaji::Drain {
                    request_id,
                    id: id.clone(),
                    budget,
                },
                request_id,
            )
            .await?;
        match reply {
            KamajiToYubaba::DrainAck {
                accepted, reason, ..
            } => Ok((accepted, reason)),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `YubabaToKamaji::DeployStatus` — where an asynchronous bundle deploy
    /// has got to (R330-F33).
    ///
    /// A bundle [`deploy_envelope`] acks on admission, so this is how a caller
    /// learns whether the node actually materialized and forked it. Returns
    /// `(state, detail)`; `detail` is the failure reason on
    /// [`WorkloadState::Failed`] and `None` otherwise. An id kamaji never
    /// admitted comes back as [`ClientError::Remote`] with
    /// [`ErrorCode::UnknownWorkload`], which a polling caller must treat as
    /// terminal rather than as "not yet".
    ///
    /// [`deploy_envelope`]: Self::deploy_envelope
    /// [`WorkloadState::Failed`]: kamaji_proto::WorkloadState::Failed
    pub async fn deploy_status(
        &self,
        id: &WorkloadId,
    ) -> Result<(kamaji_proto::WorkloadState, Option<String>), ClientError> {
        let request_id = self.next_request_id();
        let reply = self
            .request(
                YubabaToKamaji::DeployStatus {
                    request_id,
                    id: id.clone(),
                },
                request_id,
            )
            .await?;
        match reply {
            KamajiToYubaba::DeployStatusResult { state, detail, .. } => Ok((state, detail)),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// `YubabaToKamaji::Probe` — fire one probe poll for the workload.
    pub async fn probe(&self, id: &WorkloadId) -> Result<ProbeStatus, ClientError> {
        let request_id = self.next_request_id();
        let reply = self
            .request(
                YubabaToKamaji::Probe {
                    request_id,
                    id: id.clone(),
                },
                request_id,
            )
            .await?;
        match reply {
            KamajiToYubaba::ProbeResult { status, .. } => Ok(status),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Register a waiter under `rid`, queue `req` for the writer task, and park
    /// until the reader routes the matching reply back. `Error{code,message}`
    /// payloads surface as [`ClientError::Remote`].
    ///
    /// Cancel-safe in both directions: the only `.await` a caller holds is on
    /// the `oneshot`, so dropping this future discards that request's reply
    /// (via [`PendingGuard`]) and cannot desynchronize anyone else's, nor leave
    /// a half-written frame on the wire.
    async fn request(
        &self,
        req: YubabaToKamaji,
        rid: RequestId,
    ) -> Result<KamajiToYubaba, ClientError> {
        let bytes = encode_frame(&req)?;
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.shared.pending.lock().unwrap();
            if self.shared.dead.load(Ordering::Acquire) {
                return Err(ClientError::PeerClosed);
            }
            pending.insert(rid, tx);
        }
        let _guard = PendingGuard {
            shared: &self.shared,
            rid,
        };

        self.outbound
            .send(bytes)
            .map_err(|_| ClientError::PeerClosed)?;
        let reply = rx.await.map_err(|_| ClientError::PeerClosed)?;

        if let KamajiToYubaba::Error {
            request_id,
            code,
            message,
        } = reply
        {
            debug!(
                ?request_id,
                ?code,
                %message,
                "kamaji returned Error for request"
            );
            return Err(ClientError::Remote { code, message });
        }
        Ok(reply)
    }
}

/// Owns the read half: decode frames, route each to its waiter, and fail every
/// waiter when the connection ends.
async fn reader_loop(mut rd: OwnedReadHalf, mut buf: Vec<u8>, shared: Arc<Shared>) {
    loop {
        let msg = match read_frame(&mut rd, &mut buf).await {
            Ok(msg) => msg,
            Err(e) => {
                debug!(error = %e, "kamaji reader loop ended");
                break;
            }
        };

        // The correlation table lives on the proto enum (R746-B11) so it is
        // exhaustive: a reply variant appended here cannot silently be routed
        // as a push.
        match msg.reply_request_id() {
            Some(rid) => {
                let waiter = shared.pending.lock().unwrap().remove(&rid);
                match waiter {
                    Some(tx) => {
                        // Send fails only if the caller was cancelled between
                        // the remove and here; the reply is then correctly
                        // dropped rather than handed to the next caller.
                        let _ = tx.send(msg);
                    }
                    None => debug!(?rid, "kamaji reply with no waiter; dropped"),
                }
            }
            // An `Error` with no id is by definition not tied to a request, yet
            // Kamaji sends one for an unhandled message kind and keeps the
            // connection open — a live yubaba talking to an older kamaji hits
            // exactly that. There is no way to tell whose failure it is, so
            // every waiter gets it: wrong-but-loud beats parking them all until
            // the socket happens to close.
            None => match &msg {
                KamajiToYubaba::Error { code, message, .. } => {
                    warn!(?code, %message, "kamaji error with no request_id; failing all waiters");
                    shared.fail_all(*code, message);
                }
                other => debug!(?other, "kamaji push frame; no consumer"),
            },
        }
    }
    shared.shutdown();
}

/// Owns the write half. Frames are written here rather than in the caller's
/// future so a cancelled caller can never truncate one mid-frame.
async fn writer_loop(
    mut wr: OwnedWriteHalf,
    mut outbound: mpsc::UnboundedReceiver<Vec<u8>>,
    shared: Arc<Shared>,
) {
    while let Some(bytes) = outbound.recv().await {
        if let Err(e) = wr.write_all(&bytes).await {
            debug!(error = %e, "kamaji writer loop ended");
            break;
        }
    }
    shared.shutdown();
}

async fn write_frame(wr: &mut OwnedWriteHalf, msg: &YubabaToKamaji) -> Result<(), ClientError> {
    let bytes = encode_frame(msg)?;
    wr.write_all(&bytes).await?;
    Ok(())
}

/// Read exactly one `KamajiToYubaba` frame, refilling `buf` as needed.
///
/// Drains any leftover bytes from the previous read first — if a prior call
/// pulled two frames in one syscall, the second is already buffered.
async fn read_frame(
    rd: &mut OwnedReadHalf,
    buf: &mut Vec<u8>,
) -> Result<KamajiToYubaba, ClientError> {
    let mut tmp = [0u8; 4096];
    loop {
        match decode_frame::<KamajiToYubaba>(buf) {
            Ok((msg, consumed)) => {
                buf.drain(..consumed);
                return Ok(msg);
            }
            Err(CodecError::Truncated { .. }) => {
                let n = rd.read(&mut tmp).await?;
                if n == 0 {
                    return Err(ClientError::PeerClosed);
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => return Err(ClientError::Codec(e)),
        }
    }
}

// ── Kamaji trait impl ──────────────────────────────────────────────────────
//
// Bridges the `Kamaji` trait (W199 caller contract) to the sibling-shape
// postcard-over-UDS wire protocol. Methods with no proto equivalent (stream_logs,
// restart_workload, health) return explicit "not yet in sibling proto" errors
// rather than panicking so callers can handle them gracefully.
//
// See W199 §The move: callers hold `Arc<dyn Kamaji>` regardless of shape;
// the inlined impl dispatches in-process while this impl speaks the wire.

use async_trait::async_trait;
use kamaji_proto::WorkloadState as ProtoWorkloadState;

fn proto_state_to_status(s: ProtoWorkloadState) -> crate::WorkloadStatus {
    match s {
        ProtoWorkloadState::Pending | ProtoWorkloadState::Starting => {
            crate::WorkloadStatus::Pending
        }
        ProtoWorkloadState::Running => crate::WorkloadStatus::Running,
        ProtoWorkloadState::Draining => crate::WorkloadStatus::Stopping,
        ProtoWorkloadState::Exited => crate::WorkloadStatus::Stopped,
        ProtoWorkloadState::Failed => crate::WorkloadStatus::Failed {
            reason: "workload exited with failure".into(),
        },
        // `#[non_exhaustive]` — map unknown future variants to Failed so
        // callers never silently treat an unknown state as healthy.
        _ => crate::WorkloadStatus::Failed {
            reason: "unknown proto WorkloadState variant".into(),
        },
    }
}

/// Runtime [`MeshAssignment`](crate::MeshAssignment) → its wire mirror
/// (R599-F12).
///
/// The [`crate::MeshAssignment::inlined`] sentinel — no WireGuard, loopback-ish
/// IP — is *not* a mesh placement, and sending it would tell kamaji to bind an
/// address that means "there is no mesh here". Callers therefore pass `None` in
/// that case; see [`KamajiClient::deploy_envelope`].
pub(crate) fn mesh_to_proto(mesh: &crate::MeshAssignment) -> kamaji_proto::MeshAssignment {
    kamaji_proto::MeshAssignment {
        mesh_ip: mesh.mesh_ip,
        wg_private_key: mesh.wg_private_key.clone(),
        wg_listen_port: mesh.wg_listen_port,
        peers: mesh
            .peers
            .iter()
            .map(|p| kamaji_proto::WireguardPeer {
                public_key: p.public_key.clone(),
                endpoint: p.endpoint,
                allowed_ips: p.allowed_ips.clone(),
            })
            .collect(),
        netns_name: mesh.netns_name.clone(),
    }
}

/// Whether a runtime assignment is a real mesh placement worth putting on the
/// wire, or the [`inlined`](crate::MeshAssignment::inlined) "there is no mesh
/// here" sentinel — which the wire spells `None`.
///
/// The sentinel is identified the same way [`crate::MeshAssignment::inlined`]
/// constructs it: no WireGuard *and* a loopback address. A real single-node
/// deployment that genuinely assigns 127.0.0.1 to a workload gets the same
/// answer it always did (bind loopback), so collapsing the two costs nothing.
fn wire_mesh(mesh: &crate::MeshAssignment) -> Option<&crate::MeshAssignment> {
    if !mesh.has_wireguard() && mesh.mesh_ip.is_loopback() {
        None
    } else {
        Some(mesh)
    }
}

fn entry_to_workload_state(entry: WorkloadEntry) -> crate::WorkloadState {
    crate::WorkloadState {
        ident: crate::MeshIdent(entry.id.0.clone()),
        container_id: entry.id.0,
        status: proto_state_to_status(entry.state),
        mesh_ip: None,
    }
}

#[async_trait]
impl crate::Kamaji for KamajiClient {
    fn backend(&self) -> crate::Backend {
        // The proto handshake doesn't carry backend type today; default to
        // Native. A future protocol-version extension can surface this.
        crate::Backend::Native
    }

    /// Deploy a workload. Wraps `spec` in a `Workload::Container` envelope
    /// and sends `YubabaToKamaji::Deploy`. Returns a [`DeployResult`]
    /// with `mesh_ip` taken from `mesh` and `task_pid = 0` (the pid arrives
    /// later via the `WorkloadStarted` push message, not yet plumbed).
    ///
    /// R599-F12: `mesh` now reaches the daemon instead of being dropped here.
    /// A [`MeshAssignment::inlined`](crate::MeshAssignment::inlined) sentinel
    /// still doesn't — it means "this deployment has no mesh plane", which the
    /// wire spells `None`, not "bind 127.0.0.1 on purpose".
    async fn deploy_workload(
        &self,
        spec: &workload_spec::WorkloadSpec,
        mesh: &crate::MeshAssignment,
    ) -> anyhow::Result<crate::DeployResult> {
        let id = WorkloadId::new(&spec.name);
        let workload_envelope = workload_spec::Workload::container(spec.clone());
        self.deploy_envelope(&id, &workload_envelope, wire_mesh(mesh))
            .await
            .map_err(|e| anyhow::anyhow!("kamaji deploy_workload: {e}"))?;
        Ok(crate::DeployResult {
            container_id: id.0,
            mesh_ip: mesh.mesh_ip,
            task_pid: 0,
        })
    }

    async fn list_workloads(&self) -> anyhow::Result<Vec<crate::WorkloadState>> {
        let entries = self
            .list()
            .await
            .map_err(|e| anyhow::anyhow!("kamaji list_workloads: {e}"))?;
        Ok(entries.into_iter().map(entry_to_workload_state).collect())
    }

    async fn get_workload(
        &self,
        ident: &crate::MeshIdent,
    ) -> anyhow::Result<Option<crate::WorkloadState>> {
        let all = self.list_workloads().await?;
        Ok(all.into_iter().find(|s| s.ident == *ident))
    }

    async fn stream_logs(
        &self,
        _ident: &crate::MeshIdent,
        _opts: crate::LogOpts,
    ) -> anyhow::Result<crate::LogStream> {
        Err(anyhow::anyhow!(
            "stream_logs not yet in the sibling-Kamaji wire protocol"
        ))
    }

    async fn restart_workload(&self, ident: &crate::MeshIdent) -> anyhow::Result<()> {
        // No dedicated Restart message in the current proto — issue Stop and
        // let the supervisor's RestartPolicy handle re-launch. Not equivalent
        // to a true restart (the supervisor must have a non-Never policy), but
        // it is the closest available action.
        let id = WorkloadId::new(&ident.0);
        self.stop(&id)
            .await
            .map_err(|e| anyhow::anyhow!("kamaji restart_workload (via stop): {e}"))
    }

    /// Sibling graceful upgrade (R600-F9). Sends the dedicated
    /// `YubabaToKamaji::GracefulUpgrade` wire message so the daemon runs its
    /// **zero-downtime** custody reload: kamaji holds the passway listen socket
    /// and swaps the process onto the re-rendered cert without closing the
    /// listener. The daemon falls back to a connection-dropping redeploy for a
    /// non-passway workload or when custody isn't held, so this call always
    /// yields a functional reload. The `id` matches [`deploy_workload`]'s
    /// (`spec.name`) so it targets the same container.
    async fn graceful_upgrade_workload(
        &self,
        spec: &workload_spec::WorkloadSpec,
        mesh: &crate::MeshAssignment,
    ) -> anyhow::Result<crate::DeployResult> {
        let id = WorkloadId::new(&spec.name);
        let workload_envelope = workload_spec::Workload::container(spec.clone());
        let request_id = self.next_request_id();
        let reply = self
            .request(
                YubabaToKamaji::GracefulUpgrade {
                    request_id,
                    id: id.clone(),
                    spec: workload_envelope,
                },
                request_id,
            )
            .await
            .map_err(|e| anyhow::anyhow!("kamaji graceful_upgrade_workload: {e}"))?;
        match reply {
            KamajiToYubaba::Ack {
                kind: kamaji_proto::AckKind::GracefulUpgrade,
                ..
            } => {
                Ok(crate::DeployResult {
                    container_id: id.0,
                    mesh_ip: mesh.mesh_ip,
                    task_pid: 0,
                })
            }
            other => Err(anyhow::anyhow!(
                "kamaji graceful_upgrade_workload: unexpected reply {other:?}"
            )),
        }
    }

    async fn teardown_workload(&self, ident: &crate::MeshIdent) -> anyhow::Result<()> {
        let id = WorkloadId::new(&ident.0);
        self.stop(&id)
            .await
            .map_err(|e| anyhow::anyhow!("kamaji teardown_workload: {e}"))
    }

    async fn health(&self) -> anyhow::Result<crate::RuntimeHealth> {
        // No health-check message in the current proto. Report "ok" using the
        // presence of the established connection as the liveness signal.
        Ok(crate::RuntimeHealth {
            ok: true,
            version: Some(self.info().kamaji_version.clone()),
            detail: None,
        })
    }
}

/// Connect with a bounded timeout so a missing/broken socket doesn't stall
/// `yah-yubaba serve` startup forever. Returns a recognisable error so the
/// CLI can decide whether to fail-hard or fall back to the legacy runtime.
pub async fn connect_with_timeout(
    socket: impl Into<PathBuf>,
    timeout: Duration,
) -> Result<KamajiClient> {
    let socket = socket.into();
    let result = tokio::time::timeout(timeout, KamajiClient::connect(socket.clone()))
        .await
        .map_err(|_| {
            anyhow!(
                "timed out after {:?} connecting to kamaji at {}",
                timeout,
                socket.display()
            )
        })?;
    result.with_context(|| format!("connecting to kamaji at {}", socket.display()))
}

/// How often [`KamajiSibling`]'s watchdog polls [`KamajiClient::is_dead`]
/// between reconnect attempts.
const RECONNECT_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// First reconnect retry delay after a failed dial; doubles on each further
/// failure up to [`RECONNECT_MAX_BACKOFF`]. Same shape as
/// [`crate::native::ALWAYS_RESTART_DELAY`]'s "don't hot-loop a down peer"
/// concern, just with backoff since a socket that's down for a `cargo
/// build` deploy can stay down for tens of seconds.
const RECONNECT_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// A [`KamajiClient`] handle that transparently reconnects after the sibling
/// process restarts.
///
/// A bare `KamajiClient` is a one-shot connection (see the module docs'
/// "demux actor" rationale for why it can't just retry a write in place):
/// once Kamaji's process exits — e.g. `systemctl restart kamaji` for a
/// binary swap — every call on the old client fails forever with
/// [`ClientError::PeerClosed`], and nothing except restarting the *caller*
/// re-dials. Observed live 2026-08-13: a kamaji binary swap left yubaba
/// answering every workload call with PeerClosed until yubaba itself was
/// restarted.
///
/// `KamajiSibling` owns a background watchdog that polls
/// [`KamajiClient::is_dead`], clears the published handle to `None` the
/// moment it trips (so callers see "kamaji unavailable" rather than a
/// client that can only ever error), and redials with backoff until it
/// reconnects. Every [`KamajiSibling::current`] caller and every
/// [`KamajiSibling::subscribe`] watcher observes the swap without doing
/// any reconnect bookkeeping itself.
#[derive(Clone)]
pub struct KamajiSibling {
    socket: Arc<Path>,
    rx: tokio::sync::watch::Receiver<Option<Arc<KamajiClient>>>,
}

impl KamajiSibling {
    /// Wrap an already-connected `client` and start the reconnect watchdog.
    /// `socket` is redialled on every reconnect; `connect_timeout` bounds
    /// each individual dial attempt (mirrors [`connect_with_timeout`]).
    pub fn new(client: KamajiClient, socket: impl Into<PathBuf>, connect_timeout: Duration) -> Self {
        let socket: Arc<Path> = socket.into().into();
        let (tx, rx) = tokio::sync::watch::channel(Some(Arc::new(client)));
        tokio::spawn(reconnect_watchdog(tx, socket.to_path_buf(), connect_timeout));
        Self { socket, rx }
    }

    /// The current client, or `None` while a reconnect is in flight.
    pub fn current(&self) -> Option<Arc<KamajiClient>> {
        self.rx.borrow().clone()
    }

    /// The socket path this sibling dials and redials — stable across
    /// reconnects, unlike [`Self::current`].
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// A receiver that wakes on every reconnect (never on the initial
    /// connect, since that value is already the receiver's seed). Callers
    /// that want to reconcile state once Kamaji comes back — e.g. re-check
    /// which workloads it lost — `.changed().await` this in a loop.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Option<Arc<KamajiClient>>> {
        self.rx.clone()
    }
}

/// Background task backing [`KamajiSibling`]. Exits once every handle
/// (the original plus every `subscribe()` clone) is dropped, per
/// `watch::Sender::is_closed`.
async fn reconnect_watchdog(
    tx: tokio::sync::watch::Sender<Option<Arc<KamajiClient>>>,
    socket: PathBuf,
    connect_timeout: Duration,
) {
    loop {
        // Poll until the published client dies (or was already cleared by a
        // prior failed reconnect attempt).
        loop {
            if tx.is_closed() {
                return;
            }
            let dead = tx.borrow().as_ref().is_none_or(|c| c.is_dead());
            if dead {
                break;
            }
            tokio::time::sleep(RECONNECT_POLL_INTERVAL).await;
        }
        if tx.is_closed() {
            return;
        }
        // Clear immediately: a caller mid-reconnect should see "no kamaji"
        // (and fall back / wait) rather than a handle that will only ever
        // answer PeerClosed.
        if tx.send(None).is_err() {
            return;
        }
        warn!(socket = %socket.display(), "kamaji sibling connection lost; reconnecting");

        let mut backoff = RECONNECT_INITIAL_BACKOFF;
        loop {
            match connect_with_timeout(socket.clone(), connect_timeout).await {
                Ok(client) => {
                    info!(
                        socket = %socket.display(),
                        kamaji_version = %client.info().kamaji_version,
                        "kamaji sibling reconnected"
                    );
                    if tx.send(Some(Arc::new(client))).is_err() {
                        return;
                    }
                    break;
                }
                Err(e) => {
                    if tx.is_closed() {
                        return;
                    }
                    debug!(
                        socket = %socket.display(),
                        error = %e,
                        next_attempt_in = ?backoff,
                        "kamaji reconnect attempt failed"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(RECONNECT_MAX_BACKOFF);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamaji_proto::{AckKind, WorkloadState};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// Server side of one test connection. Lets a test drive the wire
    /// explicitly — how many requests it reads before replying, in what order
    /// it replies, and what it interleaves between replies.
    struct ServerConn {
        stream: tokio::net::UnixStream,
        buf: Vec<u8>,
    }

    impl ServerConn {
        /// Next request from the client. Panics on EOF — a test that expects
        /// the client to go away should simply stop calling this.
        async fn recv(&mut self) -> YubabaToKamaji {
            let mut tmpbuf = [0u8; 4096];
            loop {
                match decode_frame::<YubabaToKamaji>(&self.buf) {
                    Ok((m, n)) => {
                        self.buf.drain(..n);
                        return m;
                    }
                    Err(CodecError::Truncated { .. }) => {
                        let n = self.stream.read(&mut tmpbuf).await.unwrap();
                        assert!(n > 0, "client closed the connection");
                        self.buf.extend_from_slice(&tmpbuf[..n]);
                    }
                    Err(e) => panic!("decode req: {e}"),
                }
            }
        }

        async fn send(&mut self, msg: &KamajiToYubaba) {
            let bytes = encode_frame(msg).unwrap();
            self.stream.write_all(&bytes).await.unwrap();
        }
    }

    /// Spin up an in-process "kamaji" on a tempdir socket, complete the
    /// handshake, then hand the connection to `drive`.
    async fn scripted_server<F, Fut>(drive: F) -> (tempfile::TempDir, PathBuf)
    where
        F: FnOnce(ServerConn) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("kamaji.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = ServerConn {
                stream,
                buf: Vec::with_capacity(4096),
            };
            assert!(matches!(conn.recv().await, YubabaToKamaji::Hello { .. }));
            conn.send(&KamajiToYubaba::Welcome {
                version: ProtocolVersion::CURRENT,
                kamaji_version: "test-0.0.1".into(),
            })
            .await;
            drive(conn).await;
        });
        (tmp, sock)
    }

    /// Spin up a one-shot in-process "kamaji" on a tempdir socket that
    /// answers the first incoming request with the closure's reply.
    async fn one_shot_server(
        expect_after_hello: impl FnOnce(YubabaToKamaji) -> KamajiToYubaba + Send + 'static,
    ) -> (tempfile::TempDir, PathBuf) {
        scripted_server(|mut conn| async move {
            let req = conn.recv().await;
            let reply = expect_after_hello(req);
            conn.send(&reply).await;
        })
        .await
    }

    /// The id a request went out with, so a scripted server can echo it back.
    fn request_id_of(req: &YubabaToKamaji) -> RequestId {
        match req {
            YubabaToKamaji::List { request_id }
            | YubabaToKamaji::Deploy { request_id, .. }
            | YubabaToKamaji::Stop { request_id, .. }
            | YubabaToKamaji::Drain { request_id, .. }
            | YubabaToKamaji::Probe { request_id, .. } => *request_id,
            other => panic!("no request_id on {other:?}"),
        }
    }

    fn entry(name: &str) -> WorkloadEntry {
        WorkloadEntry {
            mesh_ident: None,
            id: WorkloadId::new(name),
            state: WorkloadState::Running,
            pid: Some(1),
        }
    }

    #[tokio::test]
    async fn connect_handshakes_and_captures_info() {
        let (_tmp, sock) = one_shot_server(|_req| KamajiToYubaba::WorkloadList {
            request_id: RequestId(1),
            entries: vec![],
        })
        .await;
        let client = KamajiClient::connect(sock).await.expect("connect");
        assert_eq!(client.info().kamaji_version, "test-0.0.1");
        let entries = client.list().await.expect("list");
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn list_returns_workload_entries() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                YubabaToKamaji::List { request_id } => request_id,
                other => panic!("expected List, got {other:?}"),
            };
            KamajiToYubaba::WorkloadList {
                request_id: rid,
                entries: vec![WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("foo"),
                    state: WorkloadState::Running,
                    pid: Some(42),
                }],
            }
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        let entries = client.list().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, WorkloadId::new("foo"));
        assert_eq!(entries[0].state, WorkloadState::Running);
        assert_eq!(entries[0].pid, Some(42));
    }

    #[tokio::test]
    async fn stop_handles_ack() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                YubabaToKamaji::Stop { request_id, .. } => request_id,
                other => panic!("expected Stop, got {other:?}"),
            };
            KamajiToYubaba::Ack {
                request_id: rid,
                kind: AckKind::Stop,
            }
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        client.stop(&WorkloadId::new("foo")).await.expect("stop");
    }

    #[tokio::test]
    async fn drain_surfaces_ack_payload() {
        let (_tmp, sock) = one_shot_server(|req| {
            let (rid, id) = match req {
                YubabaToKamaji::Drain {
                    request_id,
                    id,
                    budget,
                } => {
                    assert_eq!(budget.flush_ms, 100);
                    assert_eq!(budget.checkpoint_ms, 200);
                    (request_id, id)
                }
                other => panic!("expected Drain, got {other:?}"),
            };
            KamajiToYubaba::DrainAck {
                request_id: rid,
                id,
                accepted: true,
                reason: Some("flushed in 50ms".into()),
            }
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        let (accepted, reason) = client
            .drain(
                &WorkloadId::new("foo"),
                DrainBudget {
                    flush_ms: 100,
                    checkpoint_ms: 200,
                },
            )
            .await
            .unwrap();
        assert!(accepted);
        assert_eq!(reason.as_deref(), Some("flushed in 50ms"));
    }

    #[tokio::test]
    async fn remote_error_is_surfaced_as_client_remote() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                YubabaToKamaji::Stop { request_id, .. } => request_id,
                other => panic!("expected Stop, got {other:?}"),
            };
            KamajiToYubaba::Error {
                request_id: Some(rid),
                code: ErrorCode::UnknownWorkload,
                message: "no such id".into(),
            }
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        let err = client.stop(&WorkloadId::new("foo")).await.unwrap_err();
        match err {
            ClientError::Remote { code, message } => {
                assert_eq!(code, ErrorCode::UnknownWorkload);
                assert_eq!(message, "no such id");
            }
            other => panic!("expected Remote, got {other:?}"),
        }
    }

    /// R746-B11 regression. `DeployStatusResult` was missing from the client's
    /// correlation table, so this reply was routed as a spontaneous push and
    /// dropped — the caller parked on its oneshot until the socket closed.
    /// The bug was invisible for the unknown-id case (that answers with
    /// `Error`, which *was* correlated), which is why the live symptom was a
    /// route that 404s instantly for a workload with no deploy record and
    /// hangs forever for the one workload that has one.
    ///
    /// The `timeout` is the assertion: without it a regression hangs the test
    /// binary instead of failing it.
    #[tokio::test]
    async fn deploy_status_result_is_routed_back_to_its_caller() {
        let (_tmp, sock) = one_shot_server(|req| {
            let (rid, id) = match req {
                YubabaToKamaji::DeployStatus { request_id, id } => (request_id, id),
                other => panic!("expected DeployStatus, got {other:?}"),
            };
            KamajiToYubaba::DeployStatusResult {
                request_id: rid,
                id,
                state: WorkloadState::Failed,
                detail: Some("materialize failed".into()),
            }
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        let (state, detail) = tokio::time::timeout(
            Duration::from_secs(5),
            client.deploy_status(&WorkloadId::new("yah-marketing")),
        )
        .await
        .expect("deploy_status must answer, not park on a dropped reply")
        .expect("deploy_status");
        assert_eq!(state, WorkloadState::Failed);
        assert_eq!(detail.as_deref(), Some("materialize failed"));
    }

    /// The other half of the same route: an id kamaji never admitted comes
    /// back as `UnknownWorkload`, which a polling caller must treat as
    /// terminal. This arm always worked; it is pinned so a future change to
    /// the correlation table can't fix one arm by breaking the other.
    #[tokio::test]
    async fn deploy_status_for_an_unadmitted_id_is_a_remote_unknown_workload() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                YubabaToKamaji::DeployStatus { request_id, .. } => request_id,
                other => panic!("expected DeployStatus, got {other:?}"),
            };
            KamajiToYubaba::Error {
                request_id: Some(rid),
                code: ErrorCode::UnknownWorkload,
                message: "no deploy on record".into(),
            }
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            client.deploy_status(&WorkloadId::new("nope")),
        )
        .await
        .expect("deploy_status must answer")
        .unwrap_err();
        assert!(
            matches!(
                err,
                ClientError::Remote {
                    code: ErrorCode::UnknownWorkload,
                    ..
                }
            ),
            "expected Remote/UnknownWorkload, got {err:?}"
        );
    }

    #[tokio::test]
    async fn connect_with_timeout_fails_on_missing_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("does-not-exist.sock");
        let err = connect_with_timeout(sock, Duration::from_millis(250))
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("connecting to kamaji"),
            "error should mention the socket path: {msg}"
        );
    }

    // ── KamajiSibling reconnect watchdog ────────────────────────────────────

    /// The regression this wrapper exists for, live 2026-08-13: a bare
    /// `KamajiClient` never recovers from its peer restarting — every call
    /// answers `PeerClosed` forever. Accepts two connections in sequence on
    /// the same socket path (simulating `systemctl restart kamaji` between
    /// them) and asserts `KamajiSibling::current()` lands on the second
    /// generation without the caller doing anything.
    #[tokio::test]
    async fn kamaji_sibling_reconnects_after_the_peer_restarts() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("kamaji.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        tokio::spawn(async move {
            // Generation 1: handshake, then hang up immediately.
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = ServerConn {
                stream,
                buf: Vec::with_capacity(4096),
            };
            assert!(matches!(conn.recv().await, YubabaToKamaji::Hello { .. }));
            conn.send(&KamajiToYubaba::Welcome {
                version: ProtocolVersion::CURRENT,
                kamaji_version: "gen-1".into(),
            })
            .await;
            drop(conn);

            // Generation 2: handshake and stay up for the rest of the test.
            let (stream, _) = listener.accept().await.unwrap();
            let mut conn = ServerConn {
                stream,
                buf: Vec::with_capacity(4096),
            };
            assert!(matches!(conn.recv().await, YubabaToKamaji::Hello { .. }));
            conn.send(&KamajiToYubaba::Welcome {
                version: ProtocolVersion::CURRENT,
                kamaji_version: "gen-2".into(),
            })
            .await;
            std::future::pending::<()>().await;
        });

        let first = KamajiClient::connect(&sock).await.unwrap();
        assert_eq!(first.info().kamaji_version, "gen-1");

        let sibling = KamajiSibling::new(first, sock.clone(), Duration::from_secs(2));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(c) = sibling.current() {
                if c.info().kamaji_version == "gen-2" {
                    break;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "KamajiSibling never reconnected to the second generation"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    // ── Cancel-safety and demux ────────────────────────────────────────────

    /// The regression this client's demux exists for. A caller that gives up
    /// mid-request — an axum handler dropped because its HTTP client timed out
    /// — used to consume a request id while its reply stayed queued on the
    /// socket, handing it to the *next* caller and leaving the connection
    /// permanently off-by-one (`expected 89, got 88`) until yubaba restarted.
    #[tokio::test]
    async fn a_cancelled_request_does_not_desync_the_next_one() {
        let (_tmp, sock) = scripted_server(|mut conn| async move {
            // Stall the first reply past the caller's patience, then answer
            // both in receipt order, exactly as kamaji does.
            let first = request_id_of(&conn.recv().await);
            tokio::time::sleep(Duration::from_millis(150)).await;
            conn.send(&KamajiToYubaba::WorkloadList {
                request_id: first,
                entries: vec![entry("abandoned-first-reply")],
            })
            .await;

            let second = request_id_of(&conn.recv().await);
            conn.send(&KamajiToYubaba::WorkloadList {
                request_id: second,
                entries: vec![entry("correct-second-reply")],
            })
            .await;
        })
        .await;

        let client = KamajiClient::connect(sock).await.unwrap();

        let abandoned = tokio::time::timeout(Duration::from_millis(20), client.list()).await;
        assert!(abandoned.is_err(), "first call should have timed out");

        let entries = client.list().await.expect("second list after a cancelled one");
        assert_eq!(
            entries[0].id,
            WorkloadId::new("correct-second-reply"),
            "the second caller was handed the abandoned reply — the connection desynced"
        );
    }

    /// Replies are routed by `RequestId`, so kamaji answering out of order (or
    /// a future kamaji answering concurrently) reaches the right caller.
    #[tokio::test]
    async fn concurrent_requests_are_demuxed_by_request_id() {
        let (_tmp, sock) = scripted_server(|mut conn| async move {
            let first = request_id_of(&conn.recv().await);
            let second = request_id_of(&conn.recv().await);
            // Answer the second request first.
            conn.send(&KamajiToYubaba::Ack {
                request_id: second,
                kind: AckKind::Stop,
            })
            .await;
            conn.send(&KamajiToYubaba::WorkloadList {
                request_id: first,
                entries: vec![entry("for-the-list-caller")],
            })
            .await;
        })
        .await;

        let client = KamajiClient::connect(sock).await.unwrap();
        let stop_id = WorkloadId::new("foo");
        let (list, stop) = tokio::join!(client.list(), client.stop(&stop_id));
        assert_eq!(list.unwrap()[0].id, WorkloadId::new("for-the-list-caller"));
        stop.expect("stop should get its own ack");
    }

    /// Pushed lifecycle events carry no `RequestId` at all. Positional
    /// correlation would hand the first one kamaji ever sends to whichever
    /// caller happened to be waiting.
    #[tokio::test]
    async fn a_pushed_lifecycle_event_is_not_delivered_as_a_reply() {
        let (_tmp, sock) = scripted_server(|mut conn| async move {
            let rid = request_id_of(&conn.recv().await);
            conn.send(&KamajiToYubaba::WorkloadStarted {
                id: WorkloadId::new("some-other-workload"),
                pid: 7,
            })
            .await;
            conn.send(&KamajiToYubaba::WorkloadList {
                request_id: rid,
                entries: vec![entry("the-actual-reply")],
            })
            .await;
        })
        .await;

        let client = KamajiClient::connect(sock).await.unwrap();
        let entries = client.list().await.expect("push must not be read as the reply");
        assert_eq!(entries[0].id, WorkloadId::new("the-actual-reply"));
    }

    /// Kamaji answers an unhandled message kind with `Error { request_id:
    /// None }` and keeps the connection open — the shape a newer yubaba hits
    /// against an older kamaji. Uncorrelatable, so every waiter gets it rather
    /// than parking until the socket happens to close.
    #[tokio::test]
    async fn an_uncorrelated_error_fails_the_waiter_instead_of_hanging_it() {
        let (_tmp, sock) = scripted_server(|mut conn| async move {
            let _ = conn.recv().await;
            conn.send(&KamajiToYubaba::Error {
                request_id: None,
                code: ErrorCode::Internal,
                message: "unhandled message kind".into(),
            })
            .await;
            // Hold the connection open, so this proves the fail-all path and
            // not the connection-died path.
            std::future::pending::<()>().await;
        })
        .await;

        let client = KamajiClient::connect(sock).await.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(2), client.list())
            .await
            .expect("caller must not park forever")
            .unwrap_err();
        match err {
            ClientError::Remote { code, message } => {
                assert_eq!(code, ErrorCode::Internal);
                assert_eq!(message, "unhandled message kind");
            }
            other => panic!("expected Remote, got {other:?}"),
        }
    }

    /// A connection that dies mid-request wakes everyone parked on it, and
    /// subsequent calls fail fast rather than queueing onto a dead socket.
    #[tokio::test]
    async fn a_dead_connection_wakes_parked_callers_and_fails_later_ones() {
        let (_tmp, sock) = scripted_server(|mut conn| async move {
            let _ = conn.recv().await;
            drop(conn);
        })
        .await;

        let client = KamajiClient::connect(sock).await.unwrap();
        let err = tokio::time::timeout(Duration::from_secs(2), client.list())
            .await
            .expect("caller must not park forever")
            .unwrap_err();
        assert!(matches!(err, ClientError::PeerClosed), "got {err:?}");

        let err = tokio::time::timeout(Duration::from_secs(2), client.list())
            .await
            .expect("a request onto a dead connection must fail fast")
            .unwrap_err();
        assert!(matches!(err, ClientError::PeerClosed), "got {err:?}");
    }

    // ── Kamaji trait impl tests ────────────────────────────────────────────

    use crate::Kamaji as ConstableTrait;

    #[tokio::test]
    async fn constable_backend_returns_native() {
        // backend() is always Native (proto doesn't carry this info yet).
        let (_tmp, sock) = one_shot_server(|_| KamajiToYubaba::WorkloadList {
            request_id: RequestId(1),
            entries: vec![],
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        assert_eq!(client.backend(), crate::Backend::Native);
    }

    #[tokio::test]
    async fn constable_list_workloads_maps_proto_entries() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                YubabaToKamaji::List { request_id } => request_id,
                other => panic!("expected List, got {other:?}"),
            };
            KamajiToYubaba::WorkloadList {
                request_id: rid,
                entries: vec![
                    WorkloadEntry {
                        mesh_ident: None,
                        id: WorkloadId::new("svc-a"),
                        state: WorkloadState::Running,
                        pid: Some(1000),
                    },
                    WorkloadEntry {
                        mesh_ident: None,
                        id: WorkloadId::new("svc-b"),
                        state: WorkloadState::Exited,
                        pid: None,
                    },
                ],
            }
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        let states = client.list_workloads().await.unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].ident, crate::MeshIdent("svc-a".into()));
        assert!(matches!(states[0].status, crate::WorkloadStatus::Running));
        assert_eq!(states[1].ident, crate::MeshIdent("svc-b".into()));
        assert!(matches!(states[1].status, crate::WorkloadStatus::Stopped));
    }

    #[tokio::test]
    async fn constable_get_workload_finds_by_ident() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                YubabaToKamaji::List { request_id } => request_id,
                other => panic!("expected List, got {other:?}"),
            };
            KamajiToYubaba::WorkloadList {
                request_id: rid,
                entries: vec![WorkloadEntry {
                    mesh_ident: None,
                    id: WorkloadId::new("target"),
                    state: WorkloadState::Running,
                    pid: Some(42),
                }],
            }
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        let state = client
            .get_workload(&crate::MeshIdent("target".into()))
            .await
            .unwrap();
        assert!(state.is_some());
        assert_eq!(state.unwrap().ident, crate::MeshIdent("target".into()));
    }

    #[tokio::test]
    async fn constable_get_workload_returns_none_for_unknown_ident() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                YubabaToKamaji::List { request_id } => request_id,
                other => panic!("expected List, got {other:?}"),
            };
            KamajiToYubaba::WorkloadList {
                request_id: rid,
                entries: vec![],
            }
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        let state = client
            .get_workload(&crate::MeshIdent("nobody".into()))
            .await
            .unwrap();
        assert!(state.is_none());
    }

    #[tokio::test]
    async fn constable_teardown_workload_sends_stop() {
        let (_tmp, sock) = one_shot_server(|req| {
            let rid = match req {
                YubabaToKamaji::Stop { request_id, id } => {
                    assert_eq!(id, WorkloadId::new("svc-to-stop"));
                    request_id
                }
                other => panic!("expected Stop, got {other:?}"),
            };
            KamajiToYubaba::Ack {
                request_id: rid,
                kind: AckKind::Stop,
            }
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        client
            .teardown_workload(&crate::MeshIdent("svc-to-stop".into()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn constable_health_returns_ok_with_kamaji_version() {
        let (_tmp, sock) = one_shot_server(|_| KamajiToYubaba::WorkloadList {
            request_id: RequestId(1),
            entries: vec![],
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        let health = client.health().await.unwrap();
        assert!(health.ok);
        assert_eq!(health.version.as_deref(), Some("test-0.0.1"));
    }

    #[tokio::test]
    async fn constable_stream_logs_returns_not_supported_err() {
        let (_tmp, sock) = one_shot_server(|_| KamajiToYubaba::WorkloadList {
            request_id: RequestId(1),
            entries: vec![],
        })
        .await;
        let client = KamajiClient::connect(sock).await.unwrap();
        let result = client
            .stream_logs(&crate::MeshIdent("any".into()), crate::LogOpts::default())
            .await;
        // LogStream doesn't impl Debug, so match manually.
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected stream_logs to return Err"),
        };
        assert!(err.to_string().contains("not yet in the sibling"));
    }
}

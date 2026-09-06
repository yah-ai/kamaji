//! End-to-end proof of the on-demand JIT lifecycle (R599-F6, W272 §3): **kamaji
//! holds the listen socket, forks the serve runtime on the first connection,
//! reaps it after an idle TTL, and re-forks on the next connection — dropping
//! zero connections across the reap boundary.**
//!
//! kamaji ([`JitRuntime`]) binds+holds a TCP listener and arms a readable-watch
//! WITHOUT accepting. A first connection triggers a fork of a "serve" child that
//! adopts kamaji's fd via the systemd `LISTEN_FDS` socket-activation convention
//! and writes a marker byte per connection; it self-reaps after an idle TTL. The
//! invariants asserted:
//!
//! - **zero-resident when idle** — no child before the first connection, and the
//!   child is gone again after `idle_ttl`;
//! - **lazy fork** — the first connection spawns the serve child, which serves;
//! - **socket outlives the process** — a `connect()` issued while the workload is
//!   idle (no resident process) still succeeds and is served by a freshly forked
//!   child (re-fork), because the kamaji-held socket never closed;
//! - **zero dropped connections** — every `connect()` throughout succeeds.
//!
//! This owns its own `main` (`harness = false`) so the same binary can re-exec
//! itself as the serve child. Unix + `native-integration` only.
//!
//! Run: `cargo test -p kamaji --features native-integration --test jit_lazy_fork`

#[cfg(all(unix, feature = "native-integration"))]
fn main() {
    // Re-exec dispatch: a child invoked with JIT_ROLE=child becomes the "serve"
    // runtime that adopts kamaji's fd (LISTEN_FDS) and serves its marker byte.
    if std::env::var("JIT_ROLE").as_deref() == Ok("child") {
        imp::child_main();
        return;
    }
    imp::driver();
    println!("jit_lazy_fork: OK");
}

#[cfg(not(all(unix, feature = "native-integration")))]
fn main() {
    eprintln!("SKIP: jit_lazy_fork runs on unix with --features native-integration");
}

#[cfg(all(unix, feature = "native-integration"))]
mod imp {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::os::fd::FromRawFd;
    use std::time::{Duration, Instant};

    use kamaji::jit::JitRuntime;
    use kamaji::{MeshAssignment, WorkloadStatus};
    use workload_spec::{
        EnvValue, EnvVar, ExposeSpec, ImageRef, MeshExpose, MeshIdent, Millis, NamespaceId,
        ResourceLimits, RestartPolicy, SchemaVersion, StopPolicy, TenantId, TierTag, WorkloadSpec,
    };

    const PORT: &str = "127.0.0.1:39443";
    const IDLE_MS: u64 = 700;

    // ── The serve child (socket-activation stand-in for mesofact-serve) ───────

    /// Adopt the kamaji-held listener from fd 3 (`LISTEN_FDS`), write our marker
    /// byte to each connection, and self-reap after `JIT_IDLE_MS` with no new
    /// connection — the runtime contract kamaji's JIT policy drives.
    pub fn child_main() {
        let marker = std::env::var("JIT_MARKER").unwrap().into_bytes()[0];
        let idle = Duration::from_millis(std::env::var("JIT_IDLE_MS").unwrap().parse().unwrap());

        // Socket activation: fd 3 is kamaji's listening socket. SAFETY: the
        // LISTEN_FDS contract guarantees fd 3 is the passed listener and we are
        // its sole owner in this process.
        assert_eq!(
            std::env::var("LISTEN_FDS").as_deref(),
            Ok("1"),
            "LISTEN_FDS=1 not set"
        );
        let listener = unsafe { std::net::TcpListener::from_raw_fd(3) };
        listener.set_nonblocking(true).unwrap();

        let mut last_activity = Instant::now();
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.write_all(&[marker]);
                    let _ = stream.flush();
                    last_activity = Instant::now();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if last_activity.elapsed() >= idle {
                        // Idle TTL elapsed with zero connections — self-reap.
                        std::process::exit(0);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }

    // ── The driver / kamaji side ──────────────────────────────────────────────

    pub fn driver() {
        // Multi-thread: the driver blocks synchronously on TCP probes while the
        // per-workload supervisor task must keep running (arm → fork → reap) on
        // another worker — a current-thread runtime would starve it.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async { driver_async().await });
    }

    async fn driver_async() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = JitRuntime::new(tmp.path());
        let self_exe = std::env::current_exe().unwrap();

        let spec = jit_spec("jit-site", &self_exe, PORT);
        let ident = spec.expose.mesh.identity.clone();
        let mesh = MeshAssignment::inlined(std::net::Ipv4Addr::LOCALHOST);

        // Deploy: kamaji binds+holds the socket and arms the watch — NO process
        // is forked yet.
        runtime
            .deploy_on_demand(&spec, &mesh, PORT)
            .await
            .expect("on-demand deploy binds the socket");

        // ── Invariant: zero-resident when idle (before any connection). ──
        let st = runtime
            .get_workload(&ident)
            .await
            .expect("workload present");
        assert_eq!(
            st.status,
            WorkloadStatus::Pending,
            "idle workload must be Pending"
        );
        assert!(
            st.container_id.ends_with("-0"),
            "no resident pid when idle, got {}",
            st.container_id
        );

        // ── Lazy fork: the first connection spawns the serve child. ──
        let mut connect_failures = 0u32;
        let served1 = probe_until_served(b'M', Duration::from_secs(5), &mut connect_failures);
        assert!(
            served1,
            "first connection did not fork+serve within timeout"
        );

        // Workload is now Running with a resident pid.
        let running_pid = wait_for_running(&runtime, &ident, Duration::from_secs(3)).await;
        assert!(running_pid > 0, "expected a resident serve pid after fork");

        // ── Idle reap: stop probing; the child self-reaps after IDLE_MS. Back to
        //    zero-resident. ──
        let reaped = wait_for_idle(&runtime, &ident, Duration::from_secs(5)).await;
        assert!(
            reaped,
            "serve child was not reaped after idle_ttl (still resident)"
        );
        // The reaped child's pid must be gone from the OS.
        assert!(
            !pid_alive(running_pid),
            "reaped pid {running_pid} still alive"
        );

        // ── Socket outlives the process + re-fork: a connect issued while idle
        //    (pid 0) still succeeds AND is served by a freshly forked child. ──
        // Prove the TCP-level connect succeeds against the held socket even with
        // no resident process, then that it gets served (re-fork).
        assert!(
            TcpStream::connect(PORT).is_ok(),
            "connect to the held socket failed while workload was idle — socket did not outlive the process"
        );
        let served2 = probe_until_served(b'M', Duration::from_secs(5), &mut connect_failures);
        assert!(served2, "reconnect did not re-fork+serve within timeout");
        let refork_pid = wait_for_running(&runtime, &ident, Duration::from_secs(3)).await;
        assert!(
            refork_pid > 0,
            "expected a resident serve pid after re-fork"
        );
        assert_ne!(refork_pid, running_pid, "re-fork should be a fresh pid");

        // ── Zero dropped connections across the whole exercise. ──
        assert_eq!(
            connect_failures, 0,
            "ZERO-DROP VIOLATED: {connect_failures} connect() failures — the kamaji-held socket must never stop listening"
        );

        // ── Teardown: stop the supervisor + release the socket. ──
        runtime.teardown_workload(&ident).await.expect("teardown");
        assert!(
            !runtime.holds(&ident).await,
            "workload still held after teardown"
        );
        // The re-fork child is either self-reaped or SIGTERM'd by teardown; give
        // the OS a beat, then confirm it is gone.
        let deadline = Instant::now() + Duration::from_secs(3);
        while pid_alive(refork_pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !pid_alive(refork_pid),
            "serve child {refork_pid} survived teardown"
        );
        // Idempotent teardown.
        runtime
            .teardown_workload(&ident)
            .await
            .expect("idempotent teardown");

        eprintln!(
            "jit lifecycle verified: lazy fork → serve → idle reap → re-fork, 0 dropped connections"
        );
    }

    /// Connect and read one marker byte, retrying until `want` is served or the
    /// timeout elapses. Increments `connect_failures` on a failed `connect()`
    /// (the invariant that must never trip). A successful connect that reads no
    /// byte (idle, pre-fork) is NOT a failure — it triggers the fork and we retry.
    fn probe_until_served(want: u8, timeout: Duration, connect_failures: &mut u32) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match TcpStream::connect(PORT) {
                Ok(mut s) => {
                    s.set_read_timeout(Some(Duration::from_millis(400))).ok();
                    let mut buf = [0u8; 1];
                    if let Ok(1) = s.read(&mut buf) {
                        if buf[0] == want {
                            return true;
                        }
                    }
                }
                Err(_) => *connect_failures += 1,
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// Poll until the workload reports `Running` with a non-zero pid; returns the
    /// pid (0 on timeout).
    async fn wait_for_running(rt: &JitRuntime, ident: &MeshIdent, timeout: Duration) -> u32 {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(st) = rt.get_workload(ident).await {
                if st.status == WorkloadStatus::Running {
                    if let Some(pid) = st
                        .container_id
                        .strip_prefix("jit-")
                        .and_then(|p| p.parse::<u32>().ok())
                    {
                        if pid != 0 {
                            return pid;
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        0
    }

    /// Poll until the workload is back to idle (`Pending`, pid 0) — the child
    /// self-reaped. Returns false on timeout.
    async fn wait_for_idle(rt: &JitRuntime, ident: &MeshIdent, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(st) = rt.get_workload(ident).await {
                if st.status == WorkloadStatus::Pending && st.container_id.ends_with("-0") {
                    return true;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    /// `true` if `pid` is a live process (kill(pid, 0) == 0).
    fn pid_alive(pid: u32) -> bool {
        // SAFETY: signal 0 performs error checking without sending a signal.
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }

    /// A minimal native WorkloadSpec whose argv is `[self_exe]` (re-exec'd as the
    /// serve child) and whose env drives the child role + idle TTL. `--idle-ttl`
    /// is expressed via env here (the real serve bin takes a CLI flag).
    fn jit_spec(name: &str, self_exe: &std::path::Path, _listen: &str) -> WorkloadSpec {
        WorkloadSpec {
            schema_version: SchemaVersion::V1,
            name: name.to_string(),
            tenant: TenantId::singleton(),
            namespace: NamespaceId::singleton(),
            image: ImageRef {
                registry: "bundle".to_string(),
                repository: format!("mesofact/{name}"),
                tag: "serve".to_string(),
                digest: workload_spec::testing::test_digest(),
            },
            tier: TierTag("infra".to_string()),
            replicas: 1,
            command: None,
            entrypoint: Some(vec![self_exe.to_string_lossy().into_owned()]),
            workdir: None,
            user: None,
            env: vec![
                EnvVar {
                    name: "JIT_ROLE".to_string(),
                    value: EnvValue::Literal {
                        value: "child".to_string(),
                    },
                },
                EnvVar {
                    name: "JIT_MARKER".to_string(),
                    value: EnvValue::Literal {
                        value: "M".to_string(),
                    },
                },
                EnvVar {
                    name: "JIT_IDLE_MS".to_string(),
                    value: EnvValue::Literal {
                        value: IDLE_MS.to_string(),
                    },
                },
            ],
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
}

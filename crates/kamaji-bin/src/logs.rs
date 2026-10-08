//! Workload output over the UDS: the `Logs` follow stream (R729-F2).
//!
//! W257 "Decision (R729-S1)" is the spec. Kamaji is the one place that knows
//! where each backend puts a workload's output, so it is the one that reads it:
//!
//! - **container** (kamaji-bin's containerd backend) — journald, keyed by
//!   `YAH_WORKLOAD_ID=<kamaji WorkloadId>` ([`crate::journal`]); the cursor is
//!   journald's own `__CURSOR`, resumed with `--after-cursor`.
//! - **native** — `<native-exec-dir>/<mesh ident>/{stdout,stderr}.log`, opened
//!   BY PATH and followed; the cursor is `<stdout offset>:<stderr offset>`.
//!   Deliberately not `NativeRuntime::stream_logs`: that reads an in-memory map
//!   `teardown_workload` empties, and it never follows.
//! - **microVM** — `<microvm state dir>/<mesh ident>/console.log`, same
//!   file-follow, cursor `<offset>`. Everything is stdout (one console).
//!
//! Which of those a request means is decided in exactly one place,
//! [`resolve_source`] — including the key split between a container's
//! DNS-safe id (`forge-<uuid>`) and the mesh ident the files are named by
//! (`forge.<uuid>`).
//!
//! Every cursor means "the position just after this record", so resuming from
//! the last one a reader saw yields neither a duplicate nor a gap.

use std::future::Future;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use kamaji_proto::{encode_frame, KamajiToYubaba, LogRecord, LogStreamTag, RequestId};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

/// How often a quiet source is re-read.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// An empty `LogBatch` after this much silence, so the reader can tell a quiet
/// workload from a dead connection (yubaba's own heartbeat is 15s).
pub const KEEPALIVE: Duration = Duration::from_secs(10);
/// A single line longer than this is cut, so one runaway line cannot exceed
/// the codec's frame cap.
pub const MAX_LINE_BYTES: usize = 64 * 1024;
/// Records are split across frames at about this many bytes of line text.
const MAX_BATCH_BYTES: usize = 1024 * 1024;

/// Where one workload's output lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogSource {
    Journald { workload_id: String },
    Files { stdout: PathBuf, stderr: PathBuf },
    Console { path: PathBuf },
}

/// The single mapping from a `Logs` request to its source.
///
/// `requested` is whatever the caller sent — yubaba passes the mesh ident.
/// `entry` is the live `WorkloadEntry` it matched (on `id` or `mesh_ident`),
/// as `(id, mesh_ident)`. A per-workload file wins when it exists, because a
/// native or microVM workload never reaches journald; the journal is used only
/// for a workload kamaji actually knows, so an unknown ident is `None` (a
/// clean "unknown workload"), never an empty journald query that exits 0.
pub fn resolve_source(
    native_dir: Option<&Path>,
    microvm_dir: Option<&Path>,
    requested: &str,
    entry: Option<(&str, Option<&str>)>,
) -> Option<LogSource> {
    let ident = entry.and_then(|(_, m)| m).unwrap_or(requested);
    if let Some(dir) = native_dir {
        let d = dir.join(ident);
        if d.join("stdout.log").exists() || d.join("stderr.log").exists() {
            return Some(LogSource::Files {
                stdout: d.join("stdout.log"),
                stderr: d.join("stderr.log"),
            });
        }
    }
    if let Some(dir) = microvm_dir {
        let path = dir.join(ident).join("console.log");
        if path.exists() {
            return Some(LogSource::Console { path });
        }
    }
    entry.map(|(id, _)| LogSource::Journald {
        workload_id: id.to_string(),
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn cap_line(mut s: String) -> String {
    if s.len() > MAX_LINE_BYTES {
        let mut cut = MAX_LINE_BYTES;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

/// Lines appended to `path` since `*offset`, each with the offset just past it.
///
/// Only newline-terminated lines are returned, so a half-written line is
/// picked up whole on the next read — unless `flush` (the workload is
/// terminal), when the unterminated tail is returned too. A missing file reads
/// as empty; a file shorter than `*offset` was truncated by a restart and is
/// re-read from 0.
pub async fn read_appended(
    path: &Path,
    offset: &mut u64,
    flush: bool,
) -> Result<Vec<(String, u64)>> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("open {}", path.display())),
    };
    let len = file.metadata().await?.len();
    if len < *offset {
        *offset = 0;
    }
    file.seek(SeekFrom::Start(*offset)).await?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).await?;
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, b) in buf.iter().enumerate() {
        if *b == b'\n' {
            let line = String::from_utf8_lossy(&buf[start..i]).into_owned();
            out.push((cap_line(line), *offset + i as u64 + 1));
            start = i + 1;
        }
    }
    if flush && start < buf.len() {
        let line = String::from_utf8_lossy(&buf[start..]).into_owned();
        out.push((cap_line(line), *offset + buf.len() as u64));
        start = buf.len();
    }
    *offset += start as u64;
    Ok(out)
}

/// Runs one journald query: entries for `workload_id` strictly after `cursor`,
/// as `journalctl -o json` lines. Injectable so the resume logic is testable
/// without a journal.
pub type JournalQuery = Arc<
    dyn Fn(String, Option<String>) -> Pin<Box<dyn Future<Output = Result<String>> + Send>>
        + Send
        + Sync,
>;

/// `journalctl` argv for one query (no `--follow`: the stream re-queries from
/// its cursor, so termination is decided here rather than by killing a child).
pub fn journalctl_args(workload_id: &str, cursor: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--no-pager".to_string(),
        "--quiet".to_string(),
        "--output=json".to_string(),
        // Without --all, journalctl's JSON nulls out fields over 4 KiB.
        "--all".to_string(),
        format!("YAH_WORKLOAD_ID={workload_id}"),
    ];
    if let Some(c) = cursor {
        args.push(format!("--after-cursor={c}"));
    }
    args
}

/// The real [`JournalQuery`]. A non-zero exit, or the insufficient-permissions
/// notice, is an ERROR: an unreadable journal exits 0 with nothing on stdout
/// (`containerd.rs`'s recorded trap), and reporting that as a clean, empty
/// stream would make a run's output silently vanish.
pub fn journalctl_query() -> JournalQuery {
    Arc::new(|workload_id, cursor| {
        Box::pin(async move {
            let out = tokio::process::Command::new("journalctl")
                .args(journalctl_args(&workload_id, cursor.as_deref()))
                .kill_on_drop(true)
                .output()
                .await
                .context("spawn journalctl")?;
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !out.status.success() {
                bail!("journalctl exited {}: {}", out.status, stderr.trim());
            }
            if stderr.contains("insufficient permissions") {
                bail!("journalctl cannot read the journal: {}", stderr.trim());
            }
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        })
    })
}

/// One `journalctl -o json` line as a record, or `None` for a line that is not
/// a usable entry. `MESSAGE` is a string, or a byte array when it held
/// non-UTF-8 or embedded newlines.
pub fn parse_journal_entry(line: &str) -> Option<LogRecord> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let cursor = v.get("__CURSOR")?.as_str()?.to_string();
    let text = match v.get("MESSAGE")? {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(bytes) => {
            let raw: Vec<u8> = bytes
                .iter()
                .filter_map(|b| b.as_u64().map(|n| n as u8))
                .collect();
            String::from_utf8_lossy(&raw).into_owned()
        }
        _ => String::new(),
    };
    let stream = match v.get("YAH_STREAM").and_then(|s| s.as_str()) {
        Some("stderr") => LogStreamTag::Stderr,
        _ => LogStreamTag::Stdout,
    };
    let ts_ms = v
        .get("__REALTIME_TIMESTAMP")
        .and_then(|t| t.as_str())
        .and_then(|t| t.parse::<u64>().ok())
        .map(|us| us / 1000)
        .unwrap_or(0);
    Some(LogRecord {
        stream,
        cursor,
        ts_ms,
        line: cap_line(text),
    })
}

/// Stateful reader over one [`LogSource`], positioned at a cursor.
pub struct SourceReader {
    source: LogSource,
    journal: JournalQuery,
    /// Journald: the last `__CURSOR` seen.
    journal_cursor: Option<String>,
    /// Files: stdout/stderr offsets. Console: `offsets.0`.
    offsets: (u64, u64),
}

impl SourceReader {
    /// Position a reader at `cursor` (as minted by this module). A cursor that
    /// does not parse for this source is refused rather than read as "from
    /// the start" — a silent full replay would duplicate every line.
    pub fn new(source: LogSource, cursor: Option<&str>, journal: JournalQuery) -> Result<Self> {
        let mut offsets = (0, 0);
        let mut journal_cursor = None;
        if let Some(c) = cursor {
            match &source {
                LogSource::Journald { .. } => journal_cursor = Some(c.to_string()),
                LogSource::Files { .. } => {
                    let (a, b) = c
                        .split_once(':')
                        .ok_or_else(|| anyhow!("bad native log cursor {c:?}"))?;
                    offsets = (a.parse()?, b.parse()?);
                }
                LogSource::Console { .. } => {
                    offsets.0 = c
                        .parse()
                        .map_err(|_| anyhow!("bad console log cursor {c:?}"))?
                }
            }
        }
        Ok(Self {
            source,
            journal,
            journal_cursor,
            offsets,
        })
    }

    /// Everything available after the current position. `terminal` flushes a
    /// file's unterminated last line.
    pub async fn poll(&mut self, terminal: bool) -> Result<Vec<LogRecord>> {
        let ts = now_ms();
        match &self.source {
            LogSource::Journald { workload_id } => {
                let out = (self.journal)(workload_id.clone(), self.journal_cursor.clone()).await?;
                let recs: Vec<LogRecord> = out.lines().filter_map(parse_journal_entry).collect();
                if let Some(last) = recs.last() {
                    self.journal_cursor = Some(last.cursor.clone());
                }
                Ok(recs)
            }
            LogSource::Files { stdout, stderr } => {
                let (stdout, stderr) = (stdout.clone(), stderr.clone());
                let mut recs = Vec::new();
                // stdout first, then stderr: each record's cursor covers every
                // record emitted before it, so the cursors stay monotone.
                for (line, end) in read_appended(&stdout, &mut self.offsets.0, terminal).await? {
                    recs.push(LogRecord {
                        stream: LogStreamTag::Stdout,
                        cursor: format!("{end}:{}", self.offsets.1),
                        ts_ms: ts,
                        line,
                    });
                }
                for (line, end) in read_appended(&stderr, &mut self.offsets.1, terminal).await? {
                    recs.push(LogRecord {
                        stream: LogStreamTag::Stderr,
                        cursor: format!("{}:{end}", self.offsets.0),
                        ts_ms: ts,
                        line,
                    });
                }
                Ok(recs)
            }
            LogSource::Console { path } => {
                let path = path.clone();
                Ok(read_appended(&path, &mut self.offsets.0, terminal)
                    .await?
                    .into_iter()
                    .map(|(line, end)| LogRecord {
                        stream: LogStreamTag::Stdout,
                        cursor: end.to_string(),
                        ts_ms: ts,
                        line,
                    })
                    .collect())
            }
        }
    }
}

async fn write_reply<W: AsyncWrite + Unpin>(out: &mut W, msg: &KamajiToYubaba) -> Result<()> {
    let frame = encode_frame(msg).context("encode log frame")?;
    out.write_all(&frame).await.context("write log frame")?;
    Ok(())
}

/// Drive one `Logs` request to its end.
///
/// `is_terminal` is asked BEFORE each read, so the read that follows a
/// terminal answer sees everything the workload wrote; only an empty read
/// after a terminal answer ends the stream, which is what makes `LogEnd` mean
/// "terminal AND drained". Returns `Err` on a source or write failure — the
/// connection then closes without `LogEnd`, which the reader treats as a drop.
pub async fn run_stream<W, F, Fut>(
    mut reader: SourceReader,
    request_id: RequestId,
    mut cursor: Option<String>,
    mut is_terminal: F,
    out: &mut W,
    poll: Duration,
    keepalive: Duration,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let mut quiet = Duration::ZERO;
    loop {
        let terminal = is_terminal().await;
        let recs = reader.poll(terminal).await?;
        if !recs.is_empty() {
            quiet = Duration::ZERO;
            let mut batch = Vec::new();
            let mut bytes = 0usize;
            for r in recs {
                bytes += r.line.len();
                batch.push(r);
                if bytes >= MAX_BATCH_BYTES {
                    cursor = batch.last().map(|r| r.cursor.clone());
                    let records = std::mem::take(&mut batch);
                    let msg = KamajiToYubaba::LogBatch {
                        request_id,
                        records,
                        cursor: cursor.clone(),
                    };
                    write_reply(out, &msg).await?;
                    bytes = 0;
                }
            }
            if !batch.is_empty() {
                cursor = batch.last().map(|r| r.cursor.clone());
                let msg = KamajiToYubaba::LogBatch {
                    request_id,
                    records: batch,
                    cursor: cursor.clone(),
                };
                write_reply(out, &msg).await?;
            }
            continue;
        }
        if terminal {
            return write_reply(out, &KamajiToYubaba::LogEnd { request_id, cursor }).await;
        }
        if quiet >= keepalive {
            let msg = KamajiToYubaba::LogBatch {
                request_id,
                records: Vec::new(),
                cursor: cursor.clone(),
            };
            write_reply(out, &msg).await?;
            quiet = Duration::ZERO;
        }
        tokio::time::sleep(poll).await;
        quiet += poll;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kamaji_proto::decode_frame;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    fn no_journal() -> JournalQuery {
        Arc::new(|_, _| Box::pin(async { Err(anyhow!("no journal in this test")) }))
    }

    /// A fake journal: entry `i` has cursor `c<i>`; a query returns every entry
    /// strictly after the given cursor, exactly like `--after-cursor`.
    fn fake_journal(entries: Arc<Mutex<Vec<(String, String)>>>) -> JournalQuery {
        Arc::new(move |_id, after| {
            let entries = entries.lock().unwrap().clone();
            Box::pin(async move {
                let skip = match after {
                    Some(c) => entries.iter().position(|(cur, _)| *cur == c).map_or(0, |i| i + 1),
                    None => 0,
                };
                Ok(entries[skip..]
                    .iter()
                    .map(|(cur, msg)| {
                        serde_json::json!({
                            "__CURSOR": cur,
                            "MESSAGE": msg,
                            "YAH_STREAM": "stdout",
                            "__REALTIME_TIMESTAMP": "1700000000000000",
                        })
                        .to_string()
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            })
        })
    }

    fn lines(recs: &[LogRecord]) -> Vec<String> {
        recs.iter().map(|r| r.line.clone()).collect()
    }

    fn decode_all(buf: &[u8]) -> Vec<KamajiToYubaba> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < buf.len() {
            let (m, n): (KamajiToYubaba, usize) = decode_frame(&buf[at..]).unwrap();
            out.push(m);
            at += n;
        }
        out
    }

    #[tokio::test]
    async fn journald_resume_from_cursor_is_exact() {
        let entries = Arc::new(Mutex::new(
            (1..=5).map(|i| (format!("c{i}"), format!("l{i}"))).collect::<Vec<_>>(),
        ));
        let src = LogSource::Journald { workload_id: "forge-1".into() };
        let mut r = SourceReader::new(src.clone(), None, fake_journal(entries.clone())).unwrap();
        let first = r.poll(false).await.unwrap();
        assert_eq!(lines(&first), ["l1", "l2", "l3", "l4", "l5"]);
        assert_eq!(first[1].ts_ms, 1_700_000_000_000);

        // Resume from record 2's cursor: exactly l3.. with no dup, no gap.
        let mut r2 =
            SourceReader::new(src, Some(&first[1].cursor), fake_journal(entries.clone())).unwrap();
        assert_eq!(lines(&r2.poll(false).await.unwrap()), ["l3", "l4", "l5"]);
        // And a live reader only sees what is appended after its position.
        entries.lock().unwrap().push(("c6".into(), "l6".into()));
        assert_eq!(lines(&r.poll(false).await.unwrap()), ["l6"]);
        assert!(r.poll(false).await.unwrap().is_empty());
    }

    #[test]
    fn journal_entry_parsing_and_args() {
        let rec = parse_journal_entry(
            r#"{"__CURSOR":"s=a;i=1","MESSAGE":[104,105,10,33],"YAH_STREAM":"stderr","__REALTIME_TIMESTAMP":"2000"}"#,
        )
        .unwrap();
        assert_eq!(rec.line, "hi\n!");
        assert_eq!(rec.stream, LogStreamTag::Stderr);
        assert_eq!(rec.ts_ms, 2);
        assert_eq!(rec.cursor, "s=a;i=1");
        assert!(parse_journal_entry("not json").is_none());
        let args = journalctl_args("forge-x", Some("s=a;i=1"));
        assert!(args.contains(&"YAH_WORKLOAD_ID=forge-x".to_string()));
        assert!(args.contains(&"--after-cursor=s=a;i=1".to_string()));
        assert!(!journalctl_args("forge-x", None).iter().any(|a| a.starts_with("--after")));
    }

    #[tokio::test]
    async fn file_follow_sees_appends_and_resumes_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let (out, err) = (dir.path().join("stdout.log"), dir.path().join("stderr.log"));
        std::fs::write(&out, "a\nb\npart").unwrap();
        std::fs::write(&err, "e1\n").unwrap();
        let src = LogSource::Files { stdout: out.clone(), stderr: err.clone() };
        let mut r = SourceReader::new(src.clone(), None, no_journal()).unwrap();
        let first = r.poll(false).await.unwrap();
        // The unterminated "part" is held back until it is completed.
        assert_eq!(lines(&first), ["a", "b", "e1"]);

        // Appended after open, completing the partial line.
        use std::io::Write;
        std::fs::OpenOptions::new().append(true).open(&out).unwrap().write_all(b"ial\nc\n").unwrap();
        std::fs::OpenOptions::new().append(true).open(&err).unwrap().write_all(b"e2\n").unwrap();
        let second = r.poll(false).await.unwrap();
        assert_eq!(lines(&second), ["partial", "c", "e2"]);

        // Resume from every cursor seen: the remainder is exactly what followed.
        let all: Vec<LogRecord> = first.iter().chain(second.iter()).cloned().collect();
        for (i, rec) in all.iter().enumerate() {
            let mut rr = SourceReader::new(src.clone(), Some(&rec.cursor), no_journal()).unwrap();
            let rest = lines(&rr.poll(false).await.unwrap());
            // Order within a poll is stdout-then-stderr; compare as multisets
            // of what remains after record i in emission order.
            let mut want: Vec<String> = lines(&all[i + 1..]);
            let mut got = rest.clone();
            want.sort();
            got.sort();
            assert_eq!(got, want, "resume after {:?}", rec.cursor);
        }
    }

    #[tokio::test]
    async fn console_follow_flushes_partial_line_when_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        std::fs::write(&path, "boot\nlast").unwrap();
        let src = LogSource::Console { path };
        let mut r = SourceReader::new(src.clone(), None, no_journal()).unwrap();
        let a = r.poll(false).await.unwrap();
        assert_eq!(lines(&a), ["boot"]);
        assert_eq!(a[0].cursor, "5");
        let b = r.poll(true).await.unwrap();
        assert_eq!(lines(&b), ["last"]);
        assert!(r.poll(true).await.unwrap().is_empty());
        let mut rr = SourceReader::new(src, Some("5"), no_journal()).unwrap();
        assert_eq!(lines(&rr.poll(true).await.unwrap()), ["last"]);
        assert!(SourceReader::new(
            LogSource::Console { path: "/x".into() },
            Some("nope"),
            no_journal()
        )
        .is_err());
    }

    #[tokio::test]
    async fn stream_emits_end_only_once_terminal_and_drained() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        std::fs::write(&path, "one\n").unwrap();
        let reader = SourceReader::new(LogSource::Console { path: path.clone() }, None, no_journal())
            .unwrap();
        let terminal = Arc::new(AtomicBool::new(false));
        let t = terminal.clone();
        let p = path.clone();
        let mut calls = 0u32;
        let mut out: Vec<u8> = Vec::new();
        run_stream(
            reader,
            RequestId(3),
            None,
            move || {
                calls += 1;
                // Second check: the workload writes its last line and exits.
                if calls == 2 {
                    use std::io::Write;
                    std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"two").unwrap();
                    t.store(true, Ordering::SeqCst);
                }
                let v = t.load(Ordering::SeqCst);
                async move { v }
            },
            &mut out,
            Duration::from_millis(1),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        let frames = decode_all(&out);
        let got: Vec<String> = frames
            .iter()
            .filter_map(|f| match f {
                KamajiToYubaba::LogBatch { records, .. } => Some(lines(records)),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(got, ["one", "two"]);
        assert_eq!(
            frames.last(),
            Some(&KamajiToYubaba::LogEnd { request_id: RequestId(3), cursor: Some("7".into()) })
        );
        assert!(terminal.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn stream_sends_keepalive_while_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        std::fs::write(&path, "").unwrap();
        let reader = SourceReader::new(LogSource::Console { path }, None, no_journal()).unwrap();
        let mut n = 0u32;
        let mut out: Vec<u8> = Vec::new();
        run_stream(
            reader,
            RequestId(1),
            None,
            move || {
                n += 1;
                let v = n > 6;
                async move { v }
            },
            &mut out,
            Duration::from_millis(1),
            Duration::from_millis(2),
        )
        .await
        .unwrap();
        let frames = decode_all(&out);
        assert!(frames.iter().any(|f| matches!(f, KamajiToYubaba::LogBatch { records, .. } if records.is_empty())));
        assert!(matches!(frames.last(), Some(KamajiToYubaba::LogEnd { cursor: None, .. })));
    }

    #[test]
    fn resolve_source_maps_both_key_spellings_in_one_place() {
        let dir = tempfile::tempdir().unwrap();
        let native = dir.path().join("native");
        let vm = dir.path().join("vm");
        std::fs::create_dir_all(native.join("forge.n1")).unwrap();
        std::fs::write(native.join("forge.n1/stdout.log"), "").unwrap();
        std::fs::create_dir_all(vm.join("vm.1")).unwrap();
        std::fs::write(vm.join("vm.1/console.log"), "").unwrap();
        let (n, v) = (Some(native.as_path()), Some(vm.as_path()));

        // Native by mesh ident, even after teardown dropped the entry.
        assert!(matches!(resolve_source(n, v, "forge.n1", None), Some(LogSource::Files { .. })));
        assert!(matches!(resolve_source(n, v, "vm.1", None), Some(LogSource::Console { .. })));
        // Container: requested by mesh ident, journald keyed by the entry's id.
        assert_eq!(
            resolve_source(n, v, "forge.c1", Some(("forge-c1", Some("forge.c1")))),
            Some(LogSource::Journald { workload_id: "forge-c1".into() })
        );
        // Unknown: no entry and no file is NOT an empty journald query.
        assert_eq!(resolve_source(n, v, "ghost.1", None), None);
    }
}

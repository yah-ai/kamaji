//! Append-only JSONL sink at `${state_dir}/audit/YYYY-MM-DD.jsonl` with daily
//! rotation and retention pruning.
//!
//! One line per [`AuditRecord`], terminated with `\n`. On UTC date change the
//! writer opens a fresh file; the previous day's file is closed (its final
//! line already terminated, so tailers see a natural EOF). Old files are
//! pruned once the retention window is exceeded — the default is 30 days
//! per W159 §Audit journal.
//!
//! `write` is synchronous and non-blocking on the happy path (single
//! `write_all` per record). A dispatch loop that already spans multiple
//! tasks should either wrap the writer in `Arc<Mutex<>>` and call it from
//! the request handler, or push records over an mpsc into a dedicated
//! writer task — either works; the writer itself is `Send + Sync` behind a
//! `&mut self` because rotation mutates its cached day + file handle.
//!
//! Time is injected via a `Clock` closure so the daily-rotation and
//! retention-prune paths are testable without sleeping across midnight.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use super::record::AuditRecord;

/// How many days of daily files to keep before pruning. W159 §Audit journal
/// pins the default at 30d.
pub const DEFAULT_RETENTION_DAYS: u32 = 30;

/// Configuration for a [`JsonlWriter`].
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// Directory that holds the `YYYY-MM-DD.jsonl` files. Created on first
    /// write if it doesn't exist.
    pub dir: PathBuf,
    /// Retention window in days. Files whose date is more than this many
    /// days before "today" are deleted after each rotation. Set to `None`
    /// to skip pruning entirely (useful for one-shot tests).
    pub retention_days: Option<u32>,
    /// Filename stem — `"audit"` for the primary journal, `"denied"` for
    /// the sampled rejected-traffic journal. Files land at
    /// `<dir>/<stem>-YYYY-MM-DD.jsonl`.
    pub stem: String,
}

impl WriterConfig {
    /// Default primary-journal config: `<dir>/audit-YYYY-MM-DD.jsonl`, 30d
    /// retention.
    pub fn audit(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            retention_days: Some(DEFAULT_RETENTION_DAYS),
            stem: "audit".into(),
        }
    }

    /// Default denied-journal config: same shape with a `denied` stem so
    /// operators can `ls audit/denied-*.jsonl` to enumerate the sampled
    /// stream separately.
    pub fn denied(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            retention_days: Some(DEFAULT_RETENTION_DAYS),
            stem: "denied".into(),
        }
    }
}

/// Injected clock — returns Unix seconds. Production is
/// [`SystemTime::now`](std::time::SystemTime::now); tests supply a closure
/// that returns a canned value so the midnight-rotation path can be
/// exercised in-process.
pub type Clock = Box<dyn FnMut() -> i64 + Send + Sync>;

/// Daily-rotating JSONL writer.
pub struct JsonlWriter {
    cfg: WriterConfig,
    clock: Clock,
    current: Option<OpenFile>,
}

struct OpenFile {
    date: UtcDate,
    file: File,
}

impl std::fmt::Debug for JsonlWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonlWriter")
            .field("cfg", &self.cfg)
            .field("current_date", &self.current.as_ref().map(|c| c.date))
            .finish()
    }
}

impl JsonlWriter {
    /// Build a writer with the real system clock.
    pub fn new(cfg: WriterConfig) -> Self {
        Self::with_clock(
            cfg,
            Box::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
            }),
        )
    }

    /// Build a writer with an injected clock (for tests).
    pub fn with_clock(cfg: WriterConfig, clock: Clock) -> Self {
        Self {
            cfg,
            clock,
            current: None,
        }
    }

    /// Append one record. Opens (or rotates) the day file as needed, then
    /// writes one JSONL line + `\n`. Serialization errors bubble as
    /// `io::Error` with `InvalidData` — the record shape is compile-time
    /// controlled so this only fires on truly-broken record data.
    pub fn write(&mut self, record: &AuditRecord) -> io::Result<()> {
        let now = (self.clock)();
        let date = UtcDate::from_unix_seconds(now);
        self.ensure_day(date)?;
        let line = serde_json::to_string(record)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let file = &mut self.current.as_mut().expect("day file open").file;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    }

    /// Flush the current day file to the OS. Rotation implicitly flushes
    /// (drop closes the handle); this is exposed for the forwarder-shutdown
    /// path where a caller wants durability before exit.
    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(cur) = self.current.as_mut() {
            cur.file.flush()?;
        }
        Ok(())
    }

    fn ensure_day(&mut self, date: UtcDate) -> io::Result<()> {
        let needs_rotate = match &self.current {
            Some(cur) => cur.date != date,
            None => true,
        };
        if !needs_rotate {
            return Ok(());
        }
        fs::create_dir_all(&self.cfg.dir)?;
        let path = self.day_path(date);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        self.current = Some(OpenFile { date, file });
        // Prune after rotation, not on every write — cheap enough given
        // rotation happens once per day per writer.
        if let Some(days) = self.cfg.retention_days {
            self.prune(date, days)?;
        }
        Ok(())
    }

    fn day_path(&self, date: UtcDate) -> PathBuf {
        self.cfg
            .dir
            .join(format!("{}-{}.jsonl", self.cfg.stem, date.iso_date()))
    }

    /// Delete `<stem>-YYYY-MM-DD.jsonl` files whose date is strictly older
    /// than `today - retention_days`. Same-day and future-dated files (clock
    /// skew) are always kept.
    fn prune(&self, today: UtcDate, retention_days: u32) -> io::Result<()> {
        let entries = match fs::read_dir(&self.cfg.dir) {
            Ok(e) => e,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        };
        let cutoff_day = today.day_number().saturating_sub(retention_days as i64);
        let prefix = format!("{}-", self.cfg.stem);
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let Some(rest) = name_str.strip_prefix(&prefix) else {
                continue;
            };
            let Some(date_str) = rest.strip_suffix(".jsonl") else {
                continue;
            };
            let Some(date) = UtcDate::parse_iso(date_str) else {
                continue;
            };
            if date.day_number() < cutoff_day {
                // Best-effort — a warning would just noise the log for
                // a file another process already deleted (unlikely, but
                // possible in operator-driven manual cleanup).
                let _ = fs::remove_file(entry.path());
            }
        }
        Ok(())
    }

    /// Test / diagnostic helper — the path of the current-day file, or
    /// `None` if the writer hasn't opened one yet.
    pub fn current_path(&self) -> Option<PathBuf> {
        self.current.as_ref().map(|c| self.day_path(c.date))
    }
}

/// UTC calendar date, computed from Unix seconds without pulling in a
/// heavyweight date crate.
///
/// The conversion uses the well-known "civil_from_days" algorithm (Howard
/// Hinnant, `date` library) which is exact for the full proleptic Gregorian
/// range we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcDate {
    pub year: i32,
    pub month: u32,
    pub day: u32,
}

impl UtcDate {
    /// Build from Unix seconds (UTC). Negative inputs floor toward the past.
    pub fn from_unix_seconds(secs: i64) -> Self {
        // Floor-divide to a day count (Rust's `/` truncates; we need floor for
        // negative seconds so pre-epoch instants land on the correct day).
        let days = secs.div_euclid(86_400);
        Self::from_day_number(days)
    }

    /// Days since the Unix epoch (1970-01-01 = 0). Used by pruning.
    pub fn day_number(self) -> i64 {
        let mut y = self.year as i64;
        let mut m = self.month as i64;
        if m <= 2 {
            y -= 1;
            m += 12;
        }
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let doy = (153 * (m - 3) + 2) / 5 + self.day as i64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    fn from_day_number(days: i64) -> Self {
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = (y + i64::from(m <= 2)) as i32;
        Self {
            year,
            month: m as u32,
            day: d as u32,
        }
    }

    /// `YYYY-MM-DD` — the filename-embedded form.
    pub fn iso_date(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }

    /// Inverse of [`iso_date`]. Returns `None` for shapes that don't parse.
    pub fn parse_iso(s: &str) -> Option<Self> {
        // Expect exact `YYYY-MM-DD` — no fractional / extended forms.
        let bytes = s.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return None;
        }
        let year: i32 = s[0..4].parse().ok()?;
        let month: u32 = s[5..7].parse().ok()?;
        let day: u32 = s[8..10].parse().ok()?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        Some(Self { year, month, day })
    }
}

impl AsRef<Path> for &JsonlWriter {
    fn as_ref(&self) -> &Path {
        &self.cfg.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::record::{AuditRecord, Outcome};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    fn rec(at: i64, req: &str) -> AuditRecord {
        AuditRecord {
            at,
            sub: Some("user:abc".into()),
            act: None,
            camp_id: Some("C1".into()),
            aud: Some("https://kamaji.example".into()),
            method: "cloud.deploy".into(),
            scope: Some("cloud:deploy".into()),
            result: Outcome::Ok,
            request_id: req.into(),
        }
    }

    /// A clock backed by a shared cell so the test can advance time in
    /// steps without reconstructing the writer.
    fn stepped_clock(cell: Arc<Mutex<i64>>) -> Clock {
        Box::new(move || *cell.lock().unwrap())
    }

    #[test]
    fn utc_date_from_epoch_start() {
        assert_eq!(
            UtcDate::from_unix_seconds(0),
            UtcDate {
                year: 1970,
                month: 1,
                day: 1
            }
        );
    }

    #[test]
    fn utc_date_from_known_instant_2026_06_30() {
        // 2026-06-30 00:00:00 UTC — used in this session's context header.
        let secs = 1_782_777_600_i64;
        assert_eq!(
            UtcDate::from_unix_seconds(secs),
            UtcDate {
                year: 2026,
                month: 6,
                day: 30
            }
        );
    }

    #[test]
    fn utc_date_late_seconds_stay_on_same_day() {
        // 2026-06-30 23:59:59 UTC.
        let secs = 1_782_777_600_i64 + 86_399;
        assert_eq!(
            UtcDate::from_unix_seconds(secs),
            UtcDate {
                year: 2026,
                month: 6,
                day: 30
            }
        );
    }

    #[test]
    fn utc_date_roundtrip_via_day_number() {
        let d = UtcDate {
            year: 2026,
            month: 6,
            day: 30,
        };
        let n = d.day_number();
        assert_eq!(UtcDate::from_day_number(n), d);
    }

    #[test]
    fn utc_date_parse_iso_roundtrip() {
        let d = UtcDate {
            year: 2026,
            month: 6,
            day: 30,
        };
        assert_eq!(UtcDate::parse_iso(&d.iso_date()), Some(d));
        assert_eq!(UtcDate::parse_iso("bogus"), None);
        assert_eq!(UtcDate::parse_iso("2026-13-01"), None);
        assert_eq!(UtcDate::parse_iso("2026-06-32"), None);
    }

    #[test]
    fn write_creates_day_file_and_appends_line() {
        let dir = tempdir().unwrap();
        let clock = Arc::new(Mutex::new(1_782_777_600_i64)); // 2026-06-30
        let cfg = WriterConfig::audit(dir.path());
        let mut w = JsonlWriter::with_clock(cfg, stepped_clock(clock.clone()));

        w.write(&rec(1_782_777_600, "req-1")).unwrap();
        w.write(&rec(1_782_777_601, "req-2")).unwrap();
        w.flush().unwrap();

        let path = dir.path().join("audit-2026-06-30.jsonl");
        let body = fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = body.lines().collect();
        assert_eq!(lines.len(), 2, "two records → two lines");
        // Each line is a full JSON object terminated by \n.
        assert!(body.ends_with('\n'));
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["method"], "cloud.deploy");
        }
    }

    #[test]
    fn crossing_midnight_opens_a_new_file() {
        let dir = tempdir().unwrap();
        let clock = Arc::new(Mutex::new(1_782_777_600_i64)); // 2026-06-30
        let cfg = WriterConfig::audit(dir.path());
        let mut w = JsonlWriter::with_clock(cfg, stepped_clock(clock.clone()));

        w.write(&rec(1_782_777_600, "req-a")).unwrap();
        // Advance clock past midnight → 2026-07-01.
        *clock.lock().unwrap() = 1_782_777_600 + 86_400;
        w.write(&rec(1_782_864_000, "req-b")).unwrap();
        w.flush().unwrap();

        let jun30 = dir.path().join("audit-2026-06-30.jsonl");
        let jul01 = dir.path().join("audit-2026-07-01.jsonl");
        assert!(jun30.exists(), "day-1 file present");
        assert!(jul01.exists(), "day-2 file present after rotation");
        // Each file has exactly one line.
        assert_eq!(fs::read_to_string(&jun30).unwrap().lines().count(), 1);
        assert_eq!(fs::read_to_string(&jul01).unwrap().lines().count(), 1);
    }

    #[test]
    fn retention_prune_deletes_files_older_than_window() {
        let dir = tempdir().unwrap();
        // Pre-seed old files across a wide window.
        for iso in [
            "2026-05-01",
            "2026-05-15",
            "2026-05-30",
            "2026-06-15",
            "2026-06-25",
        ] {
            let path = dir.path().join(format!("audit-{iso}.jsonl"));
            fs::write(path, "").unwrap();
        }
        // 30d retention on 2026-06-30 → cutoff day = 2026-05-31; strictly
        // older is deleted (05-01, 05-15, 05-30). 06-15 + 06-25 survive.
        let clock = Arc::new(Mutex::new(1_782_777_600_i64));
        let cfg = WriterConfig::audit(dir.path());
        let mut w = JsonlWriter::with_clock(cfg, stepped_clock(clock));
        w.write(&rec(1_782_777_600, "req-1")).unwrap();

        let names: std::collections::BTreeSet<String> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "audit-2026-06-15.jsonl",
                "audit-2026-06-25.jsonl",
                "audit-2026-06-30.jsonl",
            ]
            .into_iter()
            .map(String::from)
            .collect()
        );
    }

    #[test]
    fn prune_ignores_foreign_files_and_wrong_stem() {
        let dir = tempdir().unwrap();
        // Neighbouring files that must survive:
        // - a denied-* file (different stem, would be pruned by a `denied` writer only)
        // - README.md (no matching prefix)
        // - a malformed date-stub (must not crash the walker)
        fs::write(dir.path().join("denied-2026-05-01.jsonl"), "").unwrap();
        fs::write(dir.path().join("README.md"), "").unwrap();
        fs::write(dir.path().join("audit-bogus.jsonl"), "").unwrap();
        fs::write(dir.path().join("audit-2026-05-01.jsonl"), "").unwrap();

        let clock = Arc::new(Mutex::new(1_782_777_600_i64));
        let cfg = WriterConfig::audit(dir.path());
        let mut w = JsonlWriter::with_clock(cfg, stepped_clock(clock));
        w.write(&rec(1_782_777_600, "req-1")).unwrap();

        let names: std::collections::BTreeSet<String> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        assert!(names.contains("denied-2026-05-01.jsonl"));
        assert!(names.contains("README.md"));
        assert!(names.contains("audit-bogus.jsonl"));
        assert!(!names.contains("audit-2026-05-01.jsonl"));
    }

    #[test]
    fn retention_none_skips_prune() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("audit-2020-01-01.jsonl"), "").unwrap();
        let clock = Arc::new(Mutex::new(1_782_777_600_i64));
        let mut cfg = WriterConfig::audit(dir.path());
        cfg.retention_days = None;
        let mut w = JsonlWriter::with_clock(cfg, stepped_clock(clock));
        w.write(&rec(1_782_777_600, "req-1")).unwrap();
        assert!(dir.path().join("audit-2020-01-01.jsonl").exists());
    }

    #[test]
    fn append_across_writer_restarts_preserves_prior_lines() {
        let dir = tempdir().unwrap();
        let clock = Arc::new(Mutex::new(1_782_777_600_i64));
        {
            let mut w = JsonlWriter::with_clock(
                WriterConfig::audit(dir.path()),
                stepped_clock(clock.clone()),
            );
            w.write(&rec(1_782_777_600, "req-1")).unwrap();
            w.flush().unwrap();
        }
        {
            let mut w2 = JsonlWriter::with_clock(
                WriterConfig::audit(dir.path()),
                stepped_clock(clock.clone()),
            );
            w2.write(&rec(1_782_777_601, "req-2")).unwrap();
            w2.flush().unwrap();
        }
        let body = fs::read_to_string(dir.path().join("audit-2026-06-30.jsonl")).unwrap();
        assert_eq!(body.lines().count(), 2);
    }

    #[test]
    fn current_path_reflects_open_day() {
        let dir = tempdir().unwrap();
        let clock = Arc::new(Mutex::new(1_782_777_600_i64));
        let mut w = JsonlWriter::with_clock(WriterConfig::audit(dir.path()), stepped_clock(clock));
        assert!(w.current_path().is_none());
        w.write(&rec(1_782_777_600, "req-1")).unwrap();
        assert_eq!(
            w.current_path(),
            Some(dir.path().join("audit-2026-06-30.jsonl"))
        );
    }
}

//! Staged-write helpers: stage at a path no other writer can pick, then rename
//! it over the destination.
//!
//! R925: a *fixed* staging name (`<file>.json.tmp`, `.<id>.json.tmp`) is shared
//! by every concurrent writer of that destination, so two writers interleave
//! into one staging file and the rename publishes whichever bytes happen to be
//! there — typically a truncated JSON document. That is not theoretical:
//! `~/.yah/slots.json` was found on disk at 3719 bytes ending in `]]`, valid at
//! exactly one byte less, from this race. Malformed JSON projects as EMPTY
//! downstream through most of this codebase rather than erroring (the port
//! ledger's own `load` does precisely that), so the failure presents as silent
//! wrong behaviour rather than as a parse error somebody would chase.
//!
//! Staging at a path disambiguated by pid *and* an in-process sequence number
//! gives every writer its own file: the pid separates processes, the sequence
//! separates the tokio tasks inside one.
//!
//! Modelled on `oss/cheers/crates/cheers-store/src/atomic_file.rs`. A separate
//! implementation rather than a shared dependency because each `oss/<name>` is
//! an independent Cargo workspace that must stay buildable standalone.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Distinguishes two staging files made by the same process. The pid alone is
/// not enough — the writers this module exists for are as often two tokio tasks
/// in one kamaji as they are two processes.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// A staging path beside `final_path` that no concurrent writer will pick:
/// `<final_path>.tmp.<pid>.<seq>`.
///
/// Appended to the whole file name rather than substituted through
/// `with_extension`, so a caller that already encodes something in the name —
/// `kamaji-bin`'s per-record `.<id>.json`, including its leading dot — keeps it.
///
/// The resulting extension is the sequence number, never `json`. That is what
/// keeps staging files out of `BundleBackend::recorded_deploys`, whose scan
/// filters on `extension == "json"`.
pub fn staging_path(final_path: &Path) -> PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut name = final_path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}.{seq}", std::process::id()));
    match final_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

/// `create_dir_all` the parent, write `bytes` to a private staging file, then
/// rename it over `path`.
///
/// A failed rename removes the staging file, and that cleanup is load-bearing
/// rather than tidiness: staging names are unique per writer, so a leaked one is
/// never reused by a later write the way a fixed `<file>.tmp` was, and they
/// would otherwise accumulate in the state directory without bound.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = staging_path(path);
    std::fs::write(&tmp, bytes)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the module: two writers of one destination must not
    /// share a staging file.
    #[test]
    fn two_stagings_of_one_destination_do_not_collide() {
        let path = Path::new("/var/lib/kamaji/ports.json");
        assert_ne!(staging_path(path), staging_path(path));
    }

    /// A leading dot and an embedded `.json` both survive, because `recorded_deploys`
    /// relies on the name it wrote and the extension filter relies on the suffix.
    #[test]
    fn staging_keeps_the_whole_file_name_and_never_ends_in_json() {
        let staged = staging_path(Path::new("/tmp/deploys/.yah-marketing.json"));
        let name = staged.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(".yah-marketing.json.tmp."), "{name}");
        assert_ne!(staged.extension().unwrap(), "json");
        assert_eq!(staged.parent().unwrap(), Path::new("/tmp/deploys"));
    }

    #[test]
    fn write_atomic_creates_parents_and_leaves_no_staging_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/ledger.json");
        write_atomic(&path, b"{}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{}");
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .filter(|n| n.to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "staging files left behind: {leftovers:?}");
    }
}

//! The job document, as the **guest** reads it.
//!
//! This is deliberately a second, independent declaration of the same document
//! `kamaji::microvm::MicroVmJob` writes. Sharing the Rust type would be shorter
//! and would be wrong: the two artifacts ship separately — a rootfs image built
//! months before the kamaji binary that boots it — so the contract is the
//! serialized JSON, not a struct definition both sides happen to compile.
//! Sharing the type would let a field rename pass every test while breaking
//! every deployed image, because both sides would have been renamed together.
//!
//! What keeps the two honest is [`tests::the_golden_fixture_from_the_kamaji_side_parses`]:
//! the bytes asserted there are copied from
//! `the_job_document_serializes_to_the_shape_the_guest_init_parses` in
//! `oss/kamaji/crates/kamaji/src/microvm.rs`. If that test's fixture changes,
//! this one fails, and the question is whether [`SCHEMA_VERSION`] needs a bump.
//!
//! @arch:see(.yah/docs/working/W325-isolated-x86-build-capacity.md)

use std::collections::BTreeMap;

use serde::Deserialize;

/// The only document version this init understands.
///
/// Mirrors `kamaji::microvm::JOB_SCHEMA_VERSION`. A mismatch is a refusal, not
/// a best-effort parse: a guest that guesses at a document it does not
/// understand runs the wrong argv against the wrong mounts, and does it
/// silently.
pub const SCHEMA_VERSION: u32 = 1;

/// Name of the document at the root of the scratch disk.
pub const JOB_FILE: &str = "job.json";

/// What the guest was booted to do.
///
/// Unknown fields are **ignored** rather than rejected. A newer kamaji may add
/// an optional field without breaking the shape this init reads, and refusing it
/// would strand every deployed image on the day that happens; the version field
/// is what guards the changes that genuinely do break.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Job {
    pub schema: u32,
    pub workload: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub workdir: Option<String>,
    pub workspace_mount: String,
    /// Serialized by the host as a dotted-quad string, and kept as a string
    /// here: the only thing the guest does with it is write a `resolv.conf`
    /// line, so parsing it into an address type would add a failure mode
    /// (a v6 resolver one day) to a value this code never does arithmetic on.
    #[serde(default)]
    pub dns: Option<String>,
    #[serde(default)]
    pub mounts: Vec<Mount>,
}

/// One volume as the guest must present it: `<workspace_mount>/<slug>` bind-mounted at `target`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Mount {
    pub slug: String,
    pub target: String,
    pub read_only: bool,
}

/// Why a document was refused.
///
/// Split by cause because each one sends an operator somewhere different:
/// `Malformed` is a serializer bug or a truncated write, `Unusable` is a
/// document that parsed but asks for something incoherent, and `UnknownSchema`
/// is a version skew between two artifacts that were deployed independently —
/// the failure this document is versioned to make legible.
#[derive(Debug)]
pub enum JobError {
    Malformed(String),
    UnknownSchema { found: u32, supported: u32 },
    Unusable(String),
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "{JOB_FILE} is not the job document: {e}"),
            Self::UnknownSchema { found, supported } => write!(
                f,
                "{JOB_FILE} declares schema {found}; this rootfs understands only {supported} — \
                 the guest image and the kamaji that booted it are skewed, and the image is the \
                 side that has to be rebuilt"
            ),
            Self::Unusable(e) => write!(f, "{JOB_FILE} is self-inconsistent: {e}"),
        }
    }
}

impl Job {
    /// Parse and validate the document.
    ///
    /// The version is checked *before* the rest of the shape, so a document from
    /// a future kamaji is reported as skew rather than as a missing field —
    /// which is the difference between an operator rebuilding the image and an
    /// operator hunting a serializer bug that does not exist.
    pub fn parse(raw: &[u8]) -> Result<Self, JobError> {
        let value: serde_json::Value =
            serde_json::from_slice(raw).map_err(|e| JobError::Malformed(e.to_string()))?;

        let schema = value
            .get("schema")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| JobError::Malformed("no numeric `schema` field".into()))?;
        if schema != u64::from(SCHEMA_VERSION) {
            return Err(JobError::UnknownSchema {
                found: schema as u32,
                supported: SCHEMA_VERSION,
            });
        }

        let job: Job =
            serde_json::from_value(value).map_err(|e| JobError::Malformed(e.to_string()))?;
        job.validate()?;
        Ok(job)
    }

    /// Reject a document that would make the init do something incoherent.
    ///
    /// The host is trusted here — this is not a security boundary, kamaji wrote
    /// the file. It is a *legibility* boundary: a `slug` with a `/` in it or a
    /// relative `target` would produce a mount at a path nobody asked for, and
    /// the resulting build failure would be attributed to the build.
    fn validate(&self) -> Result<(), JobError> {
        if self.argv.is_empty() || self.argv[0].is_empty() {
            return Err(JobError::Unusable("`argv` is empty".into()));
        }
        if !self.workspace_mount.starts_with('/') {
            return Err(JobError::Unusable(format!(
                "`workspace_mount` {:?} is not absolute",
                self.workspace_mount
            )));
        }
        if let Some(dir) = &self.workdir {
            if !dir.starts_with('/') {
                return Err(JobError::Unusable(format!(
                    "`workdir` {dir:?} is not absolute"
                )));
            }
        }
        for m in &self.mounts {
            if m.slug.is_empty() || m.slug.contains('/') || m.slug.starts_with('.') {
                return Err(JobError::Unusable(format!(
                    "mount slug {:?} is not a single directory name",
                    m.slug
                )));
            }
            if !m.target.starts_with('/') || m.target.split('/').any(|c| c == "..") {
                return Err(JobError::Unusable(format!(
                    "mount target {:?} is not an absolute path without `..`",
                    m.target
                )));
            }
        }
        Ok(())
    }

    /// Absolute path of one mount's source inside the guest.
    pub fn source_of(&self, m: &Mount) -> String {
        format!("{}/{}", self.workspace_mount.trim_end_matches('/'), m.slug)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes below are the fixture from
    /// `the_job_document_serializes_to_the_shape_the_guest_init_parses`
    /// (`oss/kamaji/crates/kamaji/src/microvm.rs`), transcribed rather than
    /// imported. Both tests assert against the same literal shape from opposite
    /// sides, which is the only arrangement in which a rename fails a test.
    const GOLDEN: &str = r#"{
      "schema": 1,
      "workload": "forge-forge-abc",
      "argv": ["/bin/sh", "-c", "cargo build"],
      "env": { "CARGO_HOME": "/workspace/.cargo" },
      "workdir": "/src",
      "workspace_mount": "/workspace",
      "dns": "1.1.1.1",
      "mounts": [
        { "slug": "0-yah-produced", "target": "/yah/produced", "read_only": false },
        { "slug": "1-etc-certs", "target": "/etc/certs", "read_only": true }
      ]
    }"#;

    #[test]
    fn the_golden_fixture_from_the_kamaji_side_parses() {
        let job = Job::parse(GOLDEN.as_bytes()).expect("the pinned host-side shape must parse");
        assert_eq!(job.schema, SCHEMA_VERSION);
        assert_eq!(job.workload, "forge-forge-abc");
        assert_eq!(job.argv, ["/bin/sh", "-c", "cargo build"]);
        assert_eq!(job.env["CARGO_HOME"], "/workspace/.cargo");
        assert_eq!(job.workdir.as_deref(), Some("/src"));
        assert_eq!(job.workspace_mount, "/workspace");
        assert_eq!(job.dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(job.mounts.len(), 2);
        assert_eq!(job.mounts[0].slug, "0-yah-produced");
        assert_eq!(job.mounts[0].target, "/yah/produced");
        assert!(!job.mounts[0].read_only);
        assert!(job.mounts[1].read_only);
        // The join the init actually performs, asserted rather than assumed:
        // getting this wrong mounts an empty directory over the produced dir and
        // the build "succeeds" with no artifacts.
        assert_eq!(job.source_of(&job.mounts[0]), "/workspace/0-yah-produced");
    }

    #[test]
    fn an_unknown_schema_is_refused_and_says_which_side_is_stale() {
        let doc = GOLDEN.replace("\"schema\": 1", "\"schema\": 2");
        match Job::parse(doc.as_bytes()) {
            Err(JobError::UnknownSchema { found, supported }) => {
                assert_eq!((found, supported), (2, 1));
            }
            other => panic!("expected UnknownSchema, got {other:?}"),
        }
    }

    /// A future kamaji adding an optional field must not brick every image
    /// already on the fleet — that is what the version field is for, and
    /// tolerating additions is the other half of taking it seriously.
    #[test]
    fn an_unknown_field_at_a_known_schema_is_ignored_not_refused() {
        let doc = GOLDEN.replace(
            "\"workload\":",
            "\"cpu_quota_percent\": 50,\n      \"workload\":",
        );
        let job = Job::parse(doc.as_bytes()).expect("additive fields must not be fatal");
        assert_eq!(job.workload, "forge-forge-abc");
    }

    #[test]
    fn a_document_with_no_argv_is_refused_rather_than_booted_into_nothing() {
        let doc = GOLDEN.replace(r#"["/bin/sh", "-c", "cargo build"]"#, "[]");
        assert!(matches!(
            Job::parse(doc.as_bytes()),
            Err(JobError::Unusable(_))
        ));
    }

    #[test]
    fn a_slug_that_is_a_path_is_refused_because_it_would_mount_somewhere_else() {
        let doc = GOLDEN.replace("\"0-yah-produced\"", "\"../../etc\"");
        assert!(matches!(
            Job::parse(doc.as_bytes()),
            Err(JobError::Unusable(_))
        ));
    }

    #[test]
    fn a_relative_target_is_refused() {
        let doc = GOLDEN.replace("\"/yah/produced\"", "\"yah/produced\"");
        assert!(matches!(
            Job::parse(doc.as_bytes()),
            Err(JobError::Unusable(_))
        ));
    }

    /// `dns` and `workdir` are `Option` on the host side and an air-gapped node
    /// omits the resolver entirely; a guest that required them would refuse
    /// every job on such a node.
    #[test]
    fn the_optional_halves_of_the_document_may_be_absent() {
        let doc = r#"{
          "schema": 1,
          "workload": "job",
          "argv": ["/bin/true"],
          "env": {},
          "workdir": null,
          "workspace_mount": "/workspace",
          "dns": null,
          "mounts": []
        }"#;
        let job = Job::parse(doc.as_bytes()).expect("an air-gapped job is a valid job");
        assert!(job.dns.is_none());
        assert!(job.workdir.is_none());
        assert!(job.mounts.is_empty());
    }

    #[test]
    fn a_truncated_document_is_malformed_not_a_schema_problem() {
        assert!(matches!(
            Job::parse(b"{\"schema\": 1, \"workl"),
            Err(JobError::Malformed(_))
        ));
    }
}

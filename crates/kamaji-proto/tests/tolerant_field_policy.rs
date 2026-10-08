//! The per-field half of the V13 envelope (R896-F2, W349 "What (a) requires" 1).
//!
//! [`kamaji_proto::tolerant`] makes a wrapped payload match fields BY NAME, which
//! buys field *additions* outright. It does not buy what a skewed peer does when
//! a field it knows is *absent* — that is decided per field, by whether the field
//! carries a serde default. So:
//!
//! - a field **added** without a default refuses every frame from a peer that
//!   predates it (the kamaji-first half of a roll), which is the wire break the
//!   envelope was built to stop, re-created one field at a time;
//! - a field **deleted** later crosses only if the peer that still knows it can
//!   decode its absence — a property that cannot be added retroactively.
//!
//! And the default is not free to choose. It must equal the **pre-field
//! behaviour**, or tolerance turns a loud break into a silent semantic skew.
//! That is why this file does not simply demand a default everywhere: `image`,
//! `name`, a capability bit, an assignment's address — those have no honest
//! "absent" value, and defaulting them would also loosen the TOML/JSON
//! authoring parse of the same types (R658-B1 bought that loudness on purpose).
//!
//! So the test pins the split instead. Each wire-carried struct's set of fields
//! whose absence FAILS the decode is frozen below. Adding a field lands you here
//! if and only if you forgot the decision:
//!
//! - give it `#[serde(default)]` whose value is what a peer that never sent it
//!   already meant — then it crosses a skew and this test stays green; or
//! - if no such value exists, it is a semantic change: bump
//!   [`kamaji_proto::ProtocolVersion`] and add the field to the frozen list here.
//!
//! Enforcement of genuinely required fields stays where it is — serde, loudly —
//! rather than moving to `validate.rs` behind a blanket default.

use kamaji_proto::{
    MeshAssignment, MicroVmHealth, NodeCapabilities, WireguardPeer, WorkloadEntry, WorkloadId,
    WorkloadState,
};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::BTreeMap;
use workload_spec::{ImageRef, TenantPasswayTls, TenantPasswayWorkload, TierTag, WorkloadSpec};

/// Every top-level field of `value` whose absence makes the decode fail.
///
/// `value` must serialize every field it has (no `skip_serializing_if`), or a
/// skipped field is invisible here — R590-B3 already stripped those from the
/// wire-carried graph, and a field that reappears with one would be a postcard
/// hazard long before it was a gap in this test.
fn fields_whose_absence_breaks<T: Serialize + DeserializeOwned>(value: &T) -> Vec<String> {
    let encoded = serde_json::to_value(value).expect("encode");
    let obj = encoded
        .as_object()
        .expect("a wire-carried struct encodes as a map");
    let mut breaking: Vec<String> = obj
        .keys()
        .filter(|key| {
            let mut trimmed = obj.clone();
            trimmed.remove(*key);
            serde_json::from_value::<T>(serde_json::Value::Object(trimmed)).is_err()
        })
        .cloned()
        .collect();
    breaking.sort();
    breaking
}

fn assert_required<T: Serialize + DeserializeOwned>(name: &str, value: &T, frozen: &[&str]) {
    let actual = fields_whose_absence_breaks(value);
    assert_eq!(
        actual, frozen,
        "\n{name}: the set of fields a skewed peer cannot omit changed.\n\
         A NEW entry means a field was added without a serde default, so every \
         frame from a peer that predates it will be refused. Give it \
         #[serde(default)] equal to the pre-field behaviour, or — if absence has \
         no honest meaning — bump ProtocolVersion and add it to this list.\n\
         A MISSING entry means a required field gained a default: confirm that \
         default is what an older peer already meant, then drop it from the list.\n\
         See this file's module doc and W349.\n"
    );
}

#[test]
fn workload_spec_required_fields_are_a_deliberate_set() {
    let spec = WorkloadSpec::for_forge(
        "b3",
        ImageRef {
            registry: "ghcr.io".into(),
            repository: "yah/forge".into(),
            tag: "v1".into(),
            digest: "sha256:abc123".into(),
        },
        TierTag("private".into()),
        vec![8080],
    );
    assert_required(
        "WorkloadSpec",
        &spec,
        &[
            "expose",
            "image",
            "name",
            "replicas",
            "resources",
            "restart_policy",
            "stop_policy",
            "tier",
        ],
    );
}

#[test]
fn tenant_passway_required_fields_are_a_deliberate_set() {
    let passway = TenantPasswayWorkload {
        domain: "a.example".into(),
        listen: "127.0.0.1:8443".into(),
        upstreams: vec!["127.0.0.1:8080".into()],
        tls: TenantPasswayTls::for_domain("a.example"),
        idle_ttl: None,
        command: None,
        env: BTreeMap::new(),
        discover: None,
    };
    // What the passway binds, for whom, and with which certificate: no absent
    // value of any of the three describes a workload an older peer could run.
    assert_required("TenantPasswayWorkload", &passway, &["domain", "listen", "tls"]);
    assert_required("TenantPasswayTls", &passway.tls, &["cert", "key"]);
}

#[test]
fn workload_entry_required_fields_are_a_deliberate_set() {
    let entry = WorkloadEntry {
        id: WorkloadId::new("forge-b3"),
        state: WorkloadState::Running,
        pid: Some(1234),
        mesh_ident: Some("forge.b3".into()),
        ports: vec![8080],
        named_ports: BTreeMap::from([("http".to_string(), 8080)]),
        spec_digest: Some([7; 32]),
    };
    assert_required("WorkloadEntry", &entry, &["id", "state"]);
}

#[test]
fn node_capabilities_required_fields_are_a_deliberate_set() {
    let caps = NodeCapabilities {
        native_exec: true,
        native_exec_dir: Some("/var/lib/kamaji/native".into()),
        microvm: MicroVmHealth {
            attached: true,
            kvm_ok: Some(false),
            detail: Some("permission denied".into()),
        },
        log_stream: true,
    };
    // A capability nobody reported must not read as one somebody did — see
    // NodeCapabilities' doc. These two stay loud.
    assert_required("NodeCapabilities", &caps, &["microvm", "native_exec"]);
    assert_required("MicroVmHealth", &caps.microvm, &["attached"]);
}

#[test]
fn mesh_assignment_required_fields_are_a_deliberate_set() {
    let peer = WireguardPeer {
        public_key: "pk".into(),
        endpoint: Some("10.0.0.1:51820".parse().unwrap()),
        allowed_ips: vec!["10.128.0.0".parse().unwrap()],
    };
    let mesh = MeshAssignment {
        mesh_ip: "10.128.0.7".parse().unwrap(),
        wg_private_key: "sk".into(),
        wg_listen_port: 51820,
        peers: vec![peer.clone()],
    };
    assert_required("MeshAssignment", &mesh, &["mesh_ip"]);
    assert_required("WireguardPeer", &peer, &["public_key"]);
}

#[test]
fn log_record_required_fields_are_a_deliberate_set() {
    // R729-F2: every field of a log line is load-bearing — a record without
    // its cursor cannot be resumed past, and one without its line is not a
    // record. All four stay loud.
    let rec = kamaji_proto::LogRecord {
        stream: kamaji_proto::LogStreamTag::Stderr,
        cursor: "12:34".into(),
        ts_ms: 1,
        line: "hello".into(),
    };
    assert_required("LogRecord", &rec, &["cursor", "line", "stream", "ts_ms"]);
}

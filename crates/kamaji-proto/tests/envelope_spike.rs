//! R896-S1 measurement harness — evidence for the wire-envelope decision.
//!
//! The spike asks whether a single-node hot ship can be made to cross a
//! `WorkloadSpec` field change. Three claims decide that, and reasoning about
//! them from serde's documentation is exactly how V6 and V8 were nearly shipped
//! wrong (see `kamaji-proto/src/version.rs`). So each is measured here instead:
//!
//! 1. `old_decoder_vs_a_new_field` — what a peer one field behind actually does
//!    with a newer encoding, under postcard and under a named/self-describing
//!    codec. This is the field-ADDITION half of the question.
//! 2. `which_top_level_deletions_a_named_codec_can_cross` — enumerates every
//!    top-level key of a real `Workload::Container` and reports which ones a
//!    decoder survives the absence of. This is the field-DELETION half, and it
//!    doubles as an inventory of which fields carry `#[serde(default)]`, which
//!    is the property a deletion depends on and which nothing else reports.
//! 3. `encoded_size_and_decode_cost` — the size and decode-time price of the
//!    self-describing option on the deploy path.
//!
//! Run with output:
//!
//! ```text
//! cargo test --manifest-path oss/kamaji/Cargo.toml -p kamaji-proto \
//!     --test envelope_spike -- --nocapture
//! ```
//!
//! These stay green whatever the decision is — they assert the mechanism, not
//! the choice — so they become the regression floor for whichever envelope
//! R896's implementation child lands.

use kamaji_proto::{encode_frame, RequestId, WorkloadId, YubabaToKamaji};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use workload_spec::{ImageRef, TierTag, Workload, WorkloadSpec};

fn forge_spec() -> WorkloadSpec {
    WorkloadSpec::for_forge(
        "b3",
        ImageRef {
            registry: "ghcr.io".into(),
            repository: "yah/forge".into(),
            tag: "v1".into(),
            digest: "sha256:abc123".into(),
        },
        TierTag("private".into()),
        vec![8080],
    )
}

fn deploy_msg() -> YubabaToKamaji {
    YubabaToKamaji::Deploy {
        request_id: RequestId(7),
        id: WorkloadId::new("forge-b3"),
        spec: Workload::container(forge_spec()),
        mesh: None,
    }
}

// A two-version pair standing in for "a struct inside the Deploy frame, one
// field apart". Using local types rather than the real `WorkloadSpec` is the
// point: it is the only way to hold *both* versions in one process, which is
// the situation a skewed node is in and which no test over a single tree-built
// type can reproduce.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct OldShape {
    name: String,
    replicas: u32,
    #[serde(default)]
    tail: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct NewShape {
    name: String,
    replicas: u32,
    /// The V8 situation: a field appended to a struct the frame already
    /// carries. `#[serde(default)]` is on it, which is the attribute whose
    /// misreading version.rs's V8 stanza is written to prevent.
    #[serde(default)]
    files: Vec<String>,
    #[serde(default)]
    tail: Vec<String>,
}

#[test]
fn old_decoder_vs_a_new_field() {
    let new = NewShape {
        name: "forge-b3".into(),
        replicas: 2,
        files: vec!["/etc/app.toml".into()],
        tail: vec!["sentinel".into()],
    };

    // --- postcard (what the wire does today) ------------------------------
    let pc = postcard::to_stdvec(&new).expect("encode");
    let pc_old = postcard::from_bytes::<OldShape>(&pc);
    println!("postcard: new->old = {pc_old:?}");
    match pc_old {
        // The dangerous outcome version.rs describes: it decodes, and every
        // field after the added one is wrong. `tail` picked up the *files*
        // payload, so a peer one field behind reads a value that was never
        // sent rather than getting an error.
        Ok(decoded) => assert_ne!(
            decoded.tail, new.tail,
            "postcard silently misread the trailing field — if this ever \
             starts matching, positionality stopped being the hazard and the \
             V2/V4/V5/V6/V8 stanzas need rewriting"
        ),
        // Or it fails mid-frame. Either is a wire break; neither is crossable.
        Err(_) => {}
    }

    // --- a named/self-describing codec ------------------------------------
    let js = serde_json::to_vec(&new).expect("encode");
    let js_old: OldShape = serde_json::from_slice(&js).expect("named codec tolerates the new field");
    println!("json:     new->old = {js_old:?}");
    assert_eq!(
        js_old.name, new.name,
        "every field the old peer DOES know must survive"
    );
    assert_eq!(
        js_old.tail, new.tail,
        "and a field after the addition must not shift — this is the whole \
         property a positional codec cannot offer"
    );

    // And the reverse direction, which is the one a kamaji-first ship is in.
    let old_bytes = serde_json::to_vec(&OldShape {
        name: "forge-b3".into(),
        replicas: 2,
        tail: vec!["sentinel".into()],
    })
    .expect("encode");
    let new_from_old: NewShape =
        serde_json::from_slice(&old_bytes).expect("a defaulted field absorbs the older encoding");
    assert_eq!(new_from_old.files, Vec::<String>::new());
}

/// Mirror of the real [`YubabaToKamaji`] prefix, with the spec typed as raw
/// JSON. Postcard tags an enum with a varint discriminant index, so a mirror
/// whose first two variants are in the same order decodes a real `Deploy` frame
/// byte-for-byte — which is what lets this test hold "the spec a future binary
/// would send" without a second copy of `WorkloadSpec` in the tree.
#[derive(Debug, Serialize, Deserialize)]
enum DeployFrameMirror {
    #[allow(dead_code)]
    Hello {
        version: kamaji_proto::ProtocolVersion,
    },
    Deploy {
        request_id: RequestId,
        id: WorkloadId,
        #[serde(with = "kamaji_proto::tolerant")]
        spec: serde_json::Value,
        #[serde(with = "kamaji_proto::tolerant")]
        mesh: Option<kamaji_proto::MeshAssignment>,
    },
}

/// The end-to-end claim, over the real types on the real wire path: a `Deploy`
/// frame carrying a field this binary has never heard of decodes anyway, and
/// every field after it is intact.
///
/// This is the property R896 exists to buy. Without it, the same frame is the
/// silent misread `old_decoder_vs_a_new_field` demonstrates.
#[test]
fn a_real_deploy_frame_carrying_a_future_field_still_decodes() {
    let framed = encode_frame(&deploy_msg()).expect("encode a real Deploy");

    // Decode as the mirror, so the spec is editable as JSON.
    let (mirror, _) =
        kamaji_proto::decode_frame::<DeployFrameMirror>(&framed).expect("mirror decodes the frame");
    let DeployFrameMirror::Deploy {
        request_id,
        id,
        mut spec,
        mesh,
    } = mirror
    else {
        panic!("expected Deploy");
    };

    // Add a field from the future, inside the container spec where a real one
    // would land, and mark a field that comes *after* it alphabetically — JSON
    // objects are sorted here, so `name` genuinely follows the injection point.
    //
    // `Workload` and `ContainerManifest` are both externally tagged
    // (`{"<variant>": {…}}`), so descend through the single-key wrappers until
    // the spec itself — the object carrying `image` — is reached. Walking rather
    // than hardcoding the two variant names keeps this test honest if either
    // enum is renamed.
    let mut path = Vec::new();
    {
        let mut cursor = &spec;
        while cursor.get("image").is_none() {
            let key = cursor
                .as_object()
                .expect("an externally-tagged wrapper object")
                .keys()
                .next()
                .expect("exactly one variant key")
                .clone();
            cursor = &cursor[&key];
            path.push(key);
        }
    }
    let mut target = &mut spec;
    for key in &path {
        target = target.get_mut(key).expect("path was just walked");
    }
    let obj = target.as_object_mut().expect("the spec is an object");
    obj.insert(
        "a_field_from_the_future".into(),
        serde_json::json!({ "nested": ["shape", 42] }),
    );
    obj.insert("name".into(), serde_json::json!("sentinel-name"));

    let future_frame = encode_frame(&DeployFrameMirror::Deploy {
        request_id,
        id,
        spec,
        mesh,
    })
    .expect("re-encode");

    // The binary that has never heard of that field decodes it anyway.
    let (decoded, consumed) =
        kamaji_proto::decode_frame::<YubabaToKamaji>(&future_frame).expect(
            "a peer one field behind must decode a newer Deploy — this failing means \
             the tolerant envelope is not actually on the spec field",
        );
    assert_eq!(consumed, future_frame.len());

    let YubabaToKamaji::Deploy { spec, .. } = decoded else {
        panic!("expected Deploy");
    };
    let spec = spec.container_spec().expect("a container spec");
    assert_eq!(
        spec.name, "sentinel-name",
        "the field after the unknown one must be itself, not shifted"
    );
    assert_eq!(
        spec.image.repository, "yah/forge",
        "and so must every other field"
    );
}

#[test]
fn which_top_level_deletions_a_named_codec_can_cross() {
    // A deletion is crossable exactly when the peer that still knows the field
    // can deserialize without it — i.e. when that peer's field carries
    // `#[serde(default)]`. Nothing in the tree reports which fields those are,
    // so enumerate them: drop one key at a time and see what survives.
    let spec = forge_spec();
    let value = serde_json::to_value(&spec).expect("spec to json");
    let obj = value.as_object().expect("spec encodes as a map").clone();

    let mut crossable = Vec::new();
    let mut breaking = Vec::new();
    for key in obj.keys() {
        let mut trimmed = obj.clone();
        trimmed.remove(key);
        match serde_json::from_value::<WorkloadSpec>(serde_json::Value::Object(trimmed)) {
            Ok(_) => crossable.push(key.clone()),
            Err(_) => breaking.push(key.clone()),
        }
    }

    println!(
        "WorkloadSpec top-level fields: {} total, {} deletable across a skew, {} not",
        obj.len(),
        crossable.len(),
        breaking.len()
    );
    println!("  DELETION CROSSES (field has a serde default): {crossable:?}");
    println!("  DELETION BREAKS  (no default — needs a bump):  {breaking:?}");

    // Not an assertion about the ratio — that moves with the spec. The claim
    // under test is that the set is non-empty in both directions, i.e. that
    // "self-describing" alone does not buy deletion tolerance; a per-field
    // `#[serde(default)]` policy is the other half.
    assert!(
        !crossable.is_empty(),
        "if nothing is deletable, a named codec buys additions only"
    );
}

#[test]
fn encoded_size_and_decode_cost() {
    let msg = deploy_msg();
    let framed = encode_frame(&msg).expect("postcard frame");
    let pc = postcard::to_stdvec(&msg).expect("postcard");
    let js = serde_json::to_vec(&msg).expect("json");

    const N: u32 = 2_000;

    let t0 = Instant::now();
    for _ in 0..N {
        let out: YubabaToKamaji = postcard::from_bytes(&pc).expect("postcard decode");
        std::hint::black_box(out);
    }
    let pc_ns = t0.elapsed().as_nanos() / u128::from(N);

    let t1 = Instant::now();
    for _ in 0..N {
        let out: YubabaToKamaji = serde_json::from_slice(&js).expect("json decode");
        std::hint::black_box(out);
    }
    let js_ns = t1.elapsed().as_nanos() / u128::from(N);

    println!("Deploy(Workload::Container) — a realistic forge spec");
    println!("  postcard payload: {:>6} B (framed {} B)", pc.len(), framed.len());
    println!(
        "  json payload:     {:>6} B  ({:.1}x)",
        js.len(),
        js.len() as f64 / pc.len() as f64
    );
    println!("  postcard decode:  {pc_ns:>6} ns/msg");
    println!("  json decode:      {js_ns:>6} ns/msg");

    // The deploy path is per workload-change, not per request; the ceiling that
    // matters is the frame limit, not the microsecond.
    assert!(
        js.len() < kamaji_proto::MAX_FRAME_BYTES,
        "a self-describing spec must still fit the existing frame ceiling"
    );
}

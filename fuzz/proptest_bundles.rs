use assert_cmd::Command;
use proptest::prelude::*;
use serde_json::json;
use std::fs;
use tempfile::TempDir;

use aegx::audit;
use aegx::bundle;
use aegx::canonical::canonical_json;
use aegx::records::{
    append_record, compute_record_id, Payload, Principal, RecordType, TypedRecord,
};

fn aegx_cmd() -> Command {
    Command::cargo_bin("aegx").unwrap()
}

// --- Strategy generators for property-based testing ---

fn arb_record_type() -> impl Strategy<Value = RecordType> {
    prop_oneof![
        Just(RecordType::SessionStart),
        Just(RecordType::SessionMessage),
        Just(RecordType::ToolCall),
        Just(RecordType::ToolResult),
        Just(RecordType::FileRead),
        Just(RecordType::FileWrite),
        Just(RecordType::FileDelete),
        Just(RecordType::ControlPlaneChangeRequest),
        Just(RecordType::MemoryCommitRequest),
        Just(RecordType::GuardDecision),
        Just(RecordType::Snapshot),
        Just(RecordType::Rollback),
    ]
}

fn arb_principal() -> impl Strategy<Value = Principal> {
    prop_oneof![
        Just(Principal::USER),
        Just(Principal::SYS),
        Just(Principal::WEB),
        Just(Principal::TOOL),
        Just(Principal::SKILL),
        Just(Principal::CHANNEL),
        Just(Principal::EXTERNAL),
    ]
}

fn arb_inline_value() -> impl Strategy<Value = serde_json::Value> {
    // Generate bounded JSON values
    prop_oneof![
        Just(json!(null)),
        any::<bool>().prop_map(|b| json!(b)),
        any::<i32>().prop_map(|n| json!(n)),
        "[a-zA-Z0-9 ]{0,50}".prop_map(|s| json!(s)),
        prop::collection::vec("[a-zA-Z0-9]{0,10}".prop_map(|s| json!(s)), 0..5)
            .prop_map(|v| serde_json::Value::Array(v)),
    ]
}

// --- Bundle generation and verification tests ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn generated_bundle_passes_verify(
        num_records in 2usize..10,
        seed in any::<u64>(),
    ) {
        let tmp = TempDir::new().unwrap();
        let bundle_dir = tmp.path().join("proptest.aegx");

        // Init bundle using library
        bundle::init_bundle(&bundle_dir).unwrap();

        let records_path = bundle_dir.join("records.jsonl");
        let audit_path = bundle_dir.join("audit-log.jsonl");

        let mut record_ids: Vec<String> = Vec::new();
        let mut audit_head = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        for i in 0..num_records {
            let rt = if i == 0 {
                RecordType::SessionStart
            } else {
                RecordType::SessionMessage
            };
            let pr = Principal::SYS;
            let ts = format!("2026-02-15T00:00:{:02}Z", i.min(59));
            let meta = json!({"ts": ts});

            let parents: Vec<String> = if i == 0 {
                vec![]
            } else {
                vec![record_ids[i - 1].clone()]
            };

            let payload = Payload::Inline {
                inline: json!({"idx": i, "seed": seed}),
            };
            let taint: Vec<String> = vec![];

            let record_id = compute_record_id(&rt, &pr, &taint, &parents, &meta, &payload);

            let record = TypedRecord {
                record_id: record_id.clone(),
                record_type: rt,
                principal: pr,
                taint,
                parents,
                meta: meta.clone(),
                payload,
                schema: Some("0.1".to_string()),
                extensions: None,
            };

            append_record(&records_path, &record).unwrap();

            let audit_entry = audit::new_audit_entry(i as u64, &ts, &record_id, &audit_head);
            audit::append_audit_entry(&audit_path, &audit_entry).unwrap();
            audit_head = audit_entry.entry_hash.clone();

            record_ids.push(record_id);
        }

        // Update manifest
        let root_records: Vec<String> = vec![record_ids[0].clone()];
        bundle::update_manifest(
            &bundle_dir,
            num_records as u64,
            0,
            &audit_head,
            &root_records,
        )
        .unwrap();

        // Verify via subprocess - must pass
        aegx_cmd()
            .args(["verify", bundle_dir.to_str().unwrap()])
            .assert()
            .success();

        // Tamper: modify the inline payload in the first record's JSON line.
        // Read the file as text, parse the first line, change the payload, write back.
        let records_text = fs::read_to_string(&records_path).unwrap();
        let lines: Vec<&str> = records_text.lines().collect();
        if !lines.is_empty() {
            let mut first_record: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
            // Tamper the inline payload but keep the recordId unchanged
            if let Some(payload) = first_record.get_mut("payload") {
                if let Some(inline) = payload.get_mut("inline") {
                    *inline = json!({"tampered": true, "seed": seed});
                }
            }
            let mut new_lines = vec![serde_json::to_string(&first_record).unwrap()];
            for line in &lines[1..] {
                new_lines.push(line.to_string());
            }
            fs::write(&records_path, new_lines.join("\n") + "\n").unwrap();

            // Verify should now fail with recordId mismatch
            let output = aegx_cmd()
                .args(["verify", bundle_dir.to_str().unwrap()])
                .output()
                .unwrap();
            prop_assert!(
                !output.status.success(),
                "Tampered bundle should fail verification"
            );
        }
    }
}

// --- Record ID and canonicalization tests ---

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn record_id_is_deterministic(
        rt in arb_record_type(),
        pr in arb_principal(),
        payload_data in arb_inline_value(),
    ) {
        let meta = json!({"ts": "2026-02-15T00:00:00Z"});
        let taint: Vec<String> = vec![];
        let parents: Vec<String> = vec![];
        let payload = Payload::Inline { inline: payload_data };

        let id1 = compute_record_id(&rt, &pr, &taint, &parents, &meta, &payload);
        let id2 = compute_record_id(&rt, &pr, &taint, &parents, &meta, &payload);

        prop_assert_eq!(&id1, &id2, "recordId must be deterministic");
        prop_assert_eq!(id1.len(), 64, "recordId must be 64 hex chars");
    }

    #[test]
    fn canonical_json_is_deterministic(
        payload_data in arb_inline_value(),
    ) {
        let val = json!({
            "type": "SessionStart",
            "principal": "SYS",
            "taint": [],
            "parents": [],
            "meta": {"ts": "2026-02-15T00:00:00Z"},
            "payload": {"inline": payload_data},
            "schema": "0.1"
        });

        let bytes1 = canonical_json(&val);
        let bytes2 = canonical_json(&val);
        prop_assert_eq!(&bytes1, &bytes2, "canonical JSON must be deterministic");

        // Must be valid UTF-8
        let s = String::from_utf8(bytes1.clone());
        prop_assert!(s.is_ok(), "canonical JSON must be valid UTF-8");

        // Must be valid JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&bytes1);
        prop_assert!(parsed.is_ok(), "canonical JSON must be parseable");
    }

    #[test]
    fn different_payloads_produce_different_ids(
        a in "[a-zA-Z]{1,20}",
        b in "[a-zA-Z]{1,20}",
    ) {
        prop_assume!(a != b);

        let meta = json!({"ts": "2026-02-15T00:00:00Z"});
        let taint: Vec<String> = vec![];
        let parents: Vec<String> = vec![];

        let id_a = compute_record_id(
            &RecordType::SessionStart,
            &Principal::SYS,
            &taint,
            &parents,
            &meta,
            &Payload::Inline { inline: json!(a) },
        );
        let id_b = compute_record_id(
            &RecordType::SessionStart,
            &Principal::SYS,
            &taint,
            &parents,
            &meta,
            &Payload::Inline { inline: json!(b) },
        );

        prop_assert_ne!(id_a, id_b, "Different payloads must produce different IDs");
    }
}

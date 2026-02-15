use assert_cmd::Command;
use proptest::prelude::*;
use serde_json::json;
use std::fs;
use tempfile::TempDir;

use aegx::audit;
use aegx::bundle;
use aegx::records::{
    append_record, compute_record_id, Payload, Principal, RecordType, TypedRecord,
};

fn aegx_cmd() -> Command {
    Command::cargo_bin("aegx").unwrap()
}

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

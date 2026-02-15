use proptest::prelude::*;
use serde_json::json;

use aegx::canonical::canonical_json;
use aegx::records::{compute_record_id, Payload, Principal, RecordType};

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

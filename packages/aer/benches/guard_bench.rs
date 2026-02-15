//! Criterion benchmarks for the Provenable.ai guard pipeline.
//!
//! Measures guard evaluation latency, policy evaluation throughput,
//! record emission rate, and audit chain append performance.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;

use aer::canonical::{canonicalize, compute_entry_hash, compute_record_id, sha256_hex};
use aer::metrics;
use aer::policy::{self, default_policy};
use aer::types::*;

/// Benchmark: policy evaluation (the core guard decision path).
fn bench_policy_evaluate(c: &mut Criterion) {
    let policy = default_policy();

    c.bench_function("policy_evaluate_cpi_deny", |b| {
        b.iter(|| {
            policy::evaluate(
                black_box(&policy),
                black_box(GuardSurface::ControlPlane),
                black_box(Principal::Web),
                black_box(TaintFlags::UNTRUSTED),
                black_box(false),
            )
        })
    });

    c.bench_function("policy_evaluate_cpi_allow", |b| {
        b.iter(|| {
            policy::evaluate(
                black_box(&policy),
                black_box(GuardSurface::ControlPlane),
                black_box(Principal::User),
                black_box(TaintFlags::empty()),
                black_box(false),
            )
        })
    });

    c.bench_function("policy_evaluate_mi_deny_tainted", |b| {
        b.iter(|| {
            policy::evaluate(
                black_box(&policy),
                black_box(GuardSurface::DurableMemory),
                black_box(Principal::ToolAuth),
                black_box(TaintFlags::WEB_DERIVED),
                black_box(false),
            )
        })
    });

    c.bench_function("policy_evaluate_mi_allow", |b| {
        b.iter(|| {
            policy::evaluate(
                black_box(&policy),
                black_box(GuardSurface::DurableMemory),
                black_box(Principal::User),
                black_box(TaintFlags::empty()),
                black_box(false),
            )
        })
    });
}

/// Benchmark: SHA-256 hashing at various sizes.
fn bench_sha256(c: &mut Criterion) {
    let small = vec![0u8; 64];
    let medium = vec![0u8; 4096];
    let large = vec![0u8; 65536];

    c.bench_function("sha256_64_bytes", |b| {
        b.iter(|| sha256_hex(black_box(&small)))
    });

    c.bench_function("sha256_4096_bytes", |b| {
        b.iter(|| sha256_hex(black_box(&medium)))
    });

    c.bench_function("sha256_65536_bytes", |b| {
        b.iter(|| sha256_hex(black_box(&large)))
    });
}

/// Benchmark: JSON canonicalization.
fn bench_canonicalize(c: &mut Criterion) {
    let small_payload = serde_json::json!({"key": "value"});
    let medium_payload = serde_json::json!({
        "tool_id": "read_file",
        "arguments": {"path": "/tmp/test.txt", "encoding": "utf-8"},
        "result": {"content": "Hello, world!", "size": 13},
        "metadata": {"elapsed_ms": 42, "cache_hit": false}
    });
    let nested_payload = serde_json::json!({
        "guard_decision": {
            "verdict": "Deny",
            "rule_id": "cpi-deny-untrusted",
            "rationale": "Block CPI changes from non-USER/SYS",
            "surface": "ControlPlane",
            "principal": "WEB",
            "taint": 129
        },
        "change_request": {
            "config_key": "skills.install",
            "value": {"name": "malicious-skill", "url": "http://evil.com/skill.js"}
        }
    });

    c.bench_function("canonicalize_small", |b| {
        b.iter(|| canonicalize(black_box(&small_payload)))
    });

    c.bench_function("canonicalize_medium", |b| {
        b.iter(|| canonicalize(black_box(&medium_payload)))
    });

    c.bench_function("canonicalize_nested", |b| {
        b.iter(|| canonicalize(black_box(&nested_payload)))
    });
}

/// Benchmark: record ID computation (canonicalize + SHA-256).
fn bench_record_id(c: &mut Criterion) {
    let payload = serde_json::json!({
        "guard_decision": {
            "verdict": "Deny",
            "rule_id": "cpi-deny-untrusted",
            "rationale": "Block CPI changes",
            "surface": "ControlPlane",
            "principal": "WEB",
            "taint": 1
        }
    });
    let meta = serde_json::json!({
        "ts": "2026-02-15T10:00:00Z",
        "agent_id": "test-agent",
        "config_key": "skills.install"
    });

    c.bench_function("compute_record_id", |b| {
        b.iter(|| compute_record_id(black_box(&payload), black_box(&meta)))
    });
}

/// Benchmark: audit entry hash computation.
fn bench_entry_hash(c: &mut Criterion) {
    let record_id = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2a3b4c5d6a7b8c9d0e1f2";
    let prev_hash = "f1e2d3c4b5a6978869504132abcdef1234567890abcdef1234567890abcdef12";

    c.bench_function("compute_entry_hash", |b| {
        b.iter(|| {
            compute_entry_hash(
                black_box(42),
                black_box("2026-02-15T10:00:00Z"),
                black_box(record_id),
                black_box(prev_hash),
            )
        })
    });
}

/// Benchmark: taint propagation.
fn bench_taint_propagation(c: &mut Criterion) {
    let parents_2 = vec![TaintFlags::UNTRUSTED, TaintFlags::WEB_DERIVED];
    let parents_10 = vec![
        TaintFlags::UNTRUSTED,
        TaintFlags::WEB_DERIVED,
        TaintFlags::INJECTION_SUSPECT,
        TaintFlags::SECRET_RISK,
        TaintFlags::CROSS_SESSION,
        TaintFlags::TOOL_OUTPUT,
        TaintFlags::SKILL_OUTPUT,
        TaintFlags::PROXY_DERIVED,
        TaintFlags::UNTRUSTED | TaintFlags::WEB_DERIVED,
        TaintFlags::empty(),
    ];

    c.bench_function("taint_propagate_2_parents", |b| {
        b.iter(|| TaintFlags::propagate(black_box(&parents_2)))
    });

    c.bench_function("taint_propagate_10_parents", |b| {
        b.iter(|| TaintFlags::propagate(black_box(&parents_10)))
    });
}

/// Benchmark: metrics recording overhead.
fn bench_metrics_recording(c: &mut Criterion) {
    metrics::reset_metrics();

    c.bench_function("metrics_record_evaluation", |b| {
        b.iter(|| {
            metrics::record_evaluation(
                black_box(GuardSurface::ControlPlane),
                black_box(GuardVerdict::Deny),
                black_box(Duration::from_micros(50)),
            )
        })
    });

    c.bench_function("metrics_get_snapshot", |b| {
        b.iter(|| metrics::get_metrics())
    });
}

/// Benchmark: full guard decision pipeline (policy eval + hash + serialize).
fn bench_full_guard_pipeline(c: &mut Criterion) {
    let policy = default_policy();

    c.bench_function("full_guard_pipeline_deny", |b| {
        b.iter(|| {
            // Policy evaluation
            let (verdict, rule_id, rationale) = policy::evaluate(
                &policy,
                GuardSurface::ControlPlane,
                Principal::Web,
                TaintFlags::UNTRUSTED,
                false,
            );

            // Build detail struct
            let detail = GuardDecisionDetail {
                verdict,
                rule_id: rule_id.clone(),
                rationale,
                surface: GuardSurface::ControlPlane,
                principal: Principal::Web,
                taint: TaintFlags::UNTRUSTED,
            };

            // Serialize payload
            let payload = serde_json::to_value(&detail).unwrap();
            let meta = serde_json::json!({"ts": "2026-02-15T10:00:00Z", "rule_id": rule_id});

            // Compute record ID
            let _record_id = compute_record_id(&payload, &meta);

            black_box(verdict)
        })
    });
}

criterion_group!(
    benches,
    bench_policy_evaluate,
    bench_sha256,
    bench_canonicalize,
    bench_record_id,
    bench_entry_hash,
    bench_taint_propagation,
    bench_metrics_recording,
    bench_full_guard_pipeline,
);
criterion_main!(benches);

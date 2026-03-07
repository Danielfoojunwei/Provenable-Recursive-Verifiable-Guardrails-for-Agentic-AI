//! `aegx-guard` — Policy engine, scanner, and guard surfaces for AEGX.
//!
//! Provides the three guard surfaces grounded in formal theorems:
//! - **Control Plane** (CPI Theorem): prevents untrusted mutations to config/policy
//! - **Durable Memory** (MI Theorem): prevents tainted/untrusted memory writes
//! - **Conversation I/O** (Noninterference): input scanning + output leakage detection
//!
//! Also includes:
//! - 8-category prompt injection/extraction scanner
//! - System prompt leakage detection (output guard)
//! - Sensitive file read guard
//! - Network egress guard
//! - Skill pre-install verification (ClawHavoc attack taxonomy)
//! - Threat alerts and agent notifications
//! - Guard performance metrics

pub mod alerts;
pub mod file_read_guard;
pub mod guard;
pub mod metrics;
pub mod network_guard;
pub mod output_guard;
pub mod policy;
pub mod scanner;
pub mod skill_verifier;

pub use guard::{
    gate_control_plane_change, gate_memory_write, Guard,
    correlated_taint_for_principal, correlated_taint_for_session,
    cross_surface_denial_count, reset_correlation_state,
    signal_cpi_denial, signal_injection_detected,
};
pub use metrics::{get_metrics, record_evaluation, reset_metrics, EvalTimer, GuardMetrics};
pub use policy::{default_policy, evaluate, load_policy, save_policy};

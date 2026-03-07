//! `aegx-bundle` — Bundle packaging, verification, and reporting for AEGX.
//!
//! Merges aegx's `bundle.rs`/`verify.rs` (security-hardened zip, schema validation,
//! 10-step verification) with aer's `bundle.rs`/`verify.rs`/`report.rs`
//! (live export, extraction, markdown/JSON reports).

pub mod bundle;
pub mod report;
pub mod verify;

pub use bundle::{export_bundle, extract_bundle};
pub use verify::{verify_bundle, verify_live};

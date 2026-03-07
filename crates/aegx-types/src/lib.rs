//! `aegx-types` — Unified types and canonical hashing for the Provenable AEGX system.
//!
//! This crate provides the foundational types and cryptographic primitives shared
//! across all AEGX components. It merges and unifies types from both the original
//! `aegx` crate (bundle format) and the `aer` crate (runtime guard), resolving
//! all incompatibilities into a single coherent type system.
//!
//! # Formal Grounding
//!
//! All types in this crate are grounded in the four formal theorems:
//! - **CPI (Control-Plane Integrity)**: Principal trust lattice, GuardSurface
//! - **MI (Memory Integrity)**: TaintFlags, GuardVerdict
//! - **Noninterference**: Taint propagation rules
//! - **RVU (Recursive Verifiable Unlearning)**: SnapshotManifest, VerificationResult

pub mod canonical;
pub mod error;

mod principal;
mod record;
mod taint;

pub use principal::Principal;
pub use record::*;
pub use taint::TaintFlags;

// Re-export canonical functions at crate root for convenience
pub use canonical::{
    canonical_json, compute_entry_hash, compute_record_id, nfc_normalize, normalize_meta,
    normalize_timestamp, sha256_bytes, sha256_file, sha256_hex,
};

//! `aegx-records` — Record I/O, audit chain, and configuration for AEGX.
//!
//! This crate provides:
//! - Record creation with automatic ID computation and blob promotion
//! - JSONL append/read for records and audit entries
//! - Hash-linked audit chain with verification
//! - State directory configuration and path resolution
//!
//! Merges functionality from aegx's `records.rs`/`audit.rs` and aer's
//! `records.rs`/`audit_chain.rs`/`config.rs`.

pub mod audit_chain;
pub mod config;
pub mod records;

pub use audit_chain::{ChainError, verify_entries};
pub use config::{ensure_aer_dirs, resolve_state_dir, MEMORY_FILES};
pub use records::{append_record, create_record, emit_record, read_all_records, read_filtered_records};

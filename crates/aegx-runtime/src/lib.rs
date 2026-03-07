//! `aegx-runtime` — Runtime: snapshots, rollback, hooks, and integration for AEGX.
//!
//! Provides the runtime integration layer:
//! - Snapshot creation and management (RVU Theorem)
//! - Rollback policy with auto-snapshot and contamination scope
//! - Integration hooks for tool calls, file I/O, messages
//! - Workspace memory management (MI chokepoint)
//! - /prove query engine
//! - Sandbox environment auditing

pub mod hooks;
pub mod prove;
pub mod rollback_policy;
pub mod sandbox_audit;
pub mod snapshot;
pub mod workspace;

pub use snapshot::{create_snapshot, diff_snapshot, list_snapshots, load_snapshot};
pub use workspace::{ensure_workspace, read_memory_file, write_memory_file};

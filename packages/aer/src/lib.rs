pub mod alerts;
pub mod audit_chain;
pub mod bundle;
pub mod canonical;
pub mod cli;
pub mod config;
pub mod file_read_guard;
pub mod guard;
pub mod hooks;
pub mod network_guard;
pub mod output_guard;
pub mod policy;
pub mod prove;
pub mod records;
pub mod report;
pub mod rollback_policy;
pub mod sandbox_audit;
pub mod scanner;
pub mod skill_verifier;
pub mod snapshot;
pub mod types;
pub mod verify;
pub mod workspace;

// Re-exports for modules consolidated during file reduction.
// rollback functions merged into rollback_policy.
pub mod rollback {
    pub use crate::rollback_policy::*;
}

// metrics functions merged into prove.
pub mod metrics {
    pub use crate::prove::{get_metrics, record_evaluation, reset_metrics, GuardMetrics};
}

// system_prompt_registry functions merged into output_guard.
pub mod system_prompt_registry {
    pub use crate::output_guard::{
        clear_registry as clear, dynamic_token_count, get_cached_config, prompt_hash,
        register_system_prompt, register_tokens_only,
    };
}

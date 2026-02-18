//! System prompt registry for dynamic output guard token discovery.
//!
//! # Problem
//!
//! The output guard's `config_with_runtime_discovery()` can extract protected
//! tokens from a system prompt, but the system prompt content isn't available
//! to AER at runtime — OpenClaw doesn't expose it via the plugin API.
//!
//! # Solution
//!
//! This module provides a thread-safe registry that caches the system prompt's
//! extracted tokens. When a host platform (OpenClaw or otherwise) makes the
//! system prompt available — either the full text or individual tokens — the
//! registry stores the resulting `OutputGuardConfig`. The output guard
//! automatically uses this cached config when no explicit config is passed.
//!
//! # Formal Grounding
//!
//! This implements the **MI Dynamic Discovery Corollary**: the system prompt
//! is a protected memory artifact, and ALL internal identifiers within it
//! are protected. Dynamic discovery adapts the output guard to the actual
//! deployed prompt, not just the static ZeroLeaks watchlist.
//!
//! # Integration Pattern
//!
//! ```ignore
//! // Option 1: Host passes full system prompt (preferred)
//! aer::hooks::on_system_prompt_available("agent-1", "sess-1", &system_prompt)?;
//!
//! // Option 2: Host passes individual tokens (when full prompt unavailable)
//! aer::system_prompt_registry::register_tokens_only(vec![
//!     "CUSTOM_TOKEN".into(), "buildMySection".into(),
//! ]);
//!
//! // After registration, on_message_output() automatically uses dynamic tokens
//! aer::hooks::on_message_output("agent-1", "sess-1", &response, None, vec![])?;
//! ```

use crate::output_guard::{
    self, LeakCategory, OutputGuardConfig, WatchlistEntry,
};
use chrono::{DateTime, Utc};
use std::sync::Mutex;

/// Cached system prompt configuration.
#[derive(Debug, Clone)]
struct CachedPromptConfig {
    /// The merged output guard config (static watchlist + dynamic tokens).
    config: OutputGuardConfig,
    /// SHA-256 of the registered system prompt (for audit correlation).
    /// `None` if registered via `register_tokens_only()`.
    prompt_hash: Option<String>,
    /// When the config was registered.
    registered_at: DateTime<Utc>,
    /// Number of dynamically discovered tokens.
    dynamic_token_count: usize,
}

/// Global registry — thread-safe singleton.
static REGISTRY: Mutex<Option<CachedPromptConfig>> = Mutex::new(None);

/// Register a full system prompt for dynamic token extraction.
///
/// Extracts SCREAMING_CASE, camelCase, and template variable tokens from the
/// prompt, merges them with the static ZeroLeaks watchlist, and caches the
/// result for automatic use by the output guard.
///
/// Returns the number of dynamically discovered tokens.
pub fn register_system_prompt(system_prompt: &str) -> usize {
    let config = output_guard::config_with_runtime_discovery(system_prompt);
    let static_count = output_guard::default_config().watchlist_exact.len();
    let dynamic_count = config.watchlist_exact.len().saturating_sub(static_count);
    let prompt_hash = crate::canonical::sha256_hex(system_prompt.as_bytes());

    let cached = CachedPromptConfig {
        config,
        prompt_hash: Some(prompt_hash),
        registered_at: Utc::now(),
        dynamic_token_count: dynamic_count,
    };

    let mut lock = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    *lock = Some(cached);
    dynamic_count
}

/// Register individual tokens without the full system prompt.
///
/// Use this when the host platform can expose specific internal tokens
/// but not the complete system prompt text. Tokens are added to the
/// static ZeroLeaks watchlist.
///
/// Returns the total number of tokens added.
pub fn register_tokens_only(tokens: Vec<String>) -> usize {
    let mut config = output_guard::default_config();
    let added = tokens.len();

    for token in tokens {
        // Skip tokens already in the static watchlist
        if config.watchlist_exact.iter().any(|e| e.token == token) {
            continue;
        }

        let category = if token.starts_with("${") {
            LeakCategory::TemplateVariable
        } else if token.chars().next().is_some_and(|c| c.is_uppercase())
            && token.contains('_')
        {
            LeakCategory::InternalToken
        } else {
            LeakCategory::InternalFunction
        };

        config.watchlist_exact.push(WatchlistEntry {
            token: token.clone(),
            category,
            description: format!("Manually registered token: {}", token),
        });
    }

    let cached = CachedPromptConfig {
        config,
        prompt_hash: None,
        registered_at: Utc::now(),
        dynamic_token_count: added,
    };

    let mut lock = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    *lock = Some(cached);
    added
}

/// Get the cached output guard config, if any has been registered.
///
/// Called by `guard.rs::check_conversation_output()` when no explicit
/// config is provided by the caller.
pub fn get_cached_config() -> Option<OutputGuardConfig> {
    let lock = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    lock.as_ref().map(|c| c.config.clone())
}

/// Get the SHA-256 hash of the registered system prompt (for audit).
pub fn prompt_hash() -> Option<String> {
    let lock = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    lock.as_ref().and_then(|c| c.prompt_hash.clone())
}

/// Get the number of dynamically discovered tokens.
pub fn dynamic_token_count() -> usize {
    let lock = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    lock.as_ref().map_or(0, |c| c.dynamic_token_count)
}

/// Get the registration timestamp.
pub fn registered_at() -> Option<DateTime<Utc>> {
    let lock = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    lock.as_ref().map(|c| c.registered_at)
}

/// Clear the registry (for testing or session reset).
pub fn clear() {
    let mut lock = REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    *lock = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize tests that share the global REGISTRY singleton.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_register_system_prompt() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let prompt = "Use CUSTOM_SECRET_TOKEN for auth. Call buildPromptSection() to construct.";
        let count = register_system_prompt(prompt);
        assert!(count > 0, "Should discover dynamic tokens");
        assert!(get_cached_config().is_some());
        assert!(prompt_hash().is_some());
    }

    #[test]
    fn test_register_tokens_only() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let count = register_tokens_only(vec![
            "MY_CUSTOM_TOKEN".into(),
            "buildCustomSection".into(),
        ]);
        assert_eq!(count, 2);
        let config = get_cached_config().unwrap();
        assert!(config.watchlist_exact.iter().any(|e| e.token == "MY_CUSTOM_TOKEN"));
        assert!(config.watchlist_exact.iter().any(|e| e.token == "buildCustomSection"));
        assert!(prompt_hash().is_none(), "No prompt hash for token-only registration");
    }

    #[test]
    fn test_dynamic_tokens_catch_leakage() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let prompt = "Internal: AGENT_BOOTSTRAP_KEY is critical. Use initAgentSession() to start.";
        register_system_prompt(prompt);

        let config = get_cached_config().unwrap();
        let result = output_guard::scan_output(
            "The system uses AGENT_BOOTSTRAP_KEY for initialization.",
            Some(&config),
        );
        assert!(!result.safe, "Should catch dynamically discovered token");
        assert!(result.leaked_tokens.iter().any(|t| t.token == "AGENT_BOOTSTRAP_KEY"));
    }

    #[test]
    fn test_clean_output_remains_clean() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        let prompt = "Internal: SOME_TOKEN exists. Call buildPrompt().";
        register_system_prompt(prompt);

        let config = get_cached_config().unwrap();
        let result = output_guard::scan_output(
            "Here is the code you asked for:\n```rust\nfn main() {}\n```",
            Some(&config),
        );
        assert!(result.safe, "Clean output should remain clean");
    }

    #[test]
    fn test_re_registration_replaces_config() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear();
        register_system_prompt("Use TOKEN_ALPHA for auth.");
        let hash1 = prompt_hash().unwrap();

        register_system_prompt("Use TOKEN_BETA for auth.");
        let hash2 = prompt_hash().unwrap();

        assert_ne!(hash1, hash2, "Re-registration should update the hash");
        let config = get_cached_config().unwrap();
        assert!(config.watchlist_exact.iter().any(|e| e.token == "TOKEN_BETA"));
    }

    #[test]
    fn test_clear_resets_registry() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        register_system_prompt("Use SECRET_THING for auth.");
        assert!(get_cached_config().is_some());
        clear();
        assert!(get_cached_config().is_none());
        assert!(prompt_hash().is_none());
        assert_eq!(dynamic_token_count(), 0);
    }
}

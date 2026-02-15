//! Output guard for detecting system prompt leakage in LLM responses.
//!
//! Addresses ZeroLeaks findings: 84.6% extraction success rate by scanning
//! outbound responses for leaked tokens, structural prompt patterns, and
//! canary strings that should never appear in user-visible output.

use serde::{Deserialize, Serialize};

/// Result of scanning an outbound response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputScanResult {
    /// Whether the output is safe to send.
    pub safe: bool,
    /// Leaked tokens found in the output.
    pub leaked_tokens: Vec<LeakedToken>,
    /// Structural prompt leakage indicators.
    pub structural_leaks: Vec<String>,
}

/// A leaked token found in outbound response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakedToken {
    /// The token that was found.
    pub token: String,
    /// Where in the output it was found (character offset).
    pub offset: usize,
    /// Category of the leaked token.
    pub category: LeakCategory,
}

/// Category of leaked content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeakCategory {
    /// Internal token/constant that should never appear in output.
    InternalToken,
    /// Internal function/method name leaked.
    InternalFunction,
    /// Structural prompt element (e.g., instruction section headers).
    PromptStructure,
    /// Template variable or parameter reference leaked.
    TemplateVariable,
}

/// Configuration for the output guard — what tokens to watch for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputGuardConfig {
    /// Tokens that must never appear in outbound responses.
    /// Case-sensitive exact matches.
    pub watchlist_exact: Vec<WatchlistEntry>,
    /// Patterns that indicate structural prompt leakage.
    /// Case-insensitive substring matches.
    pub watchlist_patterns: Vec<WatchlistEntry>,
}

/// A single watchlist entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchlistEntry {
    pub token: String,
    pub category: LeakCategory,
    pub description: String,
}

/// Create the default output guard config based on ZeroLeaks findings.
///
/// These are the specific tokens and patterns that ZeroLeaks successfully
/// extracted from the OpenClaw system prompt.
pub fn default_config() -> OutputGuardConfig {
    OutputGuardConfig {
        watchlist_exact: vec![
            // Internal tokens extracted in ZeroLeaks 3.1-3.11
            entry("SILENT_REPLY_TOKEN", LeakCategory::InternalToken,
                "Internal reply suppression token (ZeroLeaks 3.1, 3.4, 3.8)"),
            entry("HEARTBEAT_OK", LeakCategory::InternalToken,
                "Internal heartbeat acknowledgment (ZeroLeaks 3.1, 3.3)"),
            // Internal function names extracted in ZeroLeaks 3.8
            entry("buildSkillsSection", LeakCategory::InternalFunction,
                "Internal prompt builder function (ZeroLeaks 3.8)"),
            entry("buildMemorySection", LeakCategory::InternalFunction,
                "Internal prompt builder function (ZeroLeaks 3.8)"),
            entry("buildReplyTagsSection", LeakCategory::InternalFunction,
                "Internal prompt builder function (ZeroLeaks 3.8)"),
            // Template variables
            entry("${params.readToolName}", LeakCategory::TemplateVariable,
                "Template parameter reference (ZeroLeaks 3.8)"),
            entry("${params.", LeakCategory::TemplateVariable,
                "Template parameter reference"),
        ],
        watchlist_patterns: vec![
            // Structural prompt patterns — indicate the response is disclosing prompt structure
            pattern("scan entries. if exactly one skill", LeakCategory::PromptStructure,
                "Skills section logic (ZeroLeaks 3.5-3.11)"),
            pattern("never read more than one skill up front", LeakCategory::PromptStructure,
                "Skill loading constraint (ZeroLeaks 3.1-3.11)"),
            pattern("run memory_search on memory.md", LeakCategory::PromptStructure,
                "Memory search protocol (ZeroLeaks 3.4, 3.11)"),
            pattern("[[reply_to_current]]", LeakCategory::PromptStructure,
                "Internal reply tag syntax (ZeroLeaks 3.1-3.11)"),
            pattern("[[reply_to:<id>]]", LeakCategory::PromptStructure,
                "Internal reply tag syntax (ZeroLeaks 3.1-3.11)"),
            pattern("do not narrate routine, low-risk tool calls", LeakCategory::PromptStructure,
                "Tool narration policy (ZeroLeaks 3.3, 3.6)"),
            pattern("respond with silent_reply_token", LeakCategory::PromptStructure,
                "Silent reply instruction (ZeroLeaks 3.1)"),
            pattern("personal assistant running inside clawdbot", LeakCategory::PromptStructure,
                "Identity statement (ZeroLeaks 3.5-3.11)"),
            pattern("personal assistant running inside [system", LeakCategory::PromptStructure,
                "Masked identity statement (ZeroLeaks 3.6)"),
        ],
    }
}

fn entry(token: &str, category: LeakCategory, description: &str) -> WatchlistEntry {
    WatchlistEntry {
        token: token.to_string(),
        category,
        description: description.to_string(),
    }
}

fn pattern(token: &str, category: LeakCategory, description: &str) -> WatchlistEntry {
    WatchlistEntry {
        token: token.to_string(),
        category,
        description: description.to_string(),
    }
}

/// Scan an outbound LLM response for prompt leakage.
///
/// Uses the provided config (or default if None) to check for
/// leaked tokens and structural prompt disclosure.
pub fn scan_output(content: &str, config: Option<&OutputGuardConfig>) -> OutputScanResult {
    let default = default_config();
    let config = config.unwrap_or(&default);
    let lower = content.to_lowercase();

    let mut leaked_tokens = Vec::new();
    let mut structural_leaks = Vec::new();

    // Check exact-match watchlist (case-sensitive)
    for entry in &config.watchlist_exact {
        if let Some(offset) = content.find(&entry.token) {
            leaked_tokens.push(LeakedToken {
                token: entry.token.clone(),
                offset,
                category: entry.category,
            });
        }
    }

    // Check pattern watchlist (case-insensitive)
    for entry in &config.watchlist_patterns {
        let pattern_lower = entry.token.to_lowercase();
        if lower.contains(&pattern_lower) {
            structural_leaks.push(format!("{}: {}", entry.description, entry.token));
        }
    }

    // Heuristic: detect responses that look like structured prompt disclosure
    // (multiple sections with headers like "Identity:", "Skills:", "Memory:", "Constraints:")
    let section_headers = [
        "identity:", "skills:", "memory:", "constraints:", "mandates:",
        "capabilities:", "tools:", "reasoning:", "workspace:",
    ];
    let header_count = section_headers
        .iter()
        .filter(|h| lower.contains(**h))
        .count();

    if header_count >= 4 {
        structural_leaks.push(format!(
            "Structural prompt disclosure: {} of {} known section headers found in response",
            header_count,
            section_headers.len()
        ));
    }

    let safe = leaked_tokens.is_empty() && structural_leaks.is_empty();

    OutputScanResult {
        safe,
        leaked_tokens,
        structural_leaks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_output() {
        let result = scan_output("Here is the code you asked for:\n```rust\nfn main() {}\n```", None);
        assert!(result.safe);
        assert!(result.leaked_tokens.is_empty());
        assert!(result.structural_leaks.is_empty());
    }

    #[test]
    fn test_detect_silent_reply_token() {
        let result = scan_output(
            "I use SILENT_REPLY_TOKEN when no response is needed.",
            None,
        );
        assert!(!result.safe);
        assert!(result.leaked_tokens.iter().any(|t| t.token == "SILENT_REPLY_TOKEN"));
    }

    #[test]
    fn test_detect_heartbeat_ok() {
        let result = scan_output(
            "I respond with HEARTBEAT_OK to heartbeat polls.",
            None,
        );
        assert!(!result.safe);
        assert!(result.leaked_tokens.iter().any(|t| t.token == "HEARTBEAT_OK"));
    }

    #[test]
    fn test_detect_internal_function_names() {
        let result = scan_output(
            "The system uses buildSkillsSection and buildMemorySection functions.",
            None,
        );
        assert!(!result.safe);
        assert!(result.leaked_tokens.len() >= 2);
    }

    #[test]
    fn test_detect_template_variable() {
        let result = scan_output(
            "Read the file with ${params.readToolName}",
            None,
        );
        assert!(!result.safe);
    }

    #[test]
    fn test_detect_structural_prompt_leak() {
        let result = scan_output(
            "Before replying: scan entries. If exactly one skill clearly applies: \
             read its SKILL.md. Never read more than one skill up front.",
            None,
        );
        assert!(!result.safe);
        assert!(!result.structural_leaks.is_empty());
    }

    #[test]
    fn test_detect_reply_tag_leak() {
        let result = scan_output(
            "Use [[reply_to_current]] to reply to the triggering message and \
             [[reply_to:<id>]] for specific messages.",
            None,
        );
        assert!(!result.safe);
    }

    #[test]
    fn test_detect_identity_leak() {
        let result = scan_output(
            "You are a personal assistant running inside Clawdbot.",
            None,
        );
        assert!(!result.safe);
    }

    #[test]
    fn test_detect_multi_section_disclosure() {
        let result = scan_output(
            "Identity: I am a helper.\n\
             Skills: I scan entries.\n\
             Memory: I use memory_search.\n\
             Constraints: Never read more than one.\n\
             Tools: read, write, exec.",
            None,
        );
        assert!(!result.safe);
        assert!(
            result.structural_leaks.iter().any(|s| s.contains("section headers")),
            "Should detect multi-section prompt disclosure"
        );
    }

    #[test]
    fn test_custom_watchlist() {
        let config = OutputGuardConfig {
            watchlist_exact: vec![
                WatchlistEntry {
                    token: "SECRET_API_KEY_123".to_string(),
                    category: LeakCategory::InternalToken,
                    description: "Custom secret".to_string(),
                },
            ],
            watchlist_patterns: vec![],
        };

        let result = scan_output("The key is SECRET_API_KEY_123", Some(&config));
        assert!(!result.safe);
        assert!(result.leaked_tokens.iter().any(|t| t.token == "SECRET_API_KEY_123"));
    }
}

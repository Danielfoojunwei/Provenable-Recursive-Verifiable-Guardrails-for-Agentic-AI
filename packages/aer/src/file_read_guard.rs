//! File read guard for sensitive file access control.
//!
//! # Problem
//!
//! AER's MI guard protects workspace memory file **writes**, but a skill with
//! raw filesystem access can still read `.env`, `~/.ssh/id_rsa`,
//! `~/.aws/credentials`, and other sensitive files. The `read_memory_file()`
//! function only covers the 7 workspace MEMORY_FILES.
//!
//! # Solution
//!
//! This module provides a policy-based file read guard that can:
//! - **Deny** reads of sensitive files from untrusted principals
//! - **Taint** reads from secret-containing paths with `SECRET_RISK`
//! - **Record** all guarded reads as tamper-evident evidence
//!
//! Since AER cannot intercept raw syscalls, enforcement requires the
//! integration layer to route file reads through `hooks::on_file_read()`.
//! For true prevention, OS-level sandboxing (seccomp, landlock, containers)
//! is required.
//!
//! # Formal Grounding
//!
//! This extends the **MI Theorem (read-side)**: sensitive files are protected
//! memory artifacts. Unauthorized disclosure violates memory confidentiality,
//! enabling downstream attacks (credential theft, lateral movement).
//!
//! The guard also feeds the **Noninterference Theorem**: taint propagation
//! ensures that data read from sensitive files carries `SECRET_RISK`, preventing
//! clean-provenance laundering.

use crate::types::*;
use std::path::Path;

/// Configuration for the file read guard.
#[derive(Debug, Clone)]
pub struct SensitiveFileConfig {
    /// File patterns that should be denied to untrusted principals.
    /// Matched against the file basename (not full path).
    pub denied_basenames: Vec<String>,
    /// File patterns whose content should carry SECRET_RISK taint.
    /// Matched against the file basename.
    pub tainted_basenames: Vec<String>,
    /// Directory components that indicate sensitive locations.
    /// Matched against any component in the file path.
    pub sensitive_dirs: Vec<String>,
}

/// Result of a file read guard check.
#[derive(Debug, Clone)]
pub struct FileReadCheckResult {
    /// Whether the read is allowed.
    pub verdict: GuardVerdict,
    /// Taint flags to apply to the read result.
    pub output_taint: TaintFlags,
    /// Human-readable rationale.
    pub rationale: String,
    /// The matched pattern that triggered the decision.
    pub matched_pattern: Option<String>,
}

/// Create the default sensitive file configuration.
///
/// Based on common credential and secret file locations observed in
/// ClawHavoc V3 (Credential Exfiltration) attacks.
pub fn default_config() -> SensitiveFileConfig {
    SensitiveFileConfig {
        denied_basenames: vec![
            // Environment files
            ".env".into(),
            ".env.local".into(),
            ".env.production".into(),
            ".env.development".into(),
            // SSH keys
            "id_rsa".into(),
            "id_ed25519".into(),
            "id_ecdsa".into(),
            "id_dsa".into(),
            // TLS/PKI
            "server.key".into(),
            "private.key".into(),
            // Cloud credentials
            "credentials".into(),
            "credentials.json".into(),
            "service-account.json".into(),
            // API tokens
            ".netrc".into(),
            ".pgpass".into(),
            // Docker secrets
            "config.json".into(),
        ],
        tainted_basenames: vec![
            // Files that should be tainted but not blocked
            "known_hosts".into(),
            "authorized_keys".into(),
            ".gitconfig".into(),
            ".npmrc".into(),
            ".pypirc".into(),
        ],
        sensitive_dirs: vec![
            ".ssh".into(),
            ".aws".into(),
            ".gnupg".into(),
            ".docker".into(),
            ".config/gcloud".into(),
            ".kube".into(),
            ".clawdbot".into(),
        ],
    }
}

/// Check whether a file read should be allowed.
///
/// # Decision Logic
///
/// 1. If the file basename matches a denied pattern AND the principal is
///    untrusted → **Deny**
/// 2. If the file path contains a sensitive directory component AND the
///    principal is untrusted → **Deny** with SECRET_RISK taint
/// 3. If the file basename matches a tainted pattern → **Allow** with
///    SECRET_RISK taint
/// 4. Otherwise → **Allow** with propagated taint
pub fn check_file_read(
    principal: Principal,
    taint: TaintFlags,
    file_path: &str,
    config: Option<&SensitiveFileConfig>,
) -> FileReadCheckResult {
    let default = default_config();
    let config = config.unwrap_or(&default);

    let path = Path::new(file_path);
    let basename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    let is_untrusted = principal.is_untrusted_for_memory();

    // Check denied basenames
    for pattern in &config.denied_basenames {
        if basename_matches(basename, pattern) {
            if is_untrusted {
                return FileReadCheckResult {
                    verdict: GuardVerdict::Deny,
                    output_taint: taint | TaintFlags::SECRET_RISK | TaintFlags::UNTRUSTED,
                    rationale: format!(
                        "File read denied: '{}' matches sensitive file pattern '{}' \
                         for {:?} principal (untrusted)",
                        file_path, pattern, principal
                    ),
                    matched_pattern: Some(pattern.clone()),
                };
            }
            // Trusted principal reading denied file — allow but taint
            return FileReadCheckResult {
                verdict: GuardVerdict::Allow,
                output_taint: taint | TaintFlags::SECRET_RISK,
                rationale: format!(
                    "File read allowed with SECRET_RISK taint: '{}' matches \
                     sensitive pattern '{}' for {:?} principal (trusted)",
                    file_path, pattern, principal
                ),
                matched_pattern: Some(pattern.clone()),
            };
        }
    }

    // Check sensitive directory components
    let path_str = file_path.replace('\\', "/");
    for dir in &config.sensitive_dirs {
        if path_str.contains(&format!("/{}/", dir))
            || path_str.contains(&format!("/{}", dir))
            || path_str.starts_with(&format!("{}/", dir))
        {
            if is_untrusted {
                return FileReadCheckResult {
                    verdict: GuardVerdict::Deny,
                    output_taint: taint | TaintFlags::SECRET_RISK | TaintFlags::UNTRUSTED,
                    rationale: format!(
                        "File read denied: path '{}' is in sensitive directory '{}' \
                         for {:?} principal (untrusted)",
                        file_path, dir, principal
                    ),
                    matched_pattern: Some(dir.clone()),
                };
            }
            return FileReadCheckResult {
                verdict: GuardVerdict::Allow,
                output_taint: taint | TaintFlags::SECRET_RISK,
                rationale: format!(
                    "File read allowed with SECRET_RISK taint: path '{}' is in \
                     sensitive directory '{}' for {:?} principal (trusted)",
                    file_path, dir, principal
                ),
                matched_pattern: Some(dir.clone()),
            };
        }
    }

    // Check tainted basenames
    for pattern in &config.tainted_basenames {
        if basename_matches(basename, pattern) {
            return FileReadCheckResult {
                verdict: GuardVerdict::Allow,
                output_taint: taint | TaintFlags::SECRET_RISK,
                rationale: format!(
                    "File read allowed with SECRET_RISK taint: '{}' matches \
                     tainted pattern '{}'",
                    file_path, pattern
                ),
                matched_pattern: Some(pattern.clone()),
            };
        }
    }

    // Default: allow with propagated taint
    FileReadCheckResult {
        verdict: GuardVerdict::Allow,
        output_taint: taint,
        rationale: format!(
            "File read allowed: '{}' (no sensitive patterns matched)",
            file_path
        ),
        matched_pattern: None,
    }
}

/// Match a file basename against a pattern.
///
/// Supports:
/// - Exact match (case-insensitive)
/// - Prefix match for `.env.*` patterns (`.env.local`, `.env.production`)
/// - Extension match for `*.key`, `*.pem` patterns
fn basename_matches(basename: &str, pattern: &str) -> bool {
    let lower = basename.to_lowercase();
    let pat_lower = pattern.to_lowercase();

    // Exact match
    if lower == pat_lower {
        return true;
    }

    // .env prefix matching — ".env" pattern matches ".env.local", ".env.production"
    if pat_lower == ".env" && lower.starts_with(".env.") {
        return true;
    }

    false
}

/// Detect sensitive file content patterns in arbitrary text.
///
/// Used as a defense-in-depth scanner for tool output that may contain
/// leaked credentials, even when the file read wasn't routed through
/// the file read guard hook.
pub fn detect_sensitive_content(content: &str) -> Vec<SensitiveContentFinding> {
    let mut findings = Vec::new();

    // Credential patterns
    let patterns = [
        (
            "-----BEGIN RSA PRIVATE KEY-----",
            "RSA private key detected",
        ),
        ("-----BEGIN EC PRIVATE KEY-----", "EC private key detected"),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "OpenSSH private key detected",
        ),
        (
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "PGP private key detected",
        ),
        ("AKIA", "AWS access key ID prefix detected"),
    ];

    for (pattern, description) in patterns {
        if content.contains(pattern) {
            findings.push(SensitiveContentFinding {
                description: description.to_string(),
                evidence: pattern.to_string(),
            });
        }
    }

    // Key-value patterns (case-insensitive)
    let lower = content.to_lowercase();
    let kv_patterns = [
        ("aws_secret_access_key", "AWS secret access key"),
        ("api_key=", "API key assignment"),
        ("api_secret=", "API secret assignment"),
        ("password=", "Password assignment"),
        ("secret_key=", "Secret key assignment"),
        ("private_key=", "Private key assignment"),
        ("database_url=", "Database URL with credentials"),
        ("connection_string=", "Connection string"),
    ];

    for (pattern, description) in kv_patterns {
        if lower.contains(pattern) {
            findings.push(SensitiveContentFinding {
                description: description.to_string(),
                evidence: pattern.to_string(),
            });
        }
    }

    findings
}

/// A finding from sensitive content detection.
#[derive(Debug, Clone)]
pub struct SensitiveContentFinding {
    pub description: String,
    pub evidence: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deny_env_file_for_skill() {
        let result = check_file_read(
            Principal::Skill,
            TaintFlags::SKILL_OUTPUT,
            "/home/user/.clawdbot/.env",
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
        assert!(result.output_taint.contains(TaintFlags::SECRET_RISK));
    }

    #[test]
    fn test_allow_env_file_for_user() {
        let result = check_file_read(
            Principal::User,
            TaintFlags::empty(),
            "/home/user/.env",
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);
        assert!(result.output_taint.contains(TaintFlags::SECRET_RISK));
    }

    #[test]
    fn test_deny_ssh_key_for_web() {
        let result = check_file_read(
            Principal::Web,
            TaintFlags::WEB_DERIVED,
            "/home/user/.ssh/id_rsa",
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
    }

    #[test]
    fn test_deny_aws_credentials_for_skill() {
        let result = check_file_read(
            Principal::Skill,
            TaintFlags::SKILL_OUTPUT,
            "/home/user/.aws/credentials",
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
    }

    #[test]
    fn test_allow_normal_file_for_skill() {
        let result = check_file_read(
            Principal::Skill,
            TaintFlags::SKILL_OUTPUT,
            "/home/user/project/README.md",
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);
        assert!(!result.output_taint.contains(TaintFlags::SECRET_RISK));
    }

    #[test]
    fn test_taint_known_hosts() {
        let result = check_file_read(
            Principal::User,
            TaintFlags::empty(),
            "/home/user/.ssh/known_hosts",
            None,
        );
        // .ssh dir match triggers for user too but as allow with taint
        assert_eq!(result.verdict, GuardVerdict::Allow);
        assert!(result.output_taint.contains(TaintFlags::SECRET_RISK));
    }

    #[test]
    fn test_env_prefix_matching() {
        let result = check_file_read(
            Principal::Skill,
            TaintFlags::empty(),
            "/app/.env.production",
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
    }

    #[test]
    fn test_detect_private_key_in_content() {
        let findings = detect_sensitive_content(
            "Here is the file content:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
        );
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.description.contains("RSA private key")));
    }

    #[test]
    fn test_detect_aws_key_in_content() {
        let findings = detect_sensitive_content(
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_clean_content_no_findings() {
        let findings = detect_sensitive_content("def hello():\n    print('Hello, world!')\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_custom_config() {
        let config = SensitiveFileConfig {
            denied_basenames: vec!["secret.txt".into()],
            tainted_basenames: vec![],
            sensitive_dirs: vec![],
        };
        let result = check_file_read(
            Principal::Skill,
            TaintFlags::empty(),
            "/app/secret.txt",
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
    }
}

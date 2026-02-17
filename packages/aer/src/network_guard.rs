//! Network egress guard for outbound request monitoring.
//!
//! # Problem
//!
//! AER doesn't monitor outbound HTTP requests. A skill could exfiltrate data
//! via `curl`, `fetch()`, or direct socket connections. AER is a reference
//! monitor, not a network proxy.
//!
//! # Solution
//!
//! This module provides the **policy and recording layer** for network egress.
//! When the integration layer routes outbound requests through the
//! `hooks::on_outbound_request()` hook, this guard evaluates:
//!
//! - Domain allowlist/blocklist
//! - Payload size limits (detect bulk exfiltration)
//! - Exfiltration heuristics (base64 in URLs, suspicious query strings)
//! - Principal-based access control
//!
//! Actual network-level enforcement requires an egress proxy (squid, envoy),
//! eBPF, or firewall rules. This module provides the policy layer that
//! informs those controls.
//!
//! # Formal Grounding
//!
//! This extends the **Noninterference Theorem** to the network boundary:
//! data from trusted contexts should not flow to untrusted external endpoints
//! without taint tracking. The guard also feeds the **RVU Machine Unlearning**
//! pipeline: every blocked or flagged request is recorded as tamper-evident
//! evidence, enabling contamination detection if data was partially exfiltrated.

use crate::types::*;

/// Configuration for the network egress guard.
#[derive(Debug, Clone)]
pub struct NetworkEgressConfig {
    /// Allowed domains. If non-empty, only these domains are permitted.
    /// Empty means all domains allowed (backward-compatible default).
    pub allowed_domains: Vec<String>,
    /// Blocked domains. Always denied regardless of allowlist.
    pub blocked_domains: Vec<String>,
    /// Maximum outbound payload size in bytes before flagging.
    /// Default: 1 MB.
    pub max_payload_bytes: usize,
    /// Whether to flag base64-encoded content in URLs.
    pub flag_base64_in_urls: bool,
}

/// Result of a network egress guard check.
#[derive(Debug, Clone)]
pub struct NetworkCheckResult {
    /// Whether the request is allowed.
    pub verdict: GuardVerdict,
    /// Taint flags to apply to any response data.
    pub output_taint: TaintFlags,
    /// Human-readable rationale.
    pub rationale: String,
    /// Specific flags raised during the check.
    pub flags: Vec<NetworkFlag>,
}

/// Specific flags raised during network check.
#[derive(Debug, Clone)]
pub struct NetworkFlag {
    pub category: NetworkFlagCategory,
    pub description: String,
}

/// Categories of network flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkFlagCategory {
    /// Domain is on the blocklist.
    BlockedDomain,
    /// Domain not on the allowlist.
    UnallowedDomain,
    /// Payload exceeds size limit.
    OversizedPayload,
    /// Base64 content detected in URL.
    Base64InUrl,
    /// Known exfiltration service.
    ExfiltrationService,
    /// Suspicious query parameters.
    SuspiciousQuery,
}

/// Create the default network egress configuration.
pub fn default_config() -> NetworkEgressConfig {
    NetworkEgressConfig {
        allowed_domains: vec![], // Empty = all allowed (backward-compatible)
        blocked_domains: vec![
            // Known exfiltration/interaction services
            "webhook.site".into(),
            "requestbin.com".into(),
            "pipedream.net".into(),
            "hookbin.com".into(),
            "canarytokens.com".into(),
            "interact.sh".into(),
            "interactsh.com".into(),
            "burpcollaborator.net".into(),
            // Known paste services used for exfil
            "pastebin.com".into(),
            "paste.ee".into(),
            "hastebin.com".into(),
            "dpaste.org".into(),
        ],
        max_payload_bytes: 1_048_576, // 1 MB
        flag_base64_in_urls: true,
    }
}

/// Check whether an outbound request should be allowed.
///
/// # Arguments
///
/// * `principal` — Who is making the request
/// * `taint` — Current taint flags
/// * `url` — The target URL
/// * `method` — HTTP method (GET, POST, etc.)
/// * `payload_size` — Size of the request body in bytes
/// * `config` — Network egress configuration (or None for defaults)
pub fn check_outbound_request(
    principal: Principal,
    taint: TaintFlags,
    url: &str,
    method: &str,
    payload_size: usize,
    config: Option<&NetworkEgressConfig>,
) -> NetworkCheckResult {
    let default = default_config();
    let config = config.unwrap_or(&default);
    let mut flags = Vec::new();

    let domain = extract_domain(url);

    // 1. Check blocklist (always applies, all principals)
    if let Some(ref d) = domain {
        for blocked in &config.blocked_domains {
            if domain_matches(d, blocked) {
                flags.push(NetworkFlag {
                    category: NetworkFlagCategory::BlockedDomain,
                    description: format!("Domain '{}' is on the blocklist", d),
                });
                return NetworkCheckResult {
                    verdict: GuardVerdict::Deny,
                    output_taint: taint | TaintFlags::UNTRUSTED | TaintFlags::WEB_DERIVED,
                    rationale: format!(
                        "Outbound request to '{}' denied: domain '{}' is blocked \
                         (known exfiltration/interaction service)",
                        url, d
                    ),
                    flags,
                };
            }
        }
    }

    // 2. Check allowlist (if configured)
    if !config.allowed_domains.is_empty() {
        let allowed = domain.as_ref().map_or(false, |d| {
            config.allowed_domains.iter().any(|a| domain_matches(d, a))
        });
        if !allowed {
            let d = domain.as_deref().unwrap_or("unknown");
            flags.push(NetworkFlag {
                category: NetworkFlagCategory::UnallowedDomain,
                description: format!("Domain '{}' is not on the allowlist", d),
            });
            // Untrusted principals are denied; trusted get a flag
            if principal.is_untrusted_for_memory() {
                return NetworkCheckResult {
                    verdict: GuardVerdict::Deny,
                    output_taint: taint | TaintFlags::UNTRUSTED | TaintFlags::WEB_DERIVED,
                    rationale: format!(
                        "Outbound request to '{}' denied: domain '{}' not on allowlist \
                         for {:?} principal (untrusted)",
                        url, d, principal
                    ),
                    flags,
                };
            }
        }
    }

    // 3. Check payload size (POST/PUT/PATCH only)
    let method_upper = method.to_uppercase();
    if matches!(method_upper.as_str(), "POST" | "PUT" | "PATCH")
        && payload_size > config.max_payload_bytes
    {
        flags.push(NetworkFlag {
            category: NetworkFlagCategory::OversizedPayload,
            description: format!(
                "Payload size {} exceeds limit {} bytes",
                payload_size, config.max_payload_bytes
            ),
        });
        // Deny oversized payloads from untrusted principals
        if principal.is_untrusted_for_memory() {
            return NetworkCheckResult {
                verdict: GuardVerdict::Deny,
                output_taint: taint | TaintFlags::UNTRUSTED,
                rationale: format!(
                    "Outbound {} request denied: payload size {} exceeds limit {} \
                     for {:?} principal (potential exfiltration)",
                    method_upper, payload_size, config.max_payload_bytes, principal
                ),
                flags,
            };
        }
    }

    // 4. Check for base64 in URLs (exfiltration via GET params)
    if config.flag_base64_in_urls && contains_base64_in_url(url) {
        flags.push(NetworkFlag {
            category: NetworkFlagCategory::Base64InUrl,
            description: "Base64-encoded content detected in URL query parameters".into(),
        });
    }

    // 5. Check for known exfiltration patterns
    if let Some(ref d) = domain {
        if is_exfiltration_service(d) {
            flags.push(NetworkFlag {
                category: NetworkFlagCategory::ExfiltrationService,
                description: format!("Domain '{}' is a known exfiltration service", d),
            });
        }
    }

    // Determine output taint
    let output_taint = if !flags.is_empty() {
        taint | TaintFlags::WEB_DERIVED
    } else {
        taint | TaintFlags::WEB_DERIVED
    };

    NetworkCheckResult {
        verdict: GuardVerdict::Allow,
        output_taint,
        rationale: if flags.is_empty() {
            format!("Outbound {} request to '{}' allowed", method_upper, url)
        } else {
            format!(
                "Outbound {} request to '{}' allowed with {} flag(s)",
                method_upper,
                url,
                flags.len()
            )
        },
        flags,
    }
}

/// Extract the domain from a URL.
fn extract_domain(url: &str) -> Option<String> {
    // Simple extraction: skip scheme, take host
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host_part = without_scheme.split('/').next()?;
    // Remove port
    let domain = host_part.split(':').next()?;
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_lowercase())
    }
}

/// Check if a domain matches a pattern (exact or subdomain match).
fn domain_matches(domain: &str, pattern: &str) -> bool {
    let d = domain.to_lowercase();
    let p = pattern.to_lowercase();
    d == p || d.ends_with(&format!(".{}", p))
}

/// Check if a URL contains base64-encoded content in query parameters.
fn contains_base64_in_url(url: &str) -> bool {
    if let Some(query) = url.split('?').nth(1) {
        // Look for base64-like strings (long alphanumeric + /+= sequences)
        for param in query.split('&') {
            let value = param.split('=').nth(1).unwrap_or("");
            if value.len() >= 40
                && value.chars().all(|c| {
                    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '%'
                })
            {
                return true;
            }
        }
    }
    false
}

/// Check if a domain is a known exfiltration/interaction service.
fn is_exfiltration_service(domain: &str) -> bool {
    let services = [
        "ngrok.io",
        "ngrok.app",
        "trycloudflare.com",
        "loca.lt",
        "serveo.net",
    ];
    services
        .iter()
        .any(|s| domain_matches(domain, s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_normal_request() {
        let result = check_outbound_request(
            Principal::User,
            TaintFlags::empty(),
            "https://api.github.com/repos",
            "GET",
            0,
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);
    }

    #[test]
    fn test_block_exfil_service() {
        let result = check_outbound_request(
            Principal::Skill,
            TaintFlags::SKILL_OUTPUT,
            "https://webhook.site/abc123",
            "POST",
            100,
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
        assert!(result.flags.iter().any(|f| f.category == NetworkFlagCategory::BlockedDomain));
    }

    #[test]
    fn test_block_pastebin() {
        let result = check_outbound_request(
            Principal::Skill,
            TaintFlags::empty(),
            "https://pastebin.com/api/create",
            "POST",
            1000,
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
    }

    #[test]
    fn test_allowlist_enforcement() {
        let config = NetworkEgressConfig {
            allowed_domains: vec!["api.github.com".into(), "api.openai.com".into()],
            blocked_domains: vec![],
            max_payload_bytes: 1_048_576,
            flag_base64_in_urls: true,
        };

        // Allowed domain
        let result = check_outbound_request(
            Principal::Skill,
            TaintFlags::empty(),
            "https://api.github.com/repos",
            "GET",
            0,
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);

        // Non-allowed domain from untrusted principal
        let result = check_outbound_request(
            Principal::Skill,
            TaintFlags::empty(),
            "https://evil.com/exfil",
            "POST",
            100,
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
    }

    #[test]
    fn test_oversized_payload_denied_for_skill() {
        let config = NetworkEgressConfig {
            allowed_domains: vec![],
            blocked_domains: vec![],
            max_payload_bytes: 1024,
            flag_base64_in_urls: false,
        };
        let result = check_outbound_request(
            Principal::Skill,
            TaintFlags::empty(),
            "https://example.com/api",
            "POST",
            2048,
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
        assert!(result.flags.iter().any(|f| f.category == NetworkFlagCategory::OversizedPayload));
    }

    #[test]
    fn test_oversized_payload_allowed_for_user() {
        let config = NetworkEgressConfig {
            allowed_domains: vec![],
            blocked_domains: vec![],
            max_payload_bytes: 1024,
            flag_base64_in_urls: false,
        };
        let result = check_outbound_request(
            Principal::User,
            TaintFlags::empty(),
            "https://example.com/api",
            "POST",
            2048,
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);
        assert!(result.flags.iter().any(|f| f.category == NetworkFlagCategory::OversizedPayload));
    }

    #[test]
    fn test_base64_in_url_detection() {
        let result = check_outbound_request(
            Principal::User,
            TaintFlags::empty(),
            "https://example.com/api?data=SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBsb25nIGJhc2U2NCBlbmNvZGVkIHN0cmluZw==",
            "GET",
            0,
            None,
        );
        assert!(result.flags.iter().any(|f| f.category == NetworkFlagCategory::Base64InUrl));
    }

    #[test]
    fn test_subdomain_matching() {
        assert!(domain_matches("sub.webhook.site", "webhook.site"));
        assert!(domain_matches("webhook.site", "webhook.site"));
        assert!(!domain_matches("notwebhook.site", "webhook.site"));
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(extract_domain("https://api.github.com/repos"), Some("api.github.com".into()));
        assert_eq!(extract_domain("http://localhost:8080/api"), Some("localhost".into()));
        assert_eq!(extract_domain("https://example.com"), Some("example.com".into()));
    }

    #[test]
    fn test_blocklist_overrides_allowlist() {
        let config = NetworkEgressConfig {
            allowed_domains: vec!["webhook.site".into()], // Allowed but also blocked
            blocked_domains: vec!["webhook.site".into()],
            max_payload_bytes: 1_048_576,
            flag_base64_in_urls: false,
        };
        let result = check_outbound_request(
            Principal::User,
            TaintFlags::empty(),
            "https://webhook.site/test",
            "GET",
            0,
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
    }

    #[test]
    fn test_get_request_ignores_payload_size() {
        let config = NetworkEgressConfig {
            allowed_domains: vec![],
            blocked_domains: vec![],
            max_payload_bytes: 100,
            flag_base64_in_urls: false,
        };
        let result = check_outbound_request(
            Principal::Skill,
            TaintFlags::empty(),
            "https://example.com/api",
            "GET",
            99999, // Large but GET, so ignored
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);
    }
}

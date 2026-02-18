//! Integration tests for v0.1.5 — Remaining Known Limitations.
//!
//! Tests all four new guard surfaces introduced in v0.1.5:
//! 1. Output guard dynamic tokens (system prompt registry)
//! 2. File read guard (sensitive file access control)
//! 3. Network egress guard (outbound request monitoring)
//! 4. Sandbox audit (OS-level isolation verification)

// ============================================================
// Phase 1: Output Guard Dynamic Tokens
// ============================================================

mod system_prompt_registry {
    use aer::output_guard;
    use aer::system_prompt_registry;
    use std::sync::Mutex;

    /// Serialize tests that share the global REGISTRY singleton.
    static REGISTRY_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_registry_activates_dynamic_discovery_for_output_guard() {
        let _lock = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        system_prompt_registry::clear();

        // Register a system prompt with a novel internal token
        let prompt = "You are an assistant. Use INTERNAL_BOOTSTRAP_VECTOR to initialize. \
                      Call buildContextSection() for context assembly. \
                      Template: ${params.toolConfig}.";
        let count = system_prompt_registry::register_system_prompt(prompt);
        assert!(count >= 2, "Should discover at least 2 dynamic tokens, got {}", count);

        // Now the output guard should catch these tokens automatically
        let config = system_prompt_registry::get_cached_config().unwrap();

        // Test: novel SCREAMING_CASE token is caught
        let result = output_guard::scan_output(
            "Here is how initialization works: INTERNAL_BOOTSTRAP_VECTOR activates the system.",
            Some(&config),
        );
        assert!(!result.safe, "Should catch INTERNAL_BOOTSTRAP_VECTOR");
        assert!(result.leaked_tokens.iter().any(|t| t.token == "INTERNAL_BOOTSTRAP_VECTOR"));

        // Test: camelCase function is caught
        let result2 = output_guard::scan_output(
            "The buildContextSection function assembles the prompt.",
            Some(&config),
        );
        assert!(!result2.safe, "Should catch buildContextSection");

        // Test: clean output still passes
        let result3 = output_guard::scan_output(
            "Here is the code you asked for:\n```python\nprint('hello')\n```",
            Some(&config),
        );
        assert!(result3.safe, "Clean output should still pass");

        system_prompt_registry::clear();
    }

    #[test]
    fn test_token_only_registration_path() {
        let _lock = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        system_prompt_registry::clear();

        // Simulate future OpenClaw API exposing individual tokens
        system_prompt_registry::register_tokens_only(vec![
            "SKILL_AUTH_NONCE".into(),
            "parseManifestConfig".into(),
            "${runtime.secretKey}".into(),
        ]);

        let config = system_prompt_registry::get_cached_config().unwrap();
        assert!(config.watchlist_exact.iter().any(|e| e.token == "SKILL_AUTH_NONCE"));
        assert!(config.watchlist_exact.iter().any(|e| e.token == "parseManifestConfig"));
        assert!(config.watchlist_exact.iter().any(|e| e.token == "${runtime.secretKey}"));

        // Verify these tokens are actually caught
        let result = output_guard::scan_output(
            "The SKILL_AUTH_NONCE is used for authentication between services.",
            Some(&config),
        );
        assert!(!result.safe, "Should catch manually registered token");

        system_prompt_registry::clear();
    }

    #[test]
    fn test_prompt_re_registration_replaces_tokens() {
        let _lock = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        system_prompt_registry::clear();

        system_prompt_registry::register_system_prompt("Use FIRST_SECRET_TOKEN for auth.");
        let config1 = system_prompt_registry::get_cached_config().unwrap();
        assert!(config1.watchlist_exact.iter().any(|e| e.token == "FIRST_SECRET_TOKEN"));

        // Re-register with different prompt
        system_prompt_registry::register_system_prompt("Use SECOND_SECRET_TOKEN for auth.");
        let config2 = system_prompt_registry::get_cached_config().unwrap();
        assert!(config2.watchlist_exact.iter().any(|e| e.token == "SECOND_SECRET_TOKEN"));
        assert!(
            !config2.watchlist_exact.iter().any(|e| e.token == "FIRST_SECRET_TOKEN"),
            "Old token should be gone after re-registration"
        );

        system_prompt_registry::clear();
    }

    #[test]
    fn test_prompt_hash_for_audit_correlation() {
        let _lock = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        system_prompt_registry::clear();

        system_prompt_registry::register_system_prompt("Deterministic prompt content.");
        let hash1 = system_prompt_registry::prompt_hash().unwrap();

        system_prompt_registry::register_system_prompt("Deterministic prompt content.");
        let hash2 = system_prompt_registry::prompt_hash().unwrap();

        assert_eq!(hash1, hash2, "Same prompt should produce same hash");
        assert_eq!(hash1.len(), 64, "SHA-256 hex should be 64 chars");

        system_prompt_registry::register_system_prompt("Different prompt content.");
        let hash3 = system_prompt_registry::prompt_hash().unwrap();
        assert_ne!(hash1, hash3, "Different prompts should produce different hashes");

        system_prompt_registry::clear();
    }

    #[test]
    fn test_static_watchlist_preserved_with_dynamic_tokens() {
        // This test verifies that dynamic discovery preserves the static watchlist.
        // We use config_with_runtime_discovery directly to avoid global state races.
        let static_config = output_guard::default_config();
        let static_count = static_config.watchlist_exact.len();

        let dynamic_config =
            output_guard::config_with_runtime_discovery("NOVEL_TOKEN_XYZ is used.");

        assert!(
            dynamic_config.watchlist_exact.len() > static_count,
            "Dynamic config should have more tokens than static ({} vs {})",
            dynamic_config.watchlist_exact.len(),
            static_count
        );

        // Verify static tokens still present
        let static_token = &static_config.watchlist_exact[0].token;
        assert!(
            dynamic_config.watchlist_exact.iter().any(|e| &e.token == static_token),
            "Static watchlist tokens should be preserved"
        );
    }
}

// ============================================================
// Phase 2: File Read Guard
// ============================================================

mod file_read_guard {
    use aer::file_read_guard;
    use aer::types::*;

    #[test]
    fn test_skill_cannot_read_env_files() {
        let result = file_read_guard::check_file_read(
            Principal::Skill,
            TaintFlags::SKILL_OUTPUT,
            "/home/agent/.clawdbot/.env",
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
        assert!(result.output_taint.contains(TaintFlags::SECRET_RISK));
    }

    #[test]
    fn test_skill_cannot_read_ssh_keys() {
        for key in &["id_rsa", "id_ed25519", "id_ecdsa"] {
            let path = format!("/home/agent/.ssh/{}", key);
            let result = file_read_guard::check_file_read(
                Principal::Skill,
                TaintFlags::empty(),
                &path,
                None,
            );
            assert_eq!(result.verdict, GuardVerdict::Deny, "Should deny {} for Skill", key);
        }
    }

    #[test]
    fn test_web_cannot_read_aws_credentials() {
        let result = file_read_guard::check_file_read(
            Principal::Web,
            TaintFlags::WEB_DERIVED,
            "/home/agent/.aws/credentials",
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);
    }

    #[test]
    fn test_user_can_read_env_with_taint() {
        let result = file_read_guard::check_file_read(
            Principal::User,
            TaintFlags::empty(),
            "/home/agent/.env",
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);
        assert!(
            result.output_taint.contains(TaintFlags::SECRET_RISK),
            "Sensitive file reads should carry SECRET_RISK even for trusted principals"
        );
    }

    #[test]
    fn test_skill_can_read_normal_files() {
        let result = file_read_guard::check_file_read(
            Principal::Skill,
            TaintFlags::SKILL_OUTPUT,
            "/home/agent/project/src/main.rs",
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);
        assert!(!result.output_taint.contains(TaintFlags::SECRET_RISK));
    }

    #[test]
    fn test_env_variant_matching() {
        // .env.production, .env.local etc. should all be caught
        for variant in &[".env", ".env.local", ".env.production", ".env.development"] {
            let path = format!("/app/{}", variant);
            let result = file_read_guard::check_file_read(
                Principal::Skill,
                TaintFlags::empty(),
                &path,
                None,
            );
            assert_eq!(
                result.verdict,
                GuardVerdict::Deny,
                "{} should be denied for skills",
                variant
            );
        }
    }

    #[test]
    fn test_sensitive_directory_detection() {
        // Files under .ssh/, .aws/, .gnupg/ should be blocked for untrusted principals
        let paths = [
            "/home/user/.ssh/config",
            "/home/user/.aws/config",
            "/home/user/.gnupg/private-keys-v1.d/key",
            "/home/user/.docker/config.json",
        ];
        for path in &paths {
            let result = file_read_guard::check_file_read(
                Principal::Skill,
                TaintFlags::empty(),
                path,
                None,
            );
            assert_eq!(
                result.verdict,
                GuardVerdict::Deny,
                "Path {} should be denied for Skill",
                path
            );
        }
    }

    #[test]
    fn test_sensitive_content_detection() {
        // Private key in tool output
        let findings = file_read_guard::detect_sensitive_content(
            "Here is the file:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n-----END RSA PRIVATE KEY-----"
        );
        assert!(!findings.is_empty(), "Should detect RSA private key");

        // AWS credentials
        let findings = file_read_guard::detect_sensitive_content(
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert!(!findings.is_empty(), "Should detect AWS secret key");

        // Clean content
        let findings = file_read_guard::detect_sensitive_content(
            "fn main() {\n    println!(\"Hello world\");\n}\n"
        );
        assert!(findings.is_empty(), "Clean code should have no findings");
    }

    #[test]
    fn test_custom_sensitive_file_config() {
        let config = file_read_guard::SensitiveFileConfig {
            denied_basenames: vec!["company-secrets.yaml".into()],
            tainted_basenames: vec!["internal-config.toml".into()],
            sensitive_dirs: vec!["vault".into()],
        };

        let result = file_read_guard::check_file_read(
            Principal::Skill,
            TaintFlags::empty(),
            "/app/company-secrets.yaml",
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);

        let result = file_read_guard::check_file_read(
            Principal::User,
            TaintFlags::empty(),
            "/app/internal-config.toml",
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);
        assert!(result.output_taint.contains(TaintFlags::SECRET_RISK));
    }
}

// ============================================================
// Phase 3: Network Egress Guard
// ============================================================

mod network_guard {
    use aer::network_guard;
    use aer::types::*;

    #[test]
    fn test_known_exfil_services_blocked() {
        let services = [
            "https://webhook.site/abc123",
            "https://requestbin.com/r/abc",
            "https://pipedream.net/flows/abc",
            "https://hookbin.com/abc",
            "https://canarytokens.com/abc",
            "https://pastebin.com/api/create",
            "https://interact.sh/abc",
            "https://burpcollaborator.net/abc",
        ];

        for url in &services {
            let result = network_guard::check_outbound_request(
                Principal::Skill,
                TaintFlags::SKILL_OUTPUT,
                url,
                "POST",
                100,
                None,
            );
            assert_eq!(
                result.verdict,
                GuardVerdict::Deny,
                "Should block {} for skills",
                url
            );
        }
    }

    #[test]
    fn test_exfil_services_blocked_for_all_principals() {
        // Even USER principal should be blocked from known exfil services
        let result = network_guard::check_outbound_request(
            Principal::User,
            TaintFlags::empty(),
            "https://webhook.site/test",
            "POST",
            100,
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Deny, "Blocklist applies to all principals");
    }

    #[test]
    fn test_normal_api_calls_allowed() {
        let result = network_guard::check_outbound_request(
            Principal::User,
            TaintFlags::empty(),
            "https://api.github.com/repos/owner/repo",
            "GET",
            0,
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);
    }

    #[test]
    fn test_allowlist_blocks_non_listed_domains_for_untrusted() {
        let config = network_guard::NetworkEgressConfig {
            allowed_domains: vec!["api.github.com".into(), "api.openai.com".into()],
            blocked_domains: vec![],
            max_payload_bytes: 1_048_576,
            flag_base64_in_urls: true,
        };

        // Allowed domain
        let result = network_guard::check_outbound_request(
            Principal::Skill,
            TaintFlags::empty(),
            "https://api.github.com/repos",
            "GET",
            0,
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);

        // Non-allowed domain from untrusted principal
        let result = network_guard::check_outbound_request(
            Principal::Skill,
            TaintFlags::empty(),
            "https://attacker.com/exfil",
            "POST",
            100,
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);

        // Non-allowed domain from trusted principal (allowed with flags)
        let result = network_guard::check_outbound_request(
            Principal::User,
            TaintFlags::empty(),
            "https://other-api.com/data",
            "GET",
            0,
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);
    }

    #[test]
    fn test_oversized_payload_detection() {
        let config = network_guard::NetworkEgressConfig {
            allowed_domains: vec![],
            blocked_domains: vec![],
            max_payload_bytes: 1024,
            flag_base64_in_urls: false,
        };

        // Skill with oversized POST — denied
        let result = network_guard::check_outbound_request(
            Principal::Skill,
            TaintFlags::empty(),
            "https://example.com/api",
            "POST",
            5000,
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Deny);

        // User with oversized POST — allowed but flagged
        let result = network_guard::check_outbound_request(
            Principal::User,
            TaintFlags::empty(),
            "https://example.com/api",
            "POST",
            5000,
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Allow);
        assert!(!result.flags.is_empty());
    }

    #[test]
    fn test_base64_in_url_flagged() {
        let result = network_guard::check_outbound_request(
            Principal::Skill,
            TaintFlags::empty(),
            "https://example.com/api?data=SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBsb25nIGJhc2U2NCBlbmNvZGVkIHN0cmluZw==",
            "GET",
            0,
            None,
        );
        assert!(
            result.flags.iter().any(|f| f.category == network_guard::NetworkFlagCategory::Base64InUrl),
            "Should flag base64 in URL query parameters"
        );
    }

    #[test]
    fn test_subdomain_blocking() {
        let result = network_guard::check_outbound_request(
            Principal::Skill,
            TaintFlags::empty(),
            "https://abc123.webhook.site/test",
            "POST",
            100,
            None,
        );
        assert_eq!(result.verdict, GuardVerdict::Deny, "Subdomains of blocked domains should also be blocked");
    }

    #[test]
    fn test_blocklist_overrides_allowlist() {
        let config = network_guard::NetworkEgressConfig {
            allowed_domains: vec!["webhook.site".into()],
            blocked_domains: vec!["webhook.site".into()],
            max_payload_bytes: 1_048_576,
            flag_base64_in_urls: false,
        };
        let result = network_guard::check_outbound_request(
            Principal::User,
            TaintFlags::empty(),
            "https://webhook.site/test",
            "GET",
            0,
            Some(&config),
        );
        assert_eq!(result.verdict, GuardVerdict::Deny, "Blocklist should take priority");
    }

    #[test]
    fn test_all_responses_carry_web_derived_taint() {
        let result = network_guard::check_outbound_request(
            Principal::User,
            TaintFlags::empty(),
            "https://api.example.com/data",
            "GET",
            0,
            None,
        );
        assert!(
            result.output_taint.contains(TaintFlags::WEB_DERIVED),
            "Network responses should always carry WEB_DERIVED taint"
        );
    }
}

// ============================================================
// Phase 4: Sandbox Audit
// ============================================================

mod sandbox_audit {
    use aer::sandbox_audit;
    use std::collections::HashMap;

    #[test]
    fn test_audit_runs_without_panic() {
        let result = sandbox_audit::audit_sandbox_environment();
        // Should work on any platform — findings may vary
        assert!(!result.findings.is_empty(), "Should have at least one finding");
    }

    #[test]
    fn test_full_compliance_computation() {
        assert_eq!(
            sandbox_audit::SandboxCompliance::Full.to_string(),
            "FULL"
        );
    }

    #[test]
    fn test_profile_evaluation_all_missing() {
        let audit = sandbox_audit::SandboxAuditResult {
            in_container: false,
            seccomp_active: false,
            seccomp_mode: "disabled".into(),
            namespaces: vec![],
            readonly_root: false,
            resource_limits: HashMap::new(),
            compliance: sandbox_audit::SandboxCompliance::None,
            findings: vec![],
        };

        let profile = sandbox_audit::default_profile();
        let violations = sandbox_audit::evaluate_profile(&audit, &profile);
        assert!(violations.len() >= 2, "Should have at least container + seccomp violations");
    }

    #[test]
    fn test_profile_evaluation_full_compliance() {
        let audit = sandbox_audit::SandboxAuditResult {
            in_container: true,
            seccomp_active: true,
            seccomp_mode: "filter".into(),
            namespaces: vec!["pid".into(), "net".into(), "mnt".into()],
            readonly_root: true,
            resource_limits: HashMap::from([
                ("nproc".into(), "1024".into()),
                ("nofile".into(), "65536".into()),
            ]),
            compliance: sandbox_audit::SandboxCompliance::Full,
            findings: vec![],
        };

        let profile = sandbox_audit::default_profile();
        let violations = sandbox_audit::evaluate_profile(&audit, &profile);
        assert!(violations.is_empty(), "Full compliance should have no violations");
    }

    #[test]
    fn test_custom_profile_with_network_namespace() {
        let audit = sandbox_audit::SandboxAuditResult {
            in_container: true,
            seccomp_active: true,
            seccomp_mode: "filter".into(),
            namespaces: vec!["pid".into(), "mnt".into()], // no "net"
            readonly_root: false,
            resource_limits: HashMap::new(),
            compliance: sandbox_audit::SandboxCompliance::Partial,
            findings: vec![],
        };

        let profile = sandbox_audit::SandboxProfile {
            require_container: true,
            require_seccomp: true,
            require_readonly_root: true,
            require_network_namespace: true,
        };

        let violations = sandbox_audit::evaluate_profile(&audit, &profile);
        assert!(
            violations.iter().any(|v| v.contains("Network namespace")),
            "Should flag missing network namespace"
        );
        assert!(
            violations.iter().any(|v| v.contains("Read-only")),
            "Should flag missing read-only root"
        );
    }
}

// ============================================================
// Cross-cutting: Hook integration
// ============================================================

mod hooks_integration {
    use aer::config;
    use aer::hooks;
    use aer::policy;
    use aer::system_prompt_registry;
    use aer::types::*;
    use aer::workspace;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn setup_temp_env() -> TempDir {
        let tmp = TempDir::new().expect("create temp dir");
        std::env::set_var("PRV_STATE_DIR", tmp.path().to_str().unwrap());
        config::ensure_aer_dirs().expect("ensure aer dirs");
        let default = policy::default_policy();
        policy::save_policy(&default, &config::default_policy_file()).expect("save policy");
        workspace::ensure_workspace().expect("ensure workspace");
        tmp
    }

    #[test]
    fn test_on_system_prompt_available_records_evidence() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _tmp = setup_temp_env();
        system_prompt_registry::clear();

        let result = hooks::on_system_prompt_available(
            "agent-test",
            "sess-test",
            "Internal token: CUSTOM_GUARD_TOKEN. Use buildAuthSection() for auth.",
        );
        assert!(result.is_ok(), "on_system_prompt_available should succeed");

        let record = result.unwrap();
        assert_eq!(record.record_type, RecordType::GuardDecision);
        assert_eq!(record.principal, Principal::Sys);

        // Registry should be populated
        assert!(system_prompt_registry::get_cached_config().is_some());
        assert!(system_prompt_registry::dynamic_token_count() > 0);

        system_prompt_registry::clear();
    }

    #[test]
    fn test_on_file_read_denies_env_for_skill() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _tmp = setup_temp_env();

        let result = hooks::on_file_read(
            "agent-test",
            "sess-test",
            Principal::Skill,
            TaintFlags::SKILL_OUTPUT,
            "/home/agent/.env",
            vec![],
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_err(), "Should deny .env read for Skill");
    }

    #[test]
    fn test_on_file_read_allows_normal_file() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _tmp = setup_temp_env();

        let result = hooks::on_file_read(
            "agent-test",
            "sess-test",
            Principal::User,
            TaintFlags::empty(),
            "/home/agent/project/src/main.rs",
            vec![],
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok(), "Should allow normal file read");
    }

    #[test]
    fn test_on_outbound_request_blocks_exfil() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _tmp = setup_temp_env();

        let result = hooks::on_outbound_request(
            "agent-test",
            "sess-test",
            Principal::Skill,
            TaintFlags::SKILL_OUTPUT,
            "https://webhook.site/exfil",
            "POST",
            1000,
            vec![],
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_err(), "Should deny exfil service request");
    }

    #[test]
    fn test_on_outbound_request_allows_normal() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _tmp = setup_temp_env();

        let result = hooks::on_outbound_request(
            "agent-test",
            "sess-test",
            Principal::User,
            TaintFlags::empty(),
            "https://api.github.com/repos",
            "GET",
            0,
            vec![],
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok(), "Should allow normal API request");
    }

    #[test]
    fn test_on_sandbox_audit_returns_result() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _tmp = setup_temp_env();

        let result = hooks::on_sandbox_audit("agent-test", "sess-test");
        assert!(result.is_ok());
        let (audit, record) = result.unwrap();
        assert!(!audit.findings.is_empty(), "Should have sandbox findings");
        assert_eq!(record.record_type, RecordType::GuardDecision);
    }
}

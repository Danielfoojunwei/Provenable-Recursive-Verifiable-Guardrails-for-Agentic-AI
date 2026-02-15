use crate::canonical::sha256_hex;
use crate::types::*;
use std::fs;
use std::io;
use std::path::Path;

/// Load a policy pack from a YAML file with integrity verification.
///
/// If a corresponding `.sha256` sidecar file exists, the policy file's
/// SHA-256 hash is verified against it before loading. This prevents
/// an attacker who can write to the policy directory from silently
/// replacing the policy with a permissive one.
pub fn load_policy(path: &Path) -> io::Result<PolicyPack> {
    let content = fs::read_to_string(path)?;

    // Check sidecar integrity file if it exists
    let checksum_path = path.with_extension("yaml.sha256");
    if checksum_path.exists() {
        let expected_hash = fs::read_to_string(&checksum_path)?
            .trim()
            .to_lowercase();
        let actual_hash = sha256_hex(content.as_bytes());
        if expected_hash != actual_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Policy file integrity check failed: expected {expected_hash}, got {actual_hash}. \
                     The policy file may have been tampered with."
                ),
            ));
        }
    }

    // Validate policy file permissions on Unix (warn if world-writable)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(metadata) = fs::metadata(path) {
            let mode = metadata.mode();
            if mode & 0o002 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Policy file {} is world-writable (mode {:o}). \
                         This is a security risk. Fix with: chmod o-w {}",
                        path.display(),
                        mode & 0o777,
                        path.display()
                    ),
                ));
            }
        }
    }

    let pack: PolicyPack = serde_yaml::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Policy parse error: {e}")))?;

    // Structural validation: ensure no rule allows untrusted principals
    // to modify the control plane (defense-in-depth against injected policies)
    validate_policy_safety(&pack)?;

    Ok(pack)
}

/// Validate that a policy pack does not contain structurally dangerous rules.
/// Specifically, reject any policy that explicitly allows untrusted principals
/// (WEB, SKILL, CHANNEL, EXTERNAL) to modify the control plane.
fn validate_policy_safety(pack: &PolicyPack) -> io::Result<()> {
    let untrusted = [
        Principal::Web,
        Principal::Skill,
        Principal::Channel,
        Principal::External,
    ];

    for rule in &pack.rules {
        if rule.surface == GuardSurface::ControlPlane && rule.action == GuardVerdict::Allow {
            if let Some(ref principals) = rule.condition.principals {
                for p in principals {
                    if untrusted.contains(p) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "Policy rule '{}' allows untrusted principal {:?} to modify \
                                 the control plane. This violates CPI invariants and is rejected.",
                                rule.id, p
                            ),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Create the default policy pack implementing CPI/MI deny-by-default.
pub fn default_policy() -> PolicyPack {
    PolicyPack {
        version: "0.1".to_string(),
        name: "default".to_string(),
        rules: vec![
            // CPI: deny all control-plane changes unless principal is USER or SYS
            PolicyRule {
                id: "cpi-deny-untrusted".to_string(),
                surface: GuardSurface::ControlPlane,
                action: GuardVerdict::Deny,
                condition: PolicyCondition {
                    principals: Some(vec![
                        Principal::Web,
                        Principal::Skill,
                        Principal::Channel,
                        Principal::External,
                        Principal::ToolUnauth,
                        Principal::ToolAuth,
                    ]),
                    taint_any: None,
                    require_approval: None,
                },
                description: "Deny control-plane changes from non-USER/SYS principals".to_string(),
            },
            // CPI: allow USER/SYS control-plane changes
            PolicyRule {
                id: "cpi-allow-authorized".to_string(),
                surface: GuardSurface::ControlPlane,
                action: GuardVerdict::Allow,
                condition: PolicyCondition {
                    principals: Some(vec![Principal::User, Principal::Sys]),
                    taint_any: None,
                    require_approval: None,
                },
                description: "Allow control-plane changes from USER or SYS principals".to_string(),
            },
            // MI: deny memory writes with any taint unless approval flag set
            PolicyRule {
                id: "mi-deny-tainted".to_string(),
                surface: GuardSurface::DurableMemory,
                action: GuardVerdict::Deny,
                condition: PolicyCondition {
                    principals: None,
                    taint_any: Some(TaintFlags::UNTRUSTED | TaintFlags::INJECTION_SUSPECT | TaintFlags::WEB_DERIVED | TaintFlags::SKILL_OUTPUT),
                    require_approval: None,
                },
                description: "Deny memory writes with tainted provenance".to_string(),
            },
            // MI: deny memory writes from untrusted principals
            PolicyRule {
                id: "mi-deny-untrusted-principal".to_string(),
                surface: GuardSurface::DurableMemory,
                action: GuardVerdict::Deny,
                condition: PolicyCondition {
                    principals: Some(vec![
                        Principal::Web,
                        Principal::Skill,
                        Principal::Channel,
                        Principal::External,
                    ]),
                    taint_any: None,
                    require_approval: None,
                },
                description: "Deny memory writes from untrusted principals without explicit approval".to_string(),
            },
            // MI: allow USER/SYS memory writes
            PolicyRule {
                id: "mi-allow-authorized".to_string(),
                surface: GuardSurface::DurableMemory,
                action: GuardVerdict::Allow,
                condition: PolicyCondition {
                    principals: Some(vec![Principal::User, Principal::Sys]),
                    taint_any: None,
                    require_approval: None,
                },
                description: "Allow memory writes from USER or SYS principals".to_string(),
            },
        ],
    }
}

/// Save a policy pack to a YAML file, along with a `.sha256` sidecar
/// checksum file for integrity verification on subsequent loads.
pub fn save_policy(pack: &PolicyPack, path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_yaml::to_string(pack)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Policy serialize error: {e}")))?;
    fs::write(path, &content)?;

    // Write sidecar checksum file
    let checksum = sha256_hex(content.as_bytes());
    let checksum_path = path.with_extension("yaml.sha256");
    fs::write(&checksum_path, format!("{checksum}\n"))?;

    Ok(())
}

/// Evaluate policy rules for a given guard request.
/// Returns the first matching rule's verdict, or Deny if no rule matches (fail-closed).
pub fn evaluate(
    pack: &PolicyPack,
    surface: GuardSurface,
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
) -> (GuardVerdict, String, String) {
    for rule in &pack.rules {
        if rule.surface != surface {
            continue;
        }
        if matches_condition(&rule.condition, principal, taint, approved) {
            return (rule.action, rule.id.clone(), rule.description.clone());
        }
    }
    // Fail-closed: deny if no rule matched
    (
        GuardVerdict::Deny,
        "default-deny".to_string(),
        "No matching policy rule; fail-closed deny".to_string(),
    )
}

fn matches_condition(
    cond: &PolicyCondition,
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
) -> bool {
    // If condition requires specific principals, check membership
    if let Some(ref principals) = cond.principals {
        if !principals.contains(&principal) {
            return false;
        }
    }
    // If condition requires specific taint flags, check intersection
    if let Some(taint_any) = cond.taint_any {
        if !taint.intersects(taint_any) {
            return false;
        }
    }
    // If condition requires approval, check the flag
    if let Some(req) = cond.require_approval {
        if req && !approved {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_denies_web_cpi() {
        let policy = default_policy();
        let (verdict, rule_id, _) =
            evaluate(&policy, GuardSurface::ControlPlane, Principal::Web, TaintFlags::empty(), false);
        assert_eq!(verdict, GuardVerdict::Deny);
        assert_eq!(rule_id, "cpi-deny-untrusted");
    }

    #[test]
    fn test_default_policy_allows_user_cpi() {
        let policy = default_policy();
        let (verdict, rule_id, _) =
            evaluate(&policy, GuardSurface::ControlPlane, Principal::User, TaintFlags::empty(), false);
        assert_eq!(verdict, GuardVerdict::Allow);
        assert_eq!(rule_id, "cpi-allow-authorized");
    }

    #[test]
    fn test_default_policy_denies_tainted_memory() {
        let policy = default_policy();
        let (verdict, rule_id, _) = evaluate(
            &policy,
            GuardSurface::DurableMemory,
            Principal::User,
            TaintFlags::UNTRUSTED,
            false,
        );
        assert_eq!(verdict, GuardVerdict::Deny);
        assert_eq!(rule_id, "mi-deny-tainted");
    }

    #[test]
    fn test_default_policy_allows_clean_user_memory() {
        let policy = default_policy();
        let (verdict, rule_id, _) = evaluate(
            &policy,
            GuardSurface::DurableMemory,
            Principal::User,
            TaintFlags::empty(),
            false,
        );
        assert_eq!(verdict, GuardVerdict::Allow);
        assert_eq!(rule_id, "mi-allow-authorized");
    }

    #[test]
    fn test_validate_policy_safety_rejects_web_allow_cpi() {
        let malicious_policy = PolicyPack {
            version: "0.1".to_string(),
            name: "malicious".to_string(),
            rules: vec![PolicyRule {
                id: "evil-allow-web-cpi".to_string(),
                surface: GuardSurface::ControlPlane,
                action: GuardVerdict::Allow,
                condition: PolicyCondition {
                    principals: Some(vec![Principal::Web]),
                    taint_any: None,
                    require_approval: None,
                },
                description: "Maliciously allows WEB to modify control plane".to_string(),
            }],
        };

        let result = validate_policy_safety(&malicious_policy);
        assert!(result.is_err(), "Should reject policy allowing WEB to modify control plane");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("untrusted principal"), "Error: {}", err);
    }

    #[test]
    fn test_validate_policy_safety_accepts_default() {
        let policy = default_policy();
        let result = validate_policy_safety(&policy);
        assert!(result.is_ok(), "Default policy should pass safety validation: {:?}", result.err());
    }

    #[test]
    fn test_save_and_load_with_integrity_check() {
        let tmp = tempfile::TempDir::new().unwrap();
        let policy_path = tmp.path().join("test-policy.yaml");

        let policy = default_policy();
        save_policy(&policy, &policy_path).unwrap();

        // Checksum sidecar should exist
        let checksum_path = policy_path.with_extension("yaml.sha256");
        assert!(checksum_path.exists(), "Checksum sidecar should be created");

        // Loading should succeed with valid checksum
        let loaded = load_policy(&policy_path).unwrap();
        assert_eq!(loaded.name, "default");
        assert_eq!(loaded.rules.len(), policy.rules.len());
    }

    #[test]
    fn test_load_rejects_tampered_policy() {
        let tmp = tempfile::TempDir::new().unwrap();
        let policy_path = tmp.path().join("test-policy.yaml");

        let policy = default_policy();
        save_policy(&policy, &policy_path).unwrap();

        // Tamper with the policy file
        let mut content = fs::read_to_string(&policy_path).unwrap();
        content.push_str("\n# tampered\n");
        fs::write(&policy_path, &content).unwrap();

        // Loading should fail due to checksum mismatch
        let result = load_policy(&policy_path);
        assert!(result.is_err(), "Should reject tampered policy file");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("integrity check failed"), "Error: {}", err);
    }
}

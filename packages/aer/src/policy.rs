use crate::types::*;
use std::fs;
use std::io;
use std::path::Path;

/// Load a policy pack from a YAML file.
pub fn load_policy(path: &Path) -> io::Result<PolicyPack> {
    let content = fs::read_to_string(path)?;
    serde_yaml::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Policy parse error: {e}")))
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

/// Save a policy pack to a YAML file.
pub fn save_policy(pack: &PolicyPack, path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_yaml::to_string(pack)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Policy serialize error: {e}")))?;
    fs::write(path, content)
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
}

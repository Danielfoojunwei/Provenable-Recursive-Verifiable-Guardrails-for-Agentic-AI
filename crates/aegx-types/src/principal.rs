use serde::{Deserialize, Serialize};

/// Principal identity in the trust lattice.
///
/// Trust ordering (CPI Theorem): WEB, SKILL <= TOOL_UNAUTH <= TOOL_AUTH <= USER <= SYS
///
/// Unified from aegx's `Principal` (7 variants, SCREAMING_CASE) and aer's
/// `Principal` (8 variants with trust methods). This version uses aer's richer
/// enum with helper methods, and SCREAMING_SNAKE_CASE serde for compatibility
/// with aegx bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Principal {
    Sys,
    User,
    ToolAuth,
    ToolUnauth,
    Web,
    Skill,
    Channel,
    External,
}

impl Principal {
    /// Returns the trust level (higher = more trusted).
    /// Grounded in CPI Theorem: only principals at trust level >= 4 may
    /// modify control-plane state.
    pub fn trust_level(self) -> u8 {
        match self {
            Principal::Sys => 5,
            Principal::User => 4,
            Principal::ToolAuth => 3,
            Principal::ToolUnauth => 2,
            Principal::Web | Principal::Skill => 1,
            Principal::Channel | Principal::External => 0,
        }
    }

    /// Returns true if this principal has authority to modify control-plane state.
    /// CPI Theorem: only USER and SYS may alter the control plane.
    pub fn can_modify_control_plane(self) -> bool {
        matches!(self, Principal::User | Principal::Sys)
    }

    /// Returns true if this principal is considered untrusted for memory writes.
    /// MI Theorem: writes from untrusted principals require guard approval.
    pub fn is_untrusted_for_memory(self) -> bool {
        matches!(
            self,
            Principal::Web | Principal::Skill | Principal::Channel | Principal::External
        )
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self).unwrap();
        write!(f, "{}", s.as_str().unwrap())
    }
}

impl std::str::FromStr for Principal {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Support both SCREAMING_SNAKE_CASE (aegx) and PascalCase
        let upper = s.to_uppercase();
        match upper.as_str() {
            "SYS" => Ok(Principal::Sys),
            "USER" => Ok(Principal::User),
            "TOOL_AUTH" | "TOOLAUTH" => Ok(Principal::ToolAuth),
            "TOOL_UNAUTH" | "TOOLUNAUTH" => Ok(Principal::ToolUnauth),
            "TOOL" => Ok(Principal::ToolUnauth), // aegx compat: TOOL maps to ToolUnauth
            "WEB" => Ok(Principal::Web),
            "SKILL" => Ok(Principal::Skill),
            "CHANNEL" => Ok(Principal::Channel),
            "EXTERNAL" => Ok(Principal::External),
            _ => Err(format!("unknown principal: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_ordering() {
        assert!(Principal::Sys.trust_level() > Principal::User.trust_level());
        assert!(Principal::User.trust_level() > Principal::ToolAuth.trust_level());
        assert!(Principal::ToolAuth.trust_level() > Principal::ToolUnauth.trust_level());
        assert!(Principal::ToolUnauth.trust_level() > Principal::Web.trust_level());
        assert_eq!(Principal::Web.trust_level(), Principal::Skill.trust_level());
    }

    #[test]
    fn test_control_plane_access() {
        assert!(Principal::User.can_modify_control_plane());
        assert!(Principal::Sys.can_modify_control_plane());
        assert!(!Principal::Skill.can_modify_control_plane());
        assert!(!Principal::Web.can_modify_control_plane());
        assert!(!Principal::ToolAuth.can_modify_control_plane());
    }

    #[test]
    fn test_memory_trust() {
        assert!(!Principal::User.is_untrusted_for_memory());
        assert!(!Principal::Sys.is_untrusted_for_memory());
        assert!(Principal::Web.is_untrusted_for_memory());
        assert!(Principal::Skill.is_untrusted_for_memory());
        assert!(Principal::External.is_untrusted_for_memory());
    }

    #[test]
    fn test_serde_roundtrip() {
        let p = Principal::ToolAuth;
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, "\"TOOL_AUTH\"");
        let back: Principal = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn test_from_str_compat() {
        assert_eq!("TOOL".parse::<Principal>().unwrap(), Principal::ToolUnauth);
        assert_eq!("SYS".parse::<Principal>().unwrap(), Principal::Sys);
    }
}

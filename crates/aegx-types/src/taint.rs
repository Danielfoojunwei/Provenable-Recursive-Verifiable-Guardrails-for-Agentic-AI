use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    /// Taint flags for provenance tracking (Noninterference Theorem).
    ///
    /// Conservative propagation: any tainted dependency taints the output.
    /// This ensures that data flowing through untrusted principals carries
    /// its provenance, preventing clean-provenance laundering attacks.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TaintFlags: u32 {
        const UNTRUSTED         = 0b0000_0001;
        const INJECTION_SUSPECT = 0b0000_0010;
        const PROXY_DERIVED     = 0b0000_0100;
        const SECRET_RISK       = 0b0000_1000;
        const CROSS_SESSION     = 0b0001_0000;
        const TOOL_OUTPUT       = 0b0010_0000;
        const SKILL_OUTPUT      = 0b0100_0000;
        const WEB_DERIVED       = 0b1000_0000;
    }
}

impl Serialize for TaintFlags {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.bits().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TaintFlags {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u32::deserialize(deserializer)?;
        TaintFlags::from_bits(bits)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid taint flags: {bits}")))
    }
}

impl TaintFlags {
    /// Returns true if any taint bit is set.
    pub fn is_tainted(self) -> bool {
        !self.is_empty()
    }

    /// Compute the union of taint from all parent records.
    /// Noninterference Theorem: taint propagates conservatively (union).
    pub fn propagate(parents: &[TaintFlags]) -> TaintFlags {
        let mut result = TaintFlags::empty();
        for t in parents {
            result |= *t;
        }
        result
    }

    /// Convert from aegx-format Vec<String> taint labels to bitflags.
    /// This provides backward compatibility with the original aegx format
    /// which used string-based taint labels.
    pub fn from_string_labels(labels: &[String]) -> Self {
        let mut flags = TaintFlags::empty();
        for label in labels {
            match label.to_uppercase().as_str() {
                "UNTRUSTED" => flags |= TaintFlags::UNTRUSTED,
                "INJECTION_SUSPECT" | "INJECTION" => flags |= TaintFlags::INJECTION_SUSPECT,
                "PROXY_DERIVED" | "PROXY" => flags |= TaintFlags::PROXY_DERIVED,
                "SECRET_RISK" | "SECRET" => flags |= TaintFlags::SECRET_RISK,
                "CROSS_SESSION" => flags |= TaintFlags::CROSS_SESSION,
                "TOOL_OUTPUT" | "TOOL" => flags |= TaintFlags::TOOL_OUTPUT,
                "SKILL_OUTPUT" | "SKILL" => flags |= TaintFlags::SKILL_OUTPUT,
                "WEB_DERIVED" | "WEB" => flags |= TaintFlags::WEB_DERIVED,
                _ => {} // Unknown labels are silently ignored for forward compatibility
            }
        }
        flags
    }

    /// Convert to aegx-format Vec<String> taint labels.
    pub fn to_string_labels(self) -> Vec<String> {
        let mut labels = Vec::new();
        if self.contains(TaintFlags::UNTRUSTED) {
            labels.push("UNTRUSTED".into());
        }
        if self.contains(TaintFlags::INJECTION_SUSPECT) {
            labels.push("INJECTION_SUSPECT".into());
        }
        if self.contains(TaintFlags::PROXY_DERIVED) {
            labels.push("PROXY_DERIVED".into());
        }
        if self.contains(TaintFlags::SECRET_RISK) {
            labels.push("SECRET_RISK".into());
        }
        if self.contains(TaintFlags::CROSS_SESSION) {
            labels.push("CROSS_SESSION".into());
        }
        if self.contains(TaintFlags::TOOL_OUTPUT) {
            labels.push("TOOL_OUTPUT".into());
        }
        if self.contains(TaintFlags::SKILL_OUTPUT) {
            labels.push("SKILL_OUTPUT".into());
        }
        if self.contains(TaintFlags::WEB_DERIVED) {
            labels.push("WEB_DERIVED".into());
        }
        labels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_propagation() {
        let a = TaintFlags::UNTRUSTED | TaintFlags::WEB_DERIVED;
        let b = TaintFlags::SECRET_RISK;
        let result = TaintFlags::propagate(&[a, b]);
        assert!(result.contains(TaintFlags::UNTRUSTED));
        assert!(result.contains(TaintFlags::WEB_DERIVED));
        assert!(result.contains(TaintFlags::SECRET_RISK));
    }

    #[test]
    fn test_string_label_roundtrip() {
        let flags = TaintFlags::UNTRUSTED | TaintFlags::SECRET_RISK;
        let labels = flags.to_string_labels();
        let back = TaintFlags::from_string_labels(&labels);
        assert_eq!(flags, back);
    }

    #[test]
    fn test_serde_roundtrip() {
        let flags = TaintFlags::INJECTION_SUSPECT | TaintFlags::SKILL_OUTPUT;
        let json = serde_json::to_string(&flags).unwrap();
        let back: TaintFlags = serde_json::from_str(&json).unwrap();
        assert_eq!(flags, back);
    }

    #[test]
    fn test_is_tainted() {
        assert!(!TaintFlags::empty().is_tainted());
        assert!(TaintFlags::UNTRUSTED.is_tainted());
    }
}

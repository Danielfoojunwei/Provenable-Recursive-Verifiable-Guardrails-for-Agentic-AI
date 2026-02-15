use std::path::PathBuf;

/// Resolve the OpenClaw state directory following the same precedence:
/// 1. OPENCLAW_STATE_DIR env var
/// 2. OPENCLAW_HOME env var + default subpath
/// 3. ~/.openclaw
pub fn resolve_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("OPENCLAW_STATE_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(home) = std::env::var("OPENCLAW_HOME") {
        return PathBuf::from(home);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".openclaw")
}

/// Root of AER state within the OpenClaw state directory.
pub fn aer_root() -> PathBuf {
    resolve_state_dir().join(".aer")
}

/// AER sub-directories.
pub fn policy_dir() -> PathBuf {
    aer_root().join("policy")
}

pub fn records_dir() -> PathBuf {
    aer_root().join("records")
}

pub fn blobs_dir() -> PathBuf {
    records_dir().join("blobs")
}

pub fn audit_dir() -> PathBuf {
    aer_root().join("audit")
}

pub fn snapshots_dir() -> PathBuf {
    aer_root().join("snapshots")
}

pub fn bundles_dir() -> PathBuf {
    aer_root().join("bundles")
}

pub fn reports_dir() -> PathBuf {
    aer_root().join("reports")
}

/// Path to the records JSONL file.
pub fn records_file() -> PathBuf {
    records_dir().join("records.jsonl")
}

/// Path to the audit log JSONL file.
pub fn audit_log_file() -> PathBuf {
    audit_dir().join("audit-log.jsonl")
}

/// Path to the default policy pack file.
pub fn default_policy_file() -> PathBuf {
    policy_dir().join("default.yaml")
}

/// Workspace memory directory.
pub fn workspace_dir() -> PathBuf {
    resolve_state_dir().join("workspace")
}

/// Known workspace memory files that are guarded by MI.
pub const MEMORY_FILES: &[&str] = &[
    "SOUL.md",
    "AGENTS.md",
    "TOOLS.md",
    "USER.md",
    "IDENTITY.md",
    "HEARTBEAT.md",
    "MEMORY.md",
];

/// Ensure all AER directories exist.
pub fn ensure_aer_dirs() -> std::io::Result<()> {
    for dir in &[
        aer_root(),
        policy_dir(),
        records_dir(),
        blobs_dir(),
        audit_dir(),
        snapshots_dir(),
        bundles_dir(),
        reports_dir(),
    ] {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_dir_env_override() {
        let tmp = "/tmp/test-openclaw-state";
        std::env::set_var("OPENCLAW_STATE_DIR", tmp);
        assert_eq!(resolve_state_dir(), PathBuf::from(tmp));
        std::env::remove_var("OPENCLAW_STATE_DIR");
    }

    #[test]
    fn test_aer_subpaths() {
        std::env::set_var("OPENCLAW_STATE_DIR", "/tmp/oc");
        assert_eq!(aer_root(), PathBuf::from("/tmp/oc/.aer"));
        assert_eq!(policy_dir(), PathBuf::from("/tmp/oc/.aer/policy"));
        assert_eq!(records_dir(), PathBuf::from("/tmp/oc/.aer/records"));
        assert_eq!(audit_dir(), PathBuf::from("/tmp/oc/.aer/audit"));
        std::env::remove_var("OPENCLAW_STATE_DIR");
    }
}

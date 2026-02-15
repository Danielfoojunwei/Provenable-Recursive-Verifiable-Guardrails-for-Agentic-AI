use std::path::PathBuf;

/// Resolve the Provenable.ai state directory following the same precedence:
/// 1. PRV_STATE_DIR env var
/// 2. PRV_HOME env var + default subpath
/// 3. ~/.proven
///
/// # Panics
/// Panics if none of `PRV_STATE_DIR`, `PRV_HOME`, or `HOME` are set.
/// Falling back to `/tmp` is a security risk on multi-user systems because
/// `/tmp` is world-writable, allowing an attacker to pre-create a malicious
/// policy directory.
pub fn resolve_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PRV_STATE_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(home) = std::env::var("PRV_HOME") {
        return PathBuf::from(home);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| {
        panic!(
            "HOME environment variable is not set. \
             AER refuses to run without HOME because falling back to /tmp \
             is a security risk. Set HOME, PRV_HOME, or PRV_STATE_DIR."
        )
    });
    PathBuf::from(home).join(".proven")
}

/// Root of AER state within the Provenable.ai state directory.
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

pub fn alerts_dir() -> PathBuf {
    aer_root().join("alerts")
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
        alerts_dir(),
    ] {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize config tests that mutate the process-global env var.
    static CFG_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_state_dir_env_override() {
        let _lock = CFG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = "/tmp/test-proven-state";
        std::env::set_var("PRV_STATE_DIR", tmp);
        assert_eq!(resolve_state_dir(), PathBuf::from(tmp));
        std::env::remove_var("PRV_STATE_DIR");
    }

    #[test]
    fn test_aer_subpaths() {
        let _lock = CFG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("PRV_STATE_DIR", "/tmp/prv");
        assert_eq!(aer_root(), PathBuf::from("/tmp/prv/.aer"));
        assert_eq!(policy_dir(), PathBuf::from("/tmp/prv/.aer/policy"));
        assert_eq!(records_dir(), PathBuf::from("/tmp/prv/.aer/records"));
        assert_eq!(audit_dir(), PathBuf::from("/tmp/prv/.aer/audit"));
        std::env::remove_var("PRV_STATE_DIR");
    }
}

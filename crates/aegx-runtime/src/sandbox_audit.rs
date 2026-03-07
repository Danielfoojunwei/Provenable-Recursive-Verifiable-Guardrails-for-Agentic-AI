//! OS sandbox environment audit for runtime security verification.
//!
//! # Problem
//!
//! AER records and enforces policy but cannot prevent arbitrary code execution
//! from skill scripts. A malicious skill can spawn processes, access the raw
//! filesystem, make syscalls, etc. True prevention requires containers or
//! seccomp profiles.
//!
//! # Solution
//!
//! This module audits the runtime environment to verify that appropriate
//! OS-level sandboxing is in place. It checks for:
//!
//! - Container isolation (Docker, Kubernetes, cgroups v2)
//! - Seccomp filtering (syscall restriction)
//! - Linux namespace isolation (pid, net, mnt, user)
//! - Read-only root filesystem
//! - Resource limits (nproc, nofile)
//!
//! The audit result is recorded as tamper-evident evidence in the audit chain,
//! and alerts are emitted when the sandbox is insufficient.
//!
//! # Formal Grounding
//!
//! This implements **defense-in-depth** for the CPI and Noninterference
//! theorems. While AER provides the policy layer, OS sandboxing provides
//! the enforcement layer that prevents bypassing the policy via raw syscalls.
//! The audit proves (or disproves) that enforcement is actually in place.
//!
//! # Usage
//!
//! The audit runs automatically on `hooks::on_session_start()` and records
//! the result. Operators can also run it manually:
//!
//! ```ignore
//! let result = aer::sandbox_audit::audit_sandbox_environment();
//! if result.compliance == SandboxCompliance::None {
//!     // Alert: no OS sandboxing detected
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Overall sandbox compliance level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxCompliance {
    /// Full compliance: container + seccomp + namespace isolation.
    Full,
    /// Partial compliance: some but not all sandbox layers active.
    Partial,
    /// No sandbox detected: running on bare host.
    None,
}

impl std::fmt::Display for SandboxCompliance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxCompliance::Full => write!(f, "FULL"),
            SandboxCompliance::Partial => write!(f, "PARTIAL"),
            SandboxCompliance::None => write!(f, "NONE"),
        }
    }
}

/// A single sandbox audit finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxFinding {
    /// What was checked.
    pub check: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Human-readable detail.
    pub detail: String,
}

/// Result of auditing the sandbox environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxAuditResult {
    /// Whether running inside a container.
    pub in_container: bool,
    /// Whether seccomp is active.
    pub seccomp_active: bool,
    /// Seccomp mode (disabled, strict, filter).
    pub seccomp_mode: String,
    /// Detected namespaces (pid, net, mnt, user, etc.).
    pub namespaces: Vec<String>,
    /// Whether the root filesystem is read-only.
    pub readonly_root: bool,
    /// Resource limits (nproc, nofile, etc.).
    pub resource_limits: HashMap<String, String>,
    /// Overall compliance level.
    pub compliance: SandboxCompliance,
    /// Individual check results.
    pub findings: Vec<SandboxFinding>,
}

/// Expected sandbox profile for skills execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfile {
    /// Require running in a container.
    pub require_container: bool,
    /// Require seccomp filtering.
    pub require_seccomp: bool,
    /// Require read-only root filesystem.
    pub require_readonly_root: bool,
    /// Require network namespace isolation.
    pub require_network_namespace: bool,
}

/// Default sandbox profile — requires container + seccomp.
pub fn default_profile() -> SandboxProfile {
    SandboxProfile {
        require_container: true,
        require_seccomp: true,
        require_readonly_root: false,
        require_network_namespace: false,
    }
}

/// Audit the current runtime sandbox environment.
///
/// Checks multiple indicators to determine whether the process is running
/// with appropriate OS-level isolation.
pub fn audit_sandbox_environment() -> SandboxAuditResult {
    let mut findings = Vec::new();

    // 1. Container detection
    let in_container = detect_container(&mut findings);

    // 2. Seccomp detection
    let (seccomp_active, seccomp_mode) = detect_seccomp(&mut findings);

    // 3. Namespace detection
    let namespaces = detect_namespaces(&mut findings);

    // 4. Read-only root detection
    let readonly_root = detect_readonly_root(&mut findings);

    // 5. Resource limits
    let resource_limits = detect_resource_limits(&mut findings);

    // Compute compliance level
    let compliance = compute_compliance(in_container, seccomp_active, &namespaces, readonly_root);

    SandboxAuditResult {
        in_container,
        seccomp_active,
        seccomp_mode,
        namespaces,
        readonly_root,
        resource_limits,
        compliance,
        findings,
    }
}

/// Evaluate the audit result against a sandbox profile.
///
/// Returns a list of violations (profile requirements that are not met).
pub fn evaluate_profile(audit: &SandboxAuditResult, profile: &SandboxProfile) -> Vec<String> {
    let mut violations = Vec::new();

    if profile.require_container && !audit.in_container {
        violations.push("Container isolation required but not detected".into());
    }
    if profile.require_seccomp && !audit.seccomp_active {
        violations.push("Seccomp filtering required but not active".into());
    }
    if profile.require_readonly_root && !audit.readonly_root {
        violations.push("Read-only root filesystem required but not detected".into());
    }
    if profile.require_network_namespace && !audit.namespaces.iter().any(|n| n == "net") {
        violations.push("Network namespace isolation required but not detected".into());
    }

    violations
}

/// Detect whether running inside a container.
fn detect_container(findings: &mut Vec<SandboxFinding>) -> bool {
    let mut in_container = false;

    // Check /.dockerenv
    if Path::new("/.dockerenv").exists() {
        in_container = true;
        findings.push(SandboxFinding {
            check: "dockerenv".into(),
            passed: true,
            detail: "/.dockerenv exists — Docker container detected".into(),
        });
    }

    // Check KUBERNETES_SERVICE_HOST env var
    if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
        in_container = true;
        findings.push(SandboxFinding {
            check: "kubernetes".into(),
            passed: true,
            detail: "KUBERNETES_SERVICE_HOST set — Kubernetes pod detected".into(),
        });
    }

    // Check /proc/1/cgroup for container indicators
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker")
            || cgroup.contains("kubepods")
            || cgroup.contains("containerd")
            || cgroup.contains("cri-o")
        {
            in_container = true;
            findings.push(SandboxFinding {
                check: "cgroup".into(),
                passed: true,
                detail: "Container cgroup detected in /proc/1/cgroup".into(),
            });
        }
    }

    // Check for container runtime env vars
    if std::env::var("container").is_ok() || std::env::var("CONTAINER_RUNTIME").is_ok() {
        in_container = true;
        findings.push(SandboxFinding {
            check: "container_env".into(),
            passed: true,
            detail: "Container runtime environment variable detected".into(),
        });
    }

    if !in_container {
        findings.push(SandboxFinding {
            check: "container".into(),
            passed: false,
            detail: "No container isolation detected — running on bare host".into(),
        });
    }

    in_container
}

/// Detect seccomp filtering status.
fn detect_seccomp(findings: &mut Vec<SandboxFinding>) -> (bool, String) {
    // Read /proc/self/status for Seccomp field
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("Seccomp:") {
                let mode = value.trim();
                let (active, mode_str) = match mode {
                    "0" => (false, "disabled"),
                    "1" => (true, "strict"),
                    "2" => (true, "filter"),
                    _ => (false, "unknown"),
                };
                findings.push(SandboxFinding {
                    check: "seccomp".into(),
                    passed: active,
                    detail: format!("Seccomp mode: {} ({})", mode, mode_str),
                });
                return (active, mode_str.to_string());
            }
        }
    }

    findings.push(SandboxFinding {
        check: "seccomp".into(),
        passed: false,
        detail: "Could not determine seccomp status (non-Linux or /proc unavailable)".into(),
    });
    (false, "unavailable".to_string())
}

/// Detect namespace isolation.
fn detect_namespaces(findings: &mut Vec<SandboxFinding>) -> Vec<String> {
    let mut namespaces = Vec::new();
    let ns_dir = Path::new("/proc/self/ns");

    if ns_dir.exists() {
        let ns_types = ["pid", "net", "mnt", "user", "ipc", "uts", "cgroup"];

        for ns in &ns_types {
            let ns_path = ns_dir.join(ns);
            if ns_path.exists() {
                // Check if we're in a non-root namespace by comparing with init
                let self_ns = fs::read_link(&ns_path).ok();
                let init_ns = fs::read_link(format!("/proc/1/ns/{}", ns)).ok();

                let isolated = match (self_ns, init_ns) {
                    (Some(s), Some(i)) => s != i,
                    _ => false,
                };

                if isolated {
                    namespaces.push(ns.to_string());
                }
            }
        }

        if namespaces.is_empty() {
            findings.push(SandboxFinding {
                check: "namespaces".into(),
                passed: false,
                detail: "No namespace isolation detected (all namespaces match init)".into(),
            });
        } else {
            findings.push(SandboxFinding {
                check: "namespaces".into(),
                passed: true,
                detail: format!("Namespace isolation detected: {}", namespaces.join(", ")),
            });
        }
    } else {
        findings.push(SandboxFinding {
            check: "namespaces".into(),
            passed: false,
            detail: "/proc/self/ns not available (non-Linux or restricted)".into(),
        });
    }

    namespaces
}

/// Detect whether root filesystem is read-only.
fn detect_readonly_root(findings: &mut Vec<SandboxFinding>) -> bool {
    // Check /proc/mounts for root filesystem flags
    if let Ok(mounts) = fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[1] == "/" {
                let flags = parts[3];
                let readonly = flags.split(',').any(|f| f == "ro");
                findings.push(SandboxFinding {
                    check: "readonly_root".into(),
                    passed: readonly,
                    detail: if readonly {
                        "Root filesystem is read-only".into()
                    } else {
                        "Root filesystem is read-write (not hardened)".into()
                    },
                });
                return readonly;
            }
        }
    }

    findings.push(SandboxFinding {
        check: "readonly_root".into(),
        passed: false,
        detail: "Could not determine root filesystem mount flags".into(),
    });
    false
}

/// Detect resource limits.
fn detect_resource_limits(findings: &mut Vec<SandboxFinding>) -> HashMap<String, String> {
    let mut limits = HashMap::new();

    if let Ok(content) = fs::read_to_string("/proc/self/limits") {
        for line in content.lines().skip(1) {
            // Parse "Limit  Soft Limit  Hard Limit  Units" format
            if line.starts_with("Max processes") {
                if let Some(val) = extract_limit_value(line) {
                    limits.insert("nproc".into(), val);
                }
            } else if line.starts_with("Max open files") {
                if let Some(val) = extract_limit_value(line) {
                    limits.insert("nofile".into(), val);
                }
            } else if line.starts_with("Max address space") {
                if let Some(val) = extract_limit_value(line) {
                    limits.insert("as".into(), val);
                }
            }
        }
    }

    let has_limits = !limits.is_empty();
    findings.push(SandboxFinding {
        check: "resource_limits".into(),
        passed: has_limits,
        detail: if has_limits {
            format!("Resource limits detected: {:?}", limits)
        } else {
            "No resource limits detected or /proc/self/limits unavailable".into()
        },
    });

    limits
}

/// Extract a soft limit value from a /proc/self/limits line.
fn extract_limit_value(line: &str) -> Option<String> {
    // Lines look like: "Max processes             123456               123456               processes"
    // We want the soft limit (first numeric value after the label)
    let parts: Vec<&str> = line.split_whitespace().collect();
    // Find the first numeric or "unlimited" value
    for part in &parts[2..] {
        if part.chars().all(|c| c.is_ascii_digit()) || *part == "unlimited" {
            return Some(part.to_string());
        }
    }
    None
}

/// Compute overall compliance level from individual checks.
fn compute_compliance(
    in_container: bool,
    seccomp_active: bool,
    namespaces: &[String],
    readonly_root: bool,
) -> SandboxCompliance {
    let has_namespaces = !namespaces.is_empty();

    if in_container && seccomp_active && has_namespaces && readonly_root {
        SandboxCompliance::Full
    } else if in_container || seccomp_active || has_namespaces {
        SandboxCompliance::Partial
    } else {
        SandboxCompliance::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_runs_without_crash() {
        // Should work on any platform, even without /proc
        let result = audit_sandbox_environment();
        // We can't assert specific values since it depends on the environment,
        // but it should not panic
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn test_compliance_computation_full() {
        assert_eq!(
            compute_compliance(true, true, &["pid".into(), "net".into()], true),
            SandboxCompliance::Full
        );
    }

    #[test]
    fn test_compliance_computation_partial() {
        assert_eq!(
            compute_compliance(true, false, &[], false),
            SandboxCompliance::Partial
        );
        assert_eq!(
            compute_compliance(false, true, &[], false),
            SandboxCompliance::Partial
        );
        assert_eq!(
            compute_compliance(false, false, &["pid".into()], false),
            SandboxCompliance::Partial
        );
    }

    #[test]
    fn test_compliance_computation_none() {
        assert_eq!(
            compute_compliance(false, false, &[], false),
            SandboxCompliance::None
        );
    }

    #[test]
    fn test_evaluate_profile_violations() {
        let audit = SandboxAuditResult {
            in_container: false,
            seccomp_active: false,
            seccomp_mode: "disabled".into(),
            namespaces: vec![],
            readonly_root: false,
            resource_limits: HashMap::new(),
            compliance: SandboxCompliance::None,
            findings: vec![],
        };

        let profile = default_profile();
        let violations = evaluate_profile(&audit, &profile);
        assert!(violations.len() >= 2); // container + seccomp
        assert!(violations.iter().any(|v| v.contains("Container")));
        assert!(violations.iter().any(|v| v.contains("Seccomp")));
    }

    #[test]
    fn test_evaluate_profile_no_violations() {
        let audit = SandboxAuditResult {
            in_container: true,
            seccomp_active: true,
            seccomp_mode: "filter".into(),
            namespaces: vec!["pid".into(), "net".into()],
            readonly_root: true,
            resource_limits: HashMap::new(),
            compliance: SandboxCompliance::Full,
            findings: vec![],
        };

        let profile = default_profile();
        let violations = evaluate_profile(&audit, &profile);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_extract_limit_value() {
        assert_eq!(
            extract_limit_value(
                "Max processes             12345               12345               processes"
            ),
            Some("12345".into())
        );
        assert_eq!(
            extract_limit_value(
                "Max open files            unlimited            unlimited            files"
            ),
            Some("unlimited".into())
        );
    }
}

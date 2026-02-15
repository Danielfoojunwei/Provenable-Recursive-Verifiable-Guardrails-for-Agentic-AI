use crate::audit_chain;
use crate::config;
use crate::policy;
use crate::records;
use crate::types::*;
use serde_json::json;
use std::io;

/// Guard context holds the loaded policy and provides enforcement.
pub struct Guard {
    policy: PolicyPack,
}

impl Guard {
    /// Create a guard with the given policy pack.
    pub fn new(policy: PolicyPack) -> Self {
        Guard { policy }
    }

    /// Load the guard from the default policy file, or use built-in defaults.
    pub fn load_default() -> io::Result<Self> {
        let path = config::default_policy_file();
        let policy = if path.exists() {
            policy::load_policy(&path)?
        } else {
            policy::default_policy()
        };
        Ok(Guard { policy })
    }

    /// Evaluate a control-plane change request.
    /// Returns the guard decision record and whether the change is allowed.
    pub fn check_control_plane(
        &self,
        principal: Principal,
        taint: TaintFlags,
        approved: bool,
        config_key: &str,
        change_detail: serde_json::Value,
        parent_records: Vec<String>,
    ) -> io::Result<(GuardVerdict, TypedRecord)> {
        let (verdict, rule_id, rationale) = policy::evaluate(
            &self.policy,
            GuardSurface::ControlPlane,
            principal,
            taint,
            approved,
        );

        let detail = GuardDecisionDetail {
            verdict,
            rule_id: rule_id.clone(),
            rationale: rationale.clone(),
            surface: GuardSurface::ControlPlane,
            principal,
            taint,
        };

        let mut meta = RecordMeta::now();
        meta.config_key = Some(config_key.to_string());
        meta.rule_id = Some(rule_id);

        let payload = json!({
            "guard_decision": detail,
            "change_request": change_detail,
        });

        let record = records::emit_record(
            RecordType::GuardDecision,
            principal,
            taint,
            parent_records,
            meta,
            payload,
        )?;

        audit_chain::emit_audit(&record.record_id)?;

        Ok((verdict, record))
    }

    /// Evaluate a memory write request.
    /// Returns the guard decision record and whether the write is allowed.
    pub fn check_memory_write(
        &self,
        principal: Principal,
        taint: TaintFlags,
        approved: bool,
        file_path: &str,
        content_hash: &str,
        parent_records: Vec<String>,
    ) -> io::Result<(GuardVerdict, TypedRecord)> {
        let (verdict, rule_id, rationale) = policy::evaluate(
            &self.policy,
            GuardSurface::DurableMemory,
            principal,
            taint,
            approved,
        );

        let detail = GuardDecisionDetail {
            verdict,
            rule_id: rule_id.clone(),
            rationale: rationale.clone(),
            surface: GuardSurface::DurableMemory,
            principal,
            taint,
        };

        let mut meta = RecordMeta::now();
        meta.path = Some(file_path.to_string());
        meta.rule_id = Some(rule_id);

        let payload = json!({
            "guard_decision": detail,
            "file_path": file_path,
            "content_hash": content_hash,
        });

        let record = records::emit_record(
            RecordType::GuardDecision,
            principal,
            taint,
            parent_records,
            meta,
            payload,
        )?;

        audit_chain::emit_audit(&record.record_id)?;

        Ok((verdict, record))
    }
}

/// Convenience function: gate a control-plane mutation.
/// If denied, the mutation is NOT applied and an error is returned.
/// If allowed, the change record is emitted and the caller proceeds.
pub fn gate_control_plane_change(
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
    config_key: &str,
    change_detail: serde_json::Value,
    parent_records: Vec<String>,
) -> io::Result<GuardVerdict> {
    let guard = Guard::load_default()?;
    let (verdict, _record) = guard.check_control_plane(
        principal,
        taint,
        approved,
        config_key,
        change_detail,
        parent_records,
    )?;
    Ok(verdict)
}

/// Convenience function: gate a memory write.
/// If denied, the write is NOT applied and an error is returned.
/// If allowed, the guard decision record is emitted and the caller proceeds.
pub fn gate_memory_write(
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
    file_path: &str,
    content_hash: &str,
    parent_records: Vec<String>,
) -> io::Result<GuardVerdict> {
    let guard = Guard::load_default()?;
    let (verdict, _record) = guard.check_memory_write(
        principal,
        taint,
        approved,
        file_path,
        content_hash,
        parent_records,
    )?;
    Ok(verdict)
}

//! Workspace memory file management.
//!
//! MI Theorem chokepoint: all workspace memory writes go through
//! `write_memory_file()` which invokes the guard.

use aegx_records::{audit_chain, config, records};
use aegx_types::*;
use std::fs;
use std::io;

/// Single chokepoint for all workspace memory writes.
///
/// All memory file mutations must go through this function.
/// If denied by the MI guard, the write is NOT applied.
pub fn write_memory_file(
    filename: &str,
    content: &[u8],
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
    parent_records: Vec<String>,
) -> io::Result<Result<String, String>> {
    if !config::MEMORY_FILES.contains(&filename) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Not a recognized memory file: {filename}"),
        ));
    }

    let workspace = config::workspace_dir();
    let file_path = workspace.join(filename);
    let file_path_str = file_path.to_string_lossy().to_string();
    let content_hash = sha256_hex(content);

    // Evaluate the MI guard
    let verdict = aegx_guard::gate_memory_write(
        principal,
        taint,
        approved,
        &file_path_str,
        &content_hash,
        parent_records,
    )?;

    match verdict {
        GuardVerdict::Allow => {
            fs::create_dir_all(&workspace)?;
            fs::write(&file_path, content)?;
            Ok(Ok(content_hash))
        }
        GuardVerdict::Deny => Ok(Err(format!(
            "MI guard denied write to {} for {:?}",
            filename, principal
        ))),
    }
}

/// Read a memory file with proper principal and taint tracking.
///
/// MI read-side taint: untrusted principals reading protected memory
/// get their output tainted to prevent clean-provenance laundering.
pub fn read_memory_file(
    filename: &str,
    principal: Principal,
    taint: TaintFlags,
    agent_id: Option<&str>,
    session_id: Option<&str>,
) -> io::Result<Option<Vec<u8>>> {
    let workspace = config::workspace_dir();
    let file_path = workspace.join(filename);

    if !file_path.exists() {
        return Ok(None);
    }

    let content = fs::read(&file_path)?;

    let read_taint = if principal.is_untrusted_for_memory() {
        taint | TaintFlags::UNTRUSTED
    } else {
        taint
    };

    let mut meta = RecordMeta::now();
    meta.path = Some(file_path.to_string_lossy().to_string());
    if let Some(aid) = agent_id {
        meta.agent_id = Some(aid.to_string());
    }
    if let Some(sid) = session_id {
        meta.session_id = Some(sid.to_string());
    }

    let payload = serde_json::json!({
        "file_path": file_path.to_string_lossy(),
        "content_hash": sha256_hex(&content),
        "content_size": content.len(),
        "reader_principal": format!("{:?}", principal),
        "read_taint": read_taint.bits(),
    });

    let record = records::emit_record(
        RecordType::FileRead,
        principal,
        read_taint,
        vec![],
        meta,
        payload,
    )?;
    audit_chain::emit_audit(&record.record_id)?;

    Ok(Some(content))
}

/// Initialize the workspace directory.
pub fn ensure_workspace() -> io::Result<()> {
    let workspace = config::workspace_dir();
    fs::create_dir_all(&workspace)?;
    Ok(())
}

use crate::canonical::sha256_hex;
use crate::config;
use crate::hooks;
use crate::types::*;
use std::fs;
use std::io;

/// Single chokepoint for all workspace memory writes.
/// All memory file mutations must go through this function.
///
/// # Arguments
/// * `filename` - One of the MEMORY_FILES (e.g., "SOUL.md")
/// * `content` - The content to write
/// * `principal` - Who is requesting this write
/// * `taint` - Taint flags from provenance
/// * `approved` - Whether the user has explicitly approved this write
/// * `parent_records` - Provenance chain record IDs
///
/// # Returns
/// Ok(record_id) if allowed, Err if denied or I/O error.
pub fn write_memory_file(
    filename: &str,
    content: &[u8],
    principal: Principal,
    taint: TaintFlags,
    approved: bool,
    parent_records: Vec<String>,
) -> io::Result<Result<String, String>> {
    // Validate that this is a known memory file
    if !config::MEMORY_FILES.contains(&filename) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Not a recognized memory file: {filename}"),
        ));
    }

    let workspace = config::workspace_dir();
    let file_path = workspace.join(filename);
    let file_path_str = file_path.to_string_lossy().to_string();

    // Go through the MI guard hook
    let result = hooks::on_file_write(
        principal,
        taint,
        approved,
        &file_path_str,
        content,
        parent_records,
    )?;

    match result {
        Ok(record) => {
            // Guard allowed — actually write the file
            fs::create_dir_all(&workspace)?;
            fs::write(&file_path, content)?;
            Ok(Ok(record.record_id))
        }
        Err(denial_record) => {
            // Guard denied — do NOT write
            Ok(Err(denial_record.record_id))
        }
    }
}

/// Read a memory file with proper principal and taint tracking.
///
/// **v0.1.4 (MI read-side taint)**: Previously, all reads were recorded as
/// `Principal::Sys` with empty taint, meaning an untrusted SKILL reading
/// SOUL.md would get clean provenance. Now reads carry the actual reader's
/// principal and appropriate taint flags, enabling downstream taint
/// propagation (Noninterference conservative-union property).
///
/// The read is NOT blocked (that would break functionality), but the
/// FileRead record carries taint that flows to any downstream operation
/// that depends on this read.
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

    // MI read-side taint: untrusted principals reading protected memory
    // get their output tainted to prevent clean-provenance laundering.
    let read_taint = if principal.is_untrusted_for_memory() {
        taint | TaintFlags::UNTRUSTED
    } else {
        taint
    };

    // Record the read event with actual principal and taint
    let mut meta = crate::types::RecordMeta::now();
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

    let record = crate::records::emit_record(
        RecordType::FileRead,
        principal,
        read_taint,
        vec![],
        meta,
        payload,
    )?;
    crate::audit_chain::emit_audit(&record.record_id)?;

    Ok(Some(content))
}

/// Initialize the workspace with default memory files if they don't exist.
pub fn ensure_workspace() -> io::Result<()> {
    let workspace = config::workspace_dir();
    fs::create_dir_all(&workspace)?;
    Ok(())
}

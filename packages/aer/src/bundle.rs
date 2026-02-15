use crate::audit_chain;
use crate::config;
use crate::records;
use crate::report;
use crate::types::*;
use chrono::Utc;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// Export an AEGX evidence bundle as a .zip file.
pub fn export_bundle(
    agent_id: Option<&str>,
    since: Option<chrono::DateTime<chrono::Utc>>,
) -> io::Result<String> {
    let bundle_id = Uuid::new_v4().to_string();
    let bundle_dir = config::bundles_dir();
    fs::create_dir_all(&bundle_dir)?;
    let bundle_path = bundle_dir.join(format!("{bundle_id}.aegx.zip"));

    let filtered_records = records::read_filtered_records(agent_id, since)?;
    let audit_entries = audit_chain::read_all_entries()?;
    let blob_refs = records::collect_blob_refs()?;

    // Count blobs that exist
    let mut blob_count = 0u64;
    for hash in &blob_refs {
        let blob_path = config::blobs_dir().join(hash);
        if blob_path.exists() {
            blob_count += 1;
        }
    }

    let manifest = BundleManifest {
        bundle_id: bundle_id.clone(),
        created_at: Utc::now(),
        format_version: "0.1".to_string(),
        record_count: filtered_records.len() as u64,
        audit_entry_count: audit_entries.len() as u64,
        blob_count,
        filters: BundleFilters {
            agent_id: agent_id.map(String::from),
            since_time: since,
            since_snapshot: None,
        },
    };

    let file = fs::File::create(&bundle_path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Write manifest
    zip.start_file("manifest.json", options)?;
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    zip.write_all(manifest_json.as_bytes())?;

    // Write records
    zip.start_file("records.jsonl", options)?;
    for record in &filtered_records {
        let line = serde_json::to_string(record)?;
        zip.write_all(line.as_bytes())?;
        zip.write_all(b"\n")?;
    }

    // Write audit log
    zip.start_file("audit-log.jsonl", options)?;
    for entry in &audit_entries {
        let line = serde_json::to_string(entry)?;
        zip.write_all(line.as_bytes())?;
        zip.write_all(b"\n")?;
    }

    // Write blobs
    for hash in &blob_refs {
        let blob_path = config::blobs_dir().join(hash);
        if blob_path.exists() {
            let data = fs::read(&blob_path)?;
            zip.start_file(format!("blobs/{hash}"), options)?;
            zip.write_all(&data)?;
        }
    }

    // Write policy pack
    let policy_path = config::default_policy_file();
    if policy_path.exists() {
        let policy_content = fs::read_to_string(&policy_path)?;
        zip.start_file("policy.yaml", options)?;
        zip.write_all(policy_content.as_bytes())?;
    }

    // Generate and write report
    let report_md = report::generate_markdown_report(&filtered_records, &audit_entries);
    zip.start_file("report.md", options)?;
    zip.write_all(report_md.as_bytes())?;

    let report_json = report::generate_json_report(&filtered_records, &audit_entries)?;
    zip.start_file("report.json", options)?;
    zip.write_all(report_json.as_bytes())?;

    zip.finish()?;

    Ok(bundle_path.to_string_lossy().to_string())
}

/// Maximum size of a single extracted zip entry (1 GB).
const ZIP_MAX_ENTRY_SIZE: u64 = 1_073_741_824;

/// Maximum total extracted size across all entries (10 GB).
const ZIP_MAX_TOTAL_SIZE: u64 = 10_737_418_240;

/// Maximum number of entries allowed in a zip archive.
const ZIP_MAX_ENTRY_COUNT: usize = 100_000;

/// Validate that a zip entry name is safe for extraction.
fn validate_zip_entry_name(name: &str) -> io::Result<()> {
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zip entry has empty name",
        ));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("zip entry has absolute path: {name}"),
        ));
    }
    if name.len() >= 2 && name.as_bytes()[1] == b':' {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("zip entry has Windows absolute path: {name}"),
        ));
    }
    for component in std::path::Path::new(name).components() {
        if let std::path::Component::ParentDir = component {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("zip entry contains path traversal (..): {name}"),
            ));
        }
    }
    if name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("zip entry name contains null byte: {name}"),
        ));
    }
    Ok(())
}

/// Extract a bundle to a temporary directory for verification.
///
/// Security hardening:
/// - Rejects path traversal (`..` components, absolute paths)
/// - Rejects symlink entries
/// - Enforces per-entry size limit (1 GB) and total extraction limit (10 GB)
/// - Rejects duplicate entry names
/// - Validates UTF-8 entry names
/// - Limits total entry count
pub fn extract_bundle(bundle_path: &Path) -> io::Result<tempfile::TempDir> {
    let file = fs::File::open(bundle_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Bad zip: {e}")))?;

    if archive.len() > ZIP_MAX_ENTRY_COUNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "zip archive has {} entries, exceeding limit of {}",
                archive.len(),
                ZIP_MAX_ENTRY_COUNT
            ),
        ));
    }

    let tmp = tempfile::TempDir::new()?;
    let mut seen_names = std::collections::HashSet::new();
    let mut total_extracted: u64 = 0;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Zip entry error: {e}")))?;

        let name = entry.name().to_string();

        // Validate UTF-8
        if name.contains('\u{FFFD}') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("zip entry {i} has non-UTF-8 name"),
            ));
        }

        // Validate entry name safety
        validate_zip_entry_name(&name)?;

        // Reject duplicates
        if !seen_names.insert(name.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("zip archive contains duplicate entry: {name}"),
            ));
        }

        // Reject symlinks
        if entry.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("zip entry is a symlink (rejected for security): {name}"),
            ));
        }

        // Per-entry size limit
        if entry.size() > ZIP_MAX_ENTRY_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "zip entry {name} exceeds size limit ({} > {} bytes)",
                    entry.size(),
                    ZIP_MAX_ENTRY_SIZE
                ),
            ));
        }

        // Total size limit
        total_extracted = total_extracted.checked_add(entry.size()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("total extraction size overflow at entry {name}"),
            )
        })?;
        if total_extracted > ZIP_MAX_TOTAL_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "total extraction size exceeds limit ({total_extracted} > {ZIP_MAX_TOTAL_SIZE} bytes)"
                ),
            ));
        }

        let out_path = tmp.path().join(&name);

        if entry.is_dir() {
            fs::create_dir_all(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }

            // Reject if output path is already a symlink on disk
            if out_path.exists()
                && fs::symlink_metadata(&out_path)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "output path is a symlink (rejected for security): {}",
                        out_path.display()
                    ),
                ));
            }

            let mut out_file = fs::File::create(&out_path)?;
            let bytes_copied = io::copy(&mut entry, &mut out_file)?;
            if bytes_copied > ZIP_MAX_ENTRY_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "zip entry {name} actual size exceeds limit ({bytes_copied} bytes)"
                    ),
                ));
            }
        }
    }

    Ok(tmp)
}

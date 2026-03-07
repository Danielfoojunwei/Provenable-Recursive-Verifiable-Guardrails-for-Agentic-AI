//! Bundle packaging: export and extraction of .aegx.zip bundles.
//!
//! Security hardening (from aegx + aer):
//! - Rejects path traversal, absolute paths, symlinks
//! - Per-entry size limit (1 GB), total extraction limit (10 GB)
//! - Rejects duplicate entries, validates UTF-8 names
//! - Entry count limit (100,000)

use aegx_records::{audit_chain, config, records};
use aegx_types::*;
use chrono::Utc;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use uuid::Uuid;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

use crate::report;

/// Maximum size of a single extracted zip entry (1 GB).
const ZIP_MAX_ENTRY_SIZE: u64 = 1_073_741_824;
/// Maximum total extracted size across all entries (10 GB).
const ZIP_MAX_TOTAL_SIZE: u64 = 10_737_418_240;
/// Maximum number of entries allowed in a zip archive.
const ZIP_MAX_ENTRY_COUNT: usize = 100_000;

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
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

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

    // Generate and write reports
    let report_md = report::generate_markdown_report(&filtered_records, &audit_entries);
    zip.start_file("report.md", options)?;
    zip.write_all(report_md.as_bytes())?;

    let report_json = report::generate_json_report(&filtered_records, &audit_entries)?;
    zip.start_file("report.json", options)?;
    zip.write_all(report_json.as_bytes())?;

    zip.finish()?;
    Ok(bundle_path.to_string_lossy().to_string())
}

/// Initialize a new AEGX bundle directory (aegx format).
pub fn init_bundle(bundle_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(bundle_dir)?;
    fs::create_dir_all(bundle_dir.join("blobs"))?;

    let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let manifest = serde_json::json!({
        "aegx_version": "0.1",
        "created_at": now,
        "hash_alg": "sha256",
        "canonicalization": "AEGX_CANON_0_1",
        "root_records": [],
        "record_count": 0,
        "blob_count": 0,
        "audit_head": "0000000000000000000000000000000000000000000000000000000000000000"
    });

    let manifest_str = serde_json::to_string_pretty(&manifest)?;
    fs::write(bundle_dir.join("manifest.json"), manifest_str)?;
    fs::write(bundle_dir.join("records.jsonl"), "")?;
    fs::write(bundle_dir.join("audit-log.jsonl"), "")?;
    Ok(())
}

/// Add a blob file to a bundle directory. Returns the SHA-256 hex of the blob.
pub fn add_blob(bundle_dir: &Path, file_path: &Path) -> io::Result<String> {
    let data = fs::read(file_path)?;
    let hash = sha256_hex(&data);
    let blob_path = bundle_dir.join("blobs").join(&hash);

    if blob_path.exists() {
        let existing = fs::read(&blob_path)?;
        if existing != data {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("blob {} already exists with different content", hash),
            ));
        }
    } else {
        fs::write(&blob_path, &data)?;
    }
    Ok(hash)
}

/// Export a bundle directory to a zip file (aegx format).
pub fn export_dir_to_zip(bundle_dir: &Path, zip_path: &Path) -> io::Result<()> {
    let file = fs::File::create(zip_path)?;
    let mut zip_writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for entry in walkdir::WalkDir::new(bundle_dir)
        .sort_by_file_name()
        .into_iter()
    {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(bundle_dir)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if relative.as_os_str().is_empty() {
            continue;
        }

        let name = relative.to_string_lossy().replace('\\', "/");

        if path.is_dir() {
            zip_writer.add_directory(format!("{}/", name), options)?;
        } else {
            zip_writer.start_file(&name, options)?;
            let mut f = fs::File::open(path)?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            zip_writer.write_all(&buf)?;
        }
    }

    zip_writer.finish()?;
    Ok(())
}

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
/// - Rejects path traversal, absolute paths, symlinks
/// - Per-entry size limit (1 GB), total extraction limit (10 GB)
/// - Duplicate entry rejection, UTF-8 validation, entry count limit
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
    let mut seen_names = HashSet::new();
    let mut total_extracted: u64 = 0;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Zip entry error: {e}"))
        })?;

        let name = entry.name().to_string();

        if name.contains('\u{FFFD}') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("zip entry {i} has non-UTF-8 name"),
            ));
        }

        validate_zip_entry_name(&name)?;

        if !seen_names.insert(name.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("zip archive contains duplicate entry: {name}"),
            ));
        }

        if entry.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("zip entry is a symlink (rejected for security): {name}"),
            ));
        }

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
                    format!("zip entry {name} actual size exceeds limit ({bytes_copied} bytes)"),
                ));
            }
        }
    }

    Ok(tmp)
}

/// Import a zip file into a bundle directory (aegx format).
pub fn import_zip(zip_path: &Path, out_dir: &Path) -> io::Result<()> {
    let tmp = extract_bundle(zip_path)?;
    // Copy extracted contents to out_dir
    fs::create_dir_all(out_dir)?;
    for entry in walkdir::WalkDir::new(tmp.path()).into_iter() {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(tmp.path())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if relative.as_os_str().is_empty() {
            continue;
        }

        let dest = out_dir.join(relative);
        if path.is_dir() {
            fs::create_dir_all(&dest)?;
        } else {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(path, &dest)?;
        }
    }
    Ok(())
}

/// Read the manifest from a bundle directory.
pub fn read_manifest(bundle_dir: &Path) -> io::Result<serde_json::Value> {
    let path = bundle_dir.join("manifest.json");
    let content = fs::read_to_string(&path)?;
    serde_json::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Count blobs in the blobs/ directory.
pub fn count_blobs(bundle_dir: &Path) -> io::Result<u64> {
    let blobs_dir = bundle_dir.join("blobs");
    if !blobs_dir.exists() {
        return Ok(0);
    }
    let mut count = 0u64;
    for entry in fs::read_dir(&blobs_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != ".keep" {
                count += 1;
            }
        }
    }
    Ok(count)
}

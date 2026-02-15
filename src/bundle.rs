use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::hash::sha256_hex;

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Initialize a new AEGX bundle directory.
pub fn init_bundle(bundle_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(bundle_dir).map_err(|e| format!("cannot create bundle dir: {}", e))?;
    fs::create_dir_all(bundle_dir.join("blobs"))
        .map_err(|e| format!("cannot create blobs dir: {}", e))?;

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let manifest = serde_json::json!({
        "aegx_version": "0.1",
        "created_at": now,
        "hash_alg": "sha256",
        "canonicalization": "AEGX_CANON_0_1",
        "root_records": [],
        "record_count": 0,
        "blob_count": 0,
        "audit_head": ZERO_HASH
    });

    let manifest_str = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("serialize manifest: {}", e))?;
    fs::write(bundle_dir.join("manifest.json"), manifest_str)
        .map_err(|e| format!("write manifest: {}", e))?;

    // Create empty JSONL files
    fs::write(bundle_dir.join("records.jsonl"), "")
        .map_err(|e| format!("write records.jsonl: {}", e))?;
    fs::write(bundle_dir.join("audit-log.jsonl"), "")
        .map_err(|e| format!("write audit-log.jsonl: {}", e))?;

    Ok(())
}

/// Add a blob file to the bundle. Returns the sha256 hex of the blob.
pub fn add_blob(bundle_dir: &Path, file_path: &Path) -> Result<String, String> {
    let data =
        fs::read(file_path).map_err(|e| format!("cannot read {}: {}", file_path.display(), e))?;
    let hash = sha256_hex(&data);
    let blob_path = bundle_dir.join("blobs").join(&hash);

    if blob_path.exists() {
        // Verify identical contents
        let existing =
            fs::read(&blob_path).map_err(|e| format!("cannot read existing blob: {}", e))?;
        if existing != data {
            return Err(format!(
                "blob {} already exists with different content",
                hash
            ));
        }
    } else {
        fs::write(&blob_path, &data).map_err(|e| format!("cannot write blob: {}", e))?;
    }

    Ok(hash)
}

/// Read the manifest from a bundle directory.
pub fn read_manifest(bundle_dir: &Path) -> Result<serde_json::Value, String> {
    let path = bundle_dir.join("manifest.json");
    let content = fs::read_to_string(&path).map_err(|e| format!("cannot read manifest: {}", e))?;
    serde_json::from_str(&content).map_err(|e| format!("cannot parse manifest: {}", e))
}

/// Write the manifest to a bundle directory.
pub fn write_manifest(bundle_dir: &Path, manifest: &serde_json::Value) -> Result<(), String> {
    let path = bundle_dir.join("manifest.json");
    let content =
        serde_json::to_string_pretty(manifest).map_err(|e| format!("serialize manifest: {}", e))?;
    fs::write(&path, content).map_err(|e| format!("write manifest: {}", e))?;
    Ok(())
}

/// Update manifest record_count, blob_count, audit_head, and root_records.
pub fn update_manifest(
    bundle_dir: &Path,
    record_count: u64,
    blob_count: u64,
    audit_head: &str,
    root_records: &[String],
) -> Result<(), String> {
    let mut manifest = read_manifest(bundle_dir)?;
    let obj = manifest
        .as_object_mut()
        .ok_or("manifest is not an object")?;
    obj.insert(
        "record_count".to_string(),
        serde_json::Value::Number(record_count.into()),
    );
    obj.insert(
        "blob_count".to_string(),
        serde_json::Value::Number(blob_count.into()),
    );
    obj.insert(
        "audit_head".to_string(),
        serde_json::Value::String(audit_head.to_string()),
    );
    obj.insert(
        "root_records".to_string(),
        serde_json::to_value(root_records).unwrap(),
    );
    write_manifest(bundle_dir, &manifest)
}

/// Count blobs in the blobs/ directory.
pub fn count_blobs(bundle_dir: &Path) -> Result<u64, String> {
    let blobs_dir = bundle_dir.join("blobs");
    if !blobs_dir.exists() {
        return Ok(0);
    }
    let mut count = 0u64;
    for entry in fs::read_dir(&blobs_dir).map_err(|e| format!("cannot read blobs dir: {}", e))? {
        let entry = entry.map_err(|e| format!("readdir error: {}", e))?;
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != ".keep" {
                count += 1;
            }
        }
    }
    Ok(count)
}

/// Export a bundle directory to a zip file.
pub fn export_zip(bundle_dir: &Path, zip_path: &Path) -> Result<(), String> {
    let file = fs::File::create(zip_path).map_err(|e| format!("cannot create zip: {}", e))?;
    let mut zip_writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Walk the bundle directory
    for entry in walkdir::WalkDir::new(bundle_dir)
        .sort_by_file_name()
        .into_iter()
    {
        let entry = entry.map_err(|e| format!("walkdir error: {}", e))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(bundle_dir)
            .map_err(|e| format!("strip prefix: {}", e))?;

        if relative.as_os_str().is_empty() {
            continue;
        }

        let name = relative.to_string_lossy().replace('\\', "/");

        if path.is_dir() {
            zip_writer
                .add_directory(format!("{}/", name), options)
                .map_err(|e| format!("zip add dir: {}", e))?;
        } else {
            zip_writer
                .start_file(&name, options)
                .map_err(|e| format!("zip start file: {}", e))?;
            let mut f =
                fs::File::open(path).map_err(|e| format!("open {}: {}", path.display(), e))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)
                .map_err(|e| format!("read {}: {}", path.display(), e))?;
            zip_writer
                .write_all(&buf)
                .map_err(|e| format!("zip write: {}", e))?;
        }
    }

    zip_writer
        .finish()
        .map_err(|e| format!("zip finish: {}", e))?;
    Ok(())
}

/// Maximum size of a single extracted zip entry (1 GB).
const ZIP_MAX_ENTRY_SIZE: u64 = 1_073_741_824;

/// Maximum total extracted size across all entries (10 GB).
const ZIP_MAX_TOTAL_SIZE: u64 = 10_737_418_240;

/// Maximum number of entries allowed in a zip archive.
const ZIP_MAX_ENTRY_COUNT: usize = 100_000;

/// Validate that a zip entry name is safe for extraction.
/// Rejects path traversal, absolute paths, and non-UTF-8 names.
fn validate_zip_entry_name(name: &str) -> Result<(), String> {
    // Reject empty names
    if name.is_empty() {
        return Err("zip entry has empty name".to_string());
    }

    // Reject absolute paths
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(format!("zip entry has absolute path: {}", name));
    }

    // Reject Windows-style absolute paths (e.g., "C:\...")
    if name.len() >= 2 && name.as_bytes()[1] == b':' {
        return Err(format!("zip entry has Windows absolute path: {}", name));
    }

    // Reject path traversal components
    for component in Path::new(name).components() {
        if let std::path::Component::ParentDir = component {
            return Err(format!(
                "zip entry contains path traversal (..): {}",
                name
            ));
        }
    }

    // Reject names containing null bytes
    if name.contains('\0') {
        return Err(format!("zip entry name contains null byte: {}", name));
    }

    Ok(())
}

/// Validate that the resolved output path stays within the target directory.
fn validate_path_containment(out_dir: &Path, out_path: &Path) -> Result<(), String> {
    let canonical_out_dir = out_dir
        .canonicalize()
        .map_err(|e| format!("cannot canonicalize output dir: {}", e))?;
    // For paths that don't exist yet, canonicalize the parent and append the filename
    let canonical_path = if out_path.exists() {
        out_path
            .canonicalize()
            .map_err(|e| format!("cannot canonicalize path: {}", e))?
    } else {
        // Canonicalize the deepest existing ancestor
        let mut ancestor = out_path.to_path_buf();
        let mut suffix_parts = Vec::new();
        loop {
            if ancestor.exists() {
                let base = ancestor
                    .canonicalize()
                    .map_err(|e| format!("cannot canonicalize ancestor: {}", e))?;
                let mut result = base;
                for part in suffix_parts.into_iter().rev() {
                    result = result.join(part);
                }
                return if result.starts_with(&canonical_out_dir) {
                    Ok(())
                } else {
                    Err(format!(
                        "zip entry path escapes output directory: {}",
                        out_path.display()
                    ))
                };
            }
            if let Some(file_name) = ancestor.file_name() {
                suffix_parts.push(file_name.to_os_string());
            }
            if !ancestor.pop() {
                break;
            }
        }
        return Err(format!(
            "cannot resolve zip entry path: {}",
            out_path.display()
        ));
    };

    if !canonical_path.starts_with(&canonical_out_dir) {
        return Err(format!(
            "zip entry path escapes output directory: {}",
            out_path.display()
        ));
    }
    Ok(())
}

/// Import a zip file into a bundle directory.
///
/// Security hardening:
/// - Rejects path traversal (`..` components, absolute paths)
/// - Rejects symlink entries
/// - Enforces per-entry size limit (1 GB) and total extraction limit (10 GB)
/// - Rejects duplicate entry names
/// - Validates UTF-8 entry names
/// - Limits total entry count
pub fn import_zip(zip_path: &Path, out_dir: &Path) -> Result<(), String> {
    let file = fs::File::open(zip_path).map_err(|e| format!("cannot open zip: {}", e))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("cannot read zip: {}", e))?;

    // Reject archives with too many entries
    if archive.len() > ZIP_MAX_ENTRY_COUNT {
        return Err(format!(
            "zip archive has {} entries, exceeding limit of {}",
            archive.len(),
            ZIP_MAX_ENTRY_COUNT
        ));
    }

    // Ensure output directory exists for containment validation
    fs::create_dir_all(out_dir).map_err(|e| format!("cannot create output dir: {}", e))?;

    // Track seen entry names to reject duplicates
    let mut seen_names = std::collections::HashSet::new();
    let mut total_extracted: u64 = 0;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("zip entry {}: {}", i, e))?;

        let name = entry.name().to_string();

        // Validate UTF-8 (entry.name() already converts, but check for lossy conversion)
        if name.contains('\u{FFFD}') {
            return Err(format!("zip entry {} has non-UTF-8 name", i));
        }

        // Validate entry name for path traversal and absolute paths
        validate_zip_entry_name(&name)?;

        // Reject duplicate entry names
        if !seen_names.insert(name.clone()) {
            return Err(format!("zip archive contains duplicate entry: {}", name));
        }

        // Reject symlink entries
        if entry.is_symlink() {
            return Err(format!(
                "zip entry is a symlink (rejected for security): {}",
                name
            ));
        }

        // Check per-entry size limit (uncompressed size)
        if entry.size() > ZIP_MAX_ENTRY_SIZE {
            return Err(format!(
                "zip entry {} exceeds size limit ({} > {} bytes)",
                name,
                entry.size(),
                ZIP_MAX_ENTRY_SIZE
            ));
        }

        // Check total extraction size limit
        total_extracted = total_extracted.checked_add(entry.size()).ok_or_else(|| {
            format!("total extraction size overflow at entry {}", name)
        })?;
        if total_extracted > ZIP_MAX_TOTAL_SIZE {
            return Err(format!(
                "total extraction size exceeds limit ({} > {} bytes)",
                total_extracted, ZIP_MAX_TOTAL_SIZE
            ));
        }

        let out_path: PathBuf = out_dir.join(&name);

        if entry.is_dir() {
            fs::create_dir_all(&out_path)
                .map_err(|e| format!("create dir {}: {}", out_path.display(), e))?;
        } else {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("create parent dir: {}", e))?;
            }

            // Validate that resolved path stays within output directory
            validate_path_containment(out_dir, &out_path)?;

            // Read with size cap enforcement (defense-in-depth beyond declared size)
            let mut buf = Vec::new();
            let bytes_read = entry
                .read_to_end(&mut buf)
                .map_err(|e| format!("read zip entry: {}", e))?;
            if bytes_read as u64 > ZIP_MAX_ENTRY_SIZE {
                return Err(format!(
                    "zip entry {} actual size exceeds limit ({} bytes)",
                    name, bytes_read
                ));
            }

            // Reject if the output path is a symlink on disk (defense-in-depth)
            if out_path.exists() && fs::symlink_metadata(&out_path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                return Err(format!(
                    "output path is a symlink (rejected for security): {}",
                    out_path.display()
                ));
            }

            fs::write(&out_path, &buf)
                .map_err(|e| format!("write {}: {}", out_path.display(), e))?;
        }
    }
    Ok(())
}

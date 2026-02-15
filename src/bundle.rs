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

/// Import a zip file into a bundle directory.
pub fn import_zip(zip_path: &Path, out_dir: &Path) -> Result<(), String> {
    let file = fs::File::open(zip_path).map_err(|e| format!("cannot open zip: {}", e))?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| format!("cannot read zip: {}", e))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("zip entry {}: {}", i, e))?;

        let name = entry.name().to_string();
        let out_path: PathBuf = out_dir.join(&name);

        if entry.is_dir() {
            fs::create_dir_all(&out_path)
                .map_err(|e| format!("create dir {}: {}", out_path.display(), e))?;
        } else {
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(|e| format!("create parent dir: {}", e))?;
            }
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .map_err(|e| format!("read zip entry: {}", e))?;
            fs::write(&out_path, &buf)
                .map_err(|e| format!("write {}: {}", out_path.display(), e))?;
        }
    }
    Ok(())
}

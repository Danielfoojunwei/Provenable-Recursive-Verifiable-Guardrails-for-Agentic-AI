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

/// Extract a bundle to a temporary directory for verification.
pub fn extract_bundle(bundle_path: &Path) -> io::Result<tempfile::TempDir> {
    let file = fs::File::open(bundle_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Bad zip: {e}")))?;

    let tmp = tempfile::TempDir::new()?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Zip entry error: {e}")))?;
        let name = entry.name().to_string();
        let out_path = tmp.path().join(&name);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out_file = fs::File::create(&out_path)?;
        io::copy(&mut entry, &mut out_file)?;
    }

    Ok(tmp)
}

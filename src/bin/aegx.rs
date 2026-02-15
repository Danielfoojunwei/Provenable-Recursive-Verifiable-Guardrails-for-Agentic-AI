use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

use aegx::audit;
use aegx::bundle;
use aegx::canonical::normalize_timestamp;
use aegx::records::{self, Payload, Principal, RecordType, TypedRecord};
use aegx::verify;

#[derive(Parser)]
#[command(name = "aegx", about = "AEGX v0.1 evidence bundle tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new AEGX bundle
    Init {
        bundle_dir: PathBuf,
        #[arg(long)]
        zip_out: Option<PathBuf>,
    },
    /// Add a blob file to the bundle
    AddBlob {
        bundle: PathBuf,
        file_path: PathBuf,
        #[arg(long, default_value = "application/octet-stream")]
        mime: String,
    },
    /// Add a typed record to the bundle
    AddRecord {
        bundle: PathBuf,
        #[arg(long, value_name = "TYPE")]
        r#type: String,
        #[arg(long)]
        principal: String,
        #[arg(long)]
        meta: String,
        #[arg(long, value_delimiter = ',')]
        parents: Vec<String>,
        #[arg(long, conflicts_with_all = &["blob", "mime_ref", "size"])]
        inline: Option<String>,
        #[arg(long, requires_all = &["mime_ref", "size"])]
        blob: Option<String>,
        #[arg(long = "mime", id = "mime_ref")]
        mime_ref: Option<String>,
        #[arg(long)]
        size: Option<u64>,
    },
    /// Export bundle directory to zip
    Export {
        bundle_dir: PathBuf,
        out_zip: PathBuf,
    },
    /// Import zip to bundle directory
    Import {
        bundle_zip: PathBuf,
        out_dir: PathBuf,
    },
    /// Verify bundle integrity
    Verify { bundle: PathBuf },
    /// Summarize bundle contents
    Summarize { bundle: PathBuf },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            bundle_dir,
            zip_out,
        } => {
            if let Err(e) = bundle::init_bundle(&bundle_dir) {
                eprintln!("error: {}", e);
                process::exit(verify::EXIT_IO_ERROR);
            }
            println!("Initialized bundle: {}", bundle_dir.display());
            if let Some(zip_path) = zip_out {
                if let Err(e) = bundle::export_zip(&bundle_dir, &zip_path) {
                    eprintln!("error: {}", e);
                    process::exit(verify::EXIT_IO_ERROR);
                }
                println!("Exported to: {}", zip_path.display());
            }
        }
        Commands::AddBlob {
            bundle,
            file_path,
            mime: _,
        } => match bundle::add_blob(&bundle, &file_path) {
            Ok(hash) => println!("{}", hash),
            Err(e) => {
                eprintln!("error: {}", e);
                process::exit(verify::EXIT_IO_ERROR);
            }
        },
        Commands::AddRecord {
            bundle,
            r#type,
            principal,
            meta,
            parents,
            inline,
            blob,
            mime_ref,
            size,
        } => {
            let record_type: RecordType = match r#type.parse() {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(1);
                }
            };
            let principal: Principal = match principal.parse() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(1);
                }
            };
            let meta_value: serde_json::Value = match serde_json::from_str(&meta) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: invalid meta JSON: {}", e);
                    process::exit(1);
                }
            };

            // Normalize meta.ts
            let meta_normalized = records::normalize_meta(&meta_value);

            // Filter out empty parent strings
            let parents: Vec<String> = parents.into_iter().filter(|p| !p.is_empty()).collect();

            let payload = if let Some(inline_json) = inline {
                let inline_val: serde_json::Value = match serde_json::from_str(&inline_json) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("error: invalid inline JSON: {}", e);
                        process::exit(1);
                    }
                };
                Payload::Inline { inline: inline_val }
            } else if let (Some(blob_sha), Some(mime), Some(sz)) = (blob, mime_ref, size) {
                Payload::Blob {
                    blob: blob_sha,
                    mime,
                    size: sz,
                }
            } else {
                eprintln!("error: must specify --inline or --blob/--mime/--size");
                process::exit(1);
            };

            let taint: Vec<String> = Vec::new();
            let record_id = records::compute_record_id(
                &record_type,
                &principal,
                &taint,
                &parents,
                &meta_normalized,
                &payload,
            );

            let record = TypedRecord {
                record_id: record_id.clone(),
                record_type,
                principal,
                taint,
                parents,
                meta: meta_normalized,
                payload,
                schema: Some("0.1".to_string()),
                extensions: None,
            };

            // Append record
            let records_path = bundle.join("records.jsonl");
            if let Err(e) = records::append_record(&records_path, &record) {
                eprintln!("error: {}", e);
                process::exit(verify::EXIT_IO_ERROR);
            }

            // Append audit entry
            let audit_path = bundle.join("audit-log.jsonl");
            let prev = match audit::get_audit_head(&audit_path) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(verify::EXIT_IO_ERROR);
                }
            };
            let entries = match audit::read_audit_log(&audit_path) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(verify::EXIT_IO_ERROR);
                }
            };
            let idx = entries.len() as u64;

            let ts = match record.meta.get("ts").and_then(|v| v.as_str()) {
                Some(t) => match normalize_timestamp(t) {
                    Ok(n) => n,
                    Err(_) => chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                },
                None => chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            };

            let audit_entry = audit::new_audit_entry(idx, &ts, &record_id, &prev);
            if let Err(e) = audit::append_audit_entry(&audit_path, &audit_entry) {
                eprintln!("error: {}", e);
                process::exit(verify::EXIT_IO_ERROR);
            }

            // Update manifest
            let new_record_count = idx + 1;
            let blob_count = match bundle::count_blobs(&bundle) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(verify::EXIT_IO_ERROR);
                }
            };

            // Determine root records: records with no parents
            let all_records = match records::read_records(&records_path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(verify::EXIT_IO_ERROR);
                }
            };
            let root_records: Vec<String> = all_records
                .iter()
                .filter(|r| r.parents.is_empty())
                .map(|r| r.record_id.clone())
                .collect();

            if let Err(e) = bundle::update_manifest(
                &bundle,
                new_record_count,
                blob_count,
                &audit_entry.entry_hash,
                &root_records,
            ) {
                eprintln!("error: {}", e);
                process::exit(verify::EXIT_IO_ERROR);
            }

            println!("{}", record_id);
        }
        Commands::Export {
            bundle_dir,
            out_zip,
        } => {
            if let Err(e) = bundle::export_zip(&bundle_dir, &out_zip) {
                eprintln!("error: {}", e);
                process::exit(verify::EXIT_IO_ERROR);
            }
            println!("Exported: {}", out_zip.display());
        }
        Commands::Import {
            bundle_zip,
            out_dir,
        } => {
            if let Err(e) = bundle::import_zip(&bundle_zip, &out_dir) {
                eprintln!("error: {}", e);
                process::exit(verify::EXIT_IO_ERROR);
            }
            println!("Imported: {}", out_dir.display());
        }
        Commands::Verify { bundle } => {
            let result = verify::verify_bundle(&bundle);
            if result.is_ok() {
                println!("Verification: PASS");
            } else {
                for e in &result.errors {
                    eprintln!("{}", e);
                }
                process::exit(result.exit_code);
            }
        }
        Commands::Summarize { bundle } => match verify::summarize_bundle(&bundle) {
            Ok(summary) => print!("{}", summary),
            Err(e) => {
                eprintln!("error: {}", e);
                process::exit(verify::EXIT_IO_ERROR);
            }
        },
    }
}

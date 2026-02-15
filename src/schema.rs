use jsonschema::Validator;
use serde_json::Value;
use std::path::Path;
use std::sync::OnceLock;

static MANIFEST_SCHEMA: OnceLock<Value> = OnceLock::new();
static RECORD_SCHEMA: OnceLock<Value> = OnceLock::new();
static AUDIT_ENTRY_SCHEMA: OnceLock<Value> = OnceLock::new();

fn find_schemas_dir() -> std::path::PathBuf {
    // Try relative to the executable first, then CARGO_MANIFEST_DIR, then cwd
    if let Ok(exe) = std::env::current_exe() {
        // In installed/built binary: schemas/ is sibling to binary's parent
        let exe_dir = exe.parent().unwrap_or(Path::new("."));
        let candidate = exe_dir.join("../schemas");
        if candidate.exists() {
            return candidate;
        }
        let candidate = exe_dir.join("../../schemas");
        if candidate.exists() {
            return candidate;
        }
    }
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let candidate = Path::new(&dir).join("schemas");
        if candidate.exists() {
            return candidate;
        }
    }
    // Fallback: current directory
    Path::new("schemas").to_path_buf()
}

fn load_schema(filename: &str) -> Value {
    let dir = find_schemas_dir();
    let path = dir.join(filename);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Cannot read schema {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Cannot parse schema {}: {}", path.display(), e))
}

pub fn manifest_schema() -> &'static Value {
    MANIFEST_SCHEMA.get_or_init(|| load_schema("manifest.schema.json"))
}

pub fn record_schema() -> &'static Value {
    RECORD_SCHEMA.get_or_init(|| load_schema("record.schema.json"))
}

pub fn audit_entry_schema() -> &'static Value {
    AUDIT_ENTRY_SCHEMA.get_or_init(|| load_schema("audit-entry.schema.json"))
}

pub fn validate_manifest(value: &Value) -> Result<(), Vec<String>> {
    validate_against(value, manifest_schema())
}

pub fn validate_record(value: &Value) -> Result<(), Vec<String>> {
    validate_against(value, record_schema())
}

pub fn validate_audit_entry(value: &Value) -> Result<(), Vec<String>> {
    validate_against(value, audit_entry_schema())
}

fn validate_against(value: &Value, schema: &Value) -> Result<(), Vec<String>> {
    let validator = Validator::new(schema).expect("schema compilation failed");
    let result = validator.validate(value);
    if result.is_ok() {
        Ok(())
    } else {
        let errors: Vec<String> = validator
            .iter_errors(value)
            .map(|e| format!("{} at {}", e, e.instance_path))
            .collect();
        Err(errors)
    }
}

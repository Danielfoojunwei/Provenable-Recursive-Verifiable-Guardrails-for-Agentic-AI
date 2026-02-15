pub mod bundle_cmd;
pub mod init;
pub mod prove_cmd;
pub mod report_cmd;
pub mod rollback_cmd;
pub mod snapshot_cmd;
pub mod verify_cmd;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "proven-aer")]
#[command(about = "Agent Evidence & Recovery (AER) — evidence bundles, CPI/MI guard, RVU rollback")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize AER in the current Provenable.ai state directory
    Init,
    /// Snapshot management
    Snapshot {
        #[command(subcommand)]
        action: SnapshotAction,
    },
    /// Rollback to a previous snapshot
    Rollback {
        /// Snapshot ID to rollback to
        snapshot_id: String,
    },
    /// Export an AEGX evidence bundle
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
    /// Verify an AEGX evidence bundle
    Verify {
        /// Path to the bundle .aegx.zip file
        bundle_path: String,
    },
    /// Generate a report from an AEGX evidence bundle
    Report {
        /// Path to the bundle .aegx.zip file
        bundle_path: String,
    },
    /// Query what Provenable.ai has protected — the /prove interface
    Prove {
        /// Filter alerts since this ISO 8601 timestamp
        #[arg(long)]
        since: Option<String>,
        /// Filter alerts until this ISO 8601 timestamp
        #[arg(long)]
        until: Option<String>,
        /// Filter by threat category: CPI, MI, TAINT, PROXY, RATE_LIMIT, INJECTION
        #[arg(long)]
        category: Option<String>,
        /// Minimum severity: INFO, MEDIUM, HIGH, CRITICAL
        #[arg(long)]
        severity: Option<String>,
        /// Maximum number of alerts to return
        #[arg(long)]
        limit: Option<usize>,
        /// Output as JSON (for API/bot consumption)
        #[arg(long)]
        json: bool,
    },
    /// Show AER status
    Status,
}

#[derive(Subcommand)]
pub enum SnapshotAction {
    /// Create a new snapshot
    Create {
        /// Name for the snapshot
        name: String,
        /// Scope: full, control-plane, or memory
        #[arg(long, default_value = "full")]
        scope: String,
    },
    /// List existing snapshots
    List,
}

#[derive(Subcommand)]
pub enum BundleAction {
    /// Export an evidence bundle
    Export {
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<String>,
        /// Filter records since this ISO 8601 timestamp
        #[arg(long)]
        since: Option<String>,
    },
}

/// Run the CLI.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => init::run()?,
        Commands::Snapshot { action } => match action {
            SnapshotAction::Create { name, scope } => snapshot_cmd::create(&name, &scope)?,
            SnapshotAction::List => snapshot_cmd::list()?,
        },
        Commands::Rollback { snapshot_id } => rollback_cmd::run(&snapshot_id)?,
        Commands::Bundle { action } => match action {
            BundleAction::Export { agent, since } => {
                bundle_cmd::export(agent.as_deref(), since.as_deref())?
            }
        },
        Commands::Verify { bundle_path } => verify_cmd::run(&bundle_path)?,
        Commands::Report { bundle_path } => report_cmd::run(&bundle_path)?,
        Commands::Prove {
            since,
            until,
            category,
            severity,
            limit,
            json,
        } => prove_cmd::run(
            since.as_deref(),
            until.as_deref(),
            category.as_deref(),
            severity.as_deref(),
            limit,
            json,
        )?,
        Commands::Status => status()?,
    }

    Ok(())
}

fn status() -> Result<(), Box<dyn std::error::Error>> {
    let aer_root = crate::config::aer_root();
    if !aer_root.exists() {
        println!("AER: not initialized");
        println!("Run `proven-aer init` to set up AER.");
        return Ok(());
    }

    println!("AER: initialized");
    println!(
        "State directory: {}",
        crate::config::resolve_state_dir().display()
    );
    println!("AER root: {}", aer_root.display());

    let record_count = crate::records::record_count()?;
    println!("Records: {}", record_count);

    let entries = crate::audit_chain::read_all_entries()?;
    println!("Audit chain entries: {}", entries.len());

    let snapshots = crate::snapshot::list_snapshots()?;
    println!("Snapshots: {}", snapshots.len());

    let alert_count = crate::alerts::alert_count()?;
    println!("Threat alerts: {}", alert_count);

    // Verify chain integrity
    match crate::audit_chain::verify_chain()? {
        Ok(_) => println!("Audit chain: VALID"),
        Err(e) => println!("Audit chain: BROKEN — {e}"),
    }

    Ok(())
}

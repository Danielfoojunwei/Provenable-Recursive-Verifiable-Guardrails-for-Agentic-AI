use clap::{Parser, Subcommand};

mod manifest;
mod commands;

#[derive(Parser)]
#[command(name = "installer-tools")]
#[command(about = "Provenable.ai AER installer tooling — validate, checksum, pin")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate manifest/manifest.json schema, checksums, and consistency
    Validate {
        /// Path to manifest.json (default: ../manifest/manifest.json relative to binary)
        #[arg(long)]
        manifest: Option<String>,
    },
    /// Compute SHA-256 checksums for installer artifacts and update manifest
    GenChecksums {
        /// Path to installer repo root (default: .. relative to binary)
        #[arg(long)]
        repo_root: Option<String>,
    },
    /// Pin a new Proven version in the manifest
    PinVersion {
        /// Proven version to pin (X.Y.Z)
        #[arg(long)]
        version: String,
        /// Also set as default version
        #[arg(long)]
        set_default: bool,
        /// Skip npm verification (for testing)
        #[arg(long)]
        skip_npm_check: bool,
        /// Path to installer repo root
        #[arg(long)]
        repo_root: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Validate { manifest } => commands::validate_run(manifest),
        Commands::GenChecksums { repo_root } => commands::checksums_run(repo_root),
        Commands::PinVersion {
            version,
            set_default,
            skip_npm_check,
            repo_root,
        } => commands::pin_run(version, set_default, skip_npm_check, repo_root),
    };

    if let Err(e) = result {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}

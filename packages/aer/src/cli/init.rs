use crate::config;
use crate::policy;

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing AER...");

    // Create directory structure
    config::ensure_aer_dirs()?;
    println!(
        "  Created AER directories under {}",
        config::aer_root().display()
    );

    // Install default policy
    let default = policy::default_policy();
    let policy_path = config::default_policy_file();
    policy::save_policy(&default, &policy_path)?;
    println!("  Installed default policy: {}", policy_path.display());

    // Ensure workspace exists
    crate::workspace::ensure_workspace()?;
    println!(
        "  Ensured workspace directory: {}",
        config::workspace_dir().display()
    );

    println!();
    println!("AER initialized successfully.");
    println!();
    println!("Policy summary:");
    println!("  - CPI: deny control-plane changes from non-USER/SYS principals");
    println!("  - MI: deny memory writes with tainted provenance");
    println!("  - MI: deny memory writes from untrusted principals");
    println!("  - All read operations: allowed");
    println!();
    println!("State directory: {}", config::resolve_state_dir().display());

    Ok(())
}

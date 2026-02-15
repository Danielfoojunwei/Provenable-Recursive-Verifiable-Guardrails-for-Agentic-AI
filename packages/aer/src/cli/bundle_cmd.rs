use crate::bundle;
use chrono::DateTime;

pub fn export(
    agent_id: Option<&str>,
    since: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let since_dt = match since {
        Some(s) => Some(
            DateTime::parse_from_rfc3339(s)
                .map_err(|e| format!("Invalid timestamp '{s}': {e}"))?
                .with_timezone(&chrono::Utc),
        ),
        None => None,
    };

    println!("Exporting AEGX evidence bundle...");
    if let Some(aid) = agent_id {
        println!("  Filter: agent_id = {aid}");
    }
    if let Some(s) = since {
        println!("  Filter: since = {s}");
    }

    let bundle_path = bundle::export_bundle(agent_id, since_dt)?;

    println!();
    println!("Bundle exported: {bundle_path}");

    Ok(())
}

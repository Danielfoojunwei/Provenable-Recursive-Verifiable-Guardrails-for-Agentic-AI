use crate::prove::{self, ProveQuery};
use chrono::DateTime;

pub fn run(
    since: Option<&str>,
    until: Option<&str>,
    category: Option<&str>,
    severity: Option<&str>,
    limit: Option<usize>,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let since_dt = since
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&chrono::Utc))
                .map_err(|e| format!("Invalid --since timestamp: {e}"))
        })
        .transpose()?;

    let until_dt = until
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|d| d.with_timezone(&chrono::Utc))
                .map_err(|e| format!("Invalid --until timestamp: {e}"))
        })
        .transpose()?;

    let category_filter = category
        .map(|c| match c.to_uppercase().as_str() {
            "CPI" | "CPI_VIOLATION" => Ok(crate::alerts::ThreatCategory::CpiViolation),
            "MI" | "MI_VIOLATION" => Ok(crate::alerts::ThreatCategory::MiViolation),
            "TAINT" | "TAINT_BLOCK" => Ok(crate::alerts::ThreatCategory::TaintBlock),
            "PROXY" | "PROXY_MISCONFIG" => Ok(crate::alerts::ThreatCategory::ProxyMisconfig),
            "RATE_LIMIT" => Ok(crate::alerts::ThreatCategory::RateLimitExceeded),
            "INJECTION" => Ok(crate::alerts::ThreatCategory::InjectionSuspect),
            _ => Err(format!(
                "Unknown category '{}'. Valid: CPI, MI, TAINT, PROXY, RATE_LIMIT, INJECTION",
                c
            )),
        })
        .transpose()?;

    let severity_filter = severity
        .map(|s| match s.to_uppercase().as_str() {
            "INFO" => Ok(crate::alerts::AlertSeverity::Info),
            "MEDIUM" => Ok(crate::alerts::AlertSeverity::Medium),
            "HIGH" => Ok(crate::alerts::AlertSeverity::High),
            "CRITICAL" => Ok(crate::alerts::AlertSeverity::Critical),
            _ => Err(format!(
                "Unknown severity '{}'. Valid: INFO, MEDIUM, HIGH, CRITICAL",
                s
            )),
        })
        .transpose()?;

    let query = ProveQuery {
        since: since_dt,
        until: until_dt,
        category: category_filter,
        severity_min: severity_filter,
        limit,
        include_metrics: true,
        include_health: true,
    };

    let response = prove::execute_query(&query)?;

    if json_output {
        let json = prove::format_prove_json(&response)?;
        println!("{}", json);
    } else {
        let formatted = prove::format_prove_response(&response);
        print!("{}", formatted);
    }

    Ok(())
}

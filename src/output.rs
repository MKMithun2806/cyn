use crate::cli::OutputFormat;
use crate::error::CynError;
use crate::feed::FeedInfo;
use crate::scanner::Finding;
use std::collections::HashSet;

/// Print feed status to the terminal.
pub fn print_feed_status(info: &FeedInfo) {
    if !info.exists {
        println!("Feed: not found at {}", info.path);
        println!("Run 'cyn feed update' to download the feed.");
        return;
    }
    println!("Feed path:  {}", info.path);
    println!("Feed version: {}", info.version);
    println!("NVT scripts: {}", info.plugin_count);
}

/// Output scan findings in the requested format.
pub fn output_findings(findings: &[Finding], format: OutputFormat) -> Result<(), CynError> {
    match format {
        OutputFormat::Terminal => print_findings_terminal(findings),
        OutputFormat::Json => print_findings_json(findings),
    }
}

fn print_findings_terminal(findings: &[Finding]) -> Result<(), CynError> {
    let actionable: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding.result_type == "Alarm" || finding.result_type == "Error")
        .collect();

    if actionable.is_empty() {
        println!("No vulnerabilities found.");
        if !findings.is_empty() {
            println!(
                "{} informational result(s) hidden; use --output json to inspect them.",
                findings.len()
            );
        }
        return Ok(());
    }

    let mut seen = HashSet::new();
    let unique: Vec<&Finding> = actionable
        .into_iter()
        .filter(|finding| {
            let key = format!(
                "{}|{}|{}|{}|{}",
                finding.result_type,
                finding.host,
                finding.port.unwrap_or_default(),
                finding.oid,
                finding.description.as_deref().unwrap_or_default()
            );
            seen.insert(key)
        })
        .collect();

    println!("\n=== Findings ({}) ===\n", unique.len());

    for (i, f) in unique.iter().enumerate() {
        let severity = f
            .severity
            .map(|s| format!("{s:.1}"))
            .unwrap_or_else(|| "N/A".into());

        println!("{}. [{}] {}", i + 1, severity, f.name);
        println!("   Host:     {}", f.host);
        if let Some(port) = &f.port {
            let proto = f.protocol.as_deref().unwrap_or("tcp");
            println!("   Port:     {port}/{proto}");
        }
        println!("   OID:      {}", f.oid);
        println!("   Type:     {}", f.result_type);
        if let Some(desc) = &f.description {
            println!("   Summary:  {desc}");
        }
        if !f.cves.is_empty() {
            println!("   CVEs:     {}", f.cves.join(", "));
        }
        if let Some(sol) = &f.solution {
            println!("   Solution: {sol}");
        }
        if !f.references.is_empty() {
            println!("   Refs:     {}", f.references.join(", "));
        }
        println!();
    }

    println!("=== Scan complete ===");
    Ok(())
}

fn print_findings_json(findings: &[Finding]) -> Result<(), CynError> {
    let json = serde_json::to_string_pretty(findings)
        .map_err(|e| CynError::ResultParse(format!("JSON serialization failed: {e}")))?;
    println!("{json}");
    Ok(())
}

/// Print a scanning progress message.
pub fn print_scan_start(target: &str) {
    println!("Starting scan against {target}...");
}

pub fn print_scan_complete(findings: &[Finding]) {
    let vulnerabilities = findings
        .iter()
        .filter(|finding| finding.result_type == "Alarm")
        .count();
    let errors = findings
        .iter()
        .filter(|finding| finding.result_type == "Error")
        .count();
    let informational = findings
        .iter()
        .filter(|finding| finding.result_type == "Log")
        .count();

    println!(
        "Scan complete: {vulnerabilities} vulnerability(s), {errors} error(s), {informational} informational result(s)."
    );
}

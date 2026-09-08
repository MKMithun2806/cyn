use crate::cli::OutputFormat;
use crate::error::CynError;
use crate::feed::FeedInfo;
use crate::scanner::Finding;

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
    if findings.is_empty() {
        println!("No vulnerability findings.");
        return Ok(());
    }

    println!("\n=== Findings ({}) ===\n", findings.len());

    for (i, f) in findings.iter().enumerate() {
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

pub fn print_scan_complete(count: usize) {
    println!("Scan complete. {count} finding(s) collected.");
}

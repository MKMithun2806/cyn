use crate::cli::OutputFormat;
use crate::discovery::{DiscoveryResult, Protocol};
use crate::error::CynError;
use crate::feed::FeedInfo;
use crate::scanner::{Finding, FindingCategory};
use std::collections::HashSet;
use std::fmt::Display;
use std::io::{self, IsTerminal};

struct Style {
    enabled: bool,
}

impl Style {
    fn terminal() -> Self {
        Self {
            enabled: io::stdout().is_terminal(),
        }
    }

    fn paint(&self, code: &str, value: impl Display) -> String {
        if self.enabled {
            format!("\x1b[{code}m{value}\x1b[0m")
        } else {
            value.to_string()
        }
    }

    fn bold(&self, value: impl Display) -> String {
        self.paint("1", value)
    }

    fn cyan(&self, value: impl Display) -> String {
        self.paint("36", value)
    }

    fn green(&self, value: impl Display) -> String {
        self.paint("32", value)
    }

    fn yellow(&self, value: impl Display) -> String {
        self.paint("33", value)
    }

    fn red(&self, value: impl Display) -> String {
        self.paint("31", value)
    }

    fn dim(&self, value: impl Display) -> String {
        self.paint("2", value)
    }
}

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
    let style = Style::terminal();
    let actionable: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding.result_type == "Alarm" || finding.result_type == "Error")
        .collect();

    if actionable.is_empty() {
        println!();
        println!(
            "╭─ {} ───────────────────────────────╮",
            style.bold("Scan result")
        );
        println!("│ {} No vulnerabilities found", style.green("✓"));
        if !findings.is_empty() {
            println!(
                "│ {} informational result(s) hidden; use --output json to inspect them.",
                findings.len()
            );
        }
        println!("╰─────────────────────────────────────╯");
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

    println!();
    println!(
        "╭─ {} ──────────────────────────────╮",
        style.bold(format!("Findings ({})", unique.len()))
    );

    for (i, f) in unique.iter().enumerate() {
        let severity = f
            .severity
            .map(|s| {
                let value = format!("{s:.1}");
                if s >= 7.0 {
                    style.red(value)
                } else if s >= 4.0 {
                    style.yellow(value)
                } else {
                    style.green(value)
                }
            })
            .unwrap_or_else(|| "N/A".into());

        let marker = style.red("!");
        println!(
            "│ {}. {} [{}] {}",
            i + 1,
            marker,
            severity,
            style.bold(&f.name)
        );
        println!("│    {} {}", style.dim("Host:"), f.host);
        if let Some(port) = &f.port {
            let proto = f.protocol.as_deref().unwrap_or("tcp");
            println!("│    {} {port}/{proto}", style.dim("Port:"));
        }
        println!(
            "│    {} {}",
            style.dim("Category:"),
            category_label(&f.category)
        );
        println!(
            "│    {} {}% ({})",
            style.dim("Confidence:"),
            f.confidence.score,
            confidence_label(&f.confidence.level)
        );
        println!("│    {} {}", style.dim("OID:"), f.oid);
        if let Some(desc) = &f.description {
            println!("│    {} {desc}", style.dim("Summary:"));
        }
        if !f.cves.is_empty() {
            println!("│    {} {}", style.dim("CVEs:"), f.cves.join(", "));
        }
        if let Some(sol) = &f.solution {
            println!("│    {} {sol}", style.dim("Solution:"));
        }
        if !f.references.is_empty() {
            println!("│    {} {}", style.dim("Refs:"), f.references.join(", "));
        }
        if i + 1 < unique.len() {
            println!("│");
        }
    }

    println!("╰────────────────────────────────────╯");
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
    let style = Style::terminal();
    println!(
        "{} {} {}",
        style.cyan("▶"),
        style.bold("Cyn scan"),
        style.dim(format!("→ {target}"))
    );
}

pub fn print_scan_complete(target: &str, discovery: &DiscoveryResult, findings: &[Finding]) {
    let style = Style::terminal();
    let alarms = findings
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
    let critical = severity_count(findings, 9.0, f64::INFINITY);
    let high = severity_count(findings, 7.0, 9.0);
    let medium = severity_count(findings, 4.0, 7.0);
    let low = severity_count(findings, 0.0, 4.0);
    let misconfigurations = findings
        .iter()
        .filter(|finding| finding.category == FindingCategory::Misconfiguration)
        .count();
    let exposures = findings
        .iter()
        .filter(|finding| finding.category == FindingCategory::Exposure)
        .count();

    println!();
    println!(
        "╭─ {} ─────────────────────────────────────────╮",
        style.bold("CYN SECURITY SCAN")
    );
    println!("│ {}", style.bold(target));
    for host in &discovery.hosts {
        let identity = host
            .os
            .as_deref()
            .or(host.hostname.as_deref())
            .unwrap_or("OS not identified");
        println!("│ {} · {} service(s)", identity, host.services.len());
    }
    println!("╰───────────────────────────────────────────────╯");

    println!();
    println!("{}", style.bold("SEVERITY"));
    println!(
        "  {} {:>3}   {} {:>3}   {} {:>3}   {} {:>3}   {} {:>3}",
        style.red("CRITICAL"),
        critical,
        style.red("HIGH"),
        high,
        style.yellow("MEDIUM"),
        medium,
        style.green("LOW"),
        low,
        style.dim("INFO"),
        informational
    );
    println!(
        "  {} misconfiguration(s) · {} exposure(s) · {} error(s)",
        misconfigurations, exposures, errors
    );

    if discovery.service_count() > 0 {
        println!();
        println!("{}", style.bold("SERVICES"));
        println!(
            "  {:<15} {:<5} {:<16} {:<24} VERSION",
            "HOST", "PORT", "SERVICE", "PRODUCT"
        );
        for host in &discovery.hosts {
            for service in &host.services {
                let protocol = match service.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                };
                let service_name = service.service.as_deref().unwrap_or("unknown");
                let product = service.product.as_deref().unwrap_or("-");
                let version = service.version.as_deref().unwrap_or("-");
                println!(
                    "  {:<15} {:<5} {:<16} {:<24} {}",
                    truncate(&format!("{}:{protocol}", host.address), 15),
                    service.port,
                    truncate(service_name, 16),
                    truncate(product, 24),
                    truncate(version, 18)
                );
            }
        }
    }

    let status = if alarms > 0 || errors > 0 {
        style.red("✗ attention needed")
    } else {
        style.green("✓ complete")
    };
    println!(
        "\n{} {}  {} findings · {} errors · {} informational",
        status,
        style.bold("Scan complete"),
        alarms,
        errors,
        informational
    );
}

fn severity_count(findings: &[Finding], lower: f64, upper: f64) -> usize {
    findings
        .iter()
        .filter(|finding| finding.result_type == "Alarm")
        .filter_map(|finding| finding.severity)
        .filter(|severity| *severity >= lower && *severity < upper)
        .count()
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let mut result = value
        .chars()
        .take(width.saturating_sub(1))
        .collect::<String>();
    result.push('…');
    result
}

fn category_label(category: &FindingCategory) -> &'static str {
    match category {
        FindingCategory::Vulnerability => "Vulnerability",
        FindingCategory::Misconfiguration => "Misconfiguration",
        FindingCategory::Exposure => "Exposure",
        FindingCategory::Information => "Information",
    }
}

fn confidence_label(level: &crate::confidence::ConfidenceLevel) -> &'static str {
    level.as_str()
}

#[cfg(test)]
mod tests {
    use super::truncate;

    #[test]
    fn truncates_wide_terminal_columns_without_panicking() {
        assert_eq!(truncate("OpenSSH_9.6p1", 8), "OpenSSH…");
        assert_eq!(truncate("http", 8), "http");
    }
}

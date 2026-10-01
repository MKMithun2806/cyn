use crate::cli::OutputFormat;
use crate::error::CynError;
use crate::feed::FeedInfo;
use crate::scanner::Finding;
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

        let marker = if f.result_type == "Error" {
            style.red("!")
        } else {
            style.red("!")
        };
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

pub fn print_scan_complete(findings: &[Finding]) {
    let style = Style::terminal();
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

    let status = if vulnerabilities > 0 || errors > 0 {
        style.red("✗ attention needed")
    } else {
        style.green("✓ complete")
    };
    println!(
        "{} {}  {} vulnerabilities · {} errors · {} informational",
        status,
        style.bold("Scan complete"),
        vulnerabilities,
        errors,
        informational
    );
}

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cyn", version, about = "Lightweight vulnerability scanner")]
pub struct Cli {
    /// Path to the NVT feed directory
    #[arg(long, env = "CYN_FEED_PATH", global = true)]
    pub feed: Option<PathBuf>,

    /// Path to configuration file
    #[arg(long, short = 'c', env = "CYN_CONFIG", global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Manage the vulnerability feed
    Feed {
        #[command(subcommand)]
        action: FeedCommand,
    },

    /// Run a vulnerability scan
    Scan {
        /// Target host or network to scan (IP address or CIDR)
        target: String,

        /// Output format
        #[arg(long, short = 'o', value_enum, default_value = "terminal")]
        output: OutputFormat,

        /// Maximum number of hosts to scan concurrently
        #[arg(long, default_value = "4")]
        max_hosts: u32,

        /// Maximum number of checks to run concurrently per host
        #[arg(long, default_value = "4")]
        max_checks: u32,

        /// List of VT OIDs to enable (comma-separated). If empty, all VTs run.
        #[arg(long)]
        vt: Option<String>,

        /// Port range to scan (e.g., "1-1024" or "22,80,443"). Default: all 65535 ports.
        #[arg(long)]
        ports: Option<String>,

        /// Import ports from nmap XML output file (e.g., -n scan.xml)
        #[arg(long, short = 'n')]
        nmap: Option<PathBuf>,

        /// Exclude hosts from scan
        #[arg(long)]
        exclude: Option<String>,

        /// Suppress informational warnings (e.g., UTF-8 fallback messages)
        #[arg(long, short = 'q')]
        quiet: bool,

        /// Generate a report file after scanning
        #[arg(long, short = 'r')]
        report: Option<PathBuf>,

        /// Report format (used with --report)
        #[arg(long, value_enum, default_value = "json")]
        report_format: ReportFormat,
    },

    /// Generate a report from a previous scan's findings
    Report {
        /// Path to the JSON findings file from a previous scan
        findings: PathBuf,

        /// Output report format
        #[arg(long, short = 'f', value_enum, default_value = "json")]
        format: ReportFormat,

        /// Output file path (default: stdout)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum FeedCommand {
    /// Show current feed status and version
    Status,

    /// Update the local feed from upstream
    Update {
        /// Upstream feed base URL (rsync)
        #[arg(long)]
        url: Option<String>,

        /// Feed release version (e.g., "24.10")
        #[arg(long)]
        feed_version: Option<String>,

        /// Verify feed signatures
        #[arg(long)]
        signature_check: bool,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq)]
pub enum OutputFormat {
    #[default]
    Terminal,
    Json,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq)]
pub enum ReportFormat {
    #[default]
    Json,
    Csv,
}

mod cli;
mod config;
mod error;
mod feed;
mod nmap;
mod output;
mod scanner;

use clap::Parser;
use cli::{Cli, Command, FeedCommand};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Force ring as the process-wide Rustls crypto provider.
    // Multiple dependencies (reqwest, sqlx) pull in different providers;
    // installing one explicitly prevents the "no crypto provider" panic.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    let quiet = matches!(&cli.command, Command::Scan { quiet, .. } if *quiet);

    let filter = if quiet {
        EnvFilter::new("warn")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();

    let result = run(cli).await;

    match result {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

async fn run(cli: Cli) -> Result<(), error::CynError> {
    let config = config::Config::resolve(cli.feed)?;

    match cli.command {
        Command::Feed { action } => match action {
            FeedCommand::Status => {
                let info = feed::status(&config)?;
                output::print_feed_status(&info);
                Ok(())
            }
            FeedCommand::Update {
                url,
                feed_version,
                signature_check,
            } => {
                feed::update(
                    &config,
                    url.as_deref(),
                    feed_version.as_deref(),
                    signature_check,
                )?;
                let info = feed::status(&config)?;
                output::print_feed_status(&info);
                Ok(())
            }
        },
        Command::Scan {
            target,
            output: format,
            max_hosts,
            max_checks,
            vt,
            ports,
            nmap,
            exclude,
            quiet: _,
        } => {
            output::print_scan_start(&target);

            let vt_oids = vt.map(|v| v.split(',').map(|s| s.trim().to_string()).collect());

            // Resolve ports: nmap file takes precedence, then --ports, then default all-ports
            let port_range = if let Some(ref nmap_path) = nmap {
                let scan = nmap::NmapScan::from_file(nmap_path)
                    .map_err(error::CynError::Scanner)?;
                let ports = scan.open_tcp_ports();
                if ports.is_empty() {
                    return Err(error::CynError::Scanner(
                        "nmap file contains no open TCP ports".into(),
                    ));
                }
                eprintln!(
                    "imported {} open TCP port(s) from {}",
                    ports.len(),
                    nmap_path.display()
                );
                Some(ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","))
            } else if ports.is_some() {
                ports
            } else {
                eprintln!("warning: no --ports or --nmap specified, scanning all 65535 TCP ports (use --ports or --nmap to narrow)");
                Some("1-65535".into())
            };

            let request = scanner::ScanRequest {
                target: target.clone(),
                max_hosts,
                max_checks,
                port_range,
                vt_oids,
                exclude_hosts: exclude.map(|e| {
                    e.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }),
            };

            let findings = scanner::run_scan(&config, &request).await?;

            output::print_scan_complete(findings.len());
            output::output_findings(&findings, format)?;
            Ok(())
        }
    }
}

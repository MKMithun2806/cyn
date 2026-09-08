mod cli;
mod config;
mod error;
mod feed;
mod output;
mod scanner;

use clap::Parser;
use cli::{Cli, Command, FeedCommand};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Set up logging
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
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
                signature_check,
            } => {
                println!("Updating feed...");
                feed::update(&config, url.as_deref(), signature_check)?;
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
            exclude,
        } => {
            output::print_scan_start(&target);

            let vt_oids = vt.map(|v| v.split(',').map(|s| s.trim().to_string()).collect());

            let request = scanner::ScanRequest {
                target: target.clone(),
                max_hosts,
                max_checks,
                port_range: ports,
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

mod cli;
mod config;
mod discovery;
mod error;
mod feed;
mod nmap;
mod output;
mod report;
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
    let verbose = cli.verbose;

    // Scans can execute tens of thousands of VTs. Keep normal output focused on
    // scan progress and findings; diagnostics require an explicit --verbose.
    let filter = if quiet || !verbose {
        EnvFilter::new("error")
    } else {
        // Keep verbose mode useful without re-enabling one warning per legacy
        // Latin-1 feed file. Detailed feed/parser diagnostics remain available
        // by changing the filter in code when specifically debugging the feed.
        EnvFilter::new("error,cyn=info,scannerlib::nasl::builtin::find_service=info")
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
            report,
            report_format,
        } => {
            output::print_scan_start(&target);

            let vt_oids = vt.map(|v| v.split(',').map(|s| s.trim().to_string()).collect());

            // Resolve ports: an imported Nmap report takes precedence. Otherwise
            // discovery runs automatically, with --ports constraining Nmap.
            let discovery = if let Some(ref nmap_path) = nmap {
                let scan =
                    nmap::NmapScan::from_file(nmap_path).map_err(error::CynError::Scanner)?;
                discovery::from_nmap(scan)
            } else {
                let request = discovery::DiscoveryRequest {
                    target: target.clone(),
                    ports: ports.clone(),
                };
                discovery::discover(&request)
                    .await
                    .map_err(|error| error::CynError::Scanner(error.to_string()))?
            };

            let open_ports = discovery.open_tcp_ports();
            if open_ports.is_empty() {
                let source = nmap
                    .as_deref()
                    .map(|path| format!("nmap file {}", path.display()))
                    .unwrap_or_else(|| "automatic discovery".into());
                return Err(error::CynError::Scanner(format!(
                    "{source} found no open TCP ports"
                )));
            }
            eprintln!(
                "discovered {} open TCP service(s) and {} total service(s) via {}",
                open_ports.len(),
                discovery.service_count(),
                discovery.backend
            );
            let port_range = Some(
                open_ports
                    .iter()
                    .map(|port| port.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );

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

            let findings = scanner::run_scan(&config, &request, &open_ports).await?;

            output::print_scan_complete(&findings);
            output::output_findings(&findings, format)?;

            // Generate report file if requested
            if let Some(ref report_path) = report {
                let fmt = match report_format {
                    cli::ReportFormat::Csv => "csv",
                    _ => "json",
                };
                report::write_report(&findings, fmt, Some(report_path))?;
            }

            Ok(())
        }
        Command::Convert {
            findings,
            format,
            output,
        } => {
            let findings = report::load_findings(&findings)?;
            let fmt = match format {
                cli::ReportFormat::Csv => "csv",
                _ => "json",
            };
            report::write_report(&findings, fmt, output.as_deref())?;
            Ok(())
        }
    }
}

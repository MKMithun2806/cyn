use std::io::{self, IsTerminal, Write};
use std::process::Stdio;

use tokio::process::Command;

#[derive(Debug, PartialEq, Eq)]
pub enum PreflightResult {
    Reachable,
    Unreachable(Vec<String>),
    Skipped,
    Unavailable(String),
}

/// Check that single-host scan targets respond to one bounded ICMP echo.
///
/// CIDR and comma-separated targets are left to the discovery engine because a
/// single ping cannot represent their reachability accurately.
pub async fn check_target(target: &str) -> PreflightResult {
    let hosts: Vec<&str> = target
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty() && !host.contains('/'))
        .collect();

    if hosts.is_empty() || target.contains(',') {
        return PreflightResult::Skipped;
    }

    match ping(hosts[0]).await {
        Ok(true) => PreflightResult::Reachable,
        Ok(false) => PreflightResult::Unreachable(vec![hosts[0].to_string()]),
        Err(error) => PreflightResult::Unavailable(error),
    }
}

async fn ping(host: &str) -> Result<bool, String> {
    let mut command = Command::new("ping");
    command
        .arg("-c")
        .arg("1")
        .arg("-W")
        .arg("2")
        .arg(host)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let status = command
        .status()
        .await
        .map_err(|error| format!("could not run ping: {error}"))?;
    Ok(status.success())
}

/// Render the reachability warning and ask whether the scan should continue.
/// Returns `true` only when the user explicitly chooses to continue.
pub fn confirm_unreachable(hosts: &[String]) -> io::Result<bool> {
    let target_list = hosts.join(", ");
    let color = io::stdout().is_terminal();
    let (red, yellow, dim, reset, bold) = if color {
        ("\x1b[31m", "\x1b[33m", "\x1b[2m", "\x1b[0m", "\x1b[1m")
    } else {
        ("", "", "", "", "")
    };

    println!();
    println!("╭─ {bold}PRE-SCAN REACHABILITY CHECK{reset} ───────────────╮");
    println!("│ {yellow}⚠{reset} {red}No ping response from:{reset} {target_list}");
    println!("│ {dim}The host may block ICMP while still exposing services.{reset}");
    println!("│ {bold}Continue with the scan anyway?{reset} {dim}[y/N]{reset}");
    println!("╰─────────────────────────────────────────────────╯");
    print!("  {bold}Choice:{reset} ");
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::{check_target, PreflightResult};

    #[tokio::test]
    async fn skips_network_ranges_and_target_lists() {
        assert_eq!(check_target("192.0.2.0/24").await, PreflightResult::Skipped);
        assert_eq!(
            check_target("192.0.2.1,192.0.2.2").await,
            PreflightResult::Skipped
        );
    }
}

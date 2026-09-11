use std::fs;
use std::io::Write;
use std::path::Path;

use crate::scanner::Finding;

pub fn generate_json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".into())
}

pub fn generate_csv(findings: &[Finding]) -> String {
    let mut w = Vec::new();
    writeln!(
        w,
        "host,port,protocol,oid,name,severity,cves,solution,references,result_type"
    )
    .unwrap();

    for f in findings {
        let port = f.port.map(|p| p.to_string()).unwrap_or_default();
        let protocol = f.protocol.clone().unwrap_or_default();
        let severity = f.severity.map(|s| s.to_string()).unwrap_or_default();
        let cves = f.cves.join(";");
        let solution = f.solution.as_deref().unwrap_or("").replace('"', "\"\"");
        let references = f.references.join(";");
        let name = f.name.replace('"', "\"\"");
        let oid = f.oid.replace('"', "\"\"");

        writeln!(
            w,
            "\"{}\",{},{},\"{}\",\"{}\",{},\"{}\",\"{}\",\"{}\",{}",
            f.host, port, protocol, oid, name, severity, cves, solution, references, f.result_type
        )
        .unwrap();
    }

    String::from_utf8(w).unwrap_or_default()
}

pub fn write_report(
    findings: &[Finding],
    format: &str,
    output: Option<&Path>,
) -> Result<(), String> {
    let content = match format {
        "csv" => generate_csv(findings),
        _ => generate_json(findings),
    };

    match output {
        Some(path) => {
            let mut file = fs::File::create(path)
                .map_err(|e| format!("failed to create report file {}: {e}", path.display()))?;
            file.write_all(content.as_bytes())
                .map_err(|e| format!("failed to write report: {e}"))?;
            eprintln!("report written to {}", path.display());
        }
        None => {
            print!("{content}");
        }
    }
    Ok(())
}

pub fn load_findings(path: &Path) -> Result<Vec<Finding>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read findings file {}: {e}", path.display()))?;
    serde_json::from_str(&content).map_err(|e| format!("failed to parse findings JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_findings() -> Vec<Finding> {
        vec![
            Finding {
                host: "192.168.1.1".into(),
                port: Some(22),
                protocol: Some("tcp".into()),
                oid: "1.3.6.1.4.1.25623.1.0.100001".into(),
                name: "OpenSSH Detection".into(),
                severity: Some(0.0),
                cves: vec![],
                description: Some("SSH service detected".into()),
                solution: None,
                references: vec![],
                result_type: "Log".into(),
            },
            Finding {
                host: "192.168.1.1".into(),
                port: Some(443),
                protocol: Some("tcp".into()),
                oid: "1.3.6.1.4.1.25623.1.0.100002".into(),
                name: "SSL/TLS Vulnerability".into(),
                severity: Some(7.5),
                cves: vec!["CVE-2024-1234".into()],
                description: Some("Critical SSL issue".into()),
                solution: Some("Update TLS".into()),
                references: vec!["cve:CVE-2024-1234".into()],
                result_type: "Alarm".into(),
            },
        ]
    }

    #[test]
    fn json_output() {
        let findings = sample_findings();
        let json = generate_json(&findings);
        let parsed: Vec<Finding> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].host, "192.168.1.1");
        assert_eq!(parsed[1].severity, Some(7.5));
    }

    #[test]
    fn csv_output() {
        let findings = sample_findings();
        let csv = generate_csv(&findings);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 rows
        assert!(lines[0].contains("host,port,protocol"));
        assert!(lines[1].contains("OpenSSH Detection"));
        assert!(lines[2].contains("CVE-2024-1234"));
    }

    #[test]
    fn csv_special_chars() {
        let findings = vec![Finding {
            host: "10.0.0.1".into(),
            port: Some(80),
            protocol: Some("tcp".into()),
            oid: "1.2.3".into(),
            name: "Test \"quoted\" value".into(),
            severity: Some(5.0),
            cves: vec![],
            description: None,
            solution: Some("Fix it".into()),
            references: vec![],
            result_type: "Alarm".into(),
        }];
        let csv = generate_csv(&findings);
        assert!(csv.contains("\"Test \"\"quoted\"\" value\""));
    }
}

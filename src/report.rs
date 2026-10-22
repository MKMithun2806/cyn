use std::fs;
use std::io::Write;
use std::path::Path;

use crate::scanner::Finding;

pub fn generate_json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".into())
}

pub fn generate_csv(findings: &[Finding]) -> String {
    let mut rows = vec![
        "host,port,protocol,oid,name,severity,cves,solution,references,result_type,category,service,product,version,evidence,detection_reason,source,confidence_score,confidence_level".to_string(),
    ];

    for f in findings {
        let evidence = f
            .evidence
            .iter()
            .map(|item| format!("{}:{}", item.kind, item.value))
            .collect::<Vec<_>>()
            .join(";");
        let category = serde_json::to_string(&f.category)
            .unwrap_or_else(|_| "\"information\"".into())
            .trim_matches('"')
            .to_string();
        let fields = [
            f.host.clone(),
            f.port.map(|p| p.to_string()).unwrap_or_default(),
            f.protocol.clone().unwrap_or_default(),
            f.oid.clone(),
            f.name.clone(),
            f.severity.map(|s| s.to_string()).unwrap_or_default(),
            f.cves.join(";"),
            f.solution.clone().unwrap_or_default(),
            f.references.join(";"),
            f.result_type.clone(),
            category,
            f.service.clone().unwrap_or_default(),
            f.product.clone().unwrap_or_default(),
            f.version.clone().unwrap_or_default(),
            evidence,
            f.detection_reason.clone().unwrap_or_default(),
            f.source.clone().unwrap_or_default(),
            f.confidence.score.to_string(),
            f.confidence.level.as_str().to_string(),
        ];
        rows.push(fields.iter().map(|field| csv_field(field)).collect::<Vec<_>>().join(","));
    }

    rows.join("\n") + "\n"
}

fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
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
    use crate::confidence::Confidence;
    use crate::scanner::{Evidence, FindingCategory};

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
                service: None,
                product: None,
                version: None,
                cpe: vec![],
                evidence: vec![],
                detection_reason: None,
                source: None,
                confidence: Confidence::default(),
                category: FindingCategory::Information,
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
                service: None,
                product: None,
                version: None,
                cpe: vec![],
                evidence: vec![Evidence {
                    kind: "banner".into(),
                    source: "fingerprint".into(),
                    value: "nginx/1.24.0".into(),
                }],
                detection_reason: None,
                source: None,
                confidence: Confidence::default(),
                category: FindingCategory::Vulnerability,
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
        assert_eq!(parsed[1].evidence[0].value, "nginx/1.24.0");
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
            service: None,
            product: None,
            version: None,
            cpe: vec![],
            evidence: vec![],
            detection_reason: None,
            source: None,
            confidence: Confidence::default(),
            category: FindingCategory::Vulnerability,
        }];
        let csv = generate_csv(&findings);
        assert!(csv.contains("\"Test \"\"quoted\"\" value\""));
    }

    #[test]
    fn loads_legacy_findings_without_evidence_fields() {
        let legacy = r#"[{"host":"192.0.2.1","port":22,"protocol":"tcp","oid":"1.2.3","name":"legacy","severity":null,"cves":[],"description":null,"solution":null,"references":[],"result_type":"Log"}]"#;
        let findings: Vec<Finding> = serde_json::from_str(legacy).unwrap();
        assert!(findings[0].evidence.is_empty());
        assert!(findings[0].service.is_none());
        assert_eq!(findings[0].confidence.score, 0);
    }
}

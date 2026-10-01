use super::finding;
use crate::discovery::DiscoveredService;
use crate::scanner::{Evidence, FindingCategory};

pub fn run(host: &str, service: &DiscoveredService) -> Vec<crate::scanner::Finding> {
    let Some(fingerprint) = &service.fingerprint else {
        return vec![];
    };
    if fingerprint.protocol.as_deref() != Some("http") {
        return vec![];
    }

    let mut missing = vec![
        "x-content-type-options",
        "x-frame-options",
        "content-security-policy",
    ];
    if service.port == 443 || service.service.as_deref() == Some("https") {
        missing.push("strict-transport-security");
    }

    let absent: Vec<&str> = missing
        .into_iter()
        .filter(|header| !fingerprint.headers.contains_key(*header))
        .collect();
    let mut findings = Vec::new();
    if !absent.is_empty() {
        let evidence = absent
            .iter()
            .map(|header| Evidence {
                kind: "missing-header".into(),
                source: "fingerprint".into(),
                value: (*header).into(),
            })
            .collect();
        findings.push(finding(
            host,
            service,
            "HTTP security headers missing",
            4.0,
            FindingCategory::Misconfiguration,
            format!(
                "Missing recommended response headers: {}",
                absent.join(", ")
            ),
            "Configure the web server or application to emit the missing security headers.".into(),
            evidence,
        ));
    }

    if let Some(server) = fingerprint.headers.get("server") {
        findings.push(finding(
            host,
            service,
            "HTTP server banner disclosure",
            2.0,
            FindingCategory::Exposure,
            "The HTTP Server header discloses implementation details to unauthenticated clients."
                .into(),
            "Remove or minimize the Server response header where operationally appropriate.".into(),
            vec![Evidence {
                kind: "header".into(),
                source: "fingerprint".into(),
                value: format!("server: {server}"),
            }],
        ));
    }
    findings
}

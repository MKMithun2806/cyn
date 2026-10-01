mod protocol;
mod web;

use crate::confidence;
use crate::discovery::{DiscoveredService, DiscoveryResult};
use crate::scanner::{Evidence, Finding, FindingCategory};

pub fn run(discovery: &DiscoveryResult) -> Vec<Finding> {
    let mut findings = Vec::new();
    for host in &discovery.hosts {
        for service in &host.services {
            findings.extend(web::run(&host.address, service));
            findings.extend(protocol::run(&host.address, service));
        }
    }
    findings
}

#[allow(clippy::too_many_arguments)]
fn finding(
    host: &str,
    service: &DiscoveredService,
    name: &str,
    severity: f64,
    category: FindingCategory,
    description: String,
    solution: String,
    evidence: Vec<Evidence>,
) -> Finding {
    let confidence = confidence::assess("Alarm", &evidence);
    Finding {
        host: host.into(),
        port: Some(service.port as i16),
        protocol: Some(
            match service.protocol {
                crate::discovery::Protocol::Tcp => "tcp",
                crate::discovery::Protocol::Udp => "udp",
            }
            .into(),
        ),
        oid: format!("cyn.check.{}", name.to_ascii_lowercase().replace(' ', "_")),
        name: name.into(),
        severity: Some(severity),
        cves: vec![],
        description: Some(description),
        solution: Some(solution),
        references: vec![],
        result_type: "Alarm".into(),
        service: service.service.clone(),
        product: service.product.clone(),
        version: service.version.clone(),
        cpe: service.cpe.clone(),
        evidence,
        detection_reason: Some("Safe configuration check matched observed service evidence".into()),
        source: Some("Cyn security checks".into()),
        confidence,
        category,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{DiscoveredHost, Protocol};
    use crate::fingerprint::ServiceFingerprint;
    use std::collections::BTreeMap;

    #[test]
    fn checks_are_safe_and_structured() {
        let discovery = DiscoveryResult {
            backend: "test".into(),
            hosts: vec![DiscoveredHost {
                address: "192.0.2.10".into(),
                hostname: None,
                os: None,
                services: vec![DiscoveredService {
                    port: 80,
                    protocol: Protocol::Tcp,
                    service: Some("http".into()),
                    product: Some("nginx".into()),
                    version: Some("1.24".into()),
                    cpe: vec![],
                    fingerprint: Some(ServiceFingerprint {
                        protocol: Some("http".into()),
                        banner: Some("HTTP/1.1 200 OK".into()),
                        product: Some("nginx/1.24".into()),
                        version: None,
                        title: None,
                        headers: BTreeMap::from([("server".into(), "nginx/1.24".into())]),
                        technologies: vec![],
                        algorithms: vec![],
                    }),
                }],
            }],
        };
        let findings = run(&discovery);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|finding| finding.confidence.score > 0));
        assert!(findings
            .iter()
            .any(|finding| finding.category == FindingCategory::Misconfiguration));
        assert!(findings
            .iter()
            .any(|finding| finding.category == FindingCategory::Exposure));
    }
}

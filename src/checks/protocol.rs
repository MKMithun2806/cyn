use super::finding;
use crate::discovery::DiscoveredService;
use crate::scanner::{Evidence, FindingCategory};

pub fn run(host: &str, service: &DiscoveredService) -> Vec<crate::scanner::Finding> {
    let Some(fingerprint) = &service.fingerprint else {
        return vec![];
    };
    if fingerprint.protocol.as_deref() != Some("ssh") {
        return vec![];
    }
    let Some(banner) = &fingerprint.banner else {
        return vec![];
    };
    if !banner.starts_with("SSH-1.") {
        return vec![];
    }

    vec![finding(
        host,
        service,
        "Legacy SSH protocol enabled",
        7.0,
        FindingCategory::Misconfiguration,
        "The service advertised the obsolete SSH protocol version 1.".into(),
        "Disable SSH protocol 1 and require SSH protocol 2 or newer.".into(),
        vec![Evidence {
            kind: "banner".into(),
            source: "fingerprint".into(),
            value: banner.clone(),
        }],
    )]
}

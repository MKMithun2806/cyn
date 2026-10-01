mod http;
mod smb;
mod ssh;

use crate::discovery::{DiscoveredHost, DiscoveredService, DiscoveryResult, Protocol};
use serde::Serialize;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ServiceFingerprint {
    pub protocol: Option<String>,
    pub banner: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub title: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub technologies: Vec<String>,
    pub algorithms: Vec<String>,
}

pub async fn enrich(discovery: &mut DiscoveryResult) {
    for host in &mut discovery.hosts {
        enrich_host(host).await;
    }
}

async fn enrich_host(host: &mut DiscoveredHost) {
    let address = host.address.clone();
    for service in &mut host.services {
        if service.protocol != Protocol::Tcp {
            continue;
        }
        if let Some(fingerprint) = fingerprint_service(&address, service).await {
            if service.product.is_none() {
                service.product = fingerprint.product.clone();
            }
            if service.version.is_none() {
                service.version = fingerprint.version.clone();
            }
            service.fingerprint = Some(fingerprint);
        }
    }
}

async fn fingerprint_service(
    address: &str,
    service: &DiscoveredService,
) -> Option<ServiceFingerprint> {
    let port = service.port;
    let stream = timeout(Duration::from_secs(2), TcpStream::connect((address, port)))
        .await
        .ok()?
        .ok()?;

    let name = service
        .service
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.contains("ssh") || port == 22 {
        return ssh::fingerprint(stream).await;
    }
    if name.contains("http") || matches!(port, 80 | 8080 | 8000 | 8081 | 9000) {
        return http::fingerprint(stream, address).await;
    }
    if name.contains("microsoft-ds") || name.contains("netbios") || matches!(port, 139 | 445) {
        return smb::fingerprint(stream).await;
    }
    None
}

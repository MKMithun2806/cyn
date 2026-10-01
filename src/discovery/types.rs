use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscoveredService {
    pub port: u16,
    pub protocol: Protocol,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub cpe: Vec<String>,
    pub fingerprint: Option<crate::fingerprint::ServiceFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscoveredHost {
    pub address: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub services: Vec<DiscoveredService>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DiscoveryResult {
    pub backend: String,
    pub hosts: Vec<DiscoveredHost>,
}

impl DiscoveryResult {
    pub fn open_tcp_ports(&self) -> Vec<u16> {
        let mut ports = self
            .hosts
            .iter()
            .flat_map(|host| &host.services)
            .filter(|service| service.protocol == Protocol::Tcp)
            .map(|service| service.port)
            .collect::<Vec<_>>();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    pub fn service_count(&self) -> usize {
        self.hosts.iter().map(|host| host.services.len()).sum()
    }
}

impl From<crate::nmap::NmapScan> for DiscoveryResult {
    fn from(scan: crate::nmap::NmapScan) -> Self {
        Self {
            backend: "nmap".into(),
            hosts: scan
                .hosts
                .into_iter()
                .map(|host| DiscoveredHost {
                    address: host.addr,
                    hostname: host.hostname,
                    os: host.os,
                    services: host
                        .ports
                        .into_iter()
                        .filter(|port| port.state == "open")
                        .map(|port| DiscoveredService {
                            port: port.port,
                            protocol: if port.protocol.eq_ignore_ascii_case("udp") {
                                Protocol::Udp
                            } else {
                                Protocol::Tcp
                            },
                            service: (!port.service.is_empty()).then_some(port.service),
                            product: port.product,
                            version: port.version,
                            cpe: port.cpes,
                            fingerprint: None,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_tcp_ports_are_sorted_and_unique() {
        let result = DiscoveryResult {
            backend: "test".into(),
            hosts: vec![DiscoveredHost {
                address: "127.0.0.1".into(),
                hostname: None,
                os: None,
                services: vec![
                    DiscoveredService {
                        port: 443,
                        protocol: Protocol::Tcp,
                        service: Some("https".into()),
                        product: None,
                        version: None,
                        cpe: vec![],
                        fingerprint: None,
                    },
                    DiscoveredService {
                        port: 22,
                        protocol: Protocol::Tcp,
                        service: Some("ssh".into()),
                        product: None,
                        version: None,
                        cpe: vec![],
                        fingerprint: None,
                    },
                    DiscoveredService {
                        port: 53,
                        protocol: Protocol::Udp,
                        service: Some("dns".into()),
                        product: None,
                        version: None,
                        cpe: vec![],
                        fingerprint: None,
                    },
                ],
            }],
        };

        assert_eq!(result.open_tcp_ports(), vec![22, 443]);
        assert_eq!(result.service_count(), 3);
    }
}

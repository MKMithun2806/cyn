use crate::discovery::{DiscoveryResult, Protocol};
use scannerlib::models;
use std::collections::{HashMap, HashSet};

const BOOTSTRAP_FAMILIES: &[&str] = &["Port scanners", "Product detection", "Service detection"];
const SKIPPED_FAMILIES: &[&str] = &[
    "attic",
    "Windows",
    "Windows : Microsoft Bulletins",
    "WindowsLocalChecks",
    "WindowsRemoteChecks",
    "Gain a shell remotely",
    "Huawei",
    "JunOS",
    "Solaris",
    "macOS Local Security Checks",
    "Fedora Local Security Checks",
    "CentOS Local Security Checks",
    "Red Hat Local Security Checks",
    "SuSE Local Security Checks",
    "Ubuntu Local Security Checks",
    "Debian Local Security Checks",
    "Mandriva Local Security Checks",
];

#[derive(Debug, Clone, Default)]
pub struct SelectionContext {
    discovered: bool,
    tcp_ports: HashSet<String>,
    udp_ports: HashSet<String>,
    tokens: HashSet<String>,
}

impl SelectionContext {
    pub fn from_tcp_ports(ports: &[u16]) -> Self {
        Self {
            tcp_ports: ports.iter().map(u16::to_string).collect(),
            ..Default::default()
        }
    }

    pub fn from_discovery(discovery: &DiscoveryResult) -> Self {
        let mut context = Self {
            discovered: true,
            ..Default::default()
        };
        for host in &discovery.hosts {
            if let Some(os) = &host.os {
                context.add_tokens(os);
            }
            for service in &host.services {
                let port = service.port.to_string();
                match service.protocol {
                    Protocol::Tcp => {
                        context.tcp_ports.insert(port);
                    }
                    Protocol::Udp => {
                        context.udp_ports.insert(port);
                    }
                }
                for value in [
                    service.service.as_deref(),
                    service.product.as_deref(),
                    service.version.as_deref(),
                ]
                .into_iter()
                .flatten()
                {
                    context.add_tokens(value);
                }
                for cpe in &service.cpe {
                    context.add_tokens(cpe);
                }
                if let Some(fingerprint) = &service.fingerprint {
                    for value in [
                        fingerprint.protocol.as_deref(),
                        fingerprint.product.as_deref(),
                        fingerprint.version.as_deref(),
                        fingerprint.banner.as_deref(),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        context.add_tokens(value);
                    }
                }
            }
        }
        context
    }

    fn add_tokens(&mut self, value: &str) {
        self.tokens.extend(
            value
                .split(|c: char| !c.is_ascii_alphanumeric())
                .map(str::to_ascii_lowercase)
                .filter(|token| token.len() >= 3),
        );
    }

    fn has_port(&self, requirement: &str, udp: bool) -> bool {
        let port = requirement.split('/').next().unwrap_or(requirement).trim();
        if udp {
            self.udp_ports.contains(port)
        } else {
            self.tcp_ports.contains(port)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SelectionStats {
    pub total: usize,
    pub selected: usize,
    pub skipped_family: usize,
    pub skipped_port: usize,
    pub skipped_irrelevant: usize,
    pub added_dependencies: usize,
}

pub fn select_vts(
    vts: &[models::VT],
    metadata: &HashMap<String, models::VTData>,
    context: &SelectionContext,
) -> (Vec<models::VT>, SelectionStats) {
    let mut stats = SelectionStats {
        total: vts.len(),
        ..Default::default()
    };
    let mut selected = Vec::new();
    let mut selected_oids = HashSet::new();

    for vt in vts {
        let Some(data) = metadata.get(&vt.oid) else {
            selected.push(vt.clone());
            selected_oids.insert(vt.oid.clone());
            stats.selected += 1;
            continue;
        };
        if SKIPPED_FAMILIES.contains(&data.family.as_str()) {
            stats.skipped_family += 1;
        } else if !ports_match(data, context) {
            stats.skipped_port += 1;
        } else if is_relevant(data, context) {
            selected.push(vt.clone());
            selected_oids.insert(vt.oid.clone());
            stats.selected += 1;
        } else {
            stats.skipped_irrelevant += 1;
        }
    }

    let mut pending: Vec<String> = selected
        .iter()
        .filter_map(|vt| metadata.get(&vt.oid))
        .flat_map(|data| data.dependencies.iter().cloned())
        .collect();
    while let Some(oid) = pending.pop() {
        if !selected_oids.insert(oid.clone()) {
            continue;
        }
        let Some(data) = metadata.get(&oid) else {
            continue;
        };
        selected.push(models::VT {
            oid,
            parameters: vec![],
        });
        stats.added_dependencies += 1;
        pending.extend(data.dependencies.iter().cloned());
    }
    (selected, stats)
}

fn ports_match(data: &models::VTData, context: &SelectionContext) -> bool {
    let tcp_match = data
        .required_ports
        .iter()
        .any(|port| context.has_port(port, false));
    let udp_match = data
        .required_udp_ports
        .iter()
        .any(|port| context.has_port(port, true));
    (data.required_ports.is_empty() || tcp_match)
        && (data.required_udp_ports.is_empty() || udp_match)
}

fn is_relevant(data: &models::VTData, context: &SelectionContext) -> bool {
    if !context.discovered {
        return true;
    }
    if BOOTSTRAP_FAMILIES.contains(&data.family.as_str()) {
        return true;
    }
    let haystack = format!(
        "{} {} {} {:?}",
        data.name, data.filename, data.family, data.tag
    )
    .to_ascii_lowercase();
    context.tokens.iter().any(|token| haystack.contains(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{DiscoveredHost, DiscoveredService};

    fn context() -> SelectionContext {
        SelectionContext::from_discovery(&DiscoveryResult {
            backend: "test".into(),
            hosts: vec![DiscoveredHost {
                address: "192.0.2.1".into(),
                hostname: None,
                os: Some("Ubuntu Linux".into()),
                services: vec![DiscoveredService {
                    port: 22,
                    protocol: Protocol::Tcp,
                    service: Some("ssh".into()),
                    product: Some("OpenSSH".into()),
                    version: Some("9.6".into()),
                    cpe: vec!["cpe:/a:openbsd:openssh:9.6".into()],
                    fingerprint: None,
                }],
            }],
        })
    }

    fn vt(oid: &str, name: &str, family: &str, port: &str) -> (models::VT, models::VTData) {
        (
            models::VT {
                oid: oid.into(),
                parameters: vec![],
            },
            models::VTData {
                oid: oid.into(),
                name: name.into(),
                family: family.into(),
                required_ports: if port.is_empty() {
                    vec![]
                } else {
                    vec![port.into()]
                },
                ..Default::default()
            },
        )
    }

    #[test]
    fn selects_matching_service_and_bootstrap_checks() {
        let candidates = vec![
            vt("ssh", "OpenSSH issue", "General", "22/tcp"),
            vt("web", "nginx issue", "General", "80/tcp"),
            vt("bootstrap", "TCP scanner", "Port scanners", ""),
        ];
        let metadata = candidates
            .iter()
            .map(|(vt, data)| (vt.oid.clone(), data.clone()))
            .collect();
        let input = candidates.into_iter().map(|(vt, _)| vt).collect::<Vec<_>>();
        let (selected, stats) = select_vts(&input, &metadata, &context());
        let oids = selected
            .into_iter()
            .map(|vt| vt.oid)
            .collect::<HashSet<_>>();
        assert!(oids.contains("ssh"));
        assert!(oids.contains("bootstrap"));
        assert!(!oids.contains("web"));
        assert_eq!(stats.skipped_port, 1);
    }

    #[test]
    fn dependencies_are_added_to_selected_vts() {
        let (root, mut root_data) = vt("root", "OpenSSH check", "General", "22/tcp");
        let (dependency, dependency_data) = vt("dependency", "Generic setup", "General", "");
        root_data.dependencies = vec![dependency.oid.clone()];
        let metadata = HashMap::from([
            (root.oid.clone(), root_data),
            (dependency.oid.clone(), dependency_data),
        ]);
        let (selected, stats) = select_vts(&[root], &metadata, &context());
        assert_eq!(selected.len(), 2);
        assert_eq!(stats.added_dependencies, 1);
    }
}

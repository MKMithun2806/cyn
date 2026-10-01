use crate::discovery::{DiscoveryResult, Protocol};
use scannerlib::models;
use std::collections::{HashMap, HashSet};

const BOOTSTRAP_FAMILIES: &[&str] = &["Port scanners"];
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
    identities: Vec<ServiceIdentity>,
}

#[derive(Debug, Clone, Default)]
struct ServiceIdentity {
    port: u16,
    udp: bool,
    tokens: HashSet<String>,
    version: Option<ParsedVersion>,
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
            for service in &host.services {
                let port = service.port.to_string();
                let udp = service.protocol == Protocol::Udp;
                match service.protocol {
                    Protocol::Tcp => {
                        context.tcp_ports.insert(port);
                    }
                    Protocol::Udp => {
                        context.udp_ports.insert(port);
                    }
                }
                let mut identity = ServiceIdentity {
                    port: service.port,
                    udp,
                    ..Default::default()
                };
                for value in [service.service.as_deref(), service.product.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    add_tokens(&mut identity.tokens, value);
                }
                if let Some((product, version)) = normalize_product_version(
                    service.product.as_deref(),
                    service.version.as_deref(),
                ) {
                    add_tokens(&mut identity.tokens, &product);
                    identity.version = Some(version);
                } else {
                    identity.version = service.version.as_deref().and_then(parse_version);
                }
                for cpe in &service.cpe {
                    add_tokens(&mut identity.tokens, cpe);
                }
                if let Some(fingerprint) = &service.fingerprint {
                    for value in [
                        fingerprint.protocol.as_deref(),
                        fingerprint.product.as_deref(),
                        fingerprint.banner.as_deref(),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        add_tokens(&mut identity.tokens, value);
                    }
                }
                context.identities.push(identity);
            }
        }
        context
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
    let metadata_tokens = tokenize(&format!("{} {} {}", data.name, data.filename, data.family));
    let matched_identities: Vec<&ServiceIdentity> = context
        .identities
        .iter()
        .filter(|identity| {
            let port_match = if identity.udp {
                data.required_udp_ports.is_empty()
                    || data.required_udp_ports.iter().any(|port| {
                        port.split('/').next().unwrap_or(port).trim() == identity.port.to_string()
                    })
            } else {
                data.required_ports.is_empty()
                    || data.required_ports.iter().any(|port| {
                        port.split('/').next().unwrap_or(port).trim() == identity.port.to_string()
                    })
            };
            port_match
                && identity
                    .tokens
                    .iter()
                    .any(|token| metadata_tokens.contains(token))
        })
        .collect();
    if matched_identities.is_empty() {
        return false;
    }

    // If the feed explicitly gives a simple upper-bound affected range, use
    // the normalized observed version to avoid selecting checks for fixed
    // versions. Unknown or complex ranges remain candidates for detection.
    if let Some(affected) = data.tag.get(&models::TagKey::Affected) {
        let affected = affected.to_string();
        if let Some(bound) = less_than_bound(&affected) {
            return matched_identities
                .into_iter()
                .filter_map(|identity| identity.version.as_ref())
                .any(|version| version < &bound);
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ParsedVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub update: Option<String>,
}

pub fn parse_version(raw: &str) -> Option<ParsedVersion> {
    let raw = raw.trim().trim_start_matches('v');
    let suffix_start = raw.find(|c: char| c.is_ascii_alphabetic());
    let (numeric_part, suffix) = match suffix_start {
        Some(index) => (&raw[..index], Some(raw[index..].to_string())),
        None => (raw, None),
    };
    let numeric = numeric_part.split('.').collect::<Vec<_>>();
    if numeric.len() < 2 || numeric.iter().any(|part| part.parse::<u64>().is_err()) {
        return None;
    }
    let suffix = suffix.filter(|value| !value.is_empty());
    Some(ParsedVersion {
        major: numeric[0].parse().ok()?,
        minor: numeric[1].parse().ok()?,
        patch: numeric
            .get(2)
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        update: suffix,
    })
}

pub fn normalize_product_version(
    product: Option<&str>,
    version: Option<&str>,
) -> Option<(String, ParsedVersion)> {
    let product = product?.trim();
    if product.is_empty() || product == "-" {
        return None;
    }
    if let Some((name, embedded_version)) = product.rsplit_once('_') {
        if let Some(version) = parse_version(embedded_version) {
            return Some((name.to_string(), version));
        }
    }
    Some((product.to_string(), parse_version(version?)?))
}

fn less_than_bound(affected: &str) -> Option<ParsedVersion> {
    let position = affected.find('<')?;
    let bound = affected[position + 1..]
        .trim_start_matches('=')
        .split_whitespace()
        .next()?;
    parse_version(bound)
}

fn tokenize(value: &str) -> HashSet<String> {
    value
        .split(|c: char| !c.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
        .filter(|token| token.len() >= 3 && token.chars().any(|c| c.is_ascii_alphabetic()))
        .collect()
}

fn add_tokens(tokens: &mut HashSet<String>, value: &str) {
    tokens.extend(tokenize(value));
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

    #[test]
    fn normalizes_openssh_product_and_update() {
        let (product, version) = normalize_product_version(Some("OpenSSH_9.6p1"), None).unwrap();
        assert_eq!(product, "OpenSSH");
        assert_eq!(version.major, 9);
        assert_eq!(version.minor, 6);
        assert_eq!(version.update.as_deref(), Some("p1"));
    }

    #[test]
    fn compares_versions_structurally() {
        assert!(parse_version("9.6p1").unwrap() < parse_version("10.5").unwrap());
        assert!(!(parse_version("10.5").unwrap() < parse_version("10.5").unwrap()));
        assert!(parse_version("unknown").is_none());
    }

    #[test]
    fn product_mismatch_is_not_selected() {
        let (candidate, data) = vt("openssh", "OpenSSH vulnerability", "General", "22/tcp");
        let metadata = HashMap::from([(candidate.oid.clone(), data)]);
        let nginx_context = SelectionContext::from_discovery(&DiscoveryResult {
            backend: "fixture".into(),
            hosts: vec![DiscoveredHost {
                address: "192.0.2.2".into(),
                hostname: None,
                os: None,
                services: vec![DiscoveredService {
                    port: 22,
                    protocol: Protocol::Tcp,
                    service: Some("ssh".into()),
                    product: Some("nginx".into()),
                    version: Some("9.6".into()),
                    cpe: vec![],
                    fingerprint: None,
                }],
            }],
        });
        let (selected, _) = select_vts(&[candidate], &metadata, &nginx_context);
        assert!(selected.is_empty());
    }

    #[test]
    fn known_service_selection_is_narrower_than_feed() {
        let mut candidates = Vec::new();
        let mut metadata = HashMap::new();
        for index in 0..100 {
            let (candidate, data) = vt(
                &format!("generic-{index}"),
                "Unrelated web application check",
                "General",
                "",
            );
            metadata.insert(candidate.oid.clone(), data);
            candidates.push(candidate);
        }
        let (ssh, ssh_data) = vt("ssh-check", "OpenSSH vulnerability", "General", "22/tcp");
        metadata.insert(ssh.oid.clone(), ssh_data);
        candidates.push(ssh);
        let (selected, _) = select_vts(&candidates, &metadata, &context());
        assert_eq!(selected.len(), 1);
        assert!(selected[0].oid == "ssh-check");
    }

    #[test]
    fn affected_upper_bound_selects_vulnerable_version_only() {
        let (candidate, mut data) = vt(
            "openssh-range",
            "OpenSSH vulnerability",
            "General",
            "22/tcp",
        );
        data.tag.insert(models::TagKey::Affected, "< 10.5".into());
        let metadata = HashMap::from([(candidate.oid.clone(), data.clone())]);
        let (selected, _) = select_vts(&[candidate.clone()], &metadata, &context());
        assert_eq!(selected.len(), 1);

        let fixed_context = SelectionContext::from_discovery(&DiscoveryResult {
            backend: "fixture".into(),
            hosts: vec![DiscoveredHost {
                address: "192.0.2.3".into(),
                hostname: None,
                os: None,
                services: vec![DiscoveredService {
                    port: 22,
                    protocol: Protocol::Tcp,
                    service: Some("ssh".into()),
                    product: Some("OpenSSH".into()),
                    version: Some("10.5".into()),
                    cpe: vec![],
                    fingerprint: None,
                }],
            }],
        });
        let (selected, _) = select_vts(&[candidate], &metadata, &fixed_context);
        assert!(selected.is_empty());
    }
}

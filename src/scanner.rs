use std::net::IpAddr;
use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::discovery::{DiscoveryResult, Protocol};
use crate::error::CynError;
use crate::selection::{select_vts, SelectionContext};

use scannerlib::feed::{HashSumNameLoader, Update};
use scannerlib::models;
use scannerlib::nasl::nasl_std_executor;
use scannerlib::nasl::syntax::Loader;
use scannerlib::nasl::utils::ctx::{CtxTarget, CtxTargets, ScanCtx, TargetId};
use scannerlib::scanner::{Scan, ScanRunner};
use scannerlib::scheduling::Scheduler;
use scannerlib::storage::inmemory::InMemoryStorage;
use scannerlib::storage::items::nvt::Feed;
use scannerlib::storage::{Remover, Retriever, ScanID};

/// synscan.nasl requires raw sockets (CAP_NET_RAW). We exclude it so the
/// TCP-connect scanner (`openvas_tcp_scanner.nasl`) handles port scanning instead.
const SYNSCAN_NASL_OID: &str = "1.3.6.1.4.1.25623.1.0.11219";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub host: String,
    pub port: Option<i16>,
    pub protocol: Option<String>,
    pub oid: String,
    pub name: String,
    pub severity: Option<f64>,
    pub cves: Vec<String>,
    pub description: Option<String>,
    pub solution: Option<String>,
    pub references: Vec<String>,
    pub result_type: String,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub cpe: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub detection_reason: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Evidence {
    pub kind: String,
    pub source: String,
    pub value: String,
}

pub struct ScanRequest {
    pub target: String,
    pub max_hosts: u32,
    pub max_checks: u32,
    pub port_range: Option<String>,
    pub vt_oids: Option<Vec<String>>,
    pub exclude_hosts: Option<Vec<String>>,
    pub discovery: Option<DiscoveryResult>,
}

pub async fn run_scan(
    config: &Config,
    request: &ScanRequest,
    _open_ports: &[u16],
) -> Result<Vec<Finding>, CynError> {
    let feed_path = &config.feed_path;

    if !feed_path.exists() {
        return Err(CynError::FeedNotFound {
            path: feed_path.display().to_string(),
        });
    }

    let storage = Arc::new(InMemoryStorage::new());
    let loader = Loader::from_feed_path(feed_path);

    eprintln!("Loading vulnerability feed...");
    let verifier = HashSumNameLoader::sha256(&loader)
        .map_err(|e| CynError::Scanner(format!("failed to create feed verifier: {e}")))?;
    let updater = Update::init("cyn", 5, loader.clone(), &storage, verifier);
    updater
        .perform_update()
        .await
        .map_err(|e| CynError::Scanner(format!("feed update failed: {e}")))?;
    eprintln!("Feed ready.");

    eprintln!("Selecting vulnerability checks...");
    let vts = load_vts(&storage, request, _open_ports).await?;
    eprintln!("Selected {} vulnerability checks.", vts.len());

    let models_scan = build_scan_model(request, vts)?;
    let scan_id = models_scan.scan_id.clone();
    let scan = Scan::default_to_localhost(models_scan);
    let target_count = scan.targets.iter().count();
    eprintln!("Scanning {} host(s)...", target_count);

    let capacity = target_count.max(1);
    let (tx_target, rx_target) = mpsc::channel::<TargetId>(capacity);

    for (target_id, _) in scan.targets.enumerate() {
        if tx_target.send(target_id).await.is_err() {
            break;
        }
    }
    drop(tx_target);

    let executor = nasl_std_executor();
    let scheduler = Scheduler::new(storage.clone());
    let schedule = scheduler
        .execution_plan(&scan.vts)
        .await
        .map_err(|e| CynError::Scanner(format!("scheduling failed: {e}")))?;

    tracing::info!(
        "scan started: {} target(s), {} VTs",
        target_count,
        scan.vts.len()
    );

    let targets: CtxTargets = scan
        .targets
        .iter()
        .map(|target| CtxTarget::new(target.clone(), scan.ports.clone()))
        .collect();
    let scan_ctx = ScanCtx::new(
        ScanID(scan_id.clone()),
        targets,
        &*storage,
        &loader,
        &executor,
        scan.scan_preferences.clone(),
        scan.alive_test_methods.clone(),
        None,
    );

    let runner = ScanRunner::new(schedule, rx_target, &scan_ctx)
        .map_err(|e| CynError::Scanner(format!("failed to create scan runner: {e}")))?;

    let mut succeeded = 0u32;
    let mut failed = 0u32;
    let mut errors = 0u32;

    let mut stream = Box::pin(runner.stream());
    let mut total_results = 0u32;
    while let Some(result) = stream.next().await {
        total_results += 1;
        match result {
            Ok(script_result) => {
                if script_result.has_succeeded() {
                    succeeded += 1;
                    tracing::debug!(
                        oid = %script_result.oid,
                        stage = ?script_result.stage,
                        "script succeeded"
                    );
                } else {
                    failed += 1;
                    tracing::debug!(
                        oid = %script_result.oid,
                        stage = ?script_result.stage,
                        "script did not succeed"
                    );
                }
            }
            Err(e) => {
                errors += 1;
                tracing::warn!(error = %e, "script execution error");
            }
        }
    }

    tracing::info!(
        "scan execution complete: succeeded={succeeded}, failed={failed}, errors={errors}, total_stream_results={total_results}"
    );

    let results = storage
        .remove(&ScanID(scan_id))
        .await
        .map_err(|e| CynError::Scanner(format!("failed to retrieve results: {e}")))?;

    let raw_results = results.unwrap_or_default();
    // Log result types
    use std::collections::HashMap;
    let mut type_counts: HashMap<String, u32> = HashMap::new();
    for r in &raw_results {
        let key = format!("{:?}", r.r_type);
        *type_counts.entry(key).or_insert(0) += 1;
    }
    for (typ, count) in &type_counts {
        tracing::info!("  result type {typ}: {count}");
    }

    // Pre-fetch VT metadata for all OIDs found in results
    let vt_metadata = build_vt_metadata_map(&storage, &raw_results).await;

    let findings: Vec<Finding> = raw_results
        .into_iter()
        .filter_map(|r| result_to_finding(r, &vt_metadata, request.discovery.as_ref()))
        .collect();

    tracing::info!("findings after conversion: {}", findings.len());

    Ok(findings)
}

async fn build_vt_metadata_map(
    storage: &InMemoryStorage,
    results: &[models::Result],
) -> std::collections::HashMap<String, models::VTData> {
    use std::collections::HashSet;
    let oids: HashSet<&str> = results.iter().filter_map(|r| r.oid.as_deref()).collect();

    let mut map = std::collections::HashMap::new();
    for oid in oids {
        if let Ok(Some(vt_data)) = storage
            .retrieve(&scannerlib::storage::items::nvt::Oid(oid.to_string()))
            .await
        {
            map.insert(oid.to_string(), vt_data);
        }
    }
    map
}

async fn load_vts(
    storage: &InMemoryStorage,
    request: &ScanRequest,
    open_ports: &[u16],
) -> Result<Vec<models::VT>, CynError> {
    match &request.vt_oids {
        Some(oids) if !oids.is_empty() => Ok(oids
            .iter()
            .map(|oid| models::VT {
                oid: oid.clone(),
                parameters: vec![],
            })
            .collect()),
        _ => {
            let all_vts = storage
                .retrieve(&Feed)
                .await
                .map_err(|e| CynError::Scanner(format!("failed to retrieve VTs: {e}")))?;

            match all_vts {
                Some(vts) => {
                    let metadata = vts
                        .iter()
                        .map(|data| (data.oid.clone(), data.clone()))
                        .collect::<std::collections::HashMap<_, _>>();
                    let candidates = vts
                        .iter()
                        .map(|data| models::VT {
                            oid: data.oid.clone(),
                            parameters: vec![],
                        })
                        .collect::<Vec<_>>();
                    let context = request
                        .discovery
                        .as_ref()
                        .map(SelectionContext::from_discovery)
                        .unwrap_or_else(|| SelectionContext::from_tcp_ports(open_ports));
                    let (filtered, stats) = select_vts(&candidates, &metadata, &context);

                    tracing::info!(
                        "filtered {} VTs to {} (kept={}, port_skip={}, family_skip={}, irrelevant_skip={}, dependencies={})",
                        candidates.len(),
                        filtered.len(),
                        stats.selected,
                        stats.skipped_port,
                        stats.skipped_family,
                        stats.skipped_irrelevant,
                        stats.added_dependencies,
                    );
                    Ok(filtered)
                }
                None => Ok(vec![]),
            }
        }
    }
}

fn result_to_finding(
    result: models::Result,
    vt_metadata: &std::collections::HashMap<String, models::VTData>,
    discovery: Option<&DiscoveryResult>,
) -> Option<Finding> {
    let result_type = match result.r_type {
        models::ResultType::Alarm => "Alarm",
        models::ResultType::Log => "Log",
        models::ResultType::Error => "Error",
        models::ResultType::HostStart => return None,
        models::ResultType::HostEnd => return None,
        models::ResultType::DeadHost => return None,
        models::ResultType::HostDetail => return None,
    };

    let host = result.ip_address.or(result.hostname).unwrap_or_default();
    let oid = result.oid.clone().unwrap_or_default();
    let protocol = result.protocol.map(|p| match p {
        models::Protocol::TCP => "tcp".to_string(),
        models::Protocol::UDP => "udp".to_string(),
    });

    let service = result.port.and_then(|port| {
        discovery
            .and_then(|scan| {
                scan.hosts
                    .iter()
                    .find(|candidate| candidate.address == host)
            })
            .and_then(|candidate| {
                candidate.services.iter().find(|candidate| {
                    candidate.port == port as u16
                        && protocol.as_deref().map_or(true, |value| {
                            matches!(
                                (value, candidate.protocol),
                                ("tcp", Protocol::Tcp) | ("udp", Protocol::Udp)
                            )
                        })
                })
            })
    });

    let mut evidence = Vec::new();
    if let Some(service) = service {
        if let Some(value) = &service.service {
            evidence.push(Evidence {
                kind: "service".into(),
                source: "discovery".into(),
                value: value.clone(),
            });
        }
        if let Some(value) = &service.product {
            evidence.push(Evidence {
                kind: "product".into(),
                source: "discovery".into(),
                value: value.clone(),
            });
        }
        if let Some(value) = &service.version {
            evidence.push(Evidence {
                kind: "version".into(),
                source: "discovery".into(),
                value: value.clone(),
            });
        }
        for value in &service.cpe {
            evidence.push(Evidence {
                kind: "cpe".into(),
                source: "discovery".into(),
                value: value.clone(),
            });
        }
        if let Some(fingerprint) = &service.fingerprint {
            if let Some(value) = &fingerprint.banner {
                evidence.push(Evidence {
                    kind: "banner".into(),
                    source: "fingerprint".into(),
                    value: value.clone(),
                });
            }
            for (key, value) in &fingerprint.headers {
                evidence.push(Evidence {
                    kind: "header".into(),
                    source: "fingerprint".into(),
                    value: format!("{key}: {value}"),
                });
            }
        }
    }

    if let Some(message) = &result.message {
        evidence.push(Evidence {
            kind: "result".into(),
            source: "openvas-vt".into(),
            value: message.clone(),
        });
    }

    // Look up VT metadata for name, severity, CVEs, etc.
    let (name, severity, solution, references, cves) =
        if let Some(vt) = result.oid.as_ref().and_then(|o| vt_metadata.get(o)) {
            let name = vt.name.clone();
            let severity = vt
                .tag
                .get(&models::TagKey::CvssBase)
                .and_then(|v| v.to_string().parse().ok());
            let solution = vt.tag.get(&models::TagKey::Solution).map(|v| v.to_string());
            let cves: Vec<String> = vt
                .references
                .iter()
                .filter(|r| r.class == "cve")
                .map(|r| r.id.clone())
                .collect();
            let refs: Vec<String> = vt
                .references
                .iter()
                .map(|r| format!("{}: {}", r.class, r.id))
                .collect();
            (name, severity, solution, refs, cves)
        } else {
            (String::new(), None, None, vec![], vec![])
        };

    Some(Finding {
        host,
        port: result.port,
        protocol,
        oid: oid.clone(),
        name,
        severity,
        cves,
        description: result.message.clone(),
        solution,
        references,
        result_type: result_type.to_string(),
        service: service.and_then(|value| value.service.clone()),
        product: service.and_then(|value| value.product.clone()),
        version: service.and_then(|value| value.version.clone()),
        cpe: service.map(|value| value.cpe.clone()).unwrap_or_default(),
        evidence,
        detection_reason: Some(format!(
            "OpenVAS VT {oid} produced a {} result from target evidence",
            result_type
        )),
        source: Some("OpenVAS VT feed".into()),
    })
}

fn build_scan_model(request: &ScanRequest, vts: Vec<models::VT>) -> Result<models::Scan, CynError> {
    let hosts = expand_targets(&request.target)?;

    if hosts.is_empty() {
        return Err(CynError::InvalidTarget(request.target.clone()));
    }

    let ports = parse_ports(&request.port_range);

    let excluded = request
        .exclude_hosts
        .as_ref()
        .map(|list| list.to_vec())
        .unwrap_or_default();

    let vts: Vec<models::VT> = vts
        .into_iter()
        .filter(|vt| vt.oid != SYNSCAN_NASL_OID)
        .collect();

    Ok(models::Scan {
        scan_id: format!(
            "cyn-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ),
        target: models::Target {
            hosts,
            ports,
            excluded_hosts: excluded,
            alive_test_methods: vec![models::AliveTestMethods::ConsiderAlive],
            credentials: vec![],
            reverse_lookup_only: None,
            reverse_lookup_unify: None,
            alive_test_ports: vec![],
        },
        vts,
        scan_preferences: vec![
            models::ScanPreference {
                id: "max_hosts".into(),
                value: request.max_hosts.to_string(),
            },
            models::ScanPreference {
                id: "max_checks".into(),
                value: request.max_checks.to_string(),
            },
            models::ScanPreference {
                id: "test_alive_hosts_only".into(),
                value: "yes".into(),
            },
        ],
    })
}

fn expand_targets(target: &str) -> Result<Vec<String>, CynError> {
    let mut hosts = Vec::new();
    for part in target.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(cidr_pos) = part.find('/') {
            let ip_str = &part[..cidr_pos];
            let prefix: u32 = part[cidr_pos + 1..]
                .parse()
                .map_err(|_| CynError::InvalidTarget(part.to_string()))?;
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|_| CynError::InvalidTarget(part.to_string()))?;
            match ip {
                IpAddr::V4(ipv4) => {
                    let ip_num = u32::from_be_bytes(ipv4.octets());
                    let mask = !0u32 << (32 - prefix);
                    let network = ip_num & mask;
                    let broadcast = network | !mask;
                    for addr in (network + 1)..broadcast {
                        hosts.push(IpAddr::from(addr.to_be_bytes()).to_string());
                    }
                }
                IpAddr::V6(_) => {
                    hosts.push(part.to_string());
                }
            }
        } else {
            hosts.push(part.to_string());
        }
    }
    Ok(hosts)
}

fn parse_ports(port_range: &Option<String>) -> Vec<models::Port> {
    let range = match port_range {
        Some(r) => r,
        None => {
            // Default: all TCP ports
            return vec![models::Port {
                protocol: Some(models::Protocol::TCP),
                range: vec![models::PortRange {
                    start: 1,
                    end: Some(65535),
                }],
            }];
        }
    };

    let ranges: Vec<models::PortRange> = range
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.contains('-') {
                let parts: Vec<&str> = part.splitn(2, '-').collect();
                let start: usize = parts[0].parse().ok()?;
                let end: usize = parts.get(1).and_then(|e| e.parse().ok())?;
                Some(models::PortRange {
                    start,
                    end: Some(end),
                })
            } else {
                let port: usize = part.parse().ok()?;
                Some(models::PortRange {
                    start: port,
                    end: None,
                })
            }
        })
        .collect();

    if ranges.is_empty() {
        vec![]
    } else {
        vec![models::Port {
            protocol: Some(models::Protocol::TCP),
            range: ranges,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_scan_basic() {
        let req = ScanRequest {
            target: "192.168.1.1".into(),
            max_hosts: 4,
            max_checks: 4,
            port_range: None,
            vt_oids: None,
            exclude_hosts: None,
            discovery: None,
        };
        let scan = build_scan_model(&req, vec![]).unwrap();
        assert_eq!(scan.target.hosts, vec!["192.168.1.1"]);
        assert!(scan.vts.is_empty());
    }

    #[test]
    fn build_scan_multi_target() {
        let req = ScanRequest {
            target: "10.0.0.1, 10.0.0.2".into(),
            max_hosts: 2,
            max_checks: 1,
            port_range: Some("22,80-443".into()),
            vt_oids: None,
            exclude_hosts: Some(vec!["10.0.0.3".into()]),
            discovery: None,
        };
        let scan = build_scan_model(&req, vec![]).unwrap();
        assert_eq!(scan.target.hosts.len(), 2);
        assert_eq!(scan.target.excluded_hosts, vec!["10.0.0.3"]);
        assert!(!scan.target.ports.is_empty());
    }

    #[test]
    fn build_scan_empty_target() {
        let req = ScanRequest {
            target: "".into(),
            max_hosts: 4,
            max_checks: 4,
            port_range: None,
            vt_oids: None,
            exclude_hosts: None,
            discovery: None,
        };
        assert!(build_scan_model(&req, vec![]).is_err());
    }

    #[test]
    fn expand_cidr() {
        let hosts = expand_targets("192.168.1.0/30").unwrap();
        assert_eq!(hosts, vec!["192.168.1.1", "192.168.1.2"]);
    }

    #[test]
    fn expand_mixed() {
        let hosts = expand_targets("10.0.0.1, 192.168.1.0/30").unwrap();
        assert_eq!(hosts, vec!["10.0.0.1", "192.168.1.1", "192.168.1.2"]);
    }

    #[test]
    fn parse_port_range() {
        let ports = parse_ports(&Some("22,80-443".into()));
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].range.len(), 2);
        assert_eq!(ports[0].range[0].start, 22);
        assert_eq!(ports[0].range[1].start, 80);
        assert_eq!(ports[0].range[1].end, Some(443));
    }
}

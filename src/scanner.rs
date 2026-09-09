use std::net::IpAddr;
use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::error::CynError;

use scannerlib::feed::{HashSumNameLoader, Update};
use scannerlib::models;
use scannerlib::nasl::nasl_std_executor;
use scannerlib::nasl::syntax::Loader;
use scannerlib::nasl::utils::scan_ctx::Target;
use scannerlib::scanner::{Scan, ScanRunner};
use scannerlib::scheduling::Scheduler;
use scannerlib::storage::inmemory::InMemoryStorage;
use scannerlib::storage::items::nvt::Feed;
use scannerlib::storage::{Remover, Retriever, ScanID};

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
}

pub struct ScanRequest {
    pub target: String,
    pub max_hosts: u32,
    pub max_checks: u32,
    pub port_range: Option<String>,
    pub vt_oids: Option<Vec<String>>,
    pub exclude_hosts: Option<Vec<String>>,
}

pub async fn run_scan(config: &Config, request: &ScanRequest) -> Result<Vec<Finding>, CynError> {
    let feed_path = &config.feed_path;

    if !feed_path.exists() {
        return Err(CynError::FeedNotFound {
            path: feed_path.display().to_string(),
        });
    }

    let storage = Arc::new(InMemoryStorage::new());
    let loader = Loader::from_feed_path(feed_path);

    let verifier = HashSumNameLoader::sha256(&loader)
        .map_err(|e| CynError::Scanner(format!("failed to create feed verifier: {e}")))?;
    let updater = Update::init("cyn", 5, loader.clone(), &storage, verifier);
    updater
        .perform_update()
        .await
        .map_err(|e| CynError::Scanner(format!("feed update failed: {e}")))?;

    let vts = load_vts(&storage, request).await?;

    let models_scan = build_scan_model(request, vts)?;
    let scan_id = models_scan.scan_id.clone();
    let scan = Scan::default_to_localhost(models_scan);

    let capacity = scan.targets.len().max(1);
    let (tx_target, rx_target) = mpsc::channel::<Target>(capacity);

    for target in &scan.targets {
        if tx_target.send(target.clone()).await.is_err() {
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
        scan.targets.len(),
        scan.vts.len()
    );

    let runner: ScanRunner<Arc<InMemoryStorage>> = ScanRunner::new(
        &storage,
        &loader,
        &executor,
        schedule,
        &scan,
        &None,
        rx_target,
    )
    .map_err(|e| CynError::Scanner(format!("failed to create scan runner: {e}")))?;

    let mut stream = Box::pin(runner.stream());
    while let Some(result) = stream.next().await {
        match result {
            Ok(script_result) => {
                if script_result.has_succeeded() {
                    tracing::debug!(
                        oid = %script_result.oid,
                        stage = ?script_result.stage,
                        "script succeeded"
                    );
                } else {
                    tracing::debug!(
                        oid = %script_result.oid,
                        stage = ?script_result.stage,
                        "script did not succeed"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "script execution error");
            }
        }
    }

    let results = storage
        .remove(&ScanID(scan_id))
        .await
        .map_err(|e| CynError::Scanner(format!("failed to retrieve results: {e}")))?;

    let findings = results
        .unwrap_or_default()
        .into_iter()
        .filter_map(result_to_finding)
        .collect();

    Ok(findings)
}

async fn load_vts(
    storage: &InMemoryStorage,
    request: &ScanRequest,
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
                    tracing::info!("loaded {} VTs from feed", vts.len());
                    Ok(vts
                        .iter()
                        .map(|vt| models::VT {
                            oid: vt.oid.clone(),
                            parameters: vec![],
                        })
                        .collect())
                }
                None => Ok(vec![]),
            }
        }
    }
}

fn result_to_finding(result: models::Result) -> Option<Finding> {
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

    Some(Finding {
        host,
        port: result.port,
        protocol: result.protocol.map(|p| match p {
            models::Protocol::TCP => "tcp".to_string(),
            models::Protocol::UDP => "udp".to_string(),
        }),
        oid: result.oid.unwrap_or_default(),
        name: String::new(),
        severity: None,
        cves: vec![],
        description: result.message.clone(),
        solution: None,
        references: vec![],
        result_type: result_type.to_string(),
    })
}

fn build_scan_model(
    request: &ScanRequest,
    vts: Vec<models::VT>,
) -> Result<models::Scan, CynError> {
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
            alive_test_methods: vec![models::AliveTestMethods::Icmp],
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
        None => return vec![],
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
        };
        let scan = build_scan_model(req, vec![]).unwrap();
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
        };
        let scan = build_scan_model(req, vec![]).unwrap();
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
        };
        assert!(build_scan_model(req, vec![]).is_err());
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

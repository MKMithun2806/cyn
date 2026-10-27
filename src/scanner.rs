use std::io::{self, IsTerminal, Write};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use tokio::sync::mpsc;

use crate::confidence::Confidence;
use crate::config::Config;
use crate::discovery::{DiscoveryResult, Protocol};
use crate::error::CynError;
use crate::selection::{select_vts, SelectionContext};

use scannerlib::feed::{HashSumNameLoader, Update};
use scannerlib::models;
use scannerlib::nasl::nasl_std_executor;
use scannerlib::nasl::syntax::Loader;
use scannerlib::nasl::utils::ctx::{CtxTarget, CtxTargets, ScanCtx, TargetId};
use scannerlib::scanner::{Scan, ScanRunner, ScriptResultKind};
use scannerlib::scheduling::Scheduler;
use scannerlib::storage::inmemory::InMemoryStorage;
use scannerlib::storage::items::kb::{self, KbContextKey, KbItem};
use scannerlib::storage::items::nvt::Feed;
use scannerlib::storage::{Remover, Retriever, ScanID, Target};

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
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub category: FindingCategory,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FindingCategory {
    Vulnerability,
    Misconfiguration,
    Exposure,
    #[default]
    Information,
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
    pub profile_execution: bool,
}

pub async fn run_scan(
    config: &Config,
    request: &ScanRequest,
    open_ports: &[u16],
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
    loader.clear_cache();
    eprintln!("Feed ready.");

    eprintln!("Selecting vulnerability checks...");
    let vts = load_vts(&storage, request, open_ports).await?;
    eprintln!("Selected {} vulnerability checks.", vts.len());
    let selected_count = vts.len();

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
    let scheduler_started = Instant::now();
    let schedule = scheduler
        .execution_plan(&scan.vts)
        .await
        .map_err(|e| CynError::Scanner(format!("scheduling failed: {e}")))?;
    let scheduler_elapsed = scheduler_started.elapsed();

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
    if request.profile_execution {
        scan_ctx.enable_execution_profile();
    }

    let seeded = seed_discovery_kb(&scan_ctx, request.discovery.as_ref()).await?;
    if seeded > 0 {
        tracing::info!(
            services = seeded,
            "seeded OpenVAS KB from discovery results"
        );
    }

    let runner = ScanRunner::new(schedule, rx_target, &scan_ctx)
        .map_err(|e| CynError::Scanner(format!("failed to create scan runner: {e}")))?;

    let scheduled_executions = runner
        .scheduled_execution_count()
        .saturating_mul(target_count);
    eprintln!(
        "Execution plan: {scheduled_executions} scheduled VT execution(s) across {target_count} target(s) ({selected_count} selected, {} in scan model, {} added by scheduling, scheduler {:.2}s)",
        scan.vts.len(),
        scheduled_executions.saturating_sub(scan.vts.len().saturating_mul(target_count)),
        scheduler_elapsed.as_secs_f64()
    );
    let mut progress = ScanProgress::new(scheduled_executions);
    let mut phase_timings = PhaseTimings::default();
    let mut succeeded = 0u32;
    let mut failed = 0u32;
    let mut errors = 0u32;
    let mut body_attempted = 0u32;
    let mut skipped: std::collections::BTreeMap<&'static str, u32> =
        std::collections::BTreeMap::new();

    let mut stream = Box::pin(runner.stream());
    let mut total_results = 0usize;
    while let Some(result) = stream.next().await {
        total_results += 1;
        progress.update(total_results);

        match result {
            Ok(script_result) => {
                phase_timings.add(script_result.timing);
                match &script_result.kind {
                    ScriptResultKind::MissingRequiredKey(_) => {
                        *skipped.entry("missing required key").or_default() += 1;
                    }
                    ScriptResultKind::MissingMandatoryKey(_) => {
                        *skipped.entry("missing mandatory key").or_default() += 1;
                    }
                    ScriptResultKind::MissingPort(_, _) => {
                        *skipped.entry("missing required port").or_default() += 1;
                    }
                    ScriptResultKind::ContainsExcludedKey(_) => {
                        *skipped.entry("excluded key").or_default() += 1;
                    }
                    ScriptResultKind::InvalidPort(_, _) => {
                        *skipped.entry("invalid port").or_default() += 1;
                    }
                    ScriptResultKind::StorageError(_) => {
                        *skipped.entry("storage error").or_default() += 1;
                    }
                    ScriptResultKind::ReturnCode(_) | ScriptResultKind::Error(_) => {
                        body_attempted += 1;
                    }
                }
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
    eprintln!(
        "VT execution summary: {total_results} attempted · {body_attempted} NASL bodies entered · {} prerequisite skips · {errors} runner errors",
        skipped.values().sum::<u32>()
    );
    for (reason, count) in skipped {
        eprintln!("  {reason}: {count}");
    }
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

    progress.finish(findings.len());
    if request.profile_execution {
        eprintln!(
            "Execution profile: source load {:.1}s · prerequisite checks {:.1}s · NASL parse {:.1}s · interpreter/builtins {:.1}s",
            phase_timings.source_load.as_secs_f64(),
            phase_timings.prerequisites.as_secs_f64(),
            phase_timings.parse.as_secs_f64(),
            phase_timings.interpreter.as_secs_f64(),
        );
        let mut builtins = scan_ctx.builtin_profile();
        builtins.sort_by_key(|(_, metrics)| std::cmp::Reverse(metrics.elapsed));
        for (name, metrics) in builtins.into_iter().take(12) {
            eprintln!(
                "  builtin {name}: {:.2}s total · {} calls · {} retries",
                metrics.elapsed.as_secs_f64(),
                metrics.calls,
                metrics.retries
            );
        }
    }
    tracing::info!("findings after conversion: {}", findings.len());

    Ok(findings)
}

#[derive(Default)]
struct PhaseTimings {
    source_load: Duration,
    prerequisites: Duration,
    parse: Duration,
    interpreter: Duration,
}

impl PhaseTimings {
    fn add(&mut self, timing: scannerlib::scanner::ExecutionTiming) {
        self.source_load += timing.source_load;
        self.prerequisites += timing.prerequisites;
        self.parse += timing.parse;
        self.interpreter += timing.interpreter;
    }
}

struct ScanProgress {
    total: usize,
    completed: usize,
    started: Instant,
    last_draw: Instant,
    io_start: Option<u64>,
    interactive: bool,
}

impl ScanProgress {
    fn new(total: usize) -> Self {
        let now = Instant::now();
        let interactive = io::stderr().is_terminal();
        if interactive {
            eprintln!();
            eprintln!("SCANNING");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }
        Self {
            total,
            completed: 0,
            started: now,
            last_draw: now.checked_sub(Duration::from_secs(1)).unwrap_or(now),
            io_start: process_read_bytes(),
            interactive,
        }
    }

    fn update(&mut self, completed: usize) {
        self.completed = completed;
        if self.last_draw.elapsed() < Duration::from_millis(250) {
            return;
        }
        self.last_draw = Instant::now();
        self.draw(None);
    }

    fn finish(&mut self, findings: usize) {
        self.draw(Some(findings));
        if self.interactive {
            eprintln!();
        }
    }

    fn draw(&self, findings: Option<usize>) {
        let elapsed = self.started.elapsed();
        let rate = self.completed as f64 / elapsed.as_secs_f64().max(0.001);
        let io_value = match (self.io_start, process_read_bytes()) {
            (Some(start), Some(current)) => format_mb(current.saturating_sub(start)),
            _ => "n/a".into(),
        };
        let mem = process_memory();
        let rss_value = format_mb(mem.rss_bytes);
        let findings = findings
            .map(|value| value.to_string())
            .unwrap_or_else(|| "—".into());
        let line = format!(
            "Executions {:>5} / {:<5}   Rate {:>7.1} exec/s   RSS {:>7}   Elapsed {:>8}   I/O {:>8}   Findings {:>4}",
            self.completed,
            self.total,
            rate,
            rss_value,
            format_duration(elapsed),
            io_value,
            findings,
        );

        if self.interactive {
            eprint!("\r\x1b[2K{line}");
            let _ = io::stderr().flush();
        } else if findings != "—" {
            eprintln!("{line}");
        }
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours}h {minutes:02}m")
    } else {
        format!("{minutes}m {seconds:02}s")
    }
}

fn format_mb(bytes: u64) -> String {
    if bytes >= 1_000_000_000 {
        format!("{:.1} GB", bytes as f64 / 1_000_000_000.0)
    } else {
        format!("{:.0} MB", bytes as f64 / 1_000_000.0)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessMemory {
    pub rss_bytes: u64,
    pub vm_bytes: u64,
    pub swap_bytes: u64,
}

#[cfg(target_os = "linux")]
pub fn process_memory() -> ProcessMemory {
    let mut mem = ProcessMemory::default();
    if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
        let parts: Vec<&str> = statm.split_whitespace().collect();
        if parts.len() >= 2 {
            let page_size = 4096u64;
            if let Ok(vm_pages) = parts[0].parse::<u64>() {
                mem.vm_bytes = vm_pages * page_size;
            }
            if let Ok(rss_pages) = parts[1].parse::<u64>() {
                mem.rss_bytes = rss_pages * page_size;
            }
        }
    }
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmSwap:") {
                if let Some(kb_str) = rest.trim().strip_suffix("kB") {
                    if let Ok(kb) = kb_str.trim().parse::<u64>() {
                        mem.swap_bytes = kb * 1024;
                    }
                }
            }
        }
    }
    mem
}

#[cfg(not(target_os = "linux"))]
pub fn process_memory() -> ProcessMemory {
    ProcessMemory::default()
}

#[cfg(target_os = "linux")]
fn process_read_bytes() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/self/io").ok()?;
    contents.lines().find_map(|line| {
        line.strip_prefix("read_bytes:")
            .and_then(|value| value.trim().parse().ok())
    })
}

#[cfg(not(target_os = "linux"))]
fn process_read_bytes() -> Option<u64> {
    None
}

/// Seed the OpenVAS knowledge base with facts already established by an
/// imported discovery result. NASLs still perform their own safe probes, but
/// dependent checks no longer have to rediscover facts that Nmap already gave
/// us (notably TCP/PORTS, service aliases, and application CPE records).
async fn seed_discovery_kb(
    scan_ctx: &ScanCtx<'_>,
    discovery: Option<&DiscoveryResult>,
) -> Result<usize, CynError> {
    let Some(discovery) = discovery else {
        return Ok(0);
    };
    let mut service_count = 0;

    for host in &discovery.hosts {
        let context = (scan_ctx.scan().clone(), Target(host.address.clone()));

        for service in &host.services {
            let port = service.port.to_string();
            let protocol = match service.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            };

            set_discovery_kb(
                scan_ctx,
                &context,
                kb::KbKey::Port(match service.protocol {
                    Protocol::Tcp => kb::Port::Tcp(port.clone()),
                    Protocol::Udp => kb::Port::Udp(port.clone()),
                }),
                KbItem::Number(1),
            )
            .await?;

            if service.protocol == Protocol::Tcp {
                set_discovery_custom_kb(
                    scan_ctx,
                    &context,
                    "TCP/PORTS",
                    KbItem::String(port.clone()),
                )
                .await?;
                set_discovery_kb(
                    scan_ctx,
                    &context,
                    kb::KbKey::Host(kb::Host::Tcp),
                    KbItem::Boolean(true),
                )
                .await?;
            }

            if let Some(name) = service.service.as_deref().filter(|name| {
                !name.is_empty()
                    && !name.eq_ignore_ascii_case("-")
                    && !name.eq_ignore_ascii_case("unknown")
                    && !name.eq_ignore_ascii_case("tcpwrapped")
            }) {
                set_discovery_kb(
                    scan_ctx,
                    &context,
                    kb::KbKey::Service(kb::Service::Custom(name.to_ascii_lowercase())),
                    KbItem::String(format!("{port}/{protocol}")),
                )
                .await?;
                if service.protocol == Protocol::Tcp {
                    set_discovery_kb(
                        scan_ctx,
                        &context,
                        kb::KbKey::KnownTcp(service.port),
                        KbItem::String(name.to_ascii_lowercase()),
                    )
                    .await?;
                }
                if name.eq_ignore_ascii_case("http") || name.eq_ignore_ascii_case("https") {
                    set_discovery_kb(
                        scan_ctx,
                        &context,
                        kb::KbKey::Service(kb::Service::Custom("www".to_string())),
                        KbItem::String(format!("{port}/{protocol}")),
                    )
                    .await?;
                }
            }

            if let Some(banner) = service
                .fingerprint
                .as_ref()
                .and_then(|fingerprint| fingerprint.banner.as_deref())
                .filter(|banner| !banner.is_empty())
            {
                set_discovery_kb(
                    scan_ctx,
                    &context,
                    kb::KbKey::Banner(service.port),
                    KbItem::String(banner.to_owned()),
                )
                .await?;
            }

            if let Some(server) = service
                .fingerprint
                .as_ref()
                .and_then(|fingerprint| fingerprint.headers.get("server"))
            {
                if let Some(key) = server_banner_key(server) {
                    set_discovery_custom_kb(
                        scan_ctx,
                        &context,
                        &format!("{key}/banner"),
                        KbItem::Boolean(true),
                    )
                    .await?;
                }
            }

            if let Some(product) = service
                .product
                .as_deref()
                .filter(|value| !value.is_empty() && *value != "-")
            {
                let product_key = product
                    .split_whitespace()
                    .next()
                    .unwrap_or(product)
                    .to_ascii_lowercase();
                set_discovery_custom_kb(
                    scan_ctx,
                    &context,
                    &format!("{product_key}/detected"),
                    KbItem::Boolean(true),
                )
                .await?;
                if let Some(name) = service.service.as_deref().filter(|name| !name.is_empty()) {
                    set_discovery_custom_kb(
                        scan_ctx,
                        &context,
                        &format!("{product_key}/{}/detected", name.to_ascii_lowercase()),
                        KbItem::Boolean(true),
                    )
                    .await?;
                }
            }

            for cpe in &service.cpe {
                seed_cpe_application(
                    scan_ctx,
                    &context,
                    cpe,
                    service.port,
                    protocol,
                    service.service.as_deref(),
                )
                .await?;
            }
            service_count += 1;
        }
    }

    Ok(service_count)
}

async fn set_discovery_kb(
    scan_ctx: &ScanCtx<'_>,
    context: &(ScanID, Target),
    key: kb::KbKey,
    value: KbItem,
) -> Result<(), CynError> {
    scan_ctx
        .storage()
        .dispatch(KbContextKey(context.clone(), key), value)
        .await
        .map_err(|error| CynError::Scanner(format!("failed to seed discovery KB: {error}")))
}

async fn set_discovery_custom_kb(
    scan_ctx: &ScanCtx<'_>,
    context: &(ScanID, Target),
    key: &str,
    value: KbItem,
) -> Result<(), CynError> {
    set_discovery_kb(scan_ctx, context, kb::KbKey::Custom(key.to_string()), value).await
}

async fn seed_cpe_application(
    scan_ctx: &ScanCtx<'_>,
    context: &(ScanID, Target),
    cpe: &str,
    port: u16,
    protocol: &str,
    service: Option<&str>,
) -> Result<(), CynError> {
    let Some(base_cpe) = cpe_base(cpe) else {
        return Ok(());
    };
    let location = format!("{port}/{protocol}");
    let entry = format!("cyn.discovery#-#{cpe}#-#{location}#-#{port}#-#{protocol}");

    for (key, value) in [
        ("HostDetails", KbItem::String("App".into())),
        ("HostDetails/NVT", KbItem::String("cyn.discovery".into())),
        (
            "HostDetails/NVT/cyn.discovery/App",
            KbItem::String(cpe.into()),
        ),
        (
            &format!("HostDetails/NVT/cyn.discovery/{cpe}"),
            KbItem::String(location.clone()),
        ),
        (&format!("get_app/{base_cpe}"), KbItem::String(entry)),
        (
            &format!("get_app/ports/{base_cpe}"),
            KbItem::String(port.to_string()),
        ),
        (
            &format!("get_app/protocols/{base_cpe}"),
            KbItem::String(protocol.into()),
        ),
    ] {
        set_discovery_custom_kb(scan_ctx, context, key, value).await?;
    }
    if let Some(service) = service.filter(|value| !value.is_empty()) {
        set_discovery_custom_kb(
            scan_ctx,
            context,
            &format!("get_app/services/{port}/{base_cpe}"),
            KbItem::String(service.to_ascii_lowercase()),
        )
        .await?;
    }
    Ok(())
}

fn cpe_base(cpe: &str) -> Option<String> {
    let fields: Vec<&str> = cpe.split(':').collect();
    let count = if cpe.starts_with("cpe:2.3:") { 5 } else { 4 };
    (fields.len() >= count).then(|| fields[..count].join(":"))
}

fn server_banner_key(server: &str) -> Option<String> {
    let product = server
        .trim()
        .split(|character: char| character == '/' || character.is_whitespace())
        .next()
        .filter(|value| {
            !value.is_empty()
                && value != &"-"
                && value.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
                })
        })?;
    Some(product.to_string())
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
    let (result_type, category) = match result.r_type {
        models::ResultType::Alarm => ("Alarm", FindingCategory::Vulnerability),
        models::ResultType::Log => ("Log", FindingCategory::Information),
        models::ResultType::Error => ("Error", FindingCategory::Information),
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

    let confidence = crate::confidence::assess(result_type, &evidence);

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
        confidence,
        category,
    })
}

fn build_scan_model(request: &ScanRequest, vts: Vec<models::VT>) -> Result<models::Scan, CynError> {
    let hosts = expand_targets(&request.target)?;

    if hosts.is_empty() {
        return Err(CynError::InvalidTarget(request.target.clone()));
    }

    let ports = parse_ports(&request.port_range)?;

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

pub(crate) fn expand_targets(target: &str) -> Result<Vec<String>, CynError> {
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
                    if prefix > 32 {
                        return Err(CynError::InvalidTarget(part.to_string()));
                    }
                    let ip_num = u32::from_be_bytes(ipv4.octets());
                    let mask = if prefix == 0 {
                        0
                    } else {
                        !0u32 << (32 - prefix)
                    };
                    let network = ip_num & mask;
                    let broadcast = network | !mask;
                    let (start, end) = if prefix >= 31 {
                        (network, broadcast)
                    } else {
                        (network + 1, broadcast - 1)
                    };
                    if u64::from(end) - u64::from(start) + 1 > 1_000_000 {
                        return Err(CynError::InvalidTarget(format!(
                            "target range is too large: {part}"
                        )));
                    }
                    for addr in start..=end {
                        hosts.push(IpAddr::from(addr.to_be_bytes()).to_string());
                    }
                }
                IpAddr::V6(_) => {
                    return Err(CynError::InvalidTarget(format!(
                        "IPv6 CIDR expansion is not supported: {part}"
                    )))
                }
            }
        } else {
            hosts.push(part.to_string());
        }
    }
    Ok(hosts)
}

fn parse_ports(port_range: &Option<String>) -> Result<Vec<models::Port>, CynError> {
    let range = match port_range {
        Some(r) => r,
        None => {
            // Default: all TCP ports
            return Ok(vec![models::Port {
                protocol: Some(models::Protocol::TCP),
                range: vec![models::PortRange {
                    start: 1,
                    end: Some(65535),
                }],
            }]);
        }
    };

    let mut ranges = Vec::new();
    for part in range.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(CynError::Scanner("port list contains an empty item".into()));
        }
        if part.contains('-') {
            let parts: Vec<&str> = part.splitn(2, '-').collect();
            let start: usize = parts[0]
                .parse()
                .map_err(|_| CynError::Scanner(format!("invalid port range: {part}")))?;
            let end: usize = parts[1]
                .parse()
                .map_err(|_| CynError::Scanner(format!("invalid port range: {part}")))?;
            if !(1..=65535).contains(&start) || !(1..=65535).contains(&end) || start > end {
                return Err(CynError::Scanner(format!("invalid port range: {part}")));
            }
            ranges.push(models::PortRange {
                start,
                end: Some(end),
            });
        } else {
            let port: usize = part
                .parse()
                .map_err(|_| CynError::Scanner(format!("invalid port: {part}")))?;
            if !(1..=65535).contains(&port) {
                return Err(CynError::Scanner(format!("invalid port: {part}")));
            }
            ranges.push(models::PortRange {
                start: port,
                end: None,
            });
        }
    }

    Ok(vec![models::Port {
        protocol: Some(models::Protocol::TCP),
        range: ranges,
    }])
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
            profile_execution: false,
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
            profile_execution: false,
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
            profile_execution: false,
        };
        assert!(build_scan_model(&req, vec![]).is_err());
    }

    #[test]
    fn expand_cidr() {
        let hosts = expand_targets("192.168.1.0/30").unwrap();
        assert_eq!(hosts, vec!["192.168.1.1", "192.168.1.2"]);
    }

    #[test]
    fn expand_single_host_cidr() {
        assert_eq!(
            expand_targets("192.168.1.7/32").unwrap(),
            vec!["192.168.1.7"]
        );
        assert_eq!(
            expand_targets("192.168.1.6/31").unwrap(),
            vec!["192.168.1.6", "192.168.1.7"]
        );
    }

    #[test]
    fn expand_mixed() {
        let hosts = expand_targets("10.0.0.1, 192.168.1.0/30").unwrap();
        assert_eq!(hosts, vec!["10.0.0.1", "192.168.1.1", "192.168.1.2"]);
    }

    #[test]
    fn parse_port_range() {
        let ports = parse_ports(&Some("22,80-443".into())).unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].range.len(), 2);
        assert_eq!(ports[0].range[0].start, 22);
        assert_eq!(ports[0].range[1].start, 80);
        assert_eq!(ports[0].range[1].end, Some(443));
    }

    #[test]
    fn rejects_invalid_ports() {
        assert!(parse_ports(&Some("80,garbage".into())).is_err());
        assert!(parse_ports(&Some("100-20".into())).is_err());
        assert!(parse_ports(&Some("65536".into())).is_err());
    }

    #[test]
    fn cpe_base_preserves_vendor_and_product() {
        assert_eq!(
            cpe_base("cpe:/a:vsftpd:vsftpd:2.3.4").as_deref(),
            Some("cpe:/a:vsftpd:vsftpd")
        );
        assert_eq!(
            cpe_base("cpe:2.3:a:openbsd:openssh:4.7p1:*:*:*:*:*:*").as_deref(),
            Some("cpe:2.3:a:openbsd:openssh")
        );
        assert!(cpe_base("not-a-cpe").is_none());
    }

    #[test]
    fn server_banner_key_matches_openvas_product_key_convention() {
        assert_eq!(server_banner_key("Boa/0.93.15").as_deref(), Some("Boa"));
        assert_eq!(server_banner_key("nginx 1.24.0").as_deref(), Some("nginx"));
        assert!(server_banner_key("-").is_none());
    }

    #[test]
    fn process_memory_returns_non_zero_rss_on_linux() {
        let mem = process_memory();
        #[cfg(target_os = "linux")]
        assert!(mem.rss_bytes > 0);
        let _ = mem.vm_bytes;
        let _ = mem.swap_bytes;
    }

    #[test]
    fn loader_cache_can_be_cleared_and_reloaded() {
        let temp_dir = tempfile::tempdir().unwrap();
        let plugin_file = temp_dir.path().join("test.nasl");
        std::fs::write(&plugin_file, "display('ok');").unwrap();

        let loader = Loader::from_feed_path(temp_dir.path());
        let code = loader.load("test.nasl").unwrap();
        assert_eq!(code, "display('ok');");
        std::fs::write(&plugin_file, "display('updated');").unwrap();
        let cached = loader.load("test.nasl").unwrap();
        assert_eq!(cached, "display('ok');");

        loader.clear_cache();
        let reloaded = loader.load("test.nasl").unwrap();
        assert_eq!(reloaded, "display('updated');");
    }
}

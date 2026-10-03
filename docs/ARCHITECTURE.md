# Cyn Architecture

## Overview

Cyn is a lightweight CLI around the OpenVAS scanning engine. It removes the
GVM management stack (gvmd, GSA, gsad, GMP, PostgreSQL, Redis) and exposes
the scanner directly as a single Rust binary.

A scan is a pipeline of distinct phases, each implemented by its own module:

```
        cyn scan <target>
              |
              v
   +---------------------+
   | 1. Preflight        |  ping reachability check (single hosts only)
   +---------------------+
              |
              v
   +---------------------+
   | 2. Discovery        |  nmap backend (auto) or --nmap XML import
   +---------------------+  open TCP ports + best-effort UDP services
              |
              v
   +---------------------+
   | 3. Fingerprint      |  SSH / HTTP / SMB banner + header probing
   +---------------------+  fills product, version, CPE, protocol
              |
              v
   +---------------------+
   | 4. Feed load        |  NASL feed -> InMemoryStorage (sha256 verified)
   +---------------------+
              |
              v
   +---------------------+
   | 5. VT selection     |  95K feed VTs -> checks relevant to the
   +---------------------+  discovered services (family/port/version)
              |
              v
   +---------------------+
   | 6. KB seeding       |  discovery facts written into the OpenVAS
   +---------------------+  knowledge base before execution
              |
              v
   +---------------------+
   | 7. VT execution      |  scheduler plans waves/stages; ScanRunner
   +---------------------+  runs NASL scripts with live progress
              |
              v
   +---------------------+
   | 8. Local checks     |  passive configuration checks derived from
   +---------------------+  fingerprints (no extra network I/O)
              |
              v
   +---------------------+
   | 9. Reporting        |  terminal / JSON / CSV (+ --report file)
   +---------------------+
```

## Phase details

### 1. Preflight (`src/preflight.rs`)

A single `ping -c 1 -W 2` is run before discovery for plain single-host
targets. Reachable targets continue automatically; unreachable targets show
a confirm prompt (`y/N`) so scans against firewalled hosts are deliberate.
Target ranges (CIDR) and comma-separated lists skip the check.

### 2. Discovery (`src/discovery/`)

Two input paths, one shared model (`DiscoveryResult`):

- **Automatic**: Cyn shells out to `nmap -Pn -oX -` itself.
  TCP: `-sT -sV --version-light` plus `-p <ports>` when `--ports` is given,
  otherwise `-p-` (all 65535 ports). UDP: `-sU` with `-p <ports>` or
  `--top-ports 20`, merged in **best-effort** (UDP usually needs root, and a
  failed UDP pass must not fail the scan).
- **Imported**: `--nmap scan.xml` parses an existing `nmap -oX` file instead
  of running nmap.

If no open TCP ports are found the scan stops with an actionable error
before any feed loading happens.

### 3. Fingerprint (`src/fingerprint/`)

Every open TCP service gets a 2-second connect probe that refines what nmap
reported:

- **SSH** — reads the banner, parses `SSH-2.0-OpenSSH_9.6p1 ...` into
  product + version.
- **HTTP** — sends `HEAD / HTTP/1.0`, captures the status line as banner,
  all response headers, and the `Server:` product.
- **SMB** — sends an SMB2 NEGOTIATE and confirms the `\xfeSMB` magic.

Results are stored as `ServiceFingerprint { protocol, banner, product,
version, title, headers, ... }` and only fill fields that are still empty,
so richer nmap data is never overwritten.

### 4. Feed load (`src/scanner.rs`)

The NASL feed is loaded into `InMemoryStorage` on every scan — no Redis,
no daemon, no cache warm-up. `sha256sums` verification runs via
`HashSumNameLoader::sha256`, and the loader's bulk source cache is released
as soon as the update completes to keep RSS low.

### 5. VT selection (`src/selection.rs`)

The feed ships ~95,000 scripts. Selection prunes them to checks that can
plausibly apply, in order:

1. **Family skip** — deprecated/OS-specific families (attic, Windows,
   vendor-specific local checks, ...) are dropped. `Port scanners` is always
   kept as bootstrap.
2. **Port match** — the VT's `required_ports` / `required_udp_ports` must
   intersect the discovered open ports.
3. **Relevance** — VT name/filename/family tokens are matched against the
   discovered service identities (service, product, version, CPE, banner
   tokens) at the matching port. A VT carrying an `Affected` version tag
   (e.g. `< 10.5`) is only selected when the observed version actually
   falls below the bound.
4. **Dependency closure** — transitive VT dependencies are added back so
   prerequisites still run.

An explicit `--vt <OID,...>` list bypasses filtering entirely. Selection
stats (kept/port-skip/family-skip/irrelevant-skip/dependencies) are logged
in the scan output.

### 6. KB seeding (`seed_discovery_kb` in `src/scanner.rs`)

Discovery and fingerprint facts are written into the OpenVAS knowledge base
before execution: open ports, `TCP/PORTS`, service aliases (`www` for
http/https), banners, `<product>/detected` flags, CPE `get_app/*` records
and `HostDetails/NVT/cyn.discovery/*` entries. VTs that gate on these keys
run immediately instead of trying to rediscover the service themselves.

### 7. VT execution (`openvas/rust` scannerlib)

`Scheduler::new(storage).execution_plan(&scan.vts)` builds a wave/stage
plan, then `ScanRunner` executes it against targets from a channel,
honoring `--max-hosts` / `--max-checks`. Progress (executions done/total,
rate, RSS, I/O, elapsed, findings) is redrawn on stderr every 250 ms when
stderr is a TTY. The `synscan.nasl` OID is removed from the plan so no raw
socket / `CAP_NET_RAW` is ever needed; the built-in TCP connect scanner
(`openvas_tcp_scanner.nasl`) handles VT-side port checks.

Discovery knowledge seeded in phase 6 is consulted by `find_service` before
it considers any active probing, so scans never re-probe what is already
known.

### 8. Local checks (`src/checks/`)

Passive findings derived purely from fingerprints — no additional network
I/O:

| Check | OID | Severity |
|-------|-----|----------|
| HTTP security headers missing | `cyn.check.http_security_headers_missing` | 4.0 |
| HTTP server banner disclosure | `cyn.check.http_server_banner_disclosure` | 2.0 |
| Legacy SSH protocol enabled | `cyn.check.legacy_ssh_protocol_enabled` | 7.0 |

### 9. Reporting (`src/output.rs`, `src/report.rs`)

Terminal output (severity roll-up, service inventory, findings with
confidence) or machine-readable JSON/CSV, plus optional `--report FILE`
and the `cyn convert` subcommand. See [FINDINGS.md](FINDINGS.md).

## Port Scanning

Cyn uses two methods for port discovery:

### 1. Built-in TCP connect scanner

The `openvas_tcp_scanner.nasl` VT performs TCP connect scans using
`tokio::net::TcpStream::connect()`. This requires **no raw sockets**
(no `CAP_NET_RAW`, no root). It completes the full TCP handshake,
grabs banners, and measures RTT statistics.

The raw SYN scanner (`synscan.nasl`) is excluded because it requires
`CAP_NET_RAW` via libpcap. The TCP connect scanner is more compatible
and provides richer results (banners, RTT stats, port state classification).

### 2. Nmap discovery

Users can run nmap separately for port discovery and feed the results
into Cyn via `--nmap scan.xml`. The `nmap` module parses nmap's `-oX`
XML output and extracts open TCP ports.

```
nmap -sV -oX scan.xml 192.168.1.1
cyn scan 192.168.1.1 --nmap scan.xml
```

### Default behavior

When no `--nmap` file is given, Cyn runs nmap itself as the discovery
backend. Without `--ports` the TCP pass scans all 65535 ports (`-p-`),
which is thorough but slow — prefer `--ports` or an imported nmap report
for routine scans.

## OpenVAS Source Reconnaissance

### Repository Structure (upstream: greenbone/openvas-scanner)

The upstream repository contains two scanner implementations:

1. **C Scanner** (`src/`, `misc/`, `nasl/`): The legacy C implementation.
   Built with CMake. Communicates with the management stack via Redis.
   - Binary: `openvas`
   - Startup: `openvas --scan-start <id>`, `openvas --scan-stop <id>`
   - Config: `openvas -s` outputs INI configuration
   - Uses Redis for: NVT cache, scan configuration, results, KB items

2. **Rust Scanner** (`rust/scannerlib`): The new implementation.
   - Binary: `scannerctl` (CLI), `openvasd` (daemon)
   - Library: `scannerlib`
   - Already supports Redis-free scanning via `InMemoryStorage` + `ScanRunner`

### Redis Usage (what we remove)

The C scanner uses Redis for two purposes:

1. **NVT Cache** (`nvticache` key): Stores VT metadata (OID, name,
   references, preferences) so the C scanner can read them during a scan.

2. **Scan Knowledge Base**: Each scan gets its own Redis namespace (DB).
   Stores scan configuration, preferences, and results. The Rust bridge
   writes config to Redis, starts the C scanner, then reads results back.

The Rust `scannerctl execute scan` path already avoids Redis entirely by
using `InMemoryStorage`.

### Feed System

- Feed directory contains `.nasl` scripts
- `sha256sums` file for integrity verification
- `plugin_feed_info.inc` defines feed metadata (PLUGIN_SET, FEED_NAME, etc.)
- Each script has a description block with OID, name, tags, references
- Feed update runs each script in "description mode" to extract metadata

### Result Format

Results from the scanner are pipe-delimited strings:

```
result_type|||host_ip|||hostname|||port|||OID|||value[|||uri]
```

Result types: LOG, ERRMSG, ALARM, HOST_START, HOST_END, DEADHOST,
HOSTS_COUNT, HOSTS_EXCLUDED

### Key scannerlib Modules

- `scannerlib::feed::Update` - Feed loading and verification
- `scannerlib::storage::inmemory::InMemoryStorage` - Redis-free storage
- `scannerlib::scanner::ScanRunner` - Executes VTs against targets
- `scannerlib::scanner::preferences` - Scan preference handling
- `scannerlib::scheduling::Scheduler` - VT execution ordering
- `scannerlib::nasl::syntax::Loader` - NASL script loading
- `scannerlib::models` - Scan, Result, VT data types

### Cyn Modules

| Module | Role |
|--------|------|
| `cli` | Command-line interface (clap) |
| `config` | Feed path resolution (`~/.local/share/cyn/plugins`) |
| `feed` | Feed status and rsync-based update |
| `preflight` | Pre-scan reachability check |
| `discovery` | Nmap backend + discovery model (TCP/UDP services) |
| `nmap` | Nmap XML import parser |
| `fingerprint` | SSH / HTTP / SMB banner + header probing |
| `selection` | Targeted, version-aware VT selection |
| `scanner` | Scan orchestration, feed load, KB seeding, result harvesting |
| `checks` | Passive configuration security checks |
| `confidence` | Evidence-based confidence scoring |
| `report` | JSON/CSV report generation and loading |
| `output` | Terminal and JSON finding output |
| `error` | Error types |

### Upstream Revision

Cyn v1 targets: `main` branch of `greenbone/openvas-scanner`
Scanner library: `scannerlib` (Rust crate in `rust/` directory)

The upstream tree is vendored directly under `openvas/` (tracked as a
normal directory, not a submodule) so local compatibility fixes stay
versioned with Cyn.

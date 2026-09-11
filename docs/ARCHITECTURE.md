# Cyn Architecture

## Overview

Cyn is a lightweight CLI around the OpenVAS scanning engine. It removes the
GVM management stack (gvmd, GSA, gsad, GMP, PostgreSQL, Redis) and exposes
the scanner directly.

## Architecture

```
                    CYN
                     |
        +------------+------------+
        |                         |
   Feed manager               Scan CLI
        |                         |
        +------------+------------+
                     |
                     v
            Modified OpenVAS
              scan engine
                     |
           +---------+---------+
           |                   |
      TCP connect         Nmap import
      scanner             (XML parser)
           |                   |
           +---------+---------+
                     |
                     v
              raw results
                     |
                     v
              Rust parser
                     |
              +------+------+
              |             |
          terminal         JSON
```

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

### 2. Nmap XML import

Users can run nmap separately for port discovery and feed the results
into Cyn via `--nmap scan.xml`. The `nmap` module parses nmap's `-oX`
XML output and extracts open TCP ports.

```
nmap -sV -oX scan.xml 192.168.1.1
cyn scan 192.168.1.1 --nmap scan.xml
```

### Default behavior

When neither `--ports` nor `--nmap` is specified, Cyn scans all 65535
TCP ports with a warning suggesting the user narrow the range.

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

### Key Modules

- `scannerlib::feed::Update` - Feed loading and verification
- `scannerlib::storage::inmemory::InMemoryStorage` - Redis-free storage
- `scannerlib::scanner::ScanRunner` - Executes VTs against targets
- `scannerlib::scanner::preferences` - Scan preference handling
- `scannerlib::scheduling::Scheduler` - VT execution ordering
- `scannerlib::nasl::syntax::Loader` - NASL script loading
- `scannerlib::models` - Scan, Result, VT data types

### Cyn Modules

- `cli` - Command-line interface (clap)
- `config` - Feed path resolution
- `feed` - Feed status and update
- `nmap` - Nmap XML import parser
- `scanner` - Scan orchestration, VT loading, result collection
- `output` - Terminal and JSON formatting
- `error` - Error types

### Upstream Revision

Cyn v1 targets: `main` branch of `greenbone/openvas-scanner`
Scanner library: `scannerlib` (Rust crate in `rust/` directory)

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

### Upstream Revision

Cyn v1 targets: `main` branch of `greenbone/openvas-scanner`
Scanner library: `scannerlib` (Rust crate in `rust/` directory)

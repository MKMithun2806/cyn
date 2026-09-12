# AGENTS.md

## Quick Start

```bash
cargo build          # ~5 min first time, incremental ~30s
cargo test           # 16 tests, all pass
cargo clippy -- -D warnings   # clean, no warnings
./target/debug/cyn scan 192.168.1.15 --nmap pentest-ground.xml
```

## What This Is

**Cyn** is a lightweight Rust CLI vulnerability scanner that wraps OpenVAS's NASL engine. It eliminates the entire GVM stack (Redis, gvmd, PostgreSQL, GSA, gsad) — single binary, no raw sockets, no sudo.

- **Git repo**: `git@github.com:MKMithun2806/cyn.git` at `/home/alpine/cyn`
- **Current version**: `0.4.1` in `Cargo.toml`
- **Target machine**: Alpine Linux, 3.8GB RAM, 2 cores, x86_64 musl

## Architecture

```
src/
  main.rs       - Entry point, command dispatch, port range parsing
  cli.rs        - Clap CLI: feed, scan, convert subcommands
  config.rs     - Feed path resolution (~/.local/share/cyn)
  scanner.rs    - Core scan orchestration, VT filtering, finding extraction (587 lines)
  nmap.rs       - Nmap XML parser (quick-xml), tests
  report.rs     - JSON/CSV report generation, load findings
  output.rs     - Terminal and JSON finding output
  error.rs      - CynError enum
  feed.rs       - Feed status and update
```

The Rust library is a git submodule at `openvas/rust/` (pinned to `v23.50.24`).

```
openvas/rust/
  src/scanner/vt_runner.rs      - VT execution, KB key checks, port validation
  src/scanner/scan_runner.rs    - Scan stream orchestration
  src/scheduling/mod.rs         - VT execution plan builder (waves + stages)
  src/nasl/utils/scan_ctx.rs    - KB key storage (uses ip_addr().to_string())
  src/storage/inmemory/         - InMemoryStorage (Redis-free)
```

## Build Config

`.cargo/config.toml`:
```toml
[build]
rustflags = ["-C", "target-feature=-crt-static"]
```

**NEVER use `--target x86_64-unknown-linux-musl`** — the config already sets crt-static=false. Just `cargo build`.

## Feed

- Default feed version: `24.10`
- Feed path: `~/.local/share/cyn/plugins/`
- Actual installed version: `202609080600`
- ~95,102 NASL scripts
- Status: `cyn feed status`

## Commands

```bash
# Scan with nmap import (preferred)
cyn scan 192.168.1.15 --nmap pentest-ground.xml

# Scan specific ports
cyn scan 192.168.1.15 --ports 80,443,8080

# Quiet mode (suppresses UTF-8 warnings)
cyn scan 192.168.1.15 --nmap pentest-ground.xml --quiet

# Save report during scan
cyn scan 192.168.1.15 --nmap pentest-ground.xml --report findings.json

# Convert existing findings
cyn convert findings.json --format csv -o report.csv

# Feed management
cyn feed status
```

## Key Fixes Applied

### 1. Raw socket avoidance (no CAP_NET_RAW needed)
- `synscan.nasl` (OID `1.3.6.1.4.1.25623.1.0.11219`) is filtered out
- TCP connect scanner (`openvas_tcp_scanner.nasl`) handles port scanning
- Alive test set to `ConsiderAlive` (skips Boreas raw socket detection)

### 2. Rustls crypto provider panic fix
- `docker-registry` pulls `aws-lc-rs`; `sqlx` pulls `ring` — conflict causes panic
- Fixed by pinning workspace deps to ring-only in `openvas/rust/Cargo.toml`:
  ```toml
  [workspace.dependencies]
  rustls = { version = "0.23", default-features = false, features = ["ring", "logging", "std", "tls12"] }
  tokio-rustls = { version = "0.26", default-features = false, features = ["ring"] }
  ```
- `docker-registry` with `default-features = false`
- `reqwest` with `rustls-no-provider` feature
- `install_default()` called at process startup in `main.rs`

### 3. KB context key mismatch fix (in submodule)
- `VTRunner::generate_key()` in `vt_runner.rs` uses `self.target.ip_addr().to_string()`
- `ScanCtx::kb_key()` in `scan_ctx.rs` uses `ip_addr().to_string()`
- Previously `generate_key()` used `original_target_str()` which differs for hostnames
- Fix committed locally in `openvas/` submodule (`24b5d37`), not pushable upstream

### 4. VT pre-filtering (95K → 32K VTs)
- Port-based: skip VTs whose `required_ports` don't match open ports
- Family-based: skip deprecated/OS-specific families (attic, Windows, CentOS, etc.)
- Filter is in `load_vts()` in `scanner.rs`

### 5. Default all-port scan
- When no `--ports` or `--nmap` specified, scans all 65535 TCP ports with warning

## Nmap Import

Parser at `src/nmap.rs` uses `quick-xml` streaming parser. Test data at:
- `/mnt/usb/pentest-ground.xml` — target 178.79.134.182, ports: 81, 4280, 6379, 7001, 9000
- `/mnt/usb/scan.xml` — alternate scan file

## CI/CD

- `.github/workflows/ci.yml` — fmt, clippy, test, build-flags verification
- `.github/workflows/release.yml` — auto-releases when Cargo.toml version changes
  - Targets: linux-musl-amd64, linux-musl-arm64, windows-msvc-amd64, macos-arm64

## Known Issues

### VT filtering still loads 32K VTs
The family filter skips OS-specific families but keeps ~32K "no port requirement" VTs. Feed loading takes ~4 minutes. Consider:
- More aggressive family filtering (only keep vulnerability-relevant families)
- Skip VTs with `required_keys`/`mandatory_keys` that won't be satisfied
- Add `--max-vts` flag to cap VT count

### Only informational findings produced
Last scan of pentest-ground.xml produced 17 Log-type results (hostname, OS detection, etc.) but zero Alarm/vulnerability findings. Possible causes:
- Target services may not have the specific CVEs being tested
- VTs may need dependency chains that aren't fully satisfied
- The KB key fix (item 3 above) should help but needs verification with a fresh scan

### Submodule can't push upstream
The `openvas/` submodule has 2 local commits that can't be pushed to Greenbone's repo:
- `ac4064c` — rustls ring-only fix
- `24b5d37` — KB context key fix

## What To Do Next

1. **Verify KB fix works**: Run a scan against a known-vulnerable service (e.g., Redis 6379 with no auth) and check if Alarm results appear
2. **Reduce VT count further**: Filter to only vulnerability families ("Web server abuses", "General", etc.) — should drop from 32K to ~5K
3. **Add service detection**: Use nmap service info to further filter VTs (e.g., only run Redis VTs on port 6379)
4. **Persistence**: Save scan findings to disk automatically for `convert` subcommand
5. **Performance**: Profile feed loading — the UTF-8 fallback decoder is slow on 95K files

## Testing

```bash
cargo test              # runs all 16 tests
cargo test nmap         # nmap parser tests
cargo test scanner      # scanner model tests
cargo test report       # report generation tests
```

Tests are in-module (not separate test files). Key test data:
- `pentest-ground.xml` in repo root
- Inline test data in `src/nmap.rs` and `src/report.rs`

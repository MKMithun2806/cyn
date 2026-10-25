# Cyn

[![CI](https://github.com/MKMithun2806/cyn/actions/workflows/ci.yml/badge.svg)](https://github.com/MKMithun2806/cyn/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)

A lightweight CLI vulnerability scanner built on the OpenVAS scanning
engine. Cyn removes the entire GVM management stack (Redis, gvmd,
PostgreSQL, GSA, gsad) and exposes the scanner as a single Rust binary:
no daemons, no database, no raw sockets, no sudo.

## Install

One line — no root, no package manager:

```sh
curl -fsSL https://raw.githubusercontent.com/MKMithun2806/cyn/main/install.py | python3
```

The installer ([install.py](install.py)) detects your OS, architecture
and C library (musl vs glibc), picks the matching binary from the
**latest release**, verifies its sha256 checksum, installs it to
`~/.local/bin` and puts it on your PATH (editing your shell rc only if
needed). If your platform has no published build it says so explicitly,
lists the supported targets, and points you at the source build.

## Quick start

```sh
cyn feed update                    # download the NVT feed (~95K scripts)
cyn scan 192.168.1.15              # discover, fingerprint, and scan a host
```

## What a scan does

Cyn is not a thin wrapper — a scan runs a full reconnaissance-to-report
pipeline:

1. **Preflight** — pings the target first and asks before scanning an
   unreachable host.
2. **Discovery** — runs `nmap` itself (or imports `--nmap scan.xml`),
   collecting open TCP ports, services, products and versions, plus a
   best-effort UDP pass.
3. **Fingerprinting** — probes SSH, HTTP and SMB services directly for
   banners, response headers and protocol details nmap missed.
4. **Targeted VT selection** — prunes the ~95,000-script feed down to the
   checks that can apply to *this* target: family filters, open-port
   matching, service/product token relevance, and version-aware bounds
   (`Affected: < 10.5` only runs when the observed version qualifies).
5. **KB seeding** — writes discovered ports, services, banners and CPEs
   into the scan's knowledge base so VTs detect them instantly instead of
   re-probing the target.
6. **VT execution** — a scheduler runs the selected scripts in planned
   waves with live progress, throughput and memory telemetry. Discovery
   knowledge is consulted before any active probing.
7. **Security checks** — passive configuration checks (HTTP security
   headers, banner disclosure, legacy SSH) run against the fingerprints.
8. **Reporting** — severity roll-up and findings on the terminal, JSON on
   request, plus JSON/CSV report files.

## Highlights

- **No Redis / PostgreSQL** — pure in-memory scanning via `scannerlib`
- **Single binary** — no daemons, no services to manage
- **No raw sockets** — TCP connect scanning only, no `CAP_NET_RAW`, no root
- **Automatic discovery** — Cyn runs nmap for you; `--ports` narrows it,
  `--nmap` reuses an existing report
- **Targeted testing** — ~95K feed scripts pruned to what applies, with
  version-aware selection and dependency closure
- **Evidence-rich findings** — every finding carries service evidence, a
  detection reason, category and a confidence score
- **Live progress** — executions/sec, RSS, disk I/O, elapsed time and
  findings counted while the scan runs
- **Nmap import** — parse `nmap -oX` output to feed discovered ports
- **Terminal & JSON output** — readable summaries or machine-parseable data
- **Reports** — JSON or CSV files during a scan, `cyn convert` afterwards
- **Selective scanning** — filter by VT OID, port range, or exclude hosts
- **Quiet & verbose modes** — silence chatter, or enable execution
  profiling (`--verbose`)

## Commands

| Command | Description |
|---------|-------------|
| `cyn feed status` | Show local feed version and script count |
| `cyn feed update` | Sync the NVT feed from upstream |
| `cyn scan <target>` | Run a vulnerability scan |
| `cyn convert <findings>` | Convert a previous JSON findings file to JSON/CSV |

## Scan options

```
cyn scan [OPTIONS] <TARGET>

Options:
  -o, --output <FORMAT>     terminal | json  [default: terminal]
      --max-hosts <N>       concurrent hosts   [default: 4]
      --max-checks <N>      checks per host    [default: 4]
      --vt <OID,OID,...>    specific VTs to run (bypasses selection)
      --ports <RANGE>       discovery port filter, e.g. "22,80-443"
  -n, --nmap <FILE>         import ports from nmap XML file
      --exclude <HOSTS>     comma-separated hosts to skip
  -q, --quiet               suppress informational warnings
  -r, --report <FILE>       write a report file after the scan
      --report-format <F>   json | csv  [default: json]
  -v, --verbose             diagnostics + execution profiling (global)

      --feed <PATH>         NVT feed directory (env: CYN_FEED_PATH)
  -c, --config <PATH>       TOML configuration file (currently supports feed_path)
```

### Port discovery

By default Cyn runs nmap against **all 65535 TCP ports** for discovery —
thorough but slow. The vulnerability checks then target the open ports found
by discovery. Narrow discovery one of these ways:

| Method | Example | Description |
|--------|---------|-------------|
| `--ports` | `--ports 22,80,443` | Constrain the built-in discovery pass |
| `--nmap` | `--nmap scan.xml` | Import from an nmap XML file (skips running nmap) |

Imported Nmap data is restricted to the host or hosts named by the scan target.
IPv4 `/31` and `/32` targets are supported; oversized ranges and invalid port
values are rejected.

**Nmap workflow:**

```sh
# 1. Discover ports with nmap
nmap -sV -oX scan.xml 192.168.1.0/24

# 2. Feed discovered ports into Cyn
cyn scan 192.168.1.1 --nmap scan.xml
cyn scan 192.168.1.2 --nmap scan.xml
```

## Findings and reports

The default terminal output gives a severity roll-up, a service
inventory, and a detailed findings list with CVEs, solutions and
confidence:

```
╭─ Findings (2) ───────────────────────────────────────╮
│ 1. ! [7.0] OpenSSH user enumeration                   │
│    Host: 192.168.1.15   Port: 22/tcp                  │
│    Category: vulnerability                           │
│    Confidence: 90% (CONFIRMED)                        │
│    OID: 1.3.6.1.4.1.25623.1.0.108096                 │
│    CVEs: CVE-2018-15473                               │
│    Solution: Upgrade OpenSSH ...                      │
╰──────────────────────────────────────────────────────╯
```

Machine-readable output and saved reports:

```sh
# JSON findings on stdout
cyn scan 192.168.1.15 --nmap scan.xml -o json

# Save a report during the scan
cyn scan 192.168.1.15 --nmap scan.xml --report findings.json
cyn scan 192.168.1.15 --nmap scan.xml --report findings.csv --report-format csv

# Convert a previous scan's findings
cyn convert findings.json --format csv -o report.csv
```

Findings include an evidence-backed confidence score
(`CONFIRMED` / `LIKELY` / `POSSIBLE` / `INFORMATIONAL`), a category
(`vulnerability`, `misconfiguration`, `exposure`, `information`), and
provenance (`OpenVAS VT feed` or `Cyn security checks`). The full schema
is documented in [docs/FINDINGS.md](docs/FINDINGS.md).

## Progress and telemetry

While the scan runs, stderr shows a live status line (redrawn every
250 ms when attached to a terminal):

```
Executions  1240 / 3812   Rate    42.7 exec/s   RSS   412 MB   Elapsed   0m 29s   I/O    88 MB   Findings    7
```

`--verbose` additionally prints an execution profile after the scan
(source load, NASL parse, interpreter time, top builtins).

## Documentation

- [Scanning](docs/SCANNING.md) — pipeline phases, options, telemetry
- [Findings & Reports](docs/FINDINGS.md) — schema, confidence, CSV/JSON
- [Architecture](docs/ARCHITECTURE.md) — design and internals
- [Installation](docs/INSTALL.md) — build from source, system dependencies
- [Changelog](CHANGELOG.md) — recent changes

## Building

```sh
git clone https://github.com/MKMithun2806/cyn.git
cd cyn
cargo build --release
```

The binary is at `target/release/cyn`. See
[docs/INSTALL.md](docs/INSTALL.md) for platform-specific instructions,
system dependencies and feed setup.

CI (`fmt`, `clippy -D warnings`, tests, build-flag verification) runs on
every push to `main`; releases are published automatically for:

- `x86_64-unknown-linux-gnu`
- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`

## Vendored OpenVAS library

The `openvas/` directory contains the OpenVAS scanner library vendored
directly in this repository. It is intentionally tracked as a normal
directory so Cyn can carry the local compatibility fixes it needs without
depending on a separate submodule commit.

## Licensing & Third-Party Code

This project is licensed under the **GNU General Public License v2.0 or later** (GPL-2.0-or-later). See the [LICENSE](LICENSE) file for details.

### Vendored Dependencies
* **OpenVAS / Greenbone Community Edition:** Located under `openvas/`. Retains its original GPL-2.0-only, GPL-2.0-or-later, OpenSSL exception, and MIT terms as specified in `openvas/COPYING` and `openvas/license-details.md`. Third-party file-level licensing terms remain applicable to those components.

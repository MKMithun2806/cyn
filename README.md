# Cyn

[![CI](https://github.com/MKMithun2806/cyn/actions/workflows/ci.yml/badge.svg)](https://github.com/MKMithun2806/cyn/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange?logo=rust)](https://www.rust-lang.org/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html)

A lightweight CLI vulnerability scanner built on the OpenVAS scanning engine.
Cyn removes the entire GVM management stack (Redis, gvmd, PostgreSQL, GSA, gsad) and exposes the scanner directly as a single Rust binary.

## Quick start

```sh
cyn feed update          # download the NVT feed
cyn scan 192.168.1.0/24  # scan a target
```

For faster, targeted scans:

```sh
# Scan specific ports
cyn scan 192.168.1.1 --ports 22,80,443

# Import nmap results for port discovery
nmap -sV -oX scan.xml 192.168.1.1
cyn scan 192.168.1.1 --nmap scan.xml

# Suppress informational warnings
cyn scan 192.168.1.1 --quiet
```

## Features

- **No Redis / PostgreSQL** -- pure in-memory scanning via `scannerlib`
- **Single binary** -- no daemons, no services to manage
- **Fast startup** -- feed loaded on demand, no cache warm-up
- **Nmap import** -- parse `nmap -oX` output to feed discovered ports
- **All-port default** -- scans all 65535 TCP ports when no ports specified
- **No raw sockets** -- uses TCP connect scan, no `CAP_NET_RAW` required
- **Terminal & JSON output** -- human-readable or machine-parseable results
- **Selective scanning** -- filter by VT OID, port range, or exclude hosts
- **Quiet mode** -- suppress informational warnings with `--quiet`

## Commands

| Command | Description |
|---------|-------------|
| `cyn feed status` | Show local feed version and script count |
| `cyn feed update` | Sync the NVT feed from upstream |
| `cyn scan <target>` | Run a vulnerability scan |

## Scan options

```
cyn scan [OPTIONS] <TARGET>

Options:
  -o, --output <FORMAT>     terminal | json  [default: terminal]
      --max-hosts <N>       concurrent hosts   [default: 4]
      --max-checks <N>      checks per host    [default: 4]
      --vt <OID,OID,...>    specific VTs to run
      --ports <RANGE>       port filter, e.g. "22,80-443"
  -n, --nmap <FILE>         import ports from nmap XML file
      --exclude <HOSTS>     comma-separated hosts to skip
  -q, --quiet               suppress informational warnings
```

### Port discovery

By default, Cyn scans all 65535 TCP ports. This is thorough but slow. Use one of these to narrow the scan:

| Method | Example | Description |
|--------|---------|-------------|
| `--ports` | `--ports 22,80,443` | Specify ports directly |
| `--nmap` | `--nmap scan.xml` | Import from nmap XML output |

**Nmap workflow:**

```sh
# 1. Discover ports with nmap
nmap -sV -oX scan.xml 192.168.1.0/24

# 2. Feed discovered ports into Cyn
cyn scan 192.168.1.1 --nmap scan.xml
cyn scan 192.168.1.2 --nmap scan.xml
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) -- design and internals
- [Installation](docs/INSTALL.md) -- build from source, system dependencies

## Building

```sh
git clone --recursive https://github.com/MKMithun2806/cyn.git
cd cyn
cargo build --release
```

The binary is at `target/release/cyn`. See [docs/INSTALL.md](docs/INSTALL.md) for platform-specific instructions and system dependencies.

## License

GPL-2.0-or-later -- see [LICENSE](LICENSE).

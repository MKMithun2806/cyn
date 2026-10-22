# Scanning

This guide covers everything that happens between `cyn scan <target>` and
the final report. For the module-level design see
[ARCHITECTURE.md](ARCHITECTURE.md); for the finding schema see
[FINDINGS.md](FINDINGS.md).

## Quick examples

```sh
# Full pipeline with automatic discovery (runs nmap for you)
cyn scan 192.168.1.15

# Constrain discovery to specific ports
cyn scan 192.168.1.15 --ports 22,80,443,6379

# Reuse an existing nmap scan instead of running nmap again
nmap -sV -oX scan.xml 192.168.1.15
cyn scan 192.168.1.15 --nmap scan.xml

# Machine-readable output + a saved report
cyn scan 192.168.1.15 --nmap scan.xml -o json --report findings.json

# CSV report directly
cyn scan 192.168.1.15 --nmap scan.xml --report findings.csv --report-format csv

# Quiet run, constrained concurrency
cyn scan 192.168.1.15 --nmap scan.xml --quiet --max-hosts 2 --max-checks 8
```

## Pipeline phases

### 1. Pre-scan reachability check

For plain single-host targets Cyn pings the host once (`ping -c 1 -W 2`):

- **Reachable** — the scan continues automatically.
- **Unreachable** — a `y/N` prompt asks whether to continue anyway, so a
  firewalled or sleeping host doesn't waste a full scan.
- **Skipped** — CIDR ranges and comma-separated host lists skip the check.
- **Unavailable** — `ping` missing or errored; the scan continues with a
  note.

### 2. Port and service discovery

If `--nmap <file>` is given, that XML is parsed. Otherwise Cyn runs nmap
itself:

| Pass | nmap flags | Ports |
|------|-----------|-------|
| TCP (required) | `-Pn -sT -sV --version-light -oX -` | `--ports` value, else `-p-` (all 65535) |
| UDP (best-effort) | `-Pn -sU -oX -` | `--ports` value, else `--top-ports 20` |

The UDP pass is merged in only if it succeeds — UDP scans usually need
root, and failure there must not fail the whole scan. If nothing has an
open TCP port, the scan stops before loading the feed.

Only discovered open TCP ports are handed to the VT engine, so the
expensive NASL phase never touches closed ports.

### 3. Fingerprinting

Each open TCP service gets a 2-second connect probe (SSH, HTTP, SMB) that
fills in protocol banners, HTTP headers, product and version details.
nmap's own `product`/`version`/`cpe` data is preserved — fingerprinting
only fills fields that are still empty.

### 4. Feed load and VT selection

The feed is loaded into memory (sha256-verified) and then pruned from
~95,000 VTs down to the checks that can apply to *this* target:

- deprecated / OS-specific families dropped
- VTs whose required ports aren't open dropped
- VTs with no token overlap with the discovered services dropped
- version-bounded VTs (`Affected: < 10.5`) only kept when the observed
  version is actually below the bound
- transitive VT dependencies added back

Pass `--vt 1.3.6.1.4.1.25623.1.0.108096,...` to run specific OIDs and
bypass selection entirely.

### 5. Knowledge-base seeding

Discovered ports, services, banners and CPEs are written into the scan's
knowledge base before execution, so VTs that check for known services
detect them immediately instead of re-probing the target.

### 6. VT execution

A scheduler builds an execution plan (waves/stages, dependencies
honored), then runs it with `--max-hosts` hosts in parallel and
`--max-checks` checks per host. No raw sockets are used at any point.

### 7. Local security checks

After VT execution, passive configuration checks run against the
fingerprints (HTTP security headers, server banner disclosure, legacy
SSH protocol). They need no extra network traffic. See
[FINDINGS.md](FINDINGS.md#local-security-checks).

### 8. Output and report

Findings go to stdout (terminal table or JSON), and `--report FILE`
writes a JSON or CSV report alongside.

## Progress and telemetry

While stderr is a TTY, a single status line is redrawn every 250 ms:

```
Executions  1240 / 3812   Rate    42.7 exec/s   RSS   412 MB   Elapsed   0m 29s   I/O    88 MB   Findings    7
```

| Column | Meaning |
|--------|---------|
| `Executions` | completed VT executions / scheduled total |
| `Rate` | executions per second |
| `RSS` | resident memory of the scanner process |
| `Elapsed` | wall-clock time since execution started |
| `I/O` | bytes read from disk since execution started (Linux) |
| `Findings` | findings collected so far |

Non-TTY runs print only the final line. Feed-load, selection and plan
summaries are always printed to stderr:

```
Loading vulnerability feed...
Feed ready.
Selecting vulnerability checks...
Selected 214 vulnerability checks.
Execution plan: 3812 scheduled VT execution(s) across 1 target(s) ...
```

With `--verbose`, Cyn additionally prints an execution profile after the
scan (source load, prerequisite checks, NASL parse, interpreter time and
the top builtins by elapsed time) and enables the engine's execution
profiling.

## Scan options

```
cyn scan [OPTIONS] <TARGET>

Arguments:
  <TARGET>                Host, CIDR, or comma-separated host list

Options:
  -o, --output <FORMAT>   terminal | json                    [default: terminal]
      --max-hosts <N>     Concurrent hosts                   [default: 4]
      --max-checks <N>    Checks per host                    [default: 4]
      --vt <OID,OID,...>  Specific VTs to run (bypasses automatic selection)
      --ports <RANGE>     Discovery port filter, e.g. "22,80-443"
  -n, --nmap <FILE>       Import ports/services from nmap XML (skips running nmap)
      --exclude <HOSTS>   Comma-separated hosts to skip
  -q, --quiet             Suppress informational logging (errors still shown)
  -r, --report <FILE>     Write a report file after the scan
      --report-format <F> json | csv (used with --report)   [default: json]

Global options:
      --feed <PATH>       NVT feed directory (env: CYN_FEED_PATH)
  -c, --config <PATH>     Configuration file (env: CYN_CONFIG)
  -v, --verbose           Diagnostic logging + execution profiling
```

## Port discovery strategies

| Method | Example | When to use |
|--------|---------|-------------|
| Automatic (all ports) | `cyn scan 10.0.0.5` | Unknown target, you can afford a full pass |
| Automatic (narrow) | `cyn scan 10.0.0.5 --ports 1-10000` | You know the service range |
| Import nmap XML | `cyn scan 10.0.0.5 --nmap scan.xml` | You already ran nmap / have a report |

**Nmap workflow:**

```sh
# 1. Discover ports and versions with nmap
nmap -sV -oX scan.xml 192.168.1.0/24

# 2. Feed discovered ports into Cyn per host
cyn scan 192.168.1.1 --nmap scan.xml
cyn scan 192.168.1.2 --nmap scan.xml
```

## Logging levels

| Mode | Filter | Effect |
|------|--------|--------|
| default | `error` | Only errors on stderr |
| `--quiet` | `error` | Same, explicitly silenced normal chatter |
| `--verbose` | `error,cyn=info,...` | Scan lifecycle info + execution profile |

Top-level failures print `error: <message>` and exit with status `1`.

## Feed management

```sh
cyn feed status                          # path, version, NVT count
cyn feed update                          # rsync from Greenbone community feed
cyn feed update --feed-version 24.10     # explicit release (default: 24.10)
cyn feed update --url rsync://...        # custom upstream
```

The feed is re-read (and re-verified) on every scan; the loader's bulk
source cache is released right after the update to keep memory in check.

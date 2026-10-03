# Changelog

Notable changes to Cyn, most recent first. This file currently covers the
30 most recent commits (`63963f3` .. `d9a713f`, 2026-10-01 → 2026-10-03);
earlier history is in the [git log](https://github.com/MKMithun2806/cyn/commits/main).

## [Unreleased]

### Added

- **Automatic service discovery** — Cyn now runs `nmap` itself when no
  `--nmap` file is given (`-sT -sV --version-light`, all ports unless
  `--ports` is set), with a best-effort UDP pass merged in
  (`a2cea1f`).
- **Service fingerprinting** — SSH, HTTP and SMB probes fill in banners,
  response headers, product and version details that nmap missed,
  without overwriting richer nmap data (`25f4bf2`).
- **Targeted vulnerability selection** — the ~95K-script feed is pruned
  per target by family, open port, and service/product token relevance,
  with a dependency-closure pass to keep prerequisites
  (`bf38eb6`), later made **version aware** so VTs with an `Affected`
  bound (e.g. `< 10.5`) only run when the observed version qualifies
  (`7da51be`).
- **Evidence-rich findings** — findings carry service/product/version/CPE
  evidence, a detection reason, and their provenance (`OpenVAS VT feed`
  or `Cyn security checks`) (`9d97a9f`).
- **Confidence scoring** — every finding gets an evidence-weighted score
  (0–100) mapped to `CONFIRMED` / `LIKELY` / `POSSIBLE` / `INFORMATIONAL`
  with human-readable reasons (`5597b6d`).
- **Configuration security checks** — passive checks for missing HTTP
  security headers, HTTP server banner disclosure, and legacy SSH
  protocol usage, run after VT execution with no extra network I/O
  (`13c788d`).
- **Polished colored terminal output** — severity roll-ups, service
  inventory table, and actionable findings boxes (`0c5054c`,
  `63963f3`, `e501f02`).
- **Pre-scan reachability check** — a single ping before discovery, with
  a `y/N` confirm prompt for unreachable hosts; ranges and host lists
  skip it (`5ddb49b`).
- **Live scan throughput** — a 250 ms redrawn status line showing
  executions/sec, RSS, disk I/O, elapsed time and findings collected
  (`5a0dba5`).
- **Memory and loader cache telemetry** — lightweight process memory
  (RSS/VM/swap) and NASL loader cache reporting, including retained KB
  memory after a scan (`8e7a9a8`, `02ffa04`).

### Fixed

- Discovery facts are **seeded into the OpenVAS knowledge base** before
  execution, so VTs gate on known ports/services instead of re-probing
  the target (`fa9a87d`), and `find_service` now consults the discovery
  KB before any active probing (`dfcf240`).
- Alternative `required_ports` on VTs are honored during execution
  planning (`22cdb73`).
- Progress reporting is aligned with actually scheduled executions
  instead of drifting (`5cbbdb8`), and the progress output was
  simplified (`79763bc`).
- Completed fork replay results are released instead of being retained
  for the life of the scan (`00e9ed0`).
- NASL socket handle slots are reused rather than leaked across VTs
  (`d23dcc8`).
- Self-appending `make_list` assignments are optimized in the NASL
  interpreter (`d9a713f`).
- Needless clone in the `select_vts` test fixed for
  `clippy::cloned_ref_to_slice_refs` (`6b9bff5`).

### Changed

- Replay diagnostics machinery removed end-to-end (~600 lines across the
  interpreter, storage, and scan orchestration) (`d80c870`).

### Performance

- NASL source is cached in memory during feed loading (`8ff4ace`), shared
  between cached source buffers (`7b3b255`), and the bulk VT source
  cache is released right after a feed update to keep RSS low
  (`c806f57`).

### CI / Build

- Static `krb5`/`libpcap` archives are built (and cached) before cargo —
  fixes clean-checkout failures on `build-cache/archives/include`
  (`1bde516`).
- `capnproto` is installed on runners and baked into the aarch64 cross
  image so `sequoia-ipc`'s build script can run (`843e05f`).
- Release packaging fixed; musl archives are now built with the musl
  toolchain (`5b343fe`).

# Findings and Reports

Every check Cyn runs produces a **finding** — either from the OpenVAS VT
feed or from Cyn's own passive configuration checks. Findings are rendered
on the terminal, printed as JSON, written to a report file, or converted
after the fact.

## Result types

| `result_type` | Meaning |
|---------------|---------|
| `Alarm` | A vulnerability or misconfiguration was detected |
| `Log` | Informational output (OS detection, banners, ...) — not a vulnerability claim |
| `Error` | The check failed to run |

`HostStart`, `HostEnd`, `DeadHost` and `HostDetail` engine records are
dropped before findings are built.

## Categories

`category` classifies the finding for reporting:

| Category | Typical source |
|----------|----------------|
| `vulnerability` | OpenVAS VT `Alarm` results |
| `misconfiguration` | Missing security headers, legacy protocols |
| `exposure` | Banner/version disclosure |
| `information` | `Log` and `Error` results |

## Severity

VT severities are CVSS-style scores. The terminal summary bands them:

| Band | Range |
|------|-------|
| CRITICAL | ≥ 9.0 |
| HIGH | 7.0 – 9.0 |
| MEDIUM | 4.0 – 7.0 |
| LOW | < 4.0 |
| INFO | all `Log` results |

## Confidence scoring

Each finding carries a confidence score derived from the evidence
attached to it (`src/confidence.rs`):

| Evidence kind | Weight | Reason |
|---------------|--------|--------|
| `service` | 20 | Service was confirmed on the target port |
| `product` | 15 | Product identity was detected |
| `version` | 25 | Version information was detected |
| `cpe` | 25 | A CPE was detected for the service |
| `banner` | 10 | A protocol banner supports the detection |
| `header` | 10 | Protocol headers support the detection |
| `missing-header` | 15 | A missing security header was directly observed |
| `result` | 5 | The OpenVAS VT produced a result |

Distinct kinds accumulate (capped at 100) and map to a level:

| Score | Level |
|-------|-------|
| 85 – 100 | `CONFIRMED` |
| 60 – 84 | `LIKELY` |
| 0 – 59 | `POSSIBLE` |
| any `Log` result | `INFORMATIONAL` (score 100, not a vulnerability claim) |

The reasons list every contributing kind in human-readable form.

## Local security checks

Passive checks derived from fingerprints, run after VT execution
(`source: "Cyn security checks"`):

| Finding | OID | Severity | Trigger |
|---------|-----|----------|---------|
| HTTP security headers missing | `cyn.check.http_security_headers_missing` | 4.0 | Missing `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` (plus `Strict-Transport-Security` on HTTPS) |
| HTTP server banner disclosure | `cyn.check.http_server_banner_disclosure` | 2.0 | A `Server:` header reveals product/version |
| Legacy SSH protocol enabled | `cyn.check.legacy_ssh_protocol_enabled` | 7.0 | Banner starts with `SSH-1.` |

## Terminal output

`cyn scan` (default `--output terminal`) prints:

1. A start banner, preflight result, discovery summary.
2. A live progress line on stderr (see [SCANNING.md](SCANNING.md)).
3. A `CYN SECURITY SCAN` summary box: per-host service counts, severity
   roll-up, misconfiguration/exposure/error counts, and a service
   inventory table (`HOST PORT SERVICE PRODUCT VERSION`).
4. A findings box listing **`Alarm` and `Error` findings only**, each with
   severity, host, port, category, confidence, OID, summary, CVEs,
   solution and references. If there are none:

   ```
   ✓ No vulnerabilities found
     12 informational result(s) hidden; use --output json to inspect them.
   ```

## JSON output

`--output json` prints a pretty-printed array of findings on stdout.
Schema (field order as serialized):

| Field | Type | Notes |
|-------|------|-------|
| `host` | string | Target address |
| `port` | number \| null | Port number |
| `protocol` | string \| null | `tcp` / `udp` |
| `oid` | string | VT OID or `cyn.check.*` |
| `name` | string | Human-readable name |
| `severity` | number \| null | CVSS-style score |
| `cves` | string[] | Associated CVEs |
| `description` | string \| null | Full description |
| `solution` | string \| null | Remediation |
| `references` | string[] | `class: id` entries |
| `result_type` | string | `Alarm` / `Log` / `Error` |
| `service` | string \| null | Detected service name |
| `product` | string \| null | Detected product |
| `version` | string \| null | Detected version |
| `cpe` | string[] | CPE identifiers |
| `evidence` | object[] | `{ kind, source, value }` |
| `detection_reason` | string \| null | Why this fired |
| `source` | string \| null | `OpenVAS VT feed` or `Cyn security checks` |
| `confidence` | object | `{ score, level, reasons }` |
| `category` | string | `vulnerability` / `misconfiguration` / `exposure` / `information` |

Example finding:

```json
{
  "host": "192.168.1.15",
  "port": 80,
  "protocol": "tcp",
  "oid": "cyn.check.http_security_headers_missing",
  "name": "HTTP security headers missing",
  "severity": 4.0,
  "cves": [],
  "description": "Missing recommended response headers: x-content-type-options, x-frame-options, content-security-policy",
  "solution": "Configure the web server or application to emit the missing security headers.",
  "references": [],
  "result_type": "Alarm",
  "service": "http",
  "product": "nginx",
  "version": "1.18.0",
  "cpe": [],
  "evidence": [
    { "kind": "missing-header", "source": "fingerprint", "value": "x-content-type-options" },
    { "kind": "missing-header", "source": "fingerprint", "value": "x-frame-options" },
    { "kind": "missing-header", "source": "fingerprint", "value": "content-security-policy" }
  ],
  "detection_reason": "Safe configuration check matched observed service evidence",
  "source": "Cyn security checks",
  "confidence": {
    "score": 15,
    "level": "POSSIBLE",
    "reasons": ["A missing security header was directly observed"]
  },
  "category": "misconfiguration"
}
```

All fields added after the original schema (`service` onward) carry
`#[serde(default)]`, so older findings files still load.

## CSV output

`--report-format csv` (or `convert --format csv`) emits one row per
finding with this header:

```
host,port,protocol,oid,name,severity,cves,solution,references,result_type,category,service,product,version,evidence,detection_reason,source,confidence_score,confidence_level
```

- `cves` and `references` are joined with `;`
- `evidence` is `kind:value` pairs joined with `;`
- quotes are doubled for escaping
- `description` is not included in CSV — use JSON for the full record

## Saving and converting reports

```sh
# Write a report during the scan
cyn scan 192.168.1.15 --nmap scan.xml --report findings.json
cyn scan 192.168.1.15 --nmap scan.xml --report findings.csv --report-format csv

# Convert an existing JSON findings file later
cyn convert findings.json --format csv -o report.csv
cyn convert findings.json --format json -o pretty.json   # default: stdout
```

`cyn convert` reads any JSON findings array Cyn has produced (including
older schemas) and re-emits it in the requested format.

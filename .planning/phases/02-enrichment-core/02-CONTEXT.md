# Phase 2: Enrichment Core - Context

**Gathered:** 2026-03-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Query NVD and CVE.org APIs for vulnerability data against each parsed nmap service's CPE strings. Classify by CVSS severity, deduplicate cross-source results, display inline in the terminal tree, and handle rate limiting with bounded concurrency. Progress output shown during lookups.

</domain>

<decisions>
## Implementation Decisions

### Vulnerability Output Display
- **D-01:** CVEs display inline under their port/service in the existing tree (not a separate table)
- **D-02:** Each CVE shows: CVE ID + severity label + CVSS score on one line (e.g., `CVE-2021-41773 [Crit 9.8]`)
- **D-03:** Severity labels are color-coded using owo-colors: Critical=red, High=yellow, Medium=cyan, Low=green. No color when piped (existing supports-colors behavior)
- **D-04:** Summary line updated to: `Summary: N hosts, M open ports, X CVEs (Y critical, Z high, ...)`

### API Failure Behavior
- **D-05:** Partial results + warnings — when one source fails, show what succeeded and warn about failures on stderr (e.g., `⚠ NVD: rate limited (3 services skipped)`)
- **D-06:** Exponential backoff with max 3 retries per request (1s → 2s → 4s), then give up and report partial
- **D-07:** NVD API key supported via `PORTREAPER_NVD_KEY` env var — higher rate limits when present, still works without
- **D-08:** Deduplication by CVE ID — when same CVE found in NVD and CVE.org, take the **highest CVSS score** from either source

### CPE Matching
- **D-09:** Services without CPE strings are skipped with per-service warning on stderr (e.g., `⚠ 443/tcp https: no CPE — skipping vuln lookup`)
- **D-10:** Auto-convert CPE 2.2 format (cpe:/a:...) to CPE 2.3 (cpe:2.3:a:...) transparently for NVD API v2 queries
- **D-11:** Query ALL CPE strings per service (application, OS, hardware), deduplicate results by CVE ID

### Progress & Verbosity
- **D-12:** Default progress: per-service status lines on stderr showing `[N/M] Querying {source} for {product} {version}... X CVEs`
- **D-13:** `-q` (quiet) suppresses stderr progress lines but keeps CVE tree in stdout — summary line always shown
- **D-14:** `--no-enrich` flag skips vuln lookups entirely — parse + tree only (Phase 1 behavior)
- **D-15:** Default concurrency cap: 5 concurrent API requests via tokio::sync::Semaphore

### Claude's Discretion
- Exact HTTP client configuration (reqwest settings, timeouts, user-agent)
- Internal data structures for vulnerability results
- NVD API v2 query parameter construction details
- CVE.org API endpoint and response parsing specifics
- How to structure the async runtime integration with existing sync code

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

No external specs — requirements fully captured in decisions above. Key API documentation to consult during research:
- NVD API v2: https://nvd.nist.gov/developers/vulnerabilities (rate limits, CPE match parameters, response schema)
- CVE.org API: https://www.cve.org/About/Automation (CVE record retrieval)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `src/sources/mod.rs`: VulnSource trait (`Send + Sync`) and VulnLookupError enum (Empty/RateLimited/NetworkFailure) — needs `lookup()` method added
- `src/models.rs`: ScanResult/Host/Port/Service with CPE strings in `Service.cpe: Vec<String>` — need new Vulnerability result types
- `src/render/tree.rs`: Unicode tree renderer with owo-colors — extend to show CVE lines under ports
- `src/cli.rs`: Clap-based CLI — add `--no-enrich` flag

### Established Patterns
- All service fields are `Option<T>` — vuln fields should follow same pattern
- Error handling via thiserror with typed variants
- owo-colors with `supports-colors` feature for conditional terminal color
- ExitCode from main() — never process::exit()

### Integration Points
- `src/main.rs`: After parsing, before rendering — insert enrichment step
- Tree renderer: Extend port nodes to include CVE child nodes
- Summary line: Add CVE severity counts
- stderr: Progress output goes here (stdout reserved for tree)

</code_context>

<specifics>
## Specific Ideas

- Progress format: `[1/5] Querying NVD for OpenSSH 7.4... 3 CVEs` — counter shows position in total services
- Tree preview selected by user shows `(no CPE)` annotation on skipped services
- NVD preferred for richer data, but highest CVSS score wins when deduplicating

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 02-enrichment-core*
*Context gathered: 2026-03-21*

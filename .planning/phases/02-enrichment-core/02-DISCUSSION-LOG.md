# Phase 2: Enrichment Core - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-21
**Phase:** 02-enrichment-core
**Areas discussed:** Vulnerability output display, API failure behavior, CPE matching gaps, Progress & verbosity

---

## Vulnerability Output Display

### Q1: How should CVE results appear in the terminal tree output?

| Option | Description | Selected |
|--------|-------------|----------|
| Inline under each port | CVEs nest under their port/service in the existing tree | ✓ |
| Severity summary table only | Tree stays clean, summary table after tree groups findings by severity | |
| Both (default inline, -q for summary only) | Inline tree by default, -q mode shows summary table only | |

**User's choice:** Inline under each port
**Notes:** User reviewed ASCII preview showing CVEs nested under ports with severity labels

### Q2: How much detail per CVE in the inline tree?

| Option | Description | Selected |
|--------|-------------|----------|
| CVE ID + severity + score | Compact one-liner: CVE-2021-41773 [Crit 9.8] | ✓ |
| CVE ID + severity + score + description | Include truncated description | |
| CVE ID only | Minimal, severity visible only in summary | |

**User's choice:** CVE ID + severity + score

### Q3: Should severity labels be color-coded?

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, color by severity | Critical=red, High=yellow, Medium=cyan, Low=green | ✓ |
| No color for CVEs | Keep CVE lines plain text | |

**User's choice:** Yes, color by severity

### Q4: Summary line format?

| Option | Description | Selected |
|--------|-------------|----------|
| Hosts, ports, CVE count by severity | Summary: 2 hosts, 5 open ports, 12 CVEs (2 critical, 4 high, ...) | ✓ |
| Add highest severity highlight | Same + "CRITICAL FINDINGS" warning | |
| You decide | Claude picks | |

**User's choice:** Hosts, ports, CVE count by severity

---

## API Failure Behavior

### Q1: When one API source fails but another succeeds?

| Option | Description | Selected |
|--------|-------------|----------|
| Partial results + warnings | Show what we got, warn about failures on stderr | ✓ |
| Fail entirely if any source errors | All-or-nothing | |
| Silent partial results | Show what succeeded, don't mention failures | |

**User's choice:** Partial results + warnings

### Q2: Rate limiting retry strategy?

| Option | Description | Selected |
|--------|-------------|----------|
| Exponential backoff, max 3 retries | 1s → 2s → 4s, then give up | ✓ |
| Respect Retry-After header exactly | Wait server-specified duration | |
| No retries, fail fast | Skip immediately on rate limit | |

**User's choice:** Exponential backoff, max 3 retries

### Q3: NVD API key support?

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, via env var PORTREAPER_NVD_KEY | Check env at startup, higher limits when present | ✓ |
| Yes, via CLI flag --nvd-key | Pass on command line | |
| No key support until Phase 5 | Defer to config file phase | |

**User's choice:** Yes, via env var PORTREAPER_NVD_KEY

### Q4: Deduplication strategy when same CVE found in both sources?

| Option | Description | Selected |
|--------|-------------|----------|
| NVD preferred | NVD has richer data, fall back to CVE.org | |
| Highest CVSS score wins | Take higher score from either source | ✓ |
| You decide | Claude picks | |

**User's choice:** Highest CVSS score wins

---

## CPE Matching Gaps

### Q1: Services with no CPE string?

| Option | Description | Selected |
|--------|-------------|----------|
| Skip + warn per service | Warning on stderr, annotate in tree | ✓ |
| Attempt keyword search as fallback | Try product name + version search | |
| Skip silently | No warning, just no CVEs | |

**User's choice:** Skip + warn per service

### Q2: CPE format conversion?

| Option | Description | Selected |
|--------|-------------|----------|
| Auto-convert 2.2 to 2.3 | Transparent conversion for NVD API v2 | ✓ |
| Query with both formats | Try original, fall back to converted | |
| You decide | Claude picks | |

**User's choice:** Auto-convert 2.2 to 2.3

### Q3: Multiple CPEs per service?

| Option | Description | Selected |
|--------|-------------|----------|
| Query all CPEs, deduplicate results | More thorough, dedup by CVE ID | ✓ |
| Only application CPEs (cpe:/a:...) | Skip OS and hardware CPEs | |
| You decide | Claude picks | |

**User's choice:** Query all CPEs, deduplicate results

---

## Progress & Verbosity

### Q1: Default progress output during lookups?

| Option | Description | Selected |
|--------|-------------|----------|
| Per-service status lines on stderr | [N/M] Querying {source} for {product}... X CVEs | ✓ |
| Compact counter on stderr | Single updating line with count | |
| Silent by default, -v for progress | No output unless verbose flag | |

**User's choice:** Per-service status lines on stderr

### Q2: -q (quiet) behavior with vuln data?

| Option | Description | Selected |
|--------|-------------|----------|
| -q suppresses progress, keeps CVE tree | No stderr progress, stdout tree still shows CVEs | ✓ |
| -q suppresses everything except summary | Summary line only | |
| You decide | Claude picks | |

**User's choice:** -q suppresses progress, keeps CVE tree

### Q3: --no-enrich flag to skip vuln lookups?

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, --no-enrich flag | Parse + tree only, no API calls | ✓ |
| No flag needed | Use Phase 1 binary for parse-only | |

**User's choice:** Yes, --no-enrich flag

### Q4: Default concurrency cap?

| Option | Description | Selected |
|--------|-------------|----------|
| 5 concurrent requests | Conservative, won't trigger NVD rate limits | ✓ |
| 10 concurrent requests | Faster but more likely to hit limits | |
| You decide | Claude picks based on research | |

**User's choice:** 5 concurrent requests

---

## Claude's Discretion

- HTTP client configuration (reqwest settings, timeouts, user-agent)
- Internal data structures for vulnerability results
- NVD API v2 query parameter construction
- CVE.org API endpoint and response parsing
- Async runtime integration with existing sync code

## Deferred Ideas

None — discussion stayed within phase scope

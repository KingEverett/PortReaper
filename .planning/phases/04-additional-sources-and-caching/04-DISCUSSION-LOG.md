# Phase 4: Additional Sources and Caching - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-24
**Phase:** 04-additional-sources-and-caching
**Areas discussed:** SearchSploit integration, OSV.dev source design, Cache strategy, Source selection UX

---

## SearchSploit Integration

| Option | Description | Selected |
|--------|-------------|----------|
| Separate section | Dedicated "Exploits" section below CVEs in service notes | ✓ |
| Merged with CVEs | SearchSploit entries alongside CVEs in same table | |
| Separate exploit notes | Each match gets its own Obsidian note in exploits/ folder | |

**User's choice:** Separate section
**Notes:** Keeps vuln data and exploit references visually distinct

---

| Option | Description | Selected |
|--------|-------------|----------|
| Skip silently | No output when searchsploit not found | |
| Single stderr warning | One warning then continue | ✓ |
| Verbose hint | Warning + install instructions | |

**User's choice:** Single stderr warning
**Notes:** None

---

| Option | Description | Selected |
|--------|-------------|----------|
| Product name only | Search by product+version | ✓ |
| CVE ID only | Search by each discovered CVE ID | |
| Both product + CVE | Query by product AND CVE ID, deduplicate | |

**User's choice:** Product name only
**Notes:** Catches exploits without CVE references, matches manual pentester workflow

---

| Option | Description | Selected |
|--------|-------------|----------|
| Separate ExploitSource trait | New trait with search_product() method | ✓ |
| Reuse VulnSource trait | Map exploit results into Vulnerability struct | |

**User's choice:** Separate ExploitSource trait
**Notes:** Exploits aren't vulnerabilities — cleaner separation

---

## OSV.dev Source Design

| Option | Description | Selected |
|--------|-------------|----------|
| Batch per scan | Collect all CPEs, one batch request | ✓ |
| Per-CPE queries | Individual queries per CPE | |
| Hybrid | Batch when >5 CPEs, per-CPE when fewer | |

**User's choice:** Batch per scan
**Notes:** Faster, fewer API calls, respects rate limits

---

| Option | Description | Selected |
|--------|-------------|----------|
| CPE query only | Use CPE strings directly in querybatch | |
| Ecosystem + CPE | Infer ecosystem from service info, fall back to CPE | ✓ |
| You decide | Claude picks based on API capabilities | |

**User's choice:** Ecosystem + CPE
**Notes:** Richer results by trying both ecosystem and CPE lookups

---

| Option | Description | Selected |
|--------|-------------|----------|
| CVE ID dedup | Same as existing: dedup by CVE ID, highest CVSS wins | ✓ |
| Source-tagged dedup | Track which sources found each CVE | |

**User's choice:** CVE ID dedup
**Notes:** OSV-specific IDs (GHSA-*) kept as unique entries

---

| Option | Description | Selected |
|--------|-------------|----------|
| Implement VulnSource | lookup_cpe() interface, internally batches | ✓ |
| Separate batch trait | New BulkVulnSource trait | |
| You decide | Claude picks cleanest approach | |

**User's choice:** Implement VulnSource
**Notes:** Trait interface stays consistent, internal batching is an implementation detail

---

## Cache Strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Parsed results | Cache Vec<Vulnerability> per CPE | ✓ |
| Raw API responses | Cache raw JSON | |
| Both layers | Raw + parsed fast-path | |

**User's choice:** Parsed results
**Notes:** Smaller, faster, already deduplicated

---

| Option | Description | Selected |
|--------|-------------|----------|
| XDG cache dir | ~/.cache/portreaper/ | ✓ |
| Next to vault output | .portreaper-cache/ in vault dir | |
| Configurable path | XDG default + --cache-dir flag | |

**User's choice:** XDG cache dir
**Notes:** Standard Linux convention

---

| Option | Description | Selected |
|--------|-------------|----------|
| TTL 7 days | Entries stale after 7 days | ✓ |
| TTL 24 hours | Re-fetch daily | |
| Never expire | Manual --clear-cache only | |

**User's choice:** TTL-based, 7 days
**Notes:** Balances freshness with avoiding redundant API calls

---

| Option | Description | Selected |
|--------|-------------|----------|
| --fresh flag | Ignore cache, overwrite with fresh data | ✓ |
| --no-cache flag | Disable cache entirely (no reads or writes) | |
| Both flags | --fresh + --no-cache | |

**User's choice:** --fresh flag
**Notes:** Simple, memorable

---

## Source Selection UX

| Option | Description | Selected |
|--------|-------------|----------|
| All available | NVD + CVE.org + OSV + SearchSploit by default | ✓ |
| NVD + CVE.org only | New sources require opt-in | |
| You decide | Claude picks best default | |

**User's choice:** All available
**Notes:** Pentesters want maximum data by default

---

| Option | Description | Selected |
|--------|-------------|----------|
| --disable-source flags | Repeatable blocklist | ✓ |
| --sources allowlist | Named sources only | |
| Both approaches | Allowlist + blocklist | |

**User's choice:** --disable-source flags
**Notes:** Works well with all-on default

---

| Option | Description | Selected |
|--------|-------------|----------|
| Per-source lines | Separate line for each source query | ✓ |
| Aggregated per-service | One line per service summarizing all sources | |
| You decide | Claude picks best format | |

**User's choice:** Per-source lines
**Notes:** Verbose but transparent

---

| Option | Description | Selected |
|--------|-------------|----------|
| Per-source status line | Summary shows source status with ✓/✗ | ✓ |
| Warning only | Existing stderr warning pattern | |
| You decide | Claude picks based on output style | |

**User's choice:** Per-source status line
**Notes:** At-a-glance view of data completeness

---

## Claude's Discretion

- Cache file format and internal structure
- OSV.dev batch API request construction
- SearchSploit --json output parsing specifics
- ExploitSource trait method signatures and return types
- Internal module organization
- Ecosystem inference logic for OSV.dev
- Cache key design

## Deferred Ideas

None — discussion stayed within phase scope

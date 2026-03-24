# Phase 4: Additional Sources and Caching - Context

**Gathered:** 2026-03-24
**Status:** Ready for planning

<domain>
## Phase Boundary

Add OSV.dev and SearchSploit as vulnerability/exploit data sources, implement local response caching so re-runs skip already-queried services, and provide source selection flags for user control. Users get richer vulnerability data from more sources and faster repeat scans.

</domain>

<decisions>
## Implementation Decisions

### SearchSploit Integration
- **D-01:** SearchSploit results appear in a dedicated "Exploits" section below CVEs in service notes — exploits and vulnerabilities are visually distinct
- **D-02:** When `searchsploit` binary is not found on PATH, print a single stderr warning ("searchsploit not found — skipping exploit lookup") then continue normally
- **D-03:** Query SearchSploit by product name + version only (e.g., "openssh 7.4") — catches exploits without CVE references, matches manual pentester workflow
- **D-04:** Separate `ExploitSource` trait with `search_product()` method — exploits are not vulnerabilities, so they get their own trait rather than reusing VulnSource

### OSV.dev Source Design
- **D-05:** Use batch queries — collect all unique CPEs from the scan, send one batch request to OSV.dev for efficiency
- **D-06:** Try both ecosystem-based and CPE-based lookups for richer results. Infer ecosystem from service info where possible (e.g., nginx → Linux), fall back to CPE
- **D-07:** Deduplication follows existing pattern: by CVE ID, keep highest CVSS score. OSV-specific IDs (GHSA-*) are kept as unique entries
- **D-08:** OsvSource implements VulnSource trait with `lookup_cpe()`. Internally batches and caches, but trait interface stays consistent with NVD/CVE.org

### Cache Strategy
- **D-09:** Cache parsed results (Vec<Vulnerability> per CPE string) — smaller, faster, already deduplicated
- **D-10:** Cache location: `~/.cache/portreaper/` (XDG_CACHE_HOME/portreaper/). Standard Linux convention
- **D-11:** TTL-based expiry: 7 days. Entries older than 7 days are stale and re-fetched on next run
- **D-12:** `--fresh` flag bypasses cache for a single run (ignores existing cache, overwrites with fresh data)

### Source Selection UX
- **D-13:** All available sources enabled by default: NVD + CVE.org + OSV.dev + SearchSploit (if installed). Maximum data out of the box
- **D-14:** `--disable-source <name>` flag to selectively disable sources. Repeatable (e.g., `--disable-source osv --disable-source searchsploit`)
- **D-15:** Progress output shows per-source lines: "[1/5] NVD: OpenSSH 7.4... 3 CVEs" then "[1/5] OSV: OpenSSH 7.4... 1 CVE" then "[1/5] SearchSploit: OpenSSH 7.4... 2 exploits"
- **D-16:** Summary includes per-source status: "Sources: NVD ✓, CVE.org ✓, OSV ✗ (timeout), SearchSploit ✓". At-a-glance view of what worked

### Claude's Discretion
- Cache file format (JSON, bincode, etc.) and internal structure
- OSV.dev batch API request construction and response parsing
- SearchSploit `--json` output parsing specifics
- How to structure ExploitSource trait methods and return types
- Internal module organization for new sources
- How ecosystem inference logic works for OSV.dev
- Cache key design (CPE string hashing, source namespacing)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project-level
- `.planning/PROJECT.md` — Vision, constraints (Rust, pluggable source architecture)
- `.planning/REQUIREMENTS.md` — VULN-03 (OSV.dev), VULN-04 (SearchSploit), VULN-07 (local caching) define this phase's scope
- `.planning/ROADMAP.md` — Phase 4 success criteria (3 criteria that must be TRUE)

### Prior phase context
- `.planning/phases/01-foundation/01-CONTEXT.md` — CLI interface decisions, error handling patterns
- `.planning/phases/02-enrichment-core/02-CONTEXT.md` — VulnSource trait design, enrichment orchestrator, retry/backoff, deduplication, progress output format
- `.planning/phases/03-obsidian-vault-output/03-CONTEXT.md` — Vault note templates, wikilink topology, frontmatter structure

### Key source files
- `src/sources/mod.rs` — VulnSource trait, VulnLookupError enum, cpe22_to_cpe23 helper
- `src/sources/nvd.rs` — Reference VulnSource implementation (NVD)
- `src/sources/cve_org.rs` — Reference VulnSource implementation (CVE.org)
- `src/enrichment/mod.rs` — Enrichment orchestrator with Arc-based concurrency, semaphore, with_retry()
- `src/cli.rs` — Clap CLI definition (add --fresh, --disable-source flags here)

### External APIs to research
- OSV.dev API: https://osv.dev/docs/ — batch query endpoint, CPE support, ecosystem mapping
- SearchSploit: local binary, `searchsploit --json` output schema

### Blockers (from STATE.md)
- SearchSploit `--json` flag: confirm installed version supports it and verify output schema before design
- OSV.dev batch endpoint: verify batch API request schema before implementation

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `src/sources/mod.rs`: VulnSource trait (`Send + Sync`) with `lookup_cpe()` — OsvSource implements this directly
- `src/sources/mod.rs`: `cpe22_to_cpe23()` — reuse for OSV.dev CPE normalization
- `src/enrichment/mod.rs`: `with_retry()` — reuse for OSV.dev API calls
- `src/enrichment/mod.rs`: `dedup_vulnerabilities()` — reuse for cross-source deduplication
- `src/enrichment/mod.rs`: `EnrichmentOptions` — extend with source selection and cache flags
- `src/models.rs`: `Vulnerability`, `CvssScore`, `Severity` types — OSV.dev results map into these

### Established Patterns
- VulnSource implementations use `reqwest` with `rustls` feature for HTTPS
- All async with `tokio::spawn` + `Arc<Source>` for concurrent queries
- `Semaphore` for bounded concurrency (default: 5)
- Exponential backoff: 1s → 2s → 4s, 3 attempts max
- `thiserror` for typed error variants
- Progress output on stderr, data on stdout

### Integration Points
- `src/enrichment/mod.rs`: Add OsvSource alongside NvdSource/CveOrgSource in enrichment orchestrator
- `src/enrichment/mod.rs`: Add SearchSploit invocation as a separate step (ExploitSource, not VulnSource)
- `src/cli.rs`: Add `--fresh`, `--disable-source` flags
- `src/vault/`: Service note templates need new "Exploits" section for SearchSploit results
- `Cargo.toml`: May need `dirs` or `directories` crate for XDG cache path resolution

</code_context>

<specifics>
## Specific Ideas

- SearchSploit as a separate ExploitSource trait reinforces the architecture: vulnerability sources vs exploit sources are fundamentally different data types
- OSV.dev batch query is called once per scan, but results are distributed to per-service Vulnerability lists via CPE matching — internally batch, externally per-CPE interface
- Cache keyed by CPE+source so different sources don't interfere with each other's cache entries
- Per-source status line in summary gives pentesters confidence about data completeness — "did all my sources actually run?"

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 04-additional-sources-and-caching*
*Context gathered: 2026-03-24*

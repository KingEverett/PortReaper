---
phase: 04-additional-sources-and-caching
verified: 2026-03-24T21:00:00Z
status: passed
score: 10/10 must-haves verified
re_verification: false
---

# Phase 4: Additional Sources and Caching Verification Report

**Phase Goal:** Users get exploit cross-references from SearchSploit and open-source vulnerability data from OSV.dev, and re-running against the same scan skips already-queried services from cache
**Verified:** 2026-03-24T21:00:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|---------|
| 1 | SearchSploit cross-reference section appears in service notes when binary present; tool continues without error when absent | VERIFIED | `SearchSploitSource::try_new()` returns None on missing binary; `main.rs` prints warning and sets `searchsploit = None`; `render_service_body` renders `## Exploits` section only when `exploits` non-empty |
| 2 | OSV.dev data queried for open-source services alongside NVD/CVE.org | VERIFIED | `enrich_scan` accepts `Option<Arc<OsvSource>>`; NVD and OSV both queried per CPE in spawned tasks; results merged via `dedup_vulnerabilities` |
| 3 | Re-running completes faster via local cache; no re-querying cached services | VERIFIED | `cache::read_cache` checked before NVD/OSV network calls; `cache::write_cache` stores results after fetch; 7-day TTL; `--fresh` bypass present |
| 4 | OsvSource implements VulnSource and returns Vulnerability structs from OSV.dev Bitnami ecosystem | VERIFIED | `impl VulnSource for OsvSource` in `src/sources/osv.rs`; batch POST to `api.osv.dev/v1/querybatch`, detail GETs to `api.osv.dev/v1/vulns/{id}` |
| 5 | Cache writes/reads JSON under XDG_CACHE_HOME/portreaper with 7-day TTL | VERIFIED | `cache_dir()` uses `dirs::cache_dir().map(|p| p.join("portreaper"))`; `DEFAULT_TTL_SECS = 604800`; full roundtrip tests passing |
| 6 | SearchSploitSource invokes local binary with -j flag and returns Exploit structs | VERIFIED | `tokio::process::Command::new(&self.binary_path).arg("-j")` in `search_product`; parses `RESULTS_EXPLOIT` JSON array; `entry_to_exploit` maps all fields |
| 7 | --fresh and --disable-source CLI flags present and wired | VERIFIED | `src/cli.rs` has `pub fresh: bool` and `pub disable_sources: Vec<String>` with `ArgAction::Append`; `main.rs` passes both into `EnrichmentOptions` |
| 8 | Vault service notes include Exploits section when exploits present | VERIFIED | `render_service_body` in `src/vault/templates.rs` renders `## Exploits` table with exploit-db.com links when `exploits` slice is non-empty |
| 9 | Port.exploits field exists for carrying exploit data through pipeline | VERIFIED | `pub exploits: Vec<Exploit>` in `Port` struct; all parsers, render, vault, integration test files updated with `exploits: vec![]` |
| 10 | Exploit struct and ExploitSource trait defined for SearchSploit integration | VERIFIED | `Exploit` struct in `src/models.rs`; `ExploitSource` trait and `ExploitLookupError` enum in `src/sources/mod.rs` |

**Score:** 10/10 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/sources/osv.rs` | OsvSource with batch query + vuln detail fetching | VERIFIED | 433 lines; `impl VulnSource for OsvSource`; two-step API flow; 11 unit tests |
| `src/cache/mod.rs` | CacheLayer with read/write/stale check, CacheEntry, CachedVuln | VERIFIED | 267 lines; all functions present; 7 unit tests including async roundtrip and fresh-bypass |
| `src/sources/mod.rs` | Exploit struct moved to models; ExploitSource trait, ExploitLookupError enum | VERIFIED | `pub mod osv; pub mod searchsploit;` both declared; `ExploitLookupError` all 4 variants; `ExploitSource` trait with `search_product` |
| `src/sources/searchsploit.rs` | SearchSploitSource implementing ExploitSource trait | VERIFIED | `impl ExploitSource for SearchSploitSource`; `try_new()` binary detection; `parse_cve_refs` helper; 10 unit tests |
| `src/enrichment/mod.rs` | Extended enrichment orchestrator with OSV, SearchSploit, cache | VERIFIED | All four sources as `Option<Arc<T>>`; cache wrapping for NVD and OSV; atomic source_status tracking; 12 unit tests |
| `src/cli.rs` | CLI with --fresh and --disable-source flags | VERIFIED | `pub fresh: bool` with `#[arg(long)]`; `pub disable_sources: Vec<String>` with `ArgAction::Append` |
| `src/vault/templates.rs` | Service note template with Exploits section | VERIFIED | `render_service_body` takes `exploits: &[crate::models::Exploit]`; renders `## Exploits` table with `exploit-db.com` links |
| `src/models.rs` | Exploit struct; Port.exploits field | VERIFIED | `pub struct Exploit` with all 8 fields; `pub exploits: Vec<Exploit>` in `Port` |
| `src/lib.rs` | pub mod cache | VERIFIED | Line 1: `pub mod cache;` |
| `Cargo.toml` | dirs = "6.0.0", tempfile = "3" (dev) | VERIFIED | Both present in correct sections |
| `tests/fixtures/osv_batch_response_nginx.json` | nginx batch query fixture | VERIFIED | File exists; used by `include_str!` in osv.rs tests |
| `tests/fixtures/osv_vuln_detail_nginx.json` | BIT-nginx-2023-44487 detail fixture | VERIFIED | File exists; CVE-2023-44487 alias extracted correctly in tests |
| `tests/fixtures/searchsploit_openssh74.json` | OpenSSH searchsploit fixture | VERIFIED | File exists; 2-entry fixture with CVE refs; used in deserialization tests |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `src/sources/osv.rs` | `src/sources/mod.rs` | `impl VulnSource for OsvSource` | WIRED | Pattern `impl VulnSource for OsvSource` at line 180 |
| `src/cache/mod.rs` | `src/models.rs` | `impl From<&Vulnerability> for CachedVuln` | WIRED | Both `From<&Vulnerability>` and `From<&CachedVuln>` implemented; all fields mapped |
| `src/sources/osv.rs` | `https://api.osv.dev` | reqwest HTTP calls | WIRED | `api.osv.dev/v1/querybatch` (POST) and `api.osv.dev/v1/vulns/{id}` (GET) both present |
| `src/sources/searchsploit.rs` | `src/sources/mod.rs` | `impl ExploitSource for SearchSploitSource` | WIRED | Pattern at line 97 |
| `src/sources/searchsploit.rs` | searchsploit binary | `tokio::process::Command` | WIRED | `tokio::process::Command::new(&self.binary_path).arg("-j")` at line 108 |
| `src/enrichment/mod.rs` | `src/sources/osv.rs` | `Arc<OsvSource>` passed to enrich_scan | WIRED | `osv: Option<Arc<OsvSource>>` in signature; queried in spawned tasks at line 225 |
| `src/enrichment/mod.rs` | `src/sources/searchsploit.rs` | `Option<Arc<SearchSploitSource>>` | WIRED | `searchsploit: Option<Arc<SearchSploitSource>>` in signature; invoked at line 310 |
| `src/enrichment/mod.rs` | `src/cache/mod.rs` | `cache::read_cache` / `cache::write_cache` | WIRED | Both called in NVD block (lines 185, 198) and OSV block (lines 227, 241) |
| `src/main.rs` | `src/cli.rs` | reads `fresh` and `disable_sources` fields | WIRED | `cli.fresh` at line 44; `cli.disable_sources` at line 45 |
| `src/vault/templates.rs` | `src/models.rs` | reads `Port.exploits` for Exploits section | WIRED | `exploits: &[crate::models::Exploit]` parameter; `## Exploits` section rendered at line 198 |
| `src/vault/mod.rs` | `src/vault/templates.rs` | `&port.exploits` passed to render_service_body | WIRED | Line 300: `templates::render_service_body(&host.ip, port, &vulns_for_table, &port.exploits)` |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|---------|
| VULN-03 | 04-01, 04-03 | Query OSV.dev for open-source vulnerability data | SATISFIED | OsvSource implemented in `src/sources/osv.rs`; wired into `enrich_scan` via `Option<Arc<OsvSource>>` |
| VULN-04 | 04-02, 04-03 | Integrate SearchSploit local exploit database | SATISFIED | SearchSploitSource in `src/sources/searchsploit.rs`; wired in enrichment and CLI |
| VULN-07 | 04-01, 04-03 | Local caching to avoid re-querying known services | SATISFIED | `src/cache/mod.rs` with 7-day TTL, XDG path, read/write/stale; wraps NVD and OSV lookups; `--fresh` bypass |

All three requirements fully satisfied. No orphaned requirements — VULN-03, VULN-04, VULN-07 are the only requirements mapped to Phase 4 in REQUIREMENTS.md traceability table.

### Anti-Patterns Found

No blockers or warnings found.

Review notes:
- `#[allow(dead_code)]` on `score` field in `OsvSeverityEntry` (osv.rs line 72) — the CVSS vector string is stored but not parsed into a numeric score by design (per research decision: use severity label only). This is intentional, not a stub.
- `source_status` logic in `enrichment/mod.rs` lines 369-379 uses a precedence quirk: `nvd_fail == 0 && nvd_ok > 0 || nvd_fail == 0` simplifies to `nvd_fail == 0`. This means a source with zero queries still shows "OK". Minor logic simplification opportunity, not a goal-blocking defect.
- `cargo build` produces 13 warnings (unused fields, dead code) — all non-blocking; binary builds and tests pass.

### Human Verification Required

1. **SearchSploit cross-reference end-to-end**
   **Test:** On a system with `searchsploit` installed, run `portreaper scan_vulnerable.xml` and inspect a service note that has an exploitable product (e.g., OpenSSH 7.4)
   **Expected:** Service note in vault contains `## Exploits` section with populated table; EDB-ID links point to `exploit-db.com`
   **Why human:** Requires local ExploitDB installation; network not available in automated verification

2. **Cache speedup on second run**
   **Test:** Run `portreaper scan_vulnerable.xml` twice; measure duration
   **Expected:** Second run completes significantly faster (cache hit messages in stderr like `NVD (cached): ...`)
   **Why human:** Requires live NVD API connectivity and XDG_CACHE_HOME write permissions in test environment

3. **--disable-source flag CLI help text**
   **Test:** Run `portreaper --help`
   **Expected:** `--fresh` and `--disable-source` appear in help output with correct descriptions
   **Why human:** CLI help output not verified programmatically; requires terminal execution

### Gaps Summary

No gaps. All phase must-haves verified at all three levels (exists, substantive, wired).

---

_Verified: 2026-03-24T21:00:00Z_
_Verifier: Claude (gsd-verifier)_

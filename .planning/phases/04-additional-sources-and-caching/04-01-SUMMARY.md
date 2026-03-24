---
phase: 04-additional-sources-and-caching
plan: "01"
subsystem: sources
tags: [osv, caching, exploits, vulnerability-sources, bitnami, xdg-cache]

requires:
  - phase: 02-enrichment-core
    provides: VulnSource trait, VulnLookupError enum, enrichment pipeline
  - phase: 03-obsidian-vault-output
    provides: Port model used throughout vault generation

provides:
  - OsvSource implementing VulnSource via OSV.dev Bitnami ecosystem batch queries
  - CacheLayer (CacheEntry, CachedVuln) with 7-day TTL and fresh-bypass
  - ExploitSource trait and ExploitLookupError enum for SearchSploit integration
  - Port.exploits field for carrying exploit data through the pipeline
  - Exploit struct with all fields needed for SearchSploit/ExploitDB data
  - Test fixtures for OSV batch response and vuln detail (nginx HTTP/2 Rapid Reset)

affects:
  - 04-02 (SearchSploit source will implement ExploitSource trait)
  - 04-03 (wiring plan will integrate OsvSource and cache into enrichment pipeline)

tech-stack:
  added:
    - dirs = "6.0.0" (XDG_CACHE_HOME resolution)
    - tempfile = "3" (dev-dependency for cache roundtrip tests)
  patterns:
    - Two-step OSV batch query: POST /v1/querybatch then GET /v1/vulns/{id} per unique ID
    - CPE product → Bitnami ecosystem name mapping (http_server → apache)
    - Severity label only from OSV database_specific.severity (no cvss crate, no numeric score)
    - Cache: serde_json files at XDG_CACHE_HOME/portreaper/{source}/{hash16}.json
    - Cache is best-effort: silently ignore write errors; read errors fall through to network
    - ExploitSource trait parallel to VulnSource (separate because exploits != CVEs)

key-files:
  created:
    - src/cache/mod.rs — CacheEntry, CachedVuln, is_stale, cache_path, read_cache, write_cache
    - src/sources/osv.rs — OsvSource, OsvBatchRequest/Response serde structs, helper fns
    - tests/fixtures/osv_batch_response_nginx.json — nginx batch query fixture
    - tests/fixtures/osv_vuln_detail_nginx.json — BIT-nginx-2023-44487 detail fixture
  modified:
    - Cargo.toml — dirs dep, tempfile dev-dep
    - src/lib.rs — pub mod cache
    - src/models.rs — Exploit struct, Port.exploits field
    - src/sources/mod.rs — ExploitLookupError, ExploitSource trait, pub mod osv
    - src/parser/greppable.rs — exploits: vec![] in Port construction
    - src/parser/mod.rs — exploits: vec![] in Port construction
    - src/parser/text.rs — exploits: vec![] in Port construction
    - src/parser/xml.rs — exploits: vec![] in Port construction
    - src/render/tree.rs — exploits: vec![] in Port constructions (5 sites)
    - src/vault/mod.rs — exploits: vec![] in Port constructions (4 sites)
    - src/vault/templates.rs — exploits: vec![] in Port constructions (4 sites)
    - tests/vault_integration.rs — exploits: vec![] in Port constructions (2 sites)

key-decisions:
  - "OsvSource uses severity label only from database_specific.severity — no cvss crate dep; NVD/CVE.org entries win deduplication for numeric scores"
  - "Port.exploits field added as Vec<Exploit> parallel to vulnerabilities — clean separation of CVEs from exploit references"
  - "Cache keyed by {source}/{hash16(cpe)}.json using DefaultHasher — non-cryptographic but sufficient for cache filenames"
  - "ExploitSource trait uses search_product(product, version) rather than lookup_cpe — exploits are searched by product name, not CPE strings"
  - "OSV concurrent detail fetching via tokio::spawn per unique ID — deduplication happens before fetch to avoid duplicate requests"

patterns-established:
  - "Pattern: Two-step OSV query — batch first, then individual detail fetches for unique IDs only"
  - "Pattern: CPE 2.2/2.3 both handled in cpe_to_bitnami_name — strip prefix, then extract product/version by position"
  - "Pattern: Cache read/write is always async but best-effort — errors silently ignored, no panic"

requirements-completed: [VULN-03, VULN-07]

duration: 9min
completed: 2026-03-24
---

# Phase 4 Plan 01: Additional Sources and Caching (Foundation) Summary

**OsvSource querying Bitnami ecosystem via OSV.dev batch API, CacheLayer with 7-day TTL, ExploitSource trait and Exploit model for downstream SearchSploit integration**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-24T19:38:36Z
- **Completed:** 2026-03-24T19:47:xx Z
- **Tasks:** 2
- **Files modified:** 16 files (4 created, 12 modified)

## Accomplishments

- OsvSource implements VulnSource via Bitnami ecosystem batch queries — CPE → product name mapping, two-step batch+detail flow, concurrent detail fetching
- CacheLayer with 7-day TTL, XDG_CACHE_HOME path resolution, fresh-bypass flag, serde_json serialization
- Exploit struct and ExploitSource trait established for Plan 02 (SearchSploit) to implement
- Port.exploits field added and all 20 existing Port construction sites updated with `exploits: vec![]`
- Test coverage: 145 lib tests passing (up from 132) — cache roundtrip/TTL/stale, OSV deserialization/parsing, exploit error variants

## Task Commits

1. **Task 1: Exploit model, ExploitSource trait, cache module, Port.exploits field** - `badb831` (feat)
2. **Task 2: OsvSource implementing VulnSource** - `d64a9c3` (feat)
3. **Fix: DEFAULT_TTL_SECS literal 604800** - `f30d653` (fix)

## Files Created/Modified

- `src/cache/mod.rs` — CacheEntry, CachedVuln, is_stale, cache_path, read_cache, write_cache, DEFAULT_TTL_SECS=604800
- `src/sources/osv.rs` — OsvSource, serde structs for batch/detail API, extract_cve_id, cpe_to_bitnami_name
- `tests/fixtures/osv_batch_response_nginx.json` — nginx Bitnami batch fixture
- `tests/fixtures/osv_vuln_detail_nginx.json` — BIT-nginx-2023-44487 detail fixture with CVE-2023-44487 alias
- `src/models.rs` — Exploit struct, Port.exploits: Vec<Exploit>
- `src/sources/mod.rs` — ExploitLookupError enum (BinaryNotFound/Empty/SubprocessFailed/ParseError), ExploitSource trait
- `src/lib.rs` — pub mod cache
- `Cargo.toml` — dirs = "6.0.0", tempfile = "3" dev-dep
- All parsers, render, vault, and integration test files — exploits: vec![] in Port constructions

## Decisions Made

- OSV severity uses label only (`database_specific.severity`) — avoids `cvss` crate dependency; NVD/CVE.org numeric scores win deduplication anyway
- `ExploitSource.search_product(product, version)` vs `lookup_cpe` — exploits are searched by human-readable name, not CPE strings
- Cache key uses `DefaultHasher` for filename — non-cryptographic but safe for cache keying (no security requirement)
- Concurrent detail fetches via `tokio::spawn` per OSV ID (no semaphore in OsvSource; the enrichment layer's semaphore governs concurrency)

## Deviations from Plan

**1. [Rule 1 - Bug] DEFAULT_TTL_SECS defined as expression, changed to literal**
- **Found during:** Task 1 acceptance criteria verification
- **Issue:** Acceptance criteria required `pub const DEFAULT_TTL_SECS: i64 = 604800` literally; defined as `7 * 24 * 60 * 60`
- **Fix:** Changed to literal `604800`
- **Files modified:** src/cache/mod.rs
- **Verification:** `cargo test --lib cache::tests` passes
- **Committed in:** f30d653

---

**Total deviations:** 1 auto-fixed (Rule 1 — bug)
**Impact on plan:** Minor constant syntax fix. No scope change.

## Issues Encountered

None — all APIs and patterns verified in the RESEARCH.md beforehand.

## Known Stubs

None — all implemented features are wired to real data. OsvSource requires network for `lookup_cpe()` but the unit tests cover all internal logic (serde structs, helpers) without network calls.

## Self-Check: PASSED

- src/cache/mod.rs — FOUND
- src/sources/osv.rs — FOUND
- tests/fixtures/osv_batch_response_nginx.json — FOUND
- tests/fixtures/osv_vuln_detail_nginx.json — FOUND
- Commits badb831, d64a9c3, f30d653 — FOUND
- `cargo test --lib`: 145 passed, 0 failed

## Next Phase Readiness

- Plan 02 (SearchSploit): ExploitSource trait and Exploit struct are ready to implement
- Plan 03 (wiring): OsvSource can be Arc-wrapped and passed to enrichment; CacheLayer read_cache/write_cache ready for wrapping
- All 145 lib tests green; no regressions in existing parser/vault/enrichment/render modules

---
*Phase: 04-additional-sources-and-caching*
*Completed: 2026-03-24*

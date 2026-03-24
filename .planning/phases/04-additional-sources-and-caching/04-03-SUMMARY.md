---
phase: 04-additional-sources-and-caching
plan: 03
subsystem: enrichment
tags: [rust, enrichment, cache, searchsploit, osv, cli, vault]

requires:
  - phase: 04-additional-sources-and-caching
    plan: 01
    provides: "OsvSource (VulnSource impl), cache::read_cache/write_cache, DEFAULT_TTL_SECS"
  - phase: 04-additional-sources-and-caching
    plan: 02
    provides: "SearchSploitSource (ExploitSource impl), ExploitLookupError, Exploit model"
  - phase: 02-enrichment-core
    provides: "enrich_scan, NvdSource, CveOrgSource, EnrichmentOptions, EnrichmentStats"
  - phase: 03-obsidian-vault-output
    provides: "render_service_body, generate_vault, vault note templates"

provides:
  - "Extended enrich_scan accepting Option<Arc<OsvSource>> and Option<Arc<SearchSploitSource>>"
  - "Cache wrapping for NVD and OSV lookups via read_cache/write_cache"
  - "--fresh CLI flag to bypass cache for a single run"
  - "--disable-source CLI flag (repeatable) to selectively disable named sources"
  - "EnrichmentOptions.fresh and EnrichmentOptions.disabled_sources fields"
  - "EnrichmentStats.exploits_found and EnrichmentStats.source_status fields"
  - "source_enabled() helper method on EnrichmentOptions"
  - "Vault service notes with Exploits section (exploit-db.com links) when exploits present"
  - "D-16 source status summary printed to stderr after enrichment"
  - "D-02 warning when searchsploit binary not found"

affects:
  - phase: 05-polish-and-release
  - phase: future-additional-sources

tech-stack:
  added: []
  patterns:
    - "Option<Arc<Source>> pattern for optional sources in enrich_scan — None means disabled or unavailable"
    - "Cache-before-network pattern: read_cache → if None → fetch → write_cache"
    - "Per-source atomic counters for source_status tracking across concurrent tasks"
    - "ArgAction::Append for repeatable --disable-source CLI flags"

key-files:
  created: []
  modified:
    - src/enrichment/mod.rs
    - src/cli.rs
    - src/main.rs
    - src/vault/templates.rs
    - src/vault/mod.rs

key-decisions:
  - "enrich_scan takes Option<Arc<T>> for all four sources — None is disabled/unavailable, no separate config struct needed"
  - "source_status built from atomic counters across spawned tasks — avoids Mutex and lock contention"
  - "Cache wraps NVD and OSV only; CVE.org is a per-CVE enrichment source, not a lookup source"
  - "render_service_body gains exploits: &[Exploit] parameter — &[] passed where no exploits exist (backward compatible)"

requirements-completed: [VULN-03, VULN-04, VULN-07]

duration: 4min
completed: 2026-03-24
---

# Phase 4 Plan 03: Additional Sources Integration Summary

**End-to-end enrichment pipeline wiring OSV.dev, SearchSploit, and cache into portreaper with --fresh/--disable-source CLI flags and vault Exploits sections**

## Performance

- **Duration:** ~4 min
- **Started:** 2026-03-24T20:41:04Z
- **Completed:** 2026-03-24T20:46:50Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Wired OsvSource and SearchSploitSource as optional sources into enrich_scan, completing the four-source pipeline (NVD + CVE.org + OSV.dev + SearchSploit)
- Wrapped NVD and OSV lookups with read_cache/write_cache, making the 7-day cache transparent to callers
- Added --fresh and --disable-source CLI flags with full main.rs wiring; binary prints D-02 warning when searchsploit is absent and D-16 source status after enrichment
- Extended vault service note template with an Exploits table section (exploit-db.com linked EDB-IDs) rendered when port.exploits is non-empty

## Task Commits

1. **Task 1: Extend enrichment orchestrator with OSV, SearchSploit, cache, and source selection** - `491fc4b` (feat)
2. **Task 2: CLI flags, main.rs wiring, and vault Exploits section** - `98926c3` (feat)

## Files Created/Modified

- `src/enrichment/mod.rs` - Extended enrich_scan signature, EnrichmentOptions/Stats, cache integration, SearchSploit invocation, source_status tracking
- `src/cli.rs` - Added --fresh (bool) and --disable-source (Vec<String>, Append) flags
- `src/main.rs` - Conditional source creation, D-02 warning, D-16 source status output
- `src/vault/templates.rs` - Added exploits parameter to render_service_body, Exploits table with EDB-ID links
- `src/vault/mod.rs` - Updated render_service_body call to pass &port.exploits

## Decisions Made

- Used `Option<Arc<T>>` for each source in `enrich_scan` — cleaner than a config flags struct, and callers can conditionally build sources before calling
- Cache wraps NVD and OSV only; CVE.org enriches per-CVE (not a lookup source), so caching would give no benefit
- Atomic counters for source_status avoid needing a Mutex around shared state across tokio::spawn boundaries
- Passed `&[]` for exploits in existing `render_service_body` tests — no test data changes needed, backward compatible

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required beyond existing PORTREAPER_NVD_KEY env var.

## Next Phase Readiness

- Phase 4 complete: NVD + CVE.org + OSV.dev + SearchSploit all integrated end-to-end
- Cache is operational with 7-day TTL; --fresh bypasses it
- Vault service notes include Exploits when present
- Ready for Phase 5 (polish and release): integration tests with real XML files, manpage generation, packaging

---
*Phase: 04-additional-sources-and-caching*
*Completed: 2026-03-24*

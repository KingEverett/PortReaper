---
phase: 02-enrichment-core
plan: 03
subsystem: cli
tags: [tokio, async, owo-colors, clap, enrichment, cve-display]

requires:
  - phase: 02-enrichment-core plan 01
    provides: Vulnerability/CvssScore/Severity models, VulnSource trait, NvdSource, CveOrgSource
  - phase: 02-enrichment-core plan 02
    provides: enrich_scan orchestrator with Arc<NvdSource>/Arc<CveOrgSource>, EnrichmentOptions, EnrichmentStats

provides:
  - CLI --no-enrich flag that skips enrichment entirely (Phase 1 behavior preserved)
  - Async tokio main with enrichment pipeline wired between parse and render
  - CVE child nodes under port nodes in tree with [Severity Score] tags
  - Color-coded severity display: Critical=red, High=yellow, Medium=cyan, Low=green
  - Summary line updated with CVE counts by severity when vulnerabilities present
  - Progress suppression via -q flag passed to EnrichmentOptions.quiet
  - NVD API key read from PORTREAPER_NVD_KEY env var

affects: [03-obsidian-vault, future phases reading enriched scan output]

tech-stack:
  added: []
  patterns:
    - Arc wrapping of NvdSource/CveOrgSource for tokio::spawn sharing
    - Async fn run() and #[tokio::main] async fn main() pattern
    - Tree child ordering: CPEs (verbose) before CVEs, LAST_BRANCH on final child

key-files:
  created: []
  modified:
    - src/cli.rs
    - src/main.rs
    - src/render/tree.rs
    - tests/cli.rs

key-decisions:
  - "enrich_scan takes Arc<NvdSource>/Arc<CveOrgSource> not plain refs -- plan said plain refs but actual API uses Arc; wired accordingly"
  - "CPE and CVE child nodes share same prefix logic -- CPEs (verbose) rendered first, vulns after, LAST_BRANCH on final child regardless of type"
  - "Summary line format branches on total_cves > 0: CVE counts format vs unique-services format"

patterns-established:
  - "Async run(): all new features that need enrichment go through async fn run()"
  - "render_vulnerability(): D-02 format [Label Score] with D-03 color applied per Severity variant"

requirements-completed: [ARCH-04, VULN-06]

duration: 8min
completed: 2026-03-21
---

# Phase 2 Plan 03: CLI Integration and CVE Tree Display Summary

**tokio async main wiring NVD/CVE.org enrichment into portreaper with inline CVE tree display, severity color coding, and --no-enrich bypass flag**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-03-21T22:08:00Z
- **Completed:** 2026-03-21T22:16:00Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Converted main.rs to `#[tokio::main]` async with full enrichment pipeline between parse and render
- Added `--no-enrich` flag that preserves Phase 1 tree behavior without any API calls
- Extended tree renderer with `render_vulnerability()` showing `CVE-ID [Crit 9.8]` format under port nodes
- Summary line now reports CVE counts by severity (`N CVEs (Y critical, Z high, ...)`) when vulnerabilities found
- Added integration tests `test_no_enrich_flag` and `test_quiet_with_no_enrich`
- All 107 tests pass across 7 test suites

## Task Commits

1. **Task 1: Update CLI flags, convert main to async, wire enrichment pipeline** - `59e0a4a` (feat)
2. **Task 2: Extend tree renderer with CVE display, severity colors, updated summary** - `0aa9ab2` (feat)

## Files Created/Modified

- `src/cli.rs` - Replaced hidden `--enrich` flag with public `--no-enrich: bool` flag
- `src/main.rs` - Converted to `#[tokio::main]` async, wired `enrich_scan` between parse and render, reads `PORTREAPER_NVD_KEY` env var
- `src/render/tree.rs` - Added `render_vulnerability()`, CVE child nodes under ports, severity color coding, updated summary line
- `tests/cli.rs` - Added `test_no_enrich_flag` and `test_quiet_with_no_enrich` integration tests, updated `test_summary_counts` to use `--no-enrich`

## Decisions Made

- **Arc wrapping deviation**: The plan showed `enrich_scan` taking plain `&NvdSource` / `&CveOrgSource` references, but the actual implementation from Plan 02 uses `Arc<NvdSource>` and `Arc<CveOrgSource>`. Wired correctly using `Arc::new()` in main.rs.
- **Child node ordering**: CPE strings (verbose mode) render first under a port node, vulnerability lines after. The `is_last_child` logic uses absolute child index (`cpe_count + vi == total_children - 1`) to correctly place LAST_BRANCH on whichever is the final child.
- **Summary branching**: When `total_cves == 0`, the original unique-services format is preserved. When CVEs are present, the new count-by-severity format is used.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected enrich_scan Arc signature mismatch**
- **Found during:** Task 1 (wiring enrichment pipeline)
- **Issue:** Plan showed `enrich_scan(&mut result, &nvd, &cve_org, &enrich_opts)` with plain references, but actual `enrich_scan` signature from Plan 02 takes `Arc<NvdSource>` and `Arc<CveOrgSource>`
- **Fix:** Used `Arc::new(NvdSource::new(api_key))` and `Arc::new(CveOrgSource::new())`, passed `nvd` / `cve_org` directly (Arc is clone-on-pass for the internal task spawning)
- **Files modified:** `src/main.rs`
- **Verification:** `cargo build` exits 0, all tests pass
- **Committed in:** `59e0a4a` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - Bug, API signature mismatch between plan documentation and actual implementation)
**Impact on plan:** Required fix to compile; no scope creep.

## Issues Encountered

None beyond the Arc signature deviation documented above.

## User Setup Required

Optional: set `PORTREAPER_NVD_KEY` environment variable for higher NVD API rate limits.
No mandatory configuration required for basic functionality.

## Next Phase Readiness

- Phase 2 enrichment-core complete: NVD and CVE.org sources implemented, enrichment pipeline wired, CVE display in tree
- Phase 3 (Obsidian vault generation) can use the enriched `ScanResult` with `port.vulnerabilities` populated
- `--no-enrich` flag provides escape hatch for fast tree-only output

---
*Phase: 02-enrichment-core*
*Completed: 2026-03-21*

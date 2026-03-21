---
phase: 02-enrichment-core
plan: 02
subsystem: vulnerability-enrichment
tags: [rust, reqwest, serde, tokio, semaphore, cvss, cve, nvd, cve-org]

# Dependency graph
requires:
  - phase: 02-01
    provides: VulnSource trait, VulnLookupError, NvdSource, CvssScore, Vulnerability, ScanResult models

provides:
  - CveOrgSource with lookup_cve_id for per-CVE-ID enrichment via cveawg.mitre.org
  - extract_cvss_from_cve_org extracting CVSS from CNA and ADP containers (highest wins)
  - enrich_scan orchestrator coordinating NVD CPE lookups with CVE.org per-CVE enrichment
  - dedup_vulnerabilities keeping highest CVSS per CVE ID
  - with_retry exponential backoff (1s/2s/4s, 3 attempts) for RateLimited/NetworkFailure
  - EnrichmentStats and EnrichmentOptions structs
  - CVE.org fixture files for CVE-2021-41773 and CVE-2023-44487

affects: [03-output-wiring, phase-03, main.rs integration]

# Tech tracking
tech-stack:
  added: []  # No new dependencies; uses existing tokio, reqwest, serde
  patterns:
    - Arc<T> for sharing sources across tokio::spawn tasks (avoids raw pointer Send unsafety)
    - Option fields with serde default for handling heterogeneous metric types (ssvc/cvss)
    - with_retry generic over Fn()->Future pattern for reusable retry logic
    - dedup_vulnerabilities using HashMap<cve_id, Vulnerability> keeping max score

key-files:
  created:
    - src/sources/cve_org.rs
    - src/enrichment/mod.rs
    - tests/fixtures/cve_org_response_cve_2021_41773.json
    - tests/fixtures/cve_org_response_cve_2023_44487.json
  modified:
    - src/sources/mod.rs (added pub mod cve_org)
    - src/lib.rs (added pub mod enrichment)

key-decisions:
  - "enrich_scan takes Arc<NvdSource> and Arc<CveOrgSource> rather than &dyn VulnSource to avoid RPITIT object-safety issues and enable tokio::spawn sharing"
  - "CveOrgMetric uses all-Option CVSS fields so non-CVSS metrics (ssvc/other type) deserialize without failure"
  - "enrich_scan public signature uses Arc<NvdSource>/Arc<CveOrgSource>; callers must wrap in Arc"

patterns-established:
  - "Fixture-first TDD: fixture files created before implementation, tests written against real API response shapes"
  - "with_retry generic pattern: Fn()->Future allows any async operation to benefit from backoff"
  - "Arc wrapping for Send across tokio::spawn instead of unsafe raw pointer helpers"

requirements-completed: [VULN-02, VULN-06]

# Metrics
duration: 4min
completed: 2026-03-21
---

# Phase 2 Plan 02: CVE.org Source and Enrichment Orchestrator Summary

**CveOrgSource fetching CVE records from cveawg.mitre.org with CNA+ADP CVSS extraction, and enrich_scan orchestrator with tokio::Semaphore concurrency, 1s/2s/4s exponential backoff, CVE deduplication taking highest CVSS, and stderr progress output**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-21T21:20:24Z
- **Completed:** 2026-03-21T21:24:35Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Implemented CveOrgSource with lookup_cve_id querying cveawg.mitre.org/api/cve/{id}; handles 404 (Ok(None)), 429 (RateLimited), and gracefully ignores non-CVSS metric entries (ssvc/other type)
- Implemented enrich_scan orchestrator: collects CPE services, spans bounded-concurrency tasks via Arc<Semaphore>, queries NVD then enriches each CVE via CVE.org, writes deduped results back to scan.hosts[i].ports[j].vulnerabilities
- Implemented with_retry with 1s/2s/4s delays and 3-attempt cap; returns Empty immediately without retrying (Empty is not a transient condition)
- 18 new tests pass across the two modules; full suite of 101 tests continues to pass

## Task Commits

1. **Task 1: CveOrgSource with CVSS extraction** - `b2462b1` (feat)
2. **Task 2: Enrichment orchestrator** - `7d3154f` (feat)

## Files Created/Modified

- `src/sources/cve_org.rs` - CveOrgSource struct; lookup_cve_id; extract_cvss_from_cve_org; serde structs for CVE.org v5 response; VulnSource impl returning Empty for lookup_cpe
- `src/enrichment/mod.rs` - enrich_scan orchestrator; dedup_vulnerabilities; with_retry; EnrichmentStats; EnrichmentOptions (default concurrency 5)
- `src/sources/mod.rs` - Added pub mod cve_org
- `src/lib.rs` - Added pub mod enrichment
- `tests/fixtures/cve_org_response_cve_2021_41773.json` - CVE-2021-41773 fixture with ssvc-type CNA and CVSS 9.8 CRITICAL in CISA-ADP
- `tests/fixtures/cve_org_response_cve_2023_44487.json` - CVE-2023-44487 fixture with CVSS 7.5 HIGH in CISA-ADP

## Decisions Made

- **Arc for task sharing:** enrich_scan takes `Arc<NvdSource>` and `Arc<CveOrgSource>` rather than plain references to allow sharing across tokio::spawn tasks without unsafe. Raw pointer approach rejected (tokio::spawn requires Send, raw pointers are not Send).
- **Option fields for metric types:** CveOrgMetric uses all-Option CVSS fields (cvss_v4_0, cvss_v3_1, cvss_v3_0 all Option) so entries with only `other`/`ssvc` type deserialize cleanly to all-None without panicking.
- **with_retry generic:** The with_retry function takes `Fn() -> Fut` to allow calling the same closure multiple times; this pattern avoids borrowing conflicts with the retry loop.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed missing VulnSource import in enrichment module**
- **Found during:** Task 2 (first compile)
- **Issue:** Calling `nvd_ref.lookup_cpe(cpe)` failed because VulnSource trait was not in scope
- **Fix:** Added `use crate::sources::VulnSource;` to imports
- **Files modified:** src/enrichment/mod.rs
- **Verification:** Cargo compiled successfully after fix
- **Committed in:** 7d3154f (Task 2 commit)

**2. [Rule 1 - Bug] Replaced raw pointer approach with Arc for tokio::spawn sharing**
- **Found during:** Task 2 (compile: "future cannot be sent between threads safely")
- **Issue:** Initial implementation used `*const NvdSource` raw pointer wrappers with unsafe Send impl to share across tokio::spawn; Rust correctly rejected this
- **Fix:** Changed enrich_scan signature to accept `Arc<NvdSource>` and `Arc<CveOrgSource>`; each task clones the Arc
- **Files modified:** src/enrichment/mod.rs
- **Verification:** All tests pass; no unsafe code needed
- **Committed in:** 7d3154f (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 blocking, 1 bug)
**Impact on plan:** Both fixes were necessary for correctness and safety. The Arc-based signature is idiomatic Rust for this pattern. No scope creep.

## Issues Encountered

None beyond the auto-fixed deviations above.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Enrichment pipeline complete: NVD CPE lookup + CVE.org per-CVE enrichment + dedup + backoff
- Ready for Plan 03 (output wiring): enrich_scan can be called from main.rs after parsing
- Callers must wrap NvdSource and CveOrgSource in Arc before calling enrich_scan
- Note: enrich_scan with_retry uses real sleep delays (1s/2s/4s); integration tests should avoid triggering retries

---
*Phase: 02-enrichment-core*
*Completed: 2026-03-21*

## Self-Check: PASSED

- src/sources/cve_org.rs: FOUND
- src/enrichment/mod.rs: FOUND
- tests/fixtures/cve_org_response_cve_2021_41773.json: FOUND
- tests/fixtures/cve_org_response_cve_2023_44487.json: FOUND
- .planning/phases/02-enrichment-core/02-02-SUMMARY.md: FOUND
- Commit b2462b1 (Task 1): FOUND
- Commit 7d3154f (Task 2): FOUND

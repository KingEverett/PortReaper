---
phase: 02-enrichment-core
plan: 01
subsystem: api
tags: [nvd, cvss, cpe, reqwest, tokio, serde_json, vulnerability]

# Dependency graph
requires:
  - phase: 01-foundation
    provides: Port struct, VulnSource trait skeleton, ScanResult/Host/Service models

provides:
  - Vulnerability struct with cve_id, source, cvss, description fields
  - CvssScore struct with score, severity, version fields
  - Severity enum with from_score(), from_str(), label() methods
  - Port struct extended with vulnerabilities: Vec<Vulnerability> field
  - VulnSource trait updated with async lookup_cpe() via RPITIT (edition 2024)
  - cpe22_to_cpe23() CPE format conversion function in sources/mod.rs
  - NvdSource implementing VulnSource with full CVSS extraction (V4/V31/V30/V2)
  - NVD API v2 request construction with cpeName and resultsPerPage params
  - Test fixtures: nvd_response_openssh74.json, nvd_response_apache249.json, scan_vulnerable.xml

affects:
  - 02-02 (CVE.org source uses same Vulnerability/CvssScore types)
  - 02-03 (enrichment orchestration uses NvdSource and VulnSource trait)
  - 03-obsidian (vault rendering uses Port.vulnerabilities field)

# Tech tracking
tech-stack:
  added:
    - tokio 1.50.0 (async runtime, features = full)
    - reqwest 0.13.2 (HTTP client, features = json, rustls, query)
    - serde_json 1.0.149 (NVD API JSON deserialization)
  patterns:
    - RPITIT for async trait methods (edition 2024, no async_trait crate needed)
    - Separate serde structs for V2 vs V3+ CVSS entries (V2 baseSeverity at entry level)
    - pub(crate) helper functions for unit-testable extraction logic
    - include_str! fixture loading for offline unit tests

key-files:
  created:
    - src/sources/nvd.rs
    - tests/fixtures/nvd_response_openssh74.json
    - tests/fixtures/nvd_response_apache249.json
    - tests/fixtures/scan_vulnerable.xml
  modified:
    - src/models.rs (Severity, CvssScore, Vulnerability types; Port.vulnerabilities field)
    - src/sources/mod.rs (VulnSource trait with lookup_cpe, cpe22_to_cpe23, pub mod nvd)
    - src/parser/xml.rs (Port constructor updated)
    - src/parser/greppable.rs (Port constructor updated)
    - src/parser/text.rs (Port constructor updated)
    - src/parser/mod.rs (Port constructor updated)
    - src/render/tree.rs (Port constructors in tests updated)
    - Cargo.toml (tokio, reqwest, serde_json added)

key-decisions:
  - "RPITIT (Return Position Impl Trait In Traits) used for async lookup_cpe instead of async_trait crate - edition 2024 native"
  - "reqwest 0.13 uses 'rustls' feature name (not 'rustls-tls' from 0.12); also needs explicit 'query' feature for .query() method"
  - "V2 baseSeverity at entry level - separate CvssV2Entry/CvssV2Data serde structs prevent silent null extraction"
  - "pub(crate) on extract_cvss/extract_vulnerabilities enables unit tests without HTTP mocking"
  - "Fixture JSON files use include_str! macro for offline, deterministic unit tests"

patterns-established:
  - "V2 CVSS trap: baseSeverity at CvssV2Entry level; V3+ baseSeverity inside cvssData - use separate serde structs"
  - "Both 429 and 403 map to VulnLookupError::RateLimited from NVD (historic 403 behavior)"
  - "CPE 2.2 -> 2.3 conversion via strip_prefix('cpe:/') + splitn(4, ':') produces NVD-compatible strings"

requirements-completed: [VULN-01, VULN-05]

# Metrics
duration: 5min
completed: 2026-03-21
---

# Phase 2 Plan 1: Vulnerability Types and NvdSource Summary

**Vulnerability/CvssScore/Severity types with NvdSource implementing CPE 2.2-to-2.3 conversion and CVSS V4/V31/V30/V2 extraction against fixture JSON**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-21T21:12:35Z
- **Completed:** 2026-03-21T21:17:30Z
- **Tasks:** 2
- **Files modified:** 12

## Accomplishments

- Defined Vulnerability, CvssScore, Severity types in models.rs with complete CVSS severity classification
- Extended Port struct with vulnerabilities field and updated all 5 constructor sites across the codebase
- Implemented NvdSource with correct CVSS extraction handling the V2 baseSeverity-at-entry-level trap
- Created realistic NVD API v2 fixture files and scan_vulnerable.xml for downstream test use
- Updated VulnSource trait with async lookup_cpe using edition 2024 RPITIT (no async_trait crate needed)

## Task Commits

1. **Task 1: Add dependencies, define Vulnerability/Severity types, update VulnSource trait** - `fa37118` (feat)
2. **Task 2: Implement NvdSource with CVSS extraction and fixture-based tests** - `89e9108` (feat)

## Files Created/Modified

- `src/models.rs` - Added Severity enum, CvssScore struct, Vulnerability struct; Port.vulnerabilities field
- `src/sources/mod.rs` - Updated VulnSource trait with async lookup_cpe, added cpe22_to_cpe23(), pub mod nvd
- `src/sources/nvd.rs` - NvdSource: VulnSource impl, CVSS extraction (V4/V31/V30/V2), rate limit handling
- `src/parser/xml.rs` - Port constructor: vulnerabilities: vec![]
- `src/parser/greppable.rs` - Port constructor: vulnerabilities: vec![]
- `src/parser/text.rs` - Port constructor: vulnerabilities: vec![]
- `src/parser/mod.rs` - Port constructor in test helper: vulnerabilities: vec![]
- `src/render/tree.rs` - Port constructors in tests: vulnerabilities: vec![]
- `Cargo.toml` - Added tokio 1.50.0, reqwest 0.13.2, serde_json 1.0.149
- `tests/fixtures/nvd_response_openssh74.json` - OpenSSH 7.4 CVEs (V31 + V2-only entries)
- `tests/fixtures/nvd_response_apache249.json` - CVE-2021-41773 (score 9.8, CRITICAL)
- `tests/fixtures/scan_vulnerable.xml` - nmap fixture with CPE and no-CPE ports

## Decisions Made

- Used RPITIT for async trait method instead of `async_trait` crate — edition 2024 makes it native
- reqwest 0.13 renamed the TLS feature to `rustls` (not `rustls-tls`) and extracted `query` as a separate feature — required updating from plan's suggested `cargo add reqwest --features json,rustls-tls`
- Separate `CvssV2Entry` and `CvssV2Data` serde structs enforce the V2 baseSeverity-at-entry-level pattern at the type level

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] reqwest 0.13 feature names differ from plan**
- **Found during:** Task 1 (adding dependencies)
- **Issue:** Plan specified `--features json,rustls-tls` but reqwest 0.13 uses `rustls` (not `rustls-tls`) and the `.query()` method requires a separate `query` feature
- **Fix:** Used `--features json,rustls,query` to match reqwest 0.13 API
- **Files modified:** Cargo.toml
- **Verification:** cargo build succeeds, .query() method available on RequestBuilder
- **Committed in:** fa37118 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking — dependency feature name mismatch)
**Impact on plan:** Minor — only required adjusting cargo add flags. No scope change.

## Issues Encountered

None beyond the reqwest feature name deviation above.

## Known Stubs

None - NvdSource is fully implemented with real HTTP client logic. The fixture-based tests use real serde deserialization, not mocked return values.

## Next Phase Readiness

- All Vulnerability/CvssScore/Severity types are ready for CVE.org source (Plan 02-02)
- Port.vulnerabilities field ready for enrichment orchestration (Plan 02-03)
- NvdSource ready to be instantiated in enrichment module
- scan_vulnerable.xml fixture available for integration tests in later plans
- cpe22_to_cpe23() ready to be used anywhere CPE format conversion is needed

---
*Phase: 02-enrichment-core*
*Completed: 2026-03-21*

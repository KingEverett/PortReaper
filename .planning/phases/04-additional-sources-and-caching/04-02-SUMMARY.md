---
phase: 04-additional-sources-and-caching
plan: "02"
subsystem: sources
tags: [searchsploit, exploits, exploit-source, tokio-process, serde, exploit-db]

requires:
  - phase: 04-additional-sources-and-caching
    plan: "01"
    provides: ExploitSource trait, ExploitLookupError enum, Exploit struct in models.rs

provides:
  - SearchSploitSource implementing ExploitSource trait via async tokio::process::Command
  - parse_cve_refs() helper filtering semicolon-separated Codes field to CVE-* entries only
  - try_new() binary detection returning None gracefully when searchsploit not on PATH
  - Test fixture tests/fixtures/searchsploit_openssh74.json with 2 openssh exploits

affects:
  - 04-03 (wiring plan — SearchSploitSource will be constructed and wired into enrichment pipeline)

tech-stack:
  added: []
  patterns:
    - "SearchSploitSource::try_new() pattern: probe binary via std::process::Command --help, return None on Err"
    - "parse_cve_refs() pattern: split on ';', filter starts_with('CVE-'), collect — reusable for any ExploitDB Codes field"
    - "Async binary invocation via tokio::process::Command — avoids blocking runtime during searchsploit DB reads"
    - "Verified field as String '0'/'1' mapped to bool via entry.verified == '1'"

key-files:
  created:
    - src/sources/searchsploit.rs — SearchSploitSource, parse_cve_refs, entry_to_exploit, serde structs, 10 unit tests
    - tests/fixtures/searchsploit_openssh74.json — 2-entry openssh fixture (CVE-2016-6210, CVE-2018-15473)
  modified:
    - src/sources/mod.rs — added pub mod searchsploit

key-decisions:
  - "try_new() probes via std::process::Command::new('searchsploit').arg('--help') — no 'which' crate needed, handles PATH"
  - "Empty results return ExploitLookupError::Empty (not Ok([])) — consistent with OSV pattern; callers can distinguish no-data from error"
  - "search_product() returns Err on non-zero exit code from subprocess — aligns with SubprocessFailed variant"

patterns-established:
  - "Pattern: Binary detection via Command::new(binary).arg('--help').status() — works for any local tool"
  - "Pattern: Serde rename for PascalCase JSON fields ('Title', 'EDB-ID', 'Date_Published') using #[serde(rename)]"

requirements-completed: [VULN-04]

duration: 1min
completed: 2026-03-24
---

# Phase 4 Plan 02: SearchSploitSource Summary

**SearchSploitSource implementing ExploitSource via `tokio::process::Command -j`, CVE ref extraction from Codes field, graceful binary-not-found handling**

## Performance

- **Duration:** 1 min
- **Started:** 2026-03-24T20:37:48Z
- **Completed:** 2026-03-24T20:38:59Z
- **Tasks:** 1
- **Files modified:** 3 files (2 created, 1 modified)

## Accomplishments

- SearchSploitSource implements ExploitSource — invokes `searchsploit -j <product> <version>` asynchronously via tokio::process::Command
- parse_cve_refs() filters semicolon-separated Codes field (e.g., "CVE-2016-6210;OSVDB-140070") to CVE-* entries only
- try_new() probes PATH for searchsploit binary without extra crates; returns None gracefully when not found
- Empty RESULTS_EXPLOIT array returns ExploitLookupError::Empty (not a crash)
- 10 unit tests covering: parse_cve_refs edge cases, fixture deserialization, verified flag mapping, binary detection, name()
- 155 lib tests passing (up from 145)

## Task Commits

1. **Task 1: SearchSploitSource with async binary invocation and JSON parsing** - `fe22a52` (feat)

## Files Created/Modified

- `src/sources/searchsploit.rs` — SearchSploitSource, parse_cve_refs, entry_to_exploit, SearchSploitOutput/SearchSploitEntry serde structs, 10 unit tests
- `tests/fixtures/searchsploit_openssh74.json` — 2-entry fixture (EDB-40136 with CVE-2016-6210, EDB-45233 with CVE-2018-15473)
- `src/sources/mod.rs` — added `pub mod searchsploit;`

## Decisions Made

- Used `Command::new("searchsploit").arg("--help")` for binary detection rather than `which` crate — keeps zero new dependencies
- Empty results return `ExploitLookupError::Empty` rather than `Ok(vec![])` — consistent with how OsvSource/NVD handle no-data
- try_new() accepts any successful exit code (not just success) for binary detection — `--help` on some searchsploit versions exits non-zero

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required. SearchSploitSource works offline with locally installed searchsploit binary.

## Next Phase Readiness

- Plan 03 (wiring): SearchSploitSource can be constructed via `SearchSploitSource::try_new()` and passed to enrichment pipeline
- If binary not found, caller prints warning per D-02 and skips exploit lookup
- All 155 lib tests green; no regressions

## Self-Check: PASSED

- src/sources/searchsploit.rs — FOUND
- tests/fixtures/searchsploit_openssh74.json — FOUND
- src/sources/mod.rs contains `pub mod searchsploit` — FOUND
- Commit fe22a52 — FOUND
- `cargo test --lib`: 155 passed, 0 failed

---
*Phase: 04-additional-sources-and-caching*
*Completed: 2026-03-24*

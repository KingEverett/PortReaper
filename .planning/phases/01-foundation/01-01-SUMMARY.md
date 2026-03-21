---
phase: 01-foundation
plan: "01"
subsystem: infra
tags: [rust, cargo, quick-xml, serde, thiserror, clap, owo-colors, is-terminal, sanitize-filename, nmap]

# Dependency graph
requires: []
provides:
  - Compilable Rust project skeleton with all Phase 1 dependencies
  - Core data models: ScanResult, Host, Port, Service, Address with all optional fields as Option<T>
  - VulnSource trait with Send + Sync bounds for pluggable vulnerability data sources
  - VulnLookupError enum with Empty/RateLimited/NetworkFailure typed variants via thiserror
  - sanitize_filename() wrapper routing all filename construction through sanitize-filename crate
  - Test fixture files covering XML (basic, multi-host, minimal-service), text, greppable, and non-nmap formats
affects: [01-02, 01-03, phase-2, phase-3, phase-4]

# Tech tracking
tech-stack:
  added:
    - clap 4.6.0 (CLI argument parsing with derive feature)
    - quick-xml 0.39.2 (nmap XML deserialization via serde, serialize feature)
    - serde 1.0.228 (struct deserialization with derive feature)
    - thiserror 2.0.18 (typed error enum derive)
    - is-terminal 0.4.17 (TTY detection)
    - owo-colors 4.3.0 (conditional terminal color)
    - anyhow 1.0.102 (error propagation in binary layer)
    - regex 1.12.3 (text/greppable format parsing)
    - sanitize-filename 0.6.0 (safe filename generation)
  patterns:
    - All nmap service fields except name are Option<T> (product/version/extrainfo often absent)
    - VulnSource trait bounded with Send + Sync for concurrent use
    - sanitize_filename() is the single entry point for all filename construction
    - Typed error taxonomy at trait boundaries: Empty/RateLimited/NetworkFailure

key-files:
  created:
    - Cargo.toml
    - src/main.rs
    - src/models.rs
    - src/sources/mod.rs
    - src/util/filename.rs
    - src/util/mod.rs
    - src/cli.rs
    - src/parser/mod.rs
    - src/render/mod.rs
    - tests/fixtures/scan_basic.xml
    - tests/fixtures/scan_multi_host.xml
    - tests/fixtures/scan_minimal_service.xml
    - tests/fixtures/scan_basic.txt
    - tests/fixtures/scan_basic.grep
    - tests/fixtures/not_nmap.txt
  modified: []

key-decisions:
  - "All nmap service fields except name are Option<T> -- product/version/extrainfo absent in many real-world targets"
  - "VulnSource trait has Send + Sync bounds -- required for bounded concurrency via tokio::sync::Semaphore"
  - "sanitize_filename() wrapper exists before any file-write code -- routes all filename construction through sanitize-filename crate"
  - "Typed error taxonomy (Empty/RateLimited/NetworkFailure) defined at trait boundary from Phase 1 -- enables correct error handling in Phase 2"
  - "serde-saphyr deferred to Phase 3 -- no YAML output needed in Phase 1 per research open question 1"

patterns-established:
  - "Pattern: Service model uses Option<T> for all fields except name -- avoids deserialization failures on real-world nmap scans"
  - "Pattern: VulnSource trait = interface contract; implementations live in Phase 2"
  - "Pattern: thiserror derive for VulnLookupError -- maintains type info at trait boundaries (not erased by anyhow)"
  - "Pattern: sanitize-filename crate wrapping -- all filename construction goes through sanitize_filename() fn"

requirements-completed: [ARCH-01, ARCH-02]

# Metrics
duration: 3min
completed: 2026-03-21
---

# Phase 1 Plan 01: Project Skeleton and Core Types Summary

**Compilable Rust portreaper binary with ScanResult/Host/Port/Service models, VulnSource trait + VulnLookupError taxonomy, sanitize_filename wrapper, and 6 nmap test fixtures covering all format variants**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-03-21T19:50:50Z
- **Completed:** 2026-03-21T19:53:40Z
- **Tasks:** 3
- **Files modified:** 15

## Accomplishments
- Initialized Rust project with all 9 Phase 1 dependencies; `cargo build` compiles clean
- Defined core data models (ScanResult, Host, Port, Service) with all optional service fields as `Option<T>`, matching nmap DTD spec
- Defined `VulnSource: Send + Sync` trait with `VulnLookupError` enum (Empty/RateLimited/NetworkFailure) via thiserror
- Created `sanitize_filename()` wrapper as single choke point for all filename construction
- Created 6 test fixture files covering XML single-host, XML multi-host, XML minimal-service, text, greppable, and non-nmap formats
- 13 unit tests passing across models, sources, and util modules

## Task Commits

Each task was committed atomically:

1. **Task 1: Initialize Rust project and add all Phase 1 dependencies** - `0d705c6` (feat)
2. **Task 2: Define core data models, VulnSource trait, error taxonomy, and sanitize_filename** - `ff3124e` (feat)
3. **Task 3: Create nmap test fixture files for XML, text, and greppable formats** - `53285a0` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified
- `Cargo.toml` - Project manifest with all 9 Phase 1 dependencies
- `src/main.rs` - Entry point declaring all 6 modules (cli, models, parser, render, sources, util)
- `src/models.rs` - ScanResult, Host, Port, Service, Address with Option<T> service fields and 4 unit tests
- `src/sources/mod.rs` - VulnLookupError enum + VulnSource trait with 5 unit tests
- `src/util/filename.rs` - sanitize_filename() wrapper with 4 unit tests
- `src/util/mod.rs` - Exposes filename module
- `src/cli.rs` - Stub placeholder for Plan 03
- `src/parser/mod.rs` - Stub placeholder for Plan 02
- `src/render/mod.rs` - Stub placeholder for Plan 03
- `tests/fixtures/scan_basic.xml` - Single host, 3 ports, mixed optional service fields including CPE
- `tests/fixtures/scan_multi_host.xml` - Three hosts for INPUT-03 coverage
- `tests/fixtures/scan_minimal_service.xml` - All optional service fields absent (tests Pitfall 1)
- `tests/fixtures/scan_basic.txt` - Nmap default text output
- `tests/fixtures/scan_basic.grep` - Nmap greppable (-oG) output
- `tests/fixtures/not_nmap.txt` - Non-nmap file for error handling tests

## Decisions Made
- Deferred serde-saphyr to Phase 3 per research open question 1 — no YAML output needed in Phase 1
- Used sanitize-filename 0.6.0 (latest stable) instead of 0.7.0-beta to avoid pre-stable API
- VulnSource trait intentionally minimal in Phase 1 (name() only); async lookup() deferred to Phase 2

## Deviations from Plan

None - plan executed exactly as written.

## Self-Check: PASSED

All files verified present. All task commits verified in git log.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Plan 02 (XML/text/greppable parsers) can now build on the fixture files and models defined here
- Plan 03 (CLI + tree renderer) can build on the module stubs and models
- All fixture files cover the edge cases the parsers need to handle (optional fields, multiple hosts, minimal service)
- VulnSource trait ready for Phase 2 implementations (NVD, CVE.org)

---
*Phase: 01-foundation*
*Completed: 2026-03-21*

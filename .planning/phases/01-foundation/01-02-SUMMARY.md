---
phase: 01-foundation
plan: "02"
subsystem: parser
tags: [rust, quick-xml, serde, regex, nmap, xml, text, greppable]

# Dependency graph
requires:
  - 01-01 (ScanResult/Host/Port/Service models, fixture files, Cargo.toml with dependencies)
provides:
  - XML parser (parse_xml) using quick-xml + serde two-layer deserialization
  - Text format parser (parse_text) using LazyLock<Regex> line-oriented parsing
  - Greppable format parser (parse_greppable) using LazyLock<Regex> tab-delimited parsing
  - Format auto-detection (detect_format) by content sniffing
  - Parse dispatch (parse) routing to correct parser by detected format
  - Multi-file host merging (parse_and_merge) with IP-keyed HashMap union
  - src/lib.rs exposing parser/models/sources/util for integration tests
affects: [01-03, phase-2, phase-3, phase-4]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Two-layer XML deserialization: private XmlHost/XmlPort/XmlService structs map to nmap DTD, then convert to normalized models
    - LazyLock<Regex> for compiled regex patterns in text and greppable parsers (no lazy_static dependency)
    - Text/greppable version info stored in product field -- these formats don't separate product/version cleanly
    - parse_and_merge uses HashMap<String, Host> keyed on IP for O(1) merge per host
    - src/lib.rs required to expose modules for integration tests (binary crate limitation)

key-files:
  created:
    - src/lib.rs
    - src/parser/xml.rs
    - src/parser/text.rs
    - src/parser/greppable.rs
    - tests/xml_parse.rs
    - tests/text_parse.rs
    - tests/greppable_parse.rs
  modified:
    - src/parser/mod.rs
    - src/main.rs

key-decisions:
  - "src/lib.rs added to expose parser modules for integration tests -- binary crates don't expose pub modules to tests/ by default"
  - "Text and greppable format parsers store combined version string in product field -- these formats don't separate product/version cleanly, consistent with CONTEXT.md 'parse what is available'"
  - "parse() returns Ok with empty hosts for non-nmap text input (warns stderr) rather than Err -- non-nmap text format is indistinguishable from valid text format without hosts"

requirements-completed: [INPUT-01, INPUT-02, INPUT-03, INPUT-04]

# Metrics
duration: 4min
completed: 2026-03-21
---

# Phase 1 Plan 02: Nmap Parsers Summary

**XML/text/greppable parsers with format auto-detection by content sniffing and multi-file host merging via IP-keyed HashMap**

## Performance

- **Duration:** ~4 min
- **Started:** 2026-03-21T19:55:55Z
- **Completed:** 2026-03-21T20:00:07Z
- **Tasks:** 3
- **Files modified:** 9

## Accomplishments

- Implemented XML parser using quick-xml + serde two-layer approach: private raw DTD structs (NmapRun/XmlHost/XmlPort/XmlService) converted to normalized models
- All XML optional fields (product, version, extrainfo, tunnel, hostname, ostype, devicetype) mapped as Option<T>; CPE text elements extracted from Vec<XmlCpe>
- Text format parser using LazyLock<Regex> splitting content by "Nmap scan report for" headers, extracting port/service per matching line
- Greppable format parser using LazyLock<Regex> parsing Host: lines and slash-delimited Ports: fields with HashMap merging for Status+Ports lines
- detect_format() content sniffs first 64 bytes: `<?xml`/`<nmaprun` -> XML, `# Nmap`/`Host:` -> Greppable, else Text
- parse() dispatches to correct parser; parse_and_merge() merges hosts by IP with port union
- Added src/lib.rs to expose pub modules for integration test binaries
- 45 tests total: 9 XML, 6 text, 5 greppable, 12 parser unit, 13 existing models/sources/util

## Task Commits

Each task was committed atomically:

1. **Task 1: XML parser with quick-xml serde deserialization** - `1609303` (feat)
2. **Task 2: Text and greppable parsers with regex** - `501b42d` (feat)
3. **Task 3: Format detection, parse dispatch, and host merging** - `af9f644` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `src/lib.rs` - Exposes models/parser/sources/util as pub modules for integration tests
- `src/parser/xml.rs` - XML parser: private NmapRun serde structs + parse_xml() conversion to models
- `src/parser/text.rs` - Text parser: LazyLock HOST_HEADER + PORT_LINE regex, lenient line parsing
- `src/parser/greppable.rs` - Greppable parser: LazyLock HOST_RE + PORTS_RE, HashMap per-IP merge
- `src/parser/mod.rs` - NmapFormat enum, detect_format(), parse(), parse_and_merge(), merge_host() + 12 unit tests
- `src/main.rs` - Reduced to only declare cli/render (models/sources/util now in lib.rs)
- `tests/xml_parse.rs` - 9 XML integration tests covering host count, ports, service fields, CPE, hostname, addresses
- `tests/text_parse.rs` - 6 text integration tests covering host, ports, service name, version info, empty/malformed input
- `tests/greppable_parse.rs` - 5 greppable integration tests covering host, ports, service name, comments, malformed input

## Decisions Made

- Added `src/lib.rs` to expose parser modules — Rust binary crates don't expose pub modules to `tests/` without a lib target. This was a Rule 3 auto-fix (blocking issue: integration tests couldn't compile without it).
- Text and greppable parsers store combined version string in `product` field — these formats don't separate product/version cleanly. Consistent with CONTEXT.md "parse what's available".
- `parse()` returns `Ok` with empty hosts for non-nmap content — text format is the fallback and indistinguishable from valid text-format nmap with no hosts; warns to stderr.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added src/lib.rs for integration test module access**
- **Found during:** Task 1 (RED phase)
- **Issue:** Integration tests in `tests/` could not access `portreaper::parser::xml` because the binary crate doesn't expose pub modules externally without a lib target
- **Fix:** Created `src/lib.rs` declaring `pub mod models; pub mod parser; pub mod sources; pub mod util;`; updated `src/main.rs` to only declare `mod cli; mod render;` (the modules not needed by tests)
- **Files modified:** `src/lib.rs` (new), `src/main.rs` (reduced)
- **Commit:** `1609303`

## Self-Check: PASSED

All 8 created/modified files found on disk. Task commits 1609303, 501b42d, af9f644 confirmed in git log.

All files verified present. All task commits verified in git log.

## Known Stubs

None - all parser functions are fully implemented and return real data from fixture files.

## Issues Encountered

None beyond the lib.rs fix noted above.

## Next Phase Readiness

- Plan 03 (CLI + tree renderer) can now call `parser::parse()` and `parser::parse_and_merge()` to get ScanResult
- All three format parsers tested against real fixture files; no panics on malformed input
- merge_host() ready for multi-file scan workflows
- detect_format() + parse dispatch are the entry points Plan 03's CLI will use

---
*Phase: 01-foundation*
*Completed: 2026-03-21*

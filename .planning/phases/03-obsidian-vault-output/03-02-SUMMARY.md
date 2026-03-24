---
phase: 03-obsidian-vault-output
plan: 02
subsystem: vault
tags: [rust, obsidian, vault, wikilinks, templates, two-pass, cve, technology, serde_yml]

# Dependency graph
requires:
  - phase: 03-obsidian-vault-output
    plan: 01
    provides: frontmatter serde structs, render_note(), write_note(), VaultError, VaultStats, sanitize_filename()
  - phase: 01-foundation
    provides: sanitize_filename() routing all filename construction
  - phase: 02-enrichment-core
    provides: Severity enum, Vulnerability/Host/Port/Service models for note generation

provides:
  - src/vault/templates.rs with 4 wikilink helpers and 4 note body renderer functions
  - src/vault/mod.rs generate_vault fully implemented with CveAccumulator and TechAccumulator
  - Two-pass vault generation: pass 1 collects CVE/tech maps, pass 2 writes all files
  - Shared CVE note with Affected Services listing all referencing services
  - Technology notes aggregating instances across hosts
  - Host/service/CVE/technology notes with correct wikilinks, frontmatter, body content
affects:
  - 03-03 (index page generation and CLI wiring use generate_vault and VaultStats from here)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Two-pass vault generation: accumulate global state (CVE/tech maps) before any file writes
    - CveAccumulator pattern: upsert CVEs keyed by cve_id, keep highest CVSS, collect affected service wikilinks
    - TechAccumulator pattern: aggregate instances (ip, port, version) and deduplicated CVE IDs per product
    - Aliased wikilinks: [[filename|display]] with machine-friendly filenames and human-friendly display text
    - truncate_description at word boundary (120 char) for service note vuln table cells

key-files:
  created:
    - src/vault/templates.rs
  modified:
    - src/vault/mod.rs

key-decisions:
  - "Two-pass order: CveAccumulator and TechAccumulator collected in pass 1 so shared CVEs get all affected services before any file write"
  - "Service wikilinks pre-built as strings during pass 1 accumulation — stored in affected_services Vec<String>"
  - "render_host_body takes &Host directly (not port_severities tuple) — less indirection, accesses all host/port fields directly"
  - "CveAccumulator keeps highest-severity CVSS entry to ensure correct severity tag on shared CVEs"

patterns-established:
  - "Pattern: Pass 1 builds cve_map/tech_map, Pass 2 writes all files — never mix accumulation and file writes"
  - "Pattern: Pre-build service wikilinks during pass 1 accumulation for CVE affected_services lists"
  - "Pattern: All note body functions return String; render_note() wraps with frontmatter delimiters"

requirements-completed: [OUT-01, OUT-02, OUT-05, OUT-06]

# Metrics
duration: 4min
completed: 2026-03-24
---

# Phase 3 Plan 02: Note Body Templates and Two-Pass Vault Generation Summary

**Two-pass vault generator with 4 note body renderers (host/service/CVE/technology), aliased wikilinks per D-06, shared CVE notes accumulating all affected services, and technology notes aggregating instances across hosts**

## Performance

- **Duration:** ~4 min
- **Started:** 2026-03-24T18:25:46Z
- **Completed:** 2026-03-24T18:29:16Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- 4 wikilink helpers (host_wikilink, service_wikilink, cve_wikilink, tech_wikilink) with aliased display text per D-06
- 4 note body renderers with all sections per D-09, D-11, D-13, D-15 — every note includes user-editable ## Notes section
- Two-pass generate_vault: CveAccumulator/TechAccumulator collection (pass 1), then all file writes (pass 2)
- Shared CVE across 2 services produces exactly 1 note with both service wikilinks in Affected Services
- Services with zero CVEs still get generated notes with "No vulnerabilities found."
- Services with no product do NOT create technology notes
- 42 total vault tests pass; cargo build compiles clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Note body templates and wikilink helpers** - `286f136` (feat)
2. **Task 2: Two-pass generate_vault implementation** - `1ecf125` (feat)

## Files Created/Modified

- `src/vault/templates.rs` - host_wikilink, service_wikilink, cve_wikilink, tech_wikilink; render_host_body, render_service_body, render_cve_body, render_tech_body; truncate_description; 15 unit tests
- `src/vault/mod.rs` - CveAccumulator, TechAccumulator, highest_severity helper, full two-pass generate_vault; 14 integration tests (replaced stub)

## Decisions Made

- Two-pass order required: CveAccumulator must collect all affected services in pass 1 before any CVE file writes in pass 2 — a single-pass approach cannot produce correct "Affected Services" lists
- render_host_body takes `&Host` directly rather than a pre-built port_severities tuple — provides direct access to all fields with less indirection
- CveAccumulator keeps highest-severity CVSS entry when a CVE appears with different CVSS data from different sources — ensures the CVE note reflects worst-case severity
- Service wikilinks pre-built as strings during pass 1 accumulation and stored in `affected_services: Vec<String>` — avoids redundant reconstruction during file writes

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## Known Stubs

None — all 4 note types render real data. generate_vault is fully implemented.

## Next Phase Readiness

- generate_vault() fully implemented and tested — Plan 03 can call it directly
- VaultStats returns accurate counts ready for CLI output reporting
- All building blocks ready: templates produce correct markdown, frontmatter uses serde_yml, files route through sanitize_filename()
- No blockers

---
*Phase: 03-obsidian-vault-output*
*Completed: 2026-03-24*

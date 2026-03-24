---
phase: 03-obsidian-vault-output
plan: "03"
subsystem: vault
tags: [vault, index-pages, cli, integration-test, obsidian]
dependency_graph:
  requires: [03-02]
  provides: [complete-vault-generation, index-pages, cli-wiring, end-to-end-test]
  affects: [src/vault/templates.rs, src/vault/mod.rs, src/main.rs, src/cli.rs]
tech_stack:
  added: []
  patterns: [tdd-red-green, two-pass-vault-generation, wikilink-topology]
key_files:
  created:
    - tests/vault_integration.rs
    - tests/fixtures/scan_shared_cve.xml
  modified:
    - src/vault/templates.rs
    - src/vault/mod.rs
    - src/main.rs
    - src/cli.rs
decisions:
  - "severity_breakdown computed from CVE map (not per-host); counts distinct CVE notes per severity level"
  - "critical_findings filtered from cve_map where severity == Critical, sorted by CVE ID for deterministic output"
  - "Integration test uses hand-crafted ScanResult (not XML parsing) to avoid real API calls"
metrics:
  duration: "4 minutes"
  completed: "2026-03-24"
  tasks: 2
  files: 6
---

# Phase 3 Plan 3: Index Pages, CLI Wiring, and Integration Tests Summary

Index pages (global + per-scan), --vault CLI wiring, and end-to-end integration tests proving all 7 OUT requirements with shared-CVE fixture.

## What Was Built

### Task 1: Index Page Templates and generate_vault Integration (TDD)

Added two new public functions to `src/vault/templates.rs`:

- `render_global_index_body` — Produces `_index.md` at vault root with title, summary count table (hosts/services/CVEs), severity breakdown table, critical findings section with CVE wikilinks, scans list, and hosts list with severity.
- `render_scan_index_body` — Produces per-scan `_index.md` with scan title, source filename, count line, severity breakdown table, and hosts list.

Updated `generate_vault` in `src/vault/mod.rs` to:
- Compute `severity_breakdown` from CVE map (counts distinct CVEs per severity level, ordered critical→high→medium→low→none)
- Compute `critical_findings` (CVEs with Critical severity, sorted by ID, each with affected service wikilinks)
- Compute `host_entries` (ip + highest_severity per host)
- Write `_index.md` at vault root
- Write `scans/{scan_label}/_index.md`

### Task 2: CLI Wiring and Integration Tests

**src/cli.rs:** Removed `hide = true` from `--vault` flag, updated help text to `"Generate Obsidian vault at specified directory"`.

**src/main.rs:** Added vault branch in `run()` — when `--vault` is provided, calls `vault::derive_scan_label` and `vault::generate_vault`, prints stats to stderr, returns early (skips tree rendering).

**tests/fixtures/scan_shared_cve.xml:** Minimal nmap XML with 1 host (192.168.1.1), 2 ports (22/ssh OpenSSH 7.4, 80/http Apache httpd 2.4.49), to be used as reference for shared-CVE scenario.

**tests/vault_integration.rs:** 5 integration tests covering all 7 OUT requirements:
- `vault_generates_complete_directory_structure` — OUT-02 hierarchy, OUT-06 shared CVEs, OUT-07 graph config, index pages, stats
- `vault_cve_note_lists_all_affected_services` — OUT-06 shared CVE dedup
- `vault_frontmatter_is_valid_yaml` — OUT-03 YAML frontmatter, OUT-04 severity tags
- `vault_service_notes_contain_wikilinks` — OUT-01 wikilinks
- `vault_graph_json_has_color_groups` — OUT-07 graph coloring

## Test Results

- 53 vault unit tests pass (templates + mod)
- 5 vault integration tests pass
- Full test suite: 170 tests, 0 failed

## Deviations from Plan

None — plan executed exactly as written. The TDD cycle was followed: failing tests written first (RED), then implementation (GREEN). All acceptance criteria met.

## Known Stubs

None. All generated content is wired to real data from ScanResult.

## Self-Check: PASSED

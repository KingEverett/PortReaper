---
phase: 05-config-polish-and-incremental-updates
plan: "02"
subsystem: vault
tags: [vault, merge, incremental, score-history, stale-tags, serde_yml]
dependency_graph:
  requires: []
  provides: [merge::merge_write_note, merge::merge_write_cve_note, merge::apply_stale_tags, merge::find_existing_scan_folder, vault::find_merge_target]
  affects: [src/vault/mod.rs, src/vault/merge.rs]
tech_stack:
  added: []
  patterns: [serde_yml for YAML mutation, merge-aware write pattern, stale tag detection via serde_yml round-trip]
key_files:
  created:
    - src/vault/merge.rs
  modified:
    - src/vault/mod.rs
decisions:
  - "serde_yml used for apply_stale_tags to avoid regex-based YAML mutation — required by RESEARCH.md"
  - "build_score_history_section checks last row score before appending to prevent duplicate entries on re-run"
  - "writer::write_note retained for non-note files (graph.json, CSS, _index.md) that have no Notes section to preserve"
  - "find_existing_scan_folder uses _index.md mtime for most-recently-modified tiebreak among multiple matching scan folders"
metrics:
  duration: "4 minutes"
  completed: "2026-03-24T21:40:48Z"
  tasks: 2
  files: 2
---

# Phase 05 Plan 02: Incremental Vault Merging Summary

Incremental merge module using merge_write_note/merge_write_cve_note to preserve user Notes across re-runs, serde_yml stale tagging for disappeared services, and CVE Score History tracking with dedup invariant.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create vault merge module | 6716bc3 | src/vault/merge.rs (created), src/vault/mod.rs (pub mod merge) |
| 2 | Integrate merge into generate_vault and export find_merge_target | 4e9e023 | src/vault/mod.rs |

## What Was Built

### src/vault/merge.rs (new)

Seven public functions implementing the incremental merge layer:

- `extract_notes_tail(content)` — Extracts `## Notes\n` section and everything after it from a note. Handles both leading-newline and start-of-string variants.
- `merge_write_note(vault_root, path, new_content)` — Writes a note while preserving existing Notes section from prior runs. Replaces template's empty Notes block with user-written content.
- `extract_score_history(content)` — Parses `## Score History` table from CVE note into Vec of `(date, score, severity, version)` tuples.
- `build_score_history_section(existing_rows, score, severity, version, today)` — Builds Score History markdown section. Only appends a new row when score differs from latest entry (dedup invariant).
- `merge_write_cve_note(...)` — CVE-specific merge write: preserves Notes AND inserts/updates Score History section between `## References` and `## Notes`.
- `apply_stale_tags(vault_root, pre_existing, regenerated)` — Adds `not-seen-in-latest` tag to service notes not regenerated in current run. Uses `serde_yml::from_str`/`serde_yml::to_string` for correct YAML frontmatter mutation.
- `find_existing_scan_folder(vault_root, new_ips)` — Searches `scans/` subfolders for IP overlap against current scan IPs. Returns most recently modified match (by `_index.md` mtime).

### src/vault/mod.rs (updated)

- Added `pub mod merge;` registration
- `generate_vault` updated to use merge-aware writes for all host, service, tech, and CVE notes
- Pre-existing service paths collected before pass 2; regenerated paths tracked during write loop
- `apply_stale_tags` called after pass 2 to mark disappeared services
- `pub fn find_merge_target(vault_path, scan)` exported for main.rs use in Plan 01 Task 2

## Test Results

- `cargo test vault::merge::tests` — 22 tests pass
- `cargo test vault::` — 75 tests pass (existing vault tests unchanged)
- `cargo test` — full suite (179+ tests) all pass

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed Rust 2024 edition match ergonomics error in apply_stale_tags**
- **Found during:** Task 1 first compilation
- **Issue:** `if let serde_yml::Value::Sequence(ref mut seq) = tags_entry` — Rust 2024 edition disallows `ref mut` binding modifier when default binding mode is already `ref mut` due to pattern matching on `&mut _` type
- **Fix:** Removed redundant `ref mut` — changed to `if let serde_yml::Value::Sequence(seq) = tags_entry`
- **Files modified:** src/vault/merge.rs line 260
- **Commit:** 6716bc3 (included in Task 1 commit)

## Self-Check: PASSED

- FOUND: src/vault/merge.rs
- FOUND: src/vault/mod.rs
- FOUND: commit 6716bc3
- FOUND: commit 4e9e023

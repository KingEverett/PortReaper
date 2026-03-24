---
phase: 03-obsidian-vault-output
verified: 2026-03-24T00:00:00Z
status: passed
score: 7/7 requirements verified
re_verification: false
human_verification:
  - test: "Open vault in Obsidian and inspect graph view topology"
    expected: "Hub-and-spoke topology — IP address nodes link to service nodes, service nodes link to CVE nodes; a CVE shared by two services appears as one node linked to both"
    why_human: "Graph topology and CSS-driven node coloring cannot be verified without running Obsidian; integration tests confirm the .obsidian/graph.json and severity tags are structurally correct but visual rendering requires a human"
  - test: "Verify CSS snippet activates severity colors in Obsidian Appearance settings"
    expected: "Enabling severity-colors snippet causes node color changes matching the 7 defined colorGroups"
    why_human: "CSS snippet content and install instructions are verified programmatically; whether Obsidian accepts and applies them requires human observation"
---

# Phase 3: Obsidian Vault Output Verification Report

**Phase Goal:** Users can open the generated Obsidian vault immediately after a scan and navigate a complete, severity-colored knowledge graph linking hosts, services, and shared CVE notes via wikilinks
**Verified:** 2026-03-24
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Hub-and-spoke graph topology with wikilinks between hosts, services, and CVEs | VERIFIED | `templates.rs`: `host_wikilink`, `service_wikilink`, `cve_wikilink`, `tech_wikilink` all produce `[[...]]` syntax. Integration test `vault_service_notes_contain_wikilinks` asserts `[[192.168.1.1]]`, `[[CVE-2023-38408]]`, `[[OpenSSH]]` in service note |
| 2 | YAML frontmatter valid including YAML-special characters in field values | VERIFIED | `frontmatter.rs` uses `serde_yml::to_string()` exclusively — no `format!` for YAML values. Unit test `frontmatter_with_yaml_special_chars_serializes_safely` covers colons/quotes/hashes. Integration test `vault_frontmatter_is_valid_yaml` asserts `---\n` delimiters |
| 3 | Graph view colors nodes by severity using bundled CSS snippet and graph.json colorGroups | VERIFIED | `graph_config.rs`: `generate_graph_json()` emits 7 colorGroups with correct tag queries and pre-computed RGB values. `generate_css_snippet()` includes installation instructions. Integration test `vault_graph_json_has_color_groups` asserts all 7 tag queries present |
| 4 | `_index.md` provides at-a-glance attack surface summary (global + per-scan) | VERIFIED | `templates.rs`: `render_global_index_body` produces `# PortReaper Vault` with count table, severity breakdown, critical findings, and hosts list. `render_scan_index_body` produces per-scan index. `generate_vault` writes both `_index.md` and `scans/{label}/_index.md`. Unit tests cover all sections. Integration test `vault_generates_complete_directory_structure` asserts both files exist |
| 5 | Filenames with IP addresses and special characters are filesystem-safe and resolve as wikilinks | VERIFIED | All filename construction routes through `sanitize_filename()` from `util::filename`. `derive_scan_label` sanitizes source path. `mod.rs` line 254: `sanitize_filename(&host.ip)`. Unit test `derive_scan_label_sanitizes_slashes` asserts no `/` in output |
| 6 | Shared CVE appears as one note linked from both affected services | VERIFIED | Two-pass `generate_vault`: `CveAccumulator.affected_services` collects wikilinks from all services before any file writes. Integration test `vault_cve_note_lists_all_affected_services` asserts `CVE-2023-38408.md` references both `192.168.1.1_22_tcp` and `192.168.1.1_80_tcp`. Unit test `generate_vault_shared_cve_appears_as_one_note_with_two_affected_services` verifies dedup with `stats.cves == 1` |
| 7 | `portreaper --vault ./output scan.xml` generates a complete vault directory | VERIFIED | `cli.rs`: `vault: Option<PathBuf>` field has no `hide = true`, help text is `"Generate Obsidian vault at specified directory"`. `main.rs` lines 61-71: vault branch calls `vault::derive_scan_label` and `vault::generate_vault`, prints stats to stderr, returns early |

**Score:** 7/7 truths verified

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/vault/mod.rs` | Vault module root, VaultError, VaultStats, derive_scan_label, two-pass generate_vault | VERIFIED | 424 lines; contains `CveAccumulator`, `TechAccumulator`, `highest_severity`, full `generate_vault` writing all 6 path types, 14 unit tests |
| `src/vault/writer.rs` | `write_note()` and `ensure_dir()` file helpers | VERIFIED | `write_note()` creates parent directories via `fs::create_dir_all`, wraps errors in `VaultError::DirError`/`WriteError`. 2 unit tests |
| `src/vault/frontmatter.rs` | `HostFrontmatter`, `ServiceFrontmatter`, `CveFrontmatter`, `TechFrontmatter` serde structs and `render_note()` | VERIFIED | All 4 structs present with correct `skip_serializing_if` annotations. `render_note()` uses `serde_yml::to_string()`. 5 unit tests |
| `src/vault/graph_config.rs` | `generate_graph_json()` and `generate_css_snippet()` | VERIFIED | 7 colorGroups with pre-computed RGB integers, `tag:#critical` through `tag:#technology`. CSS snippet includes `.obsidian/snippets/` installation path. 5 unit tests |
| `src/vault/templates.rs` | `render_host_body`, `render_service_body`, `render_cve_body`, `render_tech_body`, `render_global_index_body`, `render_scan_index_body` | VERIFIED | All 6 render functions plus 4 wikilink helpers and `truncate_description`. Notes include `## Open Ports`, `## Vulnerabilities`, `## Affected Services`, `## Instances`, `## Known CVEs`, `## Notes` sections. 23 unit tests |
| `src/main.rs` | Vault generation branch when `--vault` flag provided | VERIFIED | Lines 61-71: `if let Some(vault_path) = &cli.vault` branch calls `vault::derive_scan_label` and `vault::generate_vault`, prints stats, returns early before tree rendering |
| `src/cli.rs` | `--vault` flag unhidden with correct help text | VERIFIED | `vault: Option<PathBuf>` field uses `#[arg(long)]` with no `hide = true`. Help text: `"Generate Obsidian vault at specified directory"` |
| `tests/vault_integration.rs` | 5 end-to-end integration tests covering all 7 OUT requirements | VERIFIED | `vault_generates_complete_directory_structure` (OUT-02, OUT-06, OUT-07, index pages), `vault_cve_note_lists_all_affected_services` (OUT-06), `vault_frontmatter_is_valid_yaml` (OUT-03, OUT-04), `vault_service_notes_contain_wikilinks` (OUT-01), `vault_graph_json_has_color_groups` (OUT-07) |
| `src/models.rs` | `Severity::obsidian_tag()` method | VERIFIED | Lines 90-99: returns lowercase `&'static str` for all 5 variants. 5 unit tests |
| `Cargo.toml` | `serde_yml = "0.0.12"` and `chrono = "0.4"` dependencies | VERIFIED | Both present in `[dependencies]` |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `src/vault/frontmatter.rs` | `serde_yml` | `serde_yml::to_string()` for all YAML serialization | WIRED | Line 54: `serde_yml::to_string(frontmatter)`. No `format!` macros produce YAML content |
| `src/vault/mod.rs` | `src/util/filename.rs` | `sanitize_filename()` for all vault filenames | WIRED | Line 10 import. Used at lines 254, 303-306, 335, 345, 351 for every path component |
| `src/vault/templates.rs` | `src/vault/frontmatter.rs` | `render_note()` called with frontmatter structs + body strings | WIRED | `mod.rs` calls `frontmatter::render_note(&fm, &body)?` for host (line 250), service (line 301), CVE (line 334), tech (line 349) notes |
| `src/vault/mod.rs` | `src/vault/writer.rs` | `write_note()` for all file creation | WIRED | `writer::write_note(vault_path, ...)` called for graph.json, CSS, host notes, service notes, CVE notes, tech notes, and both index files |
| `src/vault/templates.rs` | `src/util/filename.rs` | `sanitize_filename()` for wikilink filenames | WIRED | Line 2 import. Used in `host_wikilink`, `service_wikilink`, `cve_wikilink`, `tech_wikilink` |
| `src/main.rs` | `src/vault/mod.rs` | `vault::generate_vault()` called when `cli.vault` is `Some` | WIRED | Lines 62-70: `portreaper::vault::derive_scan_label` and `portreaper::vault::generate_vault` called inside `if let Some(vault_path) = &cli.vault` |
| `tests/vault_integration.rs` | `src/vault/mod.rs` | Integration tests call `generate_vault` and assert file tree | WIRED | `vault::generate_vault(&scan, &dir, scan_label)` called in all 5 tests with file existence assertions |
| `src/vault/templates.rs` | `src/vault/mod.rs` | Index renderers called from `generate_vault` pass 2 | WIRED | `mod.rs` lines 393, 405: `templates::render_global_index_body(...)` and `templates::render_scan_index_body(...)` |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| OUT-01 | 03-02, 03-03 | Generate Obsidian vault with `[[wikilinks]]` for native graph view | SATISFIED | `templates.rs` wikilink helpers produce `[[filename]]` and `[[filename\|display]]` syntax. Integration test `vault_service_notes_contain_wikilinks` confirms wikilinks in generated notes |
| OUT-02 | 03-02, 03-03 | Hierarchical node structure: Project → IP Addresses → Ports/Services | SATISFIED | `generate_vault` writes `scans/{label}/hosts/{ip}.md` and `scans/{label}/services/{ip}_{port}_{proto}.md`. Integration test asserts full path hierarchy |
| OUT-03 | 03-01, 03-03 | YAML frontmatter with severity, tags, and service metadata | SATISFIED | 4 typed frontmatter serde structs. `render_note()` wraps with `---` delimiters. Integration test `vault_frontmatter_is_valid_yaml` asserts `---\n` start/close delimiters |
| OUT-04 | 03-01, 03-03 | Severity classification (critical/high/medium/low) with Obsidian tags | SATISFIED | `Severity::obsidian_tag()` returns lowercase strings. Tags arrays include severity tag. Integration test asserts lowercase severity string in host note frontmatter |
| OUT-05 | 03-02 | Structured service note template (service info table, vulns, links) | SATISFIED | `render_service_body` produces host backlink, product tech wikilink, CPE code block, Vulnerabilities table (or "No vulnerabilities found."), `## Notes` section |
| OUT-06 | 03-02, 03-03 | Shared CVE notes (one note per CVE, linked from all affected services) | SATISFIED | `CveAccumulator` deduplicates CVEs across all services. `affected_services` collects all service wikilinks before writing. Integration test confirms 1 CVE note with 2 service references. `stats.cves == 2` (not 3) for 3 CVE-service occurrences |
| OUT-07 | 03-01, 03-03 | Obsidian CSS snippet for severity-based color-coding in graph view | SATISFIED | `graph_config.rs` generates `graph.json` with 7 colorGroups (severity + entity types) and CSS snippet with `.obsidian/snippets/` installation instructions. Integration test asserts all 7 tag queries in graph.json |

---

## Anti-Patterns Found

No blockers or substantive stub patterns found.

| File | Pattern | Severity | Assessment |
|------|---------|----------|------------|
| `src/vault/mod.rs` (original plan 01 stub) | `generate_vault` was initially a stub returning zeroed stats | N/A — resolved | Stub replaced in plan 02. Final implementation is 314 lines with full two-pass logic. No stub remains. |

Scanned all 6 vault module files, `main.rs`, `cli.rs`, and `tests/vault_integration.rs` for:
- `TODO/FIXME/HACK/PLACEHOLDER` — none found in vault code
- `return null` / `return {}` / `return []` — none
- Empty handlers — none
- Format macros used for YAML — none (serde_yml mandate upheld throughout)

---

## Test Results

| Test Suite | Pass | Fail |
|-----------|------|------|
| Library unit tests (all modules) | 122 | 0 |
| vault_integration.rs | 5 | 0 |
| greppable_parse.rs | 14 | 0 |
| text_parse.rs | 5 | 0 |
| xml_parse.rs | 9 | 0 |
| **Total** | **170** | **0** |

`cargo build` exits 0 (warnings only — unused struct fields in XML parser, pre-existing and unrelated to phase 3).

---

## Human Verification Required

### 1. Obsidian Graph View Topology

**Test:** Generate a vault from a real nmap scan with multiple hosts and shared CVEs. Open the vault directory in Obsidian. Open Graph View.
**Expected:** IP address nodes in the center link out to service nodes; service nodes link to CVE nodes; a CVE shared across two services appears as a single node with two incoming edges; severity-colored node groupings are visible (red for critical, orange for high, etc.)
**Why human:** The `[[wikilink]]` syntax, YAML tags, and `graph.json` colorGroups are all structurally correct per programmatic checks. Whether Obsidian actually renders the expected topology and applies the colors requires running the application and observing the visual output.

### 2. CSS Snippet Color Activation

**Test:** Copy `assets/severity-colors.css` to the vault's `.obsidian/snippets/` directory. In Obsidian, go to Settings → Appearance → CSS Snippets. Enable "severity-colors". Observe graph view node appearance.
**Expected:** Tag nodes change color per the `--graph-node-tag` CSS variable. Severity-grouped nodes display colors from the 7 colorGroups in `graph.json`.
**Why human:** The CSS content and install path in the snippet comment are verified. Whether Obsidian's CSS snippet system applies the variable to graph nodes requires visual confirmation.

---

## Roadmap Discrepancy (Non-blocking)

The `ROADMAP.md` file still shows Phase 3 as "2/3 plans executed / In Progress" with `03-03-PLAN.md` listed as unchecked. In practice, `03-03-SUMMARY.md` exists, all acceptance criteria from 03-03 are met in the codebase, and the full test suite passes. The ROADMAP was not updated after plan 03 execution. This is a documentation gap, not an implementation gap — the phase goal is fully achieved.

---

## Summary

Phase 3 goal is achieved. All 7 OUT requirements (OUT-01 through OUT-07) are satisfied with substantive implementation and test coverage. The vault generator produces a complete, interlinked Obsidian vault from enriched scan data:

- **OUT-01 (wikilinks):** Four wikilink helper functions generate `[[filename]]` and `[[filename|display]]` syntax throughout all note types
- **OUT-02 (hierarchy):** `scans/{label}/hosts/`, `scans/{label}/services/`, `cves/`, `technologies/` directory structure
- **OUT-03 (YAML frontmatter):** Four typed serde structs serialized via `serde_yml::to_string()` — YAML-special characters handled safely
- **OUT-04 (severity tags):** `Severity::obsidian_tag()` returns lowercase strings; tags arrays include severity tag in all frontmatter types
- **OUT-05 (service template):** Full service notes with host backlink, product tech wikilink, CPE code block, vulnerabilities table, Notes section
- **OUT-06 (shared CVE notes):** Two-pass accumulation ensures one CVE note per CVE ID with all affected services listed
- **OUT-07 (graph coloring):** `graph.json` with 7 colorGroups + CSS snippet with installation instructions

The `--vault` CLI flag is unhidden, wired to `generate_vault` in `main.rs`, and produces stats output. Five integration tests validate the end-to-end pipeline.

---

_Verified: 2026-03-24_
_Verifier: Claude (gsd-verifier)_

---
phase: 05-config-polish-and-incremental-updates
verified: 2026-03-24T22:15:00Z
status: passed
score: 12/12 must-haves verified
re_verification: false
---

# Phase 05: Config, Polish, and Incremental Updates — Verification Report

**Phase Goal:** Users can configure PortReaper via a config file with API keys and source preferences, and re-running against an updated scan merges new findings into an existing vault without overwriting prior notes.
**Verified:** 2026-03-24T22:15:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

#### Plan 01 Truths (ARCH-03)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | PortReaper reads `~/.config/portreaper/config.toml` automatically on startup when it exists | VERIFIED | `load_config()` at `src/config/mod.rs:69` reads path from `dirs::config_dir()`, called at `src/main.rs:39` before any other logic |
| 2 | Missing or malformed config file does not prevent PortReaper from running | VERIFIED | `load_config()` returns `PortReaperConfig::default()` on file-absent `Err(_)` and on `toml::de::Error`, only printing a warning to stderr |
| 3 | Env var `PORTREAPER_NVD_KEY` overrides config file `nvd_key` | VERIFIED | `src/main.rs:67-68`: `std::env::var("PORTREAPER_NVD_KEY").ok().or_else(|| cfg.api_keys.nvd_key.clone())` — env var wins |
| 4 | CLI flags override config file values | VERIFIED | Vault path: `cli.vault.as_ref().or(cfg.output.vault.as_ref())` (CLI first). Disabled sources: CLI list prepended before config sources. Concurrency: CLI quiet/fresh override config defaults |
| 5 | Elapsed time is printed to stderr after every run | VERIFIED | `src/main.rs:133` and `src/main.rs:145`: both exit paths print `Completed in {:.1}s` via `start.elapsed()` |
| 6 | Re-running against a vault with IP overlap merges into existing scan subfolder instead of creating a new one | VERIFIED | `src/main.rs:124-125`: `find_merge_target(vault_path, &result)` called before `derive_scan_label`, returning existing subfolder label when IP overlap found |

#### Plan 02 Truths (OUT-08)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 7 | Re-running PortReaper against same scan preserves user-written Notes sections in existing notes | VERIFIED | `merge_write_note()` reads existing file, calls `extract_notes_tail()` to save Notes block, replaces template's empty Notes with saved content before writing. Applied to host, service, and tech notes in `generate_vault`. |
| 8 | Services no longer in the new scan get a `not-seen-in-latest` tag in frontmatter | VERIFIED | `apply_stale_tags()` uses `serde_yml::from_str`/`serde_yml::to_string` to mutate YAML frontmatter; called after pass 2 in `generate_vault` with pre-existing vs regenerated path diff |
| 9 | CVE notes with changed CVSS scores show a Score History table with previous and current values | VERIFIED | `build_score_history_section()` and `merge_write_cve_note()` insert `## Score History` table between `## References` and `## Notes` when score changes |
| 10 | Re-running against a CVE whose CVSS score has not changed does not add a duplicate row to the Score History table | VERIFIED | `build_score_history_section()`: only appends new row when `rows.last().score != current_score_str` |
| 11 | Scan overlap detected by IP address overlap merges into existing scan subfolder | VERIFIED | `find_existing_scan_folder()` scans `vault/scans/*/hosts/*.md` filenames for IP overlap; `find_merge_target()` exported from `vault/mod.rs` and wired in `main.rs` |
| 12 | First-run vault generation works identically to current behavior | VERIFIED | `merge_write_note` creates file normally when path does not exist (no existing Notes to extract); `apply_stale_tags` skips when `pre_existing_services.is_empty()`; all 237 tests pass across all modules |

**Score:** 12/12 truths verified

---

## Required Artifacts

### Plan 01 Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/config/mod.rs` | `PortReaperConfig` struct, `load_config()`, `config_path()` | VERIFIED | All three public functions present, struct with four sub-configs, serde defaults on all fields |
| `Cargo.toml` | `toml = "1"` dependency | VERIFIED | Line 22: `toml = "1"` |

### Plan 02 Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/vault/merge.rs` | `extract_notes_tail`, `merge_write_note`, `apply_stale_tags`, `extract_score_history`, `append_score_history`, `find_existing_scan_folder` | VERIFIED | All seven public functions present (plan named six, impl ships seven including `build_score_history_section` and `merge_write_cve_note`) |
| `src/vault/mod.rs` | `generate_vault` with merge support, `find_merge_target()` | VERIFIED | `merge::merge_write_note` used for host/service/tech notes, `merge::merge_write_cve_note` for CVE notes, `apply_stale_tags` called post-pass-2, `find_merge_target` exported at line 471 |

---

## Key Link Verification

### Plan 01 Key Links

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `src/main.rs` | `src/config/mod.rs` | `portreaper::config::load_config()` | WIRED | `main.rs:39`: `let cfg = portreaper::config::load_config();` — first statement in `run()` |
| `src/main.rs` | `src/enrichment/mod.rs` | `EnrichmentOptions` built from config + CLI | WIRED | `main.rs:49-66`: `EnrichmentOptions { concurrency: cfg.enrichment.concurrency, cache_ttl_secs: (cfg.enrichment.cache_ttl_days as i64) * 86400, ... }` |
| `src/main.rs` | `src/vault/mod.rs` | `find_merge_target` called before `derive_scan_label` | WIRED | `main.rs:124-125`: `portreaper::vault::find_merge_target(vault_path, &result).unwrap_or_else(|| portreaper::vault::derive_scan_label(...))` |

### Plan 02 Key Links

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `src/vault/mod.rs` | `src/vault/merge.rs` | `merge::merge_write_note` replaces `writer::write_note` | WIRED | Lines 282, 334, 387 in `generate_vault`: host notes, service notes, tech notes all use `merge::merge_write_note` |
| `src/vault/mod.rs` | `src/vault/merge.rs` | `merge::apply_stale_tags` called after pass 2 | WIRED | Lines 391-392: `if !pre_existing_services.is_empty() { merge::apply_stale_tags(...) }` |
| `src/vault/mod.rs` | `src/vault/merge.rs` | `find_merge_target` delegates to `merge::find_existing_scan_folder` | WIRED | Line 471-473: `pub fn find_merge_target` calls `merge::find_existing_scan_folder(vault_path, &ips)` |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| ARCH-03 | 05-01 | Config file for default sources, API keys, output paths | SATISFIED | `src/config/mod.rs` with `PortReaperConfig` struct covering `SourcesConfig`, `ApiKeysConfig`, `OutputConfig`, `EnrichmentConfig`; wired in `main.rs` |
| OUT-08 | 05-02 | Incremental vault updates (merge new scan data into existing vault) | SATISFIED | `src/vault/merge.rs` with Notes preservation, Score History, stale tagging, and scan-overlap detection; integrated into `generate_vault` |

No orphaned requirements detected. Both requirement IDs declared in plan frontmatter are fully implemented and satisfied by verified artifacts.

---

## Anti-Patterns Found

No blockers or stubs detected.

| File | Pattern | Severity | Assessment |
|------|---------|----------|------------|
| `src/enrichment/mod.rs:54` | `cache_ttl_secs: 604800` | Info | Default value assignment, not a stub — overridden by config via `(cfg.enrichment.cache_ttl_days as i64) * 86400` in `main.rs` |
| Build output | 4 pre-existing `unused import`/`unused variable` warnings | Info | Pre-existing, not introduced by phase 05. No functional impact. |

---

## Test Results

| Suite | Result | Tests |
|-------|--------|-------|
| `cargo test` (all modules) | PASSED | 237 total across 8 test binaries — 0 failed |
| `cargo build` | PASSED | Compiles clean (pre-existing unused-import warnings only) |
| Config unit tests | PASSED | Included in the 189-test portreaper lib suite |
| Vault merge tests | PASSED | 22 merge tests pass (included in vault suite) |
| Vault integration tests | PASSED | 14 vault tests pass |

---

## Human Verification Required

### 1. Config file round-trip on live system

**Test:** Create `~/.config/portreaper/config.toml` with `[api_keys]\nnvd_key = "test-key"`, then run `portreaper <scan>` and confirm the key hint message appears and the NVD source uses the key.
**Expected:** stderr prints `Tip: API keys can also be set via env vars (PORTREAPER_NVD_KEY) to avoid storing in plaintext.`
**Why human:** Config file path is system-dependent (`dirs::config_dir()`); unit tests use `parse_config()` directly and do not exercise the filesystem path.

### 2. Notes preservation across real re-runs

**Test:** Run PortReaper to generate a vault, hand-edit a Notes section in one service note, re-run against the same scan, and confirm the hand-edited Notes section is unchanged.
**Expected:** User-written Notes section survives the re-run intact.
**Why human:** The merge logic depends on the actual file path, vault structure, and live file I/O that tempdir-based unit tests approximate but cannot fully replicate against a real run.

### 3. Elapsed time user experience

**Test:** Run PortReaper against a real scan file and confirm the elapsed time line appears at the end of stderr output.
**Expected:** `Completed in X.Xs` appears on stderr regardless of whether enrichment succeeds or fails.
**Why human:** Both code paths (with vault and without vault) include the print statement, but actual user-visible output verification requires a real run.

---

## Gaps Summary

No gaps. All 12 observable truths verified, all artifacts substantive and wired, all key links confirmed in the codebase. Both requirement IDs (ARCH-03, OUT-08) are fully satisfied. 237 tests pass with 0 failures.

---

_Verified: 2026-03-24T22:15:00Z_
_Verifier: Claude (gsd-verifier)_

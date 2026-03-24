---
phase: 05-config-polish-and-incremental-updates
plan: "01"
subsystem: config
tags: [config, toml, enrichment, vault, merge-detection]
dependency_graph:
  requires: ["05-02"]
  provides: [portreaper::config, PortReaperConfig, load_config, config_path, parse_config]
  affects: [src/main.rs, src/enrichment/mod.rs]
tech_stack:
  added: [toml = "1"]
  patterns: [serde-defaults, config-file-load-with-fallback, priority-merge-env-config-default]
key_files:
  created: [src/config/mod.rs]
  modified: [Cargo.toml, src/lib.rs, src/main.rs, src/enrichment/mod.rs]
decisions:
  - "load_config() never fails startup — warns to stderr and returns defaults on malformed TOML (D-07)"
  - "env var PORTREAPER_NVD_KEY > config nvd_key > None priority chain (D-05)"
  - "cache_ttl_secs plumbed through EnrichmentOptions to avoid global state"
  - "find_merge_target called before derive_scan_label — scan label resolution is now overlap-aware"
metrics:
  duration: "4m"
  completed: "2026-03-24T21:46:35Z"
  tasks_completed: 2
  files_changed: 5
---

# Phase 05 Plan 01: Config Module and Main.rs Wiring Summary

TOML config file support with priority merge (CLI > env > config > default), elapsed time reporting, configurable cache TTL, and scan-overlap merge detection wired into vault path.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create config module with PortReaperConfig and load_config() | 5a9f726 | Cargo.toml, src/config/mod.rs, src/lib.rs |
| 2 | Wire config into main.rs with priority merge, elapsed time, and merge detection | cf65dcd | src/main.rs, src/enrichment/mod.rs |

## What Was Built

### Task 1: Config Module

`src/config/mod.rs` provides:
- `PortReaperConfig` struct with four sub-configs: `SourcesConfig`, `ApiKeysConfig`, `OutputConfig`, `EnrichmentConfig`
- `load_config()` — reads `~/.config/portreaper/config.toml`, returns defaults if absent, warns and falls back on malformed TOML
- `config_path()` — returns OS-appropriate path via `dirs::config_dir()`
- `parse_config(str)` — direct TOML string parsing, used by tests and load_config
- Serde defaults: all sources enabled, concurrency=5, cache_ttl_days=7, nvd_key=None, vault=None

### Task 2: Main.rs Wiring

`src/main.rs` now:
- Calls `load_config()` at top of `run()` before any other logic
- Prints API key hint (D-06) when config has nvd_key
- Builds `EnrichmentOptions.concurrency` from `cfg.enrichment.concurrency`
- Merges config-disabled + CLI-disabled sources (D-09)
- Resolves NVD key with env var > config priority (D-05)
- Resolves vault path with CLI > config priority
- Calls `find_merge_target(vault_path, &result)` before `derive_scan_label` (D-03)
- Prints elapsed time at end of every run path (D-12)

`src/enrichment/mod.rs` gains:
- `cache_ttl_secs: i64` field in `EnrichmentOptions` (default 604800)
- NVD and OSV cache reads use `opts.cache_ttl_secs` instead of `cache::DEFAULT_TTL_SECS`

## Verification

- `cargo build` exits 0 (only pre-existing warnings)
- `cargo test` exits 0 — 247 tests pass across all modules
- All config unit tests (15) pass
- All enrichment unit tests pass (including `enrichment_options_default_concurrency_5`)
- All vault integration tests pass

## Deviations from Plan

None — plan executed exactly as written. The `cache_ttl_secs` variable capture for the `tokio::spawn` closure required one extra `let ttl_secs = cache_ttl_secs;` binding (minor implementation detail within spec).

## Known Stubs

None.

## Self-Check: PASSED

Files confirmed present:
- src/config/mod.rs: exists
- src/main.rs: contains load_config(), find_merge_target, Completed in, PORTREAPER_NVD_KEY with or_else, cfg.enrichment.concurrency, cfg.sources.nvd, cfg.output.vault
- src/enrichment/mod.rs: contains pub cache_ttl_secs, opts.cache_ttl_secs replaced DEFAULT_TTL_SECS

Commits confirmed:
- 5a9f726: feat(05-01): add config module
- cf65dcd: feat(05-01): wire config into main.rs

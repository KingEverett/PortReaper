# Phase 5: Config, Polish, and Incremental Updates - Context

**Gathered:** 2026-03-24
**Status:** Ready for planning

<domain>
## Phase Boundary

TOML config file at OS-appropriate path for persistent settings (API keys, source preferences, concurrency, output defaults), incremental vault merging so re-scans update existing vaults without overwriting user content, and timing/progress polish. Users can configure PortReaper once and re-run against evolving targets with accumulating vault intelligence.

</domain>

<decisions>
## Implementation Decisions

### Incremental Vault Merge
- **D-01:** Regenerate all machine-generated sections (frontmatter, tables, wikilinks) but preserve user-editable "Notes" sections at the bottom of each note. Users know the Notes section is their space — everything above it is regenerated.
- **D-02:** When a port/service from a previous scan no longer appears in the new scan, keep its note but add a `#stale` or `#not-seen-in-latest` tag to frontmatter. Historical reference preserved, user can filter/clean up manually.
- **D-03:** Detect scan overlap by IP address overlap. If the new scan shares hosts with an existing scan subfolder, merge into that subfolder — new hosts added, existing hosts updated.
- **D-04:** When a CVE's CVSS score changes between runs, update the score AND add a "Score History" section in the CVE note showing previous values with dates. Tracks CVE maturity over time.

### API Key Management
- **D-05:** Resolution priority: env var > config file > built-in default. Standard Unix convention — `PORTREAPER_NVD_KEY` env var (Phase 2) keeps working and overrides config file value.
- **D-06:** If config file contains an API key, print a one-time stderr hint on first read: "Tip: API keys can also be set via env vars (PORTREAPER_NVD_KEY) to avoid storing in plaintext." Non-intrusive, educational.
- **D-07:** No auto-creation of config file. Tool runs with all built-in defaults when no config exists. User creates config only when they want to customize. Matches tools like rg, fd, bat.

### Config File Design (Claude's Discretion)
- **D-08:** Config at OS-appropriate path via `dirs` crate: `~/.config/portreaper/config.toml` on Linux. Read automatically on startup.
- **D-09:** Config controls: enabled sources, API keys (NVD key), concurrency cap, default output path, cache TTL. CLI flags override config values.
- **D-10:** Use `toml` crate for parsing. All fields optional with serde defaults matching current hardcoded values (concurrency=5, cache TTL=7 days, all sources enabled).

### Progress & Polish
- **D-11:** Keep existing inline status lines for progress: `[1/5] Querying NVD for OpenSSH 7.4... 3 CVEs`. No new dependency needed — already implemented in Phase 2.
- **D-12:** Add total elapsed time at end of run: "Completed in 12.4s" on stderr. Lightweight, useful for benchmarking cache vs fresh runs.

### Claude's Discretion
- Config struct design and serde deserialization approach
- How to detect and extract the Notes section during merge (regex, marker comment, or heading-based)
- Score History section formatting in CVE notes
- How to detect scan subfolder overlap (directory scan vs metadata file)
- Internal module organization for config loading
- Error handling for malformed config files (warn and use defaults vs fail)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project-level
- `.planning/PROJECT.md` — Vision, constraints (Rust, Obsidian output, pluggable sources)
- `.planning/REQUIREMENTS.md` — OUT-08 (incremental vault updates), ARCH-03 (config file) define this phase's scope
- `.planning/ROADMAP.md` — Phase 5 success criteria (2 criteria that must be TRUE)

### Prior phase context
- `.planning/phases/02-enrichment-core/02-CONTEXT.md` — D-07: NVD API key via env var, D-15: concurrency cap = 5
- `.planning/phases/03-obsidian-vault-output/03-CONTEXT.md` — D-01/D-02: vault folder structure, D-08 through D-17: note templates with Notes sections
- `.planning/phases/04-additional-sources-and-caching/04-CONTEXT.md` — D-09 through D-12: cache strategy (7-day TTL, ~/.cache/portreaper/), D-13/D-14: source selection defaults

### Key source files
- `src/cli.rs` — Clap CLI definition; config values currently hardcoded in `main.rs`
- `src/main.rs` — Hardcoded concurrency=5, env var NVD key, source construction — all config targets
- `src/enrichment/mod.rs` — `EnrichmentOptions` struct (concurrency, quiet, fresh, disabled_sources) — prime target for config-driven defaults
- `src/vault/writer.rs` — `write_note()` does unconditional `fs::write` — needs merge logic
- `src/vault/mod.rs` — `generate_vault()` and note generation — extend for incremental merge
- `src/vault/templates.rs` — Note body templates with "Notes" sections — merge must parse these
- `src/cache/mod.rs` — Cache module with XDG path support via `dirs` crate
- `Cargo.toml` — Already has `dirs`, `serde`, `serde_json`; needs `toml` crate added

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `dirs` crate already in Cargo.toml — use `dirs::config_dir()` for config path resolution
- `src/cache/mod.rs` — XDG cache path pattern can be mirrored for config path
- `src/enrichment/mod.rs` — `EnrichmentOptions` struct is the natural target for config-driven defaults
- `src/vault/writer.rs` — `write_note()` is the single write point; extend with merge-aware logic
- `serde` + derive already in use throughout — config deserialization follows same pattern

### Established Patterns
- All service fields are `Option<T>` — config fields should follow same pattern (all optional with defaults)
- `thiserror` for typed errors — add config error variants
- `dirs` crate for OS-appropriate paths (already used for cache)
- stderr for diagnostics, stdout for data output
- `ExitCode` from main() — never `process::exit()`

### Integration Points
- `src/main.rs`: Load config before CLI parsing, merge config defaults with CLI flags, pass to EnrichmentOptions
- `src/vault/writer.rs`: `write_note()` needs read-before-write logic for merge
- `src/vault/mod.rs`: `generate_vault()` needs to detect existing vault and switch to merge mode
- `src/vault/templates.rs`: CVE note template needs Score History section support
- `Cargo.toml`: Add `toml` crate for config parsing

</code_context>

<specifics>
## Specific Ideas

- Config file should feel like ripgrep's `.ripgreprc` or bat's `config` — minimal, optional, well-documented in --help
- Vault merge preserving Notes sections is the key user value — pentester annotations are sacred
- Score History in CVE notes adds intelligence over time: "this CVE was bumped from 7.5 to 9.8 after active exploitation was confirmed"
- Stale tag on disappeared services gives pentesters historical context without cluttering the active graph

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 05-config-polish-and-incremental-updates*
*Context gathered: 2026-03-24*

# Phase 5: Config, Polish, and Incremental Updates - Research

**Researched:** 2026-03-24
**Domain:** Rust TOML config deserialization, Markdown text merge, vault incremental update
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Incremental Vault Merge**
- D-01: Regenerate all machine-generated sections (frontmatter, tables, wikilinks) but preserve user-editable "Notes" sections at the bottom of each note. Users know the Notes section is their space — everything above it is regenerated.
- D-02: When a port/service from a previous scan no longer appears in the new scan, keep its note but add a `#stale` or `#not-seen-in-latest` tag to frontmatter. Historical reference preserved, user can filter/clean up manually.
- D-03: Detect scan overlap by IP address overlap. If the new scan shares hosts with an existing scan subfolder, merge into that subfolder — new hosts added, existing hosts updated.
- D-04: When a CVE's CVSS score changes between runs, update the score AND add a "Score History" section in the CVE note showing previous values with dates. Tracks CVE maturity over time.

**API Key Management**
- D-05: Resolution priority: env var > config file > built-in default. Standard Unix convention — `PORTREAPER_NVD_KEY` env var (Phase 2) keeps working and overrides config file value.
- D-06: If config file contains an API key, print a one-time stderr hint on first read: "Tip: API keys can also be set via env vars (PORTREAPER_NVD_KEY) to avoid storing in plaintext." Non-intrusive, educational.
- D-07: No auto-creation of config file. Tool runs with all built-in defaults when no config exists. User creates config only when they want to customize. Matches tools like rg, fd, bat.

**Config File Design**
- D-08: Config at OS-appropriate path via `dirs` crate: `~/.config/portreaper/config.toml` on Linux. Read automatically on startup.
- D-09: Config controls: enabled sources, API keys (NVD key), concurrency cap, default output path, cache TTL. CLI flags override config values.
- D-10: Use `toml` crate for parsing. All fields optional with serde defaults matching current hardcoded values (concurrency=5, cache TTL=7 days, all sources enabled).

**Progress & Polish**
- D-11: Keep existing inline status lines for progress: `[1/5] Querying NVD for OpenSSH 7.4... 3 CVEs`. No new dependency needed — already implemented in Phase 2.
- D-12: Add total elapsed time at end of run: "Completed in 12.4s" on stderr. Lightweight, useful for benchmarking cache vs fresh runs.

### Claude's Discretion
- Config struct design and serde deserialization approach
- How to detect and extract the Notes section during merge (regex, marker comment, or heading-based)
- Score History section formatting in CVE notes
- How to detect scan subfolder overlap (directory scan vs metadata file)
- Internal module organization for config loading
- Error handling for malformed config files (warn and use defaults vs fail)

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| OUT-08 | Incremental vault updates (merge new scan data into existing vault) | D-01 through D-04 define merge semantics; Notes-section extraction and stale-tag patterns documented below |
| ARCH-03 | Config file for default sources, API keys, output paths | D-08 through D-10 define config design; `toml` + `serde` patterns documented below; `dirs` already in Cargo.toml |
</phase_requirements>

---

## Summary

Phase 5 has two independent deliverables: (1) a TOML config file that sets persistent defaults read on startup, and (2) incremental vault merging so re-scans update existing vaults without destroying user-added notes. Both are well-bounded and rest on foundations already in the codebase.

**Config** is straightforward: add the `toml = "1.0"` crate, create `src/config/mod.rs` with a `PortReaperConfig` struct using `#[serde(default)]` on every field, read via `dirs::config_dir().join("portreaper/config.toml")` at startup, and merge config values into `EnrichmentOptions` before CLI overrides are applied. The `dirs` crate is already present in `Cargo.toml` (v6.0.0). The `serde` derive feature is already in use project-wide.

**Incremental merge** requires one design insight: every generated note ends with `## Notes\n\n` (verified across all four template functions in `templates.rs`). The merge algorithm is: if a file already exists, read it, extract everything from `## Notes` onward, regenerate the machine content, and append the saved Notes tail. For CVE notes that need Score History: additionally extract any `## Score History` block before `## Notes`. The single write point is `writer::write_note()` — add a `merge_write_note()` variant alongside it.

**Primary recommendation:** Implement config as `src/config/mod.rs`, vault merge as `src/vault/merge.rs`, and wire them together in `main.rs` before CLI flag processing.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| toml | 1.0 (current: 1.1.0+spec-1.1.0) | TOML config file parsing | Official TOML crate; `toml::from_str::<T>()` integrates directly with serde Deserialize |
| serde (derive) | 1.0.228 (already in Cargo.toml) | Config struct deserialization | Already used project-wide; `#[serde(default)]` handles all-optional config cleanly |
| dirs | 6.0.0 (already in Cargo.toml) | OS-appropriate config path | Already used for cache path; `dirs::config_dir()` returns `~/.config` on Linux |
| std::time::Instant | stdlib | Elapsed time measurement | No dep needed; `Instant::now()` / `.elapsed()` is the standard pattern |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| regex | 1.12.3 (already in Cargo.toml) | Notes section extraction from existing files | Use for the `## Notes` boundary detection in merge logic |

**Installation (new dependency only):**
```bash
cargo add toml@1.0
```

**Version verification (2026-03-24):** `cargo search toml --limit 1` confirmed current published version is `1.1.0+spec-1.1.0`. Use `toml = "1"` (major version constraint) in Cargo.toml to pick up point releases automatically.

---

## Architecture Patterns

### Config Module Location
```
src/
├── config/
│   └── mod.rs          # PortReaperConfig struct + load_config()
├── vault/
│   ├── merge.rs         # NEW: merge_write_note() + extract_notes_tail()
│   ├── writer.rs        # EXISTING: write_note() stays unchanged
│   └── ...
├── main.rs              # Wire: load config, build opts, then parse CLI
└── cli.rs               # Unchanged
```

### Pattern 1: All-Optional Config Struct with serde defaults

Every field uses `Option<T>` or has a `#[serde(default = "fn")]` attribute. Missing TOML keys produce the same hardcoded defaults the tool uses today. The struct is never written back — it is read-only.

```rust
// Source: https://docs.rs/toml/latest/toml/ + https://serde.rs/attr-default.html
use serde::Deserialize;

fn default_concurrency() -> usize { 5 }
fn default_cache_ttl_days() -> u64 { 7 }

#[derive(Debug, Deserialize, Default)]
pub struct PortReaperConfig {
    #[serde(default)]
    pub sources: SourcesConfig,
    #[serde(default)]
    pub api_keys: ApiKeysConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub enrichment: EnrichmentConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct SourcesConfig {
    #[serde(default = "default_true")]
    pub nvd: bool,
    #[serde(default = "default_true")]
    pub cveorg: bool,
    #[serde(default = "default_true")]
    pub osv: bool,
    #[serde(default = "default_true")]
    pub searchsploit: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Deserialize, Default)]
pub struct ApiKeysConfig {
    pub nvd_key: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OutputConfig {
    pub vault: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct EnrichmentConfig {
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_cache_ttl_days")]
    pub cache_ttl_days: u64,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self { concurrency: 5, cache_ttl_days: 7 }
    }
}
```

### Pattern 2: Config Loading Function

```rust
// src/config/mod.rs
use std::path::PathBuf;

pub fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("portreaper").join("config.toml"))
}

/// Load config from OS-appropriate path. Returns Default if file absent.
/// Warns to stderr on parse errors and falls back to defaults (never fails startup).
pub fn load_config() -> PortReaperConfig {
    let Some(path) = config_path() else {
        return PortReakerConfig::default();
    };
    let Ok(content) = std::fs::read_to_string(&path) else {
        return PortReaperConfig::default();
    };
    match toml::from_str::<PortReaperConfig>(&content) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("warning: config file {} could not be parsed: {} — using defaults", path.display(), e);
            PortReaperConfig::default()
        }
    }
}
```

**Error handling decision (Claude's Discretion):** Warn and use defaults. A malformed config must not prevent the tool from running — pentesters run this mid-engagement.

### Pattern 3: Priority Merge in main.rs

Load config first, then CLI args override config-derived values:

```rust
// src/main.rs — before CLI flag processing
let cfg = portreaper::config::load_config();

// D-06: hint if config file has an API key
if cfg.api_keys.nvd_key.is_some() {
    eprintln!("Tip: API keys can also be set via env vars (PORTREAPER_NVD_KEY) to avoid storing in plaintext.");
}

// D-05: resolution priority: env var > config file > built-in default
let nvd_key = std::env::var("PORTREAPER_NVD_KEY").ok()
    .or_else(|| cfg.api_keys.nvd_key.clone());

// Config sets default concurrency; CLI --concurrency flag (if added) would override
let concurrency = cfg.enrichment.concurrency; // later: cli.concurrency.unwrap_or(cfg.enrichment.concurrency)

// Build disabled_sources: union of config-disabled and CLI-disabled
let mut disabled = cli.disable_sources.iter().map(|s| s.to_lowercase()).collect::<Vec<_>>();
if !cfg.sources.nvd { disabled.push("nvd".to_string()); }
// ... etc
```

### Pattern 4: Notes Section Extraction for Merge

Every note template ends with `## Notes\n\n` (verified in `templates.rs` lines 107, 212, 267, 302). The Notes section is always the last heading in the document body. Extraction algorithm:

```rust
// src/vault/merge.rs
const NOTES_MARKER: &str = "\n## Notes\n";

/// Extract the Notes tail from an existing note for preservation during merge.
/// Returns everything from "## Notes" onward, or None if marker not found.
pub fn extract_notes_tail(existing: &str) -> Option<&str> {
    existing.find(NOTES_MARKER).map(|pos| &existing[pos + 1..]) // +1 to skip leading \n
}

/// Write a note with merge: preserve existing Notes section if file exists.
pub fn merge_write_note(
    vault_root: &Path,
    relative_path: &str,
    new_content: &str,
) -> Result<(), VaultError> {
    let full_path = vault_root.join(relative_path);

    let notes_tail = if full_path.exists() {
        let existing = fs::read_to_string(&full_path).ok();
        existing.as_deref().and_then(extract_notes_tail).map(|s| s.to_string())
    } else {
        None
    };

    // Strip the template's empty Notes section and replace with preserved content
    let final_content = match notes_tail {
        Some(saved_tail) => {
            // Replace the trailing "## Notes\n\n" from new_content with saved tail
            if let Some(notes_pos) = new_content.find(NOTES_MARKER) {
                format!("{}\n{}", &new_content[..notes_pos], saved_tail)
            } else {
                new_content.to_string()
            }
        }
        None => new_content.to_string(),
    };

    writer::write_note(vault_root, relative_path, &final_content)
}
```

### Pattern 5: Score History in CVE Notes

CVE notes have an additional section to handle: `## Score History`. This section must be extracted from existing notes and merged into the regenerated content. The Score History section, if present, lives between `## References` and `## Notes`.

Approach: Extract Score History block from existing file before regenerating. When score changes, append a new entry. Template the section as plain Markdown:

```
## Score History

| Date | Score | Severity | CVSS Version |
|------|-------|----------|--------------|
| 2026-01-15 | 7.5 | high | 3.1 |
| 2026-03-24 | 9.8 | critical | 3.1 |
```

Extraction: Find `\n## Score History\n` in existing content; extract until next `\n## ` heading or end of note (before `## Notes`).

### Pattern 6: Stale Tag on Disappeared Services (D-02)

When running in merge mode against an existing scan subfolder (D-03), collect the set of port files that existed before the run. After the new run writes its files, any port file from the previous set that was NOT regenerated gets a frontmatter update:

- Read existing file
- Extract YAML frontmatter block (between first `---` and second `---`)
- Parse with `serde_yml`
- Add `"not-seen-in-latest"` to the `tags` array if not already present
- Update `highest_severity` to reflect stale state (or leave it — decision: leave severity, just add tag)
- Re-serialize frontmatter, reconstruct note

This is a post-pass operation: after all new notes are written, iterate the pre-existing port files, check which were not touched, apply stale tags.

### Pattern 7: Scan Subfolder Overlap Detection (D-03)

**Approach: directory scan of existing vault.** When `--vault path` is given and the vault root exists:

1. List all `scans/*/` subdirectories
2. For each existing scan subfolder, list all `hosts/*.md` files and extract the IP from the filename (reverse of `sanitize_filename`)
3. Compare IP set against IPs in the new scan
4. If intersection is non-empty → merge into that subfolder
5. If no overlap → create a new scan subfolder with fresh `derive_scan_label()`

The scan subfolder name is already the scan label. Merging into an existing subfolder means using THAT label (not a new one) when calling `generate_vault`.

**No metadata file needed.** The IP-from-filename approach is sufficient because `sanitize_filename` is deterministic and reversible for IP addresses (dots are preserved, IPs have no characters that get sanitized).

### Pattern 8: Elapsed Time (D-12)

```rust
// In main.rs run() function, before get_inputs():
let start = std::time::Instant::now();

// ... all processing ...

// At the very end before returning Ok(()):
eprintln!("Completed in {:.1}s", start.elapsed().as_secs_f64());
```

`std::time::Instant` is in stdlib. No dependency needed.

### Anti-Patterns to Avoid

- **Reading config with `format!` + manual TOML parsing:** Use `toml::from_str::<T>()` with serde. Manual parsing breaks on quoting edge cases.
- **Failing on missing config file:** Config is optional by design (D-07). Missing file = use defaults. Never `unwrap()` or `?` on config read.
- **Regex-based frontmatter parsing:** YAML frontmatter is bounded by `---` delimiters. Use `serde_yml::from_str` on the extracted YAML block rather than regex field matching. Regex on YAML breaks on multiline values.
- **Overwriting Notes on merge:** The entire point of the merge. Always extract and preserve Notes tail before any `fs::write`.
- **Printing the API key hint every run:** D-06 says "one-time stderr hint on first read" — this means once per invocation when config is loaded, not every time NVD is queried.
- **Using `process::exit()` in config error path:** Project convention is `ExitCode` from main. Config parse errors should warn + fallback, never exit.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| TOML parsing | Custom string parser | `toml::from_str::<T>()` | TOML has strings, arrays, tables, multiline — edge cases require proper parser |
| Config path location | Hardcoded `~/.config` string expansion | `dirs::config_dir()` | `$HOME` can differ from `~`; XDG_CONFIG_HOME override; already used for cache |
| YAML frontmatter regeneration | String manipulation / regex substitution | `serde_yml::to_string()` | Already the project standard; YAML special chars in CVE data will break manual formatting |
| serde default values | `Option<T>` + `.unwrap_or()` everywhere | `#[serde(default = "fn")]` | Cleaner; defaults stay co-located with field definitions |

**Key insight:** The "don't hand-roll" principle for TOML is the same reason `serde_yml` was mandated for YAML in Phase 3 — CVE descriptions contain characters that break naive formatters.

---

## Common Pitfalls

### Pitfall 1: Losing Notes on First Merge Run
**What goes wrong:** Code checks `if file exists { preserve notes }`. On first run the file is created fresh (no notes to preserve). On second run, the Notes section exists in the file and gets preserved correctly. Sounds fine — BUT if the merge path is taken when no Notes content exists (user hasn't written anything yet), extracting `## Notes\n\n` and preserving an empty string is correct behavior.
**Why it happens:** Off-by-one in the extraction: extracting `## Notes\n\n` as the tail and re-appending it results in `## Notes\n\n## Notes\n\n` if the template also emits it.
**How to avoid:** The merge function must STRIP the template's `## Notes` section and REPLACE it with the extracted tail (which includes the heading). If no existing tail: append the template's empty `## Notes\n\n` as usual.
**Warning signs:** Integration test shows double `## Notes` heading.

### Pitfall 2: Score History Accumulation Duplication
**What goes wrong:** On a third run (score unchanged), the code reads the existing Score History, sees the last entry has the same score as today, and adds a duplicate row.
**Why it happens:** No deduplication on (date, score) pairs.
**How to avoid:** Before appending a Score History row, check if the most recent entry already has the current score. If score is unchanged since last run, do not add a new row.
**Warning signs:** Score History table grows on every run even when score is stable.

### Pitfall 3: Scan Subfolder Overlap False Positive
**What goes wrong:** Vault has `scans/2026-01-01_scan_192.168.1.1/` with host `192.168.1.5`. New scan has `192.168.1.5`. Code detects overlap and merges into the January subfolder — but the new scan is a completely different engagement against the same IP.
**Why it happens:** IP overlap without date/context discrimination.
**How to avoid:** Overlap detection should match on both IP AND the scan subfolder's date proximity (same day or same explicit label). The cleanest approach: only merge into an existing subfolder when the user passes `--vault` to a path where that subfolder already has a `_index.md`. Present merge as opt-in via detection, or provide a `--fresh-scan` flag to force a new subfolder. Per D-03: "If the new scan shares hosts with an existing scan subfolder, merge into that subfolder" — this is the locked behavior; document it clearly in `--help`.
**Warning signs:** Unexpected old notes appearing in new scan output.

### Pitfall 4: Config File Default Output Path vs CLI --vault Flag
**What goes wrong:** `OutputConfig.vault` sets a default vault path. User also passes `--vault ./local`. CLI flag should win per D-05 (CLI overrides config) — but if code does `cli.vault.or(cfg.output.vault)`, the Option::or semantics are correct. The trap is doing this in the wrong order.
**Why it happens:** Wrong precedence: `cfg.output.vault.or(cli.vault)` instead of `cli.vault.or(cfg.output.vault)`.
**How to avoid:** Always apply config values first, then CLI overrides. In code: `let vault_path = cli.vault.as_ref().or(cfg.output.vault.as_ref())`.
**Warning signs:** `--vault` flag is ignored when config has an output path.

### Pitfall 5: toml::from_str Borrows Input String
**What goes wrong:** `toml::from_str::<T>(s)` has lifetime `'a` on the input — `T: Deserialize<'a>`. If `T` contains `&'a str` fields, the config struct borrows the input string. This creates lifetime issues if you try to return the config from `load_config()` while the string is dropped.
**Why it happens:** Serde zero-copy deserialization for string fields.
**How to avoid:** Use `String` (owned) for all string fields in `PortReaperConfig` (not `&str`). The struct is small; allocation cost is negligible for config loading.
**Warning signs:** Compiler error about lifetime of temporary value.

---

## Code Examples

Verified patterns from official sources:

### Config struct with nested sections and serde defaults
```rust
// Source: https://docs.rs/toml/latest/toml/ + https://serde.rs/attr-default.html
use serde::Deserialize;
use std::path::PathBuf;

fn default_concurrency() -> usize { 5 }
fn default_cache_ttl_days() -> u64 { 7 }
fn default_true() -> bool { true }

#[derive(Debug, Deserialize, Default)]
pub struct PortReaperConfig {
    #[serde(default)]
    pub sources: SourcesConfig,
    #[serde(default)]
    pub api_keys: ApiKeysConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub enrichment: EnrichmentConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct SourcesConfig {
    #[serde(default = "default_true")]
    pub nvd: bool,
    #[serde(default = "default_true")]
    pub cveorg: bool,
    #[serde(default = "default_true")]
    pub osv: bool,
    #[serde(default = "default_true")]
    pub searchsploit: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct ApiKeysConfig {
    pub nvd_key: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OutputConfig {
    pub vault: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
pub struct EnrichmentConfig {
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_cache_ttl_days")]
    pub cache_ttl_days: u64,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self { concurrency: default_concurrency(), cache_ttl_days: default_cache_ttl_days() }
    }
}
```

### Loading config with graceful fallback
```rust
// src/config/mod.rs
pub fn load_config() -> PortReaperConfig {
    let path = match dirs::config_dir() {
        Some(p) => p.join("portreaper").join("config.toml"),
        None => return PortReaperConfig::default(),
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return PortReaperConfig::default(), // file absent = use defaults
    };
    match toml::from_str::<PortReaperConfig>(&content) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("warning: {}: {} — using defaults", path.display(), e);
            PortReaperConfig::default()
        }
    }
}
```

### Notes tail extraction
```rust
// src/vault/merge.rs
const NOTES_HEADING: &str = "\n## Notes\n";

pub fn extract_notes_tail(content: &str) -> Option<String> {
    content.find(NOTES_HEADING)
        .map(|pos| content[pos + 1..].to_string()) // +1 skips the leading \n; keeps "## Notes\n..."
}
```

### Sample config.toml (user-facing documentation in --help)
```toml
# ~/.config/portreaper/config.toml
# All fields are optional. Omitted fields use built-in defaults.

[sources]
nvd = true
cveorg = true
osv = true
searchsploit = true

[api_keys]
nvd_key = "your-nvd-api-key-here"

[output]
vault = "/home/user/notes/pentest-vault"

[enrichment]
concurrency = 10
cache_ttl_days = 14
```

### Elapsed time
```rust
// main.rs
let start = std::time::Instant::now();
// ... run() ...
eprintln!("Completed in {:.1}s", start.elapsed().as_secs_f64());
```

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` + `#[tokio::test]` |
| Config file | none — inline `#[cfg(test)]` modules |
| Quick run command | `cargo test` |
| Full suite command | `cargo test` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| ARCH-03 | Config loads from TOML with all defaults when file absent | unit | `cargo test config::tests::load_config_returns_defaults_when_file_absent` | ❌ Wave 0 |
| ARCH-03 | Config parses all fields correctly from valid TOML | unit | `cargo test config::tests::load_config_parses_all_fields` | ❌ Wave 0 |
| ARCH-03 | Malformed config warns and falls back to defaults | unit | `cargo test config::tests::load_config_warns_on_parse_error` | ❌ Wave 0 |
| ARCH-03 | Env var overrides config file NVD key | unit | `cargo test config::tests::env_var_overrides_config_api_key` | ❌ Wave 0 |
| ARCH-03 | CLI --vault overrides config output.vault | unit | `cargo test` (in main integration) | ❌ Wave 0 |
| OUT-08 | Notes tail extracted correctly from existing note | unit | `cargo test vault::merge::tests::extract_notes_tail_basic` | ❌ Wave 0 |
| OUT-08 | merge_write_note preserves Notes content on second write | unit | `cargo test vault::merge::tests::merge_write_note_preserves_notes` | ❌ Wave 0 |
| OUT-08 | merge_write_note creates fresh note when file absent | unit | `cargo test vault::merge::tests::merge_write_note_fresh_file` | ❌ Wave 0 |
| OUT-08 | Stale tag added to port note not in new scan | unit | `cargo test vault::merge::tests::stale_tag_applied_to_missing_port` | ❌ Wave 0 |
| OUT-08 | Score History row appended when CVSS changes | unit | `cargo test vault::merge::tests::score_history_appended_on_change` | ❌ Wave 0 |
| OUT-08 | Score History not duplicated when score unchanged | unit | `cargo test vault::merge::tests::score_history_not_duplicated_on_same_score` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test`
- **Per wave merge:** `cargo test`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `src/config/mod.rs` with `#[cfg(test)]` block — covers ARCH-03 config tests
- [ ] `src/vault/merge.rs` with `#[cfg(test)]` block — covers OUT-08 merge tests
- [ ] No framework install needed — existing `#[test]` infrastructure sufficient

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Manual TOML string parsing | `toml::from_str::<T>()` with serde | toml 0.5+ | Struct-driven, handles all TOML types |
| `~/.configrc` flat files | XDG Base Directory spec (`$XDG_CONFIG_HOME`) | Common practice since ~2015 | `dirs::config_dir()` handles this automatically |
| Hardcoded defaults in binary | `#[serde(default = "fn")]` in config struct | serde 1.0+ | Defaults co-located with field definition, no separate "defaults" logic |

**Deprecated/outdated:**
- `toml` 0.5.x API: used `toml::Value` enum manipulation. Current 1.x API deserializes directly into typed structs via serde. Do not use the `Value` enum approach.
- Manual `$HOME` expansion: `std::env::var("HOME")` + string concat. `dirs::config_dir()` handles XDG, Windows, macOS correctly.

---

## Open Questions

1. **Cache TTL config plumbing**
   - What we know: `DEFAULT_TTL_SECS` is a constant in `src/cache/mod.rs` (604800). `read_cache()` takes `ttl_secs: i64` as a parameter. `enrich_scan()` passes it through.
   - What's unclear: Exactly where in the call chain to plumb the configurable TTL from `PortReaperConfig.enrichment.cache_ttl_days` → `enrich_scan()` → `read_cache()`. `EnrichmentOptions` does not currently have a `cache_ttl_secs` field.
   - Recommendation: Add `cache_ttl_secs: i64` to `EnrichmentOptions` and set it from config in `main.rs`. The call chain already passes `EnrichmentOptions` throughout.

2. **Scan subfolder overlap: most-recent or any?**
   - What we know: D-03 says "if the new scan shares hosts with an existing scan subfolder, merge into that subfolder."
   - What's unclear: If multiple existing scan subfolders share IPs with the new scan (e.g., host 10.0.0.1 appeared in 3 previous scans), which subfolder gets the merge?
   - Recommendation: Merge into the most-recently-modified scan subfolder (by mtime of its `_index.md`). This produces the most intuitive result: re-scans update the latest snapshot.

3. **Score History section position in CVE note**
   - What we know: Current `render_cve_body` ends with `## References` then `## Notes`.
   - What's unclear: Whether Score History goes between References and Notes, or before References.
   - Recommendation: Place it after References, before Notes: `## References` → `## Score History` → `## Notes`. This matches the logical flow (references are static; score history is dynamic metadata; notes are user content).

---

## Sources

### Primary (HIGH confidence)
- `src/vault/templates.rs` (project source) — verified `## Notes\n\n` is the final heading in all four render functions (lines 107, 212, 267, 302)
- `src/cache/mod.rs` (project source) — verified `dirs::cache_dir()` pattern for XDG path
- `src/enrichment/mod.rs` (project source) — verified `EnrichmentOptions` struct fields
- `src/main.rs` (project source) — verified config targets (hardcoded `concurrency=5`, env var pattern)
- `Cargo.toml` (project source) — verified `dirs = "6.0.0"`, `serde` with derive, no `toml` crate present yet
- https://docs.rs/toml/latest/toml/ — `from_str::<T>()` API, serde integration
- https://docs.rs/dirs/latest/dirs/fn.config_dir.html — `config_dir()` returns `$XDG_CONFIG_HOME` or `$HOME/.config` on Linux

### Secondary (MEDIUM confidence)
- https://serde.rs/attr-default.html — `#[serde(default)]` and `#[serde(default = "fn")]` attribute patterns
- `cargo search toml --limit 1` (run 2026-03-24) — confirmed current published version is `1.1.0+spec-1.1.0`

### Tertiary (LOW confidence)
None — all critical claims verified against project source or official docs.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — `dirs` and `serde` already in use; `toml` crate API verified from official docs
- Architecture: HIGH — all four template functions verified to end with `## Notes\n\n`; merge algorithm derives directly from this invariant
- Pitfalls: HIGH — all pitfalls identified from direct code inspection (double-Notes, score deduplication) or from serde/toml lifetime semantics in official docs

**Research date:** 2026-03-24
**Valid until:** 2026-09-24 (stable crates; `toml` and `dirs` APIs are stable)

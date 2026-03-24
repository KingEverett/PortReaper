# Phase 5: Config, Polish, and Incremental Updates - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-24
**Phase:** 05-config-polish-and-incremental-updates
**Areas discussed:** Incremental vault merge, API key management, Progress & polish

---

## Incremental Vault Merge

### User-edited content handling

| Option | Description | Selected |
|--------|-------------|----------|
| Preserve Notes sections | Regenerate machine-generated sections, preserve user-editable "Notes" section at bottom | ✓ |
| Full note preservation | Never overwrite existing notes; only create new ones for new hosts/services/CVEs | |
| Merge with markers | Use HTML markers around generated content; everything outside markers preserved | |

**User's choice:** Preserve Notes sections
**Notes:** Simple, predictable — users know where to write

### Stale note handling

| Option | Description | Selected |
|--------|-------------|----------|
| Keep with "not seen" tag | Add #stale or #not-seen-in-latest tag to frontmatter; note stays for historical reference | ✓ |
| Move to archive folder | Move stale notes to archive/ subfolder; keeps vault clean but breaks wikilinks | |
| Delete stale notes | Remove notes for services no longer present; clean but loses user annotations | |

**User's choice:** Keep with "not seen" tag
**Notes:** Historical reference preserved, user can filter/clean up manually

### Scan identity detection

| Option | Description | Selected |
|--------|-------------|----------|
| By IP overlap | If new scan shares hosts with existing scan subfolder, merge into it | ✓ |
| Explicit --merge flag | User passes --merge-scan <label> to specify target subfolder | |
| Always new subfolder | Every run creates a new scan subfolder; no merge complexity | |

**User's choice:** By IP overlap
**Notes:** Simple heuristic based on IP addresses

### CVE score changes

| Option | Description | Selected |
|--------|-------------|----------|
| Overwrite score silently | Always use latest score; CVE notes regenerated with current data | |
| Log change in note | Update score but add "Score History" section showing previous values | ✓ |
| You decide | Claude picks the approach | |

**User's choice:** Log change in note
**Notes:** Useful for tracking CVE maturity over time

---

## API Key Management

### Resolution priority

| Option | Description | Selected |
|--------|-------------|----------|
| Env var wins | Environment variables override config file values; standard Unix convention | ✓ |
| Config file wins | Config file is primary source; env vars as fallback only | |
| CLI > env > config | Three-tier priority with --nvd-key CLI flag | |

**User's choice:** Env var wins
**Notes:** PORTREAPER_NVD_KEY env var (Phase 2) keeps working as-is

### Plaintext key warning

| Option | Description | Selected |
|--------|-------------|----------|
| Warn on first read | Print one-time stderr hint about env var alternative when config has API key | ✓ |
| No warning | Pentesters know what they're doing; don't nag | |
| Require env vars for keys | Config only stores non-sensitive settings; keys MUST come from env vars | |

**User's choice:** Warn on first read
**Notes:** Non-intrusive, educational

### Config auto-creation

| Option | Description | Selected |
|--------|-------------|----------|
| No auto-create | Run fine with no config; user creates only when needed | ✓ |
| Auto-create with comments | Create config.toml on first run with all options commented out | |
| portreaper init command | Add subcommand to generate starter config | |

**User's choice:** No auto-create
**Notes:** Matches tools like rg, fd, bat

---

## Progress & Polish

### Progress indicator style

| Option | Description | Selected |
|--------|-------------|----------|
| Inline status lines | Current [N/M] format; simple, works everywhere, already implemented | ✓ |
| Progress bar | indicatif-style progress bar with ETA and spinners | |
| Compact summary only | No per-service output; just final summary | |

**User's choice:** Inline status lines
**Notes:** No new dependency needed — already implemented in Phase 2

### Timing stats

| Option | Description | Selected |
|--------|-------------|----------|
| Total elapsed time | Single "Completed in 12.4s" line at end of stderr output | ✓ |
| Per-phase breakdown | Timing for each phase (parse, enrich, vault) | |
| No timing | Don't add timing output | |

**User's choice:** Total elapsed time
**Notes:** Lightweight, useful for benchmarking cache vs fresh runs

### Additional polish items

| Option | Description | Selected |
|--------|-------------|----------|
| Cache hit reporting | Show how many services served from cache vs fetched fresh | |
| Config dump flag | Add --show-config flag to print resolved config | |
| Both of the above | Cache hit reporting AND --show-config | |
| None needed | Phase scope is sufficient as-is | ✓ |

**User's choice:** None needed
**Notes:** No additional polish items requested

---

## Claude's Discretion

- Config file design (TOML structure, field names, serde approach)
- Notes section detection during merge (regex, marker, or heading-based)
- Score History section formatting in CVE notes
- Scan subfolder overlap detection implementation
- Config error handling (malformed file behavior)

## Deferred Ideas

None — discussion stayed within phase scope

# Phase 3: Obsidian Vault Output - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Generate a complete Obsidian vault from enriched scan results. Per-host, per-service, and shared CVE notes connected via wikilinks, with YAML frontmatter, severity tags, technology notes, and a CSS snippet for graph coloring. Single vault accumulates knowledge across multiple scan runs — CVEs and technologies are shared, scan-specific data lives in subfolders.

</domain>

<decisions>
## Implementation Decisions

### Vault folder structure
- **D-01:** Organize by type: `cves/`, `technologies/`, `scans/{scan-label}/hosts/`, `scans/{scan-label}/services/`, `assets/`
- **D-02:** Single vault model — each scan run adds a subfolder under `scans/`. CVEs and technologies live at the top level and are shared across all scans.
- **D-03:** Scan subfolders named by date + target range (auto-generated from scan metadata): e.g., `2026-03-21_192.168.1.0`. Falls back to date + filename if no target info available.
- **D-04:** Technology notes (`technologies/`) auto-generated from scan data: product name, versions seen across scans, host instances, linked CVEs, and a user-editable Notes section.

### Wikilink topology
- **D-05:** Downward + shared links: index→hosts, hosts→services, services→CVEs, services→technologies. CVE notes include explicit "Affected Services" backlinks. Technology notes link to instances and CVEs.
- **D-06:** Aliased display text for readability: `[[192.168.1.1_22_ssh|:22 ssh (OpenSSH 7.4)]]`. File names stay machine-friendly, link text is human-friendly.
- **D-07:** CVE notes include explicit "Affected Services" section listing all services that reference the CVE — not relying on Obsidian's backlinks panel.

### Note templates

#### Host notes
- **D-08:** YAML frontmatter: ip, hostnames, os, highest_severity, tags (host + severity), scan label
- **D-09:** Body: hostname display, OS info, Open Ports table (port | service link | product | severity tag), Vulnerability Summary (counts by severity + highest CVE link), user-editable Notes section

#### Service notes
- **D-10:** YAML frontmatter: host, port, protocol, service, product, version, highest_severity, tags (service + name + severity), scan label
- **D-11:** Body: title as `{ip}:{port}/{proto} - {service}`, product link to technology note, host backlink, CPE string in code block, Vulnerabilities table (CVE link | score | severity tag | description), user-editable Notes section

#### CVE notes
- **D-12:** YAML frontmatter: cve_id, cvss_score, severity, cvss_version, sources list, tags (cve + severity), first_seen date
- **D-13:** Body: score/severity/CVSS version headline, sources, description, Affected Services list with wikilinks, References section with NVD and CVE.org external links, user-editable Notes section

#### Technology notes
- **D-14:** YAML frontmatter: product, versions_seen list, tags (technology + product name), first_seen date
- **D-15:** Body: Instances list (host link + port + version), Known CVEs list, user-editable Notes section

### Index pages
- **D-16:** Global `_index.md` at vault root: severity breakdown table, total counts (hosts/services/CVEs), Critical Findings section (top CVEs with affected services), Scans list with dates and stats, Hosts list with highest severity
- **D-17:** Per-scan index note in each scan subfolder: scan date, source filename, host/service/CVE counts, host list with severity, severity breakdown table

### CSS snippet
- **D-18:** Tag-based severity graph coloring: critical=red (#ff4444), high=orange (#ff8800), medium=yellow (#ffcc00), low=green (#44bb44), host=blue (#4488ff), cve=purple (#aa44ff), technology=cyan (#44cccc)
- **D-19:** CSS file placed in `assets/severity-colors.css` with instructions to copy to `.obsidian/snippets/`

### Claude's Discretion
- Exact Obsidian graph CSS selector syntax (may need `.tag-` prefix instead of `.color-fill-tag-`)
- YAML serialization approach for frontmatter (serde_yaml is mandated, but struct design is flexible)
- How to derive scan label from nmap XML metadata (startstr, args, etc.)
- Internal module organization for vault generation code
- How to handle services with zero CVEs in templates (still generate notes or skip)
- Truncation strategy for very long CVE descriptions in service note tables

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

No external specs — requirements fully captured in decisions above.

### Project-level
- `.planning/PROJECT.md` — Vision, constraints (Rust, Obsidian output format, serde_yaml mandate)
- `.planning/REQUIREMENTS.md` — OUT-01 through OUT-07 define this phase's scope
- `.planning/ROADMAP.md` — Phase 3 success criteria (5 criteria that must be TRUE)

### Pre-phase decisions (from STATE.md)
- `serde_yaml` for all YAML frontmatter — never `format!` macros (CVE descriptions contain YAML-significant characters)
- `sanitize_filename()` must route all filename construction — already implemented in `src/util/filename.rs`
- All nmap service fields are `Option<T>` — templates must handle absent product/version/extrainfo gracefully

### Prior phase context
- `.planning/phases/01-foundation/01-CONTEXT.md` — CLI interface decisions, tree output format, error handling patterns
- `.planning/phases/02-enrichment-core/02-CONTEXT.md` — Vulnerability display format, API failure behavior, CVE deduplication by highest CVSS

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `src/util/filename.rs`: `sanitize_filename()` — route all vault filenames through this
- `src/models.rs`: `ScanResult`, `Host`, `Port`, `Service`, `Vulnerability`, `CvssScore`, `Severity` — all data needed for note generation is already typed
- `src/models.rs`: `Severity::label()` returns short labels ("Crit", "High", "Med", "Low") — use for display text in wikilink aliases
- `src/cli.rs`: `--vault` flag already defined (currently hidden) — unhide and use as output path

### Established Patterns
- All service fields are `Option<T>` — vault templates must handle None gracefully (skip or show placeholder)
- `serde_yaml` for YAML serialization — use for all frontmatter generation
- `owo-colors` with `supports-colors` for terminal output — vault generation is file I/O, no terminal colors needed
- `thiserror` for typed errors — add vault generation error variants

### Integration Points
- `src/main.rs`: After enrichment, before/instead of tree rendering — branch to vault generation when `--vault` is provided
- `src/enrichment/mod.rs`: `enrich_scan()` returns enriched `ScanResult` — vault generator consumes this
- `Cargo.toml`: May need `serde_yaml` added (currently has serde + serde_json; serde_yaml deferred from Phase 1)

</code_context>

<specifics>
## Specific Ideas

- Single vault as a growing knowledge base across engagements — CVEs and technologies accumulate, scan-specific data stays organized in subfolders
- Technology notes bridge scans: "OpenSSH appears on 5 hosts across 3 scans" — valuable for pattern recognition during pentests
- Every note has a user-editable "Notes" section at the bottom — pentester can annotate findings without disrupting generated content
- CSS snippet colors match the terminal severity color spirit: red=critical, orange=high, yellow=medium, green=low

</specifics>

<deferred>
## Deferred Ideas

- Incremental vault updates (merging new scan data into existing vault without overwriting) — Phase 5 (OUT-08)
- Config file for default vault output path — Phase 5 (ARCH-03)
- Cross-vault linking between separate Obsidian vaults — revisit if single-vault model proves insufficient

</deferred>

---

*Phase: 03-obsidian-vault-output*
*Context gathered: 2026-03-23*

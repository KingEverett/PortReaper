# Phase 1: Foundation - Context

**Gathered:** 2026-03-20
**Status:** Ready for planning

<domain>
## Phase Boundary

CLI skeleton, nmap XML/text/greppable parsing, normalized data models, and sanitized filename infrastructure. Users can parse any nmap output and see a structured tree summary of hosts, ports, services, versions, and CPE strings in the terminal — with no network calls required.

</domain>

<decisions>
## Implementation Decisions

### Terminal output format
- Tree view with Unicode box-drawing characters showing host → port → service hierarchy
- Color output by default with auto-detection for piped output (no color when stdout is not a TTY)
- Header shows scan source (filename or "stdin"), footer shows summary counts (hosts, open ports, unique services)
- CPE strings hidden in default output, shown with -v verbose flag
- Summary line at bottom: "Summary: N hosts, N open ports, N unique services"

### Input parsing
- Support three input formats: XML (-oX), text (default nmap output), and greppable (-oG)
- Auto-detect format by content sniffing (first bytes: `<?xml` or `<nmaprun` → XML, `# Nmap` or `Host:` → greppable, else text)
- Parse what's available from each format — text/greppable lack CPE, OS detection, and script results; show what exists, leave missing fields absent
- Lenient parsing with stderr warnings — extract recognizable data, log skipped/unparseable lines to stderr so user knows what was missed
- No explicit --format flag needed; content sniffing handles all cases

### CLI interface
- Flat command structure with flags (no subcommands): `portreaper scan.xml [--enrich] [--vault ./out]`
- Accept multiple scan files as positional args: `portreaper scan1.xml scan2.xml scan3.xml`
- Merge duplicate hosts by IP across multiple files — union of all discovered ports/services
- Verbosity flags: -v (verbose: CPEs, OS, extra fields), -q (quiet: summary line only), default (tree + summary)
- When stdin is a TTY with no file args, show short usage/help with examples — don't hang waiting for input
- Stdin piping supported: `nmap ... | portreaper` or `cat scan.xml | portreaper`

### Error handling
- Partial parse failures: show successfully parsed hosts in tree, print warnings to stderr for failed hosts/sections
- Contextual error messages with suggestions: what went wrong + what to try (e.g., "not a valid nmap file → expected XML/text/greppable → try: nmap -oX scan.xml target")
- Distinct exit codes: 0 = success, 1 = parse error, 2 = no input/file not found
- Non-nmap files produce clear, actionable error rather than panic or silent failure

### Claude's Discretion
- Tree indentation and spacing details
- Exact color scheme (which colors for which elements)
- Internal data model field naming
- Compression algorithm for sanitize_filename edge cases

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

No external specs — requirements are fully captured in decisions above and in:

### Project-level
- `.planning/PROJECT.md` — Vision, constraints (Rust, Obsidian output, pluggable sources)
- `.planning/REQUIREMENTS.md` — INPUT-01 through INPUT-04, ARCH-01, ARCH-02 define this phase's scope
- `.planning/ROADMAP.md` — Phase 1 success criteria (5 criteria that must be TRUE)

### Pre-phase decisions (from STATE.md)
- All nmap service fields must be `Option<T>` — product/version/extrainfo often absent in real scans
- `sanitize_filename()` must exist before any file-write code — route all filename construction through it
- `serde_yaml` for all YAML frontmatter, never `format!` macros (CVE descriptions contain YAML-significant chars)
- Typed error taxonomy (Empty/RateLimited/NetworkFailure) required at VulnSource trait boundary

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- None — greenfield project, no existing code

### Established Patterns
- None yet — Phase 1 establishes the foundational patterns

### Integration Points
- VulnSource trait defined here will be consumed by Phase 2 (NVD, CVE.org enrichment)
- Data models (Host, Port, Service) defined here feed all subsequent phases
- sanitize_filename() defined here is used by Phase 3 (Obsidian vault generation)
- Tree output format established here may be extended in Phase 2 to show vulnerability counts per service

</code_context>

<specifics>
## Specific Ideas

- Tree view should feel like `tree` or `exa --tree` — familiar Unix aesthetic
- Usage help when no args should be concise like `rg` or `fd` — not a full man page
- Error messages styled like Rust compiler errors (contextual with arrows/suggestions)

</specifics>

<deferred>
## Deferred Ideas

- Greppable output format (-oG) support was included in Phase 1 scope per user request
- --json flag for machine-readable output — consider for later phase if scripting demand arises

</deferred>

---

*Phase: 01-foundation*
*Context gathered: 2026-03-20*

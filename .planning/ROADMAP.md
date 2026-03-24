# Roadmap: PortReaper

## Overview

PortReaper is a four-layer data pipeline: nmap XML enters, gets normalized into typed models, gets enriched concurrently against vulnerability databases, and exits as a structured Obsidian vault. The phases follow the pipeline dependency order — models before parsers, parsers before enrichment, enrichment before output, caching before iterative use. Each phase delivers one complete, verifiable capability. Nothing builds on unvalidated assumptions.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundation** - CLI skeleton, nmap XML parsing, normalized data models, and sanitized filename infrastructure (completed 2026-03-21)
- [x] **Phase 2: Enrichment Core** - VulnSource trait, NVD + CVE.org integration, typed errors, bounded concurrency, CVSS classification (completed 2026-03-21)
- [ ] **Phase 3: Obsidian Vault Output** - Full vault generation: per-host/service/CVE notes, wikilinks, frontmatter, severity tags, CSS snippet
- [ ] **Phase 4: Additional Sources and Caching** - OSV.dev, SearchSploit, response caching, concurrency controls
- [ ] **Phase 5: Config, Polish, and Incremental Updates** - TOML config, API key management, incremental vault merging, progress indicators

## Phase Details

### Phase 1: Foundation
**Goal**: Users can parse any nmap XML scan and see a complete, structured summary of hosts, ports, services, versions, and CPE strings in the terminal — with no network calls required
**Depends on**: Nothing (first phase)
**Requirements**: INPUT-01, INPUT-02, INPUT-03, INPUT-04, ARCH-01, ARCH-02
**Success Criteria** (what must be TRUE):
  1. Running `portreaper scan.xml` against a real nmap `-oX` file prints a structured summary of all hosts, open ports, services, and versions without crashing on missing or malformed service fields
  2. Running `nmap ... | portreaper` (piped text input) is auto-detected and produces equivalent output to XML mode for the fields available in text format
  3. A scan file with multiple hosts produces correct per-host output — no hosts silently dropped
  4. The VulnSource plugin trait is defined and the typed error taxonomy (Empty vs RateLimited vs NetworkFailure) is in place, enforced at compile time
  5. Attempting to pass a non-nmap file produces a clear, actionable error message rather than a panic or silent failure
**Plans:** 3/3 plans complete

Plans:
- [x] 01-01-PLAN.md — Project init, data models, VulnSource trait, error taxonomy, test fixtures
- [x] 01-02-PLAN.md — XML, text, and greppable parsers with format auto-detection and host merging
- [x] 01-03-PLAN.md — CLI (clap), Unicode tree renderer, main wiring, exit codes, integration tests

### Phase 2: Enrichment Core
**Goal**: Users can run PortReaper against a real scan and get NVD + CVE.org vulnerability data for each service, classified by CVSS severity, with correct rate limiting and no silent data loss from API failures
**Depends on**: Phase 1
**Requirements**: VULN-01, VULN-02, VULN-05, VULN-06, ARCH-04
**Success Criteria** (what must be TRUE):
  1. Running against a scan with known-vulnerable services (e.g., OpenSSH 7.4, Apache 2.4.49) surfaces real CVE IDs from NVD and CVE.org with CVSS scores and Critical/High/Medium/Low classification
  2. When NVD rate limits are hit, the tool retries with exponential backoff and reports partial results rather than silently returning zero findings
  3. A 50-port scan completes without exhausting file descriptors — concurrent queries are bounded by a configurable semaphore
  4. CVE-2021-41773 appearing in both NVD and CVE.org results appears exactly once in output (deduplication by CVE ID)
  5. Progress output is shown during vulnerability lookups so the user can see the tool is working on large scans
**Plans:** 3/3 plans complete

Plans:
- [x] 02-01-PLAN.md — Vulnerability/Severity types, VulnSource trait update, NvdSource with CVSS extraction
- [x] 02-02-PLAN.md — CveOrgSource, enrichment orchestrator with concurrency, backoff, dedup
- [x] 02-03-PLAN.md — CLI wiring (async main, --no-enrich), tree renderer CVE display, severity colors

### Phase 3: Obsidian Vault Output
**Goal**: Users can open the generated Obsidian vault immediately after a scan and navigate a complete, severity-colored knowledge graph linking hosts, services, and shared CVE notes via wikilinks
**Depends on**: Phase 2
**Requirements**: OUT-01, OUT-02, OUT-03, OUT-04, OUT-05, OUT-06, OUT-07
**Success Criteria** (what must be TRUE):
  1. Opening the vault in Obsidian's graph view shows a hub-and-spoke topology: IP address nodes link to service nodes, service nodes link to CVE nodes, and a CVE shared by two services appears as one node linked to both
  2. Each service note contains valid YAML frontmatter (severity, tags, service metadata) that Obsidian renders without error — including services whose CVE descriptions contain colons, quotes, or special characters
  3. The graph view colors nodes correctly by severity (critical/high/medium/low) using the bundled CSS snippet and severity tags
  4. The `_index.md` file lists all discovered hosts and services with their highest severity, giving an at-a-glance attack surface summary without opening individual notes
  5. Filenames containing IP addresses, IPv6 brackets, and service names with slashes are all valid on the filesystem and resolve correctly as wikilinks in Obsidian
**Plans:** 3 plans

Plans:
- [ ] 03-01-PLAN.md — Vault module skeleton: serde_yml dep, frontmatter structs, graph config, Severity::obsidian_tag()
- [ ] 03-02-PLAN.md — Two-pass vault generation: note body templates, wikilinks, host/service/CVE/technology notes
- [ ] 03-03-PLAN.md — Index pages, --vault CLI wiring, end-to-end integration tests

### Phase 4: Additional Sources and Caching
**Goal**: Users get exploit cross-references from SearchSploit and open-source vulnerability data from OSV.dev, and re-running against the same scan skips already-queried services from cache
**Depends on**: Phase 3
**Requirements**: VULN-03, VULN-04, VULN-07
**Success Criteria** (what must be TRUE):
  1. Service notes for vulnerable services include a SearchSploit cross-reference section when the local `searchsploit` binary is present; when absent, the tool continues without error and skips the section silently
  2. OSV.dev data appears for open-source services (e.g., nginx, OpenSSL) that NVD may index slowly — adding CVEs not found via NVD/CVE.org alone
  3. Re-running PortReaper against an already-processed scan completes significantly faster because cached API responses are served locally without hitting rate limits
**Plans**: TBD

### Phase 5: Config, Polish, and Incremental Updates
**Goal**: Users can configure PortReaper via a config file with API keys and source preferences, and re-running against an updated scan merges new findings into an existing vault without overwriting prior notes
**Depends on**: Phase 4
**Requirements**: OUT-08, ARCH-03
**Success Criteria** (what must be TRUE):
  1. A TOML config file at the OS-appropriate path (e.g., `~/.config/portreaper/config.toml`) controls which sources are enabled, API keys (NVD key), concurrency cap, and output path — and the tool reads it automatically on startup
  2. Running PortReaper against a second scan of the same target merges new ports and CVEs into existing notes without deleting manually added content or duplicating existing entries
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation | 3/3 | Complete   | 2026-03-21 |
| 2. Enrichment Core | 3/3 | Complete   | 2026-03-21 |
| 3. Obsidian Vault Output | 0/3 | Not started | - |
| 4. Additional Sources and Caching | 0/TBD | Not started | - |
| 5. Config, Polish, and Incremental Updates | 0/TBD | Not started | - |

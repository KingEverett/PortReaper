# Requirements: PortReaper

**Defined:** 2026-03-20
**Core Value:** Eliminate manual vulnerability research during pentest enumeration by automating nmap-to-Obsidian knowledge graph generation with severity-highlighted nodes

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### Input

- [ ] **INPUT-01**: Parse nmap XML output files (`-oX` format) with full field extraction (ports, services, versions, OS, scripts)
- [ ] **INPUT-02**: Accept piped nmap text output from stdin
- [ ] **INPUT-03**: Handle multiple hosts in a single scan file
- [ ] **INPUT-04**: Auto-detect input format (XML vs text)

### Vulnerability Lookup

- [ ] **VULN-01**: Query NVD (NIST) for CVEs and CVSS scores
- [ ] **VULN-02**: Query CVE.org for vulnerability data
- [ ] **VULN-03**: Query OSV.dev for open-source vulnerability data
- [ ] **VULN-04**: Integrate SearchSploit local exploit database
- [ ] **VULN-05**: CPE-based matching for accurate vulnerability lookups
- [ ] **VULN-06**: Rate limiting and bounded concurrency for API queries
- [ ] **VULN-07**: Local caching to avoid re-querying known services

### Output

- [ ] **OUT-01**: Generate Obsidian vault with `[[wikilinks]]` for native graph view
- [ ] **OUT-02**: Hierarchical node structure: Project → IP Addresses → Ports/Services
- [ ] **OUT-03**: YAML frontmatter with severity, tags, and service metadata
- [ ] **OUT-04**: Severity classification (critical/high/medium/low) with Obsidian tags
- [ ] **OUT-05**: Structured service note template (service info table, vulns, links)
- [ ] **OUT-06**: Shared CVE notes (one note per CVE, linked from all affected services)
- [ ] **OUT-07**: Obsidian CSS snippet for severity-based color-coding in graph view
- [ ] **OUT-08**: Incremental vault updates (merge new scan data into existing vault)

### Architecture

- [ ] **ARCH-01**: Pluggable data source trait for easy swapping/adding of databases
- [ ] **ARCH-02**: Typed error handling (distinguish rate limit vs empty result vs network error)
- [ ] **ARCH-03**: Config file for default sources, API keys, output paths
- [ ] **ARCH-04**: Progress indicators during vulnerability lookups

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Exploit Sources

- **EXPL-01**: ExploitDB web scraping integration
- **EXPL-02**: PacketStorm advisory/exploit data scraping
- **EXPL-03**: VulnDB integration (requires API access confirmation)

### Advanced Parsing

- **PARSE-01**: nmap NSE script output extraction and structured display

## Out of Scope

| Feature | Reason |
|---------|--------|
| Web UI / browser-based graph | Obsidian is the visualization layer; building a web UI duplicates it |
| Active exploitation / payload generation | PortReaper is a research/enumeration tool, not an exploitation framework |
| Running nmap scans directly | PortReaper consumes nmap output; invoking nmap adds complexity and security concerns |
| Mobile app | CLI tool by design |
| AI-generated remediation advice | Adds unreliable content to what should be factual vulnerability data |
| Cloud storage of scan data | Security context — pentest data should stay local |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| INPUT-01 | — | Pending |
| INPUT-02 | — | Pending |
| INPUT-03 | — | Pending |
| INPUT-04 | — | Pending |
| VULN-01 | — | Pending |
| VULN-02 | — | Pending |
| VULN-03 | — | Pending |
| VULN-04 | — | Pending |
| VULN-05 | — | Pending |
| VULN-06 | — | Pending |
| VULN-07 | — | Pending |
| OUT-01 | — | Pending |
| OUT-02 | — | Pending |
| OUT-03 | — | Pending |
| OUT-04 | — | Pending |
| OUT-05 | — | Pending |
| OUT-06 | — | Pending |
| OUT-07 | — | Pending |
| OUT-08 | — | Pending |
| ARCH-01 | — | Pending |
| ARCH-02 | — | Pending |
| ARCH-03 | — | Pending |
| ARCH-04 | — | Pending |

**Coverage:**
- v1 requirements: 23 total
- Mapped to phases: 0
- Unmapped: 23

---
*Requirements defined: 2026-03-20*
*Last updated: 2026-03-20 after initial definition*

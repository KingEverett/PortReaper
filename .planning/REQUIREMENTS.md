# Requirements: PortReaper

**Defined:** 2026-03-20
**Core Value:** Eliminate manual vulnerability research during pentest enumeration by automating nmap-to-Obsidian knowledge graph generation with severity-highlighted nodes

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### Input

- [x] **INPUT-01**: Parse nmap XML output files (`-oX` format) with full field extraction (ports, services, versions, OS, scripts)
- [x] **INPUT-02**: Accept piped nmap text output from stdin
- [x] **INPUT-03**: Handle multiple hosts in a single scan file
- [x] **INPUT-04**: Auto-detect input format (XML vs text)

### Vulnerability Lookup

- [x] **VULN-01**: Query NVD (NIST) for CVEs and CVSS scores
- [x] **VULN-02**: Query CVE.org for vulnerability data
- [ ] **VULN-03**: Query OSV.dev for open-source vulnerability data
- [ ] **VULN-04**: Integrate SearchSploit local exploit database
- [x] **VULN-05**: CPE-based matching for accurate vulnerability lookups
- [x] **VULN-06**: Rate limiting and bounded concurrency for API queries
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

- [x] **ARCH-01**: Pluggable data source trait for easy swapping/adding of databases
- [x] **ARCH-02**: Typed error handling (distinguish rate limit vs empty result vs network error)
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
| INPUT-01 | Phase 1 | Complete |
| INPUT-02 | Phase 1 | Complete |
| INPUT-03 | Phase 1 | Complete |
| INPUT-04 | Phase 1 | Complete |
| ARCH-01 | Phase 1 | Complete |
| ARCH-02 | Phase 1 | Complete |
| VULN-01 | Phase 2 | Complete |
| VULN-02 | Phase 2 | Complete |
| VULN-05 | Phase 2 | Complete |
| VULN-06 | Phase 2 | Complete |
| ARCH-04 | Phase 2 | Pending |
| OUT-01 | Phase 3 | Pending |
| OUT-02 | Phase 3 | Pending |
| OUT-03 | Phase 3 | Pending |
| OUT-04 | Phase 3 | Pending |
| OUT-05 | Phase 3 | Pending |
| OUT-06 | Phase 3 | Pending |
| OUT-07 | Phase 3 | Pending |
| VULN-03 | Phase 4 | Pending |
| VULN-04 | Phase 4 | Pending |
| VULN-07 | Phase 4 | Pending |
| OUT-08 | Phase 5 | Pending |
| ARCH-03 | Phase 5 | Pending |

**Coverage:**
- v1 requirements: 23 total
- Mapped to phases: 23
- Unmapped: 0

---
*Requirements defined: 2026-03-20*
*Last updated: 2026-03-20 after roadmap creation — full traceability established*

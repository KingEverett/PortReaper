# PortReaper

## What This Is

A Rust CLI tool that automates the penetration testing enumeration workflow. It parses nmap scan results (piped stdin or XML files), auto-researches every discovered service and version against vulnerability databases, and generates an Obsidian vault with an interconnected graph of targets, ports, services, and vulnerabilities — color-coded by severity.

## Core Value

Eliminate the manual, scattered process of researching nmap findings across multiple vulnerability databases by automating lookup and producing an immediately navigable, severity-highlighted Obsidian knowledge graph.

## Requirements

### Validated

- [x] Parse nmap XML output files (`-oX` format) — Validated in Phase 01: Foundation
- [x] Accept piped nmap text output from stdin — Validated in Phase 01: Foundation
- [x] Support pluggable data source architecture for easy swapping/adding of databases — Validated in Phase 01: Foundation (VulnSource trait)
- [x] Query NVD (NIST) for vulnerability data and CVSS scores — Validated in Phase 02: Enrichment Core
- [x] Query CVE.org for vulnerability data — Validated in Phase 02: Enrichment Core
- [x] Auto-research each discovered service/version against vulnerability databases — Validated in Phase 02: Enrichment Core
- [x] CVSS score display and severity classification (critical/high/medium/low) — Validated in Phase 02: Enrichment Core
- [x] Generate Obsidian vault with `[[wikilinks]]` for native graph view — Validated in Phase 03: Obsidian Vault Output
- [x] Produce hierarchical node structure: Project → IP Addresses → Ports/Services — Validated in Phase 03: Obsidian Vault Output
- [x] Highlight nodes by vulnerability severity using Obsidian tags and YAML frontmatter — Validated in Phase 03: Obsidian Vault Output
- [x] Generate service notes with structured template (frontmatter, service info table, vulnerabilities, links) — Validated in Phase 03: Obsidian Vault Output

### Active
- [ ] Query OSV.dev for vulnerability data
- [ ] Query VulnDB for vulnerability data
- [ ] Query ExploitDB for available exploits
- [ ] Query SearchSploit for local exploit references
- [ ] Query PacketStorm Security for exploit/advisory data

### Out of Scope

- Web UI or browser-based graph — Obsidian is the visualization layer
- Active exploitation or payload generation — this is a research/enumeration tool
- Running nmap scans directly — PortReaper consumes nmap output, doesn't invoke nmap
- Mobile app — CLI tool only

## Context

- Built for penetration testers during the enumeration phase of engagements
- nmap is the industry-standard port scanner; its XML output (`-oX`) contains rich data (service versions, OS detection, script results)
- Current workflow is manual: run nmap, then individually search CVE.org, NVD, OSV.dev, ExploitDB, SearchSploit, PacketStorm, VulnDB for each finding
- Obsidian's graph view provides natural visualization for the hierarchical relationship between targets, services, and vulnerabilities
- Severity-based tagging (#critical, #high, #medium, #low) enables Obsidian CSS snippets and graph filtering for prioritization

## Constraints

- **Language**: Rust — single binary distribution, performance for parsing and concurrent API queries
- **Output format**: Obsidian-compatible markdown with YAML frontmatter and `[[wikilinks]]`
- **Data sources**: Must be pluggable/modular — each database source should be independently swappable without touching core logic
- **API access**: Rely on free/public APIs where available; scraping where necessary (ExploitDB, PacketStorm)

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Rust for implementation | Single binary, fast concurrent HTTP requests, strong CLI ecosystem | ✓ Validated |
| Obsidian vault as output | User's existing workflow tool, graph view maps naturally to enumeration hierarchy | ✓ Validated |
| Tags + frontmatter for severity | Enables Obsidian graph filtering and CSS snippet color-coding without folder-based organization | ✓ Validated |
| Pluggable data source architecture | User wants to easily swap/add vulnerability databases as the tool evolves | ✓ Validated |
| Support both pipe and XML input | Pipe for quick use, XML for richer data — covers both workflow patterns | ✓ Validated |

---
*Last updated: 2026-03-24 after Phase 03 (Obsidian Vault Output) completion*

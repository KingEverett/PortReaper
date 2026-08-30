# Bug Bounty Suite — Vision & Architecture

*Documented 2026-03-28*

## End Goal

An AI-driven bug bounty operations platform that automates vulnerability discovery at scale for income. Built as a suite of independent tools that compound when combined.

## Suite Components

| Tool | Role | Status | Tech |
|------|------|--------|------|
| **PortReaper** | Scan ingestion — nmap → Obsidian vault with vuln enrichment | v1.0 COMPLETE | Rust CLI |
| **Brain** (TBD) | Knowledge layer — techniques, findings, domain expertise | Research complete | TBD (Rust CLI + MCP) |
| **Dashboard** (TBD) | Command center — targets, scope, findings, submissions, earnings | Not started | TBD |
| **AI Agents** (TBD) | Automated recon, vuln discovery, iterative improvement | Not started | TBD |
| **OpenSpace** (ref) | Training/improving AI skills | Referenced | Unknown |

## Data Flow

```
[Bug Bounty Programs] → scope/targets
        ↓
[AI Agents] → automated recon + vuln discovery
        ↓
[PortReaper] → scan results → enriched Obsidian vault
        ↓
[Brain] → accumulates knowledge, techniques, findings
        ↓                    ↑
[Dashboard] ← earnings, status, submissions
        ↓
[AI Agents] ← informed by Brain, improving each iteration
```

The loop compounds: more engagements → richer brain → smarter agents → better findings → more earnings.

## Architectural Principles

1. **Individual tools, not a monolith** — each tool works standalone
2. **Markdown + YAML frontmatter** as knowledge interchange format
3. **SQLite** for AI-queryable indexing (validated: sub-100ms at 100k+ notes)
4. **MCP** for AI agent access to any tool's data
5. **Git-backed** — all knowledge is diffable, portable, shareable
6. **Obsidian-compatible** — human browsing layer over the same files
7. **Rust for CLI tools** — single binary, fast, shares patterns with PortReaper

## First Domain: Car Hacking

The Brain's first specialized domain will be car hacking. User has a book for reference material. Domains are separate directories within the brain vault with domain-specific schemas.

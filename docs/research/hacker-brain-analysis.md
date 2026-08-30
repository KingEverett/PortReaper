# Hacker Brain — Full Analysis

*Compiled 2026-03-28 from 5 parallel research agents*

## Executive Summary

No existing tool satisfies all requirements (growing knowledge base + AI-queryable + domain-specialized + engagement feedback + human-browsable). The recommended approach is a phased build using markdown + YAML as source of truth, SQLite for AI indexing, and Obsidian as the human interface.

---

## Existing Tools Evaluated

### RedStack DB
- **Claim:** Centralized knowledge graph for offensive security with AI integration
- **Reality:** No public GitHub repo found. It's an Obsidian export of redstack.io (web platform). ~9,500 procedures, ~20,000 commands bulk-ingested from public repos. "AI integration" is marketing — no MCP, no RAG, no embeddings. MITRE ATT&CK mapping status unverifiable.
- **Verdict:** Not usable as foundation. Cannot be forked or extended.

### PentestAgent / GhostCrew
- **Repo:** github.com/GH05TCREW/pentestagent (~1,800 stars)
- **RAG:** In-memory NumPy cosine similarity. No real vector DB. Chunks markdown files with 1000-char chunks + 200-char overlap. Will not scale past hundreds of documents.
- **Shadow Knowledge Graph:** NetworkX graph with regex-based entity extraction. 4 node types (host, service, credential, finding). Not an inference engine — just structured note linking with shortest_path queries.
- **Persistence:** Session-only. loot/notes.json exists but no cross-session learning. State manager is entirely in-memory.
- **MCP:** 5 built-in tools (terminal, browser, notes, web_search, spawn_mcp_agent). The "128+ tools" come from connected external MCP servers. RAG optimizer for tool selection is genuinely clever.
- **Verdict:** Good ideas to borrow (MCP RAG optimizer, playbook architecture, graph schema). Not a foundation for production use.

### TrustedSec Obsidian Vault Structure
- **Repo:** github.com/trustedsec/Obsidian-Vault-Structure
- **Reality:** Battle-tested team pentest vault. 5-tier folder hierarchy with Maps of Content (MOCs). Templater automation. Obsidian-Git sync. Emoji-based search tags.
- **Verdict:** Excellent structural template. No AI story — predates CLI/MCP era. Use as inspiration for vault organization.

### sec-vault-gen
- **Repo:** github.com/ImpostorKeanu/sec-vault-gen
- **Reality:** Programmatic MITRE ATT&CK STIX data → Obsidian markdown with proper frontmatter. Linker subcommand for bidirectional technique linking.
- **Verdict:** Good component for baseline technique library ingestion.

### kepano/obsidian-skills
- **Repo:** github.com/kepano/obsidian-skills (17.6k stars)
- **Reality:** 5 Claude Code skills from Obsidian's CEO. Pure prompt-engineering markdown files. Covers: correct Obsidian markdown, Bases, JSON Canvas, CLI commands, Defuddle web extraction.
- **Verdict:** Must-use foundation. Solves "Claude writes almost-right Obsidian markdown" problem.

---

## Backend Analysis: SQLite vs Graph DB

### SQLite (Recommended)

**sqlite-memory:** Three-layer extension — md4c markdown parser, llama.cpp/vectors.space embeddings, hybrid FTS5 + vector search.

| Scale | FTS5 latency | Vector search (768d) | Storage | Reindex |
|-------|-------------|---------------------|---------|---------|
| 10k notes | Sub-ms | <20ms | ~15 MB | Seconds |
| 50k notes | Low single-digit ms | <50ms | ~60-80 MB | ~2 min |
| 100k notes | Single-digit ms | <75ms | ~150-200 MB | ~4-5 min |

Real benchmark: 16,894 Obsidian files → 49,746 chunks in 83 MB, full reindex 4 min, incremental <10s.

**Key advantage:** Markdown files are source of truth (git-tracked). SQLite is a disposable derived index. Obsidian has no idea it exists.

**Existing MCP servers for SQLite:**
- Anthropic's official mcp-server-sqlite
- obsidian-index-service (watches vault, indexes to SQLite, serves via MCP)
- claude-memory-mcp (knowledge graph in SQLite)

### Graphiti / Neo4j (Not Recommended for Personal Tool)

Offers temporal tracking, automatic entity extraction, graph traversal — but requires Neo4j server (500MB-1GB RAM idle), LLM API calls per ingestion, Docker. Overkill for personal use. Reconsider only if the tool becomes team-scale with 4+ hop attack path analysis needs.

---

## Obsidian + AI Integration Landscape (Early 2026)

### MCP Servers Compared

| Feature | cyanheads/obsidian-mcp-server | jacksteamdev/obsidian-mcp-tools | iansinnott/obsidian-claude-code-mcp | bitbonsai/mcpvault |
|---------|------|------|------|------|
| Requires Obsidian? | Yes | Yes | Yes | No |
| Read/Write/Search | Yes/Yes/Text+regex | Yes/Templates/Semantic | Yes/Yes/File list | Yes/Yes/Text+tags |
| Semantic search | No | **Yes** (Smart Connections) | No | No |
| Frontmatter mgmt | Yes | No | No | Yes |
| Headless capable | No | No | No | **Yes** |

### Obsidian CLI (v1.12+, Feb 2026)
130+ commands for remote-controlling running Obsidian instance. Safe operations through Obsidian's API (wikilinks auto-update, index stays consistent). Best option when desktop app is running.

### Headless VPS
- **obsidianmd/obsidian-headless:** Official sync client, no app engine (no CLI, no plugins)
- **alexjbarnes/vault-sync:** Go daemon — headless sync + MCP server. The VPS solution.

---

## Recommended Architecture

```
[You + Obsidian] <---> [Markdown + YAML vault in git]
                              |              |
                         [PortReaper]    [sqlite-memory index]
                        writes scans    derived cache (disposable)
                                            |
                                       [MCP server]
                                            |
                                    [Claude / AI agents]
```

### Phased Build

**Phase 1 (Day 1): Claude Code Skill**
- Define vault structure, frontmatter schemas, note type templates
- Use kepano's obsidian-skills for correct syntax
- Start accumulating knowledge immediately

**Phase 2 (Week 1): Structured Vault + Templates**
- TrustedSec-inspired MOC pattern
- Templater templates per note type (technique, finding, tool, pattern)
- sec-vault-gen for MITRE ATT&CK baseline
- Domain directories with per-domain CLAUDE.md
- Seed car hacking brain from book

**Phase 3 (Weeks 2-4): Rust CLI or MCP Server**
- `brain init --domain car-hacking` — scaffold domain
- `brain ingest --scan-vault ./vault` — pull from PortReaper output
- `brain add technique` — structured entry
- `brain query <term>` — search across brain
- Reuses PortReaper's vault/frontmatter/merge infrastructure

**Phase 4 (Month 2+): Feedback Loops**
- PortReaper scans auto-cross-link to brain techniques
- Claude Code hooks auto-log findings
- After-action reviews feed into knowledge base
- Temporal tracking (when learned, still current?)

### PortReaper Code Reuse Points
- `vault::frontmatter::render_note()` — generic YAML+body renderer
- `vault::merge::merge_write_note()` — preserves user Notes sections
- `vault::templates` — wikilink helpers, body renderers
- `vault::writer::write_note()` — creates dirs, writes files
- `util::filename::sanitize_filename()` — safe filenames
- `config/mod.rs` — TOML config pattern

---

## Key References

### Repos
- [kepano/obsidian-skills](https://github.com/kepano/obsidian-skills) — Agent skills for Obsidian
- [trustedsec/Obsidian-Vault-Structure](https://github.com/trustedsec/Obsidian-Vault-Structure) — Team pentest vault
- [ImpostorKeanu/sec-vault-gen](https://github.com/ImpostorKeanu/sec-vault-gen) — ATT&CK ingestion
- [Hacker-Hermanos/Knowledge-Management-for-Offensive-Security-Professionals](https://github.com/Hacker-Hermanos/Knowledge-Management-for-Offensive-Security-Professionals)
- [CedarvilleCyber/RedTeamVault](https://github.com/CedarvilleCyber/RedTeamVault)
- [sqliteai/sqlite-memory](https://github.com/sqliteai/sqlite-memory)
- [pmmvr/obsidian-index-service](https://github.com/pmmvr/obsidian-index-service)
- [cyanheads/obsidian-mcp-server](https://github.com/cyanheads/obsidian-mcp-server)
- [alexjbarnes/vault-sync](https://github.com/alexjbarnes/vault-sync)
- [GH05TCREW/pentestagent](https://github.com/GH05TCREW/pentestagent)
- [getzep/graphiti](https://github.com/getzep/graphiti)

### Community Knowledge
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Structured vuln payloads
- [HackTricks](https://book.hacktricks.xyz/) — Comprehensive pentest methodology
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — Best dual-format (MD+YAML) model
- [awesome-vehicle-security](https://github.com/jaredthecoder/awesome-vehicle-security) — Car hacking resources

### Articles & Discussions
- [TrustedSec Blog: Obsidian, Taming a Collective Consciousness](https://trustedsec.com/blog/obsidian-taming-a-collective-consciousness)
- [The MCP Pattern: SQLite as the AI-Queryable Cache](https://dev.to/queelius/the-mcp-pattern-sqlite-as-the-ai-queryable-cache-34g6)
- [Building a Hybrid Retriever for 16,894 Obsidian Files](https://blakecrosley.com/blog/hybrid-retriever-obsidian)

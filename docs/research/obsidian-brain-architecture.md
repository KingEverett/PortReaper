# Obsidian as Security Research Brain

*Compiled 2026-03-25*

## Core Pattern

Obsidian vault = folder of markdown files. Any external process can read/write. Structured YAML frontmatter makes it queryable. Wikilinks make it a knowledge graph. PortReaper is the structured write layer.

## Integration Stack

### MCP Servers (AI Agent Access)
| Repo | Approach |
|------|----------|
| cyanheads/obsidian-mcp-server | REST API bridge, 8 tools, in-memory cache |
| jacksteamdev/obsidian-mcp-tools | Obsidian plugin, semantic search + Templater |
| iansinnott/obsidian-claude-code-mcp | Claude Code specific |

### Key Plugins
- **Dataview**: SQL-like queries over frontmatter. Live dashboards. DataviewJS for complex logic.
- **Templater**: Scripted templates, auto-apply on file creation, JS execution.
- **Tasks**: Vault-wide task tracking with queries, due dates, priorities.
- **Local REST API**: Full CRUD on vault files. PATCH for surgical edits. Bearer auth on localhost:27124.
- **Obsidian CLI (v1.12+)**: Official CLI, remote control running instance, rewrites wikilinks on move.

### Notion Sync
- Share to NotionNext plugin syncs folders to Notion databases
- Frontmatter fields map to Notion properties

## Programmatic Vault Access (Ranked)
1. **Obsidian CLI** (official, best) — remote control running instance
2. **Local REST API plugin** — HTTP endpoints, PATCH for surgical edits
3. **Direct filesystem writes** — works without Obsidian running, best for batch ops
4. **MCP servers** — wraps above for AI agent integration

## Security Research Community Patterns
- InsiderPhD/BugBountyKnowledgeBase — Obsidian vault template for bounty hunters
- PARA (Projects/Areas/Resources/Archive) for operational organization
- Zettelkasten for permanent knowledge network
- Hierarchical tags: #vuln/xss, #tool/burpsuite, #target/webapp
- Daily notes for engagement logging
- Frontmatter-based KPI tracking with Dataview aggregations

## Dataview Dashboard Examples

```dataview
TABLE platform, tvl, max_bounty, status, hours_invested
FROM "campaigns"
WHERE status != "archived"
SORT tvl DESC
```

```dataview
TABLE severity, vuln_class, status, confidence
FROM #finding
WHERE status = "investigating"
SORT confidence DESC
```

```dataviewjs
const findings = dv.pages('#finding').where(f => f.status === "accepted")
const total = findings.values.reduce((sum, f) => sum + (f.payout || 0), 0)
dv.paragraph(`**Total Earnings:** $${total.toLocaleString()}`)
```

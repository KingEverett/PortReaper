# PortReaper v2 Vision: Universal Security Tool → Obsidian Bridge

## Core Thesis

PortReaper's value isn't "nmap parser" — it's **structured vault generation from security tool output**. v2 extends this to accept output from any security tool, making PortReaper the universal write layer for an Obsidian-based security knowledge brain.

## Architecture

```
Input Formats:              PortReaper Core:           Vault Output:
  nmap XML (v1)    ──┐                                ┌── scans/
  slither JSON     ──┤     parse → normalize →        ├── campaigns/
  aderyn JSON      ──┤     enrich → generate          ├── findings/
  foundry logs     ──┤                                ├── cves/
  nuclei JSON      ──┤                                ├── technologies/
  manual entry     ──┘                                └── vuln-patterns/
```

Each new input format requires:
1. A parser (read tool's output format)
2. A mapper (convert to PortReaper's internal models)
3. Existing vault writer handles the rest

## Two-Brain Architecture

### Brain 1: Campaign Tracker (per-engagement)
Tracks active bounty campaigns — what we're testing, what we found, status, earnings.

```
campaigns/{protocol-name}/
├── _overview.md          (scope, assets, bounty tiers, platform, TVL)
├── findings/finding-001.md  (severity, vuln_class, status, confidence, payout)
├── sessions/2026-03-25.md   (work log — hours, what we examined)
├── scans/                   (PortReaper nmap output for infra assets)
└── notes/                   (manual research notes)
```

### Brain 2: Methodology Library (permanent knowledge base)
HOW to test different asset types. Grows forever, never archived.

```
asset-types/{type}/testing-workflow.md
asset-types/{type}/tools/{tool}.md
asset-types/{type}/checklists/{category}.md
vuln-patterns/{pattern}.md
platforms/{platform}.md
playbooks/{workflow}.md
```

### Connection
Wikilinks between brains. Finding a new oracle pattern → update vuln-patterns/oracle-manipulation.md → wikilink back to the campaign finding.

## Obsidian Ecosystem Integration

| Layer | Tool | Role |
|-------|------|------|
| Write | PortReaper CLI | Generates/updates structured vault notes |
| Query | Dataview plugin | Live dashboards from YAML frontmatter |
| AI Access | Obsidian MCP Server | Claude reads/writes/searches the vault |
| API | Local REST API plugin | External scripts update vault |
| Sync | Share to NotionNext | Optional Notion dashboard sync |

## New CLI Commands (Incremental)

```bash
# Campaign management
portreaper campaign init "aave-v3" --platform immunefi --tvl 12.5B
portreaper finding add "aave-v3" --severity high --class oracle-manipulation
portreaper finding update "aave-v3/finding-001" --status submitted
portreaper session log "aave-v3" --hours 4 --notes "Reviewed flash loan paths"

# Tool output imports (add as needed during real campaigns)
portreaper import slither report.json -o vault/campaigns/aave-v3/
portreaper import aderyn report.json -o vault/campaigns/aave-v3/
```

## KPI Tracking via Dataview

Frontmatter fields on campaign/finding notes enable live Dataview dashboards:

- **Target Pipeline**: status, tvl, max_bounty, hours_invested per campaign
- **Findings Board**: severity, vuln_class, status, confidence, payout per finding
- **Specialty Tracker**: acceptance rate by vuln_class and protocol category
- **Monthly Rollup**: earnings, submissions, acceptance rate (3-month rolling)

## Development Approach

Organic growth driven by actual hunting:
1. Start a bounty campaign manually
2. Run a tool, get output that needs to go into Obsidian
3. Add that parser to PortReaper
4. Repeat — each hunt naturally extends the tool

No speculative features. Build what's needed when it's needed.

## Revenue Target

$5-10K/month from Web3 bug bounties within 3-6 months, tracked via vault KPIs.

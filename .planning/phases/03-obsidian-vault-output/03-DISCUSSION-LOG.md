# Phase 3: Obsidian Vault Output - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-23
**Phase:** 03-obsidian-vault-output
**Areas discussed:** Vault folder structure, Wikilink topology, Note content & templates, Index & attack surface summary

---

## Vault Folder Structure

### Directory organization
| Option | Description | Selected |
|--------|-------------|----------|
| By type | hosts/, services/, cves/ directories — groups similar notes together | ✓ |
| By host | Each host gets a folder with its services inside | |
| Flat | All notes in one directory | |

**User's choice:** By type
**Notes:** None

### Multi-scan handling
| Option | Description | Selected |
|--------|-------------|----------|
| Single vault, scan subfolders | Each scan creates a subfolder. CVEs/technologies shared at top level. | ✓ |
| Per-scan vault, no sharing | Independent vaults per scan run | |
| Per-scan vault + shared reference vault | Separate reference vault for CVEs/technologies | |

**User's choice:** Single vault, scan subfolders
**Notes:** User specifically asked about cross-vault linking and consolidation — single vault model addresses this by making CVEs and technologies shared across all scans.

### Scan subfolder naming
| Option | Description | Selected |
|--------|-------------|----------|
| Date + target range | Auto-generated from scan metadata | ✓ |
| User-provided label via --label flag | User names each scan | |
| Just the date + incrementing number | Simple sequential naming | |

**User's choice:** Date + target range
**Notes:** None

### Technology notes
| Option | Description | Selected |
|--------|-------------|----------|
| Auto-generated with known data | Pre-populate with product, versions, instances, CVEs | ✓ |
| Stubs only | Just name and backlinks | |
| Skip technology notes | No technology/ directory | |

**User's choice:** Auto-generated with known data
**Notes:** None

---

## Wikilink Topology

### Link direction
| Option | Description | Selected |
|--------|-------------|----------|
| Downward + shared links | Host→service→CVE + CVE→affected services + technology links | ✓ |
| Bidirectional explicit | Every note links both directions explicitly | |
| Minimal (downward only) | Only host→service→CVE, rely on Obsidian backlinks | |

**User's choice:** Downward + shared links
**Notes:** None

### Link display text
| Option | Description | Selected |
|--------|-------------|----------|
| Aliased for readability | [[target\|human-friendly text]] | ✓ |
| Raw filenames | Plain [[filename]] everywhere | |
| Short aliases | Minimal display text | |

**User's choice:** Aliased for readability
**Notes:** None

### CVE backlinks
| Option | Description | Selected |
|--------|-------------|----------|
| Explicit 'Affected Services' section | CVE notes list all affected services | ✓ |
| Rely on Obsidian backlinks | No explicit reverse links | |

**User's choice:** Explicit 'Affected Services' section
**Notes:** None

---

## Note Content & Templates

### Host notes
| Option | Description | Selected |
|--------|-------------|----------|
| Full summary with tables | Frontmatter + port table + vuln summary + notes section | ✓ |
| Minimal with links | Just frontmatter + service list | |
| Detailed with inline CVEs | Everything in one note, no need for service notes | |

**User's choice:** Full summary with tables
**Notes:** None

### Service notes
| Option | Description | Selected |
|--------|-------------|----------|
| Structured template | Frontmatter + service info + CVE table + tech link + notes section | ✓ |
| Compact list | Frontmatter + bullet list of CVEs | |

**User's choice:** Structured template
**Notes:** None

### CVE notes
| Option | Description | Selected |
|--------|-------------|----------|
| Full detail with affected list | Frontmatter + description + affected services + references + notes | ✓ |
| Minimal with links | Just score, severity, one-line description, backlinks | |

**User's choice:** Full detail with affected list
**Notes:** None

---

## Index & Attack Surface Summary

### Global index
| Option | Description | Selected |
|--------|-------------|----------|
| Global dashboard | Severity breakdown, critical findings, scans list, hosts list | ✓ |
| Simple host list | Just hosts with highest severity | |
| Per-scan index only | No global index | |

**User's choice:** Global dashboard
**Notes:** None

### Per-scan index
| Option | Description | Selected |
|--------|-------------|----------|
| Yes, per-scan index | Each scan gets its own index with scan-specific stats | ✓ |
| No, global index is enough | Only global _index.md | |

**User's choice:** Yes, per-scan index
**Notes:** None

### CSS snippet
| Option | Description | Selected |
|--------|-------------|----------|
| Tag-based severity colors | Full color scheme: critical/high/medium/low + host/cve/technology | ✓ |
| Minimal (severity only) | Only critical/high/medium/low colors | |

**User's choice:** Tag-based severity colors
**Notes:** None

---

## Claude's Discretion

- Exact Obsidian graph CSS selector syntax
- YAML serialization struct design
- Scan label derivation from nmap XML metadata
- Internal module organization for vault generation
- Handling of zero-CVE services in templates
- CVE description truncation strategy

## Deferred Ideas

- Incremental vault updates — Phase 5 (OUT-08)
- Config file for default vault path — Phase 5 (ARCH-03)
- Cross-vault linking — revisit if single-vault model proves insufficient

# Feature Landscape

**Domain:** Pentest enumeration automation (nmap parsers, vuln lookup, report generation)
**Project:** PortReaper — Rust CLI, Obsidian vault output
**Researched:** 2026-03-20
**Confidence:** MEDIUM — Web search unavailable; based on training-data knowledge of the ecosystem (nmap-parse-output, Metasploit db_nmap, nmaptocsv, Dradis, Serpico, Lair, vulners, lazyrecon, AutoRecon, reconftw, nmapviz). Specific API behaviors and rate limits should be verified against live docs before implementation.

---

## Table Stakes

Features users expect. Missing = product feels incomplete or users reach for a different tool immediately.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Parse nmap XML (`-oX`) | nmap XML is the universal interchange format; all serious tools use it over grepable/text | Low | Well-documented DTD; quick_xml or roxmltree in Rust |
| Extract host/port/service/version tuple | The minimum useful data unit — every downstream action depends on this | Low | Must handle open, filtered, and closed states distinctly |
| CVSS score display per CVE | Users need severity signal immediately; raw CVE IDs alone are useless | Low | NVD provides CVSS v3.1/v4.0 in JSON API |
| Severity classification (critical/high/medium/low) | Prioritization is the whole point; testers work CVSS ≥ 7.0 first | Low | Derive from CVSS base score; CRITICAL ≥ 9.0, HIGH 7.0-8.9, MED 4.0-6.9, LOW < 4.0 |
| CVE lookup by service + version | Core value loop: version detected → CVEs queried automatically | Medium | CPE matching is the hard part; service name normalization required |
| Structured output per host | Testers need per-target notes, not a flat dump | Low | One markdown file per IP is the natural unit |
| Deduplicate findings | Same CVE from multiple sources must not appear twice | Low | Hash-set on CVE ID during collection |
| Graceful handling of API failures | APIs go down, rate-limit, return partial data — tool must not crash | Medium | Per-source error isolation; partial results are better than nothing |
| ExploitDB / SearchSploit cross-reference | Testers immediately want "is there a public exploit?" after seeing a CVE | Medium | SearchSploit CLI is local; ExploitDB has no clean public API — scraping or local mirror needed |
| Human-readable output at a glance | Enumeration phase is time-pressured; output must be scannable, not wall-of-JSON | Low | Severity badges, grouped by host, sorted by CVSS descending |

---

## Differentiators

Features that set the product apart. Not universally expected from existing tools, but meaningfully valued by the target user.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Obsidian vault with wikilinks | No existing tool produces Obsidian-native output; graph view maps perfectly to host→port→vuln hierarchy | Medium | YAML frontmatter + `[[wikilinks]]` + tag structure; graph emerges automatically |
| Severity-colored graph nodes | Obsidian graph CSS snippets + tags let users see the attack surface at a glance — no other enumeration tool does this | Low | Tags (#critical, #high, etc.) drive CSS; one snippet file in the vault |
| Pluggable data source architecture | Most tools hardcode one or two sources; pluggable design means PortReaper ages well as sources change | High | Trait-based abstraction in Rust; each source is a struct implementing `VulnSource` trait |
| Concurrent multi-source queries | Query all vuln sources in parallel per service, not sequentially — dramatically faster on large scans | Medium | Tokio async; rate-limit per source independently |
| Pipe-from-nmap stdin support | `nmap ... | portreaper` is ergonomic for quick assessments; most XML-centric tools require a saved file | Medium | Detect stdin vs file arg; nmap normal output is different from XML — must parse both formats |
| OSV.dev integration | OSV covers open-source software CVEs that NVD is slow to index; adds signal for targets running OSS stacks | Medium | OSV has a clean JSON API (osv.dev/docs); queries by package + version |
| PacketStorm Security integration | Broader exploit/advisory coverage than ExploitDB; rarely automated | High | No official API — HTML scraping with rate limiting; fragile, needs resilience layer |
| Service note template consistency | Every service note has the same structure (frontmatter, info table, vulns, links); ready to paste into a pentest report | Low | Template once, fill per service |
| Index note with attack surface summary | A single `_index.md` listing all hosts, total open ports, count of critical/high findings — triage at a glance | Low | Computed during output generation pass |
| CPE-based CVE matching | Use the CPE (Common Platform Enumeration) string nmap provides for more precise CVE lookups vs. fuzzy name matching | High | CPE parser in Rust; NVD CPE dictionary lookup; reduces false positives significantly |

---

## Anti-Features

Features to explicitly NOT build. Each one has a clear reason and a better alternative.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| Running nmap scans directly | Scope creep; nmap has 30 years of scan optimization we cannot replicate; complicates permissions/legal surface | Accept nmap output as input only — document the intended invocation pattern |
| Web UI / browser dashboard | Obsidian IS the UI; building a parallel web interface splits the codebase and duplicates work | Invest in Obsidian vault quality: better templates, better wikilink structure |
| Active exploitation / payload generation | Crosses from recon to attack; legal liability, out of scope for enumeration phase | Link to ExploitDB/SearchSploit entries; let the tester decide what to do with them |
| Storing or caching API results to a cloud backend | Pentest data is client-confidential; sending it anywhere is a serious trust violation | All data stays local: vault on disk, no telemetry, no cloud sync |
| Automatic severity override / risk scoring | Tools that invent their own scoring erode trust; testers know CVSS | Surface CVSS as-is; let the tester annotate |
| AI-generated remediation advice | Hallucinations in a security context are dangerous; testers need accurate information | Link to the official NVD advisory and any referenced CWE entries |
| Interactive TUI (curses-style) | Adds a large dependency surface (ratatui/crossterm), breaks pipe-ability, not needed for the enumeration workflow | Keep it a pure CLI: args in, vault out. Progress output to stderr so stdout can be piped |
| Per-user accounts / auth / licensing | This is a practitioner tool; auth adds friction for zero user-experience gain at this stage | Single-binary, no registration |
| Automatic nmap output ingestion from network paths (SMB, NFS) | Scope creep + security risk (SSRF-adjacent); the tool processes local files | Accept local file paths and stdin only |

---

## Feature Dependencies

```
nmap XML parsing
  └── host/port/service/version extraction
        ├── CPE normalization
        │     └── CVE lookup (NVD, CVE.org, OSV.dev, VulnDB)
        │           ├── CVSS score extraction
        │           │     └── severity classification
        │           │           └── severity tags (#critical/#high/...)
        │           └── deduplication (by CVE ID)
        │                 └── structured vuln list per service
        └── ExploitDB / SearchSploit cross-reference (by service name + version)
              └── exploit links in service notes

Service/version extraction
  └── pluggable VulnSource trait dispatch
        └── concurrent async queries (Tokio)
              └── per-source rate limiting
                    └── per-source error isolation

All collected data
  └── Obsidian vault generation
        ├── per-host markdown file ([[IP_address]].md)
        ├── per-service markdown file ([[service_version]].md)
        ├── YAML frontmatter (tags, severity, CVSS)
        ├── wikilinks connecting host → service → CVE → exploit
        ├── severity CSS snippet (_assets/severity.css)
        └── index summary note (_index.md)

stdin pipe support
  └── nmap text-format parser (separate from XML parser)
        └── feeds same extraction pipeline as XML path
```

---

## MVP Recommendation

Build the tight value loop first: parse → lookup → output. Everything else is enhancement.

**Prioritize for MVP:**
1. nmap XML parsing with host/port/service/version/CPE extraction
2. NVD API lookup (best free API; covers most CVEs with CVSS v3.1)
3. CVE.org lookup (complements NVD; official MITRE data)
4. Severity classification and deduplication
5. Obsidian vault generation: per-host files, per-service files, YAML frontmatter, wikilinks, index note
6. Severity tags + bundled CSS snippet

**Defer to post-MVP:**
- ExploitDB / SearchSploit integration — local SearchSploit is user-environment-dependent; ExploitDB scraping is fragile. Flag for Phase 2.
- OSV.dev — valuable but adds scope. Flag for Phase 2.
- PacketStorm Security — scraping-heavy, high maintenance. Flag for Phase 3 or as optional plugin.
- VulnDB — often commercial/gated. Verify access model before committing. Flag as low priority.
- stdin pipe from nmap text output — useful but XML (`-oX`) covers 90% of serious workflows. Flag for Phase 2.
- CPE-based precise matching — important for accuracy but adds implementation complexity. MVP can use service-name fuzzy matching with a clear "improve CPE matching" backlog item.

**MVP definition:** A tester runs `portreaper scan.xml` and gets an Obsidian vault they can immediately open, navigate by graph, and filter by severity. That proves the core value proposition.

---

## Sources

Note: Web search was unavailable for this research pass. Findings are based on training-data knowledge (cutoff August 2025) of the following tools and their documented feature sets:

- **AutoRecon** (github.com/Tib3rius/AutoRecon) — enumeration automation, multi-tool orchestration patterns
- **reconFTW** (github.com/six2dez/reconftw) — scope of data sources used by automation tools
- **nmap-parse-output** (github.com/ernw/nmap-parse-output) — nmap XML parsing patterns
- **Lair Framework** — vulnerability aggregation design patterns
- **Dradis / Serpico / PlexTrac** — pentest report generation, what structured output testers expect
- **vulners.com** — multi-source vuln aggregation, API design
- **NVD API documentation** (nvd.nist.gov/developers) — CVSS data availability
- **OSV.dev API** (google.osv.dev) — open-source vuln data structure
- **ExploitDB** (exploit-db.com) — no official API; scraping or local mirror (SearchSploit) is standard

**Confidence assessment:**

| Area | Confidence | Notes |
|------|------------|-------|
| Table stakes features | MEDIUM | These match observed patterns across 5+ enumeration tools; verify SearchSploit API behavior |
| Differentiators | MEDIUM | Obsidian output is novel — no evidence of prior art found in training data |
| Anti-features | HIGH | Conservative by design; all exclusions are also in PROJECT.md |
| Feature dependencies | MEDIUM | Pipeline ordering is logical; CPE matching complexity should be confirmed empirically |
| API availability | LOW | NVD, CVE.org, OSV.dev APIs confirmed functional as of knowledge cutoff; verify rate limits and auth requirements before implementation |

# Project Research Summary

**Project:** PortReaper
**Domain:** Pentest enumeration automation — nmap XML parsing, concurrent vulnerability API queries, Obsidian vault generation
**Researched:** 2026-03-20
**Confidence:** MEDIUM

## Executive Summary

PortReaper is a Rust CLI tool that occupies a clearly defined niche: accepting nmap scan output, enriching each discovered service with CVE data from multiple vulnerability databases, and producing an Obsidian vault as the primary output artifact. The core insight from research is that the product is a data pipeline, not an interactive application — input enters as nmap XML, gets enriched concurrently through async API calls, and exits as structured markdown files wired together with wikilinks. No comparable tool produces Obsidian-native output; this is the primary differentiator and all architectural decisions should protect and serve this output format.

The recommended approach is to build the tight value loop first: parse nmap XML accurately, query NVD and CVE.org for CVE data, classify by CVSS severity, and write a well-structured Obsidian vault. The pluggable `VulnSource` trait is the single most important design decision in the project — it must be locked in early because all data source work (current and future) depends on its interface. The async enrichment layer using tokio with bounded concurrency via `Semaphore` is non-negotiable; synchronous HTTP would produce unusably slow output on real engagements, and unbounded async spawning would exhaust file descriptors on any realistic pentest scan.

The dominant risks are silent data loss in three forms: nmap service fields are unreliable and must be treated as `Option<T>` throughout or queries produce garbage input with zero results; NVD API rate limits silently return empty responses if errors are conflated with empty result sets; and YAML frontmatter corrupted by unescaped CVE description text makes the vault appear broken in Obsidian. All three surface quietly — the tool appears to work while key data is missing. A typed error taxonomy distinguishing "no results found" from "query failed" is mandatory from the first working build, not a polish concern.

## Key Findings

### Recommended Stack

PortReaper's stack is all-Rust with well-established crate choices for each concern. The async story is tokio-first throughout: `#[tokio::main]`, `reqwest` for HTTP, `tokio::sync::Semaphore` for concurrency control, and `tokio::fs` for vault file writing. XML parsing uses `quick-xml` with serde deserialization — the right tool for nmap's structured XML, with the caveat that quick-xml has had API-breaking changes between minor versions and the pinned version must be verified on crates.io. A key stack enabler is that `async fn in trait` has been stable since Rust 1.75 (December 2023), removing the need for the `async-trait` proc-macro for the `VulnSource` plugin interface.

Error handling follows the canonical binary-crate pattern: `thiserror` for typed errors in the `VulnSource` trait (so callers can distinguish rate-limit from network failure from empty result), and `anyhow` at the binary boundary for rich context chaining. The `serde_yaml` library should be used for YAML frontmatter generation — not hand-rolled `format!` macros — because CVE descriptions contain YAML-significant characters. This is an internal inconsistency in the research (STACK.md tentatively suggested `format!` is sufficient; PITFALLS.md and ARCHITECTURE.md both argue for `serde_yaml`). The pitfall evidence is conclusive: use `serde_yaml`.

**Core technologies:**
- `tokio ~1.38`: async runtime — de-facto standard; multi-threaded scheduler required for concurrent API queries
- `clap ~4.5` (derive feature): CLI parsing — struct-based, self-documenting, v4 stable API
- `quick-xml ~0.36` + `serde ~1.0`: nmap XML parsing — streaming with serde deserialization; verify minor version before pinning
- `reqwest ~0.12` (rustls-tls): async HTTP client — tokio-native, TLS without system OpenSSL dependency for single-binary distribution
- `serde_json ~1.0`: API response deserialization — extremely stable, already transitive via reqwest
- `anyhow ~1.0` + `thiserror ~1.0`: error handling — `thiserror` for typed trait errors, `anyhow` at binary boundary
- `tracing ~0.1` + `tracing-subscriber ~0.3`: async-aware structured logging — spans survive await points; essential for debugging concurrent queries
- `indicatif ~0.17`: progress bars — concurrent queries against 6+ sources with no progress output is bad UX
- `toml ~0.8` + `directories ~5.0`: TOML config with OS-appropriate config dir — verify toml 0.8 (had breaking change from 0.7)
- `scraper ~0.19`: HTML scraping for ExploitDB/PacketStorm — LOW confidence; fragile by nature, defer to later phases

All versions are from training data (cutoff August 2025) and must be confirmed on crates.io before pinning.

### Expected Features

**Must have (table stakes):**
- Parse nmap XML (`-oX`) — universal interchange format; structured, richer than text formats
- Extract host/port/service/version/CPE tuples — minimum useful data unit; every downstream action depends on it
- CVE lookup by service + version — core value loop: version detected triggers automatic CVE query
- CVSS score display with severity classification (Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, Low < 4.0) — testers work highest severity first
- CVE deduplication across sources — same CVE from NVD and CVE.org must appear once
- Per-host and per-service structured Obsidian output with wikilinks
- Graceful API failure handling — partial results always preferred over tool crash
- ExploitDB/SearchSploit cross-reference — "is there a public exploit?" is the first question after seeing a CVE
- Human-readable scannable output — severity badges, sorted CVSS descending; enumeration is time-pressured

**Should have (differentiators):**
- Obsidian vault with wikilinks and graph connectivity — no existing tool produces Obsidian-native output
- Severity-colored graph nodes via CSS snippet and severity tags — visual attack surface mapping
- Pluggable `VulnSource` trait architecture — aging-proof; new sources add without touching orchestrator
- Concurrent multi-source queries via tokio — dramatically faster than sequential on large scans
- OSV.dev integration — covers open-source CVEs that NVD indexes slowly
- Index note (`_index.md`) with attack surface summary — triage across all hosts at a glance
- CPE-based CVE matching — more precise than keyword search; reduces false positives

**Defer (v2+):**
- stdin pipe from nmap text output — XML (`-oX`) covers 90% of serious workflows
- PacketStorm Security scraping — fragile, high maintenance; Phase 3 or optional plugin
- VulnDB integration — often commercial/gated; verify access model before scheduling
- API response caching — important for iterative use but not MVP-blocking

### Architecture Approach

PortReaper is a four-layer data pipeline: CLI layer (clap, input source detection) → Ingestion layer (format detection, XML parsing, normalized `ScanResult` model) → Enrichment layer (async orchestrator, `VulnSource` trait dispatch, concurrent queries with bounded concurrency, deduplication, merge) → Output layer (vault layout, markdown rendering with `serde_yaml` frontmatter, wikilinks, file writing). Data flows forward through normalized types only — no layer passes raw XML or raw API JSON to another layer. CVE notes live in a shared `vulns/` directory and are wikilinked from service notes, giving Obsidian's graph view a hub-and-spoke topology where a CVE node connects to all affected services — the key visualization value.

**Major components:**
1. `ingestion::xml_parser` — parses nmap `-oX` XML via quick-xml/serde into `ScanResult { Vec<Host> }`, capturing CPE strings and `<script>` elements as first-class fields on `Port`
2. `enrichment::orchestrator` — spawns tokio tasks per `(service, source)` pair bounded by `Semaphore`, merges results, deduplicates by CVE ID, produces `Vec<EnrichedHost>`
3. `enrichment::source` (trait) — `async fn query(&self, service: &Service) -> Result<Vec<Vulnerability>>` — the plugin interface; each source handles its own auth, rate limiting, and response parsing
4. `sources::{nvd, cve_org, osv, exploitdb, searchsploit}` — independent source modules; optional sources use `fn is_available() -> bool` for graceful skip
5. `output::renderer` — renders `EnrichedHost` → markdown strings with `serde_yaml` frontmatter, wikilinks routed through `sanitize_filename()`
6. `output::vault` — plans flat directory structure (`_index.md`, `hosts/`, `services/`, `vulns/`) with stable unique filenames
7. `config` — TOML config from OS config dir; controls enabled sources, API keys, rate limits, concurrency cap

### Critical Pitfalls

1. **nmap service fields are unreliable, not guaranteed** — `product`, `version`, and `extrainfo` are absent or malformed for embedded devices, filtered ports, and vendor-mangled banners. All must be `Option<String>`. A query normalization layer must strip version suffixes (e.g., `p1`, `~dfsg`) before API submission. Silent zero-result failures are the consequence — the worst failure mode for a security tool. Resolve in XML parsing design before any API work.

2. **NVD rate limits silently produce false negatives** — 5 req/30s without API key; 50 req/30s with one. If HTTP errors return `Vec::new()` instead of a typed `QueryError::RateLimited`, the tool reports no vulnerabilities for rate-limited services. Distinguish `Empty` from `Error(RateLimited)` from `Error(NetworkFailure)` in the return type from the start. Retry 429s with exponential backoff.

3. **Unbounded async task spawning exhausts file descriptors** — a 500-port scan against 7 sources spawns 3,500 concurrent HTTP requests. Use `tokio::sync::Semaphore` with a configurable cap (default 10–20) from the initial enrichment design. This cannot be cleanly retrofitted.

4. **YAML frontmatter corrupted by CVE description text** — CVE descriptions contain colons, double quotes, and newlines. Hand-rolled `format!` macros produce malformed frontmatter that Obsidian silently fails to render. Use `serde_yaml` for frontmatter serialization from day one.

5. **Obsidian wikilinks break on special characters in filenames** — IP addresses (dots), IPv6 addresses (colons, brackets), and service names with slashes produce illegal filenames or ambiguous wikilinks. Define a canonical `sanitize_filename()` function before writing any file-generation code; route both filename construction and wikilink generation through it always.

6. **ExploitDB and PacketStorm have no stable API** — any HTML scraper will break silently when their structure changes. For ExploitDB, use the local `searchsploit` binary (`--json` flag) as the primary interface; fall back to scraping only if absent. PacketStorm scraping should be marked experimental with visible warnings in output.

## Implications for Roadmap

Based on the architecture's dependency ordering and pitfall phase warnings, a five-phase structure is recommended.

### Phase 1: Foundation — Data Models, XML Parsing, CLI Skeleton

**Rationale:** All other layers depend on the normalized `ScanResult` and `Vulnerability` models. Validating the internal model against real nmap output before any API work prevents expensive data model retrofits. Several pitfalls require architectural decisions in this phase that are nearly impossible to retrofit cleanly: optional service fields, the `sanitize_filename()` function, CVSS version typing, and the `serde_yaml` vs `format!` decision.

**Delivers:** A binary that accepts an nmap XML file, parses it fully (including `<script>` elements and CPE strings), prints a structured summary to stdout. No network calls.

**Features addressed:** nmap XML parsing, host/port/service/version/CPE extraction, port state filtering (open only by default), UDP protocol support, stdin TTY detection, clear error on wrong file format

**Pitfalls to address:** Pitfall 1 (all service fields as `Option<T>`), Pitfall 2 (model `<script>` as first-class field on `Port`), Pitfall 5 (define `sanitize_filename()` before any file-write code), Pitfall 9 (filter only `state="open"` and `state="open|filtered"` by default), Pitfall 17 (carry `protocol` field on `Port` from day one)

### Phase 2: Enrichment Core — VulnSource Trait, NVD + CVE.org, Async Architecture

**Rationale:** The `VulnSource` trait interface is the most critical design decision in the project. It must be established and validated against two sources before adding more. NVD and CVE.org are the two highest-priority free JSON APIs. This phase also establishes the typed error taxonomy and bounded concurrency model that all subsequent sources inherit.

**Delivers:** End-to-end enrichment: parse → query NVD + CVE.org concurrently → deduplicate → classify severity → print enriched findings. Rate limiting, retry logic, and typed errors are production-quality from this phase.

**Features addressed:** NVD API integration, CVE.org integration, CVSS v3.1/v4.0 scoring with version labeling, severity classification, CVE deduplication, concurrent multi-source queries, per-source rate limiting, configurable concurrency cap

**Pitfalls to address:** Pitfall 3 (typed error distinguishing Empty from RateLimited from NetworkFailure), Pitfall 4 (CPE/version normalization layer with test corpus), Pitfall 6 (bounded concurrency with `Semaphore` before any live API calls), Pitfall 10 (always label CVSS version alongside score)

### Phase 3: Obsidian Vault Output

**Rationale:** Once enriched data exists, the output layer can be built and tested against mock `EnrichedHost` values without network calls. The flat vault structure decision must be made before the first file-write line — a structural rewrite later is expensive.

**Delivers:** Full end-to-end run: `portreaper scan.xml` produces an Obsidian vault ready to open, with per-host notes, per-service notes, shared CVE notes in `vulns/`, wikilinks, `serde_yaml` frontmatter, severity tags, bundled CSS snippet, and `_index.md` summary.

**Features addressed:** Per-host markdown files, per-service markdown files, shared CVE notes, YAML frontmatter, wikilinks, severity tags (#critical/#high/#medium/#low), CSS snippet for graph coloring, `_index.md` with attack surface summary

**Pitfalls to address:** Pitfall 5 (all filenames and wikilinks through `sanitize_filename()`), Pitfall 7 (use `serde_yaml`; never `format!` for YAML), Pitfall 13 (flat vault structure; wikilinks use filename stem only), Pitfall 16 (truncate CVE descriptions ≤ 80 chars in table cells)

### Phase 4: Additional Sources, Exploit Cross-Reference, and Caching

**Rationale:** With the trait, orchestrator, and output fully established, new sources are isolated additions that do not touch any existing code. SearchSploit (local binary, `--json` flag) and OSV.dev (clean JSON API) are highest priority. Response caching must arrive before the tool is used iteratively on real engagements — repeated full re-queries against the same scan XML burn rate limit quota and take minutes.

**Delivers:** Exploit cross-references in service notes, OSV.dev coverage for open-source stacks, local SearchSploit integration (graceful skip if binary absent), local response cache (SQLite or directory cache) keyed on `(source, query)`, `--no-cache`/`--clear-cache` flags.

**Features addressed:** ExploitDB/SearchSploit integration, OSV.dev integration, API response caching, `--concurrency` CLI flag, per-source health check (`--health-check`)

**Pitfalls to address:** Pitfall 8 (searchsploit-first; scraping as degraded fallback with explicit warning), Pitfall 11 (stdin TTY detection before read attempt), Pitfall 14 (caching as part of initial architecture, not afterthought)

### Phase 5: Config, Polish, and Optional Sources

**Rationale:** PacketStorm scraping is high-maintenance and explicitly experimental. VulnDB requires verifying API access model before any implementation commitment. These belong after the core product is stable and delivering value. Full TOML config and source health checks finalize the operational experience.

**Delivers:** Full TOML config file support with OS-appropriate path, API key management, `--health-check` command per source, PacketStorm as optional experimental plugin (with output warnings), VulnDB integration (conditional on confirmed API access), large-scan stress testing.

**Features addressed:** Source enable/disable via config, health check per source, PacketStorm (experimental), VulnDB (conditional)

**Pitfalls to address:** Pitfall 12 (streaming XML parser for large files if not already using quick-xml in streaming mode), Pitfall 15 (clear error message on wrong file format if not done in Phase 1)

### Phase Ordering Rationale

- Models before parsers, parsers before enrichment, enrichment before output — this is the pipeline dependency order and cannot be inverted without building on unvalidated assumptions.
- The `VulnSource` trait must be locked in before implementing any source; the interface affects every source permanently.
- Obsidian vault output (Phase 3) can be built and tested with mock data without waiting for Phase 4 sources, so it does not block on additional integrations.
- Caching (Phase 4) must arrive before the tool is used iteratively — moving it to Phase 5 produces an unusable development workflow during any real engagement.
- PacketStorm and VulnDB are last because they carry the highest implementation uncertainty and lowest research confidence.

### Research Flags

Phases likely needing `/gsd:research-phase` deeper research during planning:
- **Phase 2:** NVD API 2.0 current rate limits and auth requirements should be verified against live docs before implementation. CPE normalization strategy needs an empirical spike against a corpus of real diverse nmap output — not just clean lab scans.
- **Phase 4:** SearchSploit `--json` flag behavior and local DB format must be confirmed before designing the integration. OSV.dev batch API endpoint structure should be verified to determine whether per-service queries can be collapsed into one request per scan.
- **Phase 5:** PacketStorm HTML structure and VulnDB API access model are both LOW confidence from research. Live investigation required before any implementation begins.

Phases with standard patterns (skip research-phase):
- **Phase 1:** nmap XML schema is stable and well-documented; quick-xml + serde deserialization is a known, established pattern. Pitfall catalog for this phase is HIGH confidence.
- **Phase 3:** Obsidian YAML frontmatter and wikilink conventions are stable and documented. `serde_yaml` serialization is standard. File-writing with tokio::fs is straightforward.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM | Core choices (tokio, clap, reqwest, serde) are highly stable. All versions are from training data (cutoff August 2025); must be verified on crates.io. scraper and toml versions are LOW confidence. |
| Features | MEDIUM | Table stakes and differentiators derived from analysis of 5+ enumeration tools in training data. Obsidian output is novel — no prior art found. API-specific behaviors (rate limits, auth requirements) must be verified live. |
| Architecture | MEDIUM | Four-layer pipeline pattern and `VulnSource` trait design are sound Rust async idioms. Obsidian wikilink resolution rules are HIGH confidence. NVD API schema changes would affect only `sources::nvd`. |
| Pitfalls | MEDIUM-HIGH | nmap XML quirks (optional fields, script elements, port states) are HIGH confidence from DTD knowledge. NVD rate limits are MEDIUM (verify current values). Obsidian wikilink/filename behavior is HIGH confidence. Scraping fragility is HIGH confidence by nature. |

**Overall confidence:** MEDIUM

### Gaps to Address

- **NVD API rate limits and key registration:** Research cites 5 req/30s unauthenticated and 50 req/30s with a free API key. Verify current values at https://nvd.nist.gov/developers/vulnerabilities before setting default semaphore bounds. Register for a key immediately — it is free and eliminates the most common failure mode.
- **SearchSploit `--json` flag:** Confirm that the installed searchsploit version supports `--json` output and verify the output schema before designing the ExploitDB integration.
- **OSV.dev batch endpoint:** OSV supports batch queries by package+version. Verify the batch API endpoint and request schema to determine if per-service queries can be collapsed into one request per scan.
- **CPE normalization empirical validation:** The correct heuristics for stripping version suffixes (`p1`, `~dfsg`, `+deb11u2`) need a test corpus of real diverse nmap scan output. Build this corpus during Phase 1 before any API work.
- **PacketStorm API/RSS:** Check whether PacketStorm offers an RSS feed or undocumented JSON endpoint before committing to HTML scraping. This could substantially reduce maintenance burden.
- **serde_yaml vs format! decision:** STACK.md and PITFALLS.md are inconsistent on this point. The correct answer is `serde_yaml` — the pitfall evidence is conclusive. This is resolved in this summary and should not be revisited.
- **VulnDB access model:** Verify whether VulnDB requires a commercial API key before scheduling Phase 5 work. If it does, deprioritize or remove from scope.

## Sources

### Primary (MEDIUM confidence — training data, well-established domain knowledge)
- nmap XML DTD and output format documentation — nmap.org/book/output-formats-xml-output.html
- NVD API 2.0 — nvd.nist.gov/developers/vulnerabilities
- OSV.dev API — osv.dev/docs
- Rust async ecosystem: tokio, reqwest, async fn in trait (stable Rust 1.75+) — training knowledge cutoff August 2025
- Obsidian vault conventions: wikilinks, YAML frontmatter, graph view — help.obsidian.md

### Secondary (MEDIUM confidence — tool behavior from training data)
- AutoRecon (github.com/Tib3rius/AutoRecon) — enumeration automation patterns, multi-tool orchestration
- reconFTW (github.com/six2dez/reconftw) — data source scope used by automation tools
- nmap-parse-output (github.com/ernw/nmap-parse-output) — nmap XML parsing patterns
- Dradis / Serpico / PlexTrac — structured output expectations for pentest reporting tools
- Lair Framework — vulnerability aggregation design patterns
- vulners.com — multi-source vuln aggregation, API design reference

### Tertiary (LOW confidence — needs live verification before implementation)
- ExploitDB searchsploit `--json` flag behavior and output schema — verify version support
- PacketStorm HTML structure and any available API or RSS feed — pre-scraping investigation required
- VulnDB API access model and pricing — confirm before scheduling
- Current crate versions: quick-xml, reqwest, toml, directories, scraper — all from training data

---
*Research completed: 2026-03-20*
*Ready for roadmap: yes*

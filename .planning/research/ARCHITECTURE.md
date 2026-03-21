# Architecture Patterns

**Domain:** Pentest enumeration automation tool (nmap parsing, vuln lookup, Obsidian vault generation)
**Researched:** 2026-03-20
**Confidence:** MEDIUM — based on training knowledge of Rust CLI tool patterns, nmap data formats, and async HTTP architecture. WebSearch unavailable; web verification not performed.

---

## Recommended Architecture

PortReaper is a pipeline tool: data enters as nmap output, gets enriched through concurrent API queries, and exits as an Obsidian vault. The architecture follows a clean pipeline pattern with four distinct layers.

```
┌─────────────────────────────────────────────────────────────────┐
│                          CLI Layer                              │
│         clap argument parsing, input source selection           │
└──────────────────────────────┬──────────────────────────────────┘
                               │ raw bytes (stdin or file path)
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Ingestion Layer                          │
│   Input Router → XML Parser   or   Grepable/Text Parser         │
│                         ↓                                       │
│              Normalized ScanResult model                        │
└──────────────────────────────┬──────────────────────────────────┘
                               │ Vec<Host> with services + versions
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Enrichment Layer                            │
│   Query Orchestrator (async, bounded concurrency)               │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│   │ CVE.org  │ │  NVD     │ │ OSV.dev  │ │ExploitDB │  ...     │
│   │ Source   │ │ Source   │ │ Source   │ │ Source   │          │
│   └──────────┘ └──────────┘ └──────────┘ └──────────┘          │
│         ↓           ↓           ↓             ↓                 │
│              Merged EnrichedService model                       │
└──────────────────────────────┬──────────────────────────────────┘
                               │ Vec<EnrichedHost> with vuln data
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Output Layer                             │
│   Vault Layout Planner → Markdown Renderer → File Writer        │
│   (wikilinks, YAML frontmatter, severity tags, index notes)     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Boundaries

| Component | Responsibility | Communicates With |
|-----------|---------------|-------------------|
| `cli` (main.rs / cli.rs) | Argument parsing (clap), input source detection (file vs stdin), config loading, orchestrates top-level flow | Ingestion Layer, Output Layer |
| `ingestion::router` | Detects input format (XML vs grepable text vs piped text), routes to correct parser | XML parser, text parser |
| `ingestion::xml_parser` | Parses nmap `-oX` XML using quick-xml or roxmltree, extracts hosts/ports/services/scripts | ScanResult model |
| `ingestion::text_parser` | Parses nmap `-oN`/`-oG` text output or piped stdout, handles gnmap format | ScanResult model |
| `models::scan` | Normalized data models: `ScanResult`, `Host`, `Port`, `Service`, `ScriptOutput` | All layers |
| `models::vuln` | Vulnerability data models: `Vulnerability`, `CvssScore`, `Severity`, `Exploit` | Enrichment, Output |
| `enrichment::orchestrator` | Spawns concurrent tasks per service, collects results, handles failures gracefully | All Source impls |
| `enrichment::source` (trait) | `VulnSource` trait: `async fn query(&self, service: &Service) -> Result<Vec<Vulnerability>>` | Implemented by each source |
| `sources::nvd` | NVD 2.0 API client, parses CVSS scores from response | `VulnSource` trait |
| `sources::cve_org` | CVE.org API client | `VulnSource` trait |
| `sources::osv` | OSV.dev API client (batch-capable) | `VulnSource` trait |
| `sources::exploitdb` | ExploitDB API or web scraper | `VulnSource` trait |
| `sources::searchsploit` | Shells out to local `searchsploit` binary (optional, graceful skip if absent) | `VulnSource` trait |
| `sources::packetstorm` | PacketStorm web scraper (reqwest + scraper crate) | `VulnSource` trait |
| `sources::vulndb` | VulnDB API client | `VulnSource` trait |
| `output::vault` | Plans Obsidian vault directory structure, delegates rendering | Markdown renderer, file writer |
| `output::renderer` | Renders `EnrichedHost` → markdown strings with YAML frontmatter, wikilinks, severity tags | File writer |
| `output::file_writer` | Writes files to disk, creates directories, handles overwrite behavior | Filesystem |
| `config` | Loads user config (API keys, rate limits, enabled sources, output path) from TOML file | CLI, all sources |
| `error` | Unified error type (thiserror), propagated via `anyhow` at binary boundary | All modules |

---

## Data Flow

### Phase 1 — Ingestion

```
stdin / file
     │
     ▼
InputRouter::detect_format()
     │
     ├─ XML detected ──→ XmlParser::parse() ──→ ScanResult
     └─ text detected ─→ TextParser::parse() ──→ ScanResult
```

`ScanResult` contains:
- `Vec<Host>` — each host has IP, hostname, OS detection
- Each `Host` has `Vec<Port>` — port number, protocol, state
- Each `Port` has `Option<Service>` — name, product, version, extrainfo, CPE strings
- Each `Port` has `Vec<ScriptOutput>` — nmap NSE script results (useful for vuln scripts)

Key detail: nmap XML is rich — CPE strings (`cpe:/a:apache:http_server:2.4.51`) enable precise CVE lookup. The parser must extract CPE strings from `<cpe>` elements inside `<service>` elements.

### Phase 2 — Enrichment

```
ScanResult
     │
     ▼
Orchestrator::enrich(scan: ScanResult, sources: Vec<Box<dyn VulnSource>>)
     │
     ├─ For each Host → for each Port with Service:
     │       ├─ Spawn tokio task per (service, source) pair
     │       │       └─ source.query(service).await → Vec<Vulnerability>
     │       └─ Collect with tokio::task::JoinSet or futures::join_all
     │
     └─ Merge all Vulnerability results into EnrichedService
          → deduplicate by CVE ID
          → compute max severity across all sources
          → attach exploit references
          → produce EnrichedHost { host, Vec<EnrichedPort> }
```

Concurrency model: use `tokio::sync::Semaphore` to bound simultaneous HTTP requests (e.g., max 20 in-flight). Rate limiting per source should be per-source (NVD has a strict rate limit; OSV is more lenient). Sources that are unavailable or return errors should not abort the run — log and continue.

### Phase 3 — Output Generation

```
Vec<EnrichedHost>
     │
     ▼
VaultPlanner::plan(hosts, project_name, output_dir)
     │ → directory tree: output_dir/project_name/{index,hosts,services,vulns}/
     │
     ▼
Renderer::render_index(hosts) → project_index.md
Renderer::render_host(host) → {ip}.md
Renderer::render_port(host, port) → {ip}_{port}.md
Renderer::render_vuln(vuln) → CVE-XXXX-XXXXX.md  (deduped, shared across hosts)
     │
     ▼
FileWriter::write_all(rendered_files, output_dir)
```

Output vault structure:
```
output/PortReaper-{project}/
├── _index.md                    ← project root, links to all hosts
├── hosts/
│   ├── 192.168.1.1.md           ← host note, links to ports
│   └── 192.168.1.2.md
├── services/
│   ├── 192.168.1.1_80_http.md   ← service note with vuln table
│   └── 192.168.1.1_443_https.md
└── vulns/
    ├── CVE-2021-41773.md        ← shared vuln note, backlinked from services
    └── CVE-2021-44228.md
```

Wikilink pattern: `[[192.168.1.1]]`, `[[CVE-2021-41773]]` — Obsidian resolves by filename, so filenames must be stable and unique.

---

## Patterns to Follow

### Pattern 1: Trait Object Plugin Architecture for Data Sources

**What:** Define `VulnSource` as an async trait. Each data source implements it independently. The orchestrator holds `Vec<Box<dyn VulnSource>>`. New sources are added by implementing the trait and registering in config.

**When:** Any time a data source is added, removed, or swapped.

**Example:**

```rust
// In enrichment/source.rs
#[async_trait::async_trait]
pub trait VulnSource: Send + Sync {
    fn name(&self) -> &'static str;
    async fn query(&self, service: &Service) -> Result<Vec<Vulnerability>>;
    fn is_available(&self) -> bool { true }  // override for optional sources
}

// In sources/nvd.rs
pub struct NvdSource {
    client: reqwest::Client,
    api_key: Option<String>,
    rate_limiter: Arc<RateLimiter>,
}

#[async_trait::async_trait]
impl VulnSource for NvdSource {
    fn name(&self) -> &'static str { "NVD" }
    async fn query(&self, service: &Service) -> Result<Vec<Vulnerability>> {
        // NVD 2.0 API call using service.cpe or service.product + service.version
    }
}
```

**Why this pattern:** Enables adding sources without touching orchestrator or output code. Sources can be enabled/disabled at runtime via config. Test doubles are trivial.

### Pattern 2: Bounded Concurrency with Semaphore

**What:** Use `tokio::sync::Semaphore` with a configurable permit count to prevent overwhelming APIs or the network.

**When:** The orchestrator spawns tasks across all (host, port, source) combinations — this can be hundreds of tasks. Without bounding, NVD will rate-limit and PacketStorm may block.

**Example:**

```rust
let semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests)); // default: 10
let mut join_set = JoinSet::new();

for (service, source) in queries {
    let permit = Arc::clone(&semaphore);
    let source = Arc::clone(&source);
    join_set.spawn(async move {
        let _permit = permit.acquire().await?;
        source.query(&service).await
    });
}

while let Some(result) = join_set.join_next().await {
    // collect results
}
```

### Pattern 3: Normalized Internal Model — Parse Once, Enrich Anywhere

**What:** After parsing, ALL data lives in the normalized internal model (`models::scan`, `models::vuln`). No layer passes raw nmap XML or raw API JSON to another layer. Each layer only consumes the normalized types.

**When:** Always. The parser emits `ScanResult`. The enricher consumes `ScanResult`, emits `EnrichedScanResult`. The renderer consumes `EnrichedScanResult`.

**Why:** Decouples format concerns from logic. If nmap adds a new XML element, only the parser changes. If NVD changes their API schema, only `sources::nvd` changes. The renderer is never touched in either case.

### Pattern 4: CPE-First Vulnerability Lookup with Version Fallback

**What:** When a `<service>` element in nmap XML contains a `<cpe>` string, use it as the primary query term for vuln databases (most support CPE-based search). When no CPE is available, fall back to `product + version` keyword search.

**When:** During enrichment phase, per service.

**Why:** CPE (Common Platform Enumeration) provides standardized identifiers that map directly to CVE records. Keyword search produces more false positives. NVD's API v2.0 accepts CPE names directly.

### Pattern 5: Deduplication at Merge Time

**What:** Multiple sources may return the same CVE. Deduplicate by CVE ID in the orchestrator after collecting all source results. Prefer the record with the highest CVSS score or most complete data (NVD record > others).

**When:** Orchestrator `merge()` step.

**Why:** A service might appear in both NVD and CVE.org results as the same CVE. Duplicate vuln notes in Obsidian would confuse the graph view.

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Parsing API Responses in the Orchestrator

**What goes wrong:** The orchestrator receives raw JSON from each source and parses it into `Vulnerability` structs inline.

**Why bad:** Orchestrator grows to understand every API's schema. Adding a source means modifying orchestrator logic. Testing requires mocking at the JSON level.

**Instead:** Each source's `query()` method is responsible for parsing its own API response and returning `Vec<Vulnerability>`. The orchestrator only sees normalized types.

### Anti-Pattern 2: Synchronous HTTP in a Sync Main

**What goes wrong:** Using `reqwest::blocking` because it's simpler to start with.

**Why bad:** With 7 sources queried for potentially dozens of services, synchronous requests will take minutes instead of seconds. Blocking in a tokio context causes hangs.

**Instead:** Use `reqwest` async from the start (not blocking). Wrap main in `#[tokio::main]`. The performance difference is 10-50x for this workload.

### Anti-Pattern 3: One Markdown File Per CVE Per Host

**What goes wrong:** CVE-2021-44228 appears in `192.168.1.1_443_log4j.md` AND `192.168.1.2_8080_log4j.md` as duplicated content.

**Why bad:** Obsidian graph shows the CVE as two disconnected nodes. Searching for the CVE finds multiple files. Updates need to be applied in multiple places.

**Instead:** CVE notes live in `vulns/CVE-XXXX-XXXXX.md` once. Service notes wikilink to the CVE note: `[[CVE-2021-44228]]`. Obsidian's graph then shows the CVE as a hub connected to all affected services — exactly the desired visualization.

### Anti-Pattern 4: Aborting on Source Failure

**What goes wrong:** If NVD returns a rate-limit 429, the entire run fails.

**Why bad:** External APIs are unreliable. A pentest engagement can't be blocked because PacketStorm is down.

**Instead:** Each source failure is logged as a warning with the source name and error. The orchestrator continues with results from other sources. The output notes which sources succeeded and which were skipped.

### Anti-Pattern 5: Hardcoded Source List

**What goes wrong:** Sources are imported and instantiated directly in `main.rs` with no way to disable them.

**Why bad:** User may not have a VulnDB API key. Disabling a source requires recompiling. Adding a new source requires touching main.rs.

**Instead:** Sources are registered in config (TOML): `enabled_sources = ["nvd", "cve_org", "osv"]`. Orchestrator builds `Vec<Box<dyn VulnSource>>` from config at startup. Optional sources (SearchSploit) check binary presence at startup via `is_available()`.

---

## Scalability Considerations

| Concern | Small scan (5 hosts) | Medium scan (50 hosts) | Large scan (500+ hosts) |
|---------|---------------------|----------------------|------------------------|
| API rate limits | Rarely hit | NVD will throttle without API key | NVD requires API key; OSV batch API preferred; cache layer needed |
| Concurrency | Default semaphore (10) fine | Default fine | Increase semaphore; add per-source rate limiters |
| Memory | Trivial | Trivial | Stream parsing for XML if >100MB files |
| Output files | Trivial | ~200-500 files, fine | 5000+ files; vault planner must not load all into memory at once |
| Deduplication | Simple HashMap | Simple HashMap | Consider SQLite intermediate store |

For the initial implementation, nmap scans in penetration testing rarely exceed 50 hosts in a targeted engagement. The architecture described handles this range without special casing. Flag the 500+ host scenario as a future concern.

---

## Module Structure (Suggested Cargo Layout)

```
src/
├── main.rs               ← clap setup, tokio::main, top-level orchestration
├── cli.rs                ← argument structs, input source enum
├── config.rs             ← Config struct, TOML deserialization
├── error.rs              ← unified error type (thiserror)
├── models/
│   ├── mod.rs
│   ├── scan.rs           ← ScanResult, Host, Port, Service, ScriptOutput
│   └── vuln.rs           ← Vulnerability, CvssScore, Severity, Exploit, EnrichedHost
├── ingestion/
│   ├── mod.rs
│   ├── router.rs         ← format detection, dispatch
│   ├── xml_parser.rs     ← nmap XML (-oX) parser
│   └── text_parser.rs    ← nmap grepable/text (-oG/-oN) parser
├── enrichment/
│   ├── mod.rs
│   ├── orchestrator.rs   ← concurrent query dispatch, merge, dedup
│   └── source.rs         ← VulnSource trait definition
├── sources/
│   ├── mod.rs
│   ├── nvd.rs
│   ├── cve_org.rs
│   ├── osv.rs
│   ├── exploitdb.rs
│   ├── searchsploit.rs   ← shells out to local binary
│   ├── packetstorm.rs    ← web scraper
│   └── vulndb.rs
└── output/
    ├── mod.rs
    ├── vault.rs          ← directory structure planning
    ├── renderer.rs       ← markdown generation, frontmatter, wikilinks
    └── file_writer.rs    ← disk I/O
```

---

## Suggested Build Order

Dependencies flow bottom-up. Build in this order:

1. **`error.rs` + `models/`** — All other modules depend on these types. Build first, test nothing depends on external I/O.

2. **`ingestion/`** — Depends only on models. Can be tested with real nmap output files (no network). This is the critical path for validating the internal model design.

3. **`enrichment/source.rs` (trait only)** — Define the `VulnSource` trait before implementing any sources. This locks the interface that all sources must satisfy.

4. **`sources/nvd.rs` + `sources/osv.rs`** — Start with the two most important sources (free, JSON APIs, well-documented). Validates the async HTTP pattern and rate limiting approach.

5. **`enrichment/orchestrator.rs`** — Depends on the trait and at least one source. Build concurrency and merge logic with NVD + OSV as the test subjects.

6. **`output/`** — Depends on enriched models. Can be tested by constructing mock `EnrichedHost` values directly, no network needed.

7. **`config.rs` + `cli.rs`** — Wire everything together. Add remaining sources (`sources/cve_org.rs`, `sources/exploitdb.rs`, etc.) as parallel work after step 4 pattern is established.

8. **`sources/searchsploit.rs` + `sources/packetstorm.rs`** — Last, because SearchSploit requires local binary (system dependency) and PacketStorm requires scraping (fragile, may need iteration).

**Key dependency insight:** The `VulnSource` trait in step 3 is the most important design decision. Getting that interface right (what does `query()` receive? what does it return?) determines how easily new sources are added throughout the project's life. Spend design time here before writing any source implementation.

---

## Data Model Detail

### Core scan models

```rust
pub struct ScanResult {
    pub scanner: String,         // "nmap"
    pub start_time: Option<DateTime<Utc>>,
    pub hosts: Vec<Host>,
}

pub struct Host {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub os_matches: Vec<OsMatch>,
    pub ports: Vec<Port>,
    pub status: HostStatus,      // Up / Down
}

pub struct Port {
    pub number: u16,
    pub protocol: Protocol,      // Tcp / Udp
    pub state: PortState,        // Open / Closed / Filtered
    pub service: Option<Service>,
    pub scripts: Vec<ScriptOutput>,
}

pub struct Service {
    pub name: String,            // "http", "ssh", "ftp"
    pub product: Option<String>, // "Apache httpd"
    pub version: Option<String>, // "2.4.51"
    pub extra_info: Option<String>,
    pub cpe: Vec<String>,        // ["cpe:/a:apache:http_server:2.4.51"]
    pub tunnel: Option<String>,  // "ssl" for HTTPS
}
```

### Vulnerability model

```rust
pub struct Vulnerability {
    pub cve_id: Option<String>,    // "CVE-2021-41773"
    pub source: String,            // "NVD", "CVE.org", etc.
    pub title: Option<String>,
    pub description: Option<String>,
    pub cvss_v3: Option<CvssScore>,
    pub cvss_v2: Option<CvssScore>,
    pub severity: Severity,        // derived from CVSS
    pub exploits: Vec<ExploitRef>,
    pub references: Vec<String>,
    pub published: Option<NaiveDate>,
}

pub enum Severity { Critical, High, Medium, Low, Informational, Unknown }

pub struct CvssScore {
    pub score: f32,               // 0.0 - 10.0
    pub vector: Option<String>,   // CVSS vector string
}

pub struct ExploitRef {
    pub source: String,           // "ExploitDB", "PacketStorm"
    pub id: Option<String>,       // "EDB-ID: 50383"
    pub url: String,
    pub title: Option<String>,
}
```

---

## Key External Libraries (Rust)

| Purpose | Library | Rationale |
|---------|---------|-----------|
| XML parsing | `quick-xml` | Zero-copy, streaming, handles large nmap XML files |
| Async runtime | `tokio` | De facto standard, required by reqwest |
| HTTP client | `reqwest` | Async, TLS, JSON, cookie handling for scraping |
| HTML scraping | `scraper` | CSS selector-based, used for ExploitDB/PacketStorm |
| CLI args | `clap` (derive) | Ergonomic, derive macros, `clap = { features = ["derive"] }` |
| Serialization | `serde` + `serde_json` + `toml` | JSON API responses + TOML config |
| Async traits | `async-trait` | Required until async fn in traits stabilizes |
| Error handling | `thiserror` + `anyhow` | thiserror for library errors, anyhow at binary boundary |
| Date/time | `chrono` | Parsing nmap timestamps, CVE published dates |
| IP addresses | `std::net::IpAddr` | Built-in, no dep needed |
| Concurrency | `tokio::sync::Semaphore` + `JoinSet` | Bounded concurrent tasks |

Confidence: MEDIUM — these are well-established Rust ecosystem choices as of mid-2025. `async fn in traits` may have stabilized in Rust 1.75+ reducing the need for `async-trait`, but `async-trait` remains safe to use.

---

## Sources

- Training knowledge: nmap XML schema (documented at https://nmap.org/book/output-formats-xml-output.html)
- Training knowledge: NVD API 2.0 (https://nvd.nist.gov/developers/vulnerabilities)
- Training knowledge: OSV API (https://osv.dev/docs/)
- Training knowledge: Rust async-trait crate (https://docs.rs/async-trait)
- Training knowledge: tokio JoinSet (https://docs.rs/tokio/latest/tokio/task/struct.JoinSet.html)
- Training knowledge: Obsidian wikilinks and YAML frontmatter (https://help.obsidian.md)
- Confidence note: WebSearch was unavailable during this research session. All findings are from training data (knowledge cutoff ~August 2025). Critical API schemas (NVD 2.0, OSV batch endpoint) should be verified against official docs before implementation.

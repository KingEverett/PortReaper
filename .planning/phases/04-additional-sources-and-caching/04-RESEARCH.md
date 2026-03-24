# Phase 4: Additional Sources and Caching - Research

**Researched:** 2026-03-24
**Domain:** OSV.dev batch API, SearchSploit CLI integration, file-based TTL cache, Rust async patterns
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**SearchSploit Integration**
- D-01: SearchSploit results appear in a dedicated "Exploits" section below CVEs in service notes — exploits and vulnerabilities are visually distinct
- D-02: When `searchsploit` binary is not found on PATH, print a single stderr warning ("searchsploit not found — skipping exploit lookup") then continue normally
- D-03: Query SearchSploit by product name + version only (e.g., "openssh 7.4") — catches exploits without CVE references, matches manual pentester workflow
- D-04: Separate `ExploitSource` trait with `search_product()` method — exploits are not vulnerabilities, so they get their own trait rather than reusing VulnSource

**OSV.dev Source Design**
- D-05: Use batch queries — collect all unique CPEs from the scan, send one batch request to OSV.dev for efficiency
- D-06: Try both ecosystem-based and CPE-based lookups for richer results. Infer ecosystem from service info where possible (e.g., nginx → Linux), fall back to CPE
- D-07: Deduplication follows existing pattern: by CVE ID, keep highest CVSS score. OSV-specific IDs (GHSA-*) are kept as unique entries
- D-08: OsvSource implements VulnSource trait with `lookup_cpe()`. Internally batches and caches, but trait interface stays consistent with NVD/CVE.org

**Cache Strategy**
- D-09: Cache parsed results (Vec<Vulnerability> per CPE string) — smaller, faster, already deduplicated
- D-10: Cache location: `~/.cache/portreaper/` (XDG_CACHE_HOME/portreaper/). Standard Linux convention
- D-11: TTL-based expiry: 7 days. Entries older than 7 days are stale and re-fetched on next run
- D-12: `--fresh` flag bypasses cache for a single run (ignores existing cache, overwrites with fresh data)

**Source Selection UX**
- D-13: All available sources enabled by default: NVD + CVE.org + OSV.dev + SearchSploit (if installed). Maximum data out of the box
- D-14: `--disable-source <name>` flag to selectively disable sources. Repeatable (e.g., `--disable-source osv --disable-source searchsploit`)
- D-15: Progress output shows per-source lines: "[1/5] NVD: OpenSSH 7.4... 3 CVEs" then "[1/5] OSV: OpenSSH 7.4... 1 CVE" then "[1/5] SearchSploit: OpenSSH 7.4... 2 exploits"
- D-16: Summary includes per-source status: "Sources: NVD ✓, CVE.org ✓, OSV ✗ (timeout), SearchSploit ✓". At-a-glance view of what worked

### Claude's Discretion
- Cache file format (JSON, bincode, etc.) and internal structure
- OSV.dev batch API request construction and response parsing
- SearchSploit `--json` output parsing specifics
- How to structure ExploitSource trait methods and return types
- Internal module organization for new sources
- How ecosystem inference logic works for OSV.dev
- Cache key design (CPE string hashing, source namespacing)

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| VULN-03 | Query OSV.dev for open-source vulnerability data | OSV.dev batch API verified; Bitnami ecosystem covers nginx, apache, redis, postgresql, tomcat, wordpress; CVSS extraction from CVSS vector string in `affected[].severity` field |
| VULN-04 | Integrate SearchSploit local exploit database | `searchsploit -j <product> <version>` confirmed working; JSON schema fully documented; binary detection via `which`/`std::process::Command` |
| VULN-07 | Local caching to avoid re-querying known services | `serde_json` + `dirs` crate for XDG cache path; Unix timestamp (i64) for TTL; cache keyed by `{source}:{cpe}` |
</phase_requirements>

---

## Summary

Phase 4 adds two new data sources (OSV.dev and SearchSploit) plus a local cache. All three features are well-understood from verification against live APIs and the local binary. No blockers remain.

**OSV.dev** is a free, rate-limit-free batch API. The practical query strategy is: extract CPE product+version, query the Bitnami ecosystem by name+version. Bitnami covers web/database services (nginx, apache, postgresql, redis, tomcat, wordpress) but NOT system tools (openssh, openssl). This is acceptable — NVD/CVE.org already cover those. The batch endpoint (`POST /api.osv.dev/v1/querybatch`) returns only `{id, modified}` per result; full vulnerability records require individual `GET /v1/vulns/{id}` fetches. CVSS scores are in CVSS vector string format inside `affected[].severity[].score` or as a string label in `database_specific.severity`. The CVE alias (e.g., `CVE-2023-44487`) is available in the `aliases` array of BIT/GHSA records, enabling mapping to the existing `Vulnerability.cve_id` field.

**SearchSploit** is installed at `/usr/bin/searchsploit`. The `-j` flag is supported and produces a stable JSON schema with `RESULTS_EXPLOIT` array containing `Title`, `EDB-ID`, `Codes` (semicolon-separated CVE IDs), `Type`, `Platform`, `Path`, and other fields. Empty results produce `{"RESULTS_EXPLOIT": [], ...}` — no error, exit code 0. The binary is invoked via `tokio::process::Command` (async, no blocking).

**Caching** uses `serde_json` (already in Cargo.toml) for human-readable cache files, the `dirs` crate (v6.0.0) for XDG_CACHE_HOME resolution, and Unix timestamps (`i64` via `std::time::SystemTime`) for TTL comparison — no chrono feature flag needed. Cache files live at `~/.cache/portreaper/{source}/{cache_key}.json`.

**Primary recommendation:** OsvSource implements VulnSource via Bitnami ecosystem name lookup; SearchSploit runs as a post-enrichment step via ExploitSource trait; cache wraps both via a `CacheLayer` that intercepts `lookup_cpe()` calls before they hit the network.

---

## Standard Stack

### Core (all already in Cargo.toml except `dirs`)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `reqwest` | 0.13.2 | OSV.dev HTTP calls | Already in use; `rustls` + `json` + `query` features |
| `serde_json` | 1.0.149 | Cache file serialization/deserialization | Already in Cargo.toml; human-readable, debuggable |
| `dirs` | 6.0.0 | XDG_CACHE_HOME resolution (`dirs::cache_dir()`) | Standard Rust XDG library; 1 function needed |
| `tokio::process::Command` | (tokio already included) | Async SearchSploit invocation | Avoids blocking the async runtime |
| `serde` | 1.0.228 | Derive Serialize/Deserialize for cache structs | Already in Cargo.toml with `derive` feature |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `chrono` | 0.4 | Already in Cargo.toml if DateTime formatting needed | Only if human-readable timestamps in cache files are desired; Unix i64 is simpler |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `serde_json` for cache | `bincode` | Bincode is faster/smaller but not human-readable; cache files are small (<100KB per scan), JSON wins on debuggability |
| `dirs` | `directories` (ProjectDirs) | `directories` is higher-level but heavier; `dirs::cache_dir()` is 1 call |
| Unix i64 timestamp | `chrono::DateTime<Utc>` | chrono needs `serde` feature flag; `SystemTime::UNIX_EPOCH.elapsed()` is zero-dep |

**Installation:**
```bash
cargo add dirs@6.0.0
```

**Version verification:** `dirs` latest stable is 6.0.0 as of 2026-03-24 (verified via `cargo search dirs`).

---

## Architecture Patterns

### Recommended New Module Structure
```
src/
├── sources/
│   ├── mod.rs          # VulnSource trait, VulnLookupError (existing)
│   │                   # ADD: ExploitSource trait
│   ├── nvd.rs          # (existing)
│   ├── cve_org.rs      # (existing)
│   ├── osv.rs          # NEW: OsvSource implements VulnSource
│   └── searchsploit.rs # NEW: SearchSploitSource implements ExploitSource
├── cache/
│   └── mod.rs          # NEW: CacheLayer, CacheEntry, cache_path(), is_stale()
├── enrichment/
│   └── mod.rs          # EXTEND: EnrichmentOptions, enrich_scan signature
├── models.rs           # EXTEND: add Exploit struct, Port.exploits field
└── cli.rs              # EXTEND: add --fresh, --disable-source flags
```

### Pattern 1: ExploitSource Trait
**What:** A separate trait for exploit sources — distinct from `VulnSource` because exploits are not CVEs
**When to use:** SearchSploit and any future exploit source (ExploitDB, PacketStorm) implement this

```rust
// src/sources/mod.rs addition
pub struct Exploit {
    pub title: String,
    pub edb_id: String,
    pub exploit_type: String,   // "remote", "local", "dos", etc.
    pub platform: String,
    pub path: String,           // local filesystem path
    pub cve_refs: Vec<String>,  // parsed from Codes field (semicolon-separated)
    pub verified: bool,
    pub date_published: String,
}

pub trait ExploitSource: Send + Sync {
    fn name(&self) -> &str;
    fn search_product(
        &self,
        product: &str,
        version: &str,
    ) -> impl std::future::Future<Output = Result<Vec<Exploit>, ExploitLookupError>> + Send;
}

#[derive(Debug, Error)]
pub enum ExploitLookupError {
    #[error("binary not found: {binary}")]
    BinaryNotFound { binary: String },
    #[error("empty results for {query}")]
    Empty { query: String },
    #[error("subprocess failed: {msg}")]
    SubprocessFailed { msg: String },
    #[error("json parse error: {msg}")]
    ParseError { msg: String },
}
```

### Pattern 2: SearchSploit Invocation via tokio::process::Command
**What:** Run `searchsploit -j <product> <version>` as async subprocess
**When to use:** Only if binary exists on PATH (detected at SearchSploitSource construction time)

```rust
// src/sources/searchsploit.rs
use tokio::process::Command;
use std::process::Stdio;

pub struct SearchSploitSource {
    binary_path: PathBuf,  // resolved at construction: which searchsploit
}

impl SearchSploitSource {
    pub fn try_new() -> Option<Self> {
        which::which("searchsploit")  // OR: std::process::Command::new("which").arg("searchsploit")
            .ok()
            .map(|p| SearchSploitSource { binary_path: p })
    }
}
// Note: use `which` crate OR inline detection with Command::new("which")
// The project already avoids extra deps where possible — inline detection is fine:
// Command::new("searchsploit").arg("--help").output().is_ok()
```

**Verified SearchSploit JSON schema** (confirmed via `searchsploit -j "apache 2.4.49"`):
```json
{
  "SEARCH": "apache 2.4.49",
  "DB_PATH_EXPLOIT": "/usr/share/exploitdb",
  "RESULTS_EXPLOIT": [
    {
      "Title": "...",
      "EDB-ID": "29290",
      "Date_Published": "2013-10-29",
      "Date_Added": "2013-10-29",
      "Date_Updated": "2014-05-16",
      "Author": "kingcope",
      "Type": "remote",
      "Platform": "php",
      "Port": "80",
      "Verified": "1",
      "Codes": "CVE-2012-2336;CVE-2012-2311;CVE-2012-1823;OSVDB-81633",
      "Tags": "",
      "Aliases": "",
      "Screenshot": "",
      "Application": "",
      "Source": "https://...",
      "Path": "/usr/share/exploitdb/exploits/php/remote/29290.c"
    }
  ],
  "DB_PATH_SHELLCODE": "/usr/share/exploitdb",
  "RESULTS_SHELLCODE": []
}
```

Key parsing notes:
- `Codes` is semicolon-separated; filter for `CVE-*` prefixed entries for `cve_refs`
- `Verified` is a string `"0"` or `"1"`, not a boolean
- Empty results: `RESULTS_EXPLOIT: []` with exit code 0 — not an error
- No output to stderr on success

### Pattern 3: OSV.dev Two-Step Batch Query
**What:** One batch query per scan (all CPEs together), then individual vuln detail fetches per unique OSV ID
**When to use:** Always — the batch endpoint is the only efficient way to query multiple services

Step 1 — Batch package query (collect all CPEs/product names from scan):
```rust
// POST https://api.osv.dev/v1/querybatch
// Request body:
{
  "queries": [
    {
      "package": {"name": "nginx", "ecosystem": "Bitnami"},
      "version": "1.18.0"
    },
    {
      "package": {"name": "apache", "ecosystem": "Bitnami"},
      "version": "2.4.49"
    }
    // one entry per unique (product, version) pair in scan
  ]
}
// Response: {"results": [{"vulns": [{"id": "BIT-nginx-...", "modified": "..."}]}, ...]}
// Positions in results[] correspond 1:1 to positions in queries[]
```

Step 2 — Fetch full vuln details for each unique OSV ID:
```rust
// GET https://api.osv.dev/v1/vulns/{id}
// e.g. GET https://api.osv.dev/v1/vulns/BIT-nginx-2023-44487
// Returns full Vulnerability record
```

**Verified OSV vulnerability record schema** (from `GET /v1/vulns/BIT-nginx-2023-44487`):
```json
{
  "id": "BIT-nginx-2023-44487",
  "details": "The HTTP/2 protocol allows...",
  "aliases": ["BIT-apisix-2023-44487", "CVE-2023-44487", "GHSA-qppj-fm5r-hxr3"],
  "modified": "2026-02-11T09:32:40.296571Z",
  "published": "2024-03-06T10:58:49.980Z",
  "database_specific": {
    "severity": "High",
    "cpes": ["cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"]
  },
  "affected": [
    {
      "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
      ]
    }
  ]
}
```

**CVSS extraction from OSV record:**
- `database_specific.severity` → plain string label ("High", "Critical") — use `Severity::from_str()`
- `affected[0].severity[0]` → CVSS vector string — parse the vector to get numeric score OR use label only
- For simplicity: use `database_specific.severity` for severity label + extract numeric score from CVSS vector string manually (parse `baseScore` is NOT in the vector; compute from AV/AC/PR/UI metrics OR use a crate)
- **Recommended:** Use the `cvss` crate (v2.2.0 on crates.io) which parses vector strings and computes base scores. Alternative: store `None` for score and only record severity label from `database_specific.severity`.
- **CVE ID extraction:** Find first `aliases[]` entry that starts with `"CVE-"` — this is the canonical CVE ID. If none, use the OSV ID directly (GHSA-* or BIT-* becomes the `cve_id` field).

### Pattern 4: Cache Layer Design
**What:** File-per-source-per-CPE JSON cache with TTL check on read
**When to use:** Wraps all VulnSource and ExploitSource calls before hitting network

```
Cache file path: {cache_dir}/portreaper/{source}/{hash(cpe)}.json
Example:         ~/.cache/portreaper/osv/a3f9b1c2.json
                 ~/.cache/portreaper/nvd/a3f9b1c2.json
```

Cache entry struct:
```rust
#[derive(Serialize, Deserialize)]
pub struct CacheEntry {
    pub cpe: String,                     // for verification / debugging
    pub source: String,
    pub fetched_at: i64,                 // Unix timestamp (seconds)
    pub vulnerabilities: Vec<CachedVuln>, // serializable form of Vulnerability
}

#[derive(Serialize, Deserialize)]
pub struct CachedVuln {
    pub cve_id: String,
    pub source: String,
    pub score: Option<f32>,
    pub severity: Option<String>,
    pub cvss_version: Option<String>,
    pub description: Option<String>,
}
```

TTL check:
```rust
pub fn is_stale(entry: &CacheEntry, ttl_secs: i64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    now - entry.fetched_at > ttl_secs
}
```

Cache key (filename):
```rust
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn cache_filename(source: &str, cpe: &str) -> String {
    let mut h = DefaultHasher::new();
    cpe.hash(&mut h);
    format!("{:016x}.json", h.finish())
}
```

Cache directory creation:
```rust
use dirs::cache_dir;

fn portreaper_cache_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|p| p.join("portreaper"))
}
```

### Pattern 5: Ecosystem Inference for OSV Bitnami Queries
**What:** Map CPE product field to Bitnami package name
**Critical finding:** Bitnami ecosystem covers web/app services but NOT system tools:

| CPE Product | Bitnami Name | Works? |
|-------------|--------------|--------|
| `apache` / `http_server` | `apache` | YES (46 results for 2.4.49) |
| `nginx` | `nginx` | YES (9 results for 1.18.0) |
| `redis` | `redis` | YES |
| `postgresql` | `postgresql` | YES |
| `tomcat` | `tomcat` | YES |
| `wordpress` | `wordpress` | YES |
| `openssh` | `openssh` | NO (0 results) |
| `openssl` | `openssl` | NO (0 results) |
| `mysql` | `mysql` | NO — use `mariadb` for MariaDB |

**CPE product → Bitnami name mapping table** (hardcoded in OsvSource):
- `http_server` → `apache` (NVD uses `http_server`, Bitnami uses `apache`)
- All others: use CPE product field directly as Bitnami name
- On 0 results: treat as `VulnLookupError::Empty` — not a failure

### Pattern 6: Port Model Extension for Exploits
**What:** Add `exploits` field to the `Port` model (parallel to `vulnerabilities`)
**When to use:** Required to store SearchSploit results through the pipeline

```rust
// src/models.rs
pub struct Port {
    pub port_id: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<Service>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub exploits: Vec<Exploit>,          // NEW — empty vec by default
}
```

### Anti-Patterns to Avoid
- **Fetching all OSV vuln details before deduplication:** The batch response returns IDs only. Deduplicate IDs first (a BIT-nginx-X and BIT-apisix-X for the same CVE are aliases), then fetch details only for unique canonical IDs.
- **Blocking the async runtime with SearchSploit:** Use `tokio::process::Command`, not `std::process::Command`. SearchSploit reads from disk but can be slow on large DBs.
- **Using `DefaultHasher` for security-sensitive keys:** Fine for cache filenames; `DefaultHasher` is intentionally non-cryptographic. For cache poisoning resistance, URL-encode the CPE string as filename instead (avoids hash collisions entirely for a small cost in filename length).
- **Caching empty results as "0 vulnerabilities":** An empty response from Bitnami for openssh is correct behavior — it SHOULD be cached to avoid future needless queries. Cache the empty `Vec<CachedVuln>` too.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| CVSS vector string → numeric score | Custom parser for `AV:N/AC:L/PR:N/UI:N/...` | `cvss` crate (v2.2.0) OR use severity label only | CVSS scoring formula has many edge cases; version differences (v2/v3/v4) |
| XDG cache path resolution | Custom `~/.cache` path logic | `dirs::cache_dir()` | Handles XDG_CACHE_HOME override, Windows, macOS — single function call |
| Async subprocess | `std::process::Command` + `spawn_blocking` | `tokio::process::Command` | Direct async support, no extra thread per call |
| SearchSploit binary detection | Complex PATH walking | `std::process::Command::new("searchsploit").arg("--help").output().is_ok()` | Simple, handles PATH, no extra crate |

**Key insight:** OSV's CVSS data is stored as vector strings (not numeric), requiring either a crate or the decision to store severity label only. The `database_specific.severity` string label ("High", "Critical") maps directly to `Severity::from_str()` and avoids the crate dependency entirely — which is the simpler path.

---

## Common Pitfalls

### Pitfall 1: OSV Batch Positions Must Match 1:1
**What goes wrong:** Batch response `results[i]` corresponds to `queries[i]`. If query construction reorders queries or the response has fewer entries, CPE→vulnerability mappings are corrupted.
**Why it happens:** The OSV API makes no guarantees beyond positional correspondence.
**How to avoid:** Zip `queries` and `results` together in the same order. Use an index map: `HashMap<usize, (product, version)>` where key is query position.
**Warning signs:** Vulnerabilities attributed to wrong services.

### Pitfall 2: OSV Batch Returns Empty `{}` Objects for No Results
**What goes wrong:** Services with no OSV data return `{}` (empty object) in results, not `{"vulns": []}`. Treating the absent `vulns` key as an error breaks the pipeline.
**Why it happens:** Verified by live API test — `openssh` in Bitnami returns `{}`.
**How to avoid:** `result.get("vulns").unwrap_or(&[])` or use `#[serde(default)]` on the `vulns` field in the response struct.
**Warning signs:** Panic on `unwrap()` when deserializing OSV batch response.

### Pitfall 3: SearchSploit `Codes` Field Needs Filtering
**What goes wrong:** The `Codes` field contains mixed identifiers: `"CVE-2012-2336;OSVDB-81633;BID-12345"`. Treating all of them as CVE IDs corrupts data.
**Why it happens:** SearchSploit uses multiple identifier namespaces.
**How to avoid:** Filter split codes by `code.starts_with("CVE-")` before storing in `Exploit.cve_refs`.
**Warning signs:** OSVDB/BID strings appearing in CVE reference lists.

### Pitfall 4: Cache Directory May Not Exist
**What goes wrong:** `std::fs::write()` to `~/.cache/portreaper/osv/abc.json` fails if intermediate directories don't exist.
**Why it happens:** First run; XDG cache dir may not have `portreaper/` or `portreaper/osv/` subdirs.
**How to avoid:** Call `std::fs::create_dir_all(&cache_subdir)` before any write. Failure to create cache dir should be a non-fatal warning, not a panic — cache miss is safe fallback.
**Warning signs:** `No such file or directory` error on first cache write.

### Pitfall 5: OSV Vuln Detail Fetch N+1 Problem
**What goes wrong:** Batch query returns 50 vuln IDs → 50 individual GET requests to `/v1/vulns/{id}` sequentially → slow.
**Why it happens:** The batch endpoint only returns IDs; details require individual fetches.
**How to avoid:** Fetch vuln details concurrently using the existing semaphore pattern. Deduplicate IDs across all services first (a shared CVE ID from two services needs only one fetch), then spawn concurrent detail fetches.
**Warning signs:** OSV enrichment takes 10x longer than expected.

### Pitfall 6: `--disable-source` with Clap Multi-Value
**What goes wrong:** `--disable-source osv --disable-source searchsploit` requires `action = clap::ArgAction::Append`, not the default. Without it, only the last value is kept.
**Why it happens:** Clap's default for string args is last-value-wins.
**How to avoid:** Use `#[arg(long, action = clap::ArgAction::Append)]` on the `disable_source` field.
**Warning signs:** Only last `--disable-source` value takes effect.

### Pitfall 7: Cache Stale Check With System Clock Skew
**What goes wrong:** Comparing `fetched_at` (Unix timestamp from time of write) against `now()` assumes monotonic time. System clock adjustments (NTP sync backward) can make cache appear fresher than it is.
**Why it happens:** `SystemTime` is not monotonic.
**How to avoid:** Accept this as a known limitation; for a 7-day TTL the error is negligible. Use `UNIX_EPOCH.elapsed()` which is stable.

---

## Code Examples

### OSV Batch Request Serde Structs
```rust
// Source: live API verification, 2026-03-24

#[derive(Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvQueryResult>,
}

#[derive(Deserialize, Default)]
struct OsvQueryResult {
    #[serde(default)]
    vulns: Vec<OsvVulnRef>,
}

#[derive(Deserialize)]
struct OsvVulnRef {
    id: String,
    // modified: String,  // not needed for our use case
}
```

### OSV Vuln Detail Response Serde Structs
```rust
// Source: live API verification, GET /v1/vulns/BIT-nginx-2023-44487

#[derive(Deserialize)]
struct OsvVulnDetail {
    id: String,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    database_specific: Option<OsvDatabaseSpecific>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Deserialize)]
struct OsvDatabaseSpecific {
    #[serde(default)]
    severity: Option<String>,   // "High", "Critical", "Medium", etc.
}

#[derive(Deserialize)]
struct OsvAffected {
    #[serde(default)]
    severity: Vec<OsvSeverityEntry>,
}

#[derive(Deserialize)]
struct OsvSeverityEntry {
    #[serde(rename = "type")]
    score_type: String,  // "CVSS_V3", "CVSS_V4"
    score: String,       // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
}
```

**Extracting CVE ID from aliases:**
```rust
fn extract_cve_id(aliases: &[String], fallback_id: &str) -> String {
    aliases.iter()
        .find(|a| a.starts_with("CVE-"))
        .cloned()
        .unwrap_or_else(|| fallback_id.to_string())
}
```

### SearchSploit Serde Structs
```rust
// Source: live binary verification, searchsploit -j "apache 2.4.49", 2026-03-24

#[derive(Deserialize)]
struct SearchSploitOutput {
    #[serde(rename = "RESULTS_EXPLOIT")]
    results_exploit: Vec<SearchSploitEntry>,
    // RESULTS_SHELLCODE exists but we don't use it
}

#[derive(Deserialize)]
struct SearchSploitEntry {
    #[serde(rename = "Title")]
    title: String,
    #[serde(rename = "EDB-ID")]
    edb_id: String,
    #[serde(rename = "Type")]
    exploit_type: String,
    #[serde(rename = "Platform")]
    platform: String,
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Codes")]
    codes: String,    // e.g. "CVE-2012-2336;CVE-2012-2311;OSVDB-81633"
    #[serde(rename = "Verified")]
    verified: String, // "0" or "1" — parse as bool
    #[serde(rename = "Date_Published")]
    date_published: String,
}

// CVE reference extraction:
fn parse_cve_refs(codes: &str) -> Vec<String> {
    codes.split(';')
        .filter(|s| s.starts_with("CVE-"))
        .map(|s| s.to_string())
        .collect()
}
```

### Clap CLI Additions
```rust
// Source: decisions D-12, D-14; Clap 4.x verified pattern

// In src/cli.rs:

/// Bypass cache: re-fetch all data even if cached results are fresh
#[arg(long)]
pub fresh: bool,

/// Disable a named source (repeatable): nvd, cveorg, osv, searchsploit
#[arg(long = "disable-source", value_name = "SOURCE", action = clap::ArgAction::Append)]
pub disable_sources: Vec<String>,
```

### Cache Read/Write Pattern
```rust
// Cache is non-fatal: log warning and proceed on any cache error

async fn read_cache(path: &Path) -> Option<CacheEntry> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    serde_json::from_str(&content).ok()
}

async fn write_cache(path: &Path, entry: &CacheEntry) {
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    if let Ok(json) = serde_json::to_string_pretty(entry) {
        let _ = tokio::fs::write(path, json).await;
        // Silently ignore write failures — cache is best-effort
    }
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Per-query API calls for every service | OSV batch API — one request per scan | OSV API v1 | Major: N queries → 1 query for the batch step |
| CVSS stored as numeric score only | OSV stores CVSS as vector string in `affected[].severity[].score` | OSV schema design | Requires either vector parsing or using `database_specific.severity` label |
| ExploitDB as web scraping | SearchSploit as local offline binary | ExploitDB ships searchsploit | No rate limits, no network dependency, works offline |

**Current behavior (verified 2026-03-24):**
- OSV API has NO rate limits (confirmed in official docs: "Currently there are no limits on the API")
- `searchsploit -j` exit code is always 0 — empty results are not errors
- `dirs::cache_dir()` on Linux returns `$XDG_CACHE_HOME` or `~/.cache` if unset

---

## Open Questions

1. **CVSS score extraction from OSV vector strings**
   - What we know: `affected[].severity[0].score` is a CVSS vector string like `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"`. The base score (7.5) is not directly in the string.
   - What's unclear: Should we add the `cvss` crate (adds a dep) or use `database_specific.severity` label only (no dep, less precision)?
   - Recommendation: Use `database_specific.severity` for the `Severity` enum (zero deps); store `cvss: None` in `Vulnerability.cvss` for OSV-sourced entries. This is already handled by `dedup_vulnerabilities()` — NVD/CVE.org entries with actual numeric scores will win deduplication anyway. Revisit only if precision matters for OSV-unique entries.

2. **OSV vuln detail fetch volume**
   - What we know: A single nginx 1.18.0 query returns 9 BIT IDs. A 500-port scan might yield 200+ unique OSV IDs requiring 200+ individual GET requests.
   - What's unclear: Whether the concurrent semaphore (5 default) is adequate or if OSV needs its own limit.
   - Recommendation: Reuse the existing semaphore at 5 concurrent. OSV has no rate limits, so 5 concurrent is conservative and safe.

3. **`--disable-source` source name canonicalization**
   - What we know: D-14 specifies `--disable-source osv --disable-source searchsploit`.
   - What's unclear: Should `NVD`, `nvd`, `Nvd` all work? Case normalization needed.
   - Recommendation: Normalize to lowercase on parse; document accepted values as `nvd`, `cveorg`, `osv`, `searchsploit`.

---

## Validation Architecture

> `workflow.nyquist_validation` is `true` in `.planning/config.json`.

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in (`cargo test`) |
| Config file | `Cargo.toml` (no separate test config) |
| Quick run command | `cargo test --lib 2>&1` |
| Full suite command | `cargo test 2>&1` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| VULN-03 | OsvSource returns vulnerabilities for nginx | unit | `cargo test --lib sources::osv 2>&1` | No — Wave 0 |
| VULN-03 | Batch query builds correct JSON body | unit | `cargo test --lib sources::osv::tests::batch_request_schema 2>&1` | No — Wave 0 |
| VULN-03 | OSV vuln detail → Vulnerability mapping | unit | `cargo test --lib sources::osv::tests::vuln_detail_parsing 2>&1` | No — Wave 0 |
| VULN-03 | CVE alias extraction from aliases array | unit | `cargo test --lib sources::osv::tests::cve_alias_extraction 2>&1` | No — Wave 0 |
| VULN-03 | Empty OSV result (no Bitnami entry) treated as Empty, not error | unit | `cargo test --lib sources::osv::tests::empty_result_is_not_error 2>&1` | No — Wave 0 |
| VULN-04 | SearchSploitSource returns exploits for openssh 7.4 | unit | `cargo test --lib sources::searchsploit 2>&1` | No — Wave 0 |
| VULN-04 | Codes field parsing extracts CVE refs only | unit | `cargo test --lib sources::searchsploit::tests::parse_cve_refs 2>&1` | No — Wave 0 |
| VULN-04 | Missing binary returns BinaryNotFound gracefully | unit | `cargo test --lib sources::searchsploit::tests::missing_binary_graceful 2>&1` | No — Wave 0 |
| VULN-07 | Cache write creates file, read returns same entry | unit | `cargo test --lib cache::tests::roundtrip 2>&1` | No — Wave 0 |
| VULN-07 | Cache entry older than 7 days is stale | unit | `cargo test --lib cache::tests::ttl_expiry 2>&1` | No — Wave 0 |
| VULN-07 | --fresh flag bypasses cache | unit | `cargo test --lib cache::tests::fresh_flag_bypasses_cache 2>&1` | No — Wave 0 |
| VULN-07 | Cache miss falls through to real source | unit | `cargo test --lib cache::tests::miss_fetches_from_source 2>&1` | No — Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test --lib 2>&1`
- **Per wave merge:** `cargo test 2>&1`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `src/sources/osv.rs` — covers VULN-03; needs fixture `tests/fixtures/osv_batch_response_nginx.json` and `tests/fixtures/osv_vuln_detail_nginx.json`
- [ ] `src/sources/searchsploit.rs` — covers VULN-04; unit tests use fixture `tests/fixtures/searchsploit_openssh74.json` (captured via `searchsploit -j "openssh 7.4"`)
- [ ] `src/cache/mod.rs` — covers VULN-07; tests use `tempfile::tempdir()` (add `tempfile` as dev-dependency)

---

## Sources

### Primary (HIGH confidence)
- Live OSV.dev API (`https://api.osv.dev/v1/querybatch`) — verified 2026-03-24, batch schema, Bitnami ecosystem coverage, empty result format
- Live OSV.dev API (`https://api.osv.dev/v1/vulns/{id}`) — verified 2026-03-24, full vuln detail schema including `aliases`, `database_specific.severity`, `affected[].severity[].score`
- `searchsploit -j` binary at `/usr/bin/searchsploit` — verified 2026-03-24, JSON schema with all field names and types
- Official OSV.dev API docs (`https://google.github.io/osv.dev/api/`) — "Currently there are no limits on the API"
- `cargo search dirs` — dirs 6.0.0 current stable version confirmed

### Secondary (MEDIUM confidence)
- OSV.dev data sources page (`https://google.github.io/osv.dev/data/`) — ecosystem list including Bitnami, Ubuntu, Alpine, Debian
- OSV.dev batch docs (`https://google.github.io/osv.dev/post-v1-querybatch/`) — pagination thresholds, request schema

### Tertiary (LOW confidence)
- None — all critical claims verified from primary sources

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all packages verified via `cargo search` and live tests
- Architecture: HIGH — all three integrations tested against live systems (OSV API, searchsploit binary)
- Pitfalls: HIGH — most pitfalls discovered by actually running the APIs (empty `{}` result, `Codes` format, etc.)
- Bitnami ecosystem coverage: MEDIUM — tested 10 product names; coverage for edge cases (e.g., Microsoft IIS) not verified

**Research date:** 2026-03-24
**Valid until:** 2026-09-24 (OSV schema is stable; SearchSploit binary API is stable; 6 months)

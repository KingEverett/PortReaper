# Phase 2: Enrichment Core - Research

**Researched:** 2026-03-21
**Domain:** NVD API v2, CVE.org API, async Rust (tokio + reqwest), bounded concurrency, exponential backoff
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Vulnerability Output Display**
- D-01: CVEs display inline under their port/service in the existing tree (not a separate table)
- D-02: Each CVE shows: CVE ID + severity label + CVSS score on one line (e.g., `CVE-2021-41773 [Crit 9.8]`)
- D-03: Severity labels are color-coded using owo-colors: Critical=red, High=yellow, Medium=cyan, Low=green. No color when piped (existing supports-colors behavior)
- D-04: Summary line updated to: `Summary: N hosts, M open ports, X CVEs (Y critical, Z high, ...)`

**API Failure Behavior**
- D-05: Partial results + warnings — when one source fails, show what succeeded and warn about failures on stderr (e.g., `⚠ NVD: rate limited (3 services skipped)`)
- D-06: Exponential backoff with max 3 retries per request (1s → 2s → 4s), then give up and report partial
- D-07: NVD API key supported via `PORTREAPER_NVD_KEY` env var — higher rate limits when present, still works without
- D-08: Deduplication by CVE ID — when same CVE found in NVD and CVE.org, take the highest CVSS score from either source

**CPE Matching**
- D-09: Services without CPE strings are skipped with per-service warning on stderr (e.g., `⚠ 443/tcp https: no CPE — skipping vuln lookup`)
- D-10: Auto-convert CPE 2.2 format (cpe:/a:...) to CPE 2.3 (cpe:2.3:a:...) transparently for NVD API v2 queries
- D-11: Query ALL CPE strings per service (application, OS, hardware), deduplicate results by CVE ID

**Progress & Verbosity**
- D-12: Default progress: per-service status lines on stderr showing `[N/M] Querying {source} for {product} {version}... X CVEs`
- D-13: `-q` (quiet) suppresses stderr progress lines but keeps CVE tree in stdout — summary line always shown
- D-14: `--no-enrich` flag skips vuln lookups entirely — parse + tree only (Phase 1 behavior)
- D-15: Default concurrency cap: 5 concurrent API requests via tokio::sync::Semaphore

**Claude's Discretion**
- Exact HTTP client configuration (reqwest settings, timeouts, user-agent)
- Internal data structures for vulnerability results
- NVD API v2 query parameter construction details
- CVE.org API endpoint and response parsing specifics
- How to structure the async runtime integration with existing sync code

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| VULN-01 | Query NVD (NIST) for CVEs and CVSS scores | NVD API v2 endpoint, cpeName param, CVSS extraction from cvssMetricV31/V30/V2 confirmed by live test |
| VULN-02 | Query CVE.org for vulnerability data | cveawg.mitre.org/api/cve/{id} endpoint confirmed; CVSS in containers.adp[].metrics |
| VULN-05 | CPE-based matching for accurate vulnerability lookups | NVD cpeName param requires CPE 2.3; CPE 2.2→2.3 conversion algorithm documented |
| VULN-06 | Rate limiting and bounded concurrency for API queries | NVD: 5 req/30s (no key), 50 req/30s (with key); CVE.org: 25000 req/60s; tokio::sync::Semaphore for concurrency bound |
| ARCH-04 | Progress indicators during vulnerability lookups | eprintln! to stderr with [N/M] counter; -q flag suppresses; matches existing stderr/stdout split |
</phase_requirements>

## Summary

Phase 2 builds the vulnerability enrichment pipeline on top of the Phase 1 parse-and-render foundation. The core flow is: CPE strings from parsed services → NVD API v2 lookup by cpeName → CVE.org API lookup by CVE ID for enrichment → deduplicate by CVE ID, take highest CVSS → classify by severity → render inline in existing tree.

The key architectural insight is that NVD supports CPE-based search (returns CVE lists) while CVE.org only supports individual CVE ID lookup (returns CVE record). The recommended approach is NVD as the primary CPE-to-CVE-list source, with CVE.org as a secondary enrichment source for CVEs NVD returned — not as an independent CPE-search source. This avoids the impossible task of searching CVE.org by CPE.

The async integration is straightforward: add `#[tokio::main]` to `fn main()`, convert `run()` to `async fn run()`, add the enrichment step between parse and render. The existing `VulnSource` trait skeleton is already present in `src/sources/mod.rs` — Phase 2 implements `lookup()` on it. The `tokio::sync::Semaphore` was pre-selected and confirmed as the correct tool for the concurrency bound (D-15).

**Primary recommendation:** Use reqwest 0.13 with tokio 1, serde_json 1.0 for response parsing, and the existing `tokio::sync::Semaphore` pattern for bounded concurrency. Hand-roll exponential backoff per D-06 (3 retries: 1s/2s/4s) rather than adding a backoff crate — the logic is simple enough not to justify a dependency.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| tokio | 1.50.0 | Async runtime for concurrent API calls | De facto standard Rust async runtime; already implicit via reqwest |
| reqwest | 0.13.2 | HTTP client for NVD and CVE.org APIs | Standard Rust HTTP client; supports async, JSON feature, header setting |
| serde_json | 1.0.149 | Deserialize NVD/CVE.org API JSON responses | Standard JSON in Rust; already used transitively via serde |
| serde (derive) | 1.0.228 | Struct deserialization of API response shapes | Already in Cargo.toml |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| tokio::sync::Semaphore | (in tokio) | Bound concurrent API requests to D-15's cap of 5 | Always — pre-decided in architecture |
| owo-colors (existing) | 4.3.0 | Color-code CVE severity labels per D-03 | Already in Cargo.toml with supports-colors feature |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Hand-rolled backoff | `backoff` crate (0.4) | Adds dependency for 10 lines of logic; not worth it for fixed 1s/2s/4s schedule |
| reqwest | `ureq` (blocking) | Simpler but blocking; tokio needed anyway for Semaphore and concurrent joins |
| `nvd-api` crate (0.1.1) | Direct reqwest | GPL-3.0 license; only 38% documented; wraps reqwest 0.11 (outdated); hand-roll instead |

**Installation:**
```bash
cargo add tokio --features full
cargo add reqwest --features json,rustls-tls
cargo add serde_json
```

**Version verification (confirmed 2026-03-21):**
- `tokio`: 1.50.0 (latest stable)
- `reqwest`: 0.13.2 (latest stable)
- `serde_json`: 1.0.149 (latest stable)

## Architecture Patterns

### Recommended Project Structure
```
src/
├── sources/
│   ├── mod.rs          # VulnSource trait + VulnLookupError (existing) -- add lookup() method
│   ├── nvd.rs          # NvdSource: reqwest Client, cpeName query, CVSS extraction
│   └── cve_org.rs      # CveOrgSource: per-CVE-ID enrichment from cveawg.mitre.org
├── enrichment/
│   └── mod.rs          # enrich_scan(): orchestrates sources, dedup, semaphore
├── models.rs           # Add Vulnerability struct, CvssScore, Severity enum
├── render/
│   └── tree.rs         # Extend to render CVE child nodes under port nodes
└── cli.rs              # Add --no-enrich flag
```

### Pattern 1: VulnSource Trait with async lookup()

The existing trait stub adds a `lookup()` method returning CVE results for a given CPE:

```rust
// src/sources/mod.rs
use async_trait::async_trait;

#[async_trait]
pub trait VulnSource: Send + Sync {
    fn name(&self) -> &str;
    async fn lookup_cpe(&self, cpe: &str) -> Result<Vec<Vulnerability>, VulnLookupError>;
}
```

Note: `async_trait` macro OR Rust 1.75+ native async-in-traits (RPITIT). Since edition 2024 is set in Cargo.toml, native async fn in traits is available — no `async_trait` crate needed.

**Native async-in-trait (edition 2024 / Rust 1.75+):**
```rust
pub trait VulnSource: Send + Sync {
    fn name(&self) -> &str;
    fn lookup_cpe(&self, cpe: &str) -> impl Future<Output = Result<Vec<Vulnerability>, VulnLookupError>> + Send;
}
```

Or simply use `async fn` in the impl blocks and an enum dispatch rather than dyn trait if dynamic dispatch is not needed.

### Pattern 2: Semaphore-Bounded Concurrent Lookups

```rust
// src/enrichment/mod.rs
use std::sync::Arc;
use tokio::sync::Semaphore;

pub async fn enrich_scan(
    scan: &mut ScanResult,
    sources: &[Arc<dyn VulnSource>],
    concurrency: usize,
) {
    let semaphore = Arc::new(Semaphore::new(concurrency)); // D-15: default 5
    let mut handles = vec![];

    for service_cpes in collect_service_cpes(scan) {
        let sem = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            // query sources, return results
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
}
```

### Pattern 3: NVD API v2 Request Construction

**Confirmed by live test 2026-03-21:**

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
Header: apiKey: {PORTREAPER_NVD_KEY}   (optional per D-07)
```

Rate limits (verified):
- Without API key: 5 requests in a rolling 30-second window
- With API key: 50 requests in a rolling 30-second window
- NVD recommends sleeping 6 seconds between requests (even with key)
- 429 status = rate limited (previously was 403 before infrastructure migration)

```rust
// src/sources/nvd.rs
let url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
let mut req = client.get(url)
    .query(&[("cpeName", &cpe23), ("resultsPerPage", "2000")])
    .header("User-Agent", "PortReaper/0.1 (github.com/portreaper)");

if let Some(key) = &self.api_key {
    req = req.header("apiKey", key);
}
let resp = req.send().await?;
```

### Pattern 4: NVD Response CVSS Extraction

**Confirmed by live query against CVE-2021-41773:**

```rust
// Response structure (verified):
// vulnerabilities[].cve.id                          → "CVE-2021-41773"
// vulnerabilities[].cve.metrics.cvssMetricV31[0].cvssData.baseScore  → 9.8
// vulnerabilities[].cve.metrics.cvssMetricV31[0].cvssData.baseSeverity → "CRITICAL"
// vulnerabilities[].cve.metrics.cvssMetricV30[0].cvssData.baseScore  → (if no V31)
// vulnerabilities[].cve.metrics.cvssMetricV2[0].baseSeverity         → "MEDIUM" (in entry, not cvssData)
// vulnerabilities[].cve.metrics.cvssMetricV2[0].cvssData.baseScore   → 4.3

// Priority: V4 > V31 > V30 > V2 (use highest available)
fn extract_cvss(metrics: &NvdMetrics) -> Option<CvssScore> {
    if let Some(v) = &metrics.cvss_metric_v4 {
        return score_from_v4(&v[0]);
    }
    if let Some(v) = &metrics.cvss_metric_v31 {
        return score_from_v3(&v[0]);  // baseSeverity in cvssData
    }
    if let Some(v) = &metrics.cvss_metric_v30 {
        return score_from_v3(&v[0]);
    }
    if let Some(v) = &metrics.cvss_metric_v2 {
        return score_from_v2(&v[0]);  // baseSeverity in entry, not cvssData
    }
    None
}
```

**CVSS V2 trap:** `baseSeverity` is at the entry level (not inside `cvssData`) for V2 records. V3+ has `baseSeverity` inside `cvssData`.

### Pattern 5: CVE.org API

**Confirmed by live test 2026-03-21:**

```
GET https://cveawg.mitre.org/api/cve/{CVE-ID}
No authentication required.
Rate limit: 25,000 requests per 60 seconds (from ratelimit-policy header).
```

**CVSS location in CVE.org response (confirmed by live test):**

```rust
// containers.cna.metrics[].cvssV3_1.baseScore     — CNA-supplied score
// containers.adp[].metrics[].cvssV3_1.baseScore   — ADP-enriched score (often CISA)
// containers.cna.metrics[0].cveId field does NOT exist — use cveMetadata.cveId

// CVE-2021-41773: containers.cna.metrics[0] = {other: {...}}  (no standard CVSS)
// CVE-2023-44487: containers.adp[0].metrics[0].cvssV3_1.baseScore = 7.5  (ADP has it)
// Many records have NO CVSS in CVE.org — NVD is richer source
```

**Critical insight:** CVE.org does NOT support CPE-based search. It only supports lookup by CVE ID (`GET /api/cve/{id}`). The correct integration is: use NVD to get CVE IDs from CPE → optionally enrich by fetching from CVE.org to cross-check CVSS. Given CVE.org's CVSS coverage is sparse and NVD is richer, CVE.org enrichment may add little value for CVSS accuracy. However, it fulfills VULN-02 and allows taking the highest CVSS per D-08.

### Pattern 6: CPE 2.2 to CPE 2.3 Conversion (D-10)

nmap CPE strings use 2.2 format: `cpe:/a:openbsd:openssh:8.9p1`
NVD API v2 requires 2.3 format: `cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*`

```rust
fn cpe22_to_cpe23(cpe22: &str) -> String {
    // cpe:/X:vendor:product:version → cpe:2.3:X:vendor:product:version:*:*:*:*:*:*:*
    if let Some(rest) = cpe22.strip_prefix("cpe:/") {
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        let part = parts.get(0).copied().unwrap_or("*");
        let vendor = parts.get(1).copied().unwrap_or("*");
        let product = parts.get(2).copied().unwrap_or("*");
        let version = parts.get(3).copied().unwrap_or("*");
        format!("cpe:2.3:{}:{}:{}:{}:*:*:*:*:*:*:*", part, vendor, product, version)
    } else {
        cpe22.to_string() // already 2.3 or unknown format
    }
}
```

### Pattern 7: Exponential Backoff (D-06)

Simple hand-roll for 1s→2s→4s (3 retries):

```rust
async fn with_retry<F, Fut, T>(mut f: F) -> Result<T, VulnLookupError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, VulnLookupError>>,
{
    let delays = [1u64, 2, 4];
    let mut last_err = None;
    for (attempt, &delay_secs) in delays.iter().enumerate() {
        match f().await {
            Ok(v) => return Ok(v),
            Err(VulnLookupError::RateLimited { .. }) | Err(VulnLookupError::NetworkFailure { .. }) => {
                if attempt < delays.len() - 1 {
                    tokio::time::sleep(Duration::from_secs(delay_secs)).await;
                }
                last_err = Some(/* the error */);
            }
            Err(VulnLookupError::Empty { .. }) => return Err(/* empty */),
        }
    }
    Err(last_err.unwrap())
}
```

### Pattern 8: tokio::main Integration

The existing `fn main() -> ExitCode` becomes `async fn main()`:

```rust
// src/main.rs
#[tokio::main]
async fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    match run(&cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => { /* existing error handling */ ExitCode::from(1) }
    }
}

async fn run(cli: &cli::Cli) -> anyhow::Result<()> {
    let inputs = get_inputs(cli)?;
    let mut result = parser::parse_and_merge(inputs)?;

    if !cli.no_enrich {
        enrichment::enrich_scan(&mut result, &sources, 5).await;
    }

    let opts = render::tree::RenderOptions { /* ... */ };
    render::tree::render_tree(&result, &opts);
    Ok(())
}
```

Note: rename existing `--enrich` (hidden, present in cli.rs) to `--no-enrich` per D-14.

### Anti-Patterns to Avoid

- **Blocking reqwest in async context:** Never use `reqwest::blocking` inside a tokio task. Use `reqwest::Client` (async).
- **Unbounded `tokio::spawn` per CPE:** 50-port scan × 5 CPEs × 2 sources = 500 concurrent requests without the semaphore. Always acquire permit before spawning or inside the task.
- **Single shared reqwest::Client per source struct:** This is correct — do NOT create a new `Client` per request. One `Client` for NVD, one for CVE.org, initialized once.
- **Treating CVE.org as a CPE search engine:** CVE.org only accepts CVE ID. Use NVD for CPE→CVE-IDs, then optionally enrich via CVE.org per-ID.
- **Assuming V31 always present:** Many older CVEs only have V2. Many newer ones lack a V2. Check presence before indexing.
- **Treating `baseSeverity` location as uniform:** In V2 responses, `baseSeverity` is at the metric entry level, not inside `cvssData`. In V3+, it is inside `cvssData`. Deserialize accordingly.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| HTTP client with TLS | Custom TCP/TLS | reqwest 0.13 | Certificate verification, connection pooling, HTTP/2, redirect handling |
| JSON parsing | String scanning | serde_json + serde derive | Type-safe, handles edge cases, already in dependency tree |
| Async runtime | Custom executor | tokio 1.x | Battle-tested, ecosystem standard, reqwest requires it |
| Concurrency limiting | Manual mutex + counter | tokio::sync::Semaphore | Correct async semantics, no busy-waiting |
| CPE 2.2→2.3 conversion | Third-party CPE library | 10-line string function | The conversion is a simple prefix/split operation; no library needed |
| User-agent spoofing | Complex fingerprinting | Simple static string | NVD docs say to identify your client; static string suffices |

**Key insight:** The NVD and CVE.org APIs have enough quirks (CVSS location differences, CPE format requirements, rate limit status code history) that wrapping an existing Rust NVD crate (nvd-api 0.1.1) would add opacity without simplifying the implementation. The `nvd-api` crate is GPL-licensed, uses reqwest 0.11 (outdated), and is only 38% documented — hand-rolling the 40-line NVD client is the right call.

## Common Pitfalls

### Pitfall 1: CVSS baseSeverity Location Differs by Version
**What goes wrong:** Code indexes `cvssData.baseSeverity` for all CVSS versions, gets `null` for V2 records.
**Why it happens:** NVD API response puts `baseSeverity` at the metric entry level for V2, but inside `cvssData` for V3+.
**How to avoid:** Define separate serde structs for V2 and V3+ metric entries. Verified by live test against CVE-2007-2768 (V2 only) and CVE-2021-41773 (V31 + V2).
**Warning signs:** CVEs published before ~2015 showing no severity in output despite having CVSS scores.

### Pitfall 2: CVE.org CVSS Often Only in ADP Containers
**What goes wrong:** Code reads `containers.cna.metrics` and finds nothing for most CVEs.
**Why it happens:** CNA (vendor) often omits CVSS; CISA (an ADP = Authorized Data Publisher) adds it to `containers.adp[].metrics`. Confirmed by testing CVE-2023-44487.
**How to avoid:** Search both `containers.cna.metrics` and all `containers.adp[].metrics` arrays when extracting CVSS from CVE.org responses.
**Warning signs:** CVE.org always returning "no CVSS" while NVD returns a score for the same CVE.

### Pitfall 3: NVD 429 vs Historic 403
**What goes wrong:** Code treats HTTP 403 as "access denied" rather than "rate limited."
**Why it happens:** NVD migrated from returning 403 to 429 for rate limiting during infrastructure changes. Some implementations pattern-matched on 403.
**How to avoid:** Handle both 403 and 429 as `VulnLookupError::RateLimited` from NVD. Current NVD returns 429.
**Warning signs:** Seeing 403 in logs and treating it as a permanent error, giving up instead of retrying.

### Pitfall 4: CPE Query Returns Zero Results for Valid Service
**What goes wrong:** `cpeName` query returns 0 CVEs for a known-vulnerable service.
**Why it happens:** NVD's `cpeName` does exact matching — it won't match `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*` against CVEs whose configuration uses version ranges. Use `virtualMatchString` for broader matching that covers version ranges.
**How to avoid:** Try `virtualMatchString` when `cpeName` returns 0 results. `virtualMatchString` matches against CPE Match Criteria (includes version range entries), not just exact CPE names.
**Warning signs:** Known-vulnerable versions (e.g., Apache 2.4.49 / CVE-2021-41773) returning zero CVEs via `cpeName`.

### Pitfall 5: Blocking main Thread with Sync reqwest in Async Context
**What goes wrong:** `reqwest::blocking::Client` used inside a `#[tokio::main]` task causes a panic: "Cannot start a runtime from within a runtime."
**Why it happens:** The blocking client creates its own runtime internally, which conflicts with the existing tokio runtime.
**How to avoid:** Only use `reqwest::Client` (async version) within tokio tasks. Reserve `reqwest::blocking` for non-async code paths only.
**Warning signs:** Runtime panic at the first HTTP call.

### Pitfall 6: Creating reqwest::Client Per Request
**What goes wrong:** TLS handshake overhead on every request; connection pool bypassed; performance degrades severely on large scans.
**Why it happens:** `reqwest::Client::new()` is cheap to create but each new client opens fresh connections.
**How to avoid:** Create one `Client` per `VulnSource` struct, at construction time. Store it as `Arc<reqwest::Client>` if shared across tasks.

### Pitfall 7: NVD CPE Query Latency
**What goes wrong:** Scan of 50 services takes 10+ minutes even with concurrency.
**Why it happens:** NVD CPE API is inherently slow — one Gist benchmarked CPE queries at 5-10 seconds per request (vs <3s for CVE-by-ID queries). With 5 concurrent queries and the 6s sleep recommendation, this is unavoidable.
**How to avoid:** Set realistic timeout expectations. Show progress per D-12 so users know the tool is working. Consider using `virtualMatchString` only as fallback (it may be slower than `cpeName` for exact hits). Do not set very short timeouts — 30s per request is appropriate.
**Warning signs:** Tests timing out at 10s; integration tests hitting the real API.

### Pitfall 8: File Descriptor Exhaustion Without Semaphore
**What goes wrong:** 50 ports × multiple CPEs × 2 sources = hundreds of concurrent open sockets; OS rejects new connections.
**Why it happens:** `tokio::spawn` creates tasks for each lookup; without the Semaphore, all 500 can run concurrently.
**How to avoid:** The Semaphore with cap=5 (D-15) is non-negotiable. Acquire permit before making any HTTP request.

## Code Examples

### NVD Source Skeleton (Verified Patterns)
```rust
// src/sources/nvd.rs
use reqwest::{Client, StatusCode};
use serde::Deserialize;

pub struct NvdSource {
    client: Client,
    api_key: Option<String>,
}

impl NvdSource {
    pub fn new(api_key: Option<String>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("PortReaper/0.1 vulnerability-scanner")
            .build()
            .expect("failed to build HTTP client");
        NvdSource { client, api_key }
    }
}

// Serde types for NVD response (field names match API exactly)
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    total_results: u32,
    vulnerabilities: Vec<NvdVulnWrapper>,
}

#[derive(Deserialize)]
struct NvdVulnWrapper {
    cve: NvdCve,
}

#[derive(Deserialize)]
struct NvdCve {
    id: String,
    metrics: Option<NvdMetrics>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdMetrics {
    cvss_metric_v4: Option<Vec<CvssV4Entry>>,
    cvss_metric_v31: Option<Vec<CvssV3Entry>>,
    cvss_metric_v30: Option<Vec<CvssV3Entry>>,
    cvss_metric_v2: Option<Vec<CvssV2Entry>>,
}

// V3+: baseSeverity is inside cvssData
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssV3Entry {
    cvss_data: CvssV3Data,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssV3Data {
    base_score: f32,
    base_severity: String,  // "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"
}

// V2: baseSeverity is at the entry level, NOT inside cvssData
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssV2Entry {
    cvss_data: CvssV2Data,
    base_severity: String,  // "HIGH", "MEDIUM", "LOW"
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssV2Data {
    base_score: f32,
}
```

### CVE.org Source Skeleton
```rust
// src/sources/cve_org.rs
// Base URL: https://cveawg.mitre.org/api/cve/{id}
// No auth needed. Rate limit: 25,000 req/60s.
// CVSS may be in containers.cna.metrics OR containers.adp[].metrics.

#[derive(Deserialize)]
struct CveOrgResponse {
    #[serde(rename = "cveMetadata")]
    cve_metadata: CveMetadata,
    containers: CveContainers,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveMetadata {
    cve_id: String,
}

#[derive(Deserialize)]
struct CveContainers {
    cna: CveCna,
    #[serde(default)]
    adp: Vec<CveAdp>,
}

#[derive(Deserialize)]
struct CveCna {
    #[serde(default)]
    metrics: Vec<CveMetric>,
}

#[derive(Deserialize)]
struct CveAdp {
    #[serde(default)]
    metrics: Vec<CveMetric>,
}

#[derive(Deserialize)]
struct CveMetric {
    #[serde(rename = "cvssV3_1")]
    cvss_v3_1: Option<CveOrgCvssV3>,
    #[serde(rename = "cvssV3_0")]
    cvss_v3_0: Option<CveOrgCvssV3>,
    #[serde(rename = "cvssV4_0")]
    cvss_v4_0: Option<CveOrgCvssV4>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveOrgCvssV3 {
    base_score: f32,
    base_severity: String,
}
```

### CPE 2.2 to 2.3 Conversion
```rust
/// Convert nmap CPE 2.2 URI binding to NVD API v2.3 formatted string binding.
/// "cpe:/a:openbsd:openssh:8.9p1" → "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
pub fn cpe22_to_cpe23(cpe: &str) -> String {
    if let Some(rest) = cpe.strip_prefix("cpe:/") {
        // Split on ':' to extract part, vendor, product, version
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        let part    = parts.first().copied().unwrap_or("*");
        let vendor  = parts.get(1).copied().unwrap_or("*");
        let product = parts.get(2).copied().unwrap_or("*");
        let version = parts.get(3).copied().unwrap_or("*");
        format!("cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*")
    } else {
        // Already 2.3 format or unknown — pass through
        cpe.to_string()
    }
}
```

### Progress Output Pattern
```rust
// To stderr, format: "[N/M] Querying NVD for OpenSSH 8.9p1... 3 CVEs"
// N = completed + 1, M = total services with CPEs
eprintln!("[{}/{}] Querying {} for {} {}... {} CVEs",
    idx + 1,
    total,
    source_name,
    product.unwrap_or("unknown"),
    version.unwrap_or(""),
    cve_count
);
```

### Severity Classification
```rust
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    None,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "CRITICAL" => Self::Critical,
            "HIGH"     => Self::High,
            "MEDIUM"   => Self::Medium,
            "LOW"      => Self::Low,
            _          => Self::None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "Crit",
            Self::High     => "High",
            Self::Medium   => "Med",
            Self::Low      => "Low",
            Self::None     => "None",
        }
    }
}

// Color output with owo-colors (matches D-03):
// Critical = red, High = yellow, Medium = cyan, Low = green
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| NVD HTTPS data feeds (JSON/XML download) | NVD API v2 REST | 2023 (feeds retired) | Must use API; batch downloads no longer available |
| NVD API 1.0 | NVD API 2.0 | 2023 | Different base URL, apiKey in header not query param |
| NVD rate limit 403 | NVD rate limit 429 | ~2023 infrastructure migration | Must handle both for robustness |
| CVSS v2 primary | CVSS v3.1 primary, v4.0 emerging | July 2022 (NVD stopped generating v2) | Older CVEs may only have v2; newer have v3.1+ |
| CVE 4.0 JSON format | CVE JSON 5.0/5.1 format | 2023 | CVE.org API now uses 5.x schema |

**Deprecated/outdated:**
- NVD HTTPS data feeds (nvd.nist.gov/vuln/data-feeds): Retired. Must use API.
- NVD API v1 (services.nvd.nist.gov/rest/json/cves/1.0): No longer documented as current.
- CVSS v2 NVD generation: Stopped July 2022; existing records still have v2 data.
- `nvd-api` crate 0.1.1: GPL-3.0, reqwest 0.11, 38% documented — do not use.

## Open Questions

1. **virtualMatchString vs cpeName fallback strategy**
   - What we know: `cpeName` does exact match; `virtualMatchString` matches CPE Match Criteria including version ranges
   - What's unclear: Whether `cpeName` ever returns results for nmap-format CPEs that don't appear exactly in NVD's CPE dictionary (version components with suffixes like `8.9p1` may not match)
   - Recommendation: Try `cpeName` first; if `totalResults == 0`, retry with `virtualMatchString` using same CPE components. Document this as a fallback in the NVD source implementation.

2. **CVE.org enrichment value**
   - What we know: CVE.org CVSS coverage is sparse (often only in ADP containers); rate limit is 25,000/60s (no concern)
   - What's unclear: Whether fetching from CVE.org per-CVE-ID after NVD lookup adds enough CVSS coverage to justify the extra requests
   - Recommendation: Implement CVE.org as a secondary enrichment source per VULN-02. If CVE.org has a higher CVSS for a CVE already found in NVD, D-08 takes the highest. Implement but make it low-priority in execution (run after NVD, per CVE ID).

3. **Integration test strategy for API calls**
   - What we know: Tests should not hit live APIs (flaky, rate-limited)
   - What's unclear: Whether to use `mockito` (HTTP mock server) or recorded fixtures
   - Recommendation: Use recorded JSON fixture files. Capture one real NVD response and one CVE.org response. Feed them through a `MockVulnSource` that returns fixed data. Keep live API calls out of automated tests.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in (`cargo test`) |
| Config file | none (uses Cargo.toml test setup) |
| Quick run command | `cargo test --lib` |
| Full suite command | `cargo test` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|--------------|
| VULN-01 | NVD lookup returns CVEs with CVSS scores for OpenSSH 7.4 CPE | unit (mock) | `cargo test --lib sources::nvd` | Wave 0 |
| VULN-01 | CVSS extraction works for V2, V31, and mixed records | unit | `cargo test --lib sources::nvd::tests` | Wave 0 |
| VULN-02 | CVE.org lookup enriches a CVE ID with CVSS from ADP containers | unit (mock) | `cargo test --lib sources::cve_org` | Wave 0 |
| VULN-05 | CPE 2.2 to 2.3 conversion produces correct NVD-compatible strings | unit | `cargo test --lib sources::nvd::tests::cpe_conversion` | Wave 0 |
| VULN-05 | Services without CPE strings are skipped with warning | unit | `cargo test --lib enrichment::tests::no_cpe_skip` | Wave 0 |
| VULN-06 | Semaphore limits concurrent requests to configured cap | unit | `cargo test --lib enrichment::tests::concurrency_bounded` | Wave 0 |
| VULN-06 | Exponential backoff retries 3x on RateLimited errors | unit | `cargo test --lib sources::nvd::tests::retry_backoff` | Wave 0 |
| VULN-06 | Partial results returned when one source fails | unit | `cargo test --lib enrichment::tests::partial_failure` | Wave 0 |
| ARCH-04 | Progress lines written to stderr during lookup | integration | `cargo test --test cli test_enrich_progress_to_stderr` | Wave 0 |
| ARCH-04 | -q flag suppresses progress but CVEs appear in stdout | integration | `cargo test --test cli test_enrich_quiet_flag` | Wave 0 |
| D-04 | Summary line includes CVE counts by severity | unit | `cargo test --lib render::tree::tests::summary_with_cves` | Wave 0 |
| D-08 | Deduplication keeps highest CVSS when same CVE in both sources | unit | `cargo test --lib enrichment::tests::dedup_takes_highest` | Wave 0 |
| D-14 | --no-enrich flag skips vuln lookups entirely | integration | `cargo test --test cli test_no_enrich_flag` | Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test --lib`
- **Per wave merge:** `cargo test`
- **Phase gate:** Full `cargo test` green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `src/sources/nvd.rs` — NvdSource unit tests with fixture JSON
- [ ] `src/sources/cve_org.rs` — CveOrgSource unit tests with fixture JSON
- [ ] `src/enrichment/mod.rs` — enrichment orchestration tests (mock sources)
- [ ] `tests/fixtures/nvd_response_openssh74.json` — recorded NVD API response for testing
- [ ] `tests/fixtures/cve_org_response_cve_2021_41773.json` — recorded CVE.org response
- [ ] `tests/fixtures/scan_vulnerable.xml` — nmap XML with OpenSSH 7.4 + Apache 2.4.49 + CPEs

*(Existing test infrastructure covers Phase 1 requirements; Phase 2 needs new source and enrichment test modules.)*

## Sources

### Primary (HIGH confidence)
- Live NVD API query (2026-03-21) — confirmed endpoint URL, cpeName parameter, response structure, CVSS field locations for V2 and V31
- Live CVE.org API query (2026-03-21) — confirmed endpoint URL, rate limit headers (25000/60s), no auth required, ADP container CVSS pattern
- Official NVD documentation (nvd.nist.gov/developers/vulnerabilities, nvd.nist.gov/developers/start-here) — rate limits, apiKey header format, pagination parameters
- Existing codebase inspection — VulnSource trait structure, models.rs field shapes, render/tree.rs patterns, Cargo.toml dependencies

### Secondary (MEDIUM confidence)
- WebSearch: NVD rate limits (5/30s without key, 50/30s with key) — confirmed by multiple sources including SANS ISC diary, Medium article, and NVD announcement page
- WebSearch: reqwest 0.13.2 current version — confirmed via crates.io search
- WebSearch: tokio 1.50.0 current version — confirmed via crates.io search
- CVE JSON 5.0 schema docs (cveproject.github.io/cve-schema/schema/docs/) — CVSS field names in CVE.org format

### Tertiary (LOW confidence)
- CPE query latency (5-10 seconds per request) — from a single GitHub Gist benchmark; not independently verified
- NVD 403→429 migration history — mentioned in multiple community sources but exact timeline not verified against official NVD changelog

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — versions confirmed from crates.io registry live query
- NVD API structure: HIGH — confirmed by live API calls returning real data
- CVE.org API structure: HIGH — confirmed by live API calls including rate limit headers
- Architecture patterns: HIGH — derived from confirmed API behavior + existing codebase patterns
- Pitfalls: HIGH for CVSS field location (live-confirmed); MEDIUM for latency estimates

**Research date:** 2026-03-21
**Valid until:** 2026-06-21 (90 days; NVD API is stable but verify rate limits if NVD announces changes)

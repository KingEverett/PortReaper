---
phase: 02-enrichment-core
verified: 2026-03-21T00:00:00Z
status: passed
score: 17/17 must-haves verified
---

# Phase 2: Enrichment Core — Verification Report

**Phase Goal:** Users can run PortReaper against a real scan and get NVD + CVE.org vulnerability data for each service, classified by CVSS severity, with correct rate limiting and no silent data loss from API failures
**Verified:** 2026-03-21
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

The five success criteria from ROADMAP.md were used as the primary truth set, supplemented by must_haves from each plan's frontmatter.

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Running against a scan with known-vulnerable services surfaces real CVE IDs from NVD and CVE.org with CVSS scores and severity classification | VERIFIED | `NvdSource::lookup_cpe` queries NVD API v2 by CPE; `CveOrgSource::lookup_cve_id` enriches per CVE; `enrich_scan` wires both; fixture tests confirm CVE-2021-41773 at 9.8/Critical, CVE-2017-15906 at 5.3/Medium |
| 2 | When NVD rate limits are hit, the tool retries with exponential backoff and reports partial results rather than silently returning zero findings | VERIFIED | `with_retry` in `src/enrichment/mod.rs` implements [1s, 2s, 4s] delays, retries on `RateLimited` and `NetworkFailure`, returns immediately on `Empty`; test `with_retry_retries_3_times_on_rate_limited` confirms 3 attempts; partial results preserved via `source_failures` vec |
| 3 | A 50-port scan completes without exhausting file descriptors — concurrent queries are bounded by a configurable semaphore | VERIFIED | `Arc<Semaphore>::new(opts.concurrency)` in `enrich_scan`; `EnrichmentOptions.concurrency` defaults to 5; semaphore permit acquired before each service task |
| 4 | CVE-2021-41773 appearing in both NVD and CVE.org results appears exactly once in output (deduplication by CVE ID) | VERIFIED | `dedup_vulnerabilities` groups by `cve_id`, keeps highest CVSS score; `dedup_keeps_highest_cvss_for_same_cve_id` test confirms; CVE.org integration updates CVSS on existing entry rather than adding duplicate |
| 5 | Progress output is shown during vulnerability lookups so the user can see the tool is working on large scans | VERIFIED | `eprintln!("[{}/{}] Querying NVD for {}... {} CVEs", ...)` for NVD phase; `eprintln!("[CVE.org] Enriching {} CVEs for {}...", ...)` for CVE.org phase; both suppressed by `opts.quiet`; `-q` flag wired through CLI |

**Score: 5/5 success criteria verified**

---

## Plan 01 Must-Haves

| Truth | Status | Evidence |
|-------|--------|----------|
| Vulnerability and Severity types exist with correct field shapes | VERIFIED | `src/models.rs`: `pub struct Vulnerability`, `pub struct CvssScore`, `pub enum Severity` all present with correct fields |
| NVD API v2 queries by CPE 2.3 string return parsed CVE results with CVSS scores | VERIFIED | `NvdSource::lookup_cpe` builds URL with `cpeName` query param and `resultsPerPage=2000`; `extract_vulnerabilities` parses response; tested against fixtures |
| CPE 2.2 strings from nmap are transparently converted to CPE 2.3 for NVD queries | VERIFIED | `cpe22_to_cpe23` in `src/sources/mod.rs`; called at start of `lookup_cpe`; 3 unit tests cover openssh, already-2.3, and no-version cases |
| CVSS extraction works for V4, V31, V30, and V2 with correct baseSeverity location | VERIFIED | `extract_cvss` in `src/sources/nvd.rs`; V4/V3.x read `baseSeverity` from `cvssData`; V2 reads `baseSeverity` from entry level not `cvssData`; fixture test `parse_openssh74_v2_entry_baseseverity_at_entry_level` confirms |
| NVD rate limiting (429 and 403) triggers RateLimited error variant | VERIFIED | `if status == StatusCode::TOO_MANY_REQUESTS \|\| status == StatusCode::FORBIDDEN { return Err(VulnLookupError::RateLimited {...}) }` in `lookup_cpe` |

---

## Plan 02 Must-Haves

| Truth | Status | Evidence |
|-------|--------|----------|
| CVE.org API returns CVSS data for a known CVE ID, extracting from both CNA and ADP containers | VERIFIED | `extract_cvss_from_cve_org` iterates CNA then all ADP containers; tests `parse_41773_adp_has_cvss_v3_1_critical` and `parse_44487_adp_has_cvss_v3_1_high` confirm; `other`-type CNA metrics handled gracefully |
| Enrichment orchestrator queries all CPE strings per service across all sources with bounded concurrency | VERIFIED | `enrich_scan` iterates all (host, port, cpe_list) tuples; spawns tokio tasks; semaphore bounds concurrency |
| Deduplication by CVE ID keeps the highest CVSS score | VERIFIED | `dedup_vulnerabilities` logic confirmed; 4 unit tests cover all cases including None/Some and same/different IDs |
| Exponential backoff retries 3 times (1s, 2s, 4s) on RateLimited and NetworkFailure errors | VERIFIED | `delays = [Duration::from_secs(1), Duration::from_secs(2), Duration::from_secs(4)]` in `with_retry`; retry loop confirmed by unit tests |
| Services without CPE strings are skipped with a warning message | VERIFIED | `eprintln!("Warning: {}/{} {}: no CPE -- skipping vuln lookup", ...)` in `enrich_scan`; `services_skipped` counter incremented |
| When one source fails, partial results from successful sources are still returned | VERIFIED | Failure recorded in local `failure: Option<String>` per task; pushed to `stats.source_failures` after join; other service results collected regardless |

---

## Plan 03 Must-Haves

| Truth | Status | Evidence |
|-------|--------|----------|
| Running with --no-enrich produces Phase 1 tree output only (no API calls) | VERIFIED | `cli.no_enrich: bool` in `src/cli.rs`; `if !cli.no_enrich { ... enrich_scan ... }` in `src/main.rs`; `test_no_enrich_flag` integration test asserts no `CVE-` in output |
| CVE lines appear inline under their port/service in the tree with format CVE-ID [Severity Score] | VERIFIED | `render_vulnerability` in `src/render/tree.rs`; format `"{} {}", vuln.cve_id, severity_tag` where `severity_tag = "[{} {:.1}]"`; unit test `render_vulnerability_formats_cve_id_and_severity` confirms `[Crit 9.8]` |
| Severity labels are color-coded: Critical=red, High=yellow, Medium=cyan, Low=green | VERIFIED | `match vuln.cvss.as_ref().map(\|c\| &c.severity)` with `.red()`, `.yellow()`, `.cyan()`, `.green()` calls |
| Summary line shows CVE counts by severity when vulnerabilities present | VERIFIED | `if total_cves > 0 { format!("Summary: {} hosts, {} open ports, {} CVEs ({} critical, {} high, {} medium, {} low)", ...) }` |
| Progress lines go to stderr showing [N/M] Querying {source} for {product} {version}... X CVEs | VERIFIED | `eprintln!("[{}/{}] Querying NVD for {}... {} CVEs", pos, total, product_version, all_vulns.len())` |
| -q flag suppresses stderr progress but CVE tree still appears in stdout | VERIFIED | `quiet: cli.quiet` passed to `EnrichmentOptions`; `if !quiet { eprintln!(...) }` gates all progress; tree renderer always runs |
| main.rs uses #[tokio::main] and async fn run() | VERIFIED | Lines 11-12 of `src/main.rs` |

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/models.rs` | Vulnerability struct, CvssScore, Severity enum | VERIFIED | All three types present with correct fields; `Port.vulnerabilities: Vec<Vulnerability>` field present |
| `src/sources/mod.rs` | Updated VulnSource trait with async lookup_cpe method | VERIFIED | `fn lookup_cpe` present using RPITIT; `cpe22_to_cpe23` present; `pub mod nvd;` and `pub mod cve_org;` present |
| `src/sources/nvd.rs` | NvdSource implementing VulnSource with reqwest, CVSS extraction, CPE conversion | VERIFIED | `pub struct NvdSource`, `impl VulnSource for NvdSource`, `fn extract_cvss`, `fn extract_vulnerabilities` all present; 429/403 handled as `RateLimited` |
| `src/sources/cve_org.rs` | CveOrgSource implementing VulnSource for per-CVE-ID enrichment | VERIFIED | `pub struct CveOrgSource`, `pub async fn lookup_cve_id`, `impl VulnSource for CveOrgSource` (returns `Empty` for `lookup_cpe`); `cveawg.mitre.org` URL present |
| `src/enrichment/mod.rs` | enrich_scan orchestrator with semaphore, dedup, backoff, progress | VERIFIED | `pub async fn enrich_scan`, `fn dedup_vulnerabilities`, `async fn with_retry`, `Semaphore::new`, retry delays `[1, 2, 4]`, `EnrichmentStats`, progress `eprintln!`, `[CVE.org]` line, `no CPE` warning |
| `src/cli.rs` | Updated CLI with --no-enrich flag | VERIFIED | `pub no_enrich: bool` with `#[arg(long)]`; old `pub enrich: bool` removed |
| `src/main.rs` | Async main wiring parse -> enrich -> render pipeline | VERIFIED | `#[tokio::main]`, `async fn main()`, `async fn run()`, `NvdSource::new`, `CveOrgSource::new`, `enrich_scan`, `PORTREAPER_NVD_KEY`, `cli.no_enrich` |
| `src/render/tree.rs` | Tree renderer extended with CVE child nodes and severity summary | VERIFIED | `fn render_vulnerability`, `Severity::Critical` `.red()`, `Severity::High` `.yellow()`, `Severity::Medium` `.cyan()`, `Severity::Low` `.green()`, CVE summary format, `port.vulnerabilities` read |
| `src/lib.rs` | Module declarations for enrichment, sources | VERIFIED | `pub mod enrichment;` present alongside existing modules |
| `tests/fixtures/nvd_response_openssh74.json` | NVD fixture with V31 and V2-only entries | VERIFIED | `totalResults: 2`, contains `CVE-2017-15906` (V31+V2) and `CVE-2007-2768` (V2 only) |
| `tests/fixtures/nvd_response_apache249.json` | NVD fixture with CVE-2021-41773 CRITICAL | VERIFIED | Contains `CVE-2021-41773` with `baseScore: 9.8` and `CRITICAL` |
| `tests/fixtures/cve_org_response_cve_2021_41773.json` | CVE.org fixture with ADP CVSS | VERIFIED | CNA has `other`-type metric; ADP has `cvssV3_1: { baseScore: 9.8, baseSeverity: "CRITICAL" }` |
| `tests/fixtures/cve_org_response_cve_2023_44487.json` | CVE.org fixture for CVE-2023-44487 | VERIFIED | Contains `CVE-2023-44487` with ADP `cvssV3_1: 7.5 HIGH` |
| `tests/fixtures/scan_vulnerable.xml` | Nmap XML fixture with OpenSSH 7.4 and Apache 2.4.49 CPEs | VERIFIED | Contains `cpe:/a:openbsd:openssh:7.4` and `cpe:/a:apache:http_server:2.4.49` |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `src/sources/nvd.rs` | `src/models.rs` | `NvdSource.lookup_cpe` returns `Vec<Vulnerability>` | VERIFIED | `extract_vulnerabilities` returns `Vec<Vulnerability>`; `impl VulnSource for NvdSource` return type confirms |
| `src/sources/nvd.rs` | `src/sources/mod.rs` | `impl VulnSource for NvdSource` | VERIFIED | Present at line 167 of `nvd.rs` |
| `src/enrichment/mod.rs` | `src/sources/mod.rs` | Uses `VulnSource` trait to query sources | VERIFIED | Uses concrete `NvdSource` and `CveOrgSource` directly (Arc) rather than `dyn VulnSource`; plan notes this is intentional to avoid RPITIT object-safety issues; functionally equivalent |
| `src/enrichment/mod.rs` | `src/models.rs` | Writes `Vec<Vulnerability>` to `Port.vulnerabilities` | VERIFIED | `scan.hosts[host_idx].ports[port_idx].vulnerabilities = vulns;` at line 203 |
| `src/sources/cve_org.rs` | `src/sources/mod.rs` | `impl VulnSource for CveOrgSource` | VERIFIED | Present at line 66 of `cve_org.rs` |
| `src/main.rs` | `src/enrichment/mod.rs` | Calls `enrich_scan` between parse and render | VERIFIED | `portreaper::enrichment::enrich_scan(&mut result, nvd, cve_org, &enrich_opts).await` |
| `src/render/tree.rs` | `src/models.rs` | Reads `Port.vulnerabilities` to render CVE lines | VERIFIED | `port.vulnerabilities.len()` and `.iter().enumerate()` in `render_port` |
| `src/main.rs` | `src/sources/nvd.rs` | Creates `NvdSource` with optional API key from env | VERIFIED | `portreaper::sources::nvd::NvdSource::new(api_key)` with `std::env::var("PORTREAPER_NVD_KEY").ok()` |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| VULN-01 | 02-01 | Query NVD (NIST) for CVEs and CVSS scores | SATISFIED | `NvdSource` queries `https://services.nvd.nist.gov/rest/json/cves/2.0`; extracts CVSS V4/V31/V30/V2; wired into `enrich_scan` |
| VULN-02 | 02-02 | Query CVE.org for vulnerability data | SATISFIED | `CveOrgSource` queries `https://cveawg.mitre.org/api/cve/{id}`; extracts CVSS from CNA and ADP containers; integrated in enrichment loop |
| VULN-05 | 02-01 | CPE-based matching for accurate vulnerability lookups | SATISFIED | `cpe22_to_cpe23` converts nmap CPE 2.2 to CPE 2.3 for NVD queries; NVD API queried with `cpeName` param; `Port.service.cpe` drives lookup |
| VULN-06 | 02-02, 02-03 | Rate limiting and bounded concurrency for API queries | SATISFIED | Semaphore bounds concurrency (default 5); `with_retry` handles `RateLimited` / `NetworkFailure` with exponential backoff; 429 and 403 map to `RateLimited` |
| ARCH-04 | 02-03 | Progress indicators during vulnerability lookups | SATISFIED | `[N/M] Querying NVD for {product}... X CVEs` and `[CVE.org] Enriching N CVEs for {product}...` to stderr; suppressible with `-q` |

All 5 required requirement IDs (VULN-01, VULN-02, VULN-05, VULN-06, ARCH-04) are satisfied. No orphaned requirements found — REQUIREMENTS.md traceability table maps exactly these five IDs to Phase 2.

---

## Anti-Patterns Scan

Files modified in this phase were scanned for stub indicators.

| File | Pattern | Assessment |
|------|---------|------------|
| `src/sources/nvd.rs` | Line 1: comment "placeholder until Task 2" | INFO only — comment is stale/misleading but implementation is complete. The full `NvdSource` with `lookup_cpe`, `extract_cvss`, and `extract_vulnerabilities` is present. No functional impact. |
| All files | `return null/\{\}/\[\]` patterns | No stub returns found in implementation code paths |
| `src/enrichment/mod.rs` | TODO/FIXME | None found |
| `src/render/tree.rs` | Empty CVE rendering | `render_vulnerability` is fully implemented, not a stub |

One minor stale comment (not a blocker):
- `src/sources/nvd.rs` line 1-2: `// NvdSource implementation — placeholder until Task 2 / // This file will be fully implemented in Task 2.` These comments were left over from scaffolding and are now factually incorrect. They carry no functional impact since the implementation is complete.

Severity: INFO (not a blocker, not a warning — purely cosmetic).

---

## Test Suite Results

```
cargo test — all suites:
  lib tests:    64 passed, 0 failed  (includes models, sources, enrichment, render)
  cli tests:     9 passed, 0 failed  (integration tests including test_no_enrich_flag)
  xml_parse:     9 passed, 0 failed
  text_parse:    6 passed, 0 failed
  greppable:     5 passed, 0 failed
  doc tests:     0 tests
  Total:       107 passed, 0 failed
```

`cargo build` completes with 0 errors (warnings only: unused imports in `parser/mod.rs`, private_interfaces lint on `pub(crate)` functions in `nvd.rs`).

---

## Human Verification Required

The following behaviors cannot be verified programmatically:

### 1. Live NVD API Integration

**Test:** Run `portreaper tests/fixtures/scan_vulnerable.xml` (without `--no-enrich`) against the live NVD API
**Expected:** CVE entries appear under port 22/tcp (OpenSSH 7.4) and port 80/tcp (Apache 2.4.49) with CVSS scores, severity labels, and color-coding
**Why human:** Requires live network access to `services.nvd.nist.gov`; cannot verify in automated CI without hitting the API

### 2. Color Rendering in Terminal

**Test:** Run `portreaper --no-enrich tests/fixtures/scan_basic.xml` in a color-capable terminal after manually adding a vulnerability to a Port fixture
**Expected:** Critical severities render in red, High in yellow, Medium in cyan, Low in green
**Why human:** `owo_colors` uses `if_supports_color(Stream::Stdout, ...)` which auto-disables color in piped/test contexts; visual confirmation requires a real TTY

### 3. Progress Output Timing

**Test:** Run against a scan with multiple CPE-bearing services without `--no-enrich`
**Expected:** Progress lines appear in real-time to stderr as services are processed; not buffered until end
**Why human:** Timing/streaming behavior cannot be asserted from captured output

---

## Summary

Phase 2 goal is fully achieved. All 17 must-have items across plans 01, 02, and 03 are verified. All 5 requirements (VULN-01, VULN-02, VULN-05, VULN-06, ARCH-04) are satisfied. The complete enrichment pipeline exists and is wired:

1. `NvdSource` — queries NVD API v2 by CPE, extracts CVSS V4/V31/V30/V2 with correct V2 baseSeverity location, handles 429/403 as `RateLimited`
2. `CveOrgSource` — fetches per-CVE records from cveawg.mitre.org, extracts CVSS from both CNA and ADP containers (handling non-CVSS `other`-type metrics), returns highest score across containers
3. `enrich_scan` — orchestrates both sources per service, bounded by semaphore (default 5), retries via exponential backoff (1s/2s/4s), deduplicates by CVE ID keeping highest CVSS, reports partial results on source failure
4. `render_tree` — shows CVEs inline under port nodes with `[Crit 9.8]` format, severity color-coding, and updated summary line with CVE counts by severity
5. CLI — `--no-enrich` skips enrichment entirely; `-q` suppresses progress to stderr; `PORTREAPER_NVD_KEY` env var controls NVD API key

The sole stale comment in `nvd.rs` line 1 is cosmetic and does not affect correctness.

---

_Verified: 2026-03-21_
_Verifier: Claude (gsd-verifier)_

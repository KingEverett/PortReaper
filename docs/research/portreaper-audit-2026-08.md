# PortReaper — Audit & Market Research

*Produced 2026-08-12. Lens: personal tool / scan-ingestion layer of the bug-bounty suite (not a public product). Goals: (A) more usable for our own workflow, (B) more efficient across runtime, code health, analyst-time, and token/AI cost.*

All code claims are cited to `file:line` in the current tree and were independently
re-verified after the audit agents reported. Bottleneck rankings are static-analysis
**inferences** (no live scan was run); correctness/state claims are **measured**.

---

## 0. Ground-truth metrics (measured)

| Metric | Value | Notes |
|---|---|---|
| Source size | ~7,603 LOC / 26 files | `src/` only |
| Tests | **250 pass, 0 fail** | ~20s total; one integration suite alone is **17.25s** (suspicious — investigate, TEST-3) |
| Release build | **58s** clean | 13 lib warnings |
| `cargo clippy` | **RED — 4 errors, 35 warnings (exit 101)** | Build is green but lint gate fails; the `source_status` bug (BUG-1) is one of the 4 errors |

**Headline:** the tool builds and all tests pass, but the lint gate is red, one
user-visible status line is logically wrong, one advertised feature (OS detection)
is silently dead, and the enrichment path leaves clear efficiency and
prioritization wins on the table. None of these are structural rot — the
architecture is clean and the fixes are mostly small.

---

## 1. Code health & maintainability

Architecture is sound: unidirectional `parser → models → enrichment → vault`
layering, no circular deps, `models` dependency-free, `vault` reasonably
decomposed. The problems are localized.

| # | Sev | Finding | Evidence |
|---|-----|---------|----------|
| BUG-1 | **High** | `source_status` is a tautology. `nvd_fail == 0 && nvd_ok > 0 \|\| nvd_fail == 0` reduces to `nvd_fail == 0` (`&&` binds before `\|\|`), so the `ok > 0` term is dead — a source that ran **zero** queries reports "OK". Clippy denies this → red gate. | `enrichment/mod.rs:374,377,380,383` (verified) |
| BUG-2 | **High** | `os_matches` is a dead data path. Declared on `Host`, rendered as "OS:" (`vault/mod.rs:281`, `templates.rs:101`), merged (`parser/mod.rs:111`) — but **every parser hardcodes `vec![]`**; no `<os>`/`<osmatch>` deser exists. OS detection is advertised (`-v`) but always absent. | parsers `greppable.rs:82`, `text.rs:99`, `xml.rs:172`, `parser/mod.rs:218` (verified) |
| BUG-3 | Low | `detect_format` slices `content[..min(64)]` on a **byte** boundary → panics on multibyte input at byte 64. Input is untrusted files/stdin. | `parser/mod.rs:18` |
| DRY-1 | Med | 4-way copy-paste in the enrichment orchestrator: NVD/OSV cache blocks are ~40 near-identical lines each; success/fail tracking is 8 hand-cloned `AtomicUsize` pairs + repeated status pushes. High per-source edit cost. | `enrichment/mod.rs:148-155,186-269,364-384` |
| ABS-1 | Med | `VulnSource` trait is leaky: CVE.org's `lookup_cpe` is a permanent stub (`cve_org.rs:71`); the real method is inherent `lookup_cve_id`; the orchestrator takes concrete `Arc<NvdSource>` etc. and never dispatches through the trait. The abstraction earns little. | `cve_org.rs:66-76`, `enrichment/mod.rs:78-84` |
| MERGE-1 | Med | Score-History merge scrapes rendered markdown tables (`split('\|')`, filter `---`/`Date`) — brittle vs. the structured `serde_yml` used for tags. A user editing the table silently drops history. | `vault/merge.rs:72-102` |
| DEP-1 | Low | `tokio = { features = ["full"] }` pulls the whole runtime; only a subset is used → heavier build/binary. | `Cargo.toml:20` |
| DEP-2 | Low | `serde_yml = "0.0.12"` is a pre-1.0 fork of the unmaintained `serde_yaml`, load-bearing for all frontmatter. Supply-chain/maintenance risk. | `Cargo.toml:17` |
| DEAD-1 | Low | Dead code: `NvdSource::build_nvd_url` used only by its own test; ~10 never-read serde fields. | `nvd.rs:25`, clippy "never read" |
| TEST-1 | Med | `enrichment::enrich_scan` (the orchestrator holding BUG-1) has **no test** — only helper `dedup`/`with_retry` are covered. Nothing would have caught BUG-1. | — |
| TEST-2 | Med | `render/tree.rs` tests re-derive the expected format string inline and assert against that local copy instead of captured stdout — tautological, can't fail on regression. | `tree.rs:470,485,505` |

**Positive:** error handling is consistent and idiomatic (`thiserror` for domain
errors, `anyhow` at boundaries; no reckless `unwrap` on untrusted data). Parser,
models, cache, config, merge, and frontmatter have real coverage.

---

## 2. Runtime & throughput (inferred; no live scan)

Concurrency model is *parallel across services* (one `tokio::spawn` per
service-with-CPE, bounded by `Semaphore::new(concurrency)`, default 5 —
`enrichment/mod.rs:143,179`) but **serial within each task**, which is where the
cost is.

| # | Impact | Finding | Evidence |
|---|--------|---------|----------|
| PERF-1 | **High** | No proactive rate-limiting. Keyless NVD allows ~5 req/30s but concurrency=5 × multiple CPEs/task bursts past it; the only defense is reactive retry, and `retry_after_secs: 30` is **ignored** — `with_retry` uses fixed 1/2/4s delays shorter than NVD's window → cascading failures. | `nvd.rs:194`, `enrichment/mod.rs:422-453` |
| PERF-2 | **High** | CVE.org enrichment loops **serially per-CVE** inside each task (`for vuln in &mut all_vulns { with_retry(cve_org.lookup_cve_id).await }`). 30 CVEs = 30 sequential round-trips. Largest per-task cold cost. OSV already fans out (`osv.rs:250-276`) — mirror it. | `enrichment/mod.rs:282-306` |
| PERF-3 | **High** | **CVE.org is entirely uncached** — NVD/OSV wrap `read_cache`/`write_cache` (190/203, 232/245), CVE.org branch does not (verified). Every run re-fetches every CVE even on warm cache. | `enrichment/mod.rs:272-306`, `cache/mod.rs` |
| PERF-4 | Med | No run-level dedup/memoization. 10 hosts running `Apache 2.4.49` = 10 identical NVD+OSV fetches, fired concurrently (also worsens the rate-limit burst and causes a cold-start cache stampede — all miss, all fetch, all write same file). | `enrichment/mod.rs:92-134,159-347` |
| PERF-5 | Med | Within a task NVD→OSV→CVE.org run **sequentially** though NVD and OSV are independent and could `tokio::join!`. | `enrichment/mod.rs:187-269` |
| PERF-6 | Low | O(n²) dedup via repeated `Vec::contains` in vault index + merge. Negligible today; trivial `HashSet` swap. | `vault/mod.rs:170-219`, `merge.rs:221-273` |

**Highest cold-run ROI:** PERF-1 (rate limiter) + PERF-2 (parallel CVE.org),
then PERF-4 (dedup) for multi-host scans with repeated tech.

---

## 3. Analyst time-to-insight

The vault **index/overview** notes prioritize well (severity-ordered breakdown,
Top-CVEs sorted by score — `vault/mod.rs:416-493`). But the paths an analyst
actually reads first do not:

- **Terminal tree is unsorted** — hosts/ports/CVEs render in scan order; a
  Critical can sit below a Low on the same port (`tree.rs:76-79,113-182`).
- **Per-host & per-service tables are unsorted** (source order —
  `templates.rs:110-120,243-249`).
- **Exploit availability is invisible in the tree.** `Port.exploits` exists and
  is rendered in the service note, but never in the tree or any index — the single
  strongest triage signal ("a PoC exists") doesn't bubble up (`models.rs:46`,
  `tree.rs:119-208`).
- **No KEV / EPSS anywhere** (grep-confirmed zero hits). Prioritization is
  CVSS-only, which is exactly what the market has moved past (see §5).

Fastest wins: sort tree + tables severity-desc; add an exploit marker; add
`--min-severity` / `--exploitable-only`; then ingest CISA KEV (§5).

---

## 4. Token / AI cost for suite integration

**There is no machine-readable output at all.** The only structured file is
`.obsidian/graph.json` (UI color config, not data — `vault/mod.rs:251`). The
Brain/Dashboard/agents would have to parse human markdown, paying for:

- **Duplication:** each CVE's description+score appears in the service table, the
  CVE note body, and the overview table; host↔CVE↔service links are materialized
  bidirectionally (`templates.rs:156-161,241-249,308-325,519-527`).
- **Boilerplate:** every note ends with a literal `## Notes` heading; every CVE
  note hardcodes NVD+CVE.org reference links (`templates.rs:163,328-331`).
- *Already lean:* frontmatter skips empty fields; descriptions truncate at 120
  chars (`frontmatter.rs:6-40`, `templates.rs:75-86`).

**Fix:** emit a lean **JSONL** artifact (one object per host, nested
ports→services→vulns→exploits — `models.rs` structs are plain derives, need only
`Serialize`). One file, no wikilink-walking. Optionally **SQLite** for the
Dashboard. Markdown stays the human/Obsidian surface. This is the highest-leverage
change for the suite.

---

## 5. Market & landscape research

**Positioning — the niche is genuinely open.** The two adjacent territories each
lack the other half:

- nmap→markdown converters ([nmap-formatter](https://github.com/vdjagilev/nmap-formatter),
  ~737★, active; Nmap2Table) do **format only — no enrichment, no linked graph**.
- Obsidian-pentest workflows (TrustedSec, Snifer/blue-pho3nix templates) are
  **manual**.
- The only direct nmap→Obsidian tool,
  [Yasha-ops/nmap-plugin](https://github.com/Yasha-ops/nmap-plugin), is a ~4★
  hobby project with no CVE enrichment, no wikilinks, no frontmatter, no graph.

So *nmap → auto-enriched → bidirectionally-linked, severity-graphed vault* is
effectively undone at any maturity. The risk isn't a competitor — it's the
**false-positive credibility problem** (below) and the fact that value
concentrates in enrichment quality + prioritization, which is where the cheap
wins are.

**Expected capabilities we're missing (gaps):**

1. **CISA KEV** (known-exploited) tagging — now table-stakes; small free JSON
   feed. [Vuls](https://github.com/future-architect/vuls) integrates it. **Highest-value gap.**
2. **EPSS** exploit-probability — free daily FIRST.org feed; practitioners
   prioritize by KEV+EPSS over raw CVSS. Caveat to surface: EPSS *lags*
   weaponization, so pair with KEV, don't replace it.
3. **Confidence / version-range-aware CPE matching** — the Achilles' heel of this
   whole tool class (nmap-vulners is [notorious](https://github.com/vulnersCom/nmap-vulners/issues/32)
   for it): banners hide patch level, distro backporting, product mismatches.
   Respect NVD `versionStart/EndIncluding/Excluding` instead of exact-version, and
   stamp each host↔CVE link with a confidence level.
4. **Multi-tool ingestion** — nmap-only is limiting; the modern stack is
   masscan/[naabu](https://github.com/projectdiscovery/naabu) → httpx → nmap.
   Ingesting naabu/httpx/masscan JSON puts PortReaper at the confluence of the
   whole pipeline. Biggest reach expansion.
5. **Nuclei bridge** — emit a Nuclei target/tag manifest from matched CVEs to turn
   passive inference into an active-verification plan, then read results back.

**Flag — OSV.dev fit:** OSV is package/ecosystem-oriented (npm/PyPI/Go, keyed by
package name not CPE) and is a **poor match for nmap network-service banners**.
Worth confirming it returns real signal here vs. mostly-empty results before
investing further ([OSV data model](https://google.github.io/osv.dev/data/)).

**Also flag — NVD reliability:** NVD has a known analysis backlog since 2024
(30+ day enrichment lag); KEV+EPSS partly route around depending solely on NVD.

*Caveats: star counts / last-commit from GitHub landing pages; PlexTrac/AttackForge/reptool
capabilities not deeply verified — treat as commercial reporting platforms, out of shape for a solo hunter.*

---

## 6. Prioritized backlog

Effort: **S** ≤half-day · **M** ~1–2 days · **L** multi-day. Each item maps to a
finding above and is written to be dispatch-ready.

### Wave 0 — Correctness & gate (do first, all small)

| ID | P | Eff | Item | Ref |
|----|---|-----|------|-----|
| B0-1 | P0 | S | Fix `source_status` tautology → `fail == 0 && ok > 0` (report OK only if something succeeded) | BUG-1 |
| B0-2 | P0 | S/M | Decide `os_matches`: either add `<os><osmatch>` XML deser, or remove the field + "OS:" rendering. (Recommend **remove** unless OS data is wanted.) | BUG-2 |
| B0-3 | P0 | M | Get `cargo clippy` green (4 errors + 35 warnings) and wire it + `cargo test` into a pre-commit / CI gate so the lint gate can't silently re-red | metrics, DEAD-1 |
| B0-4 | P1 | S | Fix `detect_format` byte-boundary panic (`content.get(..64)`) | BUG-3 |
| B0-5 | P1 | M | Add a test for `enrich_scan` (would have caught B0-1); de-tautologize `render/tree.rs` tests to assert captured stdout | TEST-1/2 |

### Wave 1 — Efficiency / throughput

| ID | P | Eff | Item | Ref |
|----|---|-----|------|-----|
| B1-1 | P1 | M | Per-source rate limiter (token-bucket/min-interval), honor `RateLimited.retry_after_secs`, add jitter. Highest cold-run ROI for keyless NVD | PERF-1 |
| B1-2 | P1 | S/M | Parallelize CVE.org per-CVE loop (mirror `osv.rs:250-276`, bounded by inner semaphore) | PERF-2 |
| B1-3 | P1 | S | Add CVE.org cache layer keyed by CVE-ID (match NVD/OSV pattern) | PERF-3 |
| B1-4 | P2 | M | Run-scoped single-flight memoization keyed `(source, cpe)` / `(cve.org, cve_id)` — collapses duplicate work + cold-start stampede | PERF-4 |
| B1-5 | P2 | S | `tokio::join!` NVD + OSV within each task | PERF-5 |
| B1-6 | P3 | S | `Vec::contains` → `HashSet` in vault index/merge | PERF-6 |

### Wave 2 — Analyst time-to-insight

| ID | P | Eff | Item | Ref |
|----|---|-----|------|-----|
| B2-1 | P1 | S | Sort terminal tree + host/service tables severity-desc (worst first) | §3 |
| B2-2 | P1 | S | Exploit-available marker in tree line + `EXPLOIT` column in index tables (data already in `Port.exploits`) | §3 |
| B2-3 | P1 | M | **CISA KEV source** → `#kev` tag + graph color + overview callout | §5.1 |
| B2-4 | P2 | S/M | EPSS score join + display (pair with KEV, note the lag caveat) | §5.2 |
| B2-5 | P2 | S | `--min-severity` / `--exploitable-only` filters | §3 |
| B2-6 | P2 | L | Confidence-scored, version-range-aware CPE matching (respect NVD version ranges; stamp confidence on each host↔CVE link) | §5.3 |

### Wave 3 — CLI surface + suite/AI integration

Proposed command tree (keep bare-invocation-as-`scan` shim for muscle memory):

```
portreaper
├── scan <files...>     parse + display   [--format tree|json|jsonl] [--min-severity] [--exploitable-only] -v -q --no-enrich
├── enrich <files...>   parse+enrich, emit structured (no vault)     [--fresh --disable-source --format json|jsonl]
├── vault <files...> --out DIR   parse+enrich+write vault            [--rebuild : re-render from cache, no network]
├── cache   status | clear [--source X] | path
├── config  init | show | path
├── sources list | test
└── export <vault|files> --format json|jsonl|sqlite
```

| ID | P | Eff | Item | Ref |
|----|---|-----|------|-----|
| B3-1 | P2 | S/M | **JSONL export** (add `Serialize` to `models`, one object/host). Highest-leverage suite integration | §4 |
| B3-2 | P2 | L | Subcommand refactor (splits the fused `parse→enrich→vault` pipeline so agents can enrich-once/render-many) | §1-CLI |
| B3-3 | P2 | S | `cache status|clear|path` (state already computed internally, never surfaced) | §1-CLI |
| B3-4 | P3 | S | `config init|show|path` (README documents hand-writing the TOML today) | §1-CLI |
| B3-5 | P3 | S | `sources list|test` (probe NVD key, searchsploit on PATH) | §1-CLI |
| B3-6 | P3 | M | SQLite export for the Dashboard | §4 |
| B3-7 | P3 | S | Trim vault token bloat: make `## Notes` stub + hardcoded ref links optional for machine consumers | §4 |

### Wave 4 — Reach expansion (later)

| ID | P | Eff | Item | Ref |
|----|---|-----|------|-----|
| B4-1 | P3 | L | Multi-tool ingestion: naabu / httpx / masscan JSON parsers | §5.4 |
| B4-2 | P3 | M | Nuclei target/tag manifest from matched CVEs; read results back into vault | §5.5 |
| B4-3 | P3 | S | Investigate OSV.dev yield for network-service input; disable-by-default if mostly empty | §5-flag |

### Tech-debt / hygiene (fold into related waves)

| ID | Eff | Item | Ref |
|----|-----|------|-----|
| T-1 | S | Narrow `tokio` features from `full` | DEP-1 |
| T-2 | S | Track/migrate off `serde_yml 0.0.x` (→ `serde_yaml_ng` or maintained emitter) | DEP-2 |
| T-3 | M | De-duplicate the 4-way enrichment orchestrator copy-paste (`lookup_with_cache` helper + per-source stats map) | DRY-1 |
| T-4 | M | Resolve `VulnSource` leaky abstraction (split CPE-search vs CVE-enrich traits, or drop for CVE.org + document) | ABS-1 |
| T-5 | M | Store score-history in frontmatter, stop scraping rendered tables | MERGE-1 |
| T-6 | S | Investigate the 17.25s integration suite (network? real enrichment in tests?) | TEST-3 |
| DOC-1 | M | Write the comprehensive usage guide (outline below) | §7 |

---

## 7. Usage guide — outline

1. Overview & where PortReaper fits in the bounty suite
2. Installation (cargo install, build from source, verifying the binary)
3. Prerequisites (nmap, optional searchsploit, optional NVD API key)
4. Quick start: first scan (file, stdin pipe, multiple files)
5. Reading terminal output (tree, severity tags, colors, summary)
6. Enrichment: how the sources work; enabling/disabling; keys & rate limits
7. Caching (TTL, `--fresh`, cache location, clearing)
8. Configuration file (locations, precedence, full example, `config init/show`)
9. Generating an Obsidian vault (layout, opening as vault root)
10. Reading the vault (indexes, note types, graph view, severity CSS)
11. Incremental scanning & merging (re-runs, preserved Notes, not-seen tags, score history)
12. Triage workflow: fastest path to "what's exploitable" (severity sort, KEV, exploit flags, filters)
13. Machine/agent integration (JSON/JSONL/SQLite export, schema, consuming from Brain/Dashboard/agents)
14. Command reference (every subcommand + flag)
15. Exit codes & scripting
16. Troubleshooting (broken wikilinks, missing searchsploit, source failures, malformed input, rate-limit errors)
17. FAQ / performance tuning (concurrency, large scans)

---

## Recommended first move

Wave 0 is five small, high-certainty items that make the tool *correct* and put a
gate around it. The single highest value-to-effort feature is **B2-3 (CISA KEV)**;
the single highest efficiency win is **B1-1 + B1-2 + B1-3** together (rate limiter
+ parallel/cached CVE.org). B3-1 (JSONL export) is the highest-leverage suite move.

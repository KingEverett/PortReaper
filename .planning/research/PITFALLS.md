# Domain Pitfalls

**Domain:** Rust CLI tool — nmap XML parsing, concurrent vulnerability API queries, Obsidian markdown generation
**Project:** PortReaper
**Researched:** 2026-03-20
**Confidence note:** Web search tools were unavailable in this environment. All findings are drawn from training knowledge of nmap's DTD, NVD/CVE.org/OSV API documentation, Rust async ecosystem, and Obsidian vault conventions. Confidence is assessed per-section.

---

## Critical Pitfalls

Mistakes that cause silent data loss, rewrites, or tool failures in production use.

---

### Pitfall 1: Treating nmap Service Version as a Reliable, Structured Field

**What goes wrong:** Code assumes `service/@version` or `service/@product` are always populated with clean, parseable strings (e.g., `"OpenSSH 8.9p1"`). In reality, these fields are absent for closed ports, present but empty for filtered ports, contain freeform text that does not follow any schema (e.g., `"OpenSSH 7.4 protocol 2.0"`, `"(protocol 2.0)"`), and are often vendor-mangled for embedded devices.

**Why it happens:** Developers test against their own nmap scan results against well-behaved targets. Real-world engagements include printers, switches, IoT devices, and misconfigured hosts that emit malformed service banners.

**Consequences:** Vulnerability lookup queries are constructed from garbage strings and return zero results, silently. The operator assumes the tool found nothing when actually the parser ate the data. This is a silent data-loss failure — the worst kind.

**Prevention:**
- Never assume `product`, `version`, or `extrainfo` attributes exist on a `<service>` element. Treat all three as `Option<String>`.
- Build a query-normalization layer that strips version suffixes (e.g., `"p1"`, `"protocol 2.0"`) before submitting to APIs.
- Log a warning (at INFO level, visible by default) whenever a port is parsed but produces no queryable service identifier.
- Write a test fixture corpus from diverse real nmap scans — not just clean lab results.

**Warning signs:**
- CVE/NVD query functions receive empty or whitespace-only strings without panicking
- Tests only use nmap scans against Linux boxes with OpenSSH and Apache
- No handling for `<service>` elements with only `name="unknown"`

**Phase:** XML parsing phase (Phase 1/2). Must be solved before any API integration work begins.

---

### Pitfall 2: Not Handling nmap `<hostscript>` and `<script>` Output

**What goes wrong:** The nmap XML schema includes `<script>` elements nested inside `<port>` and `<hostscript>` elements at the host level. These contain NSE script output — banner grabs, SMB info, SSL certificate details, Heartbleed results, etc. Tools that skip `<script>` elements discard some of the highest-value enumeration data.

**Why it happens:** The obvious parse target is `<port><service>`. Script elements look "extra" and non-obvious in the DTD.

**Consequences:** `ssl-cert` output (with CN/SAN fields that reveal hostnames and internal domains) is discarded. `smb-os-discovery` output (with exact Windows build numbers) is lost. Vulnerability lookups miss precision that script output would have provided.

**Prevention:**
- Explicitly model `<script id="..." output="...">` as a first-class type alongside `Service`.
- Capture both `id` (script name) and `output` (raw text), and also parse the structured `<elem>` children where present.
- Append script output to generated service notes as a raw fenced block if no structured parsing is done.

**Warning signs:**
- `Port` struct has no field for attached scripts
- Parser walk ignores nodes that are not `<port>`, `<address>`, or `<hostname>`

**Phase:** XML parsing (Phase 1/2). Fixing this after API integration is expensive because the data model needs retrofitting.

---

### Pitfall 3: NVD API Rate Limiting Causes Silent Query Drops

**What goes wrong:** NVD's public API (api.nvd.nist.gov/rest/json/cves/2.0) enforces rate limits: 5 requests per 30 seconds without an API key, 50 requests per 30 seconds with one. A scan with 50 open ports queried against NVD without rate limiting will hit 429s. If the HTTP client is configured to silently drop errors or treat non-200 as "no results found," the tool reports zero vulnerabilities for most ports.

**Why it happens:** During development, tests hit only 2-3 services. Rate limits are never encountered. The error path returns an empty `Vec<Cve>` for both "no CVEs" and "request failed," and they look identical to callers.

**Consequences:** Operators get reports with no vulnerabilities for hosts with dozens of services. Catastrophic false negative for a security tool.

**Prevention:**
- Distinguish `QueryResult::Empty` (HTTP 200, no CVEs) from `QueryResult::Error(RateLimited)` and `QueryResult::Error(NetworkFailure)` in the return type.
- Implement a semaphore-based rate limiter for each API source (not global — each source has different limits).
- Retry 429 responses with exponential backoff (start at 30s for NVD without key).
- Display a progress indicator that shows per-source query counts, making rate limit encounters visible.
- Require or strongly encourage NVD API key in config — documented in README, prompted on first run.

**Warning signs:**
- `async fn query_nvd(service: &str) -> Vec<Cve>` returns empty vec on any HTTP error
- No `tokio::sync::Semaphore` or equivalent rate-limiter wrapping API call sites
- Integration tests never assert on 429 behavior

**Phase:** API integration phase. Must be addressed before first working build — not a polish concern.

---

### Pitfall 4: CPE String Matching is Fragile and Leads to Zero Results or Wrong Results

**What goes wrong:** Vulnerability databases (NVD in particular) are indexed by CPE (Common Platform Enumeration) strings, e.g., `cpe:2.3:a:openbsd:openssh:8.9:-:*:*:*:*:*:*`. nmap's `service/@version` value `"OpenSSH 8.9p1"` does not map directly to this. Tools that attempt naive string matching or substring search against CPE fields get either nothing (too strict) or hundreds of unrelated results (too loose).

**Why it happens:** CPE looks like a simple lookup. The complexity of the CPE dictionary and version normalization is invisible until real queries are run.

**Consequences:** Either every service shows a flood of irrelevant CVEs (low precision, operator loses trust in the tool), or nothing shows up for known-vulnerable services (low recall, false negatives).

**Prevention:**
- Use NVD's `keywordSearch` parameter (free-text) as the primary search mode, not CPE construction.
- For the CPE path, use NVD's CPE dictionary API to resolve `product+version` → CPE first, then query CVEs by CPE.
- Normalize version strings: strip Debian/Ubuntu patch suffixes (`p1`, `~dfsg`, `+deb11u2`), lowercase the product name, strip vendor prefixes before querying.
- Accept that lookup will be imperfect and surface match confidence in notes (e.g., "queried as 'openssh 8.9'").

**Warning signs:**
- Code constructs `cpe:2.3:a:{vendor}:{product}:{version}:...` strings by string formatting from nmap fields
- No version normalization step between parse and query
- No test asserting that `"OpenSSH 8.9p1"` and `"OpenSSH 8.9"` reach the same query string

**Phase:** API integration, but the normalization layer must be designed in the parsing phase data model.

---

### Pitfall 5: Obsidian Wikilinks Break When Filenames Contain Special Characters

**What goes wrong:** Service notes are named after hosts and services (e.g., `192.168.1.1 - 22 - ssh.md`). Port numbers, colons, slashes in service names, and IP addresses with dots all create Obsidian wikilink resolution ambiguity or filesystem conflicts on Windows (colons are illegal). IPv6 addresses (`::1`, `fe80::1`) are fatal to filename construction.

**Why it happens:** Developer tests on Linux with IPv4-only scans. The characters that cause problems are exactly the characters that appear naturally in nmap output.

**Consequences:** Vault notes silently not linked. Cross-platform compatibility broken. IPv6 support broken before it starts.

**Prevention:**
- Define a canonical sanitize function for all generated filenames: replace `:` with `-`, `/` with `_`, strip `[]` from IPv6 addresses, collapse whitespace.
- Never construct wikilinks from raw nmap field values — always route through the same sanitize function used for filename generation.
- Test filename generation with IPv6 addresses, service names with `/` (e.g., `http/ssl`), and names containing parentheses.
- Use a flat vault structure keyed by sanitized identifiers — not nested subdirectories, which Obsidian wikilinks handle inconsistently.

**Warning signs:**
- Filename construction is inline (not a dedicated function called from both file creation and wikilink generation)
- No test with an IPv6 address as input
- Characters like `:`, `/`, `[`, `]` pass through to filenames

**Phase:** Markdown/vault generation phase. But the sanitize function needs to exist before any file-writing code is written.

---

### Pitfall 6: Async Task Spawning Without Backpressure Exhausts File Descriptors and Memory

**What goes wrong:** A naive implementation uses `tokio::spawn` inside a loop over all (host, port, service) combinations and fires all API queries concurrently. A scan with 500 open ports against 7 sources spawns 3,500 concurrent HTTP requests. This exhausts the OS file descriptor limit, makes reqwest panic or silently fail, gets the IP banned from APIs, and OOMs on low-RAM systems.

**Why it happens:** `tokio::spawn` looks like the right tool. The pattern works fine for 10 ports in dev. The problem only manifests at realistic pentest scale.

**Consequences:** Tool crashes on real-world inputs. IP-based rate bans from API providers. Unreproducible failures.

**Prevention:**
- Use `futures::stream::iter(...).buffer_unordered(N)` or a semaphore to cap total concurrent requests at a configurable limit (default: 10-20 total, not per-source).
- Separate concurrency limits by source: NVD limit != ExploitDB limit.
- Make the concurrency cap a CLI flag (`--concurrency`) so operators can tune for their environment.
- Set explicit connection pool limits on the reqwest `Client` (`connection_verbose`, `pool_max_idle_per_host`).
- Build and test against a scan fixture with 200+ open ports.

**Warning signs:**
- Main query loop uses `tokio::spawn` in a `for` loop with no semaphore or bounded channel
- No `--concurrency` or equivalent option in CLI
- `reqwest::Client` is created per-request rather than shared

**Phase:** API integration architecture. Must be in the initial design — retrofitting backpressure into an unbounded design is a significant rewrite.

---

### Pitfall 7: YAML Frontmatter Corruption from Unescaped CVE Description Text

**What goes wrong:** CVE descriptions are free-form prose from NVD/CVE.org. They routinely contain colons (`:`), double quotes, newlines, and YAML-significant characters. Writing them directly into YAML frontmatter without escaping produces malformed `.md` files that Obsidian silently fails to parse — the note opens blank or the frontmatter is displayed as raw text.

**Why it happens:** Simple template string interpolation works for clean fields. CVE descriptions are never clean.

**Consequences:** Generated notes appear broken in Obsidian. The operator sees a vault full of malformed files. Trust in the tool's output collapses.

**Prevention:**
- All dynamic string values in YAML frontmatter must be single-quoted or double-quoted with proper escaping.
- Use a YAML serialization library (e.g., `serde_yaml`) for frontmatter generation — never hand-roll YAML strings with format macros.
- Cap CVE description length in frontmatter (e.g., 200 chars truncated with `...`) — full descriptions belong in the note body, not frontmatter.
- Write tests that pass CVE descriptions containing `"`, `:`, and `\n` through the frontmatter serializer.

**Warning signs:**
- Frontmatter is assembled with `format!("---\ntitle: {title}\ndescription: {desc}\n---")`
- No test with a CVE description containing a colon or quote character
- `serde_yaml` is not in dependencies

**Phase:** Markdown generation phase, but the architectural decision (use serde_yaml, not format strings) belongs in Phase 1 design.

---

### Pitfall 8: ExploitDB and PacketStorm Have No Official API — Scraping is Fragile

**What goes wrong:** ExploitDB's search and PacketStorm have no stable JSON API. Any scraping implementation will break when their HTML structure changes, which happens without notice. A scraper written today may silently return empty results within weeks of release. The HTML structure is also complex enough that cheerio/regex-based scrapers frequently miss results or extract wrong data.

**Why it happens:** These sources are listed as requirements. Their data is valuable. Developers write a scraper that works, ship it, and don't discover it broke until user reports come in.

**Consequences:** Silent data loss for exploit references — the most actionable findings for a pentester. Ongoing maintenance burden.

**Prevention:**
- For ExploitDB: use the `searchsploit` CLI tool (if installed) as the primary interface — it has a `--json` flag and queries a local mirror. Fall back to the web only if searchsploit is absent.
- For PacketStorm: implement scraping but encapsulate it in a clearly-marked `experimental` source plugin with a warning in output that results may be incomplete.
- Implement source-level health checks: each source plugin exposes a `fn health_check() -> Result<()>` that the user can run to verify all sources are reachable and returning expected data.
- Design the pluggable source architecture so a broken source causes a logged warning, not a panic or silent empty result.

**Warning signs:**
- ExploitDB integration uses HTTP scraping without checking for searchsploit binary first
- No health check command in the CLI
- A broken source plugin propagates as an empty result rather than a named error

**Phase:** Data source integration. The searchsploit-first strategy must be decided at architecture time, not discovered during debugging.

---

## Moderate Pitfalls

---

### Pitfall 9: Treating `<port state="filtered">` the Same as `open`

**What goes wrong:** nmap XML has port states: `open`, `closed`, `filtered`, `open|filtered`, `closed|filtered`. Tools that iterate all `<port>` elements without filtering on state attempt vulnerability lookups for filtered and closed ports. This wastes API quota and produces misleading reports.

**Prevention:**
- Default to processing only `state="open"` and `state="open|filtered"`.
- Make the included states configurable via a CLI flag.
- Log the count of skipped ports at DEBUG level.

**Phase:** XML parsing (Phase 1/2).

---

### Pitfall 10: CVSS Score Versioning — CVSS v2, v3.0, v3.1, v4.0 Are Not Directly Comparable

**What goes wrong:** NVD returns CVSS scores in v2, v3.1, and (increasingly) v4.0 format. Displaying a v2 score of `7.8` alongside a v3.1 score of `9.1` without labeling the version misleads operators. Severity thresholds differ between versions (v2 High is 7.0+, v3 High is 7.0–8.9, Critical is 9.0+).

**Prevention:**
- Always display CVSS version alongside the score (e.g., `CVSSv3.1: 9.1 [CRITICAL]`).
- Prefer the highest available version for severity classification: v3.1 > v2, v4.0 > v3.1.
- Document the version preference logic clearly in generated notes.

**Phase:** API result modeling (early). The `CvssScore` type must carry version information from the start.

---

### Pitfall 11: stdin Pipe Detection Hangs When Input Is a TTY

**What goes wrong:** Reading from stdin when no pipe is present (user forgets to pipe nmap output) causes the tool to block indefinitely waiting for input. The operator sees a frozen terminal with no feedback.

**Prevention:**
- Check if stdin is a TTY before attempting to read: `atty::is(Stream::Stdin)` or `std::io::stdin().is_terminal()` (stable in Rust 1.70+).
- If stdin is a TTY and no file argument is provided, print a usage hint and exit with a non-zero code.
- Provide a `--timeout` option for stdin reads as a safety net.

**Phase:** CLI argument parsing (Phase 1).

---

### Pitfall 12: Large Nmap XML Files OOM the Parser

**What goes wrong:** nmap XML output from large-scope scans (enterprise /16 subnets) can be hundreds of MB. A DOM-based XML parser (e.g., `roxmltree` loading the entire document) allocates the full file in memory. On constrained systems this causes OOM.

**Prevention:**
- Use a streaming/SAX-style XML parser (`quick-xml` in streaming mode) rather than a DOM parser.
- Process hosts as they are encountered in the stream, emitting to a channel for downstream processing.
- Test with a synthetically large XML file (10,000 hosts) as a benchmark case.

**Phase:** XML parsing (Phase 1/2). This is an architectural choice that cannot be easily changed post-implementation.

---

### Pitfall 13: Obsidian Graph View Does Not Resolve Wikilinks Across Subdirectories Reliably

**What goes wrong:** Obsidian resolves `[[filename]]` by matching the shortest unique filename across the vault. If the vault has subdirectory structure (e.g., `hosts/192.168.1.1.md` and `vulns/CVE-2023-1234.md`), wikilinks must use just the filename stem — but if two files share a name across directories, resolution becomes ambiguous. Deeply nested structures break graph connectivity.

**Prevention:**
- Use a flat vault structure: all generated files in a single directory (or root), distinguished by file naming conventions only.
- If subdirectories are used, ensure all wikilinks include the full relative path from vault root.
- Test the generated vault by opening it in Obsidian and verifying the graph view shows expected connections.

**Phase:** Markdown generation design. Settling on flat vs hierarchical structure before writing any file-generation code prevents a costly structural rewrite.

---

### Pitfall 14: API Response Caching Is Not Optional — It Is a Requirement

**What goes wrong:** Re-running PortReaper against the same nmap output (e.g., after adding a new output template) re-queries all APIs. This burns rate limit quota, takes minutes, and may get the user temporarily banned. Without caching, iterative development and re-processing are unusable.

**Prevention:**
- Implement a local cache (SQLite via `rusqlite`, or a flat JSON/directory cache) keyed on `(source, query_string)` from the first integration phase.
- Make cache TTL configurable (default: 24h for CVE data, shorter for exploit availability).
- Provide `--no-cache` and `--clear-cache` flags.

**Warning signs:**
- No cache layer exists after the first working API integration
- Re-running the tool against the same XML file triggers the same API requests

**Phase:** API integration, must be part of initial architecture.

---

## Minor Pitfalls

---

### Pitfall 15: nmap `-oA` Produces Both `.xml` and `.gnmap` — Tool Must Accept Only `.xml`

**What goes wrong:** Operators using `-oA` (all output formats) will try to pass the `.gnmap` or `.nmap` file to PortReaper. These are not XML and will produce an inscrutable parse error.

**Prevention:**
- Check file extension and magic bytes before attempting XML parse.
- Emit a clear error: `"PortReaper requires nmap XML output (-oX). Got grepable/normal format. Re-run nmap with -oX."`.

**Phase:** CLI input handling (Phase 1).

---

### Pitfall 16: Markdown Table Alignment Breaks for Long CVE IDs or Descriptions

**What goes wrong:** Markdown tables rendered in Obsidian with very long cell content (e.g., a 500-char CVE description) break the visual table layout or overflow.

**Prevention:**
- Truncate CVE descriptions in table cells (50-80 chars max, with `...`).
- Put full descriptions in a collapsible callout block below the table.
- Test generated markdown by rendering it in Obsidian, not just by inspecting raw text.

**Phase:** Markdown generation.

---

### Pitfall 17: Tool Produces No Output for UDP Scans

**What goes wrong:** nmap UDP scans (`-sU`) produce XML with `protocol="udp"` on port elements. Tools that hardcode TCP-only processing silently skip all UDP findings.

**Prevention:**
- The `Port` struct must carry a `protocol` field (`tcp`/`udp`/`sctp`).
- Generated filenames and note titles must include protocol to avoid collision (e.g., `port_53_udp.md` vs `port_53_tcp.md`).
- Test with a UDP nmap scan fixture.

**Phase:** XML parsing (Phase 1).

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| XML parsing design | Silent data loss from optional fields | All service fields as `Option<T>`; log skipped ports |
| XML parsing design | Script element data discarded | Model `<script>` as first-class field on `Port` |
| XML parsing design | UDP port collisions | `protocol` field on `Port` from day one |
| Data model definition | CVSS version ambiguity | `CvssScore { version, score, severity }` type, not bare `f32` |
| API integration architecture | Unbounded concurrency | Semaphore + `buffer_unordered` before any live API calls |
| API integration architecture | Missing cache layer | SQLite or directory cache in first integration sprint |
| NVD integration | Rate limiting as silent data loss | Typed error enum distinguishing empty vs error; retry logic |
| CPE/version normalization | Zero or garbage query results | Normalization layer with test corpus of real nmap version strings |
| ExploitDB/PacketStorm | Brittle scrapers | searchsploit binary first; scraping as degraded fallback |
| Markdown generation | YAML frontmatter corruption | Use serde_yaml; never format! macro for frontmatter |
| Filename generation | Special characters break wikilinks | Sanitize function used for both filenames and wikilinks |
| Vault structure | Subdirectory wikilink ambiguity | Flat vault structure decided before first file-write code |
| CLI input | stdin hangs on TTY | TTY detection before read attempt |
| CLI input | Wrong file format | Magic byte check + clear error message |

---

## Sources

- nmap XML DTD structure: training knowledge of nmap 7.x XML schema (HIGH confidence for field names/optionality)
- NVD API rate limits and endpoint structure: training knowledge of NVD API v2.0 (MEDIUM confidence — verify current limits at https://nvd.nist.gov/developers/vulnerabilities)
- OSV.dev API: training knowledge (MEDIUM confidence — verify at https://osv.dev/docs/)
- Rust async concurrency patterns (tokio, reqwest, buffer_unordered): training knowledge of Rust async ecosystem as of mid-2025 (HIGH confidence for core patterns)
- Obsidian wikilink resolution rules: training knowledge of Obsidian vault behavior (HIGH confidence for flat vs nested behavior)
- serde_yaml for YAML generation: training knowledge (HIGH confidence)
- quick-xml streaming mode: training knowledge (HIGH confidence)
- ExploitDB/searchsploit --json flag: training knowledge (MEDIUM confidence — verify searchsploit version supports --json)
- CVSSv4.0 availability from NVD: MEDIUM confidence — adoption timeline uncertain as of research date

**Note on research limitations:** Web search, WebFetch, and Bash tools were unavailable in this environment. All pitfalls are drawn from domain expertise. Claims marked MEDIUM confidence should be verified against official documentation before implementation begins, particularly NVD API rate limits and ExploitDB scraping feasibility.

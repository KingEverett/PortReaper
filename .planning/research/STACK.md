# Technology Stack

**Project:** PortReaper
**Researched:** 2026-03-20
**Note:** All external tool access (WebSearch, WebFetch, Context7) was denied in this session. All findings are from training data (knowledge cutoff August 2025). Versions MUST be verified against crates.io before use. Every entry is flagged MEDIUM or LOW confidence as a result.

---

## Recommended Stack

### Runtime / Async Executor

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| tokio | ~1.38 | Async runtime | The de-facto standard for async Rust. Multi-threaded scheduler, macro ecosystem (`#[tokio::main]`), first-class support from every major async crate in this stack. No serious alternative for a networked CLI tool. |

**Confidence:** MEDIUM — tokio 1.x has been stable and dominant since 2021; highly unlikely to have been displaced, but verify the exact minor version on crates.io.

**Do NOT use:** async-std — smaller ecosystem, fewer library integrations, stagnated compared to tokio.

---

### CLI Argument Parsing

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| clap | ~4.5 | Argument parsing, subcommands, help generation | Defacto standard. The `derive` feature allows struct-based argument definitions which are self-documenting and catch errors at compile time. v4 is a stable, mature API. |

**Confidence:** MEDIUM — clap 4.x has been the standard since 2022; verify latest patch on crates.io.

**Do NOT use:** structopt — deprecated, merged into clap 4. argh — minimal ecosystem; lacks completions, coloring, rich help. pico-args — too minimal for multi-subcommand CLI.

```toml
clap = { version = "4", features = ["derive", "color", "env"] }
```

---

### XML Parsing (nmap output)

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| quick-xml | ~0.36 | Parse nmap `-oX` XML output | Zero-copy, streaming SAX-style or DOM deserialization. Integrates with serde via `quick-xml::de`. Best performance/ergonomics ratio for well-structured XML like nmap's. |
| serde | ~1.0 | Derive deserialization onto nmap structs | Ubiquitous. With quick-xml's serde feature, nmap XML maps cleanly to Rust structs. |

**Confidence:** MEDIUM — quick-xml + serde has been the established pattern for structured XML in Rust since 2022. The nmap XML schema is stable and maps well to serde derives. Verify quick-xml version; API had breaking changes between 0.30 and 0.36.

**Alternative considered:** `roxmltree` — good for read-only DOM traversal, but no serde integration; would require manual field extraction. Use only if nmap XML structure proves too irregular for serde derives.

**Do NOT use:** `xml-rs` — older, slower, verbose API. `minidom` — GNOME-ecosystem, poor ergonomics in pure Rust context.

**Special case — stdin (piped nmap text output):**
nmap's `-oN` (normal) and grepable (`-oG`) formats are not XML. Parsing these requires regex or custom line parsing. Recommend: accept only `-oX` XML for structured data, but detect piped input and provide a clear error message directing users to re-run nmap with `-oX`. The XML format is strictly richer and more reliable.

```toml
quick-xml = { version = "0.36", features = ["serialize"] }
serde = { version = "1", features = ["derive"] }
```

---

### HTTP Client (vulnerability database queries)

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| reqwest | ~0.12 | Async HTTP requests to NVD, CVE.org, OSV.dev, etc. | Best-in-class async HTTP client for Rust. tokio-native, TLS via rustls or native-tls, automatic JSON deserialization via serde. Connection pooling handles concurrent API queries. |

**Confidence:** MEDIUM — reqwest 0.12 moved to http 1.0 types (major ecosystem shift). Verify 0.12.x is still current; if 0.13 has shipped, prefer it.

**Do NOT use:** `ureq` — synchronous only; concurrent database queries would require a thread pool which defeats Rust's async advantages. `hyper` directly — too low-level; reqwest wraps it correctly for this use case.

```toml
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }
```

Use `rustls-tls` (not `native-tls`) for portability — single-binary distribution means no system OpenSSL dependency.

---

### Concurrency Control (rate limiting / semaphores)

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| tokio (built-in) | — | `tokio::sync::Semaphore` for bounding concurrent API requests | Built into tokio; no extra dependency. Use a semaphore to cap concurrent outbound requests (e.g., max 5 simultaneous NVD queries) to avoid API rate limits. |
| futures | ~0.3 | `futures::future::join_all` / `FuturesUnordered` for fan-out query batches | Standard futures combinators. `FuturesUnordered` is preferred over `join_all` for heterogeneous query sets — processes results as they complete rather than waiting for all. |

**Confidence:** MEDIUM — both are stable, foundational crates.

---

### JSON Deserialization (API responses)

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| serde_json | ~1.0 | Deserialize NVD, CVE.org, OSV.dev JSON responses | The canonical JSON crate. Already pulled in via reqwest's `json` feature. NVD API 2.0 returns complex nested JSON; serde derives handle this cleanly. |

**Confidence:** HIGH (relative) — serde_json 1.0 has been stable and unchanged in API for years; the version range is correct.

---

### Error Handling

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| anyhow | ~1.0 | Application-level error handling | Best choice for binary crates. Provides context-chaining (`.context("querying NVD for {cve}")`), automatic backtraces, and works with `?` operator across heterogeneous error types. |
| thiserror | ~1.0 | Typed errors for the pluggable data source trait | Libraries (and the datasource plugin trait) need typed errors so callers can match on them. thiserror derives `std::error::Error` with minimal boilerplate. |

**Confidence:** MEDIUM — anyhow + thiserror is the dominant pattern for Rust binaries with library-like internals. API has been stable for years.

**Why both:** `anyhow` in `main` and CLI boundary code; `thiserror` in the `DataSource` trait and internal module errors that callers need to distinguish.

---

### Async Trait Support

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| (Rust built-in) | Rust 1.75+ | `async fn` in traits | As of Rust 1.75 (December 2023), `async fn in trait` is stable in the language. The `async-trait` proc-macro crate is no longer needed for the pluggable `DataSource` trait. |

**Confidence:** HIGH (relative) — Rust 1.75 shipped async fn in traits in December 2023; this is well within training data and confirmed stable.

**Do NOT use:** `async-trait` macro — was required before Rust 1.75. Still works, but unnecessary boxing overhead and the crate is in maintenance mode.

---

### Serialization / Output (Obsidian markdown)

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| (std `format!` / custom templates) | — | Generate `.md` files with YAML frontmatter and wikilinks | Obsidian markdown is plain text. A dedicated markdown crate is unnecessary and would likely add escaping behavior that breaks `[[wikilinks]]` syntax. Use `format!` macros with well-tested template strings. |

**Alternative considered for YAML frontmatter:** `serde_yaml` — could serialize frontmatter structs to YAML. Viable, but adds a dependency for a small subset of output. Recommendation: hand-roll frontmatter serialization (the schema is simple and stable) unless frontmatter complexity grows. Flag this decision for Phase 1 validation.

**Confidence:** MEDIUM — Obsidian's markdown superset is stable and documented; no parsing crate is needed since we only write, never read, the vault.

---

### Progress / Terminal UI

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| indicatif | ~0.17 | Progress bars during concurrent API queries | Concurrent queries against 6+ databases with no progress output creates bad UX. indicatif renders multi-bar progress with tokio compatibility. Best-in-class for CLI progress in Rust. |

**Confidence:** MEDIUM — indicatif 0.17 has been stable; verify latest patch on crates.io.

```toml
indicatif = "0.17"
```

---

### Logging / Diagnostics

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| tracing | ~0.1 | Structured async-aware logging | `log` crate is synchronous and loses context across await points. `tracing` is async-aware, spans track context through concurrent futures (critical when 6 database queries run simultaneously). tokio integrates natively with tracing. |
| tracing-subscriber | ~0.3 | Log formatting and filtering | Provides `EnvFilter` for `RUST_LOG=debug` style control; formats for human-readable terminal output. |

**Confidence:** MEDIUM — tracing has been the standard for async Rust since ~2021.

```toml
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

---

### File System Operations

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| tokio::fs | — | Async file writes for vault generation | Bundled with tokio. Writing hundreds of markdown files benefits from async I/O. No additional dependency needed. |

---

### Configuration

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| directories | ~5.0 | Locate OS-appropriate config dir (`~/.config/portreaper/`) | Cross-platform XDG/AppData/Library path resolution. Small, focused crate. No config format opinion. |
| toml | ~0.8 | Parse config file (API keys, rate limits, enabled sources) | TOML is Cargo's own format; Rustaceans expect it. serde integration is standard. |

**Confidence:** LOW — `directories` version not verified; `toml` 0.8 had a breaking API change from 0.7. Verify both on crates.io.

---

## Pluggable DataSource Architecture

The `DataSource` trait is the core architectural decision. Each vulnerability database is a separate module implementing a common trait:

```rust
// Sketch — verify async fn in trait syntax for your Rust toolchain version
pub trait DataSource: Send + Sync {
    fn name(&self) -> &str;
    async fn query(&self, service: &ServiceInfo) -> Result<Vec<Finding>, DataSourceError>;
}
```

Each source lives in its own module (`src/sources/nvd.rs`, `src/sources/osv.rs`, etc.) and is registered at startup. This isolates API-specific rate limits, auth, and response shapes. Sources that require scraping (ExploitDB, PacketStorm) implement the same trait but use `reqwest` with HTML parsing (see below).

---

### HTML Scraping (ExploitDB, PacketStorm)

| Technology | Version (verify) | Purpose | Why |
|------------|-----------------|---------|-----|
| scraper | ~0.19 | CSS-selector-based HTML parsing | ExploitDB and PacketStorm don't offer public JSON APIs. `scraper` uses the same HTML5ever parser as Firefox for correctness and provides ergonomic CSS selectors. Alternative: `select` crate — similar capability but less active maintenance. |

**Confidence:** LOW — `scraper` is the right tool, but version not verified. Web scraping targets are fragile; PacketStorm and ExploitDB HTML structure may change. Flag for phase-specific research before implementing scraper sources.

```toml
scraper = "0.19"
```

**Critical caveat:** Scraping is inherently brittle. ExploitDB has a searchable index that may be downloadable as a CSV (the `searchsploit` tool bundles one locally). Prefer the local CSV route for ExploitDB; check if PacketStorm offers RSS or an undocumented API before committing to scraping.

---

## Alternatives Considered (summary)

| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| Async runtime | tokio | async-std | Smaller ecosystem, fewer integrations, stagnated |
| XML parsing | quick-xml + serde | roxmltree | No serde integration; manual field extraction |
| XML parsing | quick-xml + serde | xml-rs | Slower, verbose, older API |
| HTTP client | reqwest | ureq | Synchronous; incompatible with concurrent async queries |
| HTTP client | reqwest | hyper (direct) | Too low-level; reqwest is the correct abstraction |
| CLI parsing | clap 4 | structopt | Deprecated, merged into clap 4 |
| CLI parsing | clap 4 | argh | Minimal, lacks rich help/completions |
| Error handling | anyhow + thiserror | Box<dyn Error> | Loses context chaining and type information |
| Logging | tracing | log | Not async-aware; loses context across await points |
| Markdown output | format! macros | pulldown-cmark | Unnecessary; we write markdown, don't parse it |
| Async trait | Rust 1.75+ built-in | async-trait crate | Unnecessary since Rust 1.75; adds boxing overhead |

---

## Cargo.toml (starter)

```toml
[package]
name = "portreaper"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "portreaper"
path = "src/main.rs"

[dependencies]
# Runtime
tokio = { version = "1", features = ["full"] }
futures = "0.3"

# CLI
clap = { version = "4", features = ["derive", "color", "env"] }

# XML parsing (nmap)
quick-xml = { version = "0.36", features = ["serialize"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# HTTP
reqwest = { version = "0.12", features = ["json", "rustls-tls"], default-features = false }

# HTML scraping (ExploitDB, PacketStorm)
scraper = "0.19"

# Error handling
anyhow = "1"
thiserror = "1"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# UX
indicatif = "0.17"

# Config
toml = "0.8"
directories = "5"

[profile.release]
strip = true
lto = true
codegen-units = 1
```

**IMPORTANT:** All versions above are from training data (cutoff August 2025). Run `cargo add <crate>` or check crates.io for each before committing to these version pins. Pay special attention to `quick-xml` (API instability between minor versions) and `toml` (0.7 → 0.8 was breaking).

---

## Confidence Assessment

| Component | Confidence | Reason |
|-----------|------------|--------|
| tokio as runtime | MEDIUM | Dominant for 4+ years; version from training data |
| clap 4 for CLI | MEDIUM | Standard; version from training data |
| quick-xml + serde | MEDIUM | Right tool; API changes between minors — verify |
| reqwest 0.12 | MEDIUM | Correct; verify if 0.13 has shipped |
| serde_json | MEDIUM | Extremely stable crate |
| anyhow + thiserror | MEDIUM | Pattern is correct; API stable for years |
| Rust async fn in trait (1.75+) | MEDIUM | Language feature, stable since Dec 2023 |
| indicatif | MEDIUM | Right tool; patch version unverified |
| tracing | MEDIUM | Standard for async Rust |
| scraper for HTML | LOW | Version unverified; scraping targets are fragile |
| directories + toml | LOW | toml 0.8 breaking change history; verify versions |
| format! for markdown | MEDIUM | No library needed; correct for simple templating |

---

## Sources

All claims derive from training data (knowledge cutoff August 2025). No external verification was possible in this session — WebSearch, WebFetch, Context7, and Bash tools were all denied.

**Required verification steps before Phase 1:**
- Check crates.io for current versions of all crates above
- Confirm `async fn in trait` stability matches your `rustup` toolchain version (`rustup show`)
- Verify ExploitDB offers a downloadable local CSV (via searchsploit offline DB) before building a scraper
- Check PacketStorm for any undocumented API or RSS feed
- Confirm NVD API 2.0 rate limits (currently 5 req/30s without API key, 50 req/30s with key) — register for a free API key

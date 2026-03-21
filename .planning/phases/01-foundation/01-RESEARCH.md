# Phase 1: Foundation - Research

**Researched:** 2026-03-21
**Domain:** Rust CLI, nmap XML/text/greppable parsing, terminal tree output, plugin trait architecture
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Terminal output format**
- Tree view with Unicode box-drawing characters showing host → port → service hierarchy
- Color output by default with auto-detection for piped output (no color when stdout is not a TTY)
- Header shows scan source (filename or "stdin"), footer shows summary counts (hosts, open ports, unique services)
- CPE strings hidden in default output, shown with -v verbose flag
- Summary line at bottom: "Summary: N hosts, N open ports, N unique services"

**Input parsing**
- Support three input formats: XML (-oX), text (default nmap output), and greppable (-oG)
- Auto-detect format by content sniffing (first bytes: `<?xml` or `<nmaprun` → XML, `# Nmap` or `Host:` → greppable, else text)
- Parse what's available from each format — text/greppable lack CPE, OS detection, and script results; show what exists, leave missing fields absent
- Lenient parsing with stderr warnings — extract recognizable data, log skipped/unparseable lines to stderr so user knows what was missed
- No explicit --format flag needed; content sniffing handles all cases

**CLI interface**
- Flat command structure with flags (no subcommands): `portreaper scan.xml [--enrich] [--vault ./out]`
- Accept multiple scan files as positional args: `portreaper scan1.xml scan2.xml scan3.xml`
- Merge duplicate hosts by IP across multiple files — union of all discovered ports/services
- Verbosity flags: -v (verbose: CPEs, OS, extra fields), -q (quiet: summary line only), default (tree + summary)
- When stdin is a TTY with no file args, show short usage/help with examples — don't hang waiting for input
- Stdin piping supported: `nmap ... | portreaper` or `cat scan.xml | portreaper`

**Error handling**
- Partial parse failures: show successfully parsed hosts in tree, print warnings to stderr for failed hosts/sections
- Contextual error messages with suggestions: what went wrong + what to try (e.g., "not a valid nmap file → expected XML/text/greppable → try: nmap -oX scan.xml target")
- Distinct exit codes: 0 = success, 1 = parse error, 2 = no input/file not found
- Non-nmap files produce clear, actionable error rather than panic or silent failure

### Claude's Discretion
- Tree indentation and spacing details
- Exact color scheme (which colors for which elements)
- Internal data model field naming
- Compression algorithm for sanitize_filename edge cases

### Deferred Ideas (OUT OF SCOPE)
- --json flag for machine-readable output — consider for later phase if scripting demand arises
- (Note: greppable format WAS included in Phase 1 scope per user request, it is NOT deferred)
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| INPUT-01 | Parse nmap XML output files (`-oX` format) with full field extraction (ports, services, versions, OS, scripts) | quick-xml 0.39.2 + serde derive pattern; nmap DTD confirms all field names and optional attrs |
| INPUT-02 | Accept piped nmap text output from stdin | `is-terminal` 0.4.17 for TTY detection; text format parse pattern documented |
| INPUT-03 | Handle multiple hosts in a single scan file | XML: `<nmaprun>` contains multiple `<host>` children; merge by IP addr field |
| INPUT-04 | Auto-detect input format (XML vs text) | Content-sniff first ~16 bytes: `<?xml`/`<nmaprun` = XML, `# Nmap`/`Host:` = greppable, else text |
| ARCH-01 | Pluggable data source trait for easy swapping/adding of databases | `trait VulnSource` defined with associated error type; `dyn VulnSource` or enum dispatch |
| ARCH-02 | Typed error handling (distinguish rate limit vs empty result vs network error) | `thiserror` 2.0.18 derive macro; enum variants: `Empty`, `RateLimited`, `NetworkFailure` |
</phase_requirements>

---

## Summary

Phase 1 is a greenfield Rust CLI project. No existing code. The Rust toolchain installed is 1.91.1, well above the MSRV for all recommended crates. The project parses three nmap output formats (XML, text, greppable), renders a tree-based terminal display with conditional color, and defines the plugin trait + error taxonomy that all later phases build on.

The standard stack is well-established: `clap` 4.6.0 for argument parsing, `quick-xml` 0.39.2 with serde for XML deserialization, `owo-colors` 4.3.0 for conditional color, `thiserror` 2.0.18 for typed errors, `is-terminal` 0.4.17 for TTY detection, and `serde-saphyr` 0.0.22 as the YAML serializer (replacing the deprecated `serde_yaml`). All versions verified against crates.io as of research date.

The key architectural decision is whether to use an existing nmap XML parsing crate. The only viable option (`nmap_xml_parser` 0.3.0) was last updated 2020-11-09 with 8,185 downloads — it predates modern nmap service fields and lacks maintenance. The correct choice is to hand-write a serde/quick-xml deserialization layer over the official nmap DTD, which is fully documented and stable.

**Primary recommendation:** Use `quick-xml` + serde derive macros to deserialize the nmap DTD directly into strongly-typed Rust structs, with all optional service fields as `Option<String>`. Use `is-terminal` for TTY detection. Define `VulnSource` trait with thiserror-derived enum error type in Phase 1 even though no implementations exist yet.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| clap | 4.6.0 | CLI argument parsing, help text generation | 724M downloads, maintained by Rust CLI WG, derive macro API |
| quick-xml | 0.39.2 | nmap XML deserialization via serde | 234M downloads, serde feature, low-level control, actively maintained (Feb 2026) |
| serde | 1.0.228 | Derive macros for struct deserialization | Universal Rust serialization framework |
| thiserror | 2.0.18 | Typed error enum derive | 838M downloads, dtolnay, industry standard for library errors |
| is-terminal | 0.4.17 | Detect whether stdout/stderr is a TTY | 234M downloads, replaces deprecated `atty` crate |
| owo-colors | 4.3.0 | Zero-allocation conditional terminal color | 103M downloads, `if_supports_color` API, respects NO_COLOR/FORCE_COLOR |
| anyhow | 1.0.102 | Error propagation in main/binary layer | 591M downloads, pairs with thiserror: libraries use thiserror, binaries use anyhow |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| regex | 1.12.3 | Parse nmap text and greppable formats | Required for text/greppable parsing where serde/XML isn't available |
| serde-saphyr | 0.0.22 | YAML serialization for future frontmatter | Use instead of deprecated `serde_yaml`; serde_yaml is archived/unmaintained as of Mar 2024 |
| sanitize-filename | 0.7.0-beta | Safe filename generation | Phase 3 dependency; define wrapper now so all filename construction is routed through it |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| quick-xml | roxmltree | roxmltree (38M downloads) gives DOM-style tree access, easier to navigate but 6x fewer downloads, no serde integration; quick-xml serde is more ergonomic for strongly-typed structs |
| quick-xml | nmap_xml_parser 0.3.0 | Abandoned (last update 2020), missing modern nmap fields, no maintenance — do not use |
| thiserror | anyhow alone | anyhow erases type information at boundaries; thiserror required to distinguish Empty/RateLimited/NetworkFailure at trait level per ARCH-02 |
| owo-colors | termcolor | termcolor uses deprecated Windows APIs; owo-colors recommended by Rain's Rust CLI guide |
| serde-saphyr | serde_yml 0.0.12 | serde_yml (10M downloads) is a fork of serde_yaml with similar maintenance concerns; serde-saphyr (updated Mar 2026) is more actively maintained and panic-free |
| regex | nom / pest | nom/pest add parser combinator complexity unnecessary for line-oriented nmap text format |

**Installation:**
```bash
cargo add clap --features derive
cargo add quick-xml --features serialize
cargo add serde --features derive
cargo add thiserror
cargo add is-terminal
cargo add owo-colors
cargo add anyhow
cargo add regex
cargo add serde-saphyr
cargo add sanitize-filename
```

**Version verification:** All versions confirmed against crates.io registry as of 2026-03-21.

---

## Architecture Patterns

### Recommended Project Structure
```
src/
├── main.rs              # CLI entry point, clap parsing, exit codes
├── cli.rs               # Clap struct definitions (#[derive(Parser)])
├── models.rs            # Core data types: ScanResult, Host, Port, Service
├── parser/
│   ├── mod.rs           # Format detection (content sniff), dispatch
│   ├── xml.rs           # quick-xml + serde nmap XML deserialization
│   ├── text.rs          # Regex-based nmap text format parser
│   └── greppable.rs     # Regex-based nmap greppable (-oG) parser
├── render/
│   ├── mod.rs           # Render dispatch (tree vs quiet)
│   └── tree.rs          # Unicode tree rendering, color conditionals
├── sources/
│   └── mod.rs           # VulnSource trait definition + error taxonomy
└── util/
    └── filename.rs      # sanitize_filename() wrapper
tests/
├── xml_parse.rs         # Integration tests for XML parsing
├── text_parse.rs        # Integration tests for text format parsing
└── greppable_parse.rs   # Integration tests for greppable parsing
```

### Pattern 1: quick-xml + serde Nmap XML Deserialization

**What:** Map nmap DTD element/attribute structure to Rust structs using `#[serde(rename = "@attr")]` for XML attributes and `#[serde(default)]` for optional children.

**When to use:** All XML parsing. The DTD is stable; attribute names are the ground truth.

**Key nmap DTD facts (verified from official DTD at svn.nmap.org):**

`<service>` attributes:
- `name` (REQUIRED) — always present
- `product` (IMPLIED/optional) — software name e.g. "OpenSSH"
- `version` (IMPLIED/optional) — version string e.g. "8.9p1"
- `extrainfo` (IMPLIED/optional) — parenthetical info e.g. "Ubuntu Linux; protocol 2.0"
- `method` (REQUIRED: "table" | "probed")
- `conf` (REQUIRED: 0-10)
- `tunnel`, `hostname`, `ostype`, `devicetype` (all IMPLIED)

`<port>` attributes: `protocol` (REQUIRED), `portid` (REQUIRED numeric)

`<address>` attributes: `addr` (REQUIRED), `addrtype` ("ipv4"|"ipv6"|"mac", default ipv4), `vendor` (IMPLIED)

`<state>` attributes: `state` (REQUIRED), `reason` (REQUIRED), `reason_ttl` (REQUIRED), `reason_ip` (IMPLIED)

`<hostname>` attributes: `name` (IMPLIED), `type` ("user"|"PTR", IMPLIED)

`<cpe>` is a text element (child of `<service>`), content via `#[serde(rename = "$text")]`

**Example:**
```rust
// Source: quick-xml docs + nmap DTD at svn.nmap.org/nmap/docs/nmap.dtd
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename = "nmaprun")]
pub struct NmapRun {
    #[serde(rename = "@args")]
    pub args: Option<String>,
    #[serde(rename = "@version")]
    pub version: Option<String>,
    #[serde(default)]
    pub host: Vec<Host>,
}

#[derive(Debug, Deserialize)]
pub struct Host {
    pub status: Status,
    #[serde(default)]
    pub address: Vec<Address>,
    pub hostnames: Option<Hostnames>,
    pub ports: Option<Ports>,
    pub os: Option<Os>,
}

#[derive(Debug, Deserialize)]
pub struct Status {
    #[serde(rename = "@state")]
    pub state: String,  // "up", "down", "unknown"
}

#[derive(Debug, Deserialize)]
pub struct Address {
    #[serde(rename = "@addr")]
    pub addr: String,
    #[serde(rename = "@addrtype")]
    pub addrtype: Option<String>,  // "ipv4", "ipv6", "mac"
}

#[derive(Debug, Deserialize)]
pub struct Port {
    #[serde(rename = "@portid")]
    pub portid: u16,
    #[serde(rename = "@protocol")]
    pub protocol: String,
    pub state: Option<PortState>,
    pub service: Option<Service>,
}

#[derive(Debug, Deserialize)]
pub struct Service {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@product")]
    pub product: Option<String>,
    #[serde(rename = "@version")]
    pub version: Option<String>,
    #[serde(rename = "@extrainfo")]
    pub extrainfo: Option<String>,
    #[serde(rename = "@tunnel")]
    pub tunnel: Option<String>,
    #[serde(rename = "@hostname")]
    pub hostname: Option<String>,
    #[serde(rename = "@ostype")]
    pub ostype: Option<String>,
    #[serde(rename = "@devicetype")]
    pub devicetype: Option<String>,
    #[serde(default)]
    pub cpe: Vec<Cpe>,
}

#[derive(Debug, Deserialize)]
pub struct Cpe {
    #[serde(rename = "$text")]
    pub value: Option<String>,
}
```

Parse with:
```rust
// Source: quick-xml docs https://docs.rs/quick-xml/latest/quick_xml/de/
let result: NmapRun = quick_xml::de::from_str(&xml_content)?;
```

### Pattern 2: Format Detection by Content Sniffing

**What:** Read the first ~64 bytes of input and dispatch to the correct parser.

**When to use:** All input — file or stdin.

**Example:**
```rust
pub enum NmapFormat {
    Xml,
    Greppable,
    Text,
}

pub fn detect_format(bytes: &[u8]) -> NmapFormat {
    let head = std::str::from_utf8(&bytes[..bytes.len().min(64)])
        .unwrap_or("");
    if head.starts_with("<?xml") || head.contains("<nmaprun") {
        NmapFormat::Xml
    } else if head.starts_with("# Nmap") || head.starts_with("Host:") {
        NmapFormat::Greppable
    } else {
        NmapFormat::Text  // default assumption
    }
}
```

### Pattern 3: TTY Detection + Conditional Color

**What:** Check at startup whether stdout is a terminal. Pass a `bool` through the render layer.

**When to use:** All color output. Never hardcode ANSI codes.

**Example:**
```rust
// Source: Rain's Rust CLI recommendations https://rust-cli-recommendations.sunshowers.io/managing-colors-in-rust.html
use is_terminal::IsTerminal;
use owo_colors::{OwoColorize, Stream};

// At startup
let use_color = std::io::stdout().is_terminal();

// In render code
if use_color {
    println!("{}", hostname.green());
} else {
    println!("{}", hostname);
}

// Or with if_supports_color (handles NO_COLOR env var automatically)
println!(
    "{}",
    hostname.if_supports_color(Stream::Stdout, |s| s.green())
);
```

### Pattern 4: Typed Error Taxonomy via thiserror

**What:** Define a `VulnLookupError` enum at the `VulnSource` trait boundary with variants for each failure mode.

**When to use:** The `VulnSource` trait return type. Phase 1 defines the shape; Phase 2 fills implementations.

**Example:**
```rust
// Source: thiserror docs https://github.com/dtolnay/thiserror
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VulnLookupError {
    #[error("no results found for {cpe}")]
    Empty { cpe: String },

    #[error("rate limited by source: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("network failure querying {url}: {source}")]
    NetworkFailure {
        url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

pub trait VulnSource: Send + Sync {
    fn name(&self) -> &str;
    // Phase 2 will add: async fn lookup(&self, cpe: &str) -> Result<Vec<Vuln>, VulnLookupError>;
}
```

### Pattern 5: Greppable Format (-oG) Parsing

**What:** Regex over lines. Each non-comment line has tab-delimited `Key: value` fields.

**Greppable line format (from official docs):**
```
Host: 64.13.134.52 (scanme.nmap.org)\tStatus: Up\tPorts: 22/open/tcp//ssh//OpenSSH 4.3/, 80/open/tcp//http//Apache httpd 2.2.3/\tIgnored State: filtered (993)
```

Port subfields (7 slash-delimited): `portnum/state/protocol/owner/service/sunrpc/version`

**Example:**
```rust
// Parse greppable line
// Lines starting with '#' are comments — skip
// "Host: IP (hostname)" followed by tab-separated "Key: value" pairs
use regex::Regex;

static PORTS_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"(\d+)/(open|filtered|closed)/(\w+)//([^/]*)//([^,]*)").unwrap()
});

// For each port match: groups are portnum, state, protocol, service, version
```

### Pattern 6: Nmap Text Format Parsing

**What:** Regex over blocks separated by "Nmap scan report for" headers.

**Nmap text output key patterns:**
```
Nmap scan report for <hostname> (<ip>)     # or just IP
Nmap scan report for <ip>
Host is up (latency).
PORT     STATE  SERVICE  VERSION
22/tcp   open   ssh      OpenSSH 8.9p1
80/tcp   open   http     Apache httpd 2.4.52
```

**Example:**
```rust
static HOST_HEADER: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?").unwrap()
});

static PORT_LINE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    // port/proto  state  service  [version info]
    Regex::new(r"^(\d+)/(\w+)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?$").unwrap()
});
```

### Pattern 7: Exit Code Handling

**What:** Return `ExitCode` from `main` instead of calling `process::exit`.

**When to use:** All error paths in main.

**Example:**
```rust
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(AppError::ParseError(_)) => ExitCode::from(1),
        Err(AppError::NoInput | AppError::FileNotFound(_)) => ExitCode::from(2),
    }
}
```

### Anti-Patterns to Avoid

- **Using `nmap_xml_parser` crate:** Last updated 2020, 8k downloads, missing current fields. Use quick-xml + serde directly.
- **Using `serde_yaml` crate:** Officially deprecated March 2024, archived GitHub repo. Use `serde-saphyr` instead.
- **Using `atty` crate:** Deprecated. Use `is-terminal` which supersedes it.
- **Hardcoding ANSI escape codes:** Use `owo-colors` with stream detection; hardcoded codes break piped output.
- **Calling `process::exit()` in library code:** Prevents tests, prevents Drop cleanup. Use Result + ExitCode in main only.
- **String formatting YAML frontmatter with `format!`:** CVE descriptions contain YAML-significant characters (`:`, `{`, `}`). Use serde serialization.
- **Making all service fields non-optional:** In real-world nmap scans, `product`, `version`, `extrainfo` are frequently absent. ALL must be `Option<String>`.
- **Panicking on malformed input:** Use lenient parsing with stderr warnings — never panic on user-provided scan files.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Argument parsing and help text | Custom argv parser | clap 4 with derive | Help formatting, --version, error messages, shell completion are solved problems |
| XML deserialization | Custom XML walker | quick-xml + serde derive | Edge cases in attribute escaping, namespace handling, UTF-8 are already solved |
| Terminal color detection | Manual TERM/COLORTERM env var checks | `owo-colors` + `is-terminal` | Handles NO_COLOR, FORCE_COLOR, CI detection, Windows ANSI, pipe detection |
| Error boilerplate (Display, source, From) | Manual impl Error blocks | thiserror | Derive macro generates all impl blocks correctly |
| Filename sanitization | Custom char-replacement loop | `sanitize-filename` crate | Handles Windows reserved names (CON, PRN, etc.), length limits, cross-platform edge cases |
| YAML serialization | `format!` strings with YAML syntax | serde-saphyr | CVE descriptions contain `{`, `:`, `"` that break manual YAML |
| TTY detection | `libc::isatty()` directly | `is-terminal` | Cross-platform (Windows, WASM, etc.), safe abstraction |

**Key insight:** Nmap XML parsing is uniquely well-suited to the serde derive pattern because the DTD provides a stable contract. The attribute naming convention (`@name` in serde = `name=""` in XML) maps cleanly to the DTD spec.

---

## Common Pitfalls

### Pitfall 1: Service Fields Not Optional
**What goes wrong:** `NmapRun` deserialization panics or returns `Err` when `product`/`version`/`extrainfo` attributes are absent from `<service>` elements.
**Why it happens:** Many nmap scans use table-based service detection (`method="table"`) which omits version fields. Some services show only name.
**How to avoid:** Every service attribute except `name`, `method`, and `conf` must be `Option<String>`. Use `#[serde(default)]` on Vec fields.
**Warning signs:** Works on your test scan, fails on customer scan files with unexpected hosts.

### Pitfall 2: Multiple `<address>` Elements Per Host
**What goes wrong:** Only the IPv4 address is captured, MAC address is lost; or deserialization fails because `address` is modeled as a single struct.
**Why it happens:** nmap emits multiple `<address>` elements per host (IPv4, IPv6, MAC each get their own element).
**How to avoid:** Model `address` as `Vec<Address>`, then select the IPv4 entry for the primary display key.
**Warning signs:** Host IP shows as empty string or MAC address instead of IPv4.

### Pitfall 3: `# Nmap` vs `Host:` Format Detection Collision
**What goes wrong:** A greppable file without the standard comment header (e.g., truncated output, custom scripts) is misclassified as text format.
**Why it happens:** The `# Nmap` header comment appears at the top of every greppable file; `Host:` is the first data line. But some tools strip comments.
**How to avoid:** Also check for `Host: ` (with space and IP pattern) as a secondary greppable signal during detection. Fall back gracefully.
**Warning signs:** No hosts found when parsing greppable file without header.

### Pitfall 4: stdin Hang When No Input
**What goes wrong:** User types `portreaper` with no args and the program blocks reading stdin instead of showing help.
**Why it happens:** `stdin().read_to_string()` blocks if stdin is a TTY (interactive terminal).
**How to avoid:** Check `is_terminal::IsTerminal::is_terminal(&std::io::stdin())` before attempting stdin read. If stdin is a TTY and no files were given, print usage and exit with code 2.
**Warning signs:** Process appears to hang on bare invocation.

### Pitfall 5: serde-saphyr vs serde_yaml API Differences
**What goes wrong:** Code written for `serde_yaml` uses `serde_yaml::to_string()` which does not exist in `serde-saphyr`.
**Why it happens:** serde-saphyr and serde_yml have different APIs from the deprecated serde_yaml.
**How to avoid:** For Phase 1, avoid YAML output entirely — Phase 3 needs it. When Phase 3 arrives, use `serde_saphyr::to_string()`. Do not use serde_yaml.
**Warning signs:** Compiler error "use of undeclared crate or module serde_yaml".

### Pitfall 6: Duplicate Host Merging Logic
**What goes wrong:** When processing multiple files, the same IP appears twice in output — once per file instead of merged.
**Why it happens:** Multiple nmap scans of the same target produce separate XML files, each with their own `<host>` for the same IP.
**How to avoid:** Use a `HashMap<IpAddr, Host>` keyed on the primary IPv4 address. When inserting, merge port sets (union of all ports). Last-seen values win for metadata.
**Warning signs:** Output shows duplicate `192.168.1.1` entries when two files are passed.

### Pitfall 7: Tree Characters Break on Non-Unicode Terminals
**What goes wrong:** Box-drawing characters (├──, └──, │) appear as garbage on Windows cmd.exe or legacy terminals.
**Why it happens:** Unicode box-drawing is U+2500 range; some terminals only support ASCII or code page 850.
**How to avoid:** This is acceptable for a modern pentest tool targeting Linux/macOS users. Document UTF-8 terminal requirement. Do NOT add ASCII fallback in Phase 1 — keep it simple.
**Warning signs:** User reports garbled tree output on Windows 10 with default cmd.exe.

---

## Code Examples

Verified patterns from official sources:

### Parsing nmap XML with quick-xml
```rust
// Source: quick-xml docs https://docs.rs/quick-xml/latest/quick_xml/de/
use quick_xml::de::from_str;

let xml = std::fs::read_to_string("scan.xml")?;
let result: NmapRun = from_str(&xml)?;
for host in &result.host {
    if host.status.state == "up" {
        // process host
    }
}
```

### Detecting stdin vs file input
```rust
// Source: is-terminal docs https://docs.rs/is-terminal/
use is_terminal::IsTerminal;
use std::io::{self, Read};

fn get_input(file_paths: &[PathBuf]) -> Result<Vec<(String, String)>, AppError> {
    if file_paths.is_empty() {
        if std::io::stdin().is_terminal() {
            // No files, stdin is interactive — show help
            return Err(AppError::NoInput);
        }
        // stdin is piped — read it
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        Ok(vec![("stdin".to_string(), buf)])
    } else {
        file_paths.iter().map(|p| {
            let content = std::fs::read_to_string(p)?;
            Ok((p.display().to_string(), content))
        }).collect()
    }
}
```

### owo-colors with TTY check
```rust
// Source: owo-colors docs https://docs.rs/owo-colors + Rain's CLI guide
use owo_colors::{OwoColorize, Stream};

// Automatic TTY + NO_COLOR + FORCE_COLOR detection:
println!("{}", hostname.if_supports_color(Stream::Stdout, |s| s.bold().green()));
println!("{}", format!("{}:{}", ip, port).if_supports_color(Stream::Stdout, |s| s.cyan()));
```

### Unicode tree rendering
```rust
// Unicode box-drawing constants for tree structure
// ├── for non-last items (U+251C, U+2500, U+2500)
// └── for last items (U+2514, U+2500, U+2500)
// │   for vertical continuation (U+2502)

const BRANCH: &str = "├── ";
const LAST_BRANCH: &str = "└── ";
const VERTICAL: &str = "│   ";
const INDENT: &str = "    ";

fn render_host(host: &Host, is_last: bool) {
    let connector = if is_last { LAST_BRANCH } else { BRANCH };
    println!("{}{}", connector, host.ip);
    // ...recurse for ports
}
```

### thiserror VulnLookupError
```rust
// Source: thiserror GitHub https://github.com/dtolnay/thiserror
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VulnLookupError {
    #[error("empty result for cpe '{cpe}' — source returned no data")]
    Empty { cpe: String },

    #[error("rate limited — retry after {retry_after_secs} seconds")]
    RateLimited { retry_after_secs: u64 },

    #[error("network failure reaching {url}")]
    NetworkFailure {
        url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Pluggable vulnerability source trait.
/// Implementations added in Phase 2.
pub trait VulnSource: Send + Sync {
    /// Human-readable name for this source (e.g., "NVD", "CVE.org")
    fn name(&self) -> &str;
}
```

### clap 4 argument struct
```rust
// Source: clap docs https://docs.rs/clap/
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "portreaper")]
#[command(about = "Parse nmap scans and display structured results")]
pub struct Cli {
    /// nmap XML or text scan file(s). Reads from stdin if omitted and stdin is piped.
    pub files: Vec<PathBuf>,

    /// Verbose output: show CPE strings, OS detection, extra service fields
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Quiet mode: show summary line only
    #[arg(short = 'q', long)]
    pub quiet: bool,

    // Phase 2+ flags (defined now so help text is stable)
    /// Enrich results with vulnerability lookups
    #[arg(long)]
    pub enrich: bool,

    /// Output Obsidian vault to this directory
    #[arg(long)]
    pub vault: Option<PathBuf>,
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `serde_yaml` for YAML output | `serde-saphyr` or `serde_yml` | March 2024 (serde_yaml deprecated) | Must use serde-saphyr; serde_yaml is archived |
| `atty` crate for TTY detection | `is-terminal` | ~2022 (atty unmaintained) | is-terminal is the stdlib-aligned replacement |
| `structopt` for CLI parsing | `clap` 4 with derive feature | 2022 (structopt merged into clap) | All new projects use clap 4; structopt is deprecated |
| `nmap_xml_parser` crate | Direct quick-xml + serde deserialization | Effectively: nmap_xml_parser last updated 2020 | Must write own deserialization layer |
| `colored` crate | `owo-colors` | ~2021 | owo-colors: zero-alloc, no_std, better stream support |

**Deprecated/outdated:**
- `serde_yaml`: Archived March 2024 by dtolnay. Do not use. Use `serde-saphyr`.
- `atty`: Unsound (GHSA-g98v-hv3f-hcfr). Use `is-terminal`.
- `structopt`: Merged into clap 4. Use `clap` with `derive` feature.
- `nmap_xml_parser 0.3.0`: Abandoned 2020, missing modern nmap fields.

---

## Open Questions

1. **serde-saphyr API maturity**
   - What we know: serde-saphyr 0.0.22 updated March 2026, 246k downloads, "panic-free" emphasis
   - What's unclear: The 0.0.x version signals pre-stability; API may change. serde_yml 0.0.12 has 10M downloads (more adoption).
   - Recommendation: For Phase 1, YAML output is not needed. Defer the YAML crate decision to Phase 3 when it's actually used. In Phase 1, only define the trait and error types using thiserror — no YAML needed yet.

2. **quick-xml serde Vec deserialization for `<host>` elements**
   - What we know: quick-xml serde supports Vec fields for repeated elements with `#[serde(default)]`
   - What's unclear: Whether `NmapRun { host: Vec<Host> }` works when there's only a single `<host>` element (some XML serde implementations require wrapping)
   - Recommendation: Test with both single-host and multi-host XML files in Wave 0. Add integration test fixtures for both cases.

3. **nmap text format VERSION column presence**
   - What we know: `nmap -sV` adds VERSION column; basic `nmap` scan without -sV has only PORT/STATE/SERVICE
   - What's unclear: Whether VERSION column is always present in piped output or depends on scan flags
   - Recommendation: Make version extraction optional in text parser — if no VERSION column content, leave `version: None`. This is consistent with `Option<String>` model.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` + integration tests in `tests/` |
| Config file | none — Cargo.toml `[dev-dependencies]` only |
| Quick run command | `cargo test` |
| Full suite command | `cargo test -- --include-ignored` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|--------------|
| INPUT-01 | XML file with 3 hosts parsed correctly | integration | `cargo test xml_parse` | ❌ Wave 0 |
| INPUT-01 | Service with all optional fields absent still parses | integration | `cargo test xml_parse::optional_fields_absent` | ❌ Wave 0 |
| INPUT-01 | Service with CPE strings extracted | integration | `cargo test xml_parse::cpe_extraction` | ❌ Wave 0 |
| INPUT-02 | Piped stdin auto-detected when not a TTY | unit | `cargo test stdin_detection` | ❌ Wave 0 |
| INPUT-02 | Stdin TTY with no files exits with code 2 | integration | `cargo test cli::no_input_exits_2` | ❌ Wave 0 |
| INPUT-03 | Multi-host scan: no hosts silently dropped | integration | `cargo test xml_parse::multi_host_count` | ❌ Wave 0 |
| INPUT-03 | Duplicate IP across files: merged, not duplicated | integration | `cargo test parser::merge_duplicate_hosts` | ❌ Wave 0 |
| INPUT-04 | `<?xml` content → XML parser dispatched | unit | `cargo test format_detection::xml` | ❌ Wave 0 |
| INPUT-04 | `# Nmap` content → greppable parser dispatched | unit | `cargo test format_detection::greppable` | ❌ Wave 0 |
| INPUT-04 | `Nmap scan report` content → text parser dispatched | unit | `cargo test format_detection::text` | ❌ Wave 0 |
| INPUT-04 | Non-nmap file → clear error, no panic | integration | `cargo test parser::non_nmap_file_error` | ❌ Wave 0 |
| ARCH-01 | VulnSource trait compiles with no implementations | unit | `cargo build` (trait definition check) | ❌ Wave 0 |
| ARCH-02 | VulnLookupError variants are distinct at compile time | unit | `cargo test error_taxonomy` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test`
- **Per wave merge:** `cargo test -- --include-ignored`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `Cargo.toml` — project does not exist yet; must be initialized with `cargo new portreaper`
- [ ] `tests/fixtures/` — nmap XML, text, greppable fixture files (real or synthetic) for integration tests
- [ ] `tests/xml_parse.rs` — covers INPUT-01, INPUT-03
- [ ] `tests/text_parse.rs` — covers INPUT-02, INPUT-04 (text branch)
- [ ] `tests/greppable_parse.rs` — covers INPUT-04 (greppable branch)
- [ ] `tests/cli.rs` — covers exit code behavior, no-input detection

---

## Sources

### Primary (HIGH confidence)
- `https://svn.nmap.org/nmap/docs/nmap.dtd` — official nmap XML DTD; verified all element/attribute names and required vs optional status
- `https://nmap.org/book/output-formats-grepable-output.html` — official nmap grepable format spec; verified field order and port subfield structure
- `https://docs.rs/quick-xml/latest/quick_xml/de/` — quick-xml serde deserialization patterns; verified `@attr`, `$text`, `Vec` handling
- `https://crates.io/api/v1/crates/*` — all crate versions verified against registry as of 2026-03-21
- `https://rust-cli-recommendations.sunshowers.io/managing-colors-in-rust.html` — authoritative Rust CLI color management guide; verified owo-colors + is-terminal pattern

### Secondary (MEDIUM confidence)
- `https://github.com/dtolnay/thiserror` — thiserror README; verified `#[error]` syntax and `#[source]` attribute
- `https://github.com/owo-colors/owo-colors` — owo-colors README; verified `if_supports_color(Stream::Stdout, ...)` API
- WebSearch results for nmap text output format structure — cross-verified with official nmap book

### Tertiary (LOW confidence)
- WebSearch for serde_yaml deprecation community discussion — confirmed via crates.io `+deprecated` tag (HIGH) and archived GitHub repo

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all versions verified against crates.io registry 2026-03-21; active maintenance confirmed
- Architecture: HIGH — nmap DTD verified from official source; quick-xml patterns verified from docs.rs
- Pitfalls: HIGH — most derived from DTD inspection and crate deprecation audit; one LOW (tree char compatibility) is noted as acceptable
- Validation: HIGH — Rust built-in test framework, no external framework needed

**Research date:** 2026-03-21
**Valid until:** 2026-06-21 (90 days — core crates are stable; serde-saphyr API watch recommended at Phase 3)

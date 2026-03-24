# Phase 3: Obsidian Vault Output - Research

**Researched:** 2026-03-23
**Domain:** Obsidian vault generation from Rust — YAML frontmatter, wikilinks, graph coloring, file I/O
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Vault folder structure**
- D-01: Organize by type: `cves/`, `technologies/`, `scans/{scan-label}/hosts/`, `scans/{scan-label}/services/`, `assets/`
- D-02: Single vault model — each scan run adds a subfolder under `scans/`. CVEs and technologies live at the top level and are shared across all scans.
- D-03: Scan subfolders named by date + target range (auto-generated from scan metadata): e.g., `2026-03-21_192.168.1.0`. Falls back to date + filename if no target info available.
- D-04: Technology notes (`technologies/`) auto-generated from scan data: product name, versions seen across scans, host instances, linked CVEs, and a user-editable Notes section.

**Wikilink topology**
- D-05: Downward + shared links: index→hosts, hosts→services, services→CVEs, services→technologies. CVE notes include explicit "Affected Services" backlinks. Technology notes link to instances and CVEs.
- D-06: Aliased display text for readability: `[[192.168.1.1_22_ssh|:22 ssh (OpenSSH 7.4)]]`. File names stay machine-friendly, link text is human-friendly.
- D-07: CVE notes include explicit "Affected Services" section listing all services that reference the CVE — not relying on Obsidian's backlinks panel.

**Note templates**

Host notes:
- D-08: YAML frontmatter: ip, hostnames, os, highest_severity, tags (host + severity), scan label
- D-09: Body: hostname display, OS info, Open Ports table (port | service link | product | severity tag), Vulnerability Summary (counts by severity + highest CVE link), user-editable Notes section

Service notes:
- D-10: YAML frontmatter: host, port, protocol, service, product, version, highest_severity, tags (service + name + severity), scan label
- D-11: Body: title as `{ip}:{port}/{proto} - {service}`, product link to technology note, host backlink, CPE string in code block, Vulnerabilities table (CVE link | score | severity tag | description), user-editable Notes section

CVE notes:
- D-12: YAML frontmatter: cve_id, cvss_score, severity, cvss_version, sources list, tags (cve + severity), first_seen date
- D-13: Body: score/severity/CVSS version headline, sources, description, Affected Services list with wikilinks, References section with NVD and CVE.org external links, user-editable Notes section

Technology notes:
- D-14: YAML frontmatter: product, versions_seen list, tags (technology + product name), first_seen date
- D-15: Body: Instances list (host link + port + version), Known CVEs list, user-editable Notes section

**Index pages**
- D-16: Global `_index.md` at vault root: severity breakdown table, total counts (hosts/services/CVEs), Critical Findings section (top CVEs with affected services), Scans list with dates and stats, Hosts list with highest severity
- D-17: Per-scan index note in each scan subfolder: scan date, source filename, host/service/CVE counts, host list with severity, severity breakdown table

**CSS snippet**
- D-18: Tag-based severity graph coloring: critical=red (#ff4444), high=orange (#ff8800), medium=yellow (#ffcc00), low=green (#44bb44), host=blue (#4488ff), cve=purple (#aa44ff), technology=cyan (#44cccc)
- D-19: CSS file placed in `assets/severity-colors.css` with instructions to copy to `.obsidian/snippets/`

### Claude's Discretion
- Exact Obsidian graph CSS selector syntax (may need `.tag-` prefix instead of `.color-fill-tag-`)
- YAML serialization approach for frontmatter (serde_yaml is mandated, but struct design is flexible)
- How to derive scan label from nmap XML metadata (startstr, args, etc.)
- Internal module organization for vault generation code
- How to handle services with zero CVEs in templates (still generate notes or skip)
- Truncation strategy for very long CVE descriptions in service note tables

### Deferred Ideas (OUT OF SCOPE)
- Incremental vault updates (merging new scan data into existing vault without overwriting) — Phase 5 (OUT-08)
- Config file for default vault output path — Phase 5 (ARCH-03)
- Cross-vault linking between separate Obsidian vaults — revisit if single-vault model proves insufficient
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| OUT-01 | Generate Obsidian vault with `[[wikilinks]]` for native graph view | Wikilink syntax verified; `[[filename\|display text]]` aliased form confirmed working |
| OUT-02 | Hierarchical node structure: Project → IP Addresses → Ports/Services | Folder-per-type structure with wikilinks creates this topology in graph view |
| OUT-03 | YAML frontmatter with severity, tags, and service metadata | serde_yml 0.0.12 handles all YAML-special chars safely; frontmatter struct patterns documented |
| OUT-04 | Severity classification (critical/high/medium/low) with Obsidian tags | Tags in frontmatter as YAML list; graph color groups use `tag:#severity` query format |
| OUT-05 | Structured service note template (service info table, vulns, links) | Template patterns for Option<T> field handling documented; description truncation patterns provided |
| OUT-06 | Shared CVE notes (one note per CVE, linked from all affected services) | Cross-service CVE deduplication pattern: collect all CVEs first, then write once; model already deduplicates by highest CVSS |
| OUT-07 | Obsidian CSS snippet for severity-based color-coding in graph view | Confirmed mechanism: pre-built `graph.json` with colorGroups + CSS snippet with `--graph-node-tag` variable |
</phase_requirements>

---

## Summary

Phase 3 generates a complete Obsidian knowledge vault from an enriched `ScanResult`. The implementation is pure file I/O — no async needed, no external APIs. It has three layers: (1) a new `src/vault/` module that owns all generation logic, (2) `serde_yml` added to `Cargo.toml` for safe YAML frontmatter serialization, and (3) `main.rs` branching to vault generation when `--vault` flag is provided.

The most important technical fact uncovered by research: **Obsidian's graph view does NOT support per-tag node coloring via CSS selectors alone.** CSS can only change the color of ALL tag nodes uniformly (`--graph-node-tag`). Per-severity node coloring of *note* nodes requires pre-configuring Obsidian's color groups feature via a generated `.obsidian/graph.json` file. The correct approach is to generate both the CSS snippet (for tag node color) AND a pre-configured `graph.json` that sets up five color groups (critical/high/medium/low/host) using `tag:#severity` queries. This is a significant architectural finding — the CSS-only approach described in D-18/D-19 delivers partial value but the graph.json approach is what actually colors note nodes.

The second critical finding: `serde_yaml` 0.9.34 is deprecated and marked as such on crates.io. The drop-in replacement is `serde_yml` 0.0.12 (a maintained fork with identical API: `serde_yml::to_string()`). The STATE.md mandate says "use serde_yaml" but this must be interpreted as "use a serde-compatible YAML crate" — switching to `serde_yml` is strictly better.

**Primary recommendation:** Add `serde_yml = "0.0.12"` to Cargo.toml. Create `src/vault/` module. Generate both `assets/severity-colors.css` AND `.obsidian/graph.json` for correct graph coloring.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| serde_yml | 0.0.12 | YAML frontmatter serialization | Maintained fork of deprecated serde_yaml; identical API; handles YAML-special chars safely |
| std::fs | stdlib | Directory creation, file writing | Pure file I/O, no async needed |
| std::collections::HashMap | stdlib | CVE deduplication across services, tech note accumulation | Grouping CVEs and products across multiple hosts/ports |
| chrono | already in ecosystem | Date formatting for scan labels | Already a transitive dep via reqwest; use `chrono::Local::now()` for YYYY-MM-DD |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| sanitize-filename | 0.6.0 (already present) | Route all vault filename construction | Already mandated; use for every filename generated |
| thiserror | 2.0.18 (already present) | VaultError enum | Add `VaultError` variants for write failures |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| serde_yml | serde_yaml 0.9.34 | serde_yaml is deprecated+archived; identical API, no reason to use it |
| serde_yml | serde-saphyr | serde-saphyr is newer/different architecture; serde_yml is the direct API-compatible fork |
| std::fs::write | tokio::fs | Vault generation is synchronous; async file I/O adds complexity with no benefit here |

**Installation:**
```bash
cargo add serde_yml@0.0.12
```

Or add to `Cargo.toml`:
```toml
serde_yml = "0.0.12"
```

**Version verification:** Confirmed via crates.io API on 2026-03-23. `serde_yml` latest stable = 0.0.12 (released 2024-08-25).

---

## Architecture Patterns

### Recommended Project Structure
```
src/
├── vault/
│   ├── mod.rs           # pub fn generate_vault(scan, path) -> Result<VaultStats>
│   ├── writer.rs        # Low-level: ensure_dir(), write_note()
│   ├── frontmatter.rs   # Serde structs for each note type's frontmatter
│   ├── templates.rs     # Note body rendering functions (host, service, cve, tech, index)
│   └── graph_config.rs  # graph.json + CSS snippet generation
```

### Pattern 1: Two-Pass Generation
**What:** First pass collects all CVEs and technology products across all hosts/ports. Second pass writes all files.
**When to use:** Required for CVE notes (need "Affected Services" list that spans all services) and technology notes (need "versions seen" across all services).
**Example:**
```rust
// Pass 1: collect global state
let mut cve_map: HashMap<String, CveAccumulator> = HashMap::new();
let mut tech_map: HashMap<String, TechAccumulator> = HashMap::new();

for host in &scan.hosts {
    for port in &host.ports {
        for vuln in &port.vulnerabilities {
            cve_map.entry(vuln.cve_id.clone())
                .or_default()
                .add_service(&host.ip, port.port_id, &port.protocol);
        }
        if let Some(svc) = &port.service {
            if let Some(product) = &svc.product {
                tech_map.entry(product.clone())
                    .or_default()
                    .add_instance(&host.ip, port.port_id, svc.version.as_deref());
            }
        }
    }
}

// Pass 2: write all files
write_host_notes(&scan, &vault_path, &cve_map, scan_label)?;
write_service_notes(&scan, &vault_path, &cve_map, &tech_map, scan_label)?;
write_cve_notes(&cve_map, &vault_path)?;
write_tech_notes(&tech_map, &vault_path)?;
write_index_notes(&scan, &vault_path, scan_label)?;
```

### Pattern 2: serde_yml Frontmatter Structs
**What:** Define a separate serde struct per note type. Serialize with `serde_yml::to_string()`, then prepend `---\n` delimiters and append note body.
**When to use:** All note types. Never use `format!` macros for YAML — CVE descriptions contain `:`, `"`, `'`, and `#`.
**Example:**
```rust
// Source: docs.rs/serde_yml/latest
use serde::Serialize;

#[derive(Serialize)]
struct ServiceFrontmatter {
    host: String,
    port: u16,
    protocol: String,
    service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    highest_severity: String,
    tags: Vec<String>,
    scan_label: String,
}

fn render_service_note(fm: &ServiceFrontmatter, body: &str) -> String {
    let yaml = serde_yml::to_string(fm).expect("frontmatter serialization failed");
    format!("---\n{}---\n\n{}", yaml, body)
}
```

### Pattern 3: Filename Convention
**What:** Service note filenames encode `{ip}_{port}_{proto}`. CVE note filenames are the CVE ID. Host note filenames are the IP.
**When to use:** All file creation. Route every name through `sanitize_filename()`.
**Example:**
```rust
// src/util/filename.rs already implements this
let host_file = sanitize_filename(&host.ip);          // "192.168.1.1"
let svc_file = sanitize_filename(
    &format!("{}_{}_{}", host.ip, port.port_id, port.protocol)
); // "192.168.1.1_22_tcp"
let cve_file = sanitize_filename(&vuln.cve_id);        // "CVE-2021-41773"
let tech_file = sanitize_filename(product);            // "Apache httpd"
```

### Pattern 4: Wikilink Generation
**What:** Generate `[[filename|display text]]` where filename is the sanitized note name (no extension) and display text is human-friendly.
**When to use:** All cross-note links.
**Example:**
```rust
fn service_wikilink(ip: &str, port_id: u16, proto: &str, svc: &Service) -> String {
    let filename = sanitize_filename(&format!("{}_{}_{}", ip, port_id, proto));
    let display = format!(":{}/ {} ({})",
        port_id,
        svc.name,
        svc.product.as_deref().unwrap_or("unknown")
    );
    format!("[[{}|{}]]", filename, display)
}
```

### Pattern 5: Scan Label Derivation
**What:** Extract `start` Unix timestamp from `NmapRun.start` and target range from `NmapRun.args`. Format as `YYYY-MM-DD_{target}`.
**When to use:** Naming `scans/{scan-label}/` subfolder (D-03).
**Example:**
```rust
// NmapRun.args = "nmap -sV -oX scan.xml 192.168.1.0/24"
// NmapRun.start = "1710000000" (Unix timestamp)
fn derive_scan_label(args: Option<&str>, start_ts: Option<&str>, source: &str) -> String {
    let date = start_ts
        .and_then(|ts| ts.parse::<i64>().ok())
        .map(|ts| chrono::DateTime::from_timestamp(ts, 0)
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "unknown-date".to_string()))
        .unwrap_or_else(|| chrono::Local::now().format("%Y-%m-%d").to_string());

    let target = args
        .and_then(|a| a.split_whitespace().last())
        .map(|t| sanitize_filename(t))
        .unwrap_or_else(|| sanitize_filename(source));

    format!("{}_{}", date, target)
}
```
**Note:** `NmapRun.args` and `NmapRun.start` are already parsed in `src/parser/xml.rs` as `Option<String>` fields on `NmapRun`. However, these fields are currently NOT propagated to `ScanResult`. The XML parser must be extended to expose `scan_args` and `scan_start` on `ScanResult`, OR the vault module can re-derive the label from `ScanResult.source` (the filename) plus current date as fallback.

### Pattern 6: Graph Color Groups via graph.json
**What:** Generate `.obsidian/graph.json` with pre-configured color groups that query `tag:#severity` for each severity level. This is the ONLY way to color individual note nodes by severity in Obsidian's graph view.
**When to use:** Required for OUT-07 success criterion ("graph view colors nodes correctly by severity").
**Important finding:** CSS snippets alone cannot color *note* nodes by their tags. CSS only controls: (a) all tag nodes uniformly (`--graph-node-tag`), (b) all attachment nodes, etc. To get per-severity note node coloring, color groups in graph.json are the mechanism.
**Example:**
```json
{
  "collapse-filter": false,
  "showTags": true,
  "showAttachments": false,
  "hideUnresolved": false,
  "collapse-color-groups": false,
  "colorGroups": [
    { "query": "tag:#critical", "color": { "a": 1, "rgb": 16728132 } },
    { "query": "tag:#high",     "color": { "a": 1, "rgb": 16744448 } },
    { "query": "tag:#medium",   "color": { "a": 1, "rgb": 16764928 } },
    { "query": "tag:#low",      "color": { "a": 1, "rgb": 4503620 } },
    { "query": "tag:#host",     "color": { "a": 1, "rgb": 4491007 } },
    { "query": "tag:#cve",      "color": { "a": 1, "rgb": 11157759 } },
    { "query": "tag:#technology", "color": { "a": 1, "rgb": 4441292 } }
  ],
  "collapse-display": false,
  "showArrow": false,
  "textFadeMultiplier": 0,
  "nodeSizeMultiplier": 1,
  "lineSizeMultiplier": 1,
  "collapse-forces": false,
  "centerStrength": 0.518025751072961,
  "repelStrength": 10,
  "linkStrength": 1,
  "linkDistance": 250,
  "scale": 1,
  "close": false
}
```

RGB values for D-18 colors (decimal integer = R*65536 + G*256 + B):
- critical #ff4444 = 16736324
- high #ff8800 = 16746496
- medium #ffcc00 = 16763904
- low #44bb44 = 4505412
- host #4488ff = 4491007
- cve #aa44ff = 11157759
- technology #44cccc = 4441292

**graph.json location:** The `.obsidian/` directory is created inside the vault root. PortReaper generates the vault directory, so it MUST create `.obsidian/graph.json` too. User still must enable the CSS snippet manually (Obsidian requires opt-in for snippets), but graph.json color groups activate automatically when the vault is opened.

### Anti-Patterns to Avoid
- **format! macros for YAML values:** CVE descriptions contain `:`, `"`, `#` — these break hand-rolled YAML. Use `serde_yml::to_string()` for all frontmatter.
- **Slash in Obsidian filenames:** Obsidian treats `/` in a filename as a folder separator. Must sanitize all IP addresses, service names (e.g., `ssl/http`), and protocols through `sanitize_filename()`.
- **IPv6 bracket handling:** IPv6 addresses contain `[` and `]` which are forbidden in Obsidian filenames (per Obsidian forum). `sanitize_filename()` will replace them with `_`, which is correct.
- **Relying on CSS alone for graph coloring:** `--graph-node-tag` CSS variable changes color of ALL tag nodes uniformly. It does not color *note* nodes by their individual tags. The graph.json color groups approach is required.
- **Overwriting the vault on each run:** Phase 3 is write-once (OUT-08 handles incremental updates). Use `std::fs::create_dir_all()` which is idempotent. For Phase 3, if a file exists, overwrite it (scan-specific files) or merge if CVE note exists (out of scope — Phase 3 can simply overwrite).
- **Blocking main with file I/O:** Vault generation is synchronous — call it from within the async `run()` function as a regular `fn`, not `async fn`.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| YAML escaping for frontmatter | Custom string escaping for colons, quotes, special chars | `serde_yml::to_string()` on a typed struct | CVE descriptions contain every YAML-special character; custom escaping will miss edge cases |
| Filename sanitization | Custom char-replacement logic | `sanitize_filename()` in `src/util/filename.rs` | Already handles OS-specific forbidden chars; tested; mandated by STATE.md |
| Graph color calculation | Custom hex→int conversion | Pre-compute RGB integers | Colors are fixed per D-18; hardcode the 7 integer values |
| Directory creation | Manual path existence checks | `std::fs::create_dir_all()` | Idempotent; handles nested paths; stdlib |
| CVE deduplication | Re-implementing dedup | `dedup_vulnerabilities()` already in `src/enrichment/mod.rs` | Phase 2 already deduplicates by highest CVSS at the port level |

**Key insight:** The vault generation problem is fundamentally a text templating + file I/O problem. Resist adding templating engine dependencies (Tera, Handlebars) — the templates are small enough to write as Rust string formatting. The only external crate needed is `serde_yml` for YAML frontmatter.

---

## Common Pitfalls

### Pitfall 1: YAML Frontmatter Special Characters
**What goes wrong:** A CVE description like `"Apache: vulnerability in mod_ssl (score: 9.8)"` serialized via `format!` produces invalid YAML because the colons and quotes break the YAML parser. Obsidian renders the frontmatter as an error or silently drops it.
**Why it happens:** Hand-written YAML escaping is error-prone. Real CVE descriptions frequently contain `:`, `"`, `#`, `>`, `|`, `{`, `}`.
**How to avoid:** Define `#[derive(Serialize)]` structs for every frontmatter type. Call `serde_yml::to_string(&frontmatter)`. Never use `format!` to construct YAML key-value pairs.
**Warning signs:** If any YAML value contains a colon followed by a space, the YAML is broken unless the value is quoted.

### Pitfall 2: Slash in Service Names
**What goes wrong:** nmap reports services like `ssl/http`, `http/proxy`. A filename like `192.168.1.1_443_ssl/http.md` is invalid on all OS. An Obsidian wikilink containing `/` is interpreted as a folder path.
**Why it happens:** Service names from the `name` field in `Port.service` are nmap's raw names and frequently contain slashes.
**How to avoid:** Route every filename component through `sanitize_filename()`. This replaces `/` with `_`, yielding `192.168.1.1_443_ssl_http.md`.
**Warning signs:** Any `Port.service.name` containing `/` (e.g., `ssl/http`, `http/proxy`, `microsoft-ds`).

### Pitfall 3: Graph Node Coloring Requires graph.json
**What goes wrong:** Generating only a CSS snippet produces no visible node color differentiation in the graph view. Users see a uniform grey graph.
**Why it happens:** Obsidian's graph uses a WebGL/canvas renderer. CSS `--graph-node-tag` CSS variable changes the global tag-node color. Note nodes are colored via the "Color groups" panel settings, stored in `.obsidian/graph.json` as `colorGroups`.
**How to avoid:** Generate `.obsidian/graph.json` alongside the CSS snippet. The `colorGroups` array uses `tag:#critical`, `tag:#high`, etc. as query strings.
**Warning signs:** If the success criterion says "graph view colors nodes by severity" and only a CSS file is generated, this is the pitfall.

### Pitfall 4: ScanResult Lacks Nmap Metadata
**What goes wrong:** `ScanResult` doesn't expose `start` timestamp or `args` from the nmap XML `<nmaprun>` element. Deriving the scan label (D-03) requires these fields.
**Why it happens:** `src/parser/xml.rs` parses `NmapRun.args` and `NmapRun.start` but only uses them for the `ScanResult.source` string (the filename). They are not forwarded to the model.
**How to avoid:** Either (a) extend `ScanResult` with `scan_args: Option<String>` and `scan_start: Option<u64>`, or (b) accept that Phase 3 derives the scan label from `ScanResult.source` (the filename) plus the current date. Option (b) is simpler and fully satisfies D-03's fallback: "falls back to date + filename if no target info available."
**Warning signs:** Plan tasks that reference deriving scan metadata from ScanResult without first adding those fields to the struct.

### Pitfall 5: CVE Note "Affected Services" Requires Two-Pass Logic
**What goes wrong:** Writing CVE notes in a single pass over hosts/ports means you can't populate "Affected Services" until all services have been iterated.
**Why it happens:** A CVE like CVE-2023-38408 may appear in both port 22/tcp and port 2222/tcp across different hosts. The CVE note needs to list all of them.
**How to avoid:** Use two-pass generation (Pattern 1 above). First pass builds `HashMap<cve_id, CveAccumulator>` collecting all affected service wikilinks. Second pass writes all note files.
**Warning signs:** Single-loop vault generation function that tries to write CVE notes inside the host/port loop.

### Pitfall 6: Obsidian Tag Syntax
**What goes wrong:** Tags in YAML frontmatter must be lowercase, hyphen-delimited, no spaces. `#Critical` or `#CRITICAL` may not match graph color group queries like `tag:#critical`.
**Why it happens:** Obsidian's tag search is case-insensitive for display but case-sensitive in color group queries depending on version.
**How to avoid:** Always emit severity tags as lowercase: `critical`, `high`, `medium`, `low`. Format in frontmatter as a YAML list:
```yaml
tags:
  - host
  - critical
```
**Warning signs:** Using `Severity::label()` which returns `"Crit"`, `"High"` etc. — these are display labels for the CLI, not Obsidian tag names. Create a separate `Severity::tag()` method returning `"critical"`, `"high"`, `"medium"`, `"low"`.

---

## Code Examples

### Frontmatter Struct and Serialization
```rust
// Source: docs.rs/serde_yml/0.0.12
use serde::Serialize;

#[derive(Serialize)]
struct HostFrontmatter {
    ip: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hostnames: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    highest_severity: String,
    tags: Vec<String>,
    scan_label: String,
}

fn render_note(frontmatter: &impl serde::Serialize, body: &str) -> String {
    let yaml = serde_yml::to_string(frontmatter)
        .expect("serde_yml serialization is infallible for these types");
    format!("---\n{}---\n\n{}", yaml, body)
}
```

### Directory and File Creation
```rust
use std::fs;
use std::path::Path;

fn write_note(vault_root: &Path, relative_path: &str, content: &str) -> std::io::Result<()> {
    let full_path = vault_root.join(relative_path);
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&full_path, content)
}
```

### Severity Tag (not label)
```rust
// Add to src/models.rs Severity impl
impl Severity {
    /// Lowercase tag string for Obsidian frontmatter tags
    pub fn obsidian_tag(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::None => "none",
        }
    }
}
```

### Highest Severity for a Port Slice
```rust
fn highest_severity(vulns: &[Vulnerability]) -> Severity {
    vulns.iter()
        .filter_map(|v| v.cvss.as_ref())
        .map(|c| &c.severity)
        .max_by_key(|s| match s {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::None => 0,
        })
        .cloned()
        .unwrap_or(Severity::None)
}
```

### graph.json Generation
```rust
// Pre-computed RGB integers for D-18 colors
// Formula: R*65536 + G*256 + B
const COLOR_CRITICAL: u32 = 0xff4444;  // 16736324
const COLOR_HIGH: u32     = 0xff8800;  // 16746496
const COLOR_MEDIUM: u32   = 0xffcc00;  // 16763904
const COLOR_LOW: u32      = 0x44bb44;  // 4505412
const COLOR_HOST: u32     = 0x4488ff;  // 4491007
const COLOR_CVE: u32      = 0xaa44ff;  // 11157759
const COLOR_TECH: u32     = 0x44cccc;  // 4441292

fn generate_graph_json() -> String {
    // Serialize as JSON; colorGroups query uses "tag:#tagname" syntax
    // rgb field is a decimal integer
    serde_json::to_string_pretty(&serde_json::json!({
        "colorGroups": [
            { "query": "tag:#critical",   "color": { "a": 1, "rgb": COLOR_CRITICAL } },
            { "query": "tag:#high",       "color": { "a": 1, "rgb": COLOR_HIGH } },
            { "query": "tag:#medium",     "color": { "a": 1, "rgb": COLOR_MEDIUM } },
            { "query": "tag:#low",        "color": { "a": 1, "rgb": COLOR_LOW } },
            { "query": "tag:#host",       "color": { "a": 1, "rgb": COLOR_HOST } },
            { "query": "tag:#cve",        "color": { "a": 1, "rgb": COLOR_CVE } },
            { "query": "tag:#technology", "color": { "a": 1, "rgb": COLOR_TECH } }
        ],
        "showTags": true,
        "hideUnresolved": false,
        "showArrow": false,
        "nodeSizeMultiplier": 1,
        "lineSizeMultiplier": 1,
        "linkDistance": 250
    })).expect("json serialization infallible")
}
```

### CVE Description Truncation
```rust
const MAX_DESC_LEN: usize = 120;

fn truncate_description(desc: &str) -> String {
    if desc.len() <= MAX_DESC_LEN {
        desc.to_string()
    } else {
        // Truncate at last word boundary before limit
        let truncated = &desc[..MAX_DESC_LEN];
        match truncated.rfind(' ') {
            Some(pos) => format!("{}...", &truncated[..pos]),
            None => format!("{}...", truncated),
        }
    }
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| serde_yaml 0.9.x | serde_yml 0.0.12 | serde_yaml deprecated 2024 | Must use serde_yml; identical API |
| CSS-only graph coloring | graph.json colorGroups + CSS | Obsidian graph view design | CSS alone cannot color note nodes by tag |

**Deprecated/outdated:**
- `serde_yaml`: Archived March 2024, marked `+deprecated` on crates.io. Use `serde_yml` instead (identical API).

---

## Open Questions

1. **Should ScanResult be extended with scan metadata fields?**
   - What we know: `NmapRun.args` and `NmapRun.start` are parsed in xml.rs but not forwarded to `ScanResult`
   - What's unclear: Whether extending the model is preferable to deriving scan label from `ScanResult.source` + current date
   - Recommendation: Use the fallback path (D-03 explicitly supports it): derive label from date + filename. Extend `ScanResult` only if Phase 4+ needs it. Simpler scope.

2. **Services with zero CVEs — generate note or skip?**
   - What we know: D-05 implies service notes are needed for the topology (hosts→services links). D-11 defines the template.
   - What's unclear: Whether a service note with empty vulnerability table is useful
   - Recommendation: Generate service notes even with zero CVEs. The note still documents the service (port/product/version) and links to technology notes. Empty vuln table is fine — show "No vulnerabilities found" row.

3. **Technology note product name normalization**
   - What we know: `Port.service.product` is `Option<String>`. Values like "Apache httpd" and "Apache Http Server" from different scans would create two separate tech notes.
   - What's unclear: Whether Phase 3 needs to normalize product names across sources
   - Recommendation: Use the raw `product` string as-is for Phase 3. Product name normalization is a Phase 4+ concern. Exact string match is sufficient for a single-scan run.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` + integration tests in `tests/` |
| Config file | `Cargo.toml` (edition 2024, no separate test config) |
| Quick run command | `cargo test vault` |
| Full suite command | `cargo test` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| OUT-01 | Wikilinks in generated files resolve correctly | integration | `cargo test vault::wikilinks` | No - Wave 0 |
| OUT-02 | Vault directory structure matches expected layout | integration | `cargo test vault::structure` | No - Wave 0 |
| OUT-03 | YAML frontmatter parses without error; special chars survive roundtrip | unit | `cargo test vault::frontmatter` | No - Wave 0 |
| OUT-04 | Severity tags appear in frontmatter as lowercase YAML list | unit | `cargo test vault::severity_tags` | No - Wave 0 |
| OUT-05 | Service note contains all required sections; Option fields handled gracefully | unit | `cargo test vault::service_note` | No - Wave 0 |
| OUT-06 | CVE notes have Affected Services list spanning multiple host/port references | unit | `cargo test vault::cve_affected_services` | No - Wave 0 |
| OUT-07 | graph.json contains 7 colorGroups with correct query strings and RGB values | unit | `cargo test vault::graph_config` | No - Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test vault`
- **Per wave merge:** `cargo test`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `src/vault/mod.rs` — module stub needed before any test can reference it
- [ ] `tests/vault_generate.rs` — integration test: generate vault from fixture scan, assert file tree
- [ ] Test fixture: `tests/fixtures/scan_multi_service_shared_cve.xml` — two services sharing one CVE (tests CVE deduplication in vault, OUT-06)

*(No new test framework installation needed — existing `cargo test` infrastructure is sufficient)*

---

## Sources

### Primary (HIGH confidence)
- `docs.rs/serde_yml/0.0.12` — serialization API verified: `to_string()`, `Serialize` derive
- `crates.io/api/v1/crates/serde_yml` — version 0.0.12 confirmed current as of 2026-03-23
- `github.com/WebBreacher/obsidian-osint-templates/.obsidian/graph.json` — graph.json schema confirmed: `colorGroups[].query` uses `"tag:#tagname"` format; `color.rgb` is decimal integer
- Project codebase (`src/models.rs`, `src/util/filename.rs`, `src/parser/xml.rs`) — existing types and constraints verified by direct reading

### Secondary (MEDIUM confidence)
- Obsidian forum (obsidian.md/forum) — CSS variable `--graph-node-tag` for global tag node color; confirmed limitation that per-tag note-node coloring requires color groups not CSS
- Obsidian forum thread `use-tags-for-coloring-in-graph-view/92842` — confirmed graph color groups use `tag:#tagname` query format
- WebSearch synthesis — `serde_yaml` deprecated March 2024; `serde_yml` is the maintained fork with identical API

### Tertiary (LOW confidence)
- RGB integer values for Obsidian graph.json — derived from hex colors in D-18 using standard formula; not directly verified against live Obsidian version. Mark as needing smoke-test when vault is first opened.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — serde_yml version verified via crates.io API; all other deps already in project
- Architecture: HIGH — based on direct codebase reading; two-pass pattern is straightforward requirement derivation
- Pitfalls: HIGH — YAML special chars and filename sanitization are project constraints already documented in STATE.md; graph.json mechanism verified via real example file
- Graph coloring mechanism: MEDIUM — CSS limitation verified via multiple Obsidian forum sources; graph.json schema verified via real example; exact Obsidian behavior with generated graph.json not smoke-tested

**Research date:** 2026-03-23
**Valid until:** 2026-06-23 (serde_yml version; Obsidian graph.json format is stable across versions)

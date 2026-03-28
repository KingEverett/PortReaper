---
phase: quick
plan: 260328-gih
type: execute
wave: 1
depends_on: []
files_modified:
  - src/vault/mod.rs
  - src/vault/templates.rs
autonomous: true
requirements: [GIH-01]
must_haves:
  truths:
    - "Host notes contain CVE wikilinks for every CVE found on that host"
    - "CVE notes contain an Affected Hosts section with host wikilinks"
    - "All existing tests pass with updated signatures"
  artifacts:
    - path: "src/vault/templates.rs"
      provides: "CVE wikilinks in host body, affected_hosts in CVE body"
      contains: "## CVEs"
    - path: "src/vault/mod.rs"
      provides: "affected_hosts collection in CveAccumulator, passed to render_cve_body"
      contains: "affected_hosts"
  key_links:
    - from: "src/vault/mod.rs"
      to: "src/vault/templates.rs"
      via: "render_cve_body call with affected_hosts parameter"
      pattern: "render_cve_body.*affected_hosts"
---

<objective>
Increase IP address node size in Obsidian graph by adding bidirectional CVE wikilinks between host notes and CVE notes.

Purpose: In Obsidian's graph view, node size scales with connection count. Host nodes currently lack direct CVE links, making them appear small. Adding host<->CVE wikilinks increases host connection density.
Output: Modified templates.rs and mod.rs with new wikilink sections and updated tests.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@src/vault/templates.rs
@src/vault/mod.rs
</context>

<interfaces>
<!-- Key functions and types the executor needs -->

From src/vault/templates.rs:
```rust
pub fn cve_wikilink(cve_id: &str) -> String;
pub fn host_wikilink(ip: &str) -> String;
pub fn render_host_body(host: &Host, _scan_label: &str) -> String;
pub fn render_cve_body(cve_id, score, severity, cvss_version, sources, description, affected_services) -> String;
```

From src/vault/mod.rs:
```rust
struct CveAccumulator {
    cve_id: String,
    score: Option<f32>,
    severity: Severity,
    cvss_version: Option<String>,
    sources: Vec<String>,
    description: Option<String>,
    affected_services: Vec<String>,
}
```
</interfaces>

<tasks>

<task type="auto">
  <name>Task 1: Add CVE wikilinks to host body and affected hosts to CVE notes</name>
  <files>src/vault/templates.rs, src/vault/mod.rs</files>
  <action>
**templates.rs — render_host_body():**
After the Vulnerability Summary counts (after the `format!("- Critical: {}..."` line, before the `## Notes` section), add a new section:

```
## CVEs

- [[CVE-2021-41773]]
- [[CVE-2021-42013]]
```

Implementation: Within the existing `for port in &host.ports` loop that counts severities (lines 87-99), also collect unique CVE IDs into a `BTreeSet<String>` (use BTreeSet for deterministic ordering). After the severity counts output, if the set is non-empty, write `\n## CVEs\n\n` followed by one `- {cve_wikilink}` per CVE ID. Use the existing `cve_wikilink()` helper.

**mod.rs — CveAccumulator struct:**
Add field `affected_hosts: Vec<String>` to the `CveAccumulator` struct (line 48-56). Initialize as empty `vec![]` in the `or_insert_with` closure (line 136-148).

**mod.rs — Pass 1 loop:**
After the existing affected_services dedup block (lines 172-175), add analogous host tracking:
```rust
let host_wl = templates::host_wikilink(&host.ip);
if !acc.affected_hosts.contains(&host_wl) {
    acc.affected_hosts.push(host_wl);
}
```

**templates.rs — render_cve_body():**
Add `affected_hosts: &[String]` parameter after `affected_services`. After the existing "## Affected Services" section, add:
```
## Affected Hosts

- [[192.168.1.1]]
- [[10.0.0.1]]
```
Render each host wikilink as a bullet. If empty, skip the section (services are always present if a CVE exists, but hosts should be too — still guard it).

**mod.rs — Pass 2 render_cve_body call (line 352-359):**
Add `&acc.affected_hosts` as the new last argument to `render_cve_body()`.
  </action>
  <verify>
    <automated>cd /home/prometheus/PortReaper && cargo build 2>&1 | tail -5</automated>
  </verify>
  <done>Code compiles. render_host_body produces CVE wikilinks section. render_cve_body accepts and renders affected_hosts. CveAccumulator collects host IPs during pass 1.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Update and add tests</name>
  <files>src/vault/templates.rs</files>
  <behavior>
    - Test: render_cve_body with affected_hosts produces "## Affected Hosts" section with host wikilinks
    - Test: render_host_body with vulns produces "## CVEs" section with CVE wikilinks
    - Test: render_host_body with no vulns does NOT produce "## CVEs" section
    - Test: existing render_cve_body test updated to pass affected_hosts parameter
  </behavior>
  <action>
**Update existing test** `render_cve_body_includes_score_severity_description_affected_services_references` (line 683):
Add `&["[[192.168.1.1]]".to_string()]` as the last argument to `render_cve_body()` call. Add assertion: `assert!(body.contains("## Affected Hosts"))` and `assert!(body.contains("[[192.168.1.1]]"))` — but note host wikilink already appears in affected_services test expectations, so specifically check for the section heading.

**Add new test** `render_cve_body_affected_hosts_renders_host_wikilinks`:
Call `render_cve_body` with `affected_hosts: &["[[10.0.0.1]]".to_string(), "[[10.0.0.2]]".to_string()]`. Assert body contains `## Affected Hosts`, `[[10.0.0.1]]`, and `[[10.0.0.2]]`.

**Add new test** `render_host_body_includes_cve_wikilinks_section`:
Create a Host with two ports, each having a vulnerability (e.g., CVE-2021-41773 on port 80, CVE-2023-38408 on port 22). Call `render_host_body`. Assert body contains `## CVEs`, `[[CVE-2021-41773]]`, and `[[CVE-2023-38408]]`.

**Add new test** `render_host_body_no_vulns_omits_cves_section`:
Create a Host with ports but no vulnerabilities. Call `render_host_body`. Assert body does NOT contain `## CVEs`.
  </action>
  <verify>
    <automated>cd /home/prometheus/PortReaper && cargo test --lib vault::templates::tests -- --nocapture 2>&1 | tail -20</automated>
  </verify>
  <done>All template tests pass. New tests verify CVE wikilinks in host body (present and absent cases) and affected hosts in CVE body.</done>
</task>

</tasks>

<verification>
```bash
cd /home/prometheus/PortReaper && cargo test 2>&1 | tail -10
```
All tests pass including integration tests.
</verification>

<success_criteria>
- `cargo test` passes with zero failures
- Host notes contain `## CVEs` section with CVE wikilinks (when vulns exist)
- CVE notes contain `## Affected Hosts` section with host wikilinks
- Both link directions increase host node connection count in Obsidian graph
</success_criteria>

<output>
After completion, create `.planning/quick/260328-gih-make-ip-address-nodes-larger-in-obsidian/260328-gih-SUMMARY.md`
</output>

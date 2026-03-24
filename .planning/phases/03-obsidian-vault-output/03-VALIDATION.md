---
phase: 3
slug: obsidian-vault-output
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-23
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `#[test]` + integration tests in `tests/` |
| **Config file** | `Cargo.toml` (edition 2024, no separate test config) |
| **Quick run command** | `cargo test vault` |
| **Full suite command** | `cargo test` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test vault`
- **After every plan wave:** Run `cargo test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 03-01-01 | 01 | 0 | OUT-01 | integration | `cargo test vault::wikilinks` | ❌ W0 | ⬜ pending |
| 03-01-02 | 01 | 0 | OUT-02 | integration | `cargo test vault::structure` | ❌ W0 | ⬜ pending |
| 03-01-03 | 01 | 0 | OUT-03 | unit | `cargo test vault::frontmatter` | ❌ W0 | ⬜ pending |
| 03-01-04 | 01 | 0 | OUT-04 | unit | `cargo test vault::severity_tags` | ❌ W0 | ⬜ pending |
| 03-01-05 | 01 | 0 | OUT-05 | unit | `cargo test vault::service_note` | ❌ W0 | ⬜ pending |
| 03-01-06 | 01 | 0 | OUT-06 | unit | `cargo test vault::cve_affected_services` | ❌ W0 | ⬜ pending |
| 03-01-07 | 01 | 0 | OUT-07 | unit | `cargo test vault::graph_config` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `src/vault/mod.rs` — module stub needed before any test can reference it
- [ ] `tests/vault_generate.rs` — integration test: generate vault from fixture scan, assert file tree
- [ ] `tests/fixtures/scan_multi_service_shared_cve.xml` — two services sharing one CVE (tests CVE deduplication in vault, OUT-06)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Graph view shows hub-and-spoke topology | OUT-01 | Requires Obsidian GUI | Open vault in Obsidian, check graph view layout |
| CSS snippet colors nodes by severity | OUT-04 | Requires Obsidian GUI | Copy CSS to `.obsidian/snippets/`, enable, check graph |
| Wikilinks resolve in Obsidian | OUT-01 | Requires Obsidian GUI | Click wikilinks in notes, verify navigation |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

---
phase: 01
slug: foundation
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-21
---

# Phase 01 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `#[test]` + `cargo test` |
| **Config file** | Cargo.toml (workspace root) |
| **Quick run command** | `cargo test --lib` |
| **Full suite command** | `cargo test` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --lib`
- **After every plan wave:** Run `cargo test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 01-01-01 | 01 | 1 | INPUT-01 | unit | `cargo test xml_parsing` | ❌ W0 | ⬜ pending |
| 01-01-02 | 01 | 1 | INPUT-02 | unit | `cargo test text_parsing` | ❌ W0 | ⬜ pending |
| 01-01-03 | 01 | 1 | INPUT-03 | unit | `cargo test format_detection` | ❌ W0 | ⬜ pending |
| 01-01-04 | 01 | 1 | INPUT-04 | unit | `cargo test error_handling` | ❌ W0 | ⬜ pending |
| 01-02-01 | 02 | 1 | ARCH-01 | unit | `cargo test vuln_source` | ❌ W0 | ⬜ pending |
| 01-02-02 | 02 | 1 | ARCH-02 | unit | `cargo test error_taxonomy` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/fixtures/` — sample nmap XML and text output files for parsing tests
- [ ] `src/lib.rs` or module test stubs — for INPUT-01 through INPUT-04
- [ ] Cargo.toml dependencies — quick-xml, serde, clap, owo-colors, is-terminal, thiserror

*If none: "Existing infrastructure covers all phase requirements."*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Terminal color output | INPUT-01 | Requires visual TTY inspection | Run `portreaper scan.xml` in terminal, verify colored output |
| Piped input detection | INPUT-02 | Requires actual pipe | Run `cat scan.xml \| portreaper` and verify output |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

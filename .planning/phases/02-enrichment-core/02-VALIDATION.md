---
phase: 2
slug: enrichment-core
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-21
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust built-in) |
| **Config file** | Cargo.toml |
| **Quick run command** | `cargo test --lib` |
| **Full suite command** | `cargo test` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --lib`
- **After every plan wave:** Run `cargo test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 2-01-01 | 01 | 1 | VULN-05 | unit | `cargo test cpe` | ❌ W0 | ⬜ pending |
| 2-01-02 | 01 | 1 | VULN-01 | unit | `cargo test nvd` | ❌ W0 | ⬜ pending |
| 2-01-03 | 01 | 1 | VULN-02 | unit | `cargo test cveorg` | ❌ W0 | ⬜ pending |
| 2-02-01 | 02 | 1 | VULN-06 | unit | `cargo test enrichment` | ❌ W0 | ⬜ pending |
| 2-02-02 | 02 | 1 | VULN-06 | unit | `cargo test retry` | ❌ W0 | ⬜ pending |
| 2-03-01 | 03 | 2 | ARCH-04 | integration | `cargo test progress` | ❌ W0 | ⬜ pending |
| 2-03-02 | 03 | 2 | VULN-01 | integration | `cargo test tree` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/nvd_tests.rs` — stubs for NVD API response parsing (VULN-01)
- [ ] `tests/cveorg_tests.rs` — stubs for CVE.org response parsing (VULN-02)
- [ ] `tests/cpe_tests.rs` — CPE 2.2→2.3 conversion tests (VULN-05)
- [ ] `tests/enrichment_tests.rs` — deduplication, concurrency, retry logic (VULN-06)

*Existing cargo test infrastructure covers framework needs.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Progress output on stderr during large scan | ARCH-04 | Requires visual inspection of stderr interleaving | Run against 10+ port scan, verify `[N/M]` lines appear on stderr |
| Color-coded severity labels in terminal | VULN-01 | Terminal color rendering | Run in color-capable terminal, verify Critical=red, High=yellow |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

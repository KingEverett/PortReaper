---
phase: 5
slug: config-polish-and-incremental-updates
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-24
---

# Phase 5 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `#[test]` + `#[tokio::test]` |
| **Config file** | none — inline `#[cfg(test)]` modules |
| **Quick run command** | `cargo test` |
| **Full suite command** | `cargo test` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test`
- **After every plan wave:** Run `cargo test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 05-01-01 | 01 | 1 | ARCH-03 | unit | `cargo test config::tests::load_config_returns_defaults_when_file_absent` | ❌ W0 | ⬜ pending |
| 05-01-02 | 01 | 1 | ARCH-03 | unit | `cargo test config::tests::load_config_parses_all_fields` | ❌ W0 | ⬜ pending |
| 05-01-03 | 01 | 1 | ARCH-03 | unit | `cargo test config::tests::load_config_warns_on_parse_error` | ❌ W0 | ⬜ pending |
| 05-01-04 | 01 | 1 | ARCH-03 | unit | `cargo test config::tests::env_var_overrides_config_api_key` | ❌ W0 | ⬜ pending |
| 05-02-01 | 02 | 1 | OUT-08 | unit | `cargo test vault::merge::tests::extract_notes_tail_basic` | ❌ W0 | ⬜ pending |
| 05-02-02 | 02 | 1 | OUT-08 | unit | `cargo test vault::merge::tests::merge_write_note_preserves_notes` | ❌ W0 | ⬜ pending |
| 05-02-03 | 02 | 1 | OUT-08 | unit | `cargo test vault::merge::tests::merge_write_note_fresh_file` | ❌ W0 | ⬜ pending |
| 05-02-04 | 02 | 1 | OUT-08 | unit | `cargo test vault::merge::tests::stale_tag_applied_to_missing_port` | ❌ W0 | ⬜ pending |
| 05-02-05 | 02 | 1 | OUT-08 | unit | `cargo test vault::merge::tests::score_history_appended_on_change` | ❌ W0 | ⬜ pending |
| 05-02-06 | 02 | 1 | OUT-08 | unit | `cargo test vault::merge::tests::score_history_not_duplicated_on_same_score` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `src/config/mod.rs` with `#[cfg(test)]` block — stubs for ARCH-03 config tests
- [ ] `src/vault/merge.rs` with `#[cfg(test)]` block — stubs for OUT-08 merge tests
- [ ] No framework install needed — existing `#[test]` infrastructure sufficient

*Existing infrastructure covers framework requirements.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Config file hint printed on stderr | ARCH-03 (D-06) | Stderr output verification in integration context | Run with config file containing API key, check stderr for hint message |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

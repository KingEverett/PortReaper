---
phase: 4
slug: additional-sources-and-caching
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-24
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in (`cargo test`) |
| **Config file** | `Cargo.toml` (no separate test config) |
| **Quick run command** | `cargo test --lib 2>&1` |
| **Full suite command** | `cargo test 2>&1` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --lib 2>&1`
- **After every plan wave:** Run `cargo test 2>&1`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 04-01-01 | 01 | 1 | VULN-03 | unit | `cargo test --lib sources::osv 2>&1` | ❌ W0 | ⬜ pending |
| 04-01-02 | 01 | 1 | VULN-03 | unit | `cargo test --lib sources::osv::tests::batch_request_schema 2>&1` | ❌ W0 | ⬜ pending |
| 04-01-03 | 01 | 1 | VULN-03 | unit | `cargo test --lib sources::osv::tests::vuln_detail_parsing 2>&1` | ❌ W0 | ⬜ pending |
| 04-01-04 | 01 | 1 | VULN-03 | unit | `cargo test --lib sources::osv::tests::cve_alias_extraction 2>&1` | ❌ W0 | ⬜ pending |
| 04-01-05 | 01 | 1 | VULN-03 | unit | `cargo test --lib sources::osv::tests::empty_result_is_not_error 2>&1` | ❌ W0 | ⬜ pending |
| 04-02-01 | 02 | 1 | VULN-04 | unit | `cargo test --lib sources::searchsploit 2>&1` | ❌ W0 | ⬜ pending |
| 04-02-02 | 02 | 1 | VULN-04 | unit | `cargo test --lib sources::searchsploit::tests::parse_cve_refs 2>&1` | ❌ W0 | ⬜ pending |
| 04-02-03 | 02 | 1 | VULN-04 | unit | `cargo test --lib sources::searchsploit::tests::missing_binary_graceful 2>&1` | ❌ W0 | ⬜ pending |
| 04-03-01 | 03 | 1 | VULN-07 | unit | `cargo test --lib cache::tests::roundtrip 2>&1` | ❌ W0 | ⬜ pending |
| 04-03-02 | 03 | 1 | VULN-07 | unit | `cargo test --lib cache::tests::ttl_expiry 2>&1` | ❌ W0 | ⬜ pending |
| 04-03-03 | 03 | 1 | VULN-07 | unit | `cargo test --lib cache::tests::fresh_flag_bypasses_cache 2>&1` | ❌ W0 | ⬜ pending |
| 04-03-04 | 03 | 1 | VULN-07 | unit | `cargo test --lib cache::tests::miss_fetches_from_source 2>&1` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `src/sources/osv.rs` — covers VULN-03; needs fixture `tests/fixtures/osv_batch_response_nginx.json` and `tests/fixtures/osv_vuln_detail_nginx.json`
- [ ] `src/sources/searchsploit.rs` — covers VULN-04; unit tests use fixture `tests/fixtures/searchsploit_openssh74.json` (captured via `searchsploit -j "openssh 7.4"`)
- [ ] `src/cache/mod.rs` — covers VULN-07; tests use `tempfile::tempdir()` (add `tempfile` as dev-dependency)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| SearchSploit binary not on PATH shows stderr warning | VULN-04 | Requires PATH manipulation | Rename/remove searchsploit binary, run PortReaper, check stderr for warning |
| Re-run completes faster from cache | VULN-07 | Timing-dependent | Run scan twice, compare wall-clock time |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending

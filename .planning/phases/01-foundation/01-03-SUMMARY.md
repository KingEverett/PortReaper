---
phase: 01-foundation
plan: 03
subsystem: cli
tags: [clap, owo-colors, is-terminal, rust-cli, tree-renderer, integration-tests]

requires:
  - phase: 01-foundation-01
    provides: ScanResult/Host/Port/Service models defined in models.rs
  - phase: 01-foundation-02
    provides: parser::parse and parser::parse_and_merge API

provides:
  - Working portreaper binary: accepts nmap XML/text/greppable files and stdin, outputs Unicode tree
  - src/cli.rs: Clap argument struct with files, verbose, quiet, hidden enrich/vault flags
  - src/render/tree.rs: Unicode box-drawing tree renderer with conditional owo-colors support
  - src/main.rs: complete wiring of CLI args -> input reading -> parsing -> rendering -> exit codes
  - tests/cli.rs: 12 integration tests validating all CLI behaviors end-to-end

affects:
  - phase-02-enrichment (tree output layer will be extended to show vuln counts per service)
  - phase-03-vault (--vault flag defined but hidden; main.rs wiring point already in place)

tech-stack:
  added:
    - owo-colors 4.3.0 with supports-colors feature (conditional terminal color)
    - clap 4.6.0 with derive feature (argument parsing)
    - is-terminal 0.4.17 (TTY detection for color auto-disable and stdin hang prevention)
  patterns:
    - ExitCode return from main() -- never process::exit() in library code
    - TTY detection at startup: stdout.is_terminal() drives use_color bool passed through render layer
    - if_supports_color(Stream::Stdout, ...) for color calls that respect NO_COLOR/FORCE_COLOR env vars
    - get_inputs() separates file reading from stdin detection -- stdin TTY check prevents hang
    - is_no_input_error() classifies error message strings to pick exit code 2 vs 1

key-files:
  created:
    - src/cli.rs
    - src/render/tree.rs
    - tests/cli.rs
  modified:
    - src/main.rs
    - src/render/mod.rs
    - Cargo.toml

key-decisions:
  - "owo-colors supports-colors feature required for if_supports_color/Stream API -- not enabled by default"
  - "render/tree.rs uses portreaper:: (lib crate) not crate:: for model imports -- binary crate cannot use crate:: for lib types"
  - "Host colors use bright_green instead of bold().green() -- chaining color modifiers creates temporary lifetime errors with if_supports_color"
  - "Exit code classification done by error message string inspection in is_no_input_error() -- simple and correct given anyhow error erasure"

patterns-established:
  - "Pattern: render functions take RenderOptions struct (verbose, quiet, use_color) -- clean separation of display concerns"
  - "Pattern: portreaper:: prefix for lib types in binary crate modules -- avoids crate:: ambiguity"
  - "Pattern: integration tests use env!(CARGO_BIN_EXE_portreaper) -- portable binary path in test code"

requirements-completed: [INPUT-01, INPUT-02, INPUT-03, INPUT-04]

duration: 4min
completed: 2026-03-21
---

# Phase 01 Plan 03: CLI, Tree Renderer, and Integration Tests Summary

**clap CLI with Unicode tree renderer and 12 integration tests -- portreaper binary fully functional end-to-end from nmap XML/text/greppable to colored terminal tree output**

## Performance

- **Duration:** ~4 min
- **Started:** 2026-03-21T20:01:45Z
- **Completed:** 2026-03-21T20:05:56Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- Complete portreaper binary: `portreaper scan.xml` prints Unicode tree with hosts, ports, services, versions
- Conditional color: auto-disabled when stdout is piped (stdout.is_terminal()); respects NO_COLOR/FORCE_COLOR via owo-colors
- Exit codes 0/1/2 per spec: success / parse error / no input or file not found with contextual hints
- 12 integration tests covering all CLI behaviors pass: tree chars, ANSI suppression, -v/-q modes, multi-file merge, all 3 formats

## Task Commits

1. **Task 1: CLI arg parsing + tree renderer** - `c6aafb9` (feat)
2. **Task 2: Wire main.rs** - `6a60d78` (feat)
3. **Task 3: Integration tests** - `91971c1` (test)

## Files Created/Modified

- `src/cli.rs` - Clap derive struct: files (Vec<PathBuf>), -v/-q verbosity, hidden --enrich/--vault for future phases
- `src/render/mod.rs` - Expose tree submodule
- `src/render/tree.rs` - Unicode box-drawing renderer with RenderOptions; build_service_detail; conditional owo-colors
- `src/main.rs` - Full wiring: Cli::parse -> get_inputs -> parse_and_merge -> render_tree; ExitCode 0/1/2
- `Cargo.toml` - Added supports-colors feature to owo-colors
- `tests/cli.rs` - 12 integration tests using CARGO_BIN_EXE_portreaper

## Decisions Made

- `owo-colors` requires the `supports-colors` feature to enable `if_supports_color` and `Stream` API -- not enabled by default in the base crate. Added to Cargo.toml.
- Binary crate modules (`render/tree.rs`) must use `portreaper::` prefix to import types from the lib crate. Using `crate::` in a binary module refers to the binary crate, which doesn't re-export models.
- Chaining `.bold().green()` inside `if_supports_color` closure produces temporary lifetime error. Used `.bright_green()` as single-call equivalent.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added supports-colors feature to owo-colors**
- **Found during:** Task 1 (tree renderer implementation)
- **Issue:** `Stream` type and `if_supports_color` method are gated behind `supports-colors` feature in owo-colors; not enabled by default
- **Fix:** Updated Cargo.toml: `owo-colors = { version = "4.3.0", features = ["supports-colors"] }`
- **Files modified:** Cargo.toml
- **Verification:** cargo build passes; if_supports_color compiles
- **Committed in:** c6aafb9 (Task 1 commit)

**2. [Rule 1 - Bug] Fixed binary crate model import path**
- **Found during:** Task 1 (tree renderer uses ScanResult/Host/Port/Service)
- **Issue:** `use crate::models::...` in `render/tree.rs` (inside binary crate) fails -- models live in lib crate
- **Fix:** Changed to `use portreaper::models::...` to reference the lib crate by name
- **Files modified:** src/render/tree.rs
- **Verification:** cargo build passes
- **Committed in:** c6aafb9 (Task 1 commit)

**3. [Rule 1 - Bug] Fixed temporary lifetime error with chained color modifiers**
- **Found during:** Task 1 (render_host function)
- **Issue:** `.bold().green()` inside `if_supports_color` closure creates a temporary that outlives the closure
- **Fix:** Used `.bright_green()` as single-call equivalent (no chaining)
- **Files modified:** src/render/tree.rs
- **Verification:** cargo build passes; colors appear correctly
- **Committed in:** c6aafb9 (Task 1 commit)

---

**Total deviations:** 3 auto-fixed (1 blocking, 2 bugs)
**Impact on plan:** All fixes were necessary for compilation. No scope creep. owo-colors feature gate is a known crate quirk not documented in the research.

## Issues Encountered

- None beyond the three auto-fixed compilation issues above.

## Next Phase Readiness

- Phase 1 complete: all three plans done, portreaper binary fully functional
- Phase 2 (enrichment) can extend the render layer -- tree.rs already has RenderOptions for future verbose fields
- Phase 3 (vault) can wire --vault flag in main.rs run() function -- flag already defined and parsed
- All INPUT-01 through INPUT-04 requirements satisfied

---
*Phase: 01-foundation*
*Completed: 2026-03-21*

# Threat Model

This document states what the Orynval Labs shared core defends against, what it
explicitly does not, and — for each guarantee — the code and the test that hold
it up. It covers `internal/core`, `internal/walk`, `internal/redact`,
`internal/output`, and `internal/cli`. Individual tools (`cmd/*`) inherit this
model and add their own detector-specific assumptions.

## System and trust boundaries

A tool is a single, short-lived, local process. It takes:

- **a directory path** chosen by the user, and
- **command-line flags** chosen by the user.

It produces a **report** on a stream the user controls. There is no daemon, no
server, no network peer, and no persistent state.

The key insight: **the scanned tree is untrusted input.** A user routinely
points these tools at code they did not write — a dependency, a vendor drop, a
repository under review. File names, file contents, and symlinks in that tree
are all attacker-controllable. The user, the flags, and the destination stream
are trusted.

```
 trusted                         untrusted                    trusted
┌─────────┐   path + flags   ┌────────────────┐   report   ┌──────────┐
│  user   │ ───────────────► │ orynval tool   │ ─────────► │  stdout  │
└─────────┘                  │ (this process) │            │ /file    │
                             └───────┬────────┘            └──────────┘
                                     │ read-only
                                     ▼
                             ┌────────────────┐
                             │ scanned tree   │  ◄── attacker-controllable
                             │ (UNTRUSTED)    │      names, contents, symlinks
                             └────────────────┘
```

## Assets to protect

1. **The user's secrets** — anything secret-shaped in the scanned tree must not
   be re-emitted in cleartext in any output the user might share.
2. **Files outside the scan root** — the tool must read only within the
   directory it was given.
3. **Integrity of the host** — the tool must not write to the tree, execute
   anything it finds, reach the network, or emit telemetry.
4. **Integrity and trustworthiness of the report** — untrusted content must not
   be able to inject markup/script into the HTML or SVG output, forge findings,
   or make output non-deterministic.

## Threats, mitigations, and the tests that enforce them

### T1 — A secret in the tree leaks into shared output

- **Mitigation.** Two layers: rules call `redact.Mask` when building evidence,
  and every renderer runs each evidence snippet through `redact.Redact` again via
  `Report.normalized` before rendering. `Mask` keeps at most a 4-rune prefix and
  a fixed-width mask, so neither the value nor its length survives.
- **Enforced by.** `redact.TestMaskNeverRevealsFullSecret`,
  `redact.TestRedactProviderTokens`, `redact.TestRedactAssignmentPreservesSyntax`,
  `redact.TestRedactIdempotentNoLeak`, and — across *every* format —
  `output.TestAllFormatsRedactEvidence`, plus per-format
  `Test*RedactsEvidence` and `TestShareDoesNotLeakSecret`.

### T2 — A symlink or crafted path escapes the scan root

- **Mitigation.** `walk.Walker` never follows symlinks: `WalkDir` reports a
  symlink (even to a directory) as a non-directory entry, and the walker skips
  every symlink outright rather than resolving it. The root itself is
  canonicalized once at `New` so "inside root" reasoning is exact; nothing inside
  is ever resolved through a link.
- **Enforced by.** `walk.TestWalkNeverFollowsSymlinkOutsideRoot` (creates a
  symlink to a file *and* a directory outside the root and asserts neither is
  yielded or read).

### T3 — The tool writes to, or executes something from, the tree

- **Mitigation.** The scan pipeline only ever opens files for reading. No code
  path writes into the scanned tree or shells out. No shared-core file imports
  `os/exec` or any networking package.
- **Enforced by.** `core.TestNoNetworkOrExecImports` (parses every non-test
  source file in `internal/` and fails on a forbidden import). Read-only behavior
  is exercised throughout the `walk` and `cli` tests, which assert on yielded
  paths and never observe mutation.

### T4 — The tool reaches the network or emits telemetry

- **Mitigation.** Offline by construction: there is no network client anywhere
  in the core, and nothing records usage.
- **Enforced by.** `core.TestNoNetworkOrExecImports`. See also `PRIVACY.md`.

### T5 — Oversized or binary files exhaust time/memory

- **Mitigation.** The walker skips files above a size cap (default 1 MiB,
  configurable) and skips binary files (detected by a NUL byte in the first 8000
  bytes) before reading them. It also skips VCS internals and dependency
  directories (`.git`, `.hg`, `.svn`, `node_modules`, `vendor`).
- **Enforced by.** `walk.TestWalkSkipsLargeFiles`, `walk.TestWalkSkipsBinaryFiles`,
  `walk.TestWalkSkipsVCSAndDeps`, `walk.TestWalkSkipsNonRegularFiles`.

### T6 — Hostile content injects markup/script into a report

- **Mitigation.** The HTML report is rendered with `html/template`, which
  contextually escapes every dynamic field; it is fully self-contained (no
  scripts, no external assets). The SVG badge escapes the five XML entities in
  every user-derived string. The terminal renderer's no-color path emits no
  control sequences.
- **Enforced by.** `output.TestRenderHTMLEscapesInjection`,
  `output.TestRenderHTMLBasics` (asserts no `<script>`, `src=`, or remote URL),
  `output.TestBadgeXMLEscape`, `output.TestRenderTerminalNoColorStable`.

### T7 — Output is non-deterministic or leaks host information

- **Mitigation.** Findings are sorted with a total order
  (`core.SortFindings`); fingerprints are content hashes with no line numbers or
  timestamps; no renderer reads the clock or uses randomness; paths are
  root-relative.
- **Enforced by.** `output.TestAllFormatsDeterministic` (renders every format
  twice and requires byte-for-byte equality, including the color terminal path),
  `output.TestRenderJSONHasNoTimestampAndTrailingNewline`,
  `core.TestFingerprintDeterministicAndLineIndependent`,
  `core.TestSortFindingsDeterministic`.

### T8 — A forged or malformed share blob corrupts a re-render

- **Mitigation.** The share blob is tagged with a scheme and version; decoding
  validates the prefix, base64, DEFLATE stream, and JSON payload, returning a
  clear error at each stage rather than producing a bogus report.
- **Enforced by.** `output.TestDecodeShareRejectsGarbage`,
  `output.TestDecodeShareRejectsValidDeflateNonJSON`,
  `output.TestShareRoundTrip`.

### T9 — CI consumers cannot rely on exit codes

- **Mitigation.** Exit codes are a documented contract: `0` (ran, nothing at or
  above `--fail-on`), `1` (usage/path/I/O error), `3` (findings at or above
  `--fail-on`). `Run` never calls `os.Exit`, so the contract is testable.
- **Enforced by.** `cli.TestRunFailOnGates`, `cli.TestRunErrors`,
  `cli.TestRunVersion`, `cli.TestRunRenderError`.

## Explicit non-goals

- **Not a sandbox for the scanned code.** The tools never execute what they
  scan, so there is nothing to sandbox — but they also make no attempt to
  contain code you run yourself.
- **Not a network or runtime monitor.** Analysis is static and local-only.
- **Not a guarantee of detector completeness.** Missing a real issue (false
  negative) or flagging a non-issue (false positive) is a correctness bug, not a
  security boundary violation. Report those via the issue templates.
- **Not resistant to a malicious local user with your privileges.** The model
  assumes the person running the tool is the person it protects.

## Assurance

Every guarantee above is backed by a test, and the shared core is held at
**100.0% statement coverage** so that a change which removes a guarded path also
removes its proof and fails review. `gofmt`, `go vet`, `go test`,
`go test -race`, and the coverage gate run in CI (`.github/workflows/ci.yml`).

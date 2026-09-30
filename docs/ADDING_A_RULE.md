# Adding a rule

A detector in Orynval Labs is just an implementation of `core.Rule`. The shared
core handles walking the tree, caching file contents, deduplicating and sorting
findings, redacting secrets, rendering every output format, and the CLI. A new
rule is a rule set entry plus a name — nothing else.

This guide walks through writing one correctly and safely.

## The contract

A rule implements four methods (`internal/core/context.go`):

```go
type Rule interface {
    ID() string                        // stable machine id, e.g. "orynval.nhi.broad-permissions"
    Name() string                      // short human label
    Description() string               // what the rule looks for
    Evaluate(ctx *core.Context) []core.Finding
}
```

`Evaluate` is the whole rule. It **must** be:

- **Deterministic and order-independent.** Given the same tree it returns the
  same findings. Do not depend on map iteration order, wall-clock time, or
  randomness — the registry sorts the combined output with a total order, so you
  never sort yourself.
- **Read-only and offline.** Never write files, never execute anything you
  discover, never open the network. (`core.TestNoNetworkOrExecImports` enforces
  the no-network/no-exec rule at the package level.)
- **Secret-safe.** Any snippet you put into `Evidence` must already be masked
  with `redact.Mask`. Renderers re-redact as defense in depth, but mask at the
  source anyway.

## Reading the tree through the Context

`ctx` is your only handle to the tree. It gives you safe, cached access:

```go
func (r myRule) Evaluate(ctx *core.Context) []core.Finding {
    var findings []core.Finding
    _ = ctx.Walk(func(f core.File) error {
        lines, err := ctx.Lines(f)   // cached; one read per file across all rules
        if err != nil {
            return nil               // unreadable file: skip, don't abort the scan
        }
        for i, line := range lines {
            // ... inspect line; i is 0-based, so the file line number is i+1
        }
        return nil
    })
    return findings
}
```

- `ctx.Walk` yields only files that passed the walker's safety filters (no
  symlinks, no `.git`/`node_modules`/`vendor`, no binaries, within the size cap),
  in deterministic lexical order.
- `f.Rel` is the slash-separated path **relative to the scan root**. Use it in
  evidence, titles, and fingerprints. **Never use `f.Abs`** in output — it would
  leak the scanning machine's directory layout and break determinism.
- `ctx.Read` / `ctx.Lines` read each file at most once and share the result with
  every other rule. The returned bytes/slice are shared — do not mutate them.

## Building a Finding

A `core.Finding` (`internal/core/finding.go`) is a structured, honest result:

```go
snippet := line                              // the raw matched text
finding := core.Finding{
    RuleID:      r.ID(),
    Title:       "Hardcoded credential",
    What:        "A long-lived credential is committed to the tree.",
    Where:       fmt.Sprintf("%s:%d", f.Rel, i+1),
    Why:         "Anyone with repo read access gains the credential's privileges.",
    Confidence:  core.ConfidenceHigh,        // HIGH | MEDIUM | LOW
    Severity:    core.SeverityCritical,      // CRITICAL | HIGH | MEDIUM | LOW | INFO
    Remediation: "Move the value to a secret manager and rotate it.",
    SaferAlternative: "Reference the value from an environment variable at runtime.",
    Evidence: []core.Evidence{{
        File:    f.Rel,
        Line:    i + 1,
        Snippet: redact.Mask(snippet),        // MASKED — never the raw secret
        Kind:    core.KindObserved,           // OBSERVED | INFERRED | UNKNOWN
    }},
    Fingerprint: core.ComputeFingerprint(r.ID(), f.Rel, snippet),
}
```

Field notes:

- **Severity vs. Confidence** are independent. Severity is impact; confidence is
  how sure you are it is a true positive. Be honest about confidence.
- **Evidence `Kind`** keeps the tool trustworthy. Use `OBSERVED` for a fact read
  straight from a file, `INFERRED` for a deduction, and `UNKNOWN` for something
  you could not verify. Do not label a guess `OBSERVED`.
- **Fingerprint** is `ComputeFingerprint(ruleID, relPath, snippet)`. Pass the
  **raw** (unmasked) snippet here — the hash is one-way and reveals nothing, and
  using the raw value keeps two different secrets distinguishable. It deliberately
  excludes the line number, so the same logical finding keeps a stable identity
  as surrounding lines shift. Findings that share a fingerprint are merged (their
  evidence is unioned) by the registry.

## Registering and running

Rules are collected in a `core.Registry` and wired into a `cli.Tool`. A tool is
its identity plus its rule set:

```go
tool := cli.Tool{
    Name:           "nhi-ghost",
    Version:        version,
    Summary:        "Non-Human Identity risk, seen locally",
    InformationURI: "https://github.com/tomelias10/orynval-labs",
    Rules: []core.Rule{
        broadPermissionsRule{},
        staleCredentialRule{},
        // ...
    },
}
os.Exit(tool.Run(os.Args[1:], os.Stdout, os.Stderr))
```

`cli.Tool.Run` gives every tool the same flags (`--format`, `--fail-on`,
`--color`, `--ignore`, `--max-file-size`, `--list-rules`, `--version`), the same
walk → context → registry → render pipeline, and the same exit-code contract
(`0` clean, `1` error, `3` findings at or above `--fail-on`). Rule IDs must be
unique within a tool — `Registry.Register` panics on a duplicate or empty ID, so
collisions surface at startup, not in a scan.

## Testing your rule

Match the standard already set by the shared core: **new rules are expected to
reach 100.0% statement coverage** without weakening tests.

Write table-driven tests over small **synthetic** fixtures (never real secrets or
customer data — see `testdata/` conventions). At minimum assert:

1. **True positives** — the rule fires on the shape it targets, with the right
   severity, confidence, `Where`, and `Kind`.
2. **True negatives** — it stays quiet on benign look-alikes (guard against false
   positives explicitly).
3. **No secret leak** — no `Evidence.Snippet` contains the raw secret; it is
   masked.
4. **Determinism** — running twice yields identical findings; fingerprints are
   stable across line shifts.
5. **Edge cases** — empty files, unreadable files, multi-byte content.

You can drive a rule end-to-end through a `core.Context` backed by the real
walker (see `internal/cli/run_test.go` for the `markerRule` pattern) or a small
in-memory `FileWalker` (see `internal/core/context_test.go`'s `sliceWalker`).

## Checklist before you open a PR

- [ ] `ID()` is a stable, namespaced, unique identifier.
- [ ] `Evaluate` is deterministic, read-only, offline, and never mutates cached
      bytes.
- [ ] Every evidence snippet is passed through `redact.Mask`.
- [ ] Evidence `Kind` honestly reflects OBSERVED vs. INFERRED vs. UNKNOWN.
- [ ] Fingerprints use the raw snippet and exclude line numbers.
- [ ] Tests cover true positives, true negatives, determinism, and no-leak.
- [ ] `gofmt`, `go vet ./...`, `go test -race ./...`, and the coverage gate pass.

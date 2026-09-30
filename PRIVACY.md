# Privacy

Short version: **Orynval Labs tools collect nothing, send nothing, and store
nothing about you.** Everything runs on your machine.

This document describes the privacy behavior of the tools in this repository. It
is a statement about how the software behaves, enforced by the design and by
tests — not a promise we ask you to trust blind.

## What the tools do

Each tool reads a directory you point it at, analyzes it in memory, and writes a
report to standard output (or a file you choose). That is the whole data flow.

## What the tools do **not** do

- **No network.** No tool opens a network connection for any reason — no update
  checks, no license checks, no "phone home." The shared core does not even
  import a networking package; `internal/core/noegress_test.go`
  (`TestNoNetworkOrExecImports`) fails the build if that ever changes.
- **No telemetry or analytics.** Nothing about your usage, environment, or
  findings is recorded or transmitted. There is no analytics SDK, no event
  pipeline, and no opt-out to configure because there is nothing to opt out of.
- **No accounts, no keys, no licensing.** The tools require no sign-up and no
  credentials to run.
- **No writes to the scanned tree.** Scans are read-only. A tool never creates,
  modifies, or deletes files in the directory it is scanning, and never executes
  anything it discovers there.
- **No hidden state.** The tools keep no cache, history, or config in your home
  directory unless you explicitly redirect output there.

## Your data stays yours

- **Reports are local.** A report is written where you send it. "Sharing" a
  result means *you* handing someone the output (for example, the offline share
  blob), never the tool uploading anything.
- **The share blob contains no network reference.** It is your report,
  compressed and encoded, that a recipient decodes locally. It carries only what
  your report already contained.

## Secrets are protected in output

Even though the tools run locally, output can be pasted into tickets, CI logs,
or chat. To keep a scan from turning a private secret into a shared one:

- Secret-shaped values are **masked** when a finding's evidence is built.
- Every renderer **re-redacts** evidence as defense in depth, so a secret cannot
  leak even if a detector forgets to mask it.
- Masking never reveals more than a short prefix and never reveals the exact
  length of the original value.

## Determinism and host information

Output is deterministic and contains **no timestamps, no clock readings, no
randomness, and no absolute host paths** — findings reference paths relative to
the scan root. The same input produces byte-for-byte identical output on any
machine, which also means the output does not fingerprint the machine that
produced it.

## Changes to this document

Because there is no data collection to change, updates to this document will
almost always be clarifications. Any change that would alter the data-flow
guarantees above would be called out prominently in release notes.

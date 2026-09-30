# Orynval Labs

Local-first security tooling for the risks that block deals and audits but that
teams cannot easily see. Every tool runs **on your machine, read-only, offline,
and deterministic** — no agent to install, no data leaving your laptop, no
account required. Point a tool at a directory, get a report in seconds.

> Status: **pre-launch, not published externally.** The shared detector core is
> complete and green. Three product wedges have implementation specs and a
> working vertical slice each. See [Status](#status).

## Why these three

Security work that closes revenue and passes audits keeps snagging on the same
three gaps. Each Orynval tool is a sharp wedge into one of them.

### 1. `nhi-ghost` — Non-Human Identity risk, seen locally

Human logins have MFA, SSO, joiner/mover/leaver process. The **non-human**
identities — service accounts, API keys and token references, workload and
CI/CD identities — usually have none of that, vastly outnumber the humans, and
are where modern breaches actually start. `nhi-ghost` scans a repository or
config tree for these identities and ranks their risk: broad permissions,
ownership gaps, and stale candidates, with an **observed local blast radius** so
you see what a given credential can actually reach in *this* tree. It reports
only what it can observe and never invents usage it cannot see.

### 2. `mcp-drift` — AI agent / MCP permission drift (the Shadow-AI wedge)

Developers are wiring local AI agents and [MCP](https://modelcontextprotocol.io)
servers into their editors and shells faster than security can review them. Each
one is an unaudited program with filesystem reach, network egress, and access to
your environment and secrets. `mcp-drift` discovers local agent/MCP
configurations and flags the security-relevant facts: unknown or unapproved
connections, the tools/capabilities they expose, their filesystem and network
scope, secret/environment exposure, risky permission combinations, and **drift
from an approved baseline**. It is intentionally narrower than a network gateway
— static, read-only, local-only, and **never executes anything it discovers** —
so it deploys in minutes instead of a quarter.

### 3. `trust-proof` — the deal-blocking security questionnaire, grounded

Security questionnaires and evidence requests stall enterprise deals for weeks,
and the answers are error-prone to assemble by hand. `trust-proof` ingests a
questionnaire (CSV / XLSX / plain text) plus your **local, already-approved**
evidence (SOC 2 excerpts, policies, security and architecture docs, READMEs),
maps each question to explicit evidence, and drafts an answer **only when it is
grounded in a cited source**. Anything unsupported is marked `UNKNOWN` rather
than guessed. It produces a gap report and an exportable draft questionnaire.
**No hallucinated compliance claims, no auto-certification, and nothing is
uploaded anywhere** — grounding and citation are enforced, not aspirational.

## Shared guarantees

Every tool is built on one shared core (`internal/`) and inherits the same
posture:

- **Local-first & offline.** No network calls, no telemetry, no account.
- **Read-only.** Scans never modify the target tree and never execute
  discovered commands or config.
- **Deterministic.** No timestamps, clocks, or randomness. The same input
  produces byte-for-byte identical output on any machine — ideal for diffing in
  CI and for reproducible evidence.
- **Never leaks secrets.** A single redaction chokepoint masks secret material
  at evidence time and again at render time as defense in depth.
- **Honest by construction.** Findings separate what was `OBSERVED` from what
  was `INFERRED` from what is `UNKNOWN`. Nothing claims more than the evidence
  supports.

Shared output formats: **terminal**, **JSON**, and **SARIF 2.1.0** (plus a
self-contained HTML report, an SVG status badge, and an offline share blob).
`trust-proof` additionally exports **CSV**, **XLSX**, and **Markdown**.

## Repository layout

```
internal/core     shared vocabulary: findings, severity, rules, registry, scan context
internal/walk     safe, deterministic, read-only file walker
internal/redact   the "never print a secret" chokepoint (Mask + Redact)
internal/output   deterministic renderers: terminal, JSON, SARIF, HTML, badge, share
internal/cli      shared CLI runner for finding-based tools
cmd/nhi-ghost     Non-Human Identity risk scanner
cmd/mcp-drift     AI agent / MCP configuration drift scanner
cmd/trust-proof   security-questionnaire + evidence automation
docs/specs        exact implementation specs for each tool
```

## Build & test

Requires Go 1.27+.

```sh
make build      # build all three tools into ./bin
make test       # go test ./...
make race       # go test -race ./...
make check      # gofmt check + go vet + tests
make demo       # run all three tools against their synthetic fixtures
```

Every fixture under `testdata/` is **synthetic** — no real secrets, no real
customer data.

## What is intentionally *not* here

`pkg-safe` (a dependency/package-risk scanner) is parked in
[`IDEA_PARKING_LOT.md`](IDEA_PARKING_LOT.md). The three wedges above are the
focus; pkg-safe is not being built now.

## License

[Apache 2.0](LICENSE).

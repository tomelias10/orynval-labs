<div align="center">

<img src="docs/assets/hero.jpg" alt="Orynval Labs: security tools for AI agents. Free, local, offline." width="100%">

<h3>Your code was reviewed. Your agent config wasn't.</h3>

<img src="docs/assets/mcp-drift-demo.gif" alt="15-second demo: an MCP server URL is rewritten in .claude.json and mcp-drift reports baseline drift to attacker-proxy.example" width="520">

<sub>Synthetic repro of the config-rewrite technique <a href="https://www.securityweek.com/claude-code-oauth-tokens-can-be-stolen-through-stealthy-mcp-hijacking/">Mitiga reported</a> (May 2026). Real mcp-drift output, condensed.</sub>

[![CI](https://github.com/tomelias10/orynval-labs/actions/workflows/ci.yml/badge.svg)](https://github.com/tomelias10/orynval-labs/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tomelias10/orynval-labs?color=4d8dff)](https://github.com/tomelias10/orynval-labs/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.27.1-00ADD8?logo=go&logoColor=white)](go.mod)
[![Stars](https://img.shields.io/github/stars/tomelias10/orynval-labs?style=flat&color=ffb020)](https://github.com/tomelias10/orynval-labs/stargazers)

**[Quick start](#-quick-start)** · **[The tools](#-the-tools)** · **[Guarantees](#shared-guarantees)** · **[Website](https://orynval.com)** · **[Report a finding](#found-something-concerning)**

</div>

---

Your code goes through review. The config that decides what your AI editor runs usually doesn't.
`npx -y` with no version, tokens pasted into JSON, filesystem servers pointed at your whole home folder.
Orynval Labs is three small Go CLIs that read those files and tell you what they found.
**No account. No cloud. No telemetry. Nothing it discovers is ever executed.**

> **Public preview.** All three tools run today. Review findings before acting on them, and please report false positives or missed detections.

## ⚡ Quick start

```sh
go install github.com/tomelias10/orynval-labs/cmd/mcp-drift@v0.1.2
mcp-drift ~/your-project
```

That's it. Point it at any folder with `.cursor/mcp.json`, `.mcp.json`, `.vscode/mcp.json` or similar agent configs.
Prebuilt binaries for macOS, Linux and Windows are on the [Releases](https://github.com/tomelias10/orynval-labs/releases) page.

### Catch silent config changes

Approve what is configured today, then let mcp-drift tell you when anything changes, such as a server's URL quietly rewritten to point somewhere else:

```sh
mkdir -p .orynval
mcp-drift --print-baseline . > .orynval/mcp-baseline.json   # approve the current servers
mcp-drift .                                                  # later: any change shows up as baseline-drift
```

`--print-baseline` only prints. mcp-drift never writes into the tree it scans; you choose where the baseline lives and commit it like any other approved config.

Want to see it first, with no real data? Run the synthetic demo:

```sh
git clone https://github.com/tomelias10/orynval-labs.git && cd orynval-labs
go run ./cmd/mcp-drift internal/mcp/testdata
```

<div align="center">
<img src="docs/assets/mcp-drift-receipt.png" alt="mcp-drift scan of a synthetic config: 6 of 6 servers flagged, 2 high, 4 medium" width="480">
<br><sub>The demo fixture above: real mcp-drift output on a synthetic config. No real company data.</sub>
</div>

## 🧰 The tools

| | Tool | What it catches | Run it |
|---|---|---|---|
| 🔌 | **`mcp-drift`** | Unpinned `npx -y` installs and `@latest` tags, tokens inline in config, filesystem scope on `~` or `/`, `curl \| bash` launchers, remote endpoints, drift from an approved baseline | `mcp-drift <dir>` |
| 👻 | **`nhi-ghost`** | Service accounts, API keys and CI identities with broad permissions, no owner, or exposed credential material, plus their observed local blast radius | `nhi-ghost <dir>` |
| 📋 | **`trust-proof`** | Security questionnaire answers drafted only from your approved local evidence, with citations. Anything unsupported is marked `UNKNOWN` | `trust-proof --questions q.csv --evidence ./docs` |

Every tool outputs **terminal**, **JSON** and **SARIF 2.1.0**, so it drops straight into GitHub code scanning or any CI:

```sh
mcp-drift -f sarif . > mcp-drift.sarif   # upload to code scanning
mcp-drift --fail-on high .               # exit 3 fails the build
```

If a tool saved you time, a ⭐ is the simplest way to help other engineers find it.

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
questionnaire (CSV / Markdown / plain text) plus your **local, already-approved**
evidence (SOC 2 excerpts, policies, security and architecture docs, READMEs),
maps each question to explicit evidence, and drafts an answer **only when it is
grounded in a cited source**. Anything unsupported is marked `UNKNOWN` rather
than guessed. It produces a gap report and an exportable draft questionnaire.
**No hallucinated compliance claims, no auto-certification, and nothing is
uploaded anywhere** — grounding and citation are enforced, not aspirational.

## Found something concerning?

If one of the tools surfaces a finding you want a second set of eyes on, **Orynval can review the report with you.** Before sharing, remove any customer data or secrets that are not already redacted.

**Next step:** visit https://orynval.com and send the finding/report through the contact form, or email **tom@orynval.com** directly. Include which tool you ran (`nhi-ghost`, `mcp-drift`, or `trust-proof`) and the smallest reproducible context you can safely share.

This is also where to report a false positive, missed detection, or deployment question.

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
`trust-proof` additionally exports **CSV** and **Markdown**. XLSX is specified in the design docs but is not implemented in the current public preview.

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

## `trust-proof` demo (under 5 seconds)

One command answers a synthetic questionnaire from a synthetic, already-approved
evidence corpus — fully offline, no LLM, no network:

```sh
make demo-trust
# or directly:
go run ./cmd/trust-proof \
  --questions internal/trustproof/testdata/questions.csv \
  --evidence  internal/trustproof/testdata/evidence
```

Sample output:

```text
trust-proof — DRAFT (human review required; no claims auto-certified)

Questions: 5   Answered: 3   Gaps: 2   Coverage: 60%

Answered (grounded in cited evidence):
  [HIGH] Do you require multi-factor authentication for production access?
        ↳ access-control.md:3: "All production access requires single sign-on (SSO) with hardware multi-factor authentication. ..."
  [HIGH] How is customer data encrypted at rest?
        ↳ encryption.md:3: "Customer data is encrypted at rest using AES-256 and in transit using TLS 1.2 or higher. ..."
  [MEDIUM] How often are backups tested and restored?
        ↳ backup-policy.txt:6: "Backups are tested monthly by restoring them to an isolated environment ... The restore runbook token is ghp_**** and must never be shared."

Gaps (no grounded evidence — answer manually):
  [UNKNOWN] Are vendor risk assessments performed for all subprocessors?
  [UNKNOWN] Do you offer a public bug bounty program with monetary rewards?
```

What the demo shows:

- **Grounded answers only.** Each answer is *extractive* — quoted from a cited
  `file:line` — never generated. Matching is deterministic TF-IDF term overlap.
- **`UNKNOWN` over wrong.** The bug-bounty question has no supporting evidence,
  and the vendor-risk question matches two files identically (an ambiguous tie);
  both are reported as gaps rather than guessed.
- **Secrets stay masked.** A token planted in the backup evidence renders as
  `ghp_****` in the citation.

This vertical slice accepts questionnaires as **CSV, Markdown, or plain text**
(`--questions`) and exports the draft as **terminal, JSON, CSV, or Markdown**
(`--format`, with `--out` for file formats). `--min-confidence {high|medium|low}`
sets the bar to draft an answer and `--fail-on-gaps` exits `3` when any question
is `UNKNOWN`. (XLSX ingest/export, described in
[`docs/specs/trust-proof.md`](docs/specs/trust-proof.md), is specified but not
part of this slice.)
### Demo: `nhi-ghost` (offline, deterministic, well under 5 seconds)

```sh
make demo-nhi      # or: go run ./cmd/nhi-ghost internal/nhi/testdata
```

Scans the synthetic fixture tree and prints one ranked, identity-centric finding
per machine identity — with observed blast radius, the OBSERVED/INFERRED basis
for each risk factor, and concrete remediation. Secret values are never printed:

```
nhi-ghost 0.1.0
7 findings: 4 high, 1 medium, 1 low, 1 info

[HIGH] orynval.nhi.identity-risk — Committed secret material
  where:      app.env:3
  what:       Discovered api-key STRIPE_API_KEY at app.env:3. Risk factors: secret-exposed.
  why:        A live credential committed to the tree can be used by anyone who can read the repository.
  fix:        Revoke and rotate the credential, remove it from the working tree and git history, and load it from a secret manager at runtime.
  safer:      Reference secrets from a manager or CI secret store; never commit raw values.
  confidence: HIGH
  evidence:
    app.env:3  defined here: STRIPE_API_KEY = sk****
    app.env:3  raw secret material committed (value masked): sk_l****
    app.env:3  owner markers: owner=platform-team
  ...
```

The same scan renders to JSON, SARIF 2.1.0, HTML, an SVG badge, or an offline
share blob via `--format` — all byte-for-byte reproducible:

```sh
go run ./cmd/nhi-ghost --format sarif internal/nhi/testdata   # CI-ingestible
go run ./cmd/nhi-ghost --fail-on high internal/nhi/testdata   # exit 3 gates CI
```

What v0 discovers: GCP service-account key JSON, cloud IAM policy docs, GitHub
Actions workflow identities, and generic credential assignments / provider
token shapes. What it ranks: `secret-exposed`, `broad-permissions`,
`secret-referenced`, `pull_request_target`-with-secrets, `ownership-gap`
(INFERRED), and `stale-candidate` — the last raised **only** when trustworthy
local timestamp/last-used evidence is present, never from mere absence of a
reference, and never from the wall clock. See
[`docs/specs/nhi-ghost.md`](docs/specs/nhi-ghost.md).
## Demo: `mcp-drift` in under 5 seconds

`mcp-drift` audits local AI-agent / MCP server configs for risky scope and
baseline drift. Point it at the synthetic fixture tree — no setup, no home
directory, no network:

```sh
go run ./cmd/mcp-drift internal/mcp/testdata     # or: make demo-mcp
```

```text
mcp-drift 0.1.0
7 findings: 2 high, 2 medium, 3 info

[HIGH] orynval.mcp.config-audit — MCP server "filesystem" — 1 risk factor(s): broad-filesystem-scope
  where:      .mcp.json:3
  fix:        Scope the server to the narrowest project subdirectory it needs instead of the root or home directory.
  evidence:
    .mcp.json:3  broad-filesystem-scope: filesystem scope granted to: /

[HIGH] orynval.mcp.config-audit — MCP server "github" — 2 risk factor(s): secret-in-env, baseline-drift
  where:      .mcp.json:7
  evidence:
    .mcp.json:7  secret-in-env: inline secret handed to server via env: GITHUB_TOKEN=gh****
    .mcp.json:7  baseline-drift: server "github" config differs from its approved baseline signature (approved 000000000000, observed 45fab4632a3e)

... plus MEDIUM (unpinned installer, remote endpoint, unapproved) and INFO inventory entries
```

The scan is read-only and offline: it parses each config **as data** and never
runs a discovered `command`, resolves a discovered `url`, or validates a
credential. The inline `GITHUB_TOKEN` is reported as drift and risk but its
value is **masked in every format**.

The same scan renders through the shared core in any format:

```sh
go run ./cmd/mcp-drift -f terminal internal/mcp/testdata   # human report (above)
go run ./cmd/mcp-drift -f json     internal/mcp/testdata   # machine-readable findings
go run ./cmd/mcp-drift -f sarif    internal/mcp/testdata   # SARIF 2.1.0 for code scanning
go run ./cmd/mcp-drift -f html     internal/mcp/testdata > report.html   # self-contained report
```

Add `--fail-on high` to make the process exit `3` when any finding is at least
that severity (exit `0` when clean) — ready for a CI gate. Drop a
`.orynval/mcp-baseline.json` into the tree to turn on drift and unapproved-server
detection; without one, those factors are skipped so there is no false noise.

## What is intentionally *not* here

`pkg-safe` (a dependency/package-risk scanner) is parked in
[`IDEA_PARKING_LOT.md`](IDEA_PARKING_LOT.md). The three wedges above are the
focus; pkg-safe is not being built now.

## Contributing

Reproducible issues and focused pull requests are welcome — especially false positives, missed config shapes, safer remediations, and synthetic fixtures for additional agent/MCP ecosystems. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR.

For a suspected vulnerability in Orynval Labs itself, follow [SECURITY.md](SECURITY.md) instead of posting exploit details publicly.

## License

[Apache 2.0](LICENSE).

## Star history

<a href="https://star-history.com/#tomelias10/orynval-labs&Date">
  <img src="https://api.star-history.com/svg?repos=tomelias10/orynval-labs&type=Date" alt="Star history chart" width="600">
</a>

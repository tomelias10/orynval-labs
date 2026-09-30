# Idea parking lot

Ideas deliberately **not** being built right now. Parked here so the focus stays
on the three primary wedges (`nhi-ghost`, `mcp-drift`, `trust-proof`) without
losing the thinking behind alternatives.

---

## pkg-safe — dependency / package-risk scanner

**Status: parked. Not in the primary suite. Do not build now.**

The original Phase 0 plan included `pkg-safe`, a local-first scanner for risky
third-party packages (typosquats, install/postinstall scripts, suspicious
maintainer or version churn, lockfile/manifest drift, known-bad indicators
without a network call). It was replaced in the primary suite by `trust-proof`.

### Why parked

- **Crowded.** Dependency scanning is well-served by Dependabot, Renovate,
  Snyk, osv-scanner, Socket, and GitHub's native advisory database. Displacing
  incumbents needs a sharper edge than "local-first."
- **Weaker local-only story.** The highest-signal package intelligence
  (advisory feeds, maintainer reputation, registry metadata, malware verdicts)
  lives in remote datasets. A strictly offline scanner sees mostly the manifest
  and lockfile the developer already has, which limits differentiated value —
  exactly the opposite of the other three wedges, whose signal is inherently
  *local* and unseen by SaaS tools.
- **Overlaps `mcp-drift`'s supply-chain angle.** The most novel supply-chain
  risk today — untrusted local AI agents and MCP servers pulling capabilities
  into your environment — is owned by `mcp-drift`, which is a fresher wedge.

### If revived later

- Lean into what is genuinely local and offline: lockfile/manifest drift, the
  presence and content of install/postinstall scripts, vendored-code diffs
  against the registry tarball, and capability surface (network/fs/child-process
  calls) of a dependency's own source — none of which require a feed.
- Reuse the shared core unchanged: `internal/walk` for traversal,
  `internal/core` for findings/fingerprints, `internal/redact` and
  `internal/output` for safe deterministic reporting, `internal/cli` for the
  command. A `pkg-safe` slice would be a rule set plus a `cmd/pkg-safe`, exactly
  like the other finding-based tools.
- Differentiate from incumbents on determinism and evidence honesty
  (`OBSERVED` / `INFERRED` / `UNKNOWN`) rather than on feed coverage.

---

## Other parked notes

- **Cross-tool "trust bundle" export.** Once all three wedges are solid, a
  combined, signed, offline evidence bundle (NHI posture + agent/MCP inventory +
  answered questionnaire) could be a compelling artifact to hand a prospect's
  security team. Depends on all three shipping first.

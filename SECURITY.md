# Security Policy

Orynval Labs builds local-first security tooling. Holding ourselves to a high
standard is the product, so we take the security of this code seriously.

## Supported versions

The project is pre-launch. Until the first tagged release, only the `main`
branch is supported and fixes land there. After the first release, the latest
minor release line receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Report a vulnerability" under the repository's **Security** tab). If that is
unavailable to you, open a minimal issue that says only "requesting a private
security contact" with no details, and a maintainer will follow up.

When you report, please include:

- the affected tool or package (`internal/core`, `internal/walk`,
  `internal/redact`, `internal/output`, `internal/cli`, or a `cmd/` tool);
- the version or commit;
- a minimal, reproducible description — ideally a small synthetic input tree
  (never include real secrets or customer data); and
- the impact you observed.

### What to expect

- **Acknowledgement** within 3 business days.
- **An initial assessment** (severity and whether we can reproduce) within 10
  business days.
- **Coordinated disclosure.** We will agree on a disclosure timeline with you,
  credit you if you wish, and publish a GitHub Security Advisory when a fix is
  available.

## What counts as a vulnerability here

Because every tool is **read-only, offline, and deterministic**, the security
boundary is unusual. The following are in scope and treated as vulnerabilities:

- **Secret leakage.** Any input that causes a raw secret to appear in *any*
  rendered output (terminal, JSON, SARIF, HTML, badge, or share blob). The
  redaction chokepoint in `internal/redact` plus render-time re-redaction in
  `internal/output` is meant to make this impossible; a bypass is a bug.
- **Escaping the scan root.** Any input (symlink, crafted path, `..` sequence)
  that causes `internal/walk` to read a file outside the directory it was
  pointed at, or to follow a symlink out of the tree.
- **Writes or execution.** Any path that causes a tool to modify the target
  tree, execute a discovered command/config, open a network connection, or emit
  telemetry. The product guarantees none of these.
- **Output injection.** Markup or control sequences in scanned content that
  break out of the HTML report, the SVG badge, or a terminal in a way that could
  mislead or attack the viewer.
- **Non-determinism** that leaks host information (absolute paths, timestamps,
  usernames) into output.

The following are **out of scope**: the accuracy of a detector (a false positive
or false negative is a normal bug — see the issue templates), denial of service
from pointing a tool at a deliberately pathological tree beyond the documented
size caps, and issues in third-party dependencies that do not affect this code's
guarantees (report those upstream).

## Our commitments in the code

These are enforced by tests, not just documented (see `THREAT_MODEL.md`):

- Secrets are masked at evidence time **and** again at render time.
- The walker never follows symlinks and never leaves the root.
- No source file in the shared core imports a networking or process-execution
  package (`TestNoNetworkOrExecImports`).
- Output is byte-for-byte deterministic with no timestamps.

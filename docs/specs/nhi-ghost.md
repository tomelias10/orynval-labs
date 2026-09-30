# nhi-ghost — implementation spec

Local-first **Non-Human Identity (NHI) risk scanner**. Discovers the machine
identities living in a repository / config tree — service accounts, API keys and
token references, workload identities, CI/CD identities — and ranks their risk
from what it can *observe locally*, never inventing usage it cannot see.

## Positioning

Human identity is governed (SSO, MFA, JML). Non-human identity usually is not,
outnumbers humans by 10–50×, and is where breaches now begin. The differentiated
signal here is **local and static**: the credentials, permission grants, and
ownership markers a team already has in its own tree, correlated into an
identity-centric risk view that SaaS IAM tools do not see because the material
never leaves the laptop.

## Safety posture

Inherits the shared guarantees: read-only, offline, deterministic, secrets
always redacted. It never calls a cloud API to "resolve" an identity and never
executes anything. Every risk factor is tagged `OBSERVED`, `INFERRED`, or
`UNKNOWN`; staleness in particular is only ever a **candidate** (INFERRED),
because absence of a local reference is not proof of non-use.

## Model

The scanner is **identity-centric**, not line-centric. It runs in two passes:

1. **Discovery** — walk the tree and extract `Identity` records. Each has:
   - `Kind`: `service-account` | `api-key` | `ci-identity` | `workload-identity`
   - `Name`: a stable, non-secret label (e.g. a service-account email, a key's
     variable name, a workflow path). Secret *values* are never used as names.
   - `DefinedAt`: file + line evidence of where it was discovered.
   - `Permissions`: observed grant strings (IAM actions/resources, roles, GitHub
     Actions permission scopes) — may be empty.
   - `SecretExposed`: whether raw secret material (a private key, a live token)
     is present in the tree, not just a reference.
   - `OwnerMarkers`: observed owner/team/maintainer signals near the definition.

2. **Assessment** — one `Finding` per identity. Severity is the max over the
   identity's risk factors; evidence enumerates each factor and the observed
   **blast radius** (the set of resources/actions the identity can reach *as
   seen in this tree*).

### Risk factors

| Factor | Kind | Confidence | Contributes |
|---|---|---|---|
| `secret-exposed` | api-key, service-account | OBSERVED | raw credential is committed |
| `broad-permissions` | any with permissions | OBSERVED | wildcard/admin grant |
| `ownership-gap` | any | INFERRED | no owner/team marker found |
| `stale-candidate` | any | INFERRED | name/key unreferenced elsewhere |

### Severity mapping (v0)

- `secret-exposed` **and** `broad-permissions` → **CRITICAL**
- `secret-exposed` (live token / private key committed) → **HIGH**
- `broad-permissions` without exposed secret → **HIGH**
- `ci-identity` with `write-all` or `pull_request_target` + secret use → **HIGH**
- otherwise, identity discovered with a lesser factor → **MEDIUM** (has a
  factor) / **LOW** (ownership-gap or stale-candidate only) / **INFO** (clean
  discovery, informational inventory entry)

## Discovery sources (v0 slice)

1. **GCP service-account key JSON** — object with `"type": "service_account"`;
   name from `client_email`; `SecretExposed` when `private_key` is present.
2. **Cloud IAM policy JSON** — object(s) with a `Statement` array; extract
   `Action`/`Resource`; `broad-permissions` on `"*"`, `"iam:*"`,
   `"*:*"`, or `AdministratorAccess`; blast radius = the observed action×resource
   pairs.
3. **GitHub Actions workflow** (`.github/workflows/*.yml|*.yaml`) — a
   `ci-identity`; `broad-permissions` on `permissions: write-all`; flags
   `pull_request_target` combined with `${{ secrets.* }}` usage; secret
   references form the observed blast radius.
4. **Generic credential assignments** — `KEY=`, `*_TOKEN`, `*_SECRET`,
   `*_API_KEY`, and provider token shapes (AWS `AKIA…`, GitHub `ghp_…`, …) →
   `api-key`; `SecretExposed` true; value always redacted in evidence.

**Ownership signal:** an identity is `ownership-gap` when no owner/team marker
(`owner`, `team`, `maintainer`, `managed-by`, GCP labels, a nearby CODEOWNERS
entry) is observed within its defining file. **Staleness:** `stale-candidate`
when the identity's `Name` (or key variable) appears exactly once in the tree —
at its definition — and nowhere else.

### Deferred (documented, not in v0)

- Kubernetes `ServiceAccount` / `(Cluster)Role` / bindings.
- Terraform HCL parsing (v0 reads JSON policy docs only).
- Azure managed identity, cross-file IAM binding graphs, key age from git blame.

## CLI

Uses `internal/cli`. `nhi-ghost [flags] [path]` with the shared flags
(`--format`, `--fail-on`, `--color`, `--ignore`, `--max-file-size`,
`--list-rules`, `--version`). Output: terminal / JSON / SARIF / HTML / badge /
share.

## Rules (IDs)

The v0 slice ships one composite rule, `orynval.nhi.identity-risk`, that performs
discovery + assessment and emits one finding per identity. (Future factors may
graduate into their own rule IDs; the identity model keeps findings correlated
rather than fragmented.)

## Fixtures (synthetic)

Under `internal/nhi/testdata/`:
- `sa-key.json` — a fake GCP SA key (documentation-style private key body).
- `iam-admin.json` — an IAM policy with `"Action": "*"`, `"Resource": "*"`.
- `.github/workflows/deploy.yml` — `permissions: write-all`, `pull_request_target`,
  a `${{ secrets.DEPLOY_TOKEN }}` reference.
- `app.env` — a `DATABASE_URL`/`STRIPE_API_KEY=` style credential.
- `clean.txt` — no identities (asserts no false positives).

All values are obviously fake; no real credentials.

## Tests

- Each discovery source yields the expected identity kind and risk factors.
- Severity mapping (critical/high/low) is exercised.
- Secret values are redacted in every rendered format (defense-in-depth check).
- Determinism: two scans of the fixture tree produce identical JSON.
- No-false-positive check on `clean.txt`.

## One-command demo

`make demo-nhi` → `go run ./cmd/nhi-ghost internal/nhi/testdata`.

// Package nhi implements nhi-ghost's detector: a local-first, read-only,
// deterministic scanner for Non-Human Identity (NHI) risk. It discovers the
// machine identities living in a repository or config tree — service accounts,
// API keys and token references, workload identities, and CI/CD identities —
// and ranks each one's risk from what it can observe locally, never inventing
// usage it cannot see.
//
// Safety posture (inherited from the shared core and enforced here):
//
//   - Read-only. Discovery only reads files through the scan Context; it never
//     writes, never executes anything it finds, and never validates a
//     credential against a live service.
//   - Offline. No package in this tool imports net, net/http, or os/exec; the
//     shared no-egress test proves it.
//   - Deterministic. No clock, no randomness. Staleness is judged only from
//     timestamps already present in the tree, never from the wall clock, so the
//     same input yields byte-for-byte identical output on any machine.
//   - Secret-safe. Raw secret material is never stored in an identity's Name,
//     evidence, or fingerprint input; values are masked at evidence time and
//     re-redacted by the renderers as defense in depth.
//   - Honest. Every risk factor is tagged OBSERVED or INFERRED. Staleness is
//     only ever an INFERRED *candidate*, gated on trustworthy local
//     timestamp/last-used evidence — absence of a reference is never treated as
//     proof of non-use.
package nhi

import (
	"github.com/orynval/orynval-labs/internal/cli"
	"github.com/orynval/orynval-labs/internal/core"
)

// Version is the nhi-ghost release version, surfaced by --version and embedded
// in every report.
const Version = "0.1.0"

// informationURI is the tool's documentation anchor, embedded in SARIF/HTML.
const informationURI = "https://github.com/orynval/orynval-labs/blob/main/docs/specs/nhi-ghost.md"

// RuleID is the stable identifier of the one composite rule nhi-ghost ships in
// v0. Discovery and assessment are correlated into a single identity-centric
// rule so findings stay per-identity rather than fragmenting per line.
const RuleID = "orynval.nhi.identity-risk"

// Kind enumerates the machine-identity categories nhi-ghost discovers. Values
// are stable, lowercase, and safe to print (never derived from secret material).
type Kind string

const (
	KindServiceAccount   Kind = "service-account"
	KindAPIKey           Kind = "api-key"
	KindCIIdentity       Kind = "ci-identity"
	KindWorkloadIdentity Kind = "workload-identity"
)

// Factor names a single risk factor observed or inferred for an identity. Each
// factor carries its own evidence Kind (OBSERVED vs INFERRED) when rendered.
type Factor string

const (
	// FactorSecretExposed: raw credential material is committed in the tree.
	FactorSecretExposed Factor = "secret-exposed"
	// FactorBroadPermissions: a wildcard/admin-level grant is present.
	FactorBroadPermissions Factor = "broad-permissions"
	// FactorSecretReferenced: the identity references/uses a secret but its
	// value is not exposed in the tree (a token reference, not a leak).
	FactorSecretReferenced Factor = "secret-referenced"
	// FactorPullRequestTarget: a CI identity runs on pull_request_target and
	// uses secrets — a well-known privilege-escalation shape.
	FactorPullRequestTarget Factor = "pull-request-target-secrets"
	// FactorOwnershipGap: no owner/team marker was observed for the identity.
	FactorOwnershipGap Factor = "ownership-gap"
	// FactorStaleCandidate: trustworthy local last-used/disuse evidence suggests
	// the identity may be unused. Always INFERRED, always a candidate.
	FactorStaleCandidate Factor = "stale-candidate"
)

// Identity is a single machine identity discovered in the tree, plus the raw
// observations used to assess it. Secret *values* live only in secret (masked
// before ever leaving the tool); Name and every other exported string are
// safe to print.
type Identity struct {
	Kind        Kind
	Name        string // stable, non-secret label
	File        string // slash-separated path relative to the scan root
	Line        int    // 1-based line of the definition (best effort)
	DefLine     string // the raw defining line (redacted before it reaches output)
	Permissions []string
	BlastRadius []string // resources/actions/secret names reachable, as seen here

	secret           string // raw secret value; never printed, only masked
	SecretExposed    bool
	SecretReferences bool
	PRTargetSecrets  bool
	broad            bool // a wildcard/admin grant was observed

	OwnerObserved bool     // an owner/team marker was found
	OwnerMarkers  []string // the observed owner markers (for evidence)
	StaleReason   string   // non-empty ⇒ stale-candidate; describes the local evidence
}

// identityRule is the composite discovery+assessment rule. It holds no mutable
// state, so it is safe to reuse across scans.
type identityRule struct{}

func (identityRule) ID() string   { return RuleID }
func (identityRule) Name() string { return "Non-human identity risk" }
func (identityRule) Description() string {
	return "Discovers machine identities (service accounts, API keys and token " +
		"references, CI/CD and workload identities) and ranks each one's local, " +
		"observed risk: exposed secrets, broad permissions, ownership gaps, and " +
		"stale candidates backed by trustworthy local timestamp evidence."
}

// Evaluate discovers every identity in the tree and emits exactly one finding
// per identity, correlated and sorted deterministically by the shared core.
func (identityRule) Evaluate(ctx *core.Context) []core.Finding {
	identities := discover(ctx)
	out := make([]core.Finding, 0, len(identities))
	for _, id := range identities {
		out = append(out, assess(id))
	}
	return out
}

// Rules returns nhi-ghost's rule set (the single composite identity rule).
func Rules() []core.Rule { return []core.Rule{identityRule{}} }

// NewTool builds the nhi-ghost CLI tool on the shared runner, giving it the
// standard flags, scan pipeline, exit-code contract, and output formats.
func NewTool() cli.Tool {
	return cli.Tool{
		Name:           "nhi-ghost",
		Version:        Version,
		Summary:        "Local-first non-human identity (NHI) risk scanner.",
		InformationURI: informationURI,
		Rules:          Rules(),
	}
}

package nhi

import (
	"strings"

	"github.com/orynval/orynval-labs/internal/core"
	"github.com/orynval/orynval-labs/internal/redact"
)

// assess turns a discovered identity into exactly one finding: it enumerates
// the observed/inferred risk factors, maps them to a severity, and attaches
// redacted evidence plus the observed local blast radius. It is pure and
// deterministic.
func assess(id Identity) core.Finding {
	sev := severityFor(id)
	conf := core.ConfidenceHigh
	if sev == core.SeverityLow {
		conf = core.ConfidenceMedium // ownership/staleness are inferred signals
	}

	title, what, why, remediation, safer := narrate(id, sev)

	f := core.Finding{
		RuleID:           RuleID,
		Title:            title,
		What:             what,
		Where:            id.location(),
		Why:              why,
		Confidence:       conf,
		Severity:         sev,
		Remediation:      remediation,
		SaferAlternative: safer,
		Evidence:         evidenceFor(id),
		Fingerprint:      core.ComputeFingerprint(RuleID, id.File, string(id.Kind)+"\x00"+id.Name),
	}
	return f
}

// severityFor maps an identity's risk factors to a severity per the v0 spec.
func severityFor(id Identity) core.Severity {
	switch {
	case id.SecretExposed && id.broad:
		return core.SeverityCritical
	case id.SecretExposed:
		return core.SeverityHigh
	case id.broad:
		return core.SeverityHigh
	case id.PRTargetSecrets:
		return core.SeverityHigh
	case id.SecretReferences:
		return core.SeverityMedium
	case !id.OwnerObserved || id.StaleReason != "":
		return core.SeverityLow
	default:
		return core.SeverityInfo
	}
}

// location renders the identity's definition site as "file:line".
func (id Identity) location() string {
	return id.File + ":" + itoa(id.Line)
}

// narrate produces the human-facing strings for a finding.
func narrate(id Identity, sev core.Severity) (title, what, why, remediation, safer string) {
	subject := string(id.Kind) + " " + id.Name
	what = "Discovered " + subject + " at " + id.location() + ". " + factorSentence(id)

	switch sev {
	case core.SeverityCritical:
		title = "Exposed credential with broad permissions"
		why = "A committed secret combined with a wildcard/admin grant means anyone with repository access holds admin-level reach over " + blastPhrase(id) + "."
		remediation = "Revoke and rotate this credential immediately, then scope its replacement to the minimum permissions it needs. Purge the value from git history."
		safer = "Use a short-lived, workload-scoped credential (OIDC/workload identity federation) with least-privilege roles instead of a long-lived admin key."
	case core.SeverityHigh:
		switch {
		case id.SecretExposed:
			title = "Committed secret material"
			why = "A live credential committed to the tree can be used by anyone who can read the repository."
			remediation = "Revoke and rotate the credential, remove it from the working tree and git history, and load it from a secret manager at runtime."
			safer = "Reference secrets from a manager or CI secret store; never commit raw values."
		case id.broad:
			title = "Broad (wildcard/admin) permissions"
			why = "A wildcard or admin grant lets this identity reach " + blastPhrase(id) + " — far beyond least privilege."
			remediation = "Replace the wildcard grant with explicit, scoped actions and resources this identity actually uses."
			safer = "Grant only the specific actions on the specific resources observed in use."
		default: // PR-target secrets
			title = "CI identity: pull_request_target with secrets"
			why = "A workflow triggered by pull_request_target runs with repository secrets while executing code from forks — a classic privilege-escalation path."
			remediation = "Avoid pull_request_target with secret use; if unavoidable, gate on trusted actors and never check out or run untrusted PR code with secrets in scope."
			safer = "Use the pull_request trigger (no secrets) for untrusted code, and split privileged steps into a separate, gated workflow."
		}
	case core.SeverityMedium:
		title = "Secret reference without exposed value"
		why = "This identity uses secret material (" + blastPhrase(id) + ") but the value is not exposed in the tree; it is inventory worth governing, not a leak."
		remediation = "Confirm the referenced secret is owned, rotated on a schedule, and scoped to least privilege."
		safer = "Track each referenced secret in an owned inventory with a rotation policy."
	case core.SeverityLow:
		title = "Governance gap (ownership/staleness)"
		why = "No exposure or broad grant was observed, but " + govPhrase(id) + " — the identity may be unowned or unused."
		remediation = "Assign an owner/team for this identity and verify whether it is still needed; disable it if not."
		safer = "Record every machine identity in an owned inventory with a review cadence."
	default: // INFO
		title = "Machine identity inventory"
		why = "Informational: this identity was discovered with an owner marker and no observed risk factor."
		remediation = "No action required; keep the owner marker and review on your normal cadence."
	}
	return title, what, why, remediation, safer
}

// factorSentence summarizes the identity's factors in a single sentence.
func factorSentence(id Identity) string {
	factors := factorLabels(id)
	if len(factors) == 0 {
		return "No risk factors were observed."
	}
	return "Risk factors: " + strings.Join(factors, ", ") + "."
}

// factorLabels lists the active factor names in a stable order.
func factorLabels(id Identity) []string {
	var out []string
	if id.SecretExposed {
		out = append(out, string(FactorSecretExposed))
	}
	if id.broad {
		out = append(out, string(FactorBroadPermissions))
	}
	if id.PRTargetSecrets {
		out = append(out, string(FactorPullRequestTarget))
	}
	if id.SecretReferences && !id.SecretExposed {
		out = append(out, string(FactorSecretReferenced))
	}
	if !id.OwnerObserved {
		out = append(out, string(FactorOwnershipGap))
	}
	if id.StaleReason != "" {
		out = append(out, string(FactorStaleCandidate))
	}
	return out
}

// blastPhrase renders the observed blast radius as a phrase, or a generic note
// when none was observed locally.
func blastPhrase(id Identity) string {
	if len(id.BlastRadius) == 0 {
		return "resources not observable in this tree"
	}
	return strings.Join(id.BlastRadius, ", ")
}

// govPhrase describes the governance gap(s) present on a LOW finding.
func govPhrase(id Identity) string {
	var parts []string
	if !id.OwnerObserved {
		parts = append(parts, "no owner/team marker was found")
	}
	if id.StaleReason != "" {
		parts = append(parts, "it is a stale candidate ("+id.StaleReason+")")
	}
	return strings.Join(parts, " and ")
}

// evidenceFor builds the redacted evidence list for an identity. Every snippet
// is safe to print: secret values are masked here and re-redacted by renderers.
func evidenceFor(id Identity) []core.Evidence {
	var ev []core.Evidence
	add := func(snippet string, kind core.EvidenceKind) {
		ev = append(ev, core.Evidence{File: id.File, Line: id.Line, Snippet: snippet, Kind: kind})
	}

	add("defined here: "+id.DefLine, core.KindObserved)

	if id.SecretExposed {
		add("raw secret material committed (value masked): "+redact.Mask(id.secret), core.KindObserved)
	}
	if id.broad {
		add("broad permission grant: "+strings.Join(broadGrants(id), ", "), core.KindObserved)
	}
	if id.PRTargetSecrets {
		add("pull_request_target combined with secret use: "+strings.Join(id.BlastRadius, ", "), core.KindObserved)
	}
	if id.SecretReferences && !id.SecretExposed {
		add("references secrets (values not exposed): "+referenceList(id), core.KindObserved)
	}
	if len(id.BlastRadius) > 0 {
		add("observed local blast radius: "+strings.Join(id.BlastRadius, ", "), core.KindObserved)
	}
	if id.OwnerObserved {
		add("owner markers: "+strings.Join(id.OwnerMarkers, ", "), core.KindObserved)
	} else {
		add("no owner/team marker found in the defining file", core.KindInferred)
	}
	if id.StaleReason != "" {
		add("stale candidate: "+id.StaleReason, core.KindInferred)
	}
	return ev
}

// broadGrants returns the observed grants that qualify as broad, falling back to
// all permissions when none matched the action shape (e.g. workflow write-all).
func broadGrants(id Identity) []string {
	var broad []string
	for _, p := range id.Permissions {
		if isBroadAction(p) {
			broad = append(broad, p)
		}
	}
	if len(broad) == 0 {
		return id.Permissions
	}
	return broad
}

// referenceList returns the secret names referenced, or the identity name when
// no distinct reach was recorded.
func referenceList(id Identity) string {
	if len(id.BlastRadius) > 0 {
		return strings.Join(id.BlastRadius, ", ")
	}
	return id.Name
}

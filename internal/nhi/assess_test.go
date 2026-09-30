package nhi

import (
	"strings"
	"testing"

	"github.com/orynval/orynval-labs/internal/core"
)

func TestSeverityFor(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
		want core.Severity
	}{
		{"critical", Identity{SecretExposed: true, broad: true}, core.SeverityCritical},
		{"high-secret", Identity{SecretExposed: true}, core.SeverityHigh},
		{"high-broad", Identity{broad: true}, core.SeverityHigh},
		{"high-prtarget", Identity{PRTargetSecrets: true}, core.SeverityHigh},
		{"medium-ref", Identity{SecretReferences: true}, core.SeverityMedium},
		{"low-gap", Identity{OwnerObserved: false}, core.SeverityLow},
		{"low-stale", Identity{OwnerObserved: true, StaleReason: "x"}, core.SeverityLow},
		{"info", Identity{OwnerObserved: true}, core.SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := severityFor(tc.id); got != tc.want {
				t.Errorf("severityFor = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestLocation(t *testing.T) {
	id := Identity{File: "a/b.json", Line: 12}
	if id.location() != "a/b.json:12" {
		t.Errorf("location = %q", id.location())
	}
}

func TestAssessNarratesEachTier(t *testing.T) {
	cases := []struct {
		name      string
		id        Identity
		wantSev   core.Severity
		wantTitle string
		wantConf  core.Confidence
		noSafer   bool
	}{
		{
			"critical",
			Identity{Kind: KindAPIKey, Name: "K", File: "f", Line: 1, SecretExposed: true, broad: true, secret: "s", Permissions: []string{"*"}, BlastRadius: []string{"* → *"}, OwnerObserved: true},
			core.SeverityCritical, "Exposed credential with broad permissions", core.ConfidenceHigh, false,
		},
		{
			"high-secret",
			Identity{Kind: KindAPIKey, Name: "K", File: "f", Line: 1, SecretExposed: true, SecretReferences: true, secret: "s", OwnerObserved: true},
			core.SeverityHigh, "Committed secret material", core.ConfidenceHigh, false,
		},
		{
			"high-broad",
			Identity{Kind: KindServiceAccount, Name: "P", File: "f", Line: 1, broad: true, Permissions: []string{"s3:*"}, BlastRadius: []string{"s3:* → arn"}, OwnerObserved: true},
			core.SeverityHigh, "Broad (wildcard/admin) permissions", core.ConfidenceHigh, false,
		},
		{
			"high-prtarget",
			Identity{Kind: KindCIIdentity, Name: "W", File: "f", Line: 1, PRTargetSecrets: true, SecretReferences: true, BlastRadius: []string{"secrets.X"}, OwnerObserved: true},
			core.SeverityHigh, "CI identity: pull_request_target with secrets", core.ConfidenceHigh, false,
		},
		{
			"medium",
			Identity{Kind: KindAPIKey, Name: "R", File: "f", Line: 1, SecretReferences: true, OwnerObserved: true},
			core.SeverityMedium, "Secret reference without exposed value", core.ConfidenceHigh, false,
		},
		{
			"low",
			Identity{Kind: KindServiceAccount, Name: "L", File: "f", Line: 1, OwnerObserved: false, StaleReason: "explicitly disabled"},
			core.SeverityLow, "Governance gap (ownership/staleness)", core.ConfidenceMedium, false,
		},
		{
			"info",
			Identity{Kind: KindWorkloadIdentity, Name: "I", File: "f", Line: 1, OwnerObserved: true, OwnerMarkers: []string{"owner=team"}},
			core.SeverityInfo, "Machine identity inventory", core.ConfidenceHigh, true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := assess(tc.id)
			if f.Severity != tc.wantSev {
				t.Errorf("severity = %s, want %s", f.Severity, tc.wantSev)
			}
			if f.Title != tc.wantTitle {
				t.Errorf("title = %q, want %q", f.Title, tc.wantTitle)
			}
			if f.Confidence != tc.wantConf {
				t.Errorf("confidence = %s, want %s", f.Confidence, tc.wantConf)
			}
			if f.Remediation == "" {
				t.Error("remediation should never be empty")
			}
			if tc.noSafer && f.SaferAlternative != "" {
				t.Errorf("info finding should have no safer alternative, got %q", f.SaferAlternative)
			}
			if !tc.noSafer && f.SaferAlternative == "" {
				t.Error("expected a safer alternative")
			}
			if f.RuleID != RuleID || f.Fingerprint == "" {
				t.Errorf("rule/fingerprint not set: %+v", f)
			}
		})
	}
}

func TestBlastPhrase(t *testing.T) {
	if got := blastPhrase(Identity{}); got != "resources not observable in this tree" {
		t.Errorf("empty radius phrase = %q", got)
	}
	if got := blastPhrase(Identity{BlastRadius: []string{"a", "b"}}); got != "a, b" {
		t.Errorf("radius phrase = %q", got)
	}
}

func TestGovPhrase(t *testing.T) {
	if got := govPhrase(Identity{OwnerObserved: false}); got != "no owner/team marker was found" {
		t.Errorf("gap-only = %q", got)
	}
	if got := govPhrase(Identity{OwnerObserved: true, StaleReason: "disabled"}); got != "it is a stale candidate (disabled)" {
		t.Errorf("stale-only = %q", got)
	}
	both := govPhrase(Identity{OwnerObserved: false, StaleReason: "disabled"})
	if !strings.Contains(both, "no owner") || !strings.Contains(both, "stale candidate") || !strings.Contains(both, " and ") {
		t.Errorf("both = %q", both)
	}
}

func TestFactorLabels(t *testing.T) {
	// Exposed + references: secret-referenced must be suppressed (value IS exposed).
	labels := factorLabels(Identity{SecretExposed: true, SecretReferences: true, broad: true, PRTargetSecrets: true, OwnerObserved: false, StaleReason: "x"})
	joined := strings.Join(labels, ",")
	if strings.Contains(joined, string(FactorSecretReferenced)) {
		t.Errorf("secret-referenced should be suppressed when exposed: %v", labels)
	}
	for _, want := range []Factor{FactorSecretExposed, FactorBroadPermissions, FactorPullRequestTarget, FactorOwnershipGap, FactorStaleCandidate} {
		if !strings.Contains(joined, string(want)) {
			t.Errorf("missing factor %s in %v", want, labels)
		}
	}
	// A referenced-only identity yields the secret-referenced label.
	if got := factorLabels(Identity{SecretReferences: true, OwnerObserved: true}); strings.Join(got, ",") != string(FactorSecretReferenced) {
		t.Errorf("referenced-only labels = %v", got)
	}
	// A clean identity yields no factors.
	if len(factorLabels(Identity{OwnerObserved: true})) != 0 {
		t.Error("clean identity should have no factors")
	}
}

func TestEvidenceForCoversEveryBranch(t *testing.T) {
	id := Identity{
		Kind: KindAPIKey, Name: "K", File: "f", Line: 3, DefLine: "K = ***",
		SecretExposed: true, secret: "sekret", broad: true, PRTargetSecrets: true,
		SecretReferences: true, Permissions: []string{"*"}, BlastRadius: []string{"secrets.X"},
		OwnerObserved: true, OwnerMarkers: []string{"owner=team"}, StaleReason: "disabled",
	}
	ev := evidenceFor(id)
	joined := renderEvidence(ev)
	for _, want := range []string{
		"defined here", "raw secret material committed", "broad permission grant",
		"pull_request_target combined with secret use", "observed local blast radius",
		"owner markers", "stale candidate",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("evidence missing %q in:\n%s", want, joined)
		}
	}
	// secret-referenced evidence is suppressed while SecretExposed is set.
	if strings.Contains(joined, "references secrets (values not exposed)") {
		t.Error("referenced-evidence should be suppressed when exposed")
	}

	// A gap identity (no owner) produces the inferred ownership-gap evidence and
	// the references-without-exposure line.
	gap := Identity{Kind: KindAPIKey, Name: "R", File: "f", Line: 1, DefLine: "R = ${X}", SecretReferences: true, OwnerObserved: false}
	gapJoined := renderEvidence(evidenceFor(gap))
	if !strings.Contains(gapJoined, "no owner/team marker found") {
		t.Errorf("gap evidence missing: %s", gapJoined)
	}
	if !strings.Contains(gapJoined, "references secrets (values not exposed)") {
		t.Errorf("reference evidence missing: %s", gapJoined)
	}
}

func renderEvidence(ev []core.Evidence) string {
	var b strings.Builder
	for _, e := range ev {
		b.WriteString(e.Snippet)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestBroadGrants(t *testing.T) {
	// A mix: only the broad action is returned.
	got := broadGrants(Identity{Permissions: []string{"s3:GetObject", "*"}})
	if len(got) != 1 || got[0] != "*" {
		t.Errorf("broadGrants filter = %v", got)
	}
	// No action matches the broad shape (e.g. workflow write-all) → fall back to
	// the full permission list.
	fb := broadGrants(Identity{Permissions: []string{"write-all"}})
	if len(fb) != 1 || fb[0] != "write-all" {
		t.Errorf("broadGrants fallback = %v", fb)
	}
}

func TestReferenceList(t *testing.T) {
	if got := referenceList(Identity{BlastRadius: []string{"secrets.A"}}); got != "secrets.A" {
		t.Errorf("referenceList radius = %q", got)
	}
	if got := referenceList(Identity{Name: "TOKEN"}); got != "TOKEN" {
		t.Errorf("referenceList fallback = %q", got)
	}
}

func TestFactorSentence(t *testing.T) {
	if got := factorSentence(Identity{OwnerObserved: true}); got != "No risk factors were observed." {
		t.Errorf("clean sentence = %q", got)
	}
	if got := factorSentence(Identity{SecretExposed: true, OwnerObserved: true}); !strings.Contains(got, "secret-exposed") {
		t.Errorf("factor sentence = %q", got)
	}
}

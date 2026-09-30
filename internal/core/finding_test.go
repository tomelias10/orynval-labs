package core

import (
	"strings"
	"testing"
)

func TestFingerprintDeterministicAndLineIndependent(t *testing.T) {
	a := ComputeFingerprint("rule", "path/to/file.go", "  token   = SECRET  ")
	b := ComputeFingerprint("rule", "path/to/file.go", "token = SECRET")
	if a != b {
		t.Errorf("normalization should make these equal:\n%s\n%s", a, b)
	}
	// 64 hex chars = sha256.
	if len(a) != 64 {
		t.Errorf("fingerprint length = %d, want 64", len(a))
	}
}

func TestFingerprintCrossPlatformPath(t *testing.T) {
	unix := ComputeFingerprint("rule", "a/b/c.go", "x")
	win := ComputeFingerprint("rule", "a\\b\\c.go", "x")
	if unix != win {
		t.Error("fingerprint must be independent of path separator")
	}
}

func TestFingerprintDistinguishesInputs(t *testing.T) {
	base := ComputeFingerprint("rule", "f", "secret1")
	if base == ComputeFingerprint("rule2", "f", "secret1") {
		t.Error("different rule IDs must differ")
	}
	if base == ComputeFingerprint("rule", "g", "secret1") {
		t.Error("different paths must differ")
	}
	if base == ComputeFingerprint("rule", "f", "secret2") {
		t.Error("different snippets must differ")
	}
	// Field-boundary collision guard.
	if ComputeFingerprint("a", "b", "c") == ComputeFingerprint("ab", "", "c") {
		t.Error("NUL separators should prevent boundary collisions")
	}
}

func TestFingerprintDoesNotContainSecret(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	fp := ComputeFingerprint("rule", "f", secret)
	if strings.Contains(fp, secret) {
		t.Error("fingerprint must not contain the raw secret")
	}
}

func TestNormalizeSnippet(t *testing.T) {
	cases := map[string]string{
		"  a  b\tc\n":     "a b c",
		"single":          "single",
		"\n\n  x\ty\n\n":  "x y",
		"":                "",
		"   ":             "",
		"tabs\t\tbetween": "tabs between",
	}
	for in, want := range cases {
		if got := NormalizeSnippet(in); got != want {
			t.Errorf("NormalizeSnippet(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSortFindingsDeterministic(t *testing.T) {
	in := []Finding{
		{RuleID: "b", Severity: SeverityLow, Where: "z:1", Fingerprint: "1"},
		{RuleID: "a", Severity: SeverityCritical, Where: "a:1", Fingerprint: "2"},
		{RuleID: "a", Severity: SeverityCritical, Where: "a:1", Fingerprint: "1"},
		{RuleID: "c", Severity: SeverityHigh, Where: "m:1", Fingerprint: "3"},
	}
	SortFindings(in)
	// CRITICAL first (both rule a, where a:1) tiebroken by fingerprint, then HIGH, then LOW.
	if in[0].Severity != SeverityCritical || in[0].Fingerprint != "1" {
		t.Errorf("first should be CRITICAL fp=1, got %s fp=%s", in[0].Severity, in[0].Fingerprint)
	}
	if in[1].Fingerprint != "2" {
		t.Errorf("second should be CRITICAL fp=2, got fp=%s", in[1].Fingerprint)
	}
	if in[2].Severity != SeverityHigh {
		t.Errorf("third should be HIGH, got %s", in[2].Severity)
	}
	if in[3].Severity != SeverityLow {
		t.Errorf("fourth should be LOW, got %s", in[3].Severity)
	}

	// Sorting again must not change the result (idempotent).
	before := append([]Finding(nil), in...)
	SortFindings(in)
	for i := range in {
		if in[i].Fingerprint != before[i].Fingerprint {
			t.Fatal("sort is not idempotent")
		}
	}
}

func TestDedupeFindingsMergesEvidence(t *testing.T) {
	in := []Finding{
		{
			Fingerprint: "same",
			Evidence:    []Evidence{{File: "f", Line: 1, Snippet: "a"}},
		},
		{
			Fingerprint: "same",
			Evidence:    []Evidence{{File: "f", Line: 2, Snippet: "b"}, {File: "f", Line: 1, Snippet: "a"}},
		},
		{
			Fingerprint: "other",
			Evidence:    []Evidence{{File: "g", Line: 9, Snippet: "c"}},
		},
	}
	out := DedupeFindings(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 findings after dedupe, got %d", len(out))
	}
	if len(out[0].Evidence) != 2 {
		t.Fatalf("expected merged evidence of 2 (deduped), got %d", len(out[0].Evidence))
	}
	if out[0].Evidence[0].Line != 1 || out[0].Evidence[1].Line != 2 {
		t.Errorf("evidence order not preserved: %+v", out[0].Evidence)
	}
}

func TestCountBySeverityStableShape(t *testing.T) {
	counts := CountBySeverity([]Finding{
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
		{Severity: SeverityInfo},
	})
	if len(counts) != len(Severities) {
		t.Fatalf("counts should include every severity, got %d keys", len(counts))
	}
	if counts[SeverityHigh] != 2 || counts[SeverityInfo] != 1 || counts[SeverityCritical] != 0 {
		t.Errorf("unexpected counts: %+v", counts)
	}
}

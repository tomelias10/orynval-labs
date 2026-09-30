package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tomelias10/orynval-labs/internal/core"
)

// leakSecret is an obviously-fake, documentation-style AWS key id used across
// the output tests to prove that a rule which "forgot" to mask a secret still
// cannot leak it: every renderer re-redacts via Report.normalized.
const leakSecret = "AKIAIOSFODNN7EXAMPLE"

// sampleReport builds a small, representative report with two rules and two
// findings at different severities. One finding carries evidence whose snippet
// contains a raw, un-masked secret so tests can assert the render-time redaction
// safety net actually fires.
func sampleReport() Report {
	return Report{
		Tool: ToolInfo{Name: "orynval-test", Version: "9.9.9", InformationURI: "https://example.invalid"},
		Rules: []RuleDoc{
			{ID: "orynval.test.beta", Name: "Beta rule", Description: "Second rule, registered later."},
			{ID: "orynval.test.alpha", Name: "Alpha rule", Description: "First rule, describes a critical issue."},
		},
		Findings: []core.Finding{
			{
				RuleID:      "orynval.test.alpha",
				Title:       "Hardcoded credential",
				What:        "A long-lived credential is committed to the tree.",
				Where:       "config/prod.env:3",
				Why:         "Anyone with repo read access gains the credential's privileges.",
				Confidence:  core.ConfidenceHigh,
				Severity:    core.SeverityCritical,
				Remediation: "Move the value to a secret manager and rotate it.",
				Evidence: []core.Evidence{
					// Snippet deliberately un-masked: the renderer must redact it.
					{File: "config/prod.env", Line: 3, Snippet: "AWS_KEY=" + leakSecret, Kind: core.KindObserved},
				},
				Fingerprint: "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888",
			},
			{
				RuleID:      "orynval.test.beta",
				Title:       "Broad file permissions",
				What:        "A config file is world-readable.",
				Where:       "config/app.yaml:1",
				Why:         "Local users can read configuration meant to be private.",
				Confidence:  core.ConfidenceMedium,
				Severity:    core.SeverityLow,
				Remediation: "Tighten the file mode to 0600.",
				Evidence: []core.Evidence{
					{File: "config/app.yaml", Line: 1, Snippet: "mode: 0644", Kind: core.KindObserved},
				},
				Fingerprint: "1111aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb",
			},
		},
	}
}

// render is a small helper that renders a report to bytes in a given format.
func render(t *testing.T, f Format, r Report, opts Options) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, f, r, opts); err != nil {
		t.Fatalf("Render(%s): %v", f, err)
	}
	return b.Bytes()
}

func TestParseFormat(t *testing.T) {
	for _, f := range Formats {
		got, err := ParseFormat(strings.ToUpper(string(f)))
		if err != nil {
			t.Errorf("ParseFormat(%q) error: %v", f, err)
			continue
		}
		if got != f {
			t.Errorf("ParseFormat(%q) = %q, want %q", f, got, f)
		}
	}
	if _, err := ParseFormat("nonsense"); err == nil {
		t.Error("expected error for unknown format")
	}
	if _, err := ParseFormat("  JSON  "); err != nil {
		t.Errorf("ParseFormat should trim and lowercase: %v", err)
	}
}

// TestAllFormatsDeterministic renders every format twice and asserts the output
// is byte-for-byte identical, which is the whole promise of the package.
func TestAllFormatsDeterministic(t *testing.T) {
	r := sampleReport()
	for _, f := range Formats {
		opts := Options{}
		if f == FormatTerminal {
			opts.Color = true // exercise the color path too; it must still be stable
		}
		a := render(t, f, r, opts)
		b := render(t, f, r, opts)
		if !bytes.Equal(a, b) {
			t.Errorf("format %q is not deterministic:\n--- a ---\n%s\n--- b ---\n%s", f, a, b)
		}
	}
}

// TestAllFormatsRedactEvidence proves the render-time safety net: no renderer
// may emit the raw secret carried in a finding's evidence snippet.
func TestAllFormatsRedactEvidence(t *testing.T) {
	r := sampleReport()
	for _, f := range Formats {
		out := render(t, f, r, Options{})
		if bytes.Contains(out, []byte(leakSecret)) {
			t.Errorf("format %q leaked the raw secret:\n%s", f, out)
		}
	}
}

// TestNormalizedDoesNotMutateInput guards against a renderer mutating the
// caller's findings/evidence slices in place.
func TestNormalizedDoesNotMutateInput(t *testing.T) {
	r := sampleReport()
	origSnippet := r.Findings[0].Evidence[0].Snippet
	origFirstRuleID := r.Rules[0].ID
	_ = r.normalized()
	if r.Findings[0].Evidence[0].Snippet != origSnippet {
		t.Error("normalized mutated the caller's evidence snippet")
	}
	if r.Rules[0].ID != origFirstRuleID {
		t.Error("normalized mutated the caller's rules slice order")
	}
}

func TestDistinctRuleIDsUnionAndSorted(t *testing.T) {
	r := Report{
		Rules: []RuleDoc{{ID: "z.rule"}, {ID: "a.rule"}},
		Findings: []core.Finding{
			{RuleID: "m.rule"},
			{RuleID: "a.rule"}, // already in Rules
			{RuleID: ""},       // ignored
		},
	}
	got := r.distinctRuleIDs()
	want := []string{"a.rule", "m.rule", "z.rule"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("distinctRuleIDs = %v, want %v", got, want)
	}
}

func TestSummarizeCounts(t *testing.T) {
	s := summarize(sampleReport().Findings)
	if s.Total != 2 || s.Critical != 1 || s.Low != 1 || s.High != 0 {
		t.Errorf("unexpected summary: %+v", s)
	}
}

func TestRenderUnsupportedFormat(t *testing.T) {
	var b bytes.Buffer
	if err := Render(&b, Format("made-up"), sampleReport(), Options{}); err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestTerminalBannerNeverPollutesMachineFormats(t *testing.T) {
	r := sampleReport()
	for _, f := range []Format{FormatJSON, FormatSARIF, FormatHTML, FormatBadge, FormatShare} {
		out := render(t, f, r, Options{})
		if bytes.Contains(out, []byte("██████╗")) || bytes.Contains(out, []byte("L  A  B  S")) {
			t.Errorf("format %q unexpectedly contains terminal banner", f)
		}
	}
}

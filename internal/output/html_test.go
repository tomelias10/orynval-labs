package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tomelias10/orynval-labs/internal/core"
)

func TestRenderHTMLBasics(t *testing.T) {
	out := string(render(t, FormatHTML, sampleReport(), Options{}))
	for _, want := range []string{
		"<!DOCTYPE html>",
		"orynval-test report",
		"Hardcoded credential",
		"sev-critical",
		"config/prod.env",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	// Self-contained: no external asset references or scripts.
	for _, banned := range []string{"<script", "http://", "https://cdn", "src=", "<link"} {
		if strings.Contains(out, banned) {
			t.Errorf("HTML should be self-contained, found %q", banned)
		}
	}
}

func TestRenderHTMLRedactsEvidence(t *testing.T) {
	out := render(t, FormatHTML, sampleReport(), Options{})
	if bytes.Contains(out, []byte(leakSecret)) {
		t.Errorf("HTML leaked secret:\n%s", out)
	}
}

// TestRenderHTMLEscapesInjection proves html/template contextually escapes a
// hostile finding title so it cannot inject markup or script into the report.
func TestRenderHTMLEscapesInjection(t *testing.T) {
	r := Report{
		Tool: ToolInfo{Name: "x"},
		Findings: []core.Finding{{
			RuleID:      "r.evil",
			Severity:    core.SeverityHigh,
			Title:       `<script>alert(1)</script>`,
			Where:       `"><img src=x onerror=alert(1)>`,
			Fingerprint: "f",
			Evidence: []core.Evidence{
				{File: `a"><b>.txt`, Line: 1, Snippet: `<script>evil()</script>`},
			},
		}},
	}
	out := string(render(t, FormatHTML, r, Options{}))
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Errorf("unescaped script tag from title leaked into HTML:\n%s", out)
	}
	if strings.Contains(out, "<img src=x onerror=alert(1)>") {
		t.Errorf("unescaped img tag from Where leaked into HTML:\n%s", out)
	}
	if strings.Contains(out, "<script>evil()</script>") {
		t.Errorf("unescaped script tag from evidence leaked into HTML:\n%s", out)
	}
	// The escaped form must be present instead.
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected escaped script tag in HTML:\n%s", out)
	}
}

func TestRenderHTMLEmpty(t *testing.T) {
	out := string(render(t, FormatHTML, Report{Tool: ToolInfo{Name: "x"}}, Options{}))
	if !strings.Contains(out, "No findings.") {
		t.Errorf("empty HTML should say No findings:\n%s", out)
	}
}

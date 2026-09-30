package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/orynval/orynval-labs/internal/core"
)

func TestRenderJSONStructure(t *testing.T) {
	out := render(t, FormatJSON, sampleReport(), Options{})

	var doc struct {
		Tool struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"tool"`
		Summary  Summary        `json:"summary"`
		Findings []core.Finding `json:"findings"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if doc.Tool.Name != "orynval-test" || doc.Tool.Version != "9.9.9" {
		t.Errorf("tool block wrong: %+v", doc.Tool)
	}
	if doc.Summary.Total != 2 || doc.Summary.Critical != 1 || doc.Summary.Low != 1 {
		t.Errorf("summary wrong: %+v", doc.Summary)
	}
	if len(doc.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(doc.Findings))
	}
	// Findings must be sorted most-severe first.
	if doc.Findings[0].Severity != core.SeverityCritical {
		t.Errorf("first finding should be CRITICAL, got %s", doc.Findings[0].Severity)
	}
	// The evidence snippet must be redacted in the decoded structure.
	if got := doc.Findings[0].Evidence[0].Snippet; bytes.Contains([]byte(got), []byte(leakSecret)) {
		t.Errorf("evidence snippet not redacted: %q", got)
	}
}

func TestRenderJSONHasNoTimestampAndTrailingNewline(t *testing.T) {
	out := render(t, FormatJSON, sampleReport(), Options{})
	for _, banned := range []string{"time", "timestamp", "date", "generatedAt"} {
		if bytes.Contains(bytes.ToLower(out), []byte(banned)) {
			t.Errorf("JSON output contains a time-like key %q — breaks determinism:\n%s", banned, out)
		}
	}
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Error("JSON output should end with a trailing newline")
	}
}

func TestRenderJSONEmpty(t *testing.T) {
	out := render(t, FormatJSON, Report{Tool: ToolInfo{Name: "x"}}, Options{})
	var doc struct {
		Summary  Summary        `json:"summary"`
		Findings []core.Finding `json:"findings"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("empty report JSON invalid: %v", err)
	}
	if doc.Summary.Total != 0 || len(doc.Findings) != 0 {
		t.Errorf("empty report should have no findings, got %+v", doc.Summary)
	}
}

// TestRenderJSONDoesNotEscapeHTML checks that SetEscapeHTML(false) is honored so
// characters like < > & in prose survive verbatim rather than as <.
func TestRenderJSONDoesNotEscapeHTML(t *testing.T) {
	r := Report{
		Tool: ToolInfo{Name: "x"},
		Findings: []core.Finding{{
			RuleID: "r", Severity: core.SeverityInfo, Title: "a < b && c > d",
			Fingerprint: "f",
		}},
	}
	out := render(t, FormatJSON, r, Options{})
	if !bytes.Contains(out, []byte("a < b && c > d")) {
		t.Errorf("expected unescaped HTML characters in JSON:\n%s", out)
	}
}

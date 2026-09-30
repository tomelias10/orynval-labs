package output

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/tomelias10/orynval-labs/internal/core"
)

// decodeSARIF parses SARIF output into a loosely-typed structure for assertions.
func decodeSARIF(t *testing.T, out []byte) sarifLog {
	t.Helper()
	var log sarifLog
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v\n%s", err, out)
	}
	return log
}

func TestRenderSARIFStructure(t *testing.T) {
	out := render(t, FormatSARIF, sampleReport(), Options{})
	log := decodeSARIF(t, out)

	if log.Schema != sarifSchema || log.Version != sarifVersion {
		t.Errorf("schema/version wrong: %q %q", log.Schema, log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "orynval-test" || run.Tool.Driver.InformationURI != "https://example.invalid" {
		t.Errorf("driver metadata wrong: %+v", run.Tool.Driver)
	}
	if len(run.Results) != 2 {
		t.Fatalf("want 2 results, got %d", len(run.Results))
	}

	// Every result's ruleIndex must point at the matching rule in the driver's
	// rules array — this is what SARIF viewers rely on.
	for _, res := range run.Results {
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("ruleIndex %d out of range", res.RuleIndex)
		}
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("ruleIndex %d points at %q, want %q",
				res.RuleIndex, run.Tool.Driver.Rules[res.RuleIndex].ID, res.RuleID)
		}
	}

	// The CRITICAL finding maps to SARIF level "error".
	var critical sarifResult
	for _, res := range run.Results {
		if res.RuleID == "orynval.test.alpha" {
			critical = res
		}
	}
	if critical.Level != "error" {
		t.Errorf("critical finding level = %q, want error", critical.Level)
	}
	if critical.PartialFingerprints[fingerprintKey] == "" {
		t.Error("critical finding missing partial fingerprint")
	}
	if critical.Properties["severity"] != "CRITICAL" {
		t.Errorf("severity property = %q", critical.Properties["severity"])
	}
}

func TestSARIFLevelMapping(t *testing.T) {
	cases := map[core.Severity]string{
		core.SeverityCritical: "error",
		core.SeverityHigh:     "error",
		core.SeverityMedium:   "warning",
		core.SeverityLow:      "note",
		core.SeverityInfo:     "note",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%s) = %q, want %q", sev, got, want)
		}
	}
}

func TestSARIFSecuritySeverityDescends(t *testing.T) {
	order := []core.Severity{
		core.SeverityCritical, core.SeverityHigh, core.SeverityMedium,
		core.SeverityLow, core.SeverityInfo,
	}
	prev := 100.0
	for _, sev := range order {
		v, err := strconv.ParseFloat(securitySeverity(sev), 64)
		if err != nil {
			t.Fatalf("securitySeverity(%s) not numeric: %v", sev, err)
		}
		if v >= prev {
			t.Errorf("security-severity for %s (%v) should be < %v", sev, v, prev)
		}
		prev = v
	}
}

func TestRenderSARIFRuleDocsPopulated(t *testing.T) {
	out := render(t, FormatSARIF, sampleReport(), Options{})
	log := decodeSARIF(t, out)
	rules := log.Runs[0].Tool.Driver.Rules
	// Rules are ordered by ID: alpha before beta.
	if rules[0].ID != "orynval.test.alpha" {
		t.Errorf("rules not sorted by ID: %q first", rules[0].ID)
	}
	if rules[0].FullDescription == nil || rules[0].FullDescription.Text == "" {
		t.Error("expected full description on rule alpha")
	}
	if rules[0].DefaultConfiguration == nil || rules[0].DefaultConfiguration.Level != "error" {
		t.Errorf("rule alpha default level wrong: %+v", rules[0].DefaultConfiguration)
	}
}

func TestRenderSARIFEmpty(t *testing.T) {
	out := render(t, FormatSARIF, Report{Tool: ToolInfo{Name: "x"}}, Options{})
	log := decodeSARIF(t, out)
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 0 {
		t.Errorf("empty report should yield a run with zero results")
	}
}

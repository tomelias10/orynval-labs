package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tomelias10/orynval-labs/internal/core"
)

func TestRenderTerminalNoColorStable(t *testing.T) {
	out := string(render(t, FormatTerminal, sampleReport(), Options{Color: false}))

	// No ANSI escape sequences in the no-color path.
	if strings.Contains(out, "\x1b[") {
		t.Errorf("no-color output contains an ANSI escape:\n%q", out)
	}
	// Suite banner, header, summary, and severity tags are present.
	for _, want := range []string{
		"██████╗ ██████╗",
		"L  A  B  S",
		"orynval-test 9.9.9",
		"2 findings: 1 critical, 1 low",
		"[CRITICAL]",
		"orynval.test.alpha",
		"Hardcoded credential",
		"where:",
		"fix:",
		"evidence:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q:\n%s", want, out)
		}
	}
	// CRITICAL is listed before LOW.
	if strings.Index(out, "[CRITICAL]") > strings.Index(out, "[LOW]") {
		t.Error("CRITICAL should be rendered before LOW")
	}
}

func TestRenderTerminalColorAddsEscapes(t *testing.T) {
	colored := render(t, FormatTerminal, sampleReport(), Options{Color: true})
	plain := render(t, FormatTerminal, sampleReport(), Options{Color: false})
	if !bytes.Contains(colored, []byte("\x1b[")) {
		t.Error("color output should contain ANSI escapes")
	}
	if bytes.Equal(colored, plain) {
		t.Error("color and no-color output should differ")
	}
}

func TestRenderTerminalRedactsEvidence(t *testing.T) {
	out := render(t, FormatTerminal, sampleReport(), Options{Color: false})
	if bytes.Contains(out, []byte(leakSecret)) {
		t.Errorf("terminal leaked secret:\n%s", out)
	}
	if !bytes.Contains(out, []byte("AKIA****")) {
		t.Errorf("expected masked form AKIA**** in evidence:\n%s", out)
	}
}

func TestRenderTerminalEmpty(t *testing.T) {
	out := string(render(t, FormatTerminal, Report{Tool: ToolInfo{Name: "x"}}, Options{}))
	if !strings.Contains(out, "No findings.") {
		t.Errorf("empty report should say 'No findings.':\n%s", out)
	}
}

func TestSummaryLineSingular(t *testing.T) {
	one := summaryLine(Summary{Total: 1, High: 1})
	if !strings.Contains(one, "1 finding:") || strings.Contains(one, "findings") {
		t.Errorf("singular summary wrong: %q", one)
	}
}

func TestShortFingerprint(t *testing.T) {
	if got := shortFingerprint("abcdef0123456789"); got != "abcdef012345" {
		t.Errorf("shortFingerprint = %q", got)
	}
	if got := shortFingerprint("short"); got != "short" {
		t.Errorf("short fingerprint should pass through: %q", got)
	}
}

// TestTerminalTitleFallsBackToRuleID ensures a title-less finding still prints a
// useful headline.
func TestTerminalTitleFallsBackToRuleID(t *testing.T) {
	r := Report{Findings: []core.Finding{{RuleID: "r.only", Severity: core.SeverityInfo, Fingerprint: "f"}}}
	out := string(render(t, FormatTerminal, r, Options{}))
	if !strings.Contains(out, "r.only") {
		t.Errorf("expected rule ID as fallback headline:\n%s", out)
	}
}

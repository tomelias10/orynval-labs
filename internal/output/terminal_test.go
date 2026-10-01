package output

import (
	"bytes"
	"os"
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
	// Without opts.Banner (piped/redirected output) there is no identity
	// block: the report starts with the plain tool header line.
	if !strings.HasPrefix(out, "orynval-test 9.9.9\n") {
		t.Errorf("non-interactive output should start with the tool header:\n%s", out)
	}
	if strings.Contains(out, "ORYNVAL LABS") || strings.Contains(out, "╭─────╮") {
		t.Errorf("non-interactive output must not contain the banner:\n%s", out)
	}
	// Header, summary, and severity tags are present.
	for _, want := range []string{
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

func TestRenderTerminalBannerOnlyWhenInteractive(t *testing.T) {
	out := string(render(t, FormatTerminal, sampleReport(), Options{Banner: true}))
	want := Banner("orynval-test", "9.9.9") + "\n2 findings: 1 critical, 1 low\n"
	if !strings.HasPrefix(out, want) {
		t.Errorf("interactive output should open with the banner then the summary:\n%s", out)
	}
	// The identity replaces the header line rather than repeating it.
	if strings.Count(out, "orynval-test 9.9.9") != 1 {
		t.Errorf("tool name/version should appear exactly once:\n%s", out)
	}
}

func TestBannerIsCompact(t *testing.T) {
	b := Banner("mcp-drift", "1.2.3")
	lines := strings.Split(strings.TrimSuffix(b, "\n"), "\n")
	if len(lines) > 6 {
		t.Fatalf("banner has %d lines, want <= 6:\n%s", len(lines), b)
	}
	for _, want := range []string{"▌ ▐", "ORYNVAL LABS · mcp-drift 1.2.3", "local · read-only · offline"} {
		if !strings.Contains(b, want) {
			t.Errorf("banner missing %q:\n%s", want, b)
		}
	}
	if strings.Contains(b, "\x1b[") {
		t.Error("banner must be plain text")
	}
	if got := Banner("", ""); !strings.Contains(got, "│ ▌ ▐ │  ORYNVAL LABS\n") {
		t.Errorf("nameless banner should show only the brand:\n%s", got)
	}
	if got := Banner("tool", ""); !strings.Contains(got, "ORYNVAL LABS · tool\n") {
		t.Errorf("versionless banner should omit the version:\n%s", got)
	}
}

func TestIsTerminal(t *testing.T) {
	var buf bytes.Buffer
	if IsTerminal(&buf) {
		t.Error("a buffer is never a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if IsTerminal(f) {
		t.Error("a regular file is not a terminal")
	}
	orig := isTerminal
	defer func() { isTerminal = orig }()
	isTerminal = func(uintptr) bool { return true }
	if !IsTerminal(f) {
		t.Error("an *os.File reported as a TTY should be a terminal")
	}
	if IsTerminal(&buf) {
		t.Error("a non-file writer is never a terminal, even if the fd check says yes")
	}
}

func TestRenderTerminalBannerColored(t *testing.T) {
	out := string(render(t, FormatTerminal, sampleReport(), Options{Banner: true, Color: true}))
	if !strings.Contains(out, "\x1b[") || !strings.Contains(out, "ORYNVAL LABS") {
		t.Errorf("colored interactive output should style the banner:\n%q", out)
	}
}

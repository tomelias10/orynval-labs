package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomelias10/orynval-labs/internal/core"
)

// markerRule flags every line in every file that contains a marker substring.
// It is a minimal, deterministic rule used to exercise the CLI runner.
type markerRule struct {
	marker   string
	severity core.Severity
}

func (r markerRule) ID() string          { return "test.marker" }
func (r markerRule) Name() string        { return "Marker rule" }
func (r markerRule) Description() string { return "Flags lines containing a test marker." }
func (r markerRule) Evaluate(ctx *core.Context) []core.Finding {
	var out []core.Finding
	_ = ctx.Walk(func(f core.File) error {
		lines, err := ctx.Lines(f)
		if err != nil {
			return nil
		}
		for i, line := range lines {
			if strings.Contains(line, r.marker) {
				out = append(out, core.Finding{
					RuleID:      r.ID(),
					Title:       "Marker present",
					Severity:    r.severity,
					Confidence:  core.ConfidenceHigh,
					Where:       f.Rel,
					Evidence:    []core.Evidence{{File: f.Rel, Line: i + 1, Snippet: line, Kind: core.KindObserved}},
					Fingerprint: core.ComputeFingerprint(r.ID(), f.Rel, line),
				})
			}
		}
		return nil
	})
	return out
}

// tool builds a Tool whose single rule flags the marker at the given severity.
func tool(marker string, sev core.Severity) Tool {
	return Tool{
		Name:    "test-tool",
		Version: "0.0.1",
		Summary: "test",
		Rules:   []core.Rule{markerRule{marker: marker, severity: sev}},
	}
}

// treeWith writes files (rel->content) under a fresh temp dir and returns it.
func treeWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func run(t *testing.T, tl Tool, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := tl.Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRunVersion(t *testing.T) {
	code, out, _ := run(t, tool("X", core.SeverityHigh), "--version")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "test-tool 0.0.1") {
		t.Errorf("version output = %q", out)
	}
}

func TestRunListRules(t *testing.T) {
	code, out, _ := run(t, tool("X", core.SeverityHigh), "--list-rules")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "test.marker") || !strings.Contains(out, "Marker rule") {
		t.Errorf("list-rules output = %q", out)
	}
}

func TestRunTerminalFindings(t *testing.T) {
	dir := treeWith(t, map[string]string{"a.txt": "clean\nHAS_MARKER here\n"})
	code, out, errb := run(t, tool("HAS_MARKER", core.SeverityHigh), dir)
	if code != ExitOK { // no --fail-on, so OK even with findings
		t.Fatalf("exit = %d, stderr=%s", code, errb)
	}
	if !strings.Contains(out, "1 finding") || !strings.Contains(out, "[HIGH]") {
		t.Errorf("terminal output = %q", out)
	}
}

func TestRunJSONFormat(t *testing.T) {
	dir := treeWith(t, map[string]string{"a.txt": "HAS_MARKER\n"})
	code, out, _ := run(t, tool("HAS_MARKER", core.SeverityHigh), "--format", "json", dir)
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, `"findings"`) || !strings.Contains(out, `"test.marker"`) {
		t.Errorf("json output = %q", out)
	}
}

func TestRunFailOnGates(t *testing.T) {
	dir := treeWith(t, map[string]string{"a.txt": "HAS_MARKER\n"})

	// Finding is HIGH; --fail-on high must gate (exit 3).
	code, _, _ := run(t, tool("HAS_MARKER", core.SeverityHigh), "--fail-on", "high", dir)
	if code != ExitFindings {
		t.Errorf("expected ExitFindings for HIGH >= high, got %d", code)
	}

	// Finding is LOW; --fail-on high must NOT gate (exit 0).
	code, _, _ = run(t, tool("HAS_MARKER", core.SeverityLow), "--fail-on", "high", dir)
	if code != ExitOK {
		t.Errorf("expected ExitOK for LOW < high, got %d", code)
	}
}

func TestRunIgnore(t *testing.T) {
	dir := treeWith(t, map[string]string{
		"keep.txt": "HAS_MARKER\n",
		"skip.log": "HAS_MARKER\n",
	})
	code, out, _ := run(t, tool("HAS_MARKER", core.SeverityMedium), "--ignore", "*.log", "--format", "json", dir)
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if strings.Contains(out, "skip.log") {
		t.Errorf("ignored file appeared in output: %q", out)
	}
	if !strings.Contains(out, "keep.txt") {
		t.Errorf("kept file missing from output: %q", out)
	}
}

func TestRunErrors(t *testing.T) {
	// Invalid format.
	if code, _, _ := run(t, tool("X", core.SeverityHigh), "--format", "nope", "."); code != ExitError {
		t.Errorf("invalid format: exit = %d, want %d", code, ExitError)
	}
	// Invalid fail-on.
	if code, _, _ := run(t, tool("X", core.SeverityHigh), "--fail-on", "nope", "."); code != ExitError {
		t.Errorf("invalid fail-on: exit = %d, want %d", code, ExitError)
	}
	// Nonexistent path.
	if code, _, _ := run(t, tool("X", core.SeverityHigh), filepath.Join(t.TempDir(), "nope")); code != ExitError {
		t.Errorf("bad path: exit = %d, want %d", code, ExitError)
	}
	// Too many args.
	if code, _, _ := run(t, tool("X", core.SeverityHigh), ".", "."); code != ExitError {
		t.Errorf("extra args: exit = %d, want %d", code, ExitError)
	}
	// Unknown flag.
	if code, _, _ := run(t, tool("X", core.SeverityHigh), "--bogus"); code != ExitError {
		t.Errorf("unknown flag: exit = %d, want %d", code, ExitError)
	}
}

func TestColorEnabled(t *testing.T) {
	var buf bytes.Buffer // not an *os.File
	if colorEnabled("auto", &buf) {
		t.Error("auto color to a non-file writer should be off")
	}
	if !colorEnabled("always", &buf) {
		t.Error("always should force color on")
	}
	if colorEnabled("never", os.Stdout) {
		t.Error("never should force color off")
	}
}

func TestRunPrintBaseline(t *testing.T) {
	dir := treeWith(t, map[string]string{"a.txt": "MARK"})
	tl := tool("MARK", core.SeverityHigh)

	// Without the hook the flag does not exist.
	if code, _, _ := run(t, tl, "--print-baseline", dir); code != ExitError {
		t.Errorf("--print-baseline without a hook should be a usage error, got %d", code)
	}

	tl.PrintBaseline = func(ctx *core.Context) []byte { return []byte("BASELINE " + filepath.Base(ctx.Root) + "\n") }
	code, out, _ := run(t, tl, "--print-baseline", dir)
	if code != ExitOK || out != "BASELINE "+filepath.Base(dir)+"\n" {
		t.Errorf("print-baseline: code %d, out %q", code, out)
	}
	if strings.Contains(out, "MARK") || strings.Contains(out, "finding") {
		t.Error("print-baseline must not run the scan report")
	}

	var errb bytes.Buffer
	if code := tl.Run([]string{"--print-baseline", dir}, failWriter{}, &errb); code != ExitError || !strings.Contains(errb.String(), "error:") {
		t.Errorf("a failed write should be an error, got %d %q", code, errb.String())
	}
}

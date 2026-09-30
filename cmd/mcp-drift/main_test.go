package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--version"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "mcp-drift "+version) {
		t.Errorf("version output = %q", out.String())
	}
}

func TestRunScanFixtures(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"-f", "json", "../../internal/mcp/testdata"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d (stderr=%q)", code, errb.String())
	}
	if !strings.Contains(out.String(), "orynval.mcp.config-audit") {
		t.Errorf("scan output missing rule id: %q", out.String())
	}
	// The scanner must never leak the synthetic token through the CLI either.
	if strings.Contains(out.String(), "ghp_synthetic0123456789abcdefghijklmnopqrst") {
		t.Error("CLI output leaked the raw secret")
	}
}

func TestRunFailOn(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"-f", "json", "--fail-on", "high", "../../internal/mcp/testdata"}, &out, &errb)
	if code != 3 {
		t.Fatalf("fail-on high exit = %d, want 3", code)
	}
}

func TestRunBadFlag(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--format", "nope", "../../internal/mcp/testdata"}, &out, &errb)
	if code != 1 {
		t.Fatalf("bad format exit = %d, want 1", code)
	}
}

// TestMainInvokesRun exercises main() in-process with os.Exit stubbed, so the
// single entrypoint line is covered without terminating the test binary.
func TestMainInvokesRun(t *testing.T) {
	oldArgs := os.Args
	oldExit := osExit
	defer func() { os.Args = oldArgs; osExit = oldExit }()

	var code int
	osExit = func(c int) { code = c }
	os.Args = []string{"mcp-drift", "--version"}

	main()

	if code != 0 {
		t.Errorf("main exit code = %d, want 0", code)
	}
}

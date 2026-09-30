package cli

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/tomelias10/orynval-labs/internal/core"
)

// failWriter fails every write, used to drive the render-error path.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRunRenderError(t *testing.T) {
	dir := treeWith(t, map[string]string{"a.txt": "HAS_MARKER\n"})
	var errb bytes.Buffer
	code := tool("HAS_MARKER", core.SeverityHigh).Run([]string{dir}, failWriter{}, &errb)
	if code != ExitError {
		t.Errorf("expected ExitError when stdout fails, got %d", code)
	}
	if !strings.Contains(errb.String(), "error:") {
		t.Errorf("expected an error message on stderr, got %q", errb.String())
	}
}

func TestRunDefaultsToCurrentDir(t *testing.T) {
	dir := treeWith(t, map[string]string{"a.txt": "HAS_MARKER\n"})
	t.Chdir(dir)
	// No path argument: the scan must default to the current directory.
	code, out, _ := run(t, tool("HAS_MARKER", core.SeverityHigh), "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "a.txt") {
		t.Errorf("default-directory scan did not find a.txt: %q", out)
	}
}

func TestColorEnabledNoColorEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	f, err := os.CreateTemp(t.TempDir(), "color")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if colorEnabled("auto", f) {
		t.Error("NO_COLOR set should disable auto color even for a file")
	}
}

func TestColorEnabledAutoFileUsesIsatty(t *testing.T) {
	t.Setenv("NO_COLOR", "") // treated as unset
	f, err := os.CreateTemp(t.TempDir(), "color")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// A regular file is an *os.File but not a terminal: the isatty branch runs
	// and reports no color.
	if colorEnabled("auto", f) {
		t.Error("a regular file is not a terminal, auto color should be off")
	}
}

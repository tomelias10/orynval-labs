package trustproof

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// failWriter returns an error on every Write, to exercise output-write failures.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

const (
	fixtureQuestions = "testdata/questions.csv"
	fixtureEvidence  = "testdata/evidence"
)

// runCLI runs Run with captured output and returns the exit code and streams.
func runCLI(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunVersion(t *testing.T) {
	code, out, _ := runCLI("--version")
	if code != ExitOK || !strings.Contains(out, Version) {
		t.Errorf("version: code=%d out=%q", code, out)
	}
}

func TestRunFlagParseError(t *testing.T) {
	if code, _, _ := runCLI("--nonexistent-flag"); code != ExitError {
		t.Errorf("expected ExitError, got %d", code)
	}
}

func TestRunMissingRequiredFlags(t *testing.T) {
	code, _, stderr := runCLI()
	if code != ExitError || !strings.Contains(stderr, "required") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestRunBadFormat(t *testing.T) {
	code, _, stderr := runCLI("--questions", fixtureQuestions, "--evidence", fixtureEvidence, "--format", "bogus")
	if code != ExitError || !strings.Contains(stderr, "unknown format") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestRunBadMinConfidence(t *testing.T) {
	code, _, stderr := runCLI("--questions", fixtureQuestions, "--evidence", fixtureEvidence, "--min-confidence", "bogus")
	if code != ExitError || !strings.Contains(stderr, "min-confidence") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestRunReadQuestionsError(t *testing.T) {
	code, _, stderr := runCLI("--questions", "/no/such/file.csv", "--evidence", fixtureEvidence)
	if code != ExitError || !strings.Contains(stderr, "read questions") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestRunParseQuestionsError(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.csv")
	if err := os.WriteFile(bad, []byte(`ab"cd,x`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI("--questions", bad, "--evidence", fixtureEvidence)
	if code != ExitError || !strings.Contains(stderr, "parse questions") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestRunReadEvidenceError(t *testing.T) {
	code, _, stderr := runCLI("--questions", fixtureQuestions, "--evidence", "/no/such/dir")
	if code != ExitError || !strings.Contains(stderr, "read evidence") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestRunSuccessTerminal(t *testing.T) {
	code, out, _ := runCLI("--questions", fixtureQuestions, "--evidence", fixtureEvidence)
	if code != ExitOK {
		t.Fatalf("expected ExitOK, got %d", code)
	}
	if !strings.Contains(out, "Answered") || !strings.Contains(out, "ghp_****") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestRunFailOnGapsWithGaps(t *testing.T) {
	code, _, _ := runCLI("--questions", fixtureQuestions, "--evidence", fixtureEvidence, "--fail-on-gaps")
	if code != ExitGaps {
		t.Errorf("expected ExitGaps, got %d", code)
	}
}

func TestRunFailOnGapsNoGaps(t *testing.T) {
	// A questionnaire whose every question is grounded produces no gaps.
	qs := filepath.Join(t.TempDir(), "answerable.txt")
	content := "Do you require multi-factor authentication for production access?\n" +
		"How is customer data encrypted at rest?\n"
	if err := os.WriteFile(qs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, _ := runCLI("--questions", qs, "--evidence", fixtureEvidence, "--fail-on-gaps")
	if code != ExitOK {
		t.Errorf("expected ExitOK with no gaps, got %d", code)
	}
}

func TestRunCSVToFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "draft.csv")
	code, _, _ := runCLI("--questions", fixtureQuestions, "--evidence", fixtureEvidence, "--format", "csv", "--out", out)
	if code != ExitOK {
		t.Fatalf("expected ExitOK, got %d", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if !strings.HasPrefix(string(data), "Question,Status,Confidence,Answer,Citations") {
		t.Errorf("unexpected CSV:\n%s", data)
	}
}

func TestRunMarkdownToFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "draft.md")
	code, _, _ := runCLI("--questions", fixtureQuestions, "--evidence", fixtureEvidence, "--format", "md", "--out", out)
	if code != ExitOK {
		t.Fatalf("expected ExitOK, got %d", code)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("markdown file not written: %v", err)
	}
}

func TestRunWriteFileError(t *testing.T) {
	// An --out path inside a nonexistent directory cannot be created.
	bad := filepath.Join(t.TempDir(), "no-such-dir", "draft.csv")
	code, _, stderr := runCLI("--questions", fixtureQuestions, "--evidence", fixtureEvidence, "--format", "csv", "--out", bad)
	if code != ExitError || !strings.Contains(stderr, "write output") {
		t.Errorf("code=%d stderr=%q", code, stderr)
	}
}

func TestRunWriteStdoutError(t *testing.T) {
	var stderr bytes.Buffer
	code := Run([]string{"--questions", fixtureQuestions, "--evidence", fixtureEvidence}, failWriter{}, &stderr)
	if code != ExitError || !strings.Contains(stderr.String(), "write output") {
		t.Errorf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestEmitStdoutSuccess(t *testing.T) {
	var buf bytes.Buffer
	if err := emit("hello", "terminal", "ignored-out.txt", &buf); err != nil {
		t.Fatalf("emit: %v", err)
	}
	// terminal output ignores --out and goes to stdout.
	if buf.String() != "hello" {
		t.Errorf("emit wrote %q", buf.String())
	}
}

func TestRunTerminalBannerOnlyOnTTY(t *testing.T) {
	args := []string{"--questions", "testdata/questions.csv", "--evidence", "testdata/evidence"}

	var piped, stderr bytes.Buffer
	if code := Run(args, &piped, &stderr); code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if strings.Contains(piped.String(), "ORYNVAL LABS") {
		t.Error("piped terminal output must not contain the banner")
	}

	orig := isTerminal
	defer func() { isTerminal = orig }()
	isTerminal = func(io.Writer) bool { return true }
	var tty bytes.Buffer
	if code := Run(args, &tty, &stderr); code != ExitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	got := tty.String()
	if strings.Count(got, "ORYNVAL LABS · trust-proof") != 1 || !strings.HasPrefix(got, " ╭─────╮") {
		t.Errorf("TTY output should open with exactly one banner:\n%s", got)
	}
}

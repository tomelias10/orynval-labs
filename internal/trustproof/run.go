package trustproof

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// Exit codes are part of the CLI contract so CI can branch on them. They match
// the rest of the Orynval Labs toolkit.
const (
	ExitOK    = 0 // ran successfully
	ExitError = 1 // usage error, bad path, or I/O failure
	ExitGaps  = 3 // ran successfully but gaps remain (with --fail-on-gaps)
)

// Name and Version identify the tool in --version and usage output.
const (
	Name    = "trust-proof"
	Version = "0.1.0"
)

// validFormats are the accepted --format values. terminal and json go to
// stdout; csv and md honor --out (falling back to stdout).
var validFormats = map[string]struct{}{
	"terminal": {}, "json": {}, "csv": {}, "md": {},
}

// Run parses args (excluding the program name), answers the questionnaire from
// local evidence, writes the requested report, and returns a process exit code.
// It never calls os.Exit and takes its writers as parameters, so it is fully
// testable. There is no network path anywhere in this function.
func Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(Name, flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		questions   string
		evidence    string
		format      string
		out         string
		minConf     string
		failOnGaps  bool
		showVersion bool
	)
	fs.StringVar(&questions, "questions", "", "questionnaire file: .csv | .md | text (required)")
	fs.StringVar(&evidence, "evidence", "", "directory of approved evidence (required)")
	fs.StringVar(&format, "format", "terminal", "output format: terminal|json|csv|md")
	fs.StringVar(&out, "out", "", "output path for csv/md (default stdout)")
	fs.StringVar(&minConf, "min-confidence", "medium", "minimum confidence to draft an answer: high|medium|low")
	fs.BoolVar(&failOnGaps, "fail-on-gaps", false, "exit 3 if any question is UNKNOWN")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "%s %s — local evidence-grounded questionnaire answering\n\n", Name, Version)
		fmt.Fprintf(stderr, "Usage:\n  %s --questions <file> --evidence <dir> [flags]\n\n", Name)
		fmt.Fprintf(stderr, "Offline and deterministic. Answers are extractive drafts; nothing is uploaded or auto-certified.\n\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return ExitError // flag already printed the error/usage
	}

	if showVersion {
		fmt.Fprintf(stdout, "%s %s\n", Name, Version)
		return ExitOK
	}

	if questions == "" || evidence == "" {
		fmt.Fprintln(stderr, "error: --questions and --evidence are required")
		fs.Usage()
		return ExitError
	}
	if _, ok := validFormats[format]; !ok {
		fmt.Fprintf(stderr, "error: unknown format %q (want terminal|json|csv|md)\n", format)
		return ExitError
	}
	minConfidence, ok := parseMinConfidence(minConf)
	if !ok {
		fmt.Fprintf(stderr, "error: unknown min-confidence %q (want high|medium|low)\n", minConf)
		return ExitError
	}

	data, err := os.ReadFile(questions)
	if err != nil {
		fmt.Fprintln(stderr, "error: read questions:", err)
		return ExitError
	}
	qs, err := parseQuestions(questions, data)
	if err != nil {
		fmt.Fprintln(stderr, "error: parse questions:", err)
		return ExitError
	}

	passages, err := readEvidenceDir(evidence)
	if err != nil {
		fmt.Fprintln(stderr, "error: read evidence:", err)
		return ExitError
	}

	rep := newReport(answerAll(newCorpus(passages), qs, minConfidence))
	content := render(format, rep)

	if err := emit(content, format, out, stdout); err != nil {
		fmt.Fprintln(stderr, "error: write output:", err)
		return ExitError
	}

	if failOnGaps && rep.Summary.Gaps > 0 {
		return ExitGaps
	}
	return ExitOK
}

// emit writes the rendered content to its destination: a file for csv/md when
// --out is set, otherwise stdout. Routing every format through one writer keeps
// the single I/O error path in one place.
func emit(content, format, out string, stdout io.Writer) error {
	if out != "" && (format == "csv" || format == "md") {
		return os.WriteFile(out, []byte(content), 0o644)
	}
	_, err := io.WriteString(stdout, content)
	return err
}

// Package cli is the shared command-line runner for Orynval Labs' finding-based
// scanners (nhi-ghost, mcp-drift). It gives every such tool the same flags,
// the same safe/deterministic scan pipeline (walk -> context -> registry ->
// render), and the same exit-code contract, so a single tool is only a rule set
// plus a name.
//
// Like the rest of the toolkit it is read-only, offline, and deterministic: it
// never writes to the scanned tree, never opens the network, and emits no
// timestamps. Output is byte-for-byte stable for a given input tree and format.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mattn/go-isatty"

	"github.com/tomelias10/orynval-labs/internal/core"
	"github.com/tomelias10/orynval-labs/internal/output"
	"github.com/tomelias10/orynval-labs/internal/walk"
)

// Exit codes. These are part of the CLI contract so CI can branch on them.
const (
	ExitOK       = 0 // scan ran; no findings at or above --fail-on
	ExitError    = 1 // usage error, bad path, or I/O failure
	ExitFindings = 3 // scan ran; findings at or above --fail-on were present
)

// Tool describes a finding-based scanner. A concrete tool supplies its identity
// and its rule set; Run provides everything else.
type Tool struct {
	Name           string
	Version        string
	Summary        string // one-line description shown in -h
	InformationURI string
	Rules          []core.Rule
	// PrintBaseline, when set, adds a --print-baseline flag: instead of
	// scanning for findings, the tool writes the approved-baseline document
	// for the tree to stdout. It never writes into the scanned tree; the user
	// redirects the output to wherever the baseline should live.
	PrintBaseline func(ctx *core.Context) []byte
}

// Run parses args (excluding the program name), executes the scan, renders the
// result to stdout, and returns a process exit code. It never calls os.Exit, so
// it is straightforward to test.
func (t Tool) Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(t.Name, flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		formatStr   string
		failOnStr   string
		colorMode   string
		ignoreList  multiString
		maxFileSize int64
		listRules   bool
		showVersion bool
		printBase   bool
	)
	fs.StringVar(&formatStr, "format", "terminal", "output format: terminal|json|sarif|html|badge|share")
	fs.StringVar(&formatStr, "f", "terminal", "shorthand for --format")
	fs.StringVar(&failOnStr, "fail-on", "", "exit "+itoa(ExitFindings)+" if any finding is at least this severity: critical|high|medium|low|info")
	fs.StringVar(&colorMode, "color", "auto", "colorize terminal output: auto|always|never")
	fs.Var(&ignoreList, "ignore", "additional file/dir name or glob to skip (repeatable)")
	fs.Int64Var(&maxFileSize, "max-file-size", walk.DefaultMaxFileSize, "skip files larger than this many bytes")
	fs.BoolVar(&listRules, "list-rules", false, "print the tool's rules and exit")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")
	if t.PrintBaseline != nil {
		fs.BoolVar(&printBase, "print-baseline", false, "print an approved-baseline document for the current configs to stdout and exit (redirect it to .orynval/mcp-baseline.json)")
	}

	fs.Usage = func() {
		fmt.Fprintf(stderr, "%s %s — %s\n\n", t.Name, t.Version, t.Summary)
		fmt.Fprintf(stderr, "Usage:\n  %s [flags] [path]\n\n", t.Name)
		fmt.Fprintf(stderr, "The scan is read-only, offline, and deterministic.\n\nFlags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return ExitError // flag already printed the error/usage
	}

	if showVersion {
		fmt.Fprintf(stdout, "%s %s\n", t.Name, t.Version)
		return ExitOK
	}

	reg := core.NewRegistry()
	for _, rule := range t.Rules {
		reg.Register(rule)
	}

	if listRules {
		printRules(stdout, reg)
		return ExitOK
	}

	format, err := output.ParseFormat(formatStr)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}

	var failOn core.Severity
	if failOnStr != "" {
		failOn, err = core.ParseSeverity(failOnStr)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return ExitError
		}
	}

	root := "."
	switch fs.NArg() {
	case 0:
	case 1:
		root = fs.Arg(0)
	default:
		fmt.Fprintln(stderr, "error: expected at most one path argument")
		return ExitError
	}

	w, err := walk.New(root, walk.Options{MaxFileSize: maxFileSize, Ignore: ignoreList})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}

	ctx := core.NewContext(w.Root(), w, core.Options{})
	if printBase {
		if _, err := stdout.Write(t.PrintBaseline(ctx)); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return ExitError
		}
		return ExitOK
	}
	findings := reg.Evaluate(ctx)

	report := output.Report{
		Tool:     output.ToolInfo{Name: t.Name, Version: t.Version, InformationURI: t.InformationURI},
		Rules:    ruleDocs(reg),
		Findings: findings,
	}
	opts := output.Options{Color: colorEnabled(colorMode, stdout)}
	if err := output.Render(stdout, format, report, opts); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return ExitError
	}

	if failOnStr != "" && anyAtLeast(findings, failOn) {
		return ExitFindings
	}
	return ExitOK
}

// anyAtLeast reports whether any finding is at least as severe as threshold.
func anyAtLeast(fs []core.Finding, threshold core.Severity) bool {
	for _, f := range fs {
		if f.Severity.AtLeast(threshold) {
			return true
		}
	}
	return false
}

// ruleDocs projects a registry's rules into output.RuleDoc metadata.
func ruleDocs(reg *core.Registry) []output.RuleDoc {
	rules := reg.Rules()
	docs := make([]output.RuleDoc, 0, len(rules))
	for _, r := range rules {
		docs = append(docs, output.RuleDoc{ID: r.ID(), Name: r.Name(), Description: r.Description()})
	}
	return docs
}

// printRules writes the registered rules (already ID-sorted) to w.
func printRules(w io.Writer, reg *core.Registry) {
	for _, r := range reg.Rules() {
		fmt.Fprintf(w, "%s\n  %s\n  %s\n\n", r.ID(), r.Name(), r.Description())
	}
}

// colorEnabled resolves the --color mode against the destination writer.
func colorEnabled(mode string, w io.Writer) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "always":
		return true
	case "never":
		return false
	default: // auto
		if os.Getenv("NO_COLOR") != "" {
			return false
		}
		if f, ok := w.(*os.File); ok {
			return isatty.IsTerminal(f.Fd())
		}
		return false
	}
}

// multiString collects a repeatable string flag.
type multiString []string

func (m *multiString) String() string { return strings.Join(*m, ",") }
func (m *multiString) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// itoa is a tiny int->string helper so the flag help text can embed the exit
// code without pulling strconv into the hot path.
func itoa(n int) string { return fmt.Sprintf("%d", n) }

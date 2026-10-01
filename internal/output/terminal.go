package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/muesli/termenv"

	"github.com/tomelias10/orynval-labs/internal/core"
)

// Banner returns the compact Orynval identity printed above human terminal
// reports: a small explorer mascot (two vertical eyes, no mouth) beside the
// tool name and the suite's guarantees. Three lines, so findings stay on
// screen. Callers print it only when the destination is an interactive
// terminal (see IsTerminal); piped, redirected, and machine formats
// (JSON, SARIF, HTML, badge, share, CSV, Markdown) never contain it.
func Banner(tool, version string) string {
	name := "ORYNVAL LABS"
	if tool != "" {
		name += " · " + tool
		if version != "" {
			name += " " + version
		}
	}
	return " ╭─────╮\n" +
		" │ ▌ ▐ │  " + name + "\n" +
		" ╰─────╯  local · read-only · offline\n"
}

// isTerminal is indirected so tests can exercise the interactive branch.
var isTerminal = isatty.IsTerminal

// IsTerminal reports whether w is an interactive terminal. Anything that is
// not an *os.File (buffers, pipes wrapped in writers) is never a terminal.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && isTerminal(f.Fd())
}

// severityColor maps a severity to a hex color used only in the colored
// terminal path. The no-color path never consults it.
func severityColor(s core.Severity) lipgloss.Color {
	switch s {
	case core.SeverityCritical:
		return lipgloss.Color("#ff5f5f")
	case core.SeverityHigh:
		return lipgloss.Color("#ff875f")
	case core.SeverityMedium:
		return lipgloss.Color("#ffd75f")
	case core.SeverityLow:
		return lipgloss.Color("#5fafff")
	default:
		return lipgloss.Color("#8a8a8a")
	}
}

// styler wraps text with color when enabled and returns it unchanged otherwise.
// Keeping styling behind this single seam means the layout code is identical in
// both modes, so no-color output is byte-for-byte deterministic.
type styler struct {
	color bool
	re    *lipgloss.Renderer
}

func newStyler(w io.Writer, color bool) styler {
	re := lipgloss.NewRenderer(w)
	if color {
		// Force a profile so color is emitted even when w is not a TTY (the
		// caller asked for it); otherwise strip everything for determinism.
		re.SetColorProfile(termenv.TrueColor)
	} else {
		re.SetColorProfile(termenv.Ascii)
	}
	return styler{color: color, re: re}
}

func (s styler) severity(sev core.Severity, text string) string {
	if !s.color {
		return text
	}
	return s.re.NewStyle().Bold(true).Foreground(severityColor(sev)).Render(text)
}

func (s styler) bold(text string) string {
	if !s.color {
		return text
	}
	return s.re.NewStyle().Bold(true).Render(text)
}

// accent colors text in the Orynval cyan; used only for the banner.
func (s styler) accent(text string) string {
	if !s.color {
		return text
	}
	return s.re.NewStyle().Foreground(lipgloss.Color("#22D3EE")).Render(text)
}

func (s styler) faint(text string) string {
	if !s.color {
		return text
	}
	return s.re.NewStyle().Faint(true).Render(text)
}

// RenderTerminal writes a human-readable report. With opts.Color it adds ANSI
// styling; without it the output is plain, stable text suitable for snapshots
// and pipes.
func RenderTerminal(w io.Writer, r Report, opts Options) error {
	r = r.normalized()
	s := newStyler(w, opts.Color)

	var b strings.Builder
	if opts.Banner {
		b.WriteString(s.accent(Banner(r.Tool.Name, r.Tool.Version)))
		b.WriteString("\n")
	} else if r.Tool.Name != "" {
		header := r.Tool.Name
		if r.Tool.Version != "" {
			header += " " + r.Tool.Version
		}
		fmt.Fprintln(&b, s.bold(header))
	}
	fmt.Fprintln(&b, summaryLine(summarize(r.Findings)))

	for _, f := range r.Findings {
		b.WriteString("\n")
		tag := "[" + string(f.Severity) + "]"
		title := f.Title
		if title == "" {
			title = f.RuleID
		}
		fmt.Fprintf(&b, "%s %s — %s\n", s.severity(f.Severity, tag), f.RuleID, title)
		writeField(&b, "where:", f.Where)
		writeField(&b, "what:", f.What)
		writeField(&b, "why:", f.Why)
		writeField(&b, "fix:", f.Remediation)
		writeField(&b, "safer:", f.SaferAlternative)
		writeField(&b, "confidence:", string(f.Confidence))
		if len(f.Evidence) > 0 {
			fmt.Fprintf(&b, "  %-12s\n", "evidence:")
			for _, e := range f.Evidence {
				loc := e.File
				if e.Line > 0 {
					loc = fmt.Sprintf("%s:%d", e.File, e.Line)
				}
				fmt.Fprintf(&b, "    %s  %s\n", loc, e.Snippet)
			}
		}
		if f.Fingerprint != "" {
			writeField(&b, "id:", s.faint(shortFingerprint(f.Fingerprint)))
		}
	}

	b.WriteString("\nNeed help reviewing a finding?  https://orynval.com  |  tom@orynval.com\n")
	b.WriteString("Include the tool name and the smallest reproducible context you can safely share.\n")

	_, err := io.WriteString(w, b.String())
	return err
}

// writeField writes an aligned "  label        value" line, skipping empty
// values so absent fields do not clutter the output.
func writeField(b *strings.Builder, label, value string) {
	if value == "" {
		return
	}
	fmt.Fprintf(b, "  %-12s%s\n", label, value)
}

// summaryLine renders the one-line severity tally in severity order, listing
// only non-zero buckets.
func summaryLine(s Summary) string {
	if s.Total == 0 {
		return "No findings."
	}
	parts := make([]string, 0, 5)
	for _, kv := range []struct {
		n    int
		name string
	}{
		{s.Critical, "critical"},
		{s.High, "high"},
		{s.Medium, "medium"},
		{s.Low, "low"},
		{s.Info, "info"},
	} {
		if kv.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", kv.n, kv.name))
		}
	}
	noun := "findings"
	if s.Total == 1 {
		noun = "finding"
	}
	return fmt.Sprintf("%d %s: %s", s.Total, noun, strings.Join(parts, ", "))
}

// shortFingerprint returns a stable, human-sized prefix of a fingerprint.
func shortFingerprint(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12]
}

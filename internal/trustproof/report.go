package trustproof

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tomelias10/orynval-labs/internal/output"
)

// Summary is the run-level tally shown at the top of every report: how many
// questions there were, how many were answered, and how many remain gaps.
type Summary struct {
	Total    int     `json:"total"`
	Answered int     `json:"answered"`
	Gaps     int     `json:"gaps"`
	Percent  float64 `json:"answeredPercent"` // answered / total * 100
}

// summarize tallies results into a Summary. Percent is 0 for an empty
// questionnaire so the report never divides by zero.
func summarize(results []Result) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		if r.IsGap() {
			s.Gaps++
		} else {
			s.Answered++
		}
	}
	if s.Total > 0 {
		s.Percent = float64(s.Answered) / float64(s.Total) * 100
	}
	return s
}

// report bundles results with their summary; it is the single value every
// renderer consumes.
type report struct {
	Summary Summary  `json:"summary"`
	Results []Result `json:"results"`
}

// newReport builds the report for a set of drafted results.
func newReport(results []Result) report {
	return report{Summary: summarize(results), Results: results}
}

// render dispatches a report to the chosen output format. The format string has
// already been validated by the caller, so an unknown value is a programming
// error rather than user input.
func render(format string, rep report) string {
	switch format {
	case "json":
		return renderJSON(rep)
	case "csv":
		return renderCSV(rep)
	case "md":
		return renderMarkdown(rep)
	default: // "terminal"
		return renderTerminal(rep)
	}
}

// renderTerminal produces the human-facing gap report: a labeled draft banner,
// the summary line, each answered question with its confidence and citation,
// and the list of remaining gaps.
func renderTerminal(rep report) string {
	var b strings.Builder
	b.WriteString(output.TerminalBanner)
	b.WriteString("\n\n")
	b.WriteString("trust-proof — DRAFT (human review required; no claims auto-certified)\n\n")
	s := rep.Summary
	fmt.Fprintf(&b, "Questions: %d   Answered: %d   Gaps: %d   Coverage: %.0f%%\n",
		s.Total, s.Answered, s.Gaps, s.Percent)

	answered := filter(rep.Results, false)
	if len(answered) > 0 {
		b.WriteString("\nAnswered (grounded in cited evidence):\n")
		for _, r := range answered {
			fmt.Fprintf(&b, "  [%s] %s\n", r.Confidence, r.Question)
			for _, c := range r.Citations {
				fmt.Fprintf(&b, "        ↳ %s: %q\n", c.Ref(), c.Snippet)
			}
		}
	}

	gaps := filter(rep.Results, true)
	if len(gaps) > 0 {
		b.WriteString("\nGaps (no grounded evidence — answer manually):\n")
		for _, r := range gaps {
			fmt.Fprintf(&b, "  [UNKNOWN] %s\n", r.Question)
		}
	}
	return b.String()
}

// filter returns the results that are (or are not) gaps, preserving order.
func filter(results []Result, gaps bool) []Result {
	out := make([]Result, 0, len(results))
	for _, r := range results {
		if r.IsGap() == gaps {
			out = append(out, r)
		}
	}
	return out
}

// renderJSON emits the report as indented JSON. The report's types contain only
// strings, numbers, and slices of the same, so marshaling cannot fail; the
// error is discarded rather than propagated through an impossible branch.
func renderJSON(rep report) string {
	b, _ := json.MarshalIndent(rep, "", "  ")
	return string(b) + "\n"
}

// renderCSV emits the draft questionnaire as CSV with a fixed header. Citations
// are flattened to a "file:line" list so the column stays a single cell.
func renderCSV(rep report) string {
	var b strings.Builder
	b.WriteString("Question,Status,Confidence,Answer,Citations\n")
	for _, r := range rep.Results {
		row := []string{r.Question, r.Status, r.Confidence, r.Answer, citationRefs(r)}
		cells := make([]string, len(row))
		for i, c := range row {
			cells[i] = csvField(c)
		}
		b.WriteString(strings.Join(cells, ","))
		b.WriteString("\n")
	}
	return b.String()
}

// renderMarkdown emits the draft as a Markdown table under a summary header, the
// form most useful to paste into a review thread or a doc.
func renderMarkdown(rep report) string {
	var b strings.Builder
	s := rep.Summary
	b.WriteString("# trust-proof draft questionnaire\n\n")
	b.WriteString("_DRAFT — human review required; answers are extractive and not auto-certified._\n\n")
	fmt.Fprintf(&b, "**Questions:** %d  **Answered:** %d  **Gaps:** %d  **Coverage:** %.0f%%\n\n",
		s.Total, s.Answered, s.Gaps, s.Percent)
	b.WriteString("| Question | Status | Confidence | Answer | Citations |\n")
	b.WriteString("| --- | --- | --- | --- | --- |\n")
	for _, r := range rep.Results {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			mdCell(r.Question), r.Status, r.Confidence,
			mdCell(r.Answer), mdCell(citationRefs(r)))
	}
	return b.String()
}

// citationRefs joins a result's citation locators for a single-cell rendering.
func citationRefs(r Result) string {
	refs := make([]string, 0, len(r.Citations))
	for _, c := range r.Citations {
		refs = append(refs, c.Ref())
	}
	return strings.Join(refs, "; ")
}

// csvField quotes a field per RFC 4180 when it contains a comma, quote, or
// newline, doubling any embedded quotes. Using an explicit helper keeps CSV
// generation a pure, total function with no I/O error path to mask.
func csvField(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// mdCell escapes the characters that would break a Markdown table cell: a pipe
// ends the cell and a newline ends the row, so both are neutralized.
func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

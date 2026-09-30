package trustproof

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleResults() []Result {
	return []Result{
		{
			Question:   "Q answered?",
			Status:     StatusAnswered,
			Confidence: "HIGH",
			Answer:     `Based on a.md:1: "cell, with \"quote\" and\npipe|"`,
			Citations:  []Citation{{File: "a.md", Line: 1, Snippet: "s"}},
			Coverage:   0.9,
		},
		{Question: "Q gap?", Status: StatusUnknown},
	}
}

func TestSummarize(t *testing.T) {
	s := summarize(sampleResults())
	if s.Total != 2 || s.Answered != 1 || s.Gaps != 1 || s.Percent != 50 {
		t.Errorf("summarize = %+v", s)
	}
	empty := summarize(nil)
	if empty.Total != 0 || empty.Percent != 0 {
		t.Errorf("empty summarize = %+v", empty)
	}
}

func TestRenderDispatch(t *testing.T) {
	rep := newReport(sampleResults())
	if !strings.HasPrefix(render("json", rep), "{") {
		t.Error("json render should start with {")
	}
	if !strings.HasPrefix(render("csv", rep), "Question,Status") {
		t.Error("csv render should start with header")
	}
	if !strings.HasPrefix(render("md", rep), "# trust-proof") {
		t.Error("md render should start with title")
	}
	terminal := render("terminal", rep)
	if !strings.Contains(terminal, "██████╗ ██████╗") || !strings.Contains(terminal, "DRAFT") {
		t.Error("terminal render should contain Orynval banner and DRAFT label")
	}
	for _, format := range []string{"json", "csv", "md"} {
		if strings.Contains(render(format, rep), "██████╗") {
			t.Errorf("%s output must not contain terminal banner", format)
		}
	}
	if !strings.Contains(render("unrecognized", rep), "DRAFT") {
		t.Error("unknown format should fall back to terminal")
	}
}

func TestRenderTerminalOnlyAnswered(t *testing.T) {
	rep := newReport([]Result{{Question: "Q", Status: StatusAnswered, Confidence: "LOW",
		Citations: []Citation{{File: "a.md", Line: 2, Snippet: "x"}}}})
	out := renderTerminal(rep)
	if !strings.Contains(out, "Answered") || strings.Contains(out, "Gaps (") {
		t.Errorf("expected only answered section:\n%s", out)
	}
}

func TestRenderTerminalOnlyGaps(t *testing.T) {
	rep := newReport([]Result{{Question: "Q", Status: StatusUnknown}})
	out := renderTerminal(rep)
	if !strings.Contains(out, "Gaps (") || strings.Contains(out, "Answered (") {
		t.Errorf("expected only gaps section:\n%s", out)
	}
}

func TestRenderJSONValid(t *testing.T) {
	out := renderJSON(newReport(sampleResults()))
	var rep report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rep.Summary.Answered != 1 {
		t.Errorf("round-tripped summary wrong: %+v", rep.Summary)
	}
}

func TestRenderCSVEscaping(t *testing.T) {
	out := renderCSV(newReport(sampleResults()))
	// The answer field contains a comma, quotes, and a newline, so it must be
	// wrapped and its quotes doubled.
	if !strings.Contains(out, `"Based on a.md:1: ""cell, with \""quote\"" and`) {
		t.Errorf("CSV escaping wrong:\n%s", out)
	}
}

func TestRenderMarkdownTable(t *testing.T) {
	out := renderMarkdown(newReport(sampleResults()))
	if !strings.Contains(out, "| Question | Status | Confidence | Answer | Citations |") {
		t.Errorf("missing table header:\n%s", out)
	}
	// A pipe inside a cell is escaped so it does not break the table.
	if !strings.Contains(out, `pipe\|`) {
		t.Errorf("pipe not escaped:\n%s", out)
	}
}

func TestCitationRefs(t *testing.T) {
	r := Result{Citations: []Citation{{File: "a", Line: 1}, {File: "b", Line: 2}}}
	if got := citationRefs(r); got != "a:1; b:2" {
		t.Errorf("citationRefs = %q", got)
	}
	if got := citationRefs(Result{}); got != "" {
		t.Errorf("empty citationRefs = %q", got)
	}
}

func TestCSVField(t *testing.T) {
	if got := csvField("plain"); got != "plain" {
		t.Errorf("plain csvField = %q", got)
	}
	if got := csvField(`a,"b"`); got != `"a,""b"""` {
		t.Errorf("special csvField = %q", got)
	}
}

func TestMDCell(t *testing.T) {
	if got := mdCell("plain"); got != "plain" {
		t.Errorf("plain mdCell = %q", got)
	}
	if got := mdCell("a|b\nc"); got != `a\|b c` {
		t.Errorf("special mdCell = %q", got)
	}
}

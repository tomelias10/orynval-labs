package trustproof

import (
	"fmt"
	"strings"

	"github.com/orynval/orynval-labs/internal/redact"
)

// Citation is a single evidence source backing an answer: the file and line it
// came from, plus the redacted passage text that was matched. Snippet is always
// redacted, so a citation is safe to print even though evidence may contain
// secret-shaped material.
type Citation struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"` // redacted, whitespace-normalized passage
}

// Ref renders the "file:line" locator used throughout the outputs.
func (c Citation) Ref() string {
	return fmt.Sprintf("%s:%d", c.File, c.Line)
}

// Result is the drafted outcome for one question. Status is ANSWERED only when
// a grounded, sufficiently confident, unambiguous passage was found; otherwise
// it is UNKNOWN and the question is a gap. Answer is extractive — quoted from
// the cited passage — never generated.
type Result struct {
	Question   string     `json:"question"`
	Status     string     `json:"status"`     // "ANSWERED" or "UNKNOWN"
	Confidence string     `json:"confidence"` // HIGH/MEDIUM/LOW, empty if gap
	Answer     string     `json:"answer"`     // extractive text, empty if gap
	Citations  []Citation `json:"citations"`
	Coverage   float64    `json:"coverage"` // 0..1, retained for auditability
}

// Status values, fixed so every output format and every exit-code check agrees.
const (
	StatusAnswered = "ANSWERED"
	StatusUnknown  = "UNKNOWN"
)

// IsGap reports whether the result is an unanswered question.
func (r Result) IsGap() bool { return r.Status == StatusUnknown }

// answerQuestion scores one question against the corpus and builds its Result.
// It drafts an answer only when the best passage clears minConfidence and is
// not an ambiguous cross-source tie; anything else is an honest UNKNOWN gap.
func answerQuestion(c *corpus, question string, minConfidence Confidence) Result {
	qTerms := termSetOf(tokenize(question))
	m := c.scoreQuestion(qTerms)

	if m.best == -1 {
		return Result{Question: question, Status: StatusUnknown}
	}
	conf := confidenceForCoverage(m.coverage)
	if m.ambiguous || conf < minConfidence || conf == Unknown {
		// Ambiguous across sources, below the bar, or below the floor: report
		// the coverage for auditability but draft nothing.
		return Result{Question: question, Status: StatusUnknown, Coverage: m.coverage}
	}

	p := c.passages[m.best]
	snippet := redactedSnippet(p.Text)
	cite := Citation{File: p.File, Line: p.Line, Snippet: snippet}
	return Result{
		Question:   question,
		Status:     StatusAnswered,
		Confidence: conf.String(),
		Answer:     fmt.Sprintf("Based on %s: %q", cite.Ref(), snippet),
		Citations:  []Citation{cite},
		Coverage:   m.coverage,
	}
}

// redactedSnippet normalizes a passage to a single line and masks any
// secret-shaped material. The whitespace collapse makes the quoted answer
// readable on one line; the redaction is the non-negotiable safety step that
// keeps a leaked token out of the drafted questionnaire.
func redactedSnippet(text string) string {
	normalized := strings.Join(strings.Fields(text), " ")
	return redact.Redact(normalized)
}

// answerAll drafts a Result for every question in order, so the output preserves
// the questionnaire's original sequence.
func answerAll(c *corpus, questions []string, minConfidence Confidence) []Result {
	results := make([]Result, 0, len(questions))
	for _, q := range questions {
		results = append(results, answerQuestion(c, q, minConfidence))
	}
	return results
}

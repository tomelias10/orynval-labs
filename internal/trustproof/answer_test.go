package trustproof

import (
	"os"
	"strings"
	"testing"
)

// fixtureCorpus builds the corpus from the committed synthetic evidence.
func fixtureCorpus(t *testing.T) *corpus {
	t.Helper()
	passages, err := readEvidenceDir("testdata/evidence")
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	return newCorpus(passages)
}

func TestCitationRef(t *testing.T) {
	c := Citation{File: "a/b.md", Line: 12}
	if c.Ref() != "a/b.md:12" {
		t.Errorf("Ref() = %q", c.Ref())
	}
}

func TestResultIsGap(t *testing.T) {
	if !(Result{Status: StatusUnknown}).IsGap() {
		t.Error("UNKNOWN should be a gap")
	}
	if (Result{Status: StatusAnswered}).IsGap() {
		t.Error("ANSWERED should not be a gap")
	}
}

func TestAnswerQuestionGrounded(t *testing.T) {
	c := fixtureCorpus(t)
	r := answerQuestion(c, "How is customer data encrypted at rest?", Medium)
	if r.Status != StatusAnswered || r.Confidence != "HIGH" {
		t.Fatalf("status=%s confidence=%s", r.Status, r.Confidence)
	}
	if len(r.Citations) != 1 || !strings.HasPrefix(r.Citations[0].File, "encryption.md") {
		t.Fatalf("expected encryption.md citation, got %+v", r.Citations)
	}
	// Extractive property: the drafted answer quotes the cited snippet verbatim.
	if !strings.Contains(r.Answer, r.Citations[0].Snippet) {
		t.Errorf("answer is not extractive from its citation:\n%s", r.Answer)
	}
}

func TestAnswerQuestionMissingIsGap(t *testing.T) {
	c := fixtureCorpus(t)
	r := answerQuestion(c, "Do you offer a public bug bounty program with monetary rewards?", Medium)
	if !r.IsGap() {
		t.Errorf("unsupported question should be a gap, got %+v", r)
	}
	if r.Answer != "" || len(r.Citations) != 0 || r.Confidence != "" {
		t.Errorf("a gap must draft nothing, got %+v", r)
	}
}

func TestAnswerQuestionAmbiguousIsGap(t *testing.T) {
	c := fixtureCorpus(t)
	// The vendor-risk sentence is identical in two files: an ambiguous tie, so
	// it is a gap despite high overlap.
	r := answerQuestion(c, "Are vendor risk assessments performed for all subprocessors?", Low)
	if !r.IsGap() {
		t.Errorf("ambiguous cross-file match should be a gap, got %+v", r)
	}
	if r.Coverage <= 0 {
		t.Errorf("ambiguous gap should still report coverage, got %v", r.Coverage)
	}
}

func TestAnswerQuestionNoScorableTermsIsGap(t *testing.T) {
	c := fixtureCorpus(t)
	r := answerQuestion(c, "the a an it is", Low)
	if !r.IsGap() || r.Coverage != 0 {
		t.Errorf("termless question should be a zero-coverage gap, got %+v", r)
	}
}

func TestAnswerQuestionMinConfidenceDemotes(t *testing.T) {
	c := fixtureCorpus(t)
	q := "How often are backups tested and restored?"
	if r := answerQuestion(c, q, Medium); r.Status != StatusAnswered {
		t.Fatalf("expected ANSWERED at medium bar, got %+v", r)
	}
	// Raising the bar to HIGH turns the MEDIUM-confidence backup answer into a
	// gap.
	if r := answerQuestion(c, q, High); !r.IsGap() {
		t.Errorf("expected gap at high bar, got %+v", r)
	}
}

func TestAnswerAllPreservesOrderAndRedacts(t *testing.T) {
	c := fixtureCorpus(t)
	qs := []string{
		"How is customer data encrypted at rest?",
		"How often are backups tested and restored?",
	}
	results := answerAll(c, qs, Medium)
	if len(results) != 2 || results[0].Question != qs[0] || results[1].Question != qs[1] {
		t.Fatalf("order not preserved: %+v", results)
	}
	// The backup passage embeds a secret-shaped token; it must be masked
	// everywhere it surfaces.
	if strings.Contains(results[1].Answer, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("secret leaked into answer: %s", results[1].Answer)
	}
	if !strings.Contains(results[1].Answer, "ghp_****") {
		t.Errorf("expected redacted token in answer: %s", results[1].Answer)
	}
}

func TestRedactedSnippetIsSubstringOfRedactedEvidence(t *testing.T) {
	// No-hallucination guarantee: every answered snippet is a verbatim,
	// whitespace-normalized substring of its cited source file (after the same
	// redaction), so nothing in an answer is invented.
	c := fixtureCorpus(t)
	for _, p := range c.passages {
		r := answerQuestion(c, p.Text, Low)
		if r.IsGap() {
			continue
		}
		cite := r.Citations[0]
		raw, err := os.ReadFile("testdata/evidence/" + cite.File)
		if err != nil {
			t.Fatalf("read source: %v", err)
		}
		sourceNormalized := redactedSnippet(string(raw))
		if !strings.Contains(sourceNormalized, cite.Snippet) {
			t.Errorf("snippet %q not found in redacted source %s", cite.Snippet, cite.File)
		}
	}
}

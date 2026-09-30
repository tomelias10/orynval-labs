package trustproof

import "testing"

func TestConfidenceString(t *testing.T) {
	cases := map[Confidence]string{
		High: "HIGH", Medium: "MEDIUM", Low: "LOW", Unknown: "UNKNOWN",
		Confidence(99): "UNKNOWN",
	}
	for c, want := range cases {
		if got := c.String(); got != want {
			t.Errorf("Confidence(%d).String() = %q, want %q", c, got, want)
		}
	}
}

func TestConfidenceForCoverage(t *testing.T) {
	cases := []struct {
		coverage float64
		want     Confidence
	}{
		{0.90, High}, {0.60, High},
		{0.59, Medium}, {0.35, Medium},
		{0.34, Low}, {0.20, Low},
		{0.19, Unknown}, {0.0, Unknown},
	}
	for _, c := range cases {
		if got := confidenceForCoverage(c.coverage); got != c.want {
			t.Errorf("confidenceForCoverage(%v) = %v, want %v", c.coverage, got, c.want)
		}
	}
}

func TestParseMinConfidence(t *testing.T) {
	cases := []struct {
		in   string
		want Confidence
		ok   bool
	}{
		{"high", High, true},
		{"medium", Medium, true},
		{"low", Low, true},
		{"nonsense", Unknown, false},
		{"", Unknown, false},
	}
	for _, c := range cases {
		got, ok := parseMinConfidence(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseMinConfidence(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestIDFOfFallbackForAbsentTerm(t *testing.T) {
	c := newCorpus(splitPassages("f.txt", "alpha beta"))
	present := c.idfOf("alpha")
	absent := c.idfOf("zeta") // never seen: df 0
	if present <= 0 || absent <= 0 {
		t.Fatalf("idf must be positive: present=%v absent=%v", present, absent)
	}
	// An unseen term (df 0) has the highest possible weight, above a term seen
	// in every passage.
	if absent <= present {
		t.Errorf("absent-term idf %v should exceed present-term idf %v", absent, present)
	}
}

func TestScoreQuestionNoScorableTerms(t *testing.T) {
	c := newCorpus(splitPassages("f.txt", "alpha beta gamma"))
	// A question of only stopwords/short tokens tokenizes to nothing, so denom
	// is zero and there is no best passage.
	m := c.scoreQuestion(termSetOf(tokenize("the a an it is")))
	if m.best != -1 {
		t.Errorf("expected no best passage, got %d", m.best)
	}
}

func TestScoreQuestionStrictlyBetterLaterPassage(t *testing.T) {
	// Two passages in one file both contain "term"; the second is shorter, so
	// its length-normalized score is strictly higher and it wins even though it
	// is visited second. A non-matching third passage exercises the skip path.
	c := newCorpus(splitPassages("f.txt", "term extra extra extra extra\n\nterm\n\nnothing here"))
	m := c.scoreQuestion(termSetOf(tokenize("term")))
	if m.best != 1 {
		t.Fatalf("expected passage 1 to win, got %d", m.best)
	}
	if m.ambiguous {
		t.Errorf("same-file win should not be ambiguous")
	}
}

func TestScoreQuestionSameFileTieNotAmbiguous(t *testing.T) {
	// Identical blocks in the same file tie exactly; a same-file tie is fine to
	// cite, so it is not flagged ambiguous.
	c := newCorpus(splitPassages("f.txt", "term other\n\nterm other"))
	m := c.scoreQuestion(termSetOf(tokenize("term other")))
	if m.best != 0 {
		t.Fatalf("expected first passage to win, got %d", m.best)
	}
	if m.ambiguous {
		t.Errorf("same-file tie should not be ambiguous")
	}
}

func TestScoreQuestionCrossFileTieAmbiguous(t *testing.T) {
	// The identical passage in two different files is an ambiguous tie: the tool
	// cannot honestly pick one source.
	passages := append(
		splitPassages("f1.txt", "term other"),
		splitPassages("f2.txt", "term other")...,
	)
	c := newCorpus(passages)
	m := c.scoreQuestion(termSetOf(tokenize("term other")))
	if !m.ambiguous {
		t.Errorf("cross-file tie should be ambiguous")
	}
}

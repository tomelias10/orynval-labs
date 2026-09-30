// Package trustproof answers security questionnaires from a corpus of
// already-approved local evidence. It maps each question to explicit evidence
// passages, drafts an answer only when that answer is grounded in a cited
// passage, and marks everything else UNKNOWN. It is the engine behind the
// trust-proof command.
//
// Like the rest of the toolkit it is local-first, offline, and deterministic:
// it never opens the network, never uploads anything, never calls an LLM, and
// emits no timestamps or randomness. The same questionnaire and the same
// evidence produce byte-for-byte identical answers, scores, and citations on
// any machine.
//
// The safety posture is explicit:
//
//   - No hallucinated claims. Every drafted answer is extractive — quoted from
//     a cited evidence passage — never generated.
//   - UNKNOWN over wrong. If evidence does not clear the confidence bar, or two
//     sources tie ambiguously, the question is a gap rather than a guess.
//   - No auto-certification. Output is labeled a draft for a human to approve.
//   - Secrets in evidence are redacted before they appear in any output.
package trustproof

import "math"

// Confidence thresholds on coverage (the fraction of a question's total term
// weight that the matched passage actually covers). They are the single knob
// that turns a numeric overlap into an honest HIGH / MEDIUM / LOW / gap
// judgement, and they are documented in the trust-proof spec.
const (
	coverageHigh   = 0.60
	coverageMedium = 0.35
	coverageLow    = 0.20
)

// ambiguityEpsilon is how close two passage scores must be, when the passages
// come from different evidence files, to count as an ambiguous tie. An
// ambiguous tie means the tool cannot honestly cite a single source, so the
// question becomes a gap even if coverage is high.
const ambiguityEpsilon = 1e-9

// Confidence is the qualitative strength of a drafted answer.
type Confidence int

// Confidence levels, ordered so a higher value is a stronger match. Unknown is
// the zero value so an unmatched question is UNKNOWN by default.
const (
	Unknown Confidence = iota // no grounded answer: a gap
	Low
	Medium
	High
)

// String renders a Confidence as the stable label used in every output format.
func (c Confidence) String() string {
	switch c {
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	case Low:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// confidenceForCoverage maps a coverage fraction to a Confidence using the
// documented thresholds.
func confidenceForCoverage(coverage float64) Confidence {
	switch {
	case coverage >= coverageHigh:
		return High
	case coverage >= coverageMedium:
		return Medium
	case coverage >= coverageLow:
		return Low
	default:
		return Unknown
	}
}

// parseMinConfidence resolves the --min-confidence flag to the lowest
// Confidence that still counts as an answer. It rejects anything else so a
// typo can never silently lower the safety bar.
func parseMinConfidence(s string) (Confidence, bool) {
	switch s {
	case "high":
		return High, true
	case "medium":
		return Medium, true
	case "low":
		return Low, true
	default:
		return Unknown, false
	}
}

// corpus is the searchable form of the evidence: the passages plus the inverse
// document frequency of every term that appears in them. It is built once per
// run and then queried per question.
type corpus struct {
	passages []passage
	idf      map[string]float64
	// n is the passage count, cached for idf of terms absent from the corpus.
	n int
}

// newCorpus indexes passages: it computes each term's document frequency across
// passages and turns that into a smoothed idf. Rarer terms get more weight, so
// boilerplate words cannot carry a match on their own.
func newCorpus(passages []passage) *corpus {
	df := make(map[string]int)
	for i := range passages {
		for term := range passages[i].termSet {
			df[term]++
		}
	}
	n := len(passages)
	idf := make(map[string]float64, len(df))
	for term, count := range df {
		idf[term] = smoothedIDF(n, count)
	}
	return &corpus{passages: passages, idf: idf, n: n}
}

// smoothedIDF returns ln(1 + n/(1+df)). The +1 keeps it finite for a term that
// appears in no passage (df 0), and the outer +1 keeps it positive for a term
// that appears in every passage, so every term contributes some weight while
// common terms contribute little.
func smoothedIDF(n, df int) float64 {
	return math.Log(1 + float64(n)/float64(1+df))
}

// idfOf returns the idf weight of a term, falling back to the weight of a term
// absent from the corpus (df 0) so a question term that matches nothing still
// counts against its own coverage.
func (c *corpus) idfOf(term string) float64 {
	if v, ok := c.idf[term]; ok {
		return v
	}
	return smoothedIDF(c.n, 0)
}

// match is the outcome of scoring one question against the corpus: the best
// passage, how well it covers the question, and whether the top result is an
// ambiguous tie across sources.
type match struct {
	best      int     // index into corpus.passages, or -1 if nothing scored
	coverage  float64 // matched question weight / total question weight
	score     float64 // length-normalized idf overlap of the best passage
	ambiguous bool    // a different-file passage tied the best score
}

// scoreQuestion finds the passage that best supports a question. It scores
// every passage by the length-normalized sum of shared-term idf, picks the
// highest (ties broken by passage order for determinism), and measures how much
// of the question's total term weight that passage covers. It also flags the
// case where a passage from a different file ties the winner, which is reported
// as ambiguous and handled as a gap.
func (c *corpus) scoreQuestion(qTerms map[string]struct{}) match {
	denom := 0.0
	for term := range qTerms {
		denom += c.idfOf(term)
	}
	result := match{best: -1}
	if denom == 0 {
		// A question with no scorable terms (all stopwords/punctuation) can
		// never be grounded; report it as a gap.
		return result
	}

	for i := range c.passages {
		p := &c.passages[i]
		matched := 0.0
		for term := range qTerms {
			if _, ok := p.termSet[term]; ok {
				matched += c.idfOf(term)
			}
		}
		if matched == 0 {
			continue
		}
		score := matched / p.lengthNorm
		switch {
		case result.best == -1 || score > result.score+ambiguityEpsilon:
			// Strictly better: adopt it and clear any earlier tie.
			result.best = i
			result.score = score
			result.coverage = matched / denom
			result.ambiguous = false
		case math.Abs(score-result.score) <= ambiguityEpsilon:
			// A tie: ambiguous only when it comes from a different file, since
			// two passages in the same file citing the same thing is fine.
			if c.passages[i].File != c.passages[result.best].File {
				result.ambiguous = true
			}
		}
	}
	return result
}

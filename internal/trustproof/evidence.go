package trustproof

import (
	"math"
	"os"
	"strings"
	"unicode"

	"github.com/orynval/orynval-labs/internal/walk"
)

// stopwords are common English function words dropped before matching so that
// overlap reflects meaningful content terms, not grammar. The set is
// deliberately small: a larger list risks discarding words that matter in
// security prose (for example "access" or "control").
var stopwords = map[string]struct{}{
	"a": {}, "an": {}, "and": {}, "are": {}, "as": {}, "at": {}, "be": {},
	"by": {}, "do": {}, "does": {}, "for": {}, "from": {}, "has": {}, "have": {},
	"how": {}, "in": {}, "is": {}, "it": {}, "its": {}, "of": {}, "on": {},
	"or": {}, "our": {}, "that": {}, "the": {}, "their": {}, "to": {}, "we": {},
	"what": {}, "when": {}, "which": {}, "will": {}, "with": {}, "you": {},
	"your": {}, "if": {}, "any": {}, "all": {}, "can": {}, "this": {}, "these": {},
}

// tokenize splits text into lowercased alphanumeric terms, dropping stopwords
// and single-character tokens. It is the one place raw text becomes matchable
// terms, so questions and passages are always compared on identical footing.
func tokenize(text string) []string {
	fields := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) < 2 {
			continue
		}
		if _, skip := stopwords[f]; skip {
			continue
		}
		out = append(out, f)
	}
	return out
}

// termSetOf reduces a token slice to the set of distinct terms, which is what
// coverage and document-frequency both count.
func termSetOf(tokens []string) map[string]struct{} {
	set := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		set[t] = struct{}{}
	}
	return set
}

// passage is one paragraph-sized block of evidence, tagged with the file and
// 1-based starting line it came from so every answer can cite an exact source.
type passage struct {
	File       string              // path relative to the evidence root
	Line       int                 // 1-based line where the block starts
	Text       string              // original (un-redacted) block text
	termSet    map[string]struct{} // distinct content terms, for matching
	lengthNorm float64             // sqrt(token count), to penalize long blocks
}

// splitPassages breaks a document into paragraph blocks separated by blank
// lines, recording each block's starting line. Blocks with no content terms are
// dropped: they can never ground an answer and would only add noise to the
// corpus. rel is the block's source path, carried onto every passage for
// citations.
func splitPassages(rel, content string) []passage {
	lines := strings.Split(content, "\n")
	var passages []passage
	var block []string
	blockStart := 0

	flush := func() {
		if len(block) == 0 {
			return
		}
		text := strings.TrimRight(strings.Join(block, "\n"), "\n")
		block = nil
		tokens := tokenize(text)
		if len(tokens) == 0 {
			return
		}
		passages = append(passages, passage{
			File:       rel,
			Line:       blockStart,
			Text:       text,
			termSet:    termSetOf(tokens),
			lengthNorm: math.Sqrt(float64(len(tokens))),
		})
	}

	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if len(block) == 0 {
			blockStart = i + 1 // 1-based line number of the block's first line
		}
		block = append(block, line)
	}
	flush()
	return passages
}

// buildPassages walks an evidence tree and turns every text file into passages.
// It takes the walk and read functions as parameters so the read-error path is
// testable without a real unreadable file; readEvidenceDir wires in the real
// walker and os.ReadFile.
func buildPassages(
	walkFn func(func(abs, rel string) error) error,
	readFile func(string) ([]byte, error),
) ([]passage, error) {
	var passages []passage
	err := walkFn(func(abs, rel string) error {
		data, err := readFile(abs)
		if err != nil {
			return err
		}
		passages = append(passages, splitPassages(rel, string(data))...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return passages, nil
}

// readEvidenceDir loads all approved evidence under dir into passages using the
// shared safe walker (read-only, no symlinks, skips binaries and oversized
// files). The walk order is lexical, so the resulting corpus — and therefore
// every score and citation — is deterministic.
func readEvidenceDir(dir string) ([]passage, error) {
	w, err := walk.New(dir, walk.Options{})
	if err != nil {
		return nil, err
	}
	return buildPassages(w.Walk, os.ReadFile)
}

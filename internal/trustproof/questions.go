package trustproof

import (
	"bytes"
	"encoding/csv"
	"path/filepath"
	"regexp"
	"strings"
)

// parseQuestions extracts the list of questions from a questionnaire file. The
// format is chosen by the file extension: .csv is a spreadsheet export,
// .md/.markdown is a Markdown list, anything else is treated as one question
// per line. name is only used for its extension; data is the file content.
func parseQuestions(name string, data []byte) ([]string, error) {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".csv":
		return parseCSVQuestions(data)
	case ".md", ".markdown":
		return parseMarkdownQuestions(data), nil
	default:
		return parseTextQuestions(data), nil
	}
}

// parseTextQuestions treats every non-empty, trimmed line as one question.
func parseTextQuestions(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if q := strings.TrimSpace(line); q != "" {
			out = append(out, q)
		}
	}
	return out
}

// parseCSVQuestions reads questions from the first column of a CSV export,
// skipping a header row when the first cell looks like a column label rather
// than a question. Variable field counts are allowed so exports with trailing
// note columns still parse.
func parseCSVQuestions(data []byte) ([]string, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	var out []string
	for i, rec := range records {
		// csv.ReadAll never yields a zero-field record (blank lines are
		// skipped), so rec[0] is always present here.
		cell := strings.TrimSpace(rec[0])
		if cell == "" {
			continue
		}
		if i == 0 && isHeaderCell(cell) {
			continue // drop the auto-detected header row
		}
		out = append(out, cell)
	}
	return out, nil
}

// headerLabels are the first-column values that mark a spreadsheet header row
// rather than a real question. Matched case-insensitively against the trimmed
// first cell.
var headerLabels = map[string]struct{}{
	"question": {}, "questions": {}, "query": {}, "prompt": {},
	"item": {}, "control": {}, "requirement": {},
}

// isHeaderCell reports whether a first cell is a header label. A real question
// virtually always ends with "?" or is a full sentence, so only an exact,
// short label match is treated as a header — this never eats a real question.
func isHeaderCell(cell string) bool {
	_, ok := headerLabels[strings.ToLower(cell)]
	return ok
}

// mdMarker strips a leading Markdown list marker (-, *, +, or an ordered "1." /
// "1)") so the question text is captured without its bullet.
var mdMarker = regexp.MustCompile(`^\s*(?:[-*+]|\d+[.)])\s+`)

// parseMarkdownQuestions pulls questions out of a Markdown document: each
// non-empty line becomes a question after its list marker is stripped, while
// headings and horizontal rules are skipped as structure, not content.
func parseMarkdownQuestions(data []byte) []string {
	var out []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || isHorizontalRule(line) {
			continue
		}
		// After a non-blank line has its list marker (marker + required
		// whitespace) removed, at least one content rune always remains, so the
		// result is never empty here.
		out = append(out, strings.TrimSpace(mdMarker.ReplaceAllString(line, "")))
	}
	return out
}

// isHorizontalRule reports whether a line is a Markdown thematic break (--- or
// ***), which is layout rather than a question.
func isHorizontalRule(line string) bool {
	if len(line) < 3 {
		return false
	}
	return strings.Trim(line, "-") == "" || strings.Trim(line, "*") == ""
}

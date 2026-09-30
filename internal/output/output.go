// Package output renders a scan's findings into every supported presentation:
// a human terminal view, JSON, SARIF 2.1.0, a self-contained HTML report, an
// SVG status badge, and a portable offline "share" blob.
//
// Every renderer is deterministic: given the same Report it emits byte-for-byte
// identical output on any machine, with no timestamps, no clock, no randomness,
// and no network. Findings are sorted with core.SortFindings and every evidence
// snippet is passed through redact.Redact as defense in depth, so no renderer
// can leak a raw secret even if a rule forgot to mask one.
package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tomelias10/orynval-labs/internal/core"
	"github.com/tomelias10/orynval-labs/internal/redact"
)

// ToolInfo identifies the tool that produced a report. It is embedded in every
// format so a reader knows the origin and version. It carries no timestamp.
type ToolInfo struct {
	Name           string
	Version        string
	InformationURI string // optional homepage, used by SARIF/HTML
}

// RuleDoc is optional metadata about a registered rule, used to enrich SARIF and
// HTML output. The CLI populates it from the registry; renderers work without
// it (they fall back to the rule IDs carried on findings).
type RuleDoc struct {
	ID          string
	Name        string
	Description string
}

// Report is the complete, render-ready result of a scan.
type Report struct {
	Tool     ToolInfo
	Rules    []RuleDoc // metadata for registered rules (any order; sorted on render)
	Findings []core.Finding
}

// Options tune a single render. Only the terminal renderer consults Color; the
// machine-readable formats ignore it so their output stays deterministic.
type Options struct {
	Color bool
}

// Summary is the per-severity tally shown at the top of every report. Field
// order is fixed (most to least severe) so JSON and HTML render stably.
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

func summarize(fs []core.Finding) Summary {
	c := core.CountBySeverity(fs)
	return Summary{
		Total:    len(fs),
		Critical: c[core.SeverityCritical],
		High:     c[core.SeverityHigh],
		Medium:   c[core.SeverityMedium],
		Low:      c[core.SeverityLow],
		Info:     c[core.SeverityInfo],
	}
}

// Format names a supported output format.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatJSON     Format = "json"
	FormatSARIF    Format = "sarif"
	FormatHTML     Format = "html"
	FormatBadge    Format = "badge"
	FormatShare    Format = "share"
)

// Formats lists every supported format in a stable order (for help text and
// validation).
var Formats = []Format{
	FormatTerminal, FormatJSON, FormatSARIF, FormatHTML, FormatBadge, FormatShare,
}

// ParseFormat parses a case-insensitive format name.
func ParseFormat(s string) (Format, error) {
	f := Format(strings.ToLower(strings.TrimSpace(s)))
	for _, known := range Formats {
		if f == known {
			return f, nil
		}
	}
	names := make([]string, len(Formats))
	for i, k := range Formats {
		names[i] = string(k)
	}
	return "", fmt.Errorf("output: invalid format %q (want one of %s)", s, strings.Join(names, ", "))
}

// Render writes r to w in format f. It is the single dispatch point used by the
// CLI.
func Render(w io.Writer, f Format, r Report, opts Options) error {
	switch f {
	case FormatTerminal:
		return RenderTerminal(w, r, opts)
	case FormatJSON:
		return RenderJSON(w, r)
	case FormatSARIF:
		return RenderSARIF(w, r)
	case FormatHTML:
		return RenderHTML(w, r)
	case FormatBadge:
		return RenderBadge(w, r)
	case FormatShare:
		return RenderShare(w, r)
	default:
		return fmt.Errorf("output: unsupported format %q", f)
	}
}

// normalized returns a deterministic, safe-to-render copy of the report:
// findings sorted, rules sorted by ID, and every evidence snippet re-redacted.
// It never mutates the caller's slices.
func (r Report) normalized() Report {
	fs := make([]core.Finding, 0, len(r.Findings))
	fs = append(fs, r.Findings...)
	core.SortFindings(fs)
	for i := range fs {
		src := fs[i].Evidence
		ev := make([]core.Evidence, len(src))
		for j, e := range src {
			e.Snippet = redact.Redact(e.Snippet)
			ev[j] = e
		}
		fs[i].Evidence = ev
	}

	rules := make([]RuleDoc, len(r.Rules))
	copy(rules, r.Rules)
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	r.Findings = fs
	r.Rules = rules
	return r
}

// ruleDocByID indexes rule metadata for quick lookup during rendering.
func (r Report) ruleDocByID() map[string]RuleDoc {
	m := make(map[string]RuleDoc, len(r.Rules))
	for _, rd := range r.Rules {
		m[rd.ID] = rd
	}
	return m
}

// distinctRuleIDs returns the sorted union of rule IDs from Rules metadata and
// from the findings themselves, so every result can reference a rule entry.
func (r Report) distinctRuleIDs() []string {
	seen := make(map[string]struct{})
	for _, rd := range r.Rules {
		seen[rd.ID] = struct{}{}
	}
	for _, f := range r.Findings {
		if f.RuleID != "" {
			seen[f.RuleID] = struct{}{}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

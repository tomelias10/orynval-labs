package output

import (
	"encoding/json"
	"io"

	"github.com/orynval/orynval-labs/internal/core"
)

// SARIF 2.1.0 output. The schema is static and no run timestamps are emitted,
// so the document is byte-for-byte stable for a given report.

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"
const sarifVersion = "2.1.0"

// fingerprintKey namespaces our partial fingerprint so viewers can match a
// result across runs even as line numbers shift.
const fingerprintKey = "orynval/v1"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name,omitempty"`
	ShortDescription     *sarifMessage     `json:"shortDescription,omitempty"`
	FullDescription      *sarifMessage     `json:"fullDescription,omitempty"`
	DefaultConfiguration *sarifConfig      `json:"defaultConfiguration,omitempty"`
	Properties           map[string]string `json:"properties,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// sarifLevel maps a severity to a SARIF result level.
func sarifLevel(s core.Severity) string {
	switch s {
	case core.SeverityCritical, core.SeverityHigh:
		return "error"
	case core.SeverityMedium:
		return "warning"
	default: // LOW, INFO, unknown
		return "note"
	}
}

// securitySeverity maps a severity to the numeric score GitHub code scanning
// reads from a rule's properties.
func securitySeverity(s core.Severity) string {
	switch s {
	case core.SeverityCritical:
		return "9.0"
	case core.SeverityHigh:
		return "7.0"
	case core.SeverityMedium:
		return "5.0"
	case core.SeverityLow:
		return "3.0"
	default:
		return "1.0"
	}
}

// RenderSARIF writes the report as SARIF 2.1.0 JSON.
func RenderSARIF(w io.Writer, r Report) error {
	r = r.normalized()

	ids := r.distinctRuleIDs()
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		index[id] = i
	}

	// Highest severity seen per rule, to drive defaultConfiguration.level and
	// the rule-level security-severity property.
	maxSev := make(map[string]core.Severity)
	for _, f := range r.Findings {
		if cur, ok := maxSev[f.RuleID]; !ok || f.Severity.Rank() > cur.Rank() {
			maxSev[f.RuleID] = f.Severity
		}
	}

	docs := r.ruleDocByID()
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		sr := sarifRule{ID: id}
		if rd, ok := docs[id]; ok {
			sr.Name = rd.Name
			if rd.Name != "" {
				sr.ShortDescription = &sarifMessage{Text: rd.Name}
			}
			if rd.Description != "" {
				sr.FullDescription = &sarifMessage{Text: rd.Description}
			}
		}
		if sev, ok := maxSev[id]; ok {
			sr.DefaultConfiguration = &sarifConfig{Level: sarifLevel(sev)}
			sr.Properties = map[string]string{"security-severity": securitySeverity(sev)}
		}
		rules = append(rules, sr)
	}

	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		res := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: index[f.RuleID],
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: sarifMessageText(f)},
			Properties: map[string]string{
				"severity":   string(f.Severity),
				"confidence": string(f.Confidence),
			},
		}
		if f.Fingerprint != "" {
			res.PartialFingerprints = map[string]string{fingerprintKey: f.Fingerprint}
		}
		for _, e := range f.Evidence {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: e.File},
				},
			}
			if e.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: e.Line}
			}
			res.Locations = append(res.Locations, loc)
		}
		results = append(results, res)
	}

	doc := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           r.Tool.Name,
				Version:        r.Tool.Version,
				InformationURI: r.Tool.InformationURI,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

// sarifMessageText composes a concise, deterministic result message from a
// finding's headline and its "what" explanation.
func sarifMessageText(f core.Finding) string {
	if f.What == "" {
		return f.Title
	}
	if f.Title == "" {
		return f.What
	}
	return f.Title + ": " + f.What
}

// Package core defines the shared vocabulary for every Orynval Labs detector:
// severities, confidences, evidence, findings, the Rule interface, the scan
// Context, and the Registry. It is deliberately dependency-light so that every
// downstream tool (secrets, config, dependency scanners, ...) speaks the same
// finding format and produces byte-for-byte deterministic output.
//
// Safety posture of this package: it never opens the network, never emits
// telemetry, and never records timestamps. Fingerprints and rendered output
// are stable across runs and across machines given the same input tree.
package core

import (
	"fmt"
	"strings"
)

// Severity ranks the impact of a finding, from CRITICAL (most severe) down to
// INFO. The zero value is intentionally invalid so an unset severity is caught
// rather than silently treated as INFO.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// severityRank orders severities for threshold comparisons. Higher is more
// severe. Kept private so callers compare via Rank / AtLeast rather than magic
// numbers.
var severityRank = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Severities lists every severity from most to least severe. Useful for stable
// iteration (summaries, tables) without re-sorting a map.
var Severities = []Severity{
	SeverityCritical,
	SeverityHigh,
	SeverityMedium,
	SeverityLow,
	SeverityInfo,
}

// Valid reports whether s is one of the known severities.
func (s Severity) Valid() bool {
	_, ok := severityRank[s]
	return ok
}

// Rank returns the ordinal used for threshold comparisons. An unknown severity
// ranks below INFO (-1) so it never accidentally trips a --fail-on gate.
func (s Severity) Rank() int {
	if r, ok := severityRank[s]; ok {
		return r
	}
	return -1
}

// AtLeast reports whether s is at least as severe as threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return s.Rank() >= threshold.Rank()
}

// String returns the canonical uppercase name.
func (s Severity) String() string { return string(s) }

// ParseSeverity parses a case-insensitive severity name.
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(strings.ToUpper(strings.TrimSpace(s)))
	if !sev.Valid() {
		return "", fmt.Errorf("core: invalid severity %q (want one of CRITICAL, HIGH, MEDIUM, LOW, INFO)", s)
	}
	return sev, nil
}

// Confidence expresses how sure a rule is that a finding is a true positive.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

var confidenceRank = map[Confidence]int{
	ConfidenceLow:    0,
	ConfidenceMedium: 1,
	ConfidenceHigh:   2,
}

// Valid reports whether c is one of the known confidences.
func (c Confidence) Valid() bool {
	_, ok := confidenceRank[c]
	return ok
}

// Rank returns the ordinal for confidence comparisons.
func (c Confidence) Rank() int {
	if r, ok := confidenceRank[c]; ok {
		return r
	}
	return -1
}

// String returns the canonical uppercase name.
func (c Confidence) String() string { return string(c) }

// ParseConfidence parses a case-insensitive confidence name.
func ParseConfidence(s string) (Confidence, error) {
	c := Confidence(strings.ToUpper(strings.TrimSpace(s)))
	if !c.Valid() {
		return "", fmt.Errorf("core: invalid confidence %q (want one of HIGH, MEDIUM, LOW)", s)
	}
	return c, nil
}

// EvidenceKind labels how a piece of evidence was established. This keeps the
// tool honest: OBSERVED is a fact read from a file, INFERRED is a deduction,
// and UNKNOWN marks something the tool could not verify. Renderers surface this
// so a reader can weigh each claim.
type EvidenceKind string

const (
	// KindObserved marks evidence read directly from the target tree.
	KindObserved EvidenceKind = "OBSERVED"
	// KindInferred marks a conclusion derived from observed facts.
	KindInferred EvidenceKind = "INFERRED"
	// KindUnknown marks something the tool could not confirm.
	KindUnknown EvidenceKind = "UNKNOWN"
)

// Valid reports whether k is one of the known evidence kinds.
func (k EvidenceKind) Valid() bool {
	switch k {
	case KindObserved, KindInferred, KindUnknown:
		return true
	default:
		return false
	}
}

// String returns the canonical uppercase name.
func (k EvidenceKind) String() string { return string(k) }

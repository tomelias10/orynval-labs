package core

import (
	"path/filepath"
	"testing"
)

func TestContextMaxEvidence(t *testing.T) {
	ctx := NewContext("/root", nil, Options{MaxEvidence: 7})
	if got := ctx.MaxEvidence(); got != 7 {
		t.Errorf("MaxEvidence = %d, want 7", got)
	}
	// Zero means unlimited and must be reported verbatim.
	if got := NewContext("/root", nil, Options{}).MaxEvidence(); got != 0 {
		t.Errorf("default MaxEvidence = %d, want 0", got)
	}
}

func TestContextWalkNilWalkerIsNoop(t *testing.T) {
	ctx := NewContext("/root", nil, Options{})
	called := false
	if err := ctx.Walk(func(File) error { called = true; return nil }); err != nil {
		t.Fatalf("Walk with nil walker: %v", err)
	}
	if called {
		t.Error("callback should not run when there is no walker")
	}
}

func TestContextReadErrorOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	ctx := NewContext(dir, nil, Options{})
	f := File{Abs: filepath.Join(dir, "does-not-exist"), Rel: "does-not-exist"}
	if _, err := ctx.Read(f); err == nil {
		t.Error("expected error reading a missing file")
	}
}

func TestContextLinesErrorOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	ctx := NewContext(dir, nil, Options{})
	f := File{Abs: filepath.Join(dir, "nope"), Rel: "nope"}
	if _, err := ctx.Lines(f); err == nil {
		t.Error("expected error from Lines on a missing file")
	}
}

// TestSortFindingsTiebreakers exercises every tiebreaker branch of the
// comparator: same severity but differing RuleID, then Where, then Title.
func TestSortFindingsTiebreakers(t *testing.T) {
	// Differ only by RuleID (same severity).
	byRule := []Finding{
		{RuleID: "b", Severity: SeverityHigh, Where: "w", Title: "t", Fingerprint: "f"},
		{RuleID: "a", Severity: SeverityHigh, Where: "w", Title: "t", Fingerprint: "f"},
	}
	SortFindings(byRule)
	if byRule[0].RuleID != "a" {
		t.Errorf("RuleID tiebreak failed: %s first", byRule[0].RuleID)
	}

	// Differ only by Where (same severity and RuleID).
	byWhere := []Finding{
		{RuleID: "a", Severity: SeverityHigh, Where: "z", Title: "t", Fingerprint: "f"},
		{RuleID: "a", Severity: SeverityHigh, Where: "a", Title: "t", Fingerprint: "f"},
	}
	SortFindings(byWhere)
	if byWhere[0].Where != "a" {
		t.Errorf("Where tiebreak failed: %s first", byWhere[0].Where)
	}

	// Differ only by Title (same severity, RuleID, Where).
	byTitle := []Finding{
		{RuleID: "a", Severity: SeverityHigh, Where: "w", Title: "zeta", Fingerprint: "f"},
		{RuleID: "a", Severity: SeverityHigh, Where: "w", Title: "alpha", Fingerprint: "f"},
	}
	SortFindings(byTitle)
	if byTitle[0].Title != "alpha" {
		t.Errorf("Title tiebreak failed: %s first", byTitle[0].Title)
	}
}

func TestRegistryEmptyIDPanics(t *testing.T) {
	reg := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Error("expected panic on empty rule ID")
		}
	}()
	reg.Register(staticRule{id: ""})
}

func TestSeverityString(t *testing.T) {
	if SeverityCritical.String() != "CRITICAL" {
		t.Errorf("Severity.String = %q", SeverityCritical.String())
	}
}

func TestConfidenceRankAndString(t *testing.T) {
	if ConfidenceHigh.Rank() != 2 || ConfidenceMedium.Rank() != 1 || ConfidenceLow.Rank() != 0 {
		t.Errorf("unexpected confidence ranks: %d %d %d",
			ConfidenceHigh.Rank(), ConfidenceMedium.Rank(), ConfidenceLow.Rank())
	}
	// An unknown confidence ranks below LOW.
	if Confidence("NOPE").Rank() != -1 {
		t.Errorf("unknown confidence rank = %d, want -1", Confidence("NOPE").Rank())
	}
	if ConfidenceHigh.String() != "HIGH" {
		t.Errorf("Confidence.String = %q", ConfidenceHigh.String())
	}
}

func TestEvidenceKindString(t *testing.T) {
	if KindObserved.String() != "OBSERVED" {
		t.Errorf("EvidenceKind.String = %q", KindObserved.String())
	}
}

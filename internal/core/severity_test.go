package core

import "testing"

func TestSeverityRankOrdering(t *testing.T) {
	order := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if order[i-1].Rank() >= order[i].Rank() {
			t.Fatalf("expected %s to rank below %s", order[i-1], order[i])
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SeverityCritical.AtLeast(SeverityLow) {
		t.Error("CRITICAL should be at least LOW")
	}
	if SeverityInfo.AtLeast(SeverityLow) {
		t.Error("INFO should not be at least LOW")
	}
	if !SeverityMedium.AtLeast(SeverityMedium) {
		t.Error("MEDIUM should be at least MEDIUM")
	}
}

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"critical": SeverityCritical,
		"HIGH":     SeverityHigh,
		" medium ": SeverityMedium,
		"Low":      SeverityLow,
		"info":     SeverityInfo,
	}
	for in, want := range cases {
		got, err := ParseSeverity(in)
		if err != nil {
			t.Errorf("ParseSeverity(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseSeverity(%q) = %s, want %s", in, got, want)
		}
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestUnknownSeverityRanksBelowInfo(t *testing.T) {
	var s Severity = "NONSENSE"
	if s.Valid() {
		t.Fatal("unexpected valid")
	}
	if s.AtLeast(SeverityInfo) {
		t.Error("an unknown severity must not satisfy a threshold of INFO")
	}
}

func TestParseConfidence(t *testing.T) {
	got, err := ParseConfidence("high")
	if err != nil || got != ConfidenceHigh {
		t.Fatalf("ParseConfidence(high) = %v, %v", got, err)
	}
	if _, err := ParseConfidence("x"); err == nil {
		t.Error("expected error")
	}
}

func TestEvidenceKindValid(t *testing.T) {
	for _, k := range []EvidenceKind{KindObserved, KindInferred, KindUnknown} {
		if !k.Valid() {
			t.Errorf("%s should be valid", k)
		}
	}
	if EvidenceKind("MADEUP").Valid() {
		t.Error("MADEUP should not be valid")
	}
}

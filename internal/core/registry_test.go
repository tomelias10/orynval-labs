package core

import "testing"

// staticRule is a test rule that returns a fixed set of findings.
type staticRule struct {
	id       string
	findings []Finding
}

func (r staticRule) ID() string                  { return r.id }
func (r staticRule) Name() string                { return r.id + " name" }
func (r staticRule) Description() string         { return r.id + " desc" }
func (r staticRule) Evaluate(*Context) []Finding { return r.findings }

func TestRegistryRegisterAndRulesSorted(t *testing.T) {
	reg := NewRegistry()
	reg.Register(staticRule{id: "z.rule"})
	reg.Register(staticRule{id: "a.rule"})
	reg.Register(staticRule{id: "m.rule"})
	if reg.Len() != 3 {
		t.Fatalf("Len = %d, want 3", reg.Len())
	}
	rules := reg.Rules()
	got := []string{rules[0].ID(), rules[1].ID(), rules[2].ID()}
	want := []string{"a.rule", "m.rule", "z.rule"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Rules()[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestRegistryDuplicatePanics(t *testing.T) {
	reg := NewRegistry()
	reg.Register(staticRule{id: "dup"})
	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate ID")
		}
	}()
	reg.Register(staticRule{id: "dup"})
}

func TestRegistryNilPanics(t *testing.T) {
	reg := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Error("expected panic on nil rule")
		}
	}()
	reg.Register(nil)
}

func TestRegistryEvaluateSortsAndDedupes(t *testing.T) {
	reg := NewRegistry()
	reg.Register(staticRule{id: "rule.a", findings: []Finding{
		{RuleID: "rule.a", Severity: SeverityLow, Fingerprint: "fp-low", Where: "a:1"},
		{RuleID: "rule.a", Severity: SeverityCritical, Fingerprint: "fp-crit", Where: "b:2"},
	}})
	reg.Register(staticRule{id: "rule.b", findings: []Finding{
		// Duplicate fingerprint of the LOW finding; should be merged away.
		{RuleID: "rule.a", Severity: SeverityLow, Fingerprint: "fp-low", Where: "a:1"},
		{RuleID: "rule.b", Severity: SeverityHigh, Fingerprint: "fp-high", Where: "c:3"},
	}})

	out := reg.Evaluate(NewContext("/root", nil, Options{}))
	if len(out) != 3 {
		t.Fatalf("expected 3 findings after dedupe, got %d: %+v", len(out), out)
	}
	// Deterministic order: CRITICAL, HIGH, LOW.
	if out[0].Severity != SeverityCritical || out[1].Severity != SeverityHigh || out[2].Severity != SeverityLow {
		t.Errorf("unexpected order: %s %s %s", out[0].Severity, out[1].Severity, out[2].Severity)
	}
}

func TestRegistryEvaluateNilWalkerIsSafe(t *testing.T) {
	reg := NewRegistry()
	reg.Register(staticRule{id: "noop"})
	out := reg.Evaluate(NewContext("/root", nil, Options{}))
	if len(out) != 0 {
		t.Errorf("expected no findings, got %d", len(out))
	}
}

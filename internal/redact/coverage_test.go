package redact

import (
	"regexp"
	"testing"
)

// TestReplaceSubmatchHandlesAbsentGroup exercises the branch that fills an empty
// string for a capture group that did not participate in a match. The exported
// Redact patterns have no optional groups, so this behavior is verified against
// the helper directly with a pattern whose middle group is optional.
func TestReplaceSubmatchHandlesAbsentGroup(t *testing.T) {
	re := regexp.MustCompile(`(a)(b)?(c)`)

	var sawGroups [][]string
	got := replaceSubmatch(re, "ac and abc", func(g []string) string {
		sawGroups = append(sawGroups, append([]string(nil), g...))
		return "<" + g[1] + "|" + g[2] + "|" + g[3] + ">"
	})

	want := "<a||c> and <a|b|c>"
	if got != want {
		t.Errorf("replaceSubmatch = %q, want %q", got, want)
	}
	if len(sawGroups) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(sawGroups))
	}
	// First match "ac": the optional middle group is absent -> empty string.
	if sawGroups[0][2] != "" {
		t.Errorf("absent group should be empty, got %q", sawGroups[0][2])
	}
	// Second match "abc": the middle group participated.
	if sawGroups[1][2] != "b" {
		t.Errorf("present group should be %q, got %q", "b", sawGroups[1][2])
	}
}

// TestReplaceSubmatchNoMatchReturnsInput confirms the fast path where nothing
// matches returns the original text unchanged (b stays nil).
func TestReplaceSubmatchNoMatchReturnsInput(t *testing.T) {
	re := regexp.MustCompile(`zzz`)
	in := "no match here"
	if got := replaceSubmatch(re, in, func([]string) string { return "X" }); got != in {
		t.Errorf("replaceSubmatch with no match = %q, want %q", got, in)
	}
}

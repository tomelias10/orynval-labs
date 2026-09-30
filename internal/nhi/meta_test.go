package nhi

import (
	"reflect"
	"testing"
)

func TestStaleReason(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]string
		want bool // whether a reason is produced
		sub  string
	}{
		{"enabled false", map[string]string{"enabled": "false"}, true, "explicitly disabled (enabled=false)"},
		{"active false", map[string]string{"active": "no"}, true, "explicitly inactive"},
		{"disabled true", map[string]string{"disabled": "true"}, true, "explicitly disabled (disabled=true)"},
		{"status disuse", map[string]string{"status": "Revoked"}, true, "status marked revoked"},
		{"state disuse", map[string]string{"state": "INACTIVE"}, true, "status marked inactive"},
		{"timestamp gap", map[string]string{"last_used": "2020-01-01", "valid_before": "2020-06-01"}, true, "before its stated cutoff"},
		{"timestamp gap with time suffix", map[string]string{"last_authenticated": "2019-01-01T08:00:00Z", "expires": "2020-01-01"}, true, "d before its stated cutoff"},
		{"gap too small", map[string]string{"last_used": "2020-01-01", "expires": "2020-02-15"}, false, ""},
		{"last used but no cutoff", map[string]string{"last_used": "2020-01-01"}, false, ""},
		{"unparseable dates ignored", map[string]string{"last_used": "yesterday", "expires": "soon"}, false, ""},
		{"nothing", map[string]string{"owner": "team"}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := staleReason(tc.meta)
			if tc.want && got == "" {
				t.Fatalf("expected a stale reason, got none")
			}
			if !tc.want && got != "" {
				t.Fatalf("expected no stale reason, got %q", got)
			}
			if tc.sub != "" && !contains(got, tc.sub) {
				t.Errorf("reason %q does not contain %q", got, tc.sub)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestOwnerMarkers(t *testing.T) {
	got := ownerMarkers(map[string]string{"owner": "a", "team": " ", "maintainer": "b"})
	// team is blank (whitespace) → excluded; owner and maintainer kept, sorted.
	want := []string{"maintainer=b", "owner=a"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ownerMarkers = %v, want %v", got, want)
	}
	if len(ownerMarkers(map[string]string{"foo": "bar"})) != 0 {
		t.Error("no owner keys → empty")
	}
}

func TestFirstDate(t *testing.T) {
	// First key unparseable, second parseable → second wins.
	dv, ok := firstDate(map[string]string{"last_used": "bad", "last_activity": "2020-03-04"}, lastUsedKeys)
	if !ok || dv.raw != "2020-03-04" {
		t.Fatalf("firstDate = %+v ok=%v", dv, ok)
	}
	if _, ok := firstDate(map[string]string{}, lastUsedKeys); ok {
		t.Error("no keys → not ok")
	}
}

func TestParseDate(t *testing.T) {
	if _, err := parseDate("2021-12-31"); err != nil {
		t.Errorf("valid date errored: %v", err)
	}
	if _, err := parseDate("2021-12-31T23:59:59Z"); err != nil {
		t.Errorf("date with time suffix should parse via prefix: %v", err)
	}
	if _, err := parseDate("nope"); err == nil {
		t.Error("invalid date should error")
	}
}

func TestBoolish(t *testing.T) {
	for _, v := range []string{"true", "YES", "1"} {
		if !isTruthy(v) {
			t.Errorf("isTruthy(%q) should be true", v)
		}
	}
	if isTruthy("maybe") {
		t.Error("isTruthy(maybe) should be false")
	}
	for _, v := range []string{"false", "No", "0"} {
		if !isFalsey(v) {
			t.Errorf("isFalsey(%q) should be true", v)
		}
	}
	if isFalsey("") || isFalsey("true") {
		t.Error("empty/affirmative must not be falsey")
	}
}

func TestItoa(t *testing.T) {
	if itoa(0) != "0" || itoa(9) != "9" || itoa(1234) != "1234" {
		t.Errorf("itoa: %q %q %q", itoa(0), itoa(9), itoa(1234))
	}
}

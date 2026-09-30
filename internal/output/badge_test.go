package output

import (
	"strings"
	"testing"
)

func TestBadgeColorBySeverity(t *testing.T) {
	cases := []struct {
		name  string
		sum   Summary
		color string
		msg   string
	}{
		{"none", Summary{Total: 0}, badgeGreen, "0 findings"},
		{"critical", Summary{Total: 3, Critical: 1}, badgeRed, "3 findings"},
		{"high", Summary{Total: 2, High: 2}, badgeRed, "2 findings"},
		{"medium", Summary{Total: 1, Medium: 1}, badgeOrange, "1 finding"},
		{"low", Summary{Total: 5, Low: 5}, badgeYellow, "5 findings"},
		{"info", Summary{Total: 1, Info: 1}, badgeBlue, "1 finding"},
	}
	for _, c := range cases {
		msg, color := badgeMessageColor(c.sum)
		if msg != c.msg || color != c.color {
			t.Errorf("%s: got (%q,%q), want (%q,%q)", c.name, msg, color, c.msg, c.color)
		}
	}
}

func TestRenderBadgeWellFormed(t *testing.T) {
	out := string(render(t, FormatBadge, sampleReport(), Options{}))
	if !strings.HasPrefix(out, "<svg") || !strings.Contains(out, "</svg>") {
		t.Errorf("badge is not an SVG document:\n%s", out)
	}
	// Critical present → red.
	if !strings.Contains(out, badgeRed) {
		t.Errorf("expected red badge for a report with a critical finding:\n%s", out)
	}
	if !strings.Contains(out, "2 findings") {
		t.Errorf("expected finding count in badge:\n%s", out)
	}
	if !strings.Contains(out, "orynval") {
		t.Errorf("expected label in badge:\n%s", out)
	}
}

func TestBadgeXMLEscape(t *testing.T) {
	got := xmlEscape(`a & b < c > d " ' e`)
	for _, raw := range []string{" & ", "<", ">"} {
		if strings.Contains(got, raw) {
			t.Errorf("xmlEscape left %q unescaped: %q", raw, got)
		}
	}
	for _, ent := range []string{"&amp;", "&lt;", "&gt;", "&quot;", "&apos;"} {
		if !strings.Contains(got, ent) {
			t.Errorf("xmlEscape missing entity %q: %q", ent, got)
		}
	}
}

func TestRenderBadgeEmptyIsGreen(t *testing.T) {
	out := string(render(t, FormatBadge, Report{}, Options{}))
	if !strings.Contains(out, badgeGreen) || !strings.Contains(out, "0 findings") {
		t.Errorf("empty report badge should be green with 0 findings:\n%s", out)
	}
}

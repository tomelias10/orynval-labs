package output

import (
	"fmt"
	"io"
	"strings"
)

// Badge colors follow the familiar shields.io flat palette.
const (
	badgeGreen  = "#4c1"    // no findings
	badgeRed    = "#e05d44" // critical / high
	badgeOrange = "#fe7d37" // medium
	badgeYellow = "#dfb317" // low
	badgeBlue   = "#007ec6" // info only
	badgeGray   = "#555"    // label background
)

// badgeCharWidth is the approximate per-character advance (px) used to size the
// badge. A fixed value keeps the SVG deterministic across machines and fonts.
const badgeCharWidth = 7

// badgeSidePad is the horizontal padding added to each text section (px).
const badgeSidePad = 10

// RenderBadge writes an SVG status badge summarizing the report. The label is
// fixed ("orynval") and the message and color are derived from the findings.
func RenderBadge(w io.Writer, r Report) error {
	r = r.normalized()
	sum := summarize(r.Findings)

	label := "orynval"
	message, color := badgeMessageColor(sum)

	labelW := badgeCharWidth*len(label) + badgeSidePad
	msgW := badgeCharWidth*len(message) + badgeSidePad
	totalW := labelW + msgW
	labelX := labelW / 2
	msgX := labelW + msgW/2

	el, em := xmlEscape(label), xmlEscape(message)

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">`+"\n", totalW, el, em)
	fmt.Fprintf(&b, `<title>%s: %s</title>`+"\n", el, em)
	b.WriteString(`<linearGradient id="s" x2="0" y2="100%">` + "\n")
	b.WriteString(`<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>` + "\n")
	b.WriteString(`<stop offset="1" stop-opacity=".1"/>` + "\n")
	b.WriteString(`</linearGradient>` + "\n")
	fmt.Fprintf(&b, `<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>`+"\n", totalW)
	b.WriteString(`<g clip-path="url(#r)">` + "\n")
	fmt.Fprintf(&b, `<rect width="%d" height="20" fill="%s"/>`+"\n", labelW, badgeGray)
	fmt.Fprintf(&b, `<rect x="%d" width="%d" height="20" fill="%s"/>`+"\n", labelW, msgW, color)
	fmt.Fprintf(&b, `<rect width="%d" height="20" fill="url(#s)"/>`+"\n", totalW)
	b.WriteString(`</g>` + "\n")
	b.WriteString(`<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">` + "\n")
	fmt.Fprintf(&b, `<text x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>`+"\n", labelX, el)
	fmt.Fprintf(&b, `<text x="%d" y="14">%s</text>`+"\n", labelX, el)
	fmt.Fprintf(&b, `<text x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>`+"\n", msgX, em)
	fmt.Fprintf(&b, `<text x="%d" y="14">%s</text>`+"\n", msgX, em)
	b.WriteString(`</g>` + "\n")
	b.WriteString(`</svg>` + "\n")

	_, err := io.WriteString(w, b.String())
	return err
}

// badgeMessageColor picks the right-hand text and color from the summary.
func badgeMessageColor(s Summary) (string, string) {
	if s.Total == 0 {
		return "0 findings", badgeGreen
	}
	noun := "findings"
	if s.Total == 1 {
		noun = "finding"
	}
	msg := fmt.Sprintf("%d %s", s.Total, noun)
	switch {
	case s.Critical > 0 || s.High > 0:
		return msg, badgeRed
	case s.Medium > 0:
		return msg, badgeOrange
	case s.Low > 0:
		return msg, badgeYellow
	default:
		return msg, badgeBlue
	}
}

// xmlEscape escapes the five XML predefined entities so a badge is well-formed
// even if a caller-supplied string contains markup characters.
func xmlEscape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	).Replace(s)
}

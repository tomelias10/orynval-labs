package output

import (
	"html/template"
	"io"
	"strings"

	"github.com/orynval/orynval-labs/internal/core"
)

// RenderHTML writes a self-contained HTML report with inline CSS and no
// external assets, scripts, or timestamps. All dynamic text is escaped by
// html/template, so a malicious file name or snippet cannot inject markup.
func RenderHTML(w io.Writer, r Report) error {
	r = r.normalized()
	data := htmlData{
		Tool:         r.Tool,
		Summary:      summarize(r.Findings),
		SeverityRows: severityRows(summarize(r.Findings)),
		Findings:     make([]htmlFinding, 0, len(r.Findings)),
	}
	for _, f := range r.Findings {
		data.Findings = append(data.Findings, htmlFinding{
			Severity:         string(f.Severity),
			SeverityClass:    severityClass(f.Severity),
			RuleID:           f.RuleID,
			Title:            f.Title,
			What:             f.What,
			Where:            f.Where,
			Why:              f.Why,
			Remediation:      f.Remediation,
			SaferAlternative: f.SaferAlternative,
			Confidence:       string(f.Confidence),
			Fingerprint:      f.Fingerprint,
			Evidence:         f.Evidence,
		})
	}
	return htmlTemplate.Execute(w, data)
}

type htmlData struct {
	Tool         ToolInfo
	Summary      Summary
	SeverityRows []severityRow
	Findings     []htmlFinding
}

type severityRow struct {
	Name  string
	Count int
	Class string
}

type htmlFinding struct {
	Severity         string
	SeverityClass    string
	RuleID           string
	Title            string
	What             string
	Where            string
	Why              string
	Remediation      string
	SaferAlternative string
	Confidence       string
	Fingerprint      string
	Evidence         []core.Evidence
}

func severityClass(s core.Severity) string {
	return "sev-" + strings.ToLower(string(s))
}

func severityRows(s Summary) []severityRow {
	return []severityRow{
		{"Critical", s.Critical, "sev-critical"},
		{"High", s.High, "sev-high"},
		{"Medium", s.Medium, "sev-medium"},
		{"Low", s.Low, "sev-low"},
		{"Info", s.Info, "sev-info"},
	}
}

// htmlTemplate is parsed once at init. Using html/template guarantees that
// every field is contextually escaped.
var htmlTemplate = template.Must(template.New("report").Parse(htmlSource))

const htmlSource = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Tool.Name}} report</title>
<style>
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem; line-height: 1.5; background: #fbfbfd; color: #1d1d1f; }
h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
.meta { color: #6e6e73; margin: 0 0 1.5rem; font-size: .9rem; }
table.summary { border-collapse: collapse; margin: 0 0 2rem; }
table.summary td { padding: .25rem .9rem; border: 1px solid #e2e2e7; }
.count { font-variant-numeric: tabular-nums; text-align: right; font-weight: 600; }
.finding { border: 1px solid #e2e2e7; border-radius: 10px; padding: 1rem 1.25rem; margin: 0 0 1rem; background: #fff; }
.finding h2 { font-size: 1.05rem; margin: 0 0 .5rem; display: flex; gap: .6rem; align-items: baseline; }
.badge { font-size: .72rem; font-weight: 700; letter-spacing: .04em; padding: .12rem .5rem; border-radius: 999px; color: #fff; }
.rule-id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #6e6e73; font-size: .8rem; font-weight: 400; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .2rem .9rem; margin: .5rem 0 0; }
dt { color: #6e6e73; font-size: .82rem; }
dd { margin: 0; }
.evidence { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; background: #f5f5f7; border-radius: 6px; padding: .5rem .75rem; margin: .35rem 0 0; overflow-x: auto; }
.evidence div { white-space: pre-wrap; word-break: break-word; }
.loc { color: #6e6e73; }
.fp { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #a1a1a6; font-size: .75rem; }
.sev-critical { background: #d70015; }
.sev-high { background: #ff6f00; }
.sev-medium { background: #b58900; }
.sev-low { background: #0071e3; }
.sev-info { background: #8a8a8e; }
.none { color: #1a7f37; font-weight: 600; }
</style>
</head>
<body>
<h1>{{if .Tool.Name}}{{.Tool.Name}}{{else}}Orynval Labs{{end}} report</h1>
<p class="meta">{{if .Tool.Version}}version {{.Tool.Version}} · {{end}}{{.Summary.Total}} finding{{if ne .Summary.Total 1}}s{{end}}</p>

{{if .Findings}}
<table class="summary">
{{range .SeverityRows}}<tr><td>{{.Name}}</td><td class="count {{.Class}}-text">{{.Count}}</td></tr>
{{end}}</table>

{{range .Findings}}
<div class="finding">
<h2><span class="badge {{.SeverityClass}}">{{.Severity}}</span> {{.Title}} <span class="rule-id">{{.RuleID}}</span></h2>
<dl>
{{if .Where}}<dt>Where</dt><dd>{{.Where}}</dd>{{end}}
{{if .What}}<dt>What</dt><dd>{{.What}}</dd>{{end}}
{{if .Why}}<dt>Why</dt><dd>{{.Why}}</dd>{{end}}
{{if .Remediation}}<dt>Fix</dt><dd>{{.Remediation}}</dd>{{end}}
{{if .SaferAlternative}}<dt>Safer</dt><dd>{{.SaferAlternative}}</dd>{{end}}
{{if .Confidence}}<dt>Confidence</dt><dd>{{.Confidence}}</dd>{{end}}
</dl>
{{if .Evidence}}<div class="evidence">{{range .Evidence}}<div><span class="loc">{{.File}}{{if gt .Line 0}}:{{.Line}}{{end}}</span>  {{.Snippet}}</div>{{end}}</div>{{end}}
{{if .Fingerprint}}<p class="fp">fingerprint: {{.Fingerprint}}</p>{{end}}
</div>
{{end}}
{{else}}
<p class="none">No findings.</p>
{{end}}
</body>
</html>
`

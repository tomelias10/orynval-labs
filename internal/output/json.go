package output

import (
	"encoding/json"
	"io"

	"github.com/tomelias10/orynval-labs/internal/core"
)

// jsonDoc is the top-level JSON document. Field order is fixed by struct
// declaration order, and it contains no timestamp, so the output is stable.
type jsonDoc struct {
	Tool     jsonTool       `json:"tool"`
	Summary  Summary        `json:"summary"`
	Findings []core.Finding `json:"findings"`
}

type jsonTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RenderJSON writes the report as indented JSON. Findings are sorted and their
// snippets redacted (via normalized); maps are not used, so key ordering cannot
// vary. A trailing newline is emitted.
func RenderJSON(w io.Writer, r Report) error {
	r = r.normalized()
	doc := jsonDoc{
		Tool:     jsonTool{Name: r.Tool.Name, Version: r.Tool.Version},
		Summary:  summarize(r.Findings),
		Findings: r.Findings,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

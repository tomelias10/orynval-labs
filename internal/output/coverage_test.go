package output

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/orynval/orynval-labs/internal/core"
)

func TestSARIFMessageText(t *testing.T) {
	cases := []struct {
		name string
		f    core.Finding
		want string
	}{
		{"both", core.Finding{Title: "T", What: "W"}, "T: W"},
		{"no what", core.Finding{Title: "T"}, "T"},
		{"no title", core.Finding{What: "W"}, "W"},
		{"neither", core.Finding{}, ""},
	}
	for _, c := range cases {
		if got := sarifMessageText(c.f); got != c.want {
			t.Errorf("%s: sarifMessageText = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSeverityColorAllSeverities covers every branch of severityColor, including
// the HIGH/MEDIUM arms and the default (unknown/INFO) fallback.
func TestSeverityColorAllSeverities(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range []core.Severity{
		core.SeverityCritical, core.SeverityHigh, core.SeverityMedium,
		core.SeverityLow, core.SeverityInfo, core.Severity("WEIRD"),
	} {
		c := string(severityColor(s))
		if c == "" {
			t.Errorf("severityColor(%s) returned an empty color", s)
		}
		seen[c] = true
	}
	// Critical, High, Medium, Low each have a distinct color; Info and unknown
	// share the gray default, so we expect 5 distinct values.
	if len(seen) != 5 {
		t.Errorf("expected 5 distinct severity colors, got %d: %v", len(seen), seen)
	}
}

// failWriter fails every write, used to exercise renderers' write-error paths.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestRenderShareWriteError(t *testing.T) {
	if err := RenderShare(failWriter{}, sampleReport()); err == nil {
		t.Error("expected a write error from RenderShare to a failing writer")
	}
}

// TestDecodeShareRejectsValidDeflateNonJSON reaches the JSON-parse error branch:
// a blob that base64-decodes and inflates cleanly but is not valid JSON.
func TestDecodeShareRejectsValidDeflateNonJSON(t *testing.T) {
	var buf bytes.Buffer
	zw, _ := flate.NewWriter(&buf, flate.BestCompression)
	if _, err := zw.Write([]byte("this is not json at all")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	blob := sharePrefix + base64.RawURLEncoding.EncodeToString(buf.Bytes())

	if _, err := DecodeShare(blob); err == nil {
		t.Error("expected a JSON parse error for well-formed deflate carrying non-JSON")
	}
}

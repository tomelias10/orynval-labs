package output

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/orynval/orynval-labs/internal/core"
)

// sharePrefix tags a share blob with a scheme and version so a decoder can
// recognize and validate it. Bumping the version lets the format evolve.
const sharePrefix = "orynval-share:v1:"

// shareDoc is the self-contained payload carried inside a share blob: enough to
// reconstruct a Report and re-render it in any other format, entirely offline.
type shareDoc struct {
	Tool     ToolInfo       `json:"tool"`
	Rules    []RuleDoc      `json:"rules,omitempty"`
	Findings []core.Finding `json:"findings"`
}

// RenderShare writes a portable, offline share blob: the report serialized to
// compact JSON, DEFLATE-compressed, base64url-encoded, and tagged with a
// scheme. It contains no network reference; "sharing" means handing someone the
// text, which they decode locally with DecodeShare. The output is deterministic
// for a given report and Go toolchain.
func RenderShare(w io.Writer, r Report) error {
	r = r.normalized()
	doc := shareDoc{Tool: r.Tool, Rules: r.Rules, Findings: r.Findings}
	raw, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("output: marshal share payload: %w", err)
	}

	var buf bytes.Buffer
	zw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return fmt.Errorf("output: init compressor: %w", err)
	}
	if _, err := zw.Write(raw); err != nil {
		return fmt.Errorf("output: compress share payload: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("output: finalize compressor: %w", err)
	}

	enc := base64.RawURLEncoding.EncodeToString(buf.Bytes())
	_, err = io.WriteString(w, sharePrefix+enc+"\n")
	return err
}

// DecodeShare reverses RenderShare, reconstructing a Report from a share blob.
// Surrounding whitespace is tolerated. It is the inverse used to verify the
// round trip and to let a recipient re-render a shared result locally.
func DecodeShare(s string) (Report, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, sharePrefix) {
		return Report{}, fmt.Errorf("output: not a share blob (missing %q prefix)", sharePrefix)
	}
	enc := strings.TrimPrefix(s, sharePrefix)
	compressed, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return Report{}, fmt.Errorf("output: decode share blob: %w", err)
	}
	zr := flate.NewReader(bytes.NewReader(compressed))
	defer zr.Close()
	raw, err := io.ReadAll(zr)
	if err != nil {
		return Report{}, fmt.Errorf("output: decompress share blob: %w", err)
	}
	var doc shareDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return Report{}, fmt.Errorf("output: parse share payload: %w", err)
	}
	return Report{Tool: doc.Tool, Rules: doc.Rules, Findings: doc.Findings}, nil
}

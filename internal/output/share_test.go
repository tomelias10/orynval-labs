package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestShareRoundTrip(t *testing.T) {
	orig := sampleReport()

	var buf bytes.Buffer
	if err := RenderShare(&buf, orig); err != nil {
		t.Fatalf("RenderShare: %v", err)
	}
	blob := buf.String()
	if !strings.HasPrefix(blob, sharePrefix) {
		t.Fatalf("share blob missing prefix %q", sharePrefix)
	}

	got, err := DecodeShare(blob)
	if err != nil {
		t.Fatalf("DecodeShare: %v", err)
	}

	// The decoded report equals the *normalized* original: findings sorted and
	// evidence snippets redacted. Compare against that expectation.
	want := orig.normalized()
	if got.Tool != want.Tool {
		t.Errorf("tool mismatch:\n got %+v\nwant %+v", got.Tool, want.Tool)
	}
	if len(got.Findings) != len(want.Findings) {
		t.Fatalf("finding count %d != %d", len(got.Findings), len(want.Findings))
	}
	for i := range want.Findings {
		if got.Findings[i].Fingerprint != want.Findings[i].Fingerprint {
			t.Errorf("finding %d fingerprint mismatch", i)
		}
		if got.Findings[i].Severity != want.Findings[i].Severity {
			t.Errorf("finding %d severity mismatch", i)
		}
	}
}

func TestShareDoesNotLeakSecret(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderShare(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	// Decode our own blob and confirm the secret is masked; the compressed blob
	// itself is opaque, so we assert on the recoverable payload.
	got, err := DecodeShare(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got.Findings {
		for _, e := range f.Evidence {
			if strings.Contains(e.Snippet, leakSecret) {
				t.Errorf("share payload leaked secret in snippet %q", e.Snippet)
			}
		}
	}
}

func TestDecodeShareRejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"not-a-share-blob",
		sharePrefix + "!!!not-base64!!!",
		sharePrefix + "aGVsbG8", // valid base64 but not valid deflate/json
	}
	for _, in := range cases {
		if _, err := DecodeShare(in); err == nil {
			t.Errorf("DecodeShare(%q) should have errored", in)
		}
	}
}

func TestDecodeShareToleratesWhitespace(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderShare(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	padded := "\n\t  " + buf.String() + "  \n"
	if _, err := DecodeShare(padded); err != nil {
		t.Errorf("DecodeShare should tolerate surrounding whitespace: %v", err)
	}
}

func TestShareEmptyReportRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderShare(&buf, Report{Tool: ToolInfo{Name: "x"}}); err != nil {
		t.Fatal(err)
	}
	got, err := DecodeShare(buf.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 0 || got.Tool.Name != "x" {
		t.Errorf("unexpected decoded empty report: %+v", got)
	}
}

package redact

import (
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"a":                    "****",
		"ab":                   "****",
		"abc":                  "a****",
		"hunter2":              "hu****",
		"AKIAIOSFODNN7EXAMPLE": "AKIA****",
	}
	for in, want := range cases {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskNeverRevealsFullSecret(t *testing.T) {
	secrets := []string{
		"hunter2",
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
		"short",
	}
	for _, s := range secrets {
		got := Mask(s)
		if got == s {
			t.Errorf("Mask(%q) returned the secret unchanged", s)
		}
		if strings.Contains(got, s) {
			t.Errorf("Mask(%q) = %q still contains the full secret", s, got)
		}
		// The mask must reveal no more than the first 4 runes.
		if !strings.HasSuffix(got, mask) {
			t.Errorf("Mask(%q) = %q missing mask suffix", s, got)
		}
		revealed := strings.TrimSuffix(got, mask)
		if len([]rune(revealed)) > 4 {
			t.Errorf("Mask(%q) revealed %q (> 4 runes)", s, revealed)
		}
	}
}

func TestMaskMultibyte(t *testing.T) {
	// Prefix extraction must be rune-aware and never split a multibyte rune.
	got := Mask("héllo-wörld-secret")
	if !strings.HasSuffix(got, mask) {
		t.Fatalf("Mask multibyte = %q, want mask suffix", got)
	}
	// Result must be valid UTF-8 (no split runes).
	for _, r := range got {
		if r == '�' {
			t.Errorf("Mask produced an invalid rune: %q", got)
		}
	}
}

func TestRedactAssignmentPreservesSyntax(t *testing.T) {
	cases := map[string]string{
		`password = "hunter2"`:   `password = "hu****"`,
		`password="hunter2"`:     `password="hu****"`,
		`secret: 'topsecret9'`:   `secret: 'top****'`,
		`token=abcd1234efgh5678`: `token=abcd****`,
		`api_key = "value-here"`: `api_key = "val****"`,
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedactProviderTokens(t *testing.T) {
	// Obviously fake / documentation-example tokens only.
	tokens := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_0123456789abcdefghijABCDEFGHIJ0123",
		"xoxb-1234567890-abcdefghijkl",
		"AIzaSyA1234567890abcdefghijklmnopqrstuv0",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLWhlcmU",
	}
	for _, tok := range tokens {
		line := "value found: " + tok + " end"
		got := Redact(line)
		if strings.Contains(got, tok) {
			t.Errorf("Redact did not mask %q: %q", tok, got)
		}
		if !strings.Contains(got, mask) {
			t.Errorf("Redact(%q) produced no mask: %q", tok, got)
		}
		if !strings.HasPrefix(got, "value found: ") || !strings.HasSuffix(got, " end") {
			t.Errorf("Redact mangled surrounding text: %q", got)
		}
	}
}

func TestRedactGenericHighEntropy(t *testing.T) {
	// A 44-char base64-ish blob with no known prefix and no key: caught by the
	// generic high-entropy safety net.
	blob := "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWpr"
	got := Redact(blob)
	if strings.Contains(got, blob) {
		t.Errorf("generic high-entropy blob not masked: %q", got)
	}
}

func TestRedactLeavesProseAlone(t *testing.T) {
	prose := "The quick brown fox jumps over the lazy dog."
	if got := Redact(prose); got != prose {
		t.Errorf("Redact altered prose: %q", got)
	}
}

func TestRedactMultipleSecretsInOneLine(t *testing.T) {
	line := `aws="AKIAIOSFODNN7EXAMPLE" and gh=ghp_0123456789abcdefghijABCDEFGHIJ0123`
	got := Redact(line)
	for _, secret := range []string{"AKIAIOSFODNN7EXAMPLE", "ghp_0123456789abcdefghijABCDEFGHIJ0123"} {
		if strings.Contains(got, secret) {
			t.Errorf("secret %q leaked through: %q", secret, got)
		}
	}
}

func TestRedactIdempotentNoLeak(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	once := Redact("key = \"" + secret + "\"")
	twice := Redact(once)
	if strings.Contains(twice, secret) {
		t.Errorf("secret leaked after double redaction: %q", twice)
	}
}

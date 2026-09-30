// Package redact masks secret material so it can never reach a terminal, a
// file, or any rendered report. It is the single chokepoint every Orynval Labs
// tool uses to satisfy the "never print secrets" guarantee.
//
// Two entry points cover the two moments a secret is handled:
//
//   - Mask is used by a rule when it builds Evidence: it turns a known secret
//     value into a short, safe token that keeps at most a tiny prefix for human
//     correlation and never reveals the full value or its exact length.
//   - Redact is used by renderers as defense in depth: it scans arbitrary text
//     for secret-shaped substrings (provider tokens, key/value assignments,
//     high-entropy runs) and masks them, so even an un-redacted snippet that
//     slips through a rule is sanitized before it is printed.
//
// The package is deterministic and side-effect free: the same input always
// produces the same output, on every machine, with no randomness, no clock,
// and no network.
package redact

import (
	"regexp"
	"unicode/utf8"
)

// mask is the fixed suffix appended after any preserved prefix. It is a
// constant width so the length of the original secret is not leaked through the
// length of the mask.
const mask = "****"

// Mask returns a safe rendering of a secret value. It preserves a short prefix
// (never more than a third of the value and never more than 4 runes) purely so
// a human can correlate two reports about the same secret, then appends a
// fixed-width mask. Short secrets reveal no prefix at all. The full secret and
// its exact length are never recoverable from the result.
//
//	Mask("")                      == ""
//	Mask("hunter2")               == "hu****"
//	Mask("AKIAIOSFODNN7EXAMPLE")  == "AKIA****"
func Mask(secret string) string {
	n := utf8.RuneCountInString(secret)
	if n == 0 {
		return ""
	}
	// keep is bounded by 4 and, since keep = n/3, is always < n for n >= 1, so
	// at least two-thirds of every secret is masked and a short one reveals
	// nothing.
	keep := n / 3
	if keep > 4 {
		keep = 4
	}
	// Take the first keep runes without assuming single-byte encoding.
	i, count := 0, 0
	for count < keep {
		_, size := utf8.DecodeRuneInString(secret[i:])
		i += size
		count++
	}
	return secret[:i] + mask
}

// secretPatterns are provider-specific and structural token shapes matched
// anywhere in a line. Each whole match is replaced by Mask(match). Ordering is
// not significant because the patterns are applied to disjoint shapes.
var secretPatterns = []*regexp.Regexp{
	// AWS access key id.
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	// GitHub personal/OAuth/app/refresh/server tokens.
	regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{20,}`),
	// Slack tokens.
	regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),
	// Google API keys.
	regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
	// JSON Web Tokens (header.payload.signature).
	regexp.MustCompile(`eyJ[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+\.[0-9A-Za-z_\-]+`),
	// Generic high-entropy run: a long token from the base64/hex/url alphabet.
	// Deliberately last and conservative (length >= 32) so it acts as a safety
	// net without shredding ordinary prose.
	regexp.MustCompile(`[0-9A-Za-z+/=_\-]{32,}`),
}

// quoteChars are the string-delimiter characters recognized in assignments:
// double quote, single quote, and backtick. Written as an escaped double-quoted
// literal so all three fit in one constant.
const quoteChars = "\"'`"

// assignQuoted matches `key = "value"` / `key: 'value'` style secret
// assignments, capturing key, separator, opening quote, value, and closing
// quote so only the value is masked and the surrounding syntax is preserved.
var assignQuoted = regexp.MustCompile(secretKeys + `(\s*[:=]\s*)([` + quoteChars + `])([^` + quoteChars + `]*)([` + quoteChars + `])`)

// assignBare matches `key = value` style assignments with an unquoted value,
// capturing key, separator, and value.
var assignBare = regexp.MustCompile(secretKeys + `(\s*[:=]\s*)([^\s` + quoteChars + `,;]+)`)

// urlUserinfo matches the password part of a URL's userinfo component.
var urlUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.\-]*://[^:/\s@]*:)([^@\s/]+)(@)`)

// secretKeys is the leading, case-insensitive key alternation shared by both
// assignment patterns, wrapped in a capturing group so the key text survives.
const secretKeys = `(?i)((?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|apikey|access[_-]?key|auth[0-9a-z_]*|credentials?|client[_-]?secret|private[_-]?key|bearer)\b)`

// Redact returns text with secret-shaped substrings masked. It is safe to print
// the result. Redact is a best-effort safety net, not a classifier: it may mask
// a value that was not actually a secret, which is the correct trade-off for
// output that must never leak one. Rules should still Mask known secrets when
// building evidence rather than relying on Redact alone.
func Redact(text string) string {
	// Mask assignment values first so a secret hidden behind a benign-looking
	// key ("token = ...") is caught even when its value is not a known shape.
	text = replaceSubmatch(assignQuoted, text, func(g []string) string {
		// g: [full, key, sep, openQuote, value, closeQuote]
		return g[1] + g[2] + g[3] + Mask(g[4]) + g[5]
	})
	text = replaceSubmatch(assignBare, text, func(g []string) string {
		// g: [full, key, sep, value]
		return g[1] + g[2] + Mask(g[3])
	})
	// Mask passwords embedded in URL userinfo (scheme://user:password@host),
	// e.g. database connection strings passed as command-line arguments.
	text = replaceSubmatch(urlUserinfo, text, func(g []string) string {
		// g: [full, prefix, password, at]
		return g[1] + Mask(g[2]) + g[3]
	})
	// Then mask standalone token shapes.
	for _, re := range secretPatterns {
		text = re.ReplaceAllStringFunc(text, Mask)
	}
	return text
}

// replaceSubmatch applies fn to each match of re, passing the full match plus
// its capture groups, and substitutes the returned string. It exists because
// the stdlib ReplaceAllStringFunc does not expose capture groups.
func replaceSubmatch(re *regexp.Regexp, text string, fn func(groups []string) string) string {
	var b []byte
	last := 0
	for _, loc := range re.FindAllStringSubmatchIndex(text, -1) {
		b = append(b, text[last:loc[0]]...)
		groups := make([]string, len(loc)/2)
		for i := 0; i < len(loc); i += 2 {
			if loc[i] < 0 {
				groups[i/2] = ""
				continue
			}
			groups[i/2] = text[loc[i]:loc[i+1]]
		}
		b = append(b, fn(groups)...)
		last = loc[1]
	}
	if b == nil {
		return text
	}
	b = append(b, text[last:]...)
	return string(b)
}

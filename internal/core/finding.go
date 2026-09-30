package core

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Evidence is a single supporting observation for a finding. Snippet MUST be
// redacted before it reaches this struct: renderers treat it as safe-to-print
// text and, as defense in depth, redact it again at render time. Kind records
// whether the evidence was directly OBSERVED, INFERRED, or is UNKNOWN.
type Evidence struct {
	File    string       `json:"file"`
	Line    int          `json:"line"`
	Snippet string       `json:"snippet"` // already redacted; never a raw secret
	Kind    EvidenceKind `json:"kind"`
}

// Finding is a single result produced by a Rule. Field roles:
//
//   - RuleID           stable identifier of the emitting rule
//   - Title            short human headline
//   - What / Where /   the three-part explanation: what is wrong, where it is,
//     Why              and why it matters
//   - Confidence       how sure the rule is
//   - Severity         impact ranking
//   - Remediation      how to fix it
//   - SaferAlternative optional: a safer pattern to adopt instead
//   - Evidence         supporting observations (redacted snippets)
//   - Fingerprint      deterministic identity, see ComputeFingerprint
type Finding struct {
	RuleID           string     `json:"ruleId"`
	Title            string     `json:"title"`
	What             string     `json:"what"`
	Where            string     `json:"where"`
	Why              string     `json:"why"`
	Confidence       Confidence `json:"confidence"`
	Severity         Severity   `json:"severity"`
	Remediation      string     `json:"remediation"`
	SaferAlternative string     `json:"saferAlternative,omitempty"`
	Evidence         []Evidence `json:"evidence"`
	Fingerprint      string     `json:"fingerprint"`
}

// ComputeFingerprint returns sha256(ruleID + relativePath + normalizedSnippet)
// as lowercase hex. It deliberately excludes line numbers and timestamps so the
// same logical finding keeps a stable identity across runs, across machines,
// and as unrelated lines shift around it.
//
// The snippet is normalized (see NormalizeSnippet) but NOT redacted before
// hashing: sha256 is one-way, so the digest reveals nothing recoverable while
// still distinguishing two different secrets that happen to share a shape. The
// digest is safe to print; the raw snippet never is. Callers pass the raw
// snippet here and a redacted snippet into Evidence.
func ComputeFingerprint(ruleID, relativePath, snippet string) string {
	h := sha256.New()
	// NUL separators prevent field-boundary collisions (e.g. "a"+"bc" vs
	// "ab"+"c").
	h.Write([]byte(ruleID))
	h.Write([]byte{0})
	h.Write([]byte(filepathToSlash(relativePath)))
	h.Write([]byte{0})
	h.Write([]byte(NormalizeSnippet(snippet)))
	return hex.EncodeToString(h.Sum(nil))
}

// NormalizeSnippet collapses all runs of whitespace (including newlines and
// tabs) to a single space and trims the ends. This makes fingerprints stable
// against reindentation and line-ending differences while preserving the
// meaningful characters of the snippet.
func NormalizeSnippet(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// filepathToSlash normalizes path separators to forward slashes so fingerprints
// match across operating systems. It avoids importing path/filepath's
// OS-specific behavior by doing a direct replacement of backslashes.
func filepathToSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// SortFindings orders findings deterministically: most severe first, then by
// RuleID, Where, Title, and finally Fingerprint as a total-order tiebreaker.
// The sort is stable and idempotent, which is what makes rendered output
// byte-for-byte reproducible.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank() // higher severity first
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Where != b.Where {
			return a.Where < b.Where
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return a.Fingerprint < b.Fingerprint
	})
}

// DedupeFindings collapses findings that share a fingerprint, unioning their
// evidence (deduplicated by file+line+snippet, in first-seen order). Input
// order is otherwise preserved; callers typically SortFindings afterwards.
func DedupeFindings(fs []Finding) []Finding {
	seen := make(map[string]int) // fingerprint -> index in out
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if idx, ok := seen[f.Fingerprint]; ok && f.Fingerprint != "" {
			out[idx].Evidence = mergeEvidence(out[idx].Evidence, f.Evidence)
			continue
		}
		seen[f.Fingerprint] = len(out)
		out = append(out, f)
	}
	return out
}

func mergeEvidence(a, b []Evidence) []Evidence {
	type key struct {
		file    string
		line    int
		snippet string
	}
	seen := make(map[key]struct{}, len(a)+len(b))
	out := make([]Evidence, 0, len(a)+len(b))
	for _, list := range [][]Evidence{a, b} {
		for _, e := range list {
			k := key{e.File, e.Line, e.Snippet}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, e)
		}
	}
	return out
}

// CountBySeverity returns the number of findings at each severity, keyed by
// severity. Absent severities are present with a zero count so summaries have a
// stable shape.
func CountBySeverity(fs []Finding) map[Severity]int {
	counts := make(map[Severity]int, len(Severities))
	for _, s := range Severities {
		counts[s] = 0
	}
	for _, f := range fs {
		counts[f.Severity]++
	}
	return counts
}

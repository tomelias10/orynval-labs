package nhi

import (
	"sort"
	"strings"
	"time"
)

// stalenessGapDays is the minimum number of days a last-used timestamp must
// precede a co-located expiry/rotation cutoff for nhi-ghost to raise a
// stale-candidate. It is a fixed window applied to two timestamps that are both
// present in the tree, so the judgement never consults the wall clock and stays
// deterministic across machines and across time.
const stalenessGapDays = 90

// lastUsedKeys are metadata keys that record when an identity was last active.
// Staleness is only ever considered when one of these is present — the product
// requires trustworthy local last-used evidence, never mere absence of a
// reference.
var lastUsedKeys = []string{
	"last_used", "lastused", "last_authenticated", "last_activity",
	"lastusedtime", "last_login", "last_seen",
}

// cutoffKeys are metadata keys that record an expiry or rotation deadline. A
// last-used timestamp is compared only against a cutoff also present in the
// tree, so no external "now" is needed.
var cutoffKeys = []string{
	"valid_before", "validbefore", "not_after", "notafter",
	"expires", "expiry", "expiration", "rotate_after", "stale_after",
	"disable_after",
}

// disuseStatuses are explicit, self-declaring states that mark an identity as
// no longer in service. Each is trustworthy local evidence on its own.
var disuseStatuses = map[string]bool{
	"disabled": true, "inactive": true, "revoked": true, "deprecated": true,
	"unused": true, "suspended": true, "stale": true, "retired": true,
}

// ownerKeys are metadata keys whose presence (with a non-empty value) counts as
// an observed owner/team marker.
var ownerKeys = []string{
	"owner", "owners", "team", "teams", "maintainer", "maintainers",
	"managed_by", "managed-by", "managedby", "codeowner", "codeowners",
	"steward", "contact",
}

// ownerMarkers returns the sorted owner/team markers observed in meta. An empty
// result means no owner signal was found within the identity's own definition.
func ownerMarkers(meta map[string]string) []string {
	var found []string
	for _, k := range ownerKeys {
		if v, ok := meta[k]; ok && strings.TrimSpace(v) != "" {
			found = append(found, k+"="+strings.TrimSpace(v))
		}
	}
	sort.Strings(found)
	return found
}

// staleReason inspects meta for trustworthy local disuse evidence and returns a
// human-readable reason when the identity is a stale candidate, or "" when it
// is not. It is deterministic and never reads the clock.
func staleReason(meta map[string]string) string {
	// 1. An explicit boolean disuse flag.
	if isFalsey(meta["enabled"]) {
		return "explicitly disabled (enabled=" + meta["enabled"] + ")"
	}
	if isFalsey(meta["active"]) {
		return "explicitly inactive (active=" + meta["active"] + ")"
	}
	if isTruthy(meta["disabled"]) {
		return "explicitly disabled (disabled=" + meta["disabled"] + ")"
	}
	// 2. An explicit disuse status/state.
	for _, key := range []string{"status", "state"} {
		if v, ok := meta[key]; ok && disuseStatuses[strings.ToLower(strings.TrimSpace(v))] {
			return "status marked " + strings.ToLower(strings.TrimSpace(v)) + " (" + key + "=" + strings.TrimSpace(v) + ")"
		}
	}
	// 3. A last-used timestamp that precedes a co-located cutoff by a full
	//    stalenessGapDays window: the credential went unused well before its own
	//    stated expiry/rotation deadline.
	last, lok := firstDate(meta, lastUsedKeys)
	cut, cok := firstDate(meta, cutoffKeys)
	if lok && cok {
		gap := cut.date.Sub(last.date)
		if gap >= stalenessGapDays*24*time.Hour {
			days := int(gap.Hours() / 24)
			return "last activity " + last.raw + " is " + itoa(days) +
				"d before its stated cutoff " + cut.raw
		}
	}
	return ""
}

// datedValue pairs a parsed date with the raw string it came from (for
// evidence).
type datedValue struct {
	date time.Time
	raw  string
}

// firstDate returns the first parseable date found among keys, in key order.
func firstDate(meta map[string]string, keys []string) (datedValue, bool) {
	for _, k := range keys {
		if v, ok := meta[k]; ok {
			if d, perr := parseDate(v); perr == nil {
				return datedValue{date: d, raw: strings.TrimSpace(v)}, true
			}
		}
	}
	return datedValue{}, false
}

// parseDate parses the leading YYYY-MM-DD of a value as a UTC date. It never
// calls time.Now, so it introduces no clock dependency. Values shorter than a
// full date, or that do not start with a valid date, are rejected.
func parseDate(v string) (time.Time, error) {
	s := strings.TrimSpace(v)
	if len(s) > 10 {
		s = s[:10]
	}
	return time.Parse("2006-01-02", s)
}

// isTruthy reports whether v is an explicit affirmative boolean-ish value.
func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "1":
		return true
	default:
		return false
	}
}

// isFalsey reports whether v is an explicit negative boolean-ish value. An
// empty/absent value is NOT falsey: silence is never treated as evidence.
func isFalsey(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "false", "no", "0":
		return true
	default:
		return false
	}
}

// itoa renders a non-negative int without importing strconv into callers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

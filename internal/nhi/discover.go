package nhi

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/tomelias10/orynval-labs/internal/core"
	"github.com/tomelias10/orynval-labs/internal/redact"
)

// discover walks the tree once, extracts every identity it can observe, then
// applies cross-file ownership coverage (CODEOWNERS) as a post-pass. It never
// writes, executes, or reaches the network — only the read-only Context is used.
func discover(ctx *core.Context) []Identity {
	var identities []Identity
	var codeowners []string // directories (slash-rel) that hold a CODEOWNERS file

	_ = ctx.Walk(func(f core.File) error {
		if base := path.Base(f.Rel); strings.EqualFold(base, "CODEOWNERS") {
			if b, err := ctx.Read(f); err == nil && hasCodeownerEntry(b) {
				codeowners = append(codeowners, path.Dir(f.Rel))
			}
			return nil
		}

		lines, err := ctx.Lines(f)
		if err != nil {
			return nil // unreadable file: skip, never abort the scan
		}

		switch {
		case isWorkflowPath(f.Rel):
			identities = append(identities, workflowIdentity(f.Rel, lines))
		default:
			if obj, arr, ok := parseJSON(joinLines(lines)); ok {
				if ids, handled := jsonIdentities(f.Rel, obj, arr, lines); handled {
					identities = append(identities, ids...)
					return nil
				}
			}
			identities = append(identities, genericIdentities(f.Rel, lines)...)
		}
		return nil
	})

	applyOwnershipCoverage(identities, codeowners)
	return identities
}

// applyOwnershipCoverage upgrades identities with no local owner marker to
// "owner observed" when a CODEOWNERS file covers their path, mutating in place.
func applyOwnershipCoverage(identities []Identity, codeowners []string) {
	repoWide := false
	var subtrees []string
	for _, dir := range codeowners {
		switch dir {
		case ".", ".github", "docs":
			repoWide = true // canonical CODEOWNERS locations cover the whole repo
		default:
			subtrees = append(subtrees, dir)
		}
	}
	for i := range identities {
		if identities[i].OwnerObserved {
			continue
		}
		if repoWide || coveredBySubtree(identities[i].File, subtrees) {
			identities[i].OwnerObserved = true
			identities[i].OwnerMarkers = append(identities[i].OwnerMarkers, "CODEOWNERS")
		}
	}
}

// coveredBySubtree reports whether file lives under any of the given directories.
func coveredBySubtree(file string, dirs []string) bool {
	d := path.Dir(file)
	for _, root := range dirs {
		if d == root || strings.HasPrefix(d+"/", root+"/") {
			return true
		}
	}
	return false
}

// hasCodeownerEntry reports whether a CODEOWNERS body has at least one
// non-comment, non-blank ownership line.
func hasCodeownerEntry(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		return true
	}
	return false
}

// isWorkflowPath reports whether rel is a GitHub Actions workflow file.
func isWorkflowPath(rel string) bool {
	if !strings.Contains(rel, ".github/workflows/") {
		return false
	}
	return strings.HasSuffix(rel, ".yml") || strings.HasSuffix(rel, ".yaml")
}

// joinLines reconstructs file text (newline-joined) for JSON parsing without a
// second read.
func joinLines(lines []string) string { return strings.Join(lines, "\n") }

// parseJSON attempts to decode text as a JSON object or array. Exactly one of
// obj/arr is non-nil on success.
func parseJSON(text string) (obj map[string]interface{}, arr []interface{}, ok bool) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return nil, nil, false
	}
	switch trimmed[0] {
	case '{':
		var m map[string]interface{}
		if json.Unmarshal([]byte(trimmed), &m) == nil {
			return m, nil, true
		}
	case '[':
		var a []interface{}
		if json.Unmarshal([]byte(trimmed), &a) == nil {
			return nil, a, true
		}
	}
	return nil, nil, false
}

// --- JSON sources: GCP service-account keys and cloud IAM policies ----------

// jsonIdentities routes a parsed JSON document to the SA-key or IAM-policy
// extractor. handled is false when the JSON is neither shape, so the caller can
// fall back to a generic credential scan.
func jsonIdentities(rel string, obj map[string]interface{}, arr []interface{}, lines []string) (ids []Identity, handled bool) {
	if obj != nil {
		if asString(obj["type"]) == "service_account" {
			return []Identity{serviceAccountKey(rel, obj, lines)}, true
		}
		if _, ok := obj["Statement"]; ok {
			return []Identity{iamIdentity(rel, obj, lines)}, true
		}
	}
	if arr != nil {
		var out []Identity
		for _, el := range arr {
			if m, ok := el.(map[string]interface{}); ok {
				if _, has := m["Statement"]; has {
					out = append(out, iamIdentity(rel, m, lines))
				}
			}
		}
		if len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

// serviceAccountKey builds a service-account identity from a GCP SA key JSON.
func serviceAccountKey(rel string, obj map[string]interface{}, lines []string) Identity {
	meta := jsonMeta(obj)
	name := asString(obj["client_email"])
	if name == "" {
		name = "service-account:" + rel
	}
	id := Identity{
		Kind:    KindServiceAccount,
		Name:    name,
		File:    rel,
		Line:    lineOf(lines, "client_email"),
		DefLine: "client_email: " + name,
	}
	if pk := asString(obj["private_key"]); strings.TrimSpace(pk) != "" {
		id.SecretExposed = true
		id.secret = pk
	}
	if proj := asString(obj["project_id"]); proj != "" {
		id.BlastRadius = append(id.BlastRadius, "gcp-project:"+proj)
	}
	finishMeta(&id, meta)
	return id
}

// iamIdentity builds an identity from a cloud IAM policy document, extracting
// its permissions and observed blast radius and flagging broad grants.
func iamIdentity(rel string, obj map[string]interface{}, lines []string) Identity {
	meta := jsonMeta(obj)
	name := firstNonEmpty(
		asString(obj["PolicyName"]), asString(obj["Id"]),
		asString(obj["RoleName"]), asString(obj["Sid"]),
	)
	kind := KindServiceAccount
	broad := false
	var perms, radius []string
	federated := false

	for _, st := range statementList(obj["Statement"]) {
		if asString(st["Sid"]) != "" && name == "" {
			name = asString(st["Sid"])
		}
		if principalIsFederated(st["Principal"]) {
			federated = true
		}
		actions := stringList(st["Action"])
		resources := stringList(st["Resource"])
		if len(resources) == 0 {
			resources = []string{"*"}
		}
		for _, a := range actions {
			perms = append(perms, a)
			if isBroadAction(a) {
				broad = true
			}
			for _, r := range resources {
				radius = append(radius, a+" → "+r)
			}
		}
	}
	if federated {
		kind = KindWorkloadIdentity
	}
	if name == "" {
		name = "iam-policy:" + rel
	}
	id := Identity{
		Kind:        kind,
		Name:        name,
		File:        rel,
		Line:        lineOf(lines, "Statement"),
		DefLine:     string(kind) + ": " + name,
		Permissions: dedupeSorted(perms),
		BlastRadius: dedupeSorted(radius),
	}
	if broad {
		id.markBroad()
	}
	finishMeta(&id, meta)
	return id
}

// markBroad records that the identity carries a broad/admin permission grant.
func (id *Identity) markBroad() { id.broad = true }

// isBroadAction reports whether an IAM action string is a wildcard/admin grant.
func isBroadAction(a string) bool {
	a = strings.TrimSpace(a)
	switch a {
	case "*", "*:*", "iam:*":
		return true
	}
	if strings.Contains(a, "AdministratorAccess") {
		return true
	}
	return strings.HasSuffix(a, ":*")
}

// principalIsFederated reports whether an IAM Principal denotes a federated /
// web-identity (workload identity) rather than a plain service account.
func principalIsFederated(p interface{}) bool {
	m, ok := p.(map[string]interface{})
	if !ok {
		return false
	}
	for k := range m {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "federated") || strings.Contains(lk, "webidentity") || strings.Contains(lk, "oidc") {
			return true
		}
	}
	return false
}

// statementList normalizes a Statement value (object or array) to a slice of
// objects.
func statementList(v interface{}) []map[string]interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		return []map[string]interface{}{t}
	case []interface{}:
		var out []map[string]interface{}
		for _, el := range t {
			if m, ok := el.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	default:
		return nil
	}
}

// --- GitHub Actions workflow source ----------------------------------------

var (
	reSecretRef    = regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}`)
	reWorkflowName = regexp.MustCompile(`(?m)^name:\s*(.+?)\s*$`)
	reWriteAll     = regexp.MustCompile(`(?m)permissions:\s*write-all\b`)
)

// workflowIdentity builds a CI identity from a GitHub Actions workflow.
func workflowIdentity(rel string, lines []string) Identity {
	text := joinLines(lines)
	name := rel
	if m := reWorkflowName.FindStringSubmatch(text); m != nil {
		name = strings.Trim(strings.TrimSpace(m[1]), `"'`)
	}
	id := Identity{
		Kind:    KindCIIdentity,
		Name:    name,
		File:    rel,
		Line:    1,
		DefLine: "workflow: " + rel,
	}

	// Observed secret references form the blast radius (names only, not values).
	seen := map[string]bool{}
	for _, m := range reSecretRef.FindAllStringSubmatch(text, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			id.BlastRadius = append(id.BlastRadius, "secrets."+m[1])
		}
	}
	sort.Strings(id.BlastRadius)
	id.SecretReferences = len(id.BlastRadius) > 0

	if reWriteAll.MatchString(text) {
		id.markBroad()
		id.Permissions = []string{"write-all"}
	}
	if strings.Contains(text, "pull_request_target") && id.SecretReferences {
		id.PRTargetSecrets = true
	}

	finishMeta(&id, collectMeta(lines))
	return id
}

// --- Generic credential source (env / config lines) ------------------------

var (
	reAssign   = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*(.*?)\s*$`)
	reSecretKW = regexp.MustCompile(`(?i)(password|passwd|passphrase|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token|bearer|credential)`)
)

// providerToken matches a known credential shape and returns a non-secret label
// for the provider. Values are only ever masked, never printed raw.
var providerTokens = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "aws-access-key"},
	{regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{20,}`), "github-token"},
	{regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`), "slack-token"},
	{regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), "google-api-key"},
	{regexp.MustCompile(`sk_live_[0-9A-Za-z]{10,}`), "stripe-secret-key"},
}

// genericIdentities scans plain config/env lines for credential assignments and
// standalone provider tokens, producing api-key identities.
func genericIdentities(rel string, lines []string) []Identity {
	meta := collectMeta(lines)
	var out []Identity
	seenName := map[string]bool{} // one identity per key name per file

	for i, line := range lines {
		if m := reAssign.FindStringSubmatch(line); m != nil {
			key, value := m[1], unquote(m[2])
			if reSecretKW.MatchString(key) || providerLabel(value) != "" {
				if seenName[key] {
					continue
				}
				seenName[key] = true
				out = append(out, credentialIdentity(rel, key, value, i+1, meta))
				continue
			}
		}
		// Standalone provider token on a line with no secret-named assignment.
		if label := providerLabel(line); label != "" && reAssign.FindStringSubmatch(line) == nil {
			if seenName[label] {
				continue
			}
			seenName[label] = true
			tok := providerMatch(line)
			out = append(out, credentialIdentity(rel, label, tok, i+1, meta))
		}
	}
	return out
}

// credentialIdentity builds one api-key identity, classifying the value as an
// exposed secret or a mere reference.
func credentialIdentity(rel, name, value string, line int, meta map[string]string) Identity {
	id := Identity{
		Kind: KindAPIKey,
		Name: name,
		File: rel,
		Line: line,
	}
	if isReference(value) {
		id.SecretReferences = true
		id.DefLine = name + " = " + value // a reference/placeholder, safe to show
	} else {
		id.SecretExposed = true
		id.secret = value
		id.DefLine = name + " = " + redact.Mask(value) // never store the raw value
	}
	finishMeta(&id, meta)
	return id
}

// providerLabel returns the provider label for the first token shape found in s,
// or "" if none.
func providerLabel(s string) string {
	for _, p := range providerTokens {
		if p.re.MatchString(s) {
			return p.label
		}
	}
	return ""
}

// providerMatch returns the first provider-token substring of s (for masking).
func providerMatch(s string) string {
	for _, p := range providerTokens {
		if loc := p.re.FindString(s); loc != "" {
			return loc
		}
	}
	return ""
}

// isReference reports whether a value is a placeholder or an interpolation
// reference rather than a committed secret.
func isReference(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	if strings.HasPrefix(v, "$") || strings.Contains(v, "${{") {
		return true
	}
	if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
		return true
	}
	switch strings.ToLower(v) {
	case "changeme", "change_me", "placeholder", "example", "todo", "tbd", "xxx", "your_token_here", "redacted":
		return true
	}
	return false
}

// unquote strips one layer of matching surrounding quotes and trailing inline
// comments from a value.
func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') ||
			(v[0] == '\'' && v[len(v)-1] == '\'') ||
			(v[0] == '`' && v[len(v)-1] == '`') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// --- shared helpers ---------------------------------------------------------

// finishMeta applies owner and staleness signals derived from meta to an
// identity.
func finishMeta(id *Identity, meta map[string]string) {
	if markers := ownerMarkers(meta); len(markers) > 0 {
		id.OwnerObserved = true
		id.OwnerMarkers = append(id.OwnerMarkers, markers...)
	}
	id.StaleReason = staleReason(meta)
}

// collectMeta scans lines for `key: value`, `key = value`, and their commented
// forms, returning a normalized key→value map (first occurrence wins). It is
// used for owner/staleness signals only; values are never rendered.
func collectMeta(lines []string) map[string]string {
	meta := map[string]string{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		line = strings.TrimPrefix(line, "#")
		line = strings.TrimPrefix(line, "//")
		line = strings.TrimPrefix(line, "- ")
		line = strings.TrimSpace(line)
		idx := strings.IndexAny(line, ":=")
		if idx <= 0 {
			continue
		}
		key := normKey(line[:idx])
		if _, ok := meta[key]; ok {
			continue
		}
		meta[key] = unquote(line[idx+1:])
	}
	return meta
}

// jsonMeta flattens a JSON object's scalar fields (plus one level of a "labels"
// or "tags" object) into a normalized meta map for owner/staleness signals.
func jsonMeta(obj map[string]interface{}) map[string]string {
	meta := map[string]string{}
	for k, v := range obj {
		switch t := v.(type) {
		case map[string]interface{}:
			if lk := strings.ToLower(k); lk == "labels" || lk == "tags" {
				for lk2, lv := range t {
					if s := scalarString(lv); s != "" {
						setIfAbsent(meta, normKey(lk2), s)
					}
				}
			}
		default:
			if s := scalarString(v); s != "" {
				setIfAbsent(meta, normKey(k), s)
			}
		}
	}
	return meta
}

func setIfAbsent(m map[string]string, k, v string) {
	if _, ok := m[k]; !ok {
		m[k] = v
	}
}

// normKey lowercases a key and normalizes separators so lookups are stable.
func normKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	return s
}

// scalarString renders a JSON scalar as a string, or "" for non-scalars.
func scalarString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return trimFloat(t)
	default:
		return ""
	}
}

// trimFloat formats a JSON number without a trailing ".0" for whole values.
func trimFloat(f float64) string {
	if f == float64(int64(f)) {
		return itoa64(int64(f))
	}
	// Non-integer numbers are not used as owner/stale signals; a stable, lossy
	// rendering is sufficient and never printed.
	return "num"
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// asString returns v as a string, or "" if it is not a string.
func asString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// stringList normalizes a JSON string-or-array value to a slice of strings.
func stringList(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		var out []string
		for _, el := range t {
			if s, ok := el.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// firstNonEmpty returns the first non-empty string argument, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// dedupeSorted returns the sorted, de-duplicated form of in.
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// lineOf returns the 1-based line number of the first line containing needle,
// or 1 if none is found.
func lineOf(lines []string, needle string) int {
	for i, l := range lines {
		if strings.Contains(l, needle) {
			return i + 1
		}
	}
	return 1
}

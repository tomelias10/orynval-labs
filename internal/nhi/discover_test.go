package nhi

import (
	"reflect"
	"testing"

	"github.com/tomelias10/orynval-labs/internal/core"
)

// fakeWalker yields caller-controlled (abs, rel) pairs, letting tests reach the
// read-error branches that the real, readability-checked walker never triggers.
type fakeWalker struct {
	entries [][2]string // {abs, rel}
}

func (w fakeWalker) Walk(fn func(abs, rel string) error) error {
	for _, e := range w.entries {
		if err := fn(e[0], e[1]); err != nil {
			return err
		}
	}
	return nil
}

func TestParseJSON(t *testing.T) {
	if _, _, ok := parseJSON("   "); ok {
		t.Error("blank text should not parse")
	}
	if obj, _, ok := parseJSON(`{"a":1}`); !ok || obj == nil {
		t.Error("object should parse")
	}
	if _, _, ok := parseJSON(`{bad`); ok {
		t.Error("malformed object should not parse")
	}
	if _, arr, ok := parseJSON(`[1,2]`); !ok || arr == nil {
		t.Error("array should parse")
	}
	if _, _, ok := parseJSON(`[bad`); ok {
		t.Error("malformed array should not parse")
	}
	if _, _, ok := parseJSON(`hello`); ok {
		t.Error("non-JSON should not parse")
	}
}

func TestIsWorkflowPath(t *testing.T) {
	cases := map[string]bool{
		".github/workflows/ci.yml":         true,
		".github/workflows/ci.yaml":        true,
		".github/workflows/readme.md":      false,
		"src/.github/workflows/deploy.yml": true,
		"workflows/ci.yml":                 false,
	}
	for rel, want := range cases {
		if got := isWorkflowPath(rel); got != want {
			t.Errorf("isWorkflowPath(%q) = %v, want %v", rel, got, want)
		}
	}
}

func TestServiceAccountKeyVariants(t *testing.T) {
	// Full key with private_key and project.
	id := serviceAccountKey("k.json", map[string]interface{}{
		"type":         "service_account",
		"client_email": "bot@x.iam",
		"project_id":   "p1",
		"private_key":  "-----BEGIN PRIVATE KEY-----X-----END PRIVATE KEY-----",
	}, []string{`"client_email": "bot@x.iam"`})
	if !id.SecretExposed || id.Name != "bot@x.iam" || id.Kind != KindServiceAccount {
		t.Fatalf("unexpected: %+v", id)
	}
	if len(id.BlastRadius) != 1 || id.BlastRadius[0] != "gcp-project:p1" {
		t.Errorf("blast radius = %v", id.BlastRadius)
	}

	// No private_key, no project, no client_email → fallback name, not exposed.
	id2 := serviceAccountKey("dir/k.json", map[string]interface{}{"type": "service_account"}, nil)
	if id2.SecretExposed {
		t.Error("absent private_key must not be exposed")
	}
	if id2.Name != "service-account:dir/k.json" {
		t.Errorf("fallback name = %q", id2.Name)
	}
	if len(id2.BlastRadius) != 0 {
		t.Errorf("no project should mean no radius, got %v", id2.BlastRadius)
	}
}

func TestIAMIdentityVariants(t *testing.T) {
	// Broad, single statement object, name from PolicyName.
	id := iamIdentity("p.json", map[string]interface{}{
		"PolicyName": "Admin",
		"Statement": map[string]interface{}{
			"Action":   "*",
			"Resource": "*",
		},
	}, []string{`"Statement": [`})
	if !id.broad || id.Name != "Admin" || id.Kind != KindServiceAccount {
		t.Fatalf("broad admin policy: %+v", id)
	}

	// Federated principal → workload identity; resource defaulting to "*".
	id2 := iamIdentity("w.json", map[string]interface{}{
		"Statement": []interface{}{
			map[string]interface{}{
				"Sid":       "Fed",
				"Action":    []interface{}{"sts:AssumeRoleWithWebIdentity"},
				"Principal": map[string]interface{}{"Federated": "arn:aws:iam::oidc"},
			},
			"not-an-object",
		},
	}, nil)
	if id2.Kind != KindWorkloadIdentity {
		t.Errorf("federated principal should be workload-identity, got %s", id2.Kind)
	}
	if id2.Name != "Fed" { // Sid fallback
		t.Errorf("name should fall back to Sid, got %q", id2.Name)
	}
	if id2.broad {
		t.Error("scoped federated policy should not be broad")
	}
	// Resource defaulted to "*" so the radius pairs against "*".
	if !reflect.DeepEqual(id2.BlastRadius, []string{"sts:AssumeRoleWithWebIdentity → *"}) {
		t.Errorf("radius = %v", id2.BlastRadius)
	}

	// Name falls through every source to the file-based default.
	id3 := iamIdentity("only.json", map[string]interface{}{
		"Statement": []interface{}{map[string]interface{}{"Action": "s3:GetObject", "Resource": "arn:x"}},
	}, nil)
	if id3.Name != "iam-policy:only.json" {
		t.Errorf("default name = %q", id3.Name)
	}

	// Name from Id and from RoleName.
	if got := iamIdentity("f.json", map[string]interface{}{"Id": "byId", "Statement": []interface{}{}}, nil).Name; got != "byId" {
		t.Errorf("name from Id = %q", got)
	}
	if got := iamIdentity("f.json", map[string]interface{}{"RoleName": "byRole", "Statement": []interface{}{}}, nil).Name; got != "byRole" {
		t.Errorf("name from RoleName = %q", got)
	}
}

func TestWorkflowIdentityVariants(t *testing.T) {
	lines := []string{
		"name: deploy",
		"on:",
		"  pull_request_target:",
		"permissions: write-all",
		"env:",
		"  A: ${{ secrets.TOKEN_A }}",
		"  B: ${{ secrets.TOKEN_A }}", // duplicate → deduped
		"  C: ${{ secrets.TOKEN_B }}",
	}
	id := workflowIdentity(".github/workflows/deploy.yml", lines)
	if id.Kind != KindCIIdentity || id.Name != "deploy" {
		t.Fatalf("unexpected: %+v", id)
	}
	if !id.broad || !id.PRTargetSecrets || !id.SecretReferences {
		t.Errorf("expected broad+prtarget+refs: %+v", id)
	}
	if !reflect.DeepEqual(id.BlastRadius, []string{"secrets.TOKEN_A", "secrets.TOKEN_B"}) {
		t.Errorf("blast radius = %v", id.BlastRadius)
	}

	// No name field (→ rel), no write-all, no secrets (→ no prtarget).
	id2 := workflowIdentity(".github/workflows/x.yml", []string{"on: push", "pull_request_target: []"})
	if id2.Name != ".github/workflows/x.yml" {
		t.Errorf("name should default to rel, got %q", id2.Name)
	}
	if id2.broad || id2.SecretReferences || id2.PRTargetSecrets {
		t.Errorf("no signals expected: %+v", id2)
	}
}

func TestGenericIdentities(t *testing.T) {
	lines := []string{
		"# owner: platform",
		"STRIPE_API_KEY=sk_live_abcdefghij0123456789", // exposed by key + provider
		"DB_PASSWORD=${SECRET}",                       // reference
		"AUTH_TOKEN=changeme",                         // placeholder → reference
		"PLAIN=value",                                 // not secret → skipped
		"STRIPE_API_KEY=other",                        // duplicate key → skipped
		"AKIAIOSFODNN7EXAMPLE",                        // standalone provider token
		"AKIA0000000000000000",                        // standalone, same provider label → deduped
	}
	ids := genericIdentities("app.env", lines)
	m := byName(ids)
	if k, ok := m["STRIPE_API_KEY"]; !ok || !k.SecretExposed || !k.OwnerObserved {
		t.Errorf("STRIPE_API_KEY: %+v", k)
	}
	if k, ok := m["DB_PASSWORD"]; !ok || !k.SecretReferences || k.SecretExposed {
		t.Errorf("DB_PASSWORD should be a reference: %+v", k)
	}
	if k, ok := m["AUTH_TOKEN"]; !ok || !k.SecretReferences {
		t.Errorf("AUTH_TOKEN placeholder should be a reference: %+v", k)
	}
	if _, ok := m["PLAIN"]; ok {
		t.Error("non-secret PLAIN should not be an identity")
	}
	if k, ok := m["aws-access-key"]; !ok || !k.SecretExposed {
		t.Errorf("standalone AWS token: %+v", k)
	}
	// One STRIPE_API_KEY, one aws-access-key despite duplicates.
	if got := len(ids); got != 4 {
		t.Fatalf("expected 4 identities, got %d: %+v", got, ids)
	}
}

func TestJSONIdentitiesRouting(t *testing.T) {
	// Top-level array of policy documents → one IAM identity each.
	_, arr, _ := parseJSON(`[{"PolicyName":"A","Statement":[{"Action":"*","Resource":"*"}]}]`)
	ids, handled := jsonIdentities("pols.json", nil, arr, nil)
	if !handled || len(ids) != 1 || !ids[0].broad {
		t.Fatalf("array of policies: handled=%v ids=%+v", handled, ids)
	}

	// Array with no policy objects (a plain map + a scalar) → not handled.
	_, arr2, _ := parseJSON(`[{"unrelated":"x"}, 7]`)
	if _, handled := jsonIdentities("x.json", nil, arr2, nil); handled {
		t.Error("array without Statement objects should not be handled")
	}

	// Object that is neither SA nor IAM → not handled (generic fallback).
	obj, _, _ := parseJSON(`{"hello":"world"}`)
	if _, handled := jsonIdentities("x.json", obj, nil, nil); handled {
		t.Error("unrelated object should not be handled")
	}
}

func TestIsReference(t *testing.T) {
	refs := []string{"", "$VAR", "${{ secrets.X }}", "<placeholder>", "changeme", "CHANGE_ME", "todo"}
	for _, v := range refs {
		if !isReference(v) {
			t.Errorf("isReference(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"sk_live_real", "plainvalue", "42"} {
		if isReference(v) {
			t.Errorf("isReference(%q) = true, want false", v)
		}
	}
}

func TestUnquote(t *testing.T) {
	cases := map[string]string{
		`"quoted"`: "quoted",
		`'single'`: "single",
		"`back`":   "back",
		`plain`:    "plain",
		`"`:        `"`, // too short to be a pair
		``:         ``,
	}
	for in, want := range cases {
		if got := unquote(in); got != want {
			t.Errorf("unquote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProviderHelpers(t *testing.T) {
	if providerLabel("nothing here") != "" {
		t.Error("no token should give empty label")
	}
	if providerMatch("nothing here") != "" {
		t.Error("no token should give empty match")
	}
	if l := providerLabel("x ghp_012345678901234567890 y"); l != "github-token" {
		t.Errorf("github label = %q", l)
	}
	if mtch := providerMatch("x AKIAIOSFODNN7EXAMPLE y"); mtch != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("aws match = %q", mtch)
	}
}

func TestCollectMeta(t *testing.T) {
	meta := collectMeta([]string{
		"# owner: alpha",
		"// team = beta",
		"- managed-by: gamma",
		"last_used: 2020-01-01",
		"no-separator-here",
		": leading-colon", // idx<=0 → skipped
		"owner: duplicate-wins-first",
	})
	if meta["owner"] != "alpha" {
		t.Errorf("owner = %q (first occurrence should win)", meta["owner"])
	}
	if meta["team"] != "beta" || meta["managed_by"] != "gamma" || meta["last_used"] != "2020-01-01" {
		t.Errorf("meta = %+v", meta)
	}
}

func TestJSONMeta(t *testing.T) {
	meta := jsonMeta(map[string]interface{}{
		"Owner":    "team-x",
		"count":    float64(3),
		"ratio":    float64(1.5),
		"disabled": true,
		"active":   false,
		"labels":   map[string]interface{}{"team": "billing", "nested": map[string]interface{}{"skip": "me"}},
		"nonlabel": map[string]interface{}{"ignored": "yes"}, // map that is not labels/tags → skipped
		"list":     []interface{}{"a"},                       // non-scalar top-level → skipped
	})
	if meta["owner"] != "team-x" {
		t.Errorf("owner = %q", meta["owner"])
	}
	if meta["count"] != "3" || meta["ratio"] != "num" {
		t.Errorf("number rendering: count=%q ratio=%q", meta["count"], meta["ratio"])
	}
	if meta["disabled"] != "true" || meta["active"] != "false" {
		t.Errorf("bool rendering: %+v", meta)
	}
	if meta["team"] != "billing" {
		t.Errorf("label team = %q", meta["team"])
	}
	if _, ok := meta["ignored"]; ok {
		t.Error("non-label nested map should be ignored")
	}
	if _, ok := meta["list"]; ok {
		t.Error("non-scalar list should be ignored")
	}
}

func TestTagsMergedAndSetIfAbsent(t *testing.T) {
	meta := jsonMeta(map[string]interface{}{
		"tags": map[string]interface{}{"owner": "from-tags"},
	})
	if meta["owner"] != "from-tags" {
		t.Errorf("tags owner = %q", meta["owner"])
	}
}

func TestScalarAndNumberHelpers(t *testing.T) {
	if scalarString("s") != "s" || scalarString(true) != "true" || scalarString(false) != "false" {
		t.Error("scalarString basic")
	}
	if scalarString(float64(7)) != "7" || scalarString(float64(2.5)) != "num" {
		t.Error("scalarString numbers")
	}
	if scalarString([]interface{}{}) != "" {
		t.Error("scalarString non-scalar should be empty")
	}
	if trimFloat(4) != "4" || trimFloat(4.2) != "num" {
		t.Error("trimFloat")
	}
	if itoa64(0) != "0" || itoa64(12) != "12" || itoa64(-5) != "-5" {
		t.Errorf("itoa64: %q %q %q", itoa64(0), itoa64(12), itoa64(-5))
	}
}

func TestSmallHelpers(t *testing.T) {
	if asString("x") != "x" || asString(3) != "" {
		t.Error("asString")
	}
	if !reflect.DeepEqual(stringList("a"), []string{"a"}) {
		t.Error("stringList string")
	}
	if !reflect.DeepEqual(stringList([]interface{}{"a", 1, "b"}), []string{"a", "b"}) {
		t.Error("stringList array skips non-strings")
	}
	if stringList(42) != nil {
		t.Error("stringList default nil")
	}
	if firstNonEmpty("", "", "z") != "z" || firstNonEmpty("") != "" {
		t.Error("firstNonEmpty")
	}
	if dedupeSorted(nil) != nil {
		t.Error("dedupeSorted empty")
	}
	if !reflect.DeepEqual(dedupeSorted([]string{"b", "a", "b"}), []string{"a", "b"}) {
		t.Error("dedupeSorted dups")
	}
	if lineOf([]string{"x", "target"}, "target") != 2 || lineOf([]string{"x"}, "z") != 1 {
		t.Error("lineOf")
	}
}

func TestOwnershipHelpers(t *testing.T) {
	if !coveredBySubtree("a/b/c.json", []string{"a/b"}) {
		t.Error("file directly in CODEOWNERS dir should cover (equal-dir branch)")
	}
	if !coveredBySubtree("a/b/deep/c.json", []string{"a/b"}) {
		t.Error("file below CODEOWNERS dir should cover (prefix branch)")
	}
	if coveredBySubtree("x/y.json", []string{"a"}) {
		t.Error("unrelated dir should not cover")
	}
	if !hasCodeownerEntry([]byte("# comment\n\n* @team\n")) {
		t.Error("real entry should be detected")
	}
	if hasCodeownerEntry([]byte("# only comments\n\n")) {
		t.Error("comment-only file has no entry")
	}
}

func TestApplyOwnershipCoverage(t *testing.T) {
	ids := []Identity{
		{Name: "root-file", File: "svc/a.json"},
		{Name: "already", File: "svc/b.json", OwnerObserved: true},
		{Name: "subtree", File: "team/x.json"},
		{Name: "uncovered", File: "other/y.json"},
	}
	// Repo-wide (.github) covers everything; a subtree dir covers team/.
	applyOwnershipCoverage(ids, []string{".github"})
	for _, id := range ids[:3] {
		if !id.OwnerObserved {
			t.Errorf("%s should be owner-covered by repo-wide CODEOWNERS", id.Name)
		}
	}

	ids2 := []Identity{{Name: "in", File: "team/x.json"}, {Name: "out", File: "other/y.json"}}
	applyOwnershipCoverage(ids2, []string{"team"})
	if !ids2[0].OwnerObserved {
		t.Error("team subtree should be covered")
	}
	if ids2[1].OwnerObserved {
		t.Error("other/ should not be covered by team CODEOWNERS")
	}
}

func TestPrincipalIsFederated(t *testing.T) {
	if !principalIsFederated(map[string]interface{}{"Federated": "x"}) {
		t.Error("Federated key")
	}
	if !principalIsFederated(map[string]interface{}{"WebIdentity": "x"}) {
		t.Error("WebIdentity key")
	}
	if !principalIsFederated(map[string]interface{}{"OIDCProvider": "x"}) {
		t.Error("oidc key")
	}
	if principalIsFederated(map[string]interface{}{"AWS": "x"}) {
		t.Error("plain principal is not federated")
	}
	if principalIsFederated("string-principal") {
		t.Error("non-map principal is not federated")
	}
}

func TestIsBroadAction(t *testing.T) {
	for _, a := range []string{"*", "*:*", "iam:*", "AdministratorAccess", "s3:*"} {
		if !isBroadAction(a) {
			t.Errorf("isBroadAction(%q) should be true", a)
		}
	}
	if isBroadAction("s3:GetObject") {
		t.Error("scoped action is not broad")
	}
}

func TestStatementList(t *testing.T) {
	if got := statementList(map[string]interface{}{"Action": "*"}); len(got) != 1 {
		t.Error("object statement")
	}
	if got := statementList([]interface{}{map[string]interface{}{}, "skip"}); len(got) != 1 {
		t.Error("array statement skips non-objects")
	}
	if statementList(42) != nil {
		t.Error("unknown statement shape → nil")
	}
}

// TestDiscoverReadErrorBranches uses a fake walker to yield unreadable paths,
// exercising the defensive skip branches the real walker never reaches.
func TestDiscoverReadErrorBranches(t *testing.T) {
	w := fakeWalker{entries: [][2]string{
		{"/nonexistent/CODEOWNERS", "CODEOWNERS"},
		{"/nonexistent/app.env", "app.env"},
	}}
	ctx := core.NewContext("/nonexistent", w, core.Options{})
	if ids := discover(ctx); len(ids) != 0 {
		t.Fatalf("unreadable entries should yield no identities, got %+v", ids)
	}
}

// TestDiscoverDispatch runs discover end to end over a tree hitting the JSON,
// workflow, generic, and CODEOWNERS-coverage paths together.
func TestDiscoverDispatch(t *testing.T) {
	ids := scanTree(t, map[string]string{
		"svc/CODEOWNERS":           "* @platform\n",
		"svc/sa.json":              `{"type":"service_account","client_email":"b@x.iam","private_key":"-----BEGIN PRIVATE KEY-----X-----END PRIVATE KEY-----"}`,
		"svc/notjson.txt":          "PLAIN TEXT, no identities\n",
		".github/workflows/ci.yml": "name: ci\npermissions: write-all\n",
		"plain.json":               `{"unrelated":"json","no":"markers"}`, // JSON but not SA/IAM → generic fallback (no secrets)
	})
	m := byName(ids)
	// The SA key lives under svc/ which has a CODEOWNERS → owner observed.
	sa, ok := m["b@x.iam"]
	if !ok || !sa.OwnerObserved {
		t.Fatalf("SA under CODEOWNERS should be owner-covered: %+v", sa)
	}
	// The workflow is a CI identity with broad perms.
	if ci, ok := m["ci"]; !ok || !ci.broad {
		t.Errorf("workflow identity: %+v", ci)
	}
	// plain.json and notjson.txt contribute no identities.
	if len(ids) != 2 {
		t.Fatalf("expected exactly 2 identities (SA + CI), got %d: %+v", len(ids), ids)
	}
}

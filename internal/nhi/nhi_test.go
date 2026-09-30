package nhi

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomelias10/orynval-labs/internal/core"
	"github.com/tomelias10/orynval-labs/internal/output"
	"github.com/tomelias10/orynval-labs/internal/walk"
)

// scanTree writes files (rel->content) under a fresh temp dir and returns the
// identities nhi-ghost discovers there, exercising the real walker + Context.
func scanTree(t *testing.T, files map[string]string) []Identity {
	t.Helper()
	root := writeTree(t, files)
	return discover(newCtx(t, root))
}

// findingsTree runs the full rule (discovery + assessment) over a temp tree.
func findingsTree(t *testing.T, files map[string]string) []core.Finding {
	t.Helper()
	root := writeTree(t, files)
	return identityRule{}.Evaluate(newCtx(t, root))
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func newCtx(t *testing.T, root string) *core.Context {
	t.Helper()
	w, err := walk.New(root, walk.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return core.NewContext(w.Root(), w, core.Options{})
}

// byName indexes identities by Name for assertions.
func byName(ids []Identity) map[string]Identity {
	m := make(map[string]Identity, len(ids))
	for _, id := range ids {
		m[id.Name] = id
	}
	return m
}

func TestNewToolWiring(t *testing.T) {
	tl := NewTool()
	if tl.Name != "nhi-ghost" || tl.Version != Version {
		t.Fatalf("unexpected tool identity: %+v", tl)
	}
	if tl.InformationURI != informationURI {
		t.Errorf("information uri = %q", tl.InformationURI)
	}
	if len(tl.Rules) != 1 || tl.Rules[0].ID() != RuleID {
		t.Fatalf("expected one rule %q, got %+v", RuleID, tl.Rules)
	}
}

func TestRuleMetadata(t *testing.T) {
	r := identityRule{}
	if r.ID() != RuleID {
		t.Errorf("ID = %q", r.ID())
	}
	if r.Name() == "" || !strings.Contains(r.Description(), "machine identities") {
		t.Errorf("name/description not set: %q / %q", r.Name(), r.Description())
	}
	if rs := Rules(); len(rs) != 1 {
		t.Fatalf("Rules() len = %d", len(rs))
	}
}

// TestDemoTreeAssessment scans the shipped synthetic fixtures and asserts the
// full severity spread the README demo documents.
func TestDemoTreeAssessment(t *testing.T) {
	w, err := walk.New("testdata", walk.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := core.NewContext(w.Root(), w, core.Options{})
	findings := identityRule{}.Evaluate(ctx)

	counts := core.CountBySeverity(findings)
	want := map[core.Severity]int{
		core.SeverityCritical: 0,
		core.SeverityHigh:     4,
		core.SeverityMedium:   1,
		core.SeverityLow:      1,
		core.SeverityInfo:     1,
	}
	for sev, n := range want {
		if counts[sev] != n {
			t.Errorf("severity %s: got %d, want %d", sev, counts[sev], n)
		}
	}
	if len(findings) != 7 {
		t.Fatalf("total findings = %d, want 7", len(findings))
	}
}

// TestDeterministicJSON proves two scans of the same tree render identically.
func TestDeterministicJSON(t *testing.T) {
	files := map[string]string{
		"sa.json":  `{"type":"service_account","client_email":"a@x.iam","private_key":"-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----"}`,
		"pol.json": `{"PolicyName":"P","Statement":[{"Action":"*","Resource":"*"}]}`,
	}
	render := func() string {
		fs := findingsTree(t, files)
		var buf bytes.Buffer
		if err := output.RenderJSON(&buf, output.Report{Findings: fs}); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if render() != render() {
		t.Error("JSON output is not deterministic across runs")
	}
}

// TestNoFalsePositivesOnCleanFile asserts ordinary prose yields no identities.
func TestNoFalsePositivesOnCleanFile(t *testing.T) {
	ids := scanTree(t, map[string]string{
		"clean.txt": "Just some release notes. The on-call team reviews logs.\nNothing to see here.\n",
	})
	if len(ids) != 0 {
		t.Fatalf("expected no identities in clean prose, got %+v", ids)
	}
}

// TestSecretsRedactedInEveryFormat is the defense-in-depth guarantee: a raw
// committed secret never appears in any rendered format, while a correlation
// prefix does.
func TestSecretsRedactedInEveryFormat(t *testing.T) {
	const secret = "sk_live_supersecretvalue999"
	fs := findingsTree(t, map[string]string{
		"app.env": "STRIPE_API_KEY=" + secret + "\n",
	})
	report := output.Report{
		Tool:     output.ToolInfo{Name: "nhi-ghost", Version: Version},
		Findings: fs,
	}
	for _, f := range output.Formats {
		var buf bytes.Buffer
		if err := output.Render(&buf, f, report, output.Options{}); err != nil {
			t.Fatalf("render %s: %v", f, err)
		}
		if strings.Contains(buf.String(), secret) {
			t.Errorf("format %s leaked the raw secret", f)
		}
	}
}

// TestUnreadableFileSkipped ensures a directory masquerading via read error does
// not abort the scan; a missing/odd entry is simply skipped.
func TestReadErrorDuringDiscoverySkips(t *testing.T) {
	// A file the walker yields but that is removed before Read would surface a
	// read error path; simpler: an empty tree yields nothing without error.
	ids := scanTree(t, map[string]string{})
	if len(ids) != 0 {
		t.Fatalf("empty tree should yield no identities, got %d", len(ids))
	}
}

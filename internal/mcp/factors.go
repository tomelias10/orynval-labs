package mcp

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tomelias10/orynval-labs/internal/core"
	"github.com/tomelias10/orynval-labs/internal/redact"
)

// factor is one risk observation about a server. A finding's severity is the max
// over its factors; its evidence enumerates each factor with a redacted detail.
type factor struct {
	id          string
	severity    core.Severity
	confidence  core.Confidence
	kind        core.EvidenceKind
	detail      string // safe to print: no raw secret ever reaches this field
	remediation string
}

// secretKeyRe matches environment-variable names whose shape implies they carry
// a credential (case-insensitive). It is deliberately broad: a secret hiding
// behind a benign key is caught separately by value inspection.
var secretKeyRe = regexp.MustCompile(`(?i)(pass(word|wd|phrase)?|secret|token|api[_-]?key|apikey|access[_-]?key|credential|private[_-]?key|bearer|auth)`)

// detectFactors runs every applicable detector against a server, in a fixed
// order, and returns the factors that fired. Baseline (drift) factors are
// included only when a baseline was supplied.
func detectFactors(s Server, baseline Baseline, haveBaseline bool) []factor {
	var fs []factor
	if f, ok := secretInEnv(s); ok {
		fs = append(fs, f)
	}
	if f, ok := filesystemScope(s); ok {
		fs = append(fs, f)
	}
	if f, ok := riskyCommand(s); ok {
		fs = append(fs, f)
	}
	if f, ok := remoteEndpoint(s); ok {
		fs = append(fs, f)
	}
	if haveBaseline {
		if f, ok := baselineFactor(s, baseline); ok {
			fs = append(fs, f)
		}
	}
	return fs
}

// secretInEnv fires when an env entry is handed an inline credential: either the
// key is secret-shaped and its value is non-empty, or the value itself looks
// like a secret regardless of the key. Values are masked before they reach the
// detail, so no secret is ever printed.
func secretInEnv(s Server) (factor, bool) {
	if len(s.Env) == 0 {
		return factor{}, false
	}
	var hits []string
	for _, k := range sortedKeys(s.Env) {
		v := s.Env[k]
		keyShaped := secretKeyRe.MatchString(k)
		valueLooksSecret := v != "" && redact.Redact(v) != v
		if (keyShaped && v != "") || valueLooksSecret {
			hits = append(hits, k+"="+redact.Mask(v))
		}
	}
	if len(hits) == 0 {
		return factor{}, false
	}
	return factor{
		id:          "secret-in-env",
		severity:    core.SeverityHigh,
		confidence:  core.ConfidenceHigh,
		kind:        core.KindObserved,
		detail:      "inline secret handed to server via env: " + strings.Join(hits, ", "),
		remediation: "Remove the inline secret from the config; inject it at runtime from a secret manager or an out-of-band env var, and rotate the exposed value.",
	}, true
}

// grant classifies how much filesystem reach an argument confers.
type grant int

const (
	grantNone grant = iota
	grantMedium
	grantHigh
)

// fsGrant classifies a single argument. The root, the home directory, and
// $HOME/~ expansions are the highest reach; any other absolute path is a
// narrower but still notable grant. Relative paths are not treated as a grant.
func fsGrant(a string) grant {
	switch {
	case a == "/":
		return grantHigh
	case a == "~" || strings.HasPrefix(a, "~/"):
		return grantHigh
	case strings.Contains(a, "$HOME") || strings.Contains(a, "${HOME}"):
		return grantHigh
	case strings.HasPrefix(a, "/"):
		return grantMedium
	default:
		return grantNone
	}
}

// filesystemScope fires when any argument grants filesystem reach. Severity is
// HIGH if any argument reaches the root or home, else MEDIUM. The detail lists
// every granting path.
func filesystemScope(s Server) (factor, bool) {
	var paths []string
	high := false
	for _, a := range s.Args {
		switch fsGrant(a) {
		case grantHigh:
			high = true
			paths = append(paths, a)
		case grantMedium:
			paths = append(paths, a)
		}
	}
	if len(paths) == 0 {
		return factor{}, false
	}
	sev := core.SeverityMedium
	if high {
		sev = core.SeverityHigh
	}
	return factor{
		id:          "broad-filesystem-scope",
		severity:    sev,
		confidence:  core.ConfidenceHigh,
		kind:        core.KindObserved,
		detail:      "filesystem scope granted to: " + strings.Join(paths, ", "),
		remediation: "Scope the server to the narrowest project subdirectory it needs instead of the root or home directory.",
	}, true
}

// curlPipeShell reports whether a command downloads a script and pipes it into a
// shell — the classic unaudited-remote-execution pattern.
func curlPipeShell(joined string) bool {
	if !strings.Contains(joined, "curl") && !strings.Contains(joined, "wget") {
		return false
	}
	return strings.Contains(joined, "| sh") || strings.Contains(joined, "|sh") ||
		strings.Contains(joined, "| bash") || strings.Contains(joined, "|bash")
}

// dockerMountsRoot reports whether any argument mounts the host root into a
// container ("-v /:/host" → the mount spec argument starts with "/:").
func dockerMountsRoot(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "/:") {
			return true
		}
	}
	return false
}

// autoApprove reports whether a command disables the human-in-the-loop guardrail
// via a known auto-approve / skip-permissions flag.
func autoApprove(joined string) bool {
	for _, flag := range []string{"--yolo", "--dangerously-skip-permissions", "--auto-approve", "--yes-always"} {
		if strings.Contains(joined, flag) {
			return true
		}
	}
	return false
}

// pinned reports whether a package spec names an explicit version. It handles
// npm scoped packages ("@scope/name@version"), plain npm ("name@version"), and
// uv ("name==version").
func pinned(pkg string) bool {
	if i := strings.Index(pkg, "=="); i >= 0 {
		// PEP 440 "==" is an exact pin unless it carries a wildcard (==1.*).
		v := pkg[i+2:]
		return v != "" && !strings.Contains(v, "*")
	}
	p := pkg
	if strings.HasPrefix(p, "@") {
		p = p[1:] // drop the scope's leading '@' so only a version '@' remains
	}
	i := strings.LastIndex(p, "@")
	if i < 0 {
		return false
	}
	// A dist-tag ("latest", "next") or a range ("^1.2.0", "1.x", "1") is
	// mutable: it resolves to whatever is published at launch time.
	return exactVersion.MatchString(p[i+1:])
}

// exactVersion matches an exact, immutable version such as 1.2.3 or
// v1.2.3-rc.1. Dist-tags and ranges do not match.
var exactVersion = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.\-]+)?$`)

// firstPackageArg returns the first non-flag argument, which for npx/uvx is the
// package spec being installed and run.
func firstPackageArg(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// npxUnpinned reports whether an "npx -y <pkg>" auto-installs an unpinned
// package (the "-y"/"--yes" flag makes it non-interactive, so an unpinned
// package is fetched and run without confirmation).
func npxUnpinned(args []string) bool {
	hasYes := false
	for _, a := range args {
		if a == "-y" || a == "--yes" {
			hasYes = true
			break
		}
	}
	if !hasYes {
		return false
	}
	pkg := firstPackageArg(args)
	if pkg == "" {
		return false
	}
	return !pinned(pkg)
}

// uvxUnpinned reports whether a "uvx <pkg>" auto-installs an unpinned package.
// uvx always fetches on demand, so no confirmation flag is required for the risk
// to apply.
func uvxUnpinned(args []string) bool {
	pkg := firstPackageArg(args)
	if pkg == "" {
		return false
	}
	return !pinned(pkg)
}

// unpinnedInstaller reports whether the server launches via an auto-installing
// runner (npx/uvx) against an unpinned package.
func unpinnedInstaller(s Server) bool {
	switch baseName(s.Command) {
	case "npx":
		return npxUnpinned(s.Args)
	case "uvx":
		return uvxUnpinned(s.Args)
	default:
		return false
	}
}

// riskyCommand fires on dangerous launch patterns. The HIGH patterns grant broad
// or unaudited execution power; the MEDIUM pattern is an unpinned auto-install.
// The discovered command is inspected as text and never executed.
func riskyCommand(s Server) (factor, bool) {
	joined := strings.ToLower(strings.Join(append([]string{s.Command}, s.Args...), " "))
	var reasons []string
	high := false
	if curlPipeShell(joined) {
		reasons = append(reasons, "pipes a downloaded script into a shell")
		high = true
	}
	if strings.Contains(joined, "--privileged") {
		reasons = append(reasons, "runs a container with --privileged (full host capabilities)")
		high = true
	}
	if dockerMountsRoot(s.Args) {
		reasons = append(reasons, "mounts the host root filesystem into a container")
		high = true
	}
	if autoApprove(joined) {
		reasons = append(reasons, "disables the permission prompt (auto-approve / skip-permissions)")
		high = true
	}
	if unpinnedInstaller(s) {
		reasons = append(reasons, "auto-installs an unpinned package (no version)")
	}
	if len(reasons) == 0 {
		return factor{}, false
	}
	sev := core.SeverityMedium
	if high {
		sev = core.SeverityHigh
	}
	return factor{
		id:          "risky-command",
		severity:    sev,
		confidence:  core.ConfidenceHigh,
		kind:        core.KindObserved,
		detail:      "risky launch command — " + strings.Join(reasons, "; "),
		remediation: "Replace the risky launch with a pinned, least-privilege invocation; drop --privileged / root mounts / auto-approve flags and pin package versions.",
	}, true
}

// remoteEndpoint fires for a URL (remote) server, recording the network egress
// destination. The host is extracted from the URL text only and never contacted.
func remoteEndpoint(s Server) (factor, bool) {
	if s.URL == "" {
		return factor{}, false
	}
	return factor{
		id:          "remote-endpoint",
		severity:    core.SeverityMedium,
		confidence:  core.ConfidenceHigh,
		kind:        core.KindObserved,
		detail:      "remote server: network egress to " + urlHost(s.URL),
		remediation: "Confirm the endpoint is an approved, trusted service; prefer a locally run stdio server where possible.",
	}, true
}

// baselineFactor compares a server against the supplied baseline: a name absent
// from the baseline is unapproved (an inference); a name present but with a
// different signature has drifted (an observation).
func baselineFactor(s Server, b Baseline) (factor, bool) {
	approvedSig, ok := b.Servers[s.Name]
	if !ok {
		return factor{
			id:          "unapproved-server",
			severity:    core.SeverityMedium,
			confidence:  core.ConfidenceMedium,
			kind:        core.KindInferred,
			detail:      fmt.Sprintf("server %q is not present in the approved baseline", s.Name),
			remediation: "Review the server and, if it is intended, add it to .orynval/mcp-baseline.json; otherwise remove it from the config.",
		}, true
	}
	if approvedSig != s.Signature {
		return factor{
			id:          "baseline-drift",
			severity:    core.SeverityHigh,
			confidence:  core.ConfidenceHigh,
			kind:        core.KindObserved,
			detail:      fmt.Sprintf("server %q config differs from its approved baseline signature (approved %s, observed %s)", s.Name, shortSig(approvedSig), shortSig(s.Signature)),
			remediation: "Review the change to the server's config; if it is intended, re-approve it by updating its signature in .orynval/mcp-baseline.json.",
		}, true
	}
	return factor{}, false
}

// shortSig trims a signature to a human-sized prefix for evidence.
func shortSig(sig string) string {
	if len(sig) <= 12 {
		return sig
	}
	return sig[:12]
}

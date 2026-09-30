package mcp

import (
	"fmt"
	"strings"

	"github.com/orynval/orynval-labs/internal/core"
)

// Rule is the single composite mcp-drift rule. It discovers every MCP/agent
// server in the tree and emits one finding per server: a risk finding when any
// factor fires, otherwise an INFO inventory entry (knowing what is connected is
// itself the point).
type Rule struct{}

// NewRule returns the mcp-drift rule as a core.Rule.
func NewRule() core.Rule { return Rule{} }

// ID returns the stable rule identifier.
func (Rule) ID() string { return RuleID }

// Name returns a short human label.
func (Rule) Name() string { return "MCP / AI-agent config audit" }

// Description explains what the rule inspects.
func (Rule) Description() string {
	return "Discovers local MCP/AI-agent server configs and audits each server's " +
		"filesystem scope, network egress, inline secrets, risky launch commands, " +
		"and drift from an approved baseline. Read-only: never executes a discovered command."
}

// Evaluate walks the tree once, collecting server entries and (if present) the
// baseline, then assesses each server into a finding. The walk reads files
// through the shared context cache and never executes anything it discovers.
func (r Rule) Evaluate(ctx *core.Context) []core.Finding {
	var servers []Server
	var baseline Baseline
	haveBaseline := false

	_ = ctx.Walk(func(f core.File) error {
		// A read error yields nil content, which serversFromFile/parseBaseline
		// both treat as "not a config", so there is no separate error path.
		content, _ := ctx.Read(f)
		if f.Rel == baselineRel {
			if b, ok := parseBaseline(content); ok {
				baseline = b
				haveBaseline = true
			}
			return nil
		}
		servers = append(servers, serversFromFile(f.Rel, content)...)
		return nil
	})

	findings := make([]core.Finding, 0, len(servers))
	for _, s := range servers {
		findings = append(findings, assess(s, baseline, haveBaseline))
	}
	return findings
}

// assess turns one server plus baseline context into a single finding.
func assess(s Server, baseline Baseline, haveBaseline bool) core.Finding {
	factors := detectFactors(s, baseline, haveBaseline)

	severity := core.SeverityInfo
	confidence := core.ConfidenceHigh
	allInferred := len(factors) > 0
	for _, f := range factors {
		if f.severity.Rank() > severity.Rank() {
			severity = f.severity
		}
		if f.kind != core.KindInferred {
			allInferred = false
		}
	}
	if allInferred {
		// The only signal is an inference (e.g. an unapproved but otherwise
		// clean server); reflect that lower certainty.
		confidence = core.ConfidenceMedium
	}

	evidence := make([]core.Evidence, 0, len(factors)+1)
	evidence = append(evidence, core.Evidence{
		File:    s.File,
		Line:    s.Line,
		Snippet: inventorySnippet(s),
		Kind:    core.KindObserved,
	})
	for _, f := range factors {
		evidence = append(evidence, core.Evidence{
			File:    s.File,
			Line:    s.Line,
			Snippet: f.id + ": " + f.detail,
			Kind:    f.kind,
		})
	}

	return core.Finding{
		RuleID:           RuleID,
		Title:            title(s, factors),
		What:             what(s, factors),
		Where:            where(s),
		Why:              why(len(factors) == 0),
		Confidence:       confidence,
		Severity:         severity,
		Remediation:      remediation(factors),
		SaferAlternative: "Keep an approved baseline at .orynval/mcp-baseline.json, pin package versions, scope filesystem access to the project, and inject secrets at runtime rather than inline.",
		Evidence:         evidence,
		Fingerprint:      core.ComputeFingerprint(RuleID, s.File, "mcp-server:"+s.Name),
	}
}

// inventorySnippet describes what a server is, as text, for the inventory line.
// A discovered command is shown but never run.
func inventorySnippet(s Server) string {
	if s.URL != "" {
		return fmt.Sprintf("server %q → remote url host %s", s.Name, urlHost(s.URL))
	}
	cmd := s.Command
	if len(s.Args) > 0 {
		cmd += " " + strings.Join(s.Args, " ")
	}
	return fmt.Sprintf("server %q → runs (as text, not executed): %s", s.Name, cmd)
}

// title composes the finding headline: an inventory label when clean, else the
// count and list of factor IDs.
func title(s Server, factors []factor) string {
	base := fmt.Sprintf("MCP server %q", s.Name)
	if len(factors) == 0 {
		return base + " — inventory (no risk factors)"
	}
	return fmt.Sprintf("%s — %d risk factor(s): %s", base, len(factors), strings.Join(factorIDs(factors), ", "))
}

// factorIDs returns the factor identifiers in order for the title.
func factorIDs(factors []factor) []string {
	ids := make([]string, len(factors))
	for i, f := range factors {
		ids[i] = f.id
	}
	return ids
}

// what explains, in one line, what was found.
func what(s Server, factors []factor) string {
	if len(factors) == 0 {
		return fmt.Sprintf("A connected MCP/agent server %q was discovered with no observed risk factors; it is recorded for inventory.", s.Name)
	}
	return fmt.Sprintf("Connected MCP/agent server %q declares %d security-relevant risk factor(s) in its config.", s.Name, len(factors))
}

// where returns the file:line anchor, or just the file when the line is unknown.
func where(s Server) string {
	if s.Line > 0 {
		return fmt.Sprintf("%s:%d", s.File, s.Line)
	}
	return s.File
}

// why states, differently for inventory vs risk, why the finding matters.
func why(clean bool) string {
	if clean {
		return "Every connected MCP server is an unaudited program with filesystem, network, and secret access; tracking even clean servers is how drift and unapproved additions are later detected."
	}
	return "Each MCP server runs with real filesystem reach, network egress, and access to environment secrets, yet is added in minutes and rarely security-reviewed; these factors widen the blast radius of a compromised or malicious server."
}

// remediation joins the per-factor fixes, or returns the inventory guidance.
func remediation(factors []factor) string {
	if len(factors) == 0 {
		return "No action required. Record this server in .orynval/mcp-baseline.json so any future change or unapproved addition is flagged as drift."
	}
	parts := make([]string, len(factors))
	for i, f := range factors {
		parts[i] = f.remediation
	}
	return strings.Join(parts, " ")
}

// Command mcp-drift is a static, read-only, local-only scanner for AI-agent and
// MCP server configuration drift and risky scope. It discovers local MCP/agent
// configs and audits each server's filesystem scope, network egress, inline
// secrets, risky launch commands, and drift from an approved baseline.
//
// It never executes a discovered command, never makes a network request, never
// validates a credential, and emits no telemetry. Output (terminal, JSON, SARIF,
// HTML, badge, share) flows through the shared Orynval Labs core and is
// byte-for-byte deterministic for a given tree.
package main

import (
	"io"
	"os"

	"github.com/tomelias10/orynval-labs/internal/cli"
	"github.com/tomelias10/orynval-labs/internal/core"
	"github.com/tomelias10/orynval-labs/internal/mcp"
)

// version is the tool's reported version. It is a build-time constant; mcp-drift
// records no timestamps and reaches no network to discover it.
const version = "0.1.0"

// osExit is indirected so main's exit path is testable without terminating the
// test process.
var osExit = os.Exit

func main() {
	osExit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run builds the mcp-drift tool on the shared CLI runner and executes it,
// returning the process exit code. It never calls os.Exit itself, so tests can
// drive it directly.
func run(args []string, stdout, stderr io.Writer) int {
	tool := cli.Tool{
		Name:           "mcp-drift",
		Version:        version,
		Summary:        "audit local AI-agent / MCP server configs for risky scope and baseline drift (read-only, offline)",
		InformationURI: "https://github.com/tomelias10/orynval-labs",
		Rules:          []core.Rule{mcp.NewRule()},
	}
	return tool.Run(args, stdout, stderr)
}

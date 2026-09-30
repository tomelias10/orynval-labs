// Package mcp implements mcp-drift: a static, read-only, local-only auditor for
// AI-agent and Model Context Protocol (MCP) server configurations. It discovers
// the MCP/agent configs in a source tree, parses each declared server as data,
// and reports the security-relevant facts about it — what it runs, what
// filesystem and network scope it is granted, which secrets it is handed, which
// risky permission combinations it declares, and whether it has drifted from a
// locally supplied baseline.
//
// Safety posture (enforced by construction): mcp-drift parses config as data and
// never runs a discovered command, never resolves or fetches a discovered URL,
// never installs anything, and never validates a credential. There is no
// os/exec, net, or net/http import anywhere in this package — a discovered
// command is reported only as text. Like the rest of the toolkit it is
// deterministic: no clock, no randomness, no telemetry, byte-for-byte stable
// output for a given tree.
package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// RuleID is the stable identifier of the single composite rule mcp-drift ships.
const RuleID = "orynval.mcp.config-audit"

// baselineRel is the conventional in-tree path of the approved-server baseline,
// read (never written) relative to the scan root. Its presence enables the
// drift factors; its absence skips them entirely so there is no false
// "unapproved" noise when no baseline has been established.
const baselineRel = ".orynval/mcp-baseline.json"

// Server is a single MCP/agent server entry discovered in a config file. It is
// the deterministic record every assessment works from.
//
// Command/Args/Env describe a stdio server; URL describes a remote server; a
// given entry has one shape or the other. Signature is the sha256 of the
// server's normalized config and is the anchor for baseline drift detection.
type Server struct {
	// Name is the server's map key (e.g. "filesystem", "github").
	Name string
	// File is the slash-separated path (relative to the scan root) the server
	// was defined in; Line is the 1-based line of its key, or 0 if not located.
	File string
	Line int
	// Command and Args are the stdio launch vector, reported as text and never
	// executed. Env is the inline environment handed to the server.
	Command string
	Args    []string
	Env     map[string]string
	// URL is set instead of Command for a remote (network) server.
	URL string
	// Signature is sha256(normalized server config) as lowercase hex.
	Signature string
}

// Baseline is the approved-server set read from baselineRel: a map from server
// name to its approved signature.
type Baseline struct {
	Servers map[string]string `json:"servers"`
}

// configFile is the shape mcp-drift matches: a JSON object carrying a server map
// under "mcpServers" (Claude Desktop, Cursor) and/or "servers" (VS Code). Each
// entry is kept raw so a non-object value (as in a baseline file, whose values
// are signature strings) is simply skipped rather than mis-parsed.
type configFile struct {
	MCPServers map[string]json.RawMessage `json:"mcpServers"`
	Servers    map[string]json.RawMessage `json:"servers"`
}

// rawServer is a single parsed server entry. Unknown fields are ignored, so
// editor-specific extras (e.g. VS Code's "type") do not defeat the match.
type rawServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
}

// canonicalServer is the normalized form hashed into a Signature. Field order is
// fixed by declaration and map keys are sorted by encoding/json, so the digest
// is identical on any machine for an equivalent config.
type canonicalServer struct {
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	URL     string            `json:"url,omitempty"`
}

// serversFromFile parses one file's bytes into zero or more Servers. Anything
// that is not a JSON object, or that carries no recognizable server map, yields
// no servers. It never errors: an unparseable or unrelated file is simply not a
// config.
func serversFromFile(rel string, content []byte) []Server {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	var cf configFile
	if err := json.Unmarshal(content, &cf); err != nil {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	var out []Server
	out = append(out, buildServers(rel, lines, cf.MCPServers)...)
	out = append(out, buildServers(rel, lines, cf.Servers)...)
	return out
}

// buildServers turns a raw server map into Servers in deterministic (name-sorted)
// order, skipping entries that are not objects or that declare neither a command
// nor a url.
func buildServers(rel string, lines []string, m map[string]json.RawMessage) []Server {
	if len(m) == 0 {
		return nil
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]Server, 0, len(names))
	for _, name := range names {
		var rs rawServer
		if err := json.Unmarshal(m[name], &rs); err != nil {
			continue // value is not an object (e.g. a baseline signature string)
		}
		if rs.Command == "" && rs.URL == "" {
			continue // not a launchable/reachable server entry
		}
		out = append(out, Server{
			Name:      name,
			File:      rel,
			Line:      lineOfKey(lines, name),
			Command:   rs.Command,
			Args:      rs.Args,
			Env:       rs.Env,
			URL:       rs.URL,
			Signature: signature(rs),
		})
	}
	return out
}

// lineOfKey returns the 1-based line of the first occurrence of the quoted key,
// used only to anchor evidence. It returns 0 when the key cannot be located
// (which never breaks a finding — the file path alone still locates it).
func lineOfKey(lines []string, name string) int {
	needle := `"` + name + `"`
	for i, ln := range lines {
		if strings.Contains(ln, needle) {
			return i + 1
		}
	}
	return 0
}

// signature returns sha256(normalized server config) as lowercase hex. The hash
// is one-way, so it is safe to print and to store in a baseline even though the
// normalized form may include an inline secret value.
func signature(rs rawServer) string {
	// encoding/json cannot fail to marshal strings, string slices, and
	// string maps, so the error is structurally impossible and ignored.
	b, _ := json.Marshal(canonicalServer{
		Command: rs.Command,
		Args:    rs.Args,
		Env:     rs.Env,
		URL:     rs.URL,
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// parseBaseline parses the baseline file. It reports ok=false for content that
// is not valid JSON, so a corrupt baseline is treated as "no baseline" rather
// than aborting the scan or flagging every server as drifted.
func parseBaseline(content []byte) (Baseline, bool) {
	var b Baseline
	if err := json.Unmarshal(content, &b); err != nil {
		return Baseline{}, false
	}
	return b, true
}

// urlHost extracts the host from a URL using string operations only — it never
// resolves or contacts the host. It strips the scheme, any path/query/fragment,
// any userinfo, and the port, and preserves an IPv6 literal in brackets.
func urlHost(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if strings.HasPrefix(s, "[") { // IPv6 literal, e.g. [::1]:8080
		if j := strings.Index(s, "]"); j >= 0 {
			return s[:j+1]
		}
		return s
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

// baseName returns the final path element of a command, so "/usr/bin/npx" and
// "npx" are treated the same when classifying an installer. It handles both
// slash flavors without importing path/filepath's OS-specific behavior.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// sortedKeys returns the keys of an env map in lexical order for deterministic
// evidence.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

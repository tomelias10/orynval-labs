package mcp

import (
	"testing"
)

// findServer is a small helper to locate a discovered server by name.
func findServer(servers []Server, name string) (Server, bool) {
	for _, s := range servers {
		if s.Name == name {
			return s, true
		}
	}
	return Server{}, false
}

func TestServersFromFileDiscovery(t *testing.T) {
	content := []byte(`{
  "mcpServers": {
    "fs": {"command": "npx", "args": ["-y", "pkg@1.0"]},
    "web": {"url": "https://example.com/sse"},
    "note": "just a string, not a server",
    "empty": {"description": "no command and no url"}
  },
  "servers": {
    "vs": {"type": "stdio", "command": "node", "args": ["server.js"]}
  }
}`)
	servers := serversFromFile("cfg.json", content)
	// fs, web, vs are valid; note (string) and empty (no command/url) are skipped.
	if len(servers) != 3 {
		t.Fatalf("want 3 servers, got %d: %+v", len(servers), servers)
	}
	fs, ok := findServer(servers, "fs")
	if !ok || fs.Command != "npx" || len(fs.Args) != 2 {
		t.Errorf("fs server not parsed: %+v", fs)
	}
	if fs.File != "cfg.json" || fs.Line != 3 {
		t.Errorf("fs source anchor wrong: file=%q line=%d", fs.File, fs.Line)
	}
	web, ok := findServer(servers, "web")
	if !ok || web.URL != "https://example.com/sse" {
		t.Errorf("web server not parsed: %+v", web)
	}
	vs, ok := findServer(servers, "vs")
	if !ok || vs.Command != "node" {
		t.Errorf("vs (servers-key) not parsed: %+v", vs)
	}
	if _, ok := findServer(servers, "note"); ok {
		t.Error("string entry should not be a server")
	}
	if _, ok := findServer(servers, "empty"); ok {
		t.Error("entry with neither command nor url should be skipped")
	}
}

func TestServersFromFileNonConfig(t *testing.T) {
	cases := map[string][]byte{
		"empty":         []byte(""),
		"whitespace":    []byte("   \n\t "),
		"not-json-obj":  []byte("hello, world"),
		"json-array":    []byte("[1,2,3]"),
		"malformed":     []byte("{not valid json"),
		"no-server-map": []byte(`{"other": {"a": 1}}`),
	}
	for name, content := range cases {
		if got := serversFromFile(name+".json", content); got != nil {
			t.Errorf("%s: expected no servers, got %+v", name, got)
		}
	}
}

func TestSignatureDeterministicAndDistinct(t *testing.T) {
	a := serversFromFile("a.json", []byte(`{"mcpServers":{"x":{"command":"node","args":["s.js"],"env":{"B":"2","A":"1"}}}}`))
	b := serversFromFile("b.json", []byte(`{"mcpServers":{"x":{"command":"node","args":["s.js"],"env":{"A":"1","B":"2"}}}}`))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected one server each, got %d and %d", len(a), len(b))
	}
	// Env key order differs in the source but the normalized signature is equal.
	if a[0].Signature != b[0].Signature {
		t.Errorf("signature not stable across env key order: %s != %s", a[0].Signature, b[0].Signature)
	}
	// A different config produces a different signature.
	c := serversFromFile("c.json", []byte(`{"mcpServers":{"x":{"command":"node","args":["other.js"]}}}`))
	if c[0].Signature == a[0].Signature {
		t.Error("different configs should have different signatures")
	}
	// Signatures are lowercase hex of sha256 (64 chars).
	if len(a[0].Signature) != 64 {
		t.Errorf("signature length = %d, want 64", len(a[0].Signature))
	}
}

func TestLineOfKey(t *testing.T) {
	lines := []string{`{`, `  "mcpServers": {`, `    "found": {}`, `  }`, `}`}
	if got := lineOfKey(lines, "found"); got != 3 {
		t.Errorf("lineOfKey(found) = %d, want 3", got)
	}
	if got := lineOfKey(lines, "absent"); got != 0 {
		t.Errorf("lineOfKey(absent) = %d, want 0", got)
	}
}

func TestParseBaseline(t *testing.T) {
	b, ok := parseBaseline([]byte(`{"servers":{"a":"sig-a","b":"sig-b"}}`))
	if !ok {
		t.Fatal("valid baseline should parse")
	}
	if b.Servers["a"] != "sig-a" || b.Servers["b"] != "sig-b" {
		t.Errorf("baseline map wrong: %+v", b.Servers)
	}
	if _, ok := parseBaseline([]byte("{not json")); ok {
		t.Error("malformed baseline should report ok=false")
	}
	// Valid JSON without a servers key parses to an empty baseline.
	empty, ok := parseBaseline([]byte(`{}`))
	if !ok || len(empty.Servers) != 0 {
		t.Errorf("empty baseline: ok=%v servers=%+v", ok, empty.Servers)
	}
}

func TestURLHost(t *testing.T) {
	cases := map[string]string{
		"https://user:pass@host.example.com:8443/sse?q=1#frag": "host.example.com",
		"http://plain.example.org/path":                        "plain.example.org",
		"https://noport.example":                               "noport.example",
		"bare.host.example":                                    "bare.host.example",
		"http://[2001:db8::1]:9000/x":                          "[2001:db8::1]",
		"http://[fe80::1":                                      "[fe80::1", // no closing bracket
		"https://host.example:443":                             "host.example",
	}
	for in, want := range cases {
		if got := urlHost(in); got != want {
			t.Errorf("urlHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBaseName(t *testing.T) {
	cases := map[string]string{
		"/usr/local/bin/npx": "npx",
		"npx":                "npx",
		`C:\tools\uvx`:       "uvx",
		"":                   "",
	}
	for in, want := range cases {
		if got := baseName(in); got != want {
			t.Errorf("baseName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSortedKeys(t *testing.T) {
	got := sortedKeys(map[string]string{"c": "3", "a": "1", "b": "2"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("sortedKeys[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

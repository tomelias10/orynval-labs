package core

import (
	"bufio"
	"bytes"
	"os"
	"sync"
)

// File is a single file offered to rules during a scan. Abs is the absolute
// path on disk (used to read bytes); Rel is the slash-separated path relative
// to the scan root (used in evidence, fingerprints, and output). Rules should
// display Rel and never Abs, so results do not leak the scanning machine's
// directory layout.
type File struct {
	Abs string
	Rel string
}

// FileWalker yields the files a scan should consider. It is an interface so the
// core package stays decoupled from the concrete walker in internal/walk (which
// enforces the safety rules: skip .git/node_modules/vendor/binaries/oversized
// files and never follow symlinks out of root). The callback receives absolute
// and root-relative paths; returning an error stops the walk.
type FileWalker interface {
	Walk(fn func(abs, rel string) error) error
}

// Options carries scan-wide, rule-tunable knobs. It is intentionally small in
// phase 0; new fields are additive.
type Options struct {
	// MaxEvidence caps how many Evidence entries a well-behaved rule attaches
	// to a single finding. Zero means unlimited. Rules may consult it via
	// Context.MaxEvidence.
	MaxEvidence int
}

// Context is the handle a Rule receives during evaluation. It exposes the scan
// root, options, safe iteration over files, and a content cache so multiple
// rules scanning the same tree read each file at most once.
//
// A Context is safe for use from a single goroutine. Rules within a Registry
// run sequentially, so the cache needs only light locking, which is provided.
type Context struct {
	// Root is the absolute directory being scanned.
	Root string
	// Options are the scan-wide knobs.
	Options Options

	walker FileWalker

	mu    sync.Mutex
	cache map[string][]byte // rel -> file content
}

// NewContext builds a Context rooted at root, drawing files from w.
func NewContext(root string, w FileWalker, opts Options) *Context {
	return &Context{
		Root:    root,
		Options: opts,
		walker:  w,
		cache:   make(map[string][]byte),
	}
}

// MaxEvidence returns the configured evidence cap (0 = unlimited).
func (c *Context) MaxEvidence() int { return c.Options.MaxEvidence }

// Walk iterates the scannable files, invoking fn for each. Iteration order is
// whatever the underlying walker provides; the concrete walker in internal/walk
// yields files in a deterministic lexical order.
func (c *Context) Walk(fn func(File) error) error {
	if c.walker == nil {
		return nil
	}
	return c.walker.Walk(func(abs, rel string) error {
		return fn(File{Abs: abs, Rel: rel})
	})
}

// Read returns the file's bytes, reading from disk at most once per file and
// caching the result for later rules. The returned slice is shared with the
// cache and must not be mutated by callers.
func (c *Context) Read(f File) ([]byte, error) {
	c.mu.Lock()
	if b, ok := c.cache[f.Rel]; ok {
		c.mu.Unlock()
		return b, nil
	}
	c.mu.Unlock()

	b, err := os.ReadFile(f.Abs)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.cache[f.Rel] = b
	c.mu.Unlock()
	return b, nil
}

// Lines returns the file split into lines with line-ending characters removed.
// Line N of the file is Lines()[N-1]. It is built on Read, so it shares the
// same one-read-per-file cache.
func (c *Context) Lines(f File) ([]string, error) {
	b, err := c.Read(f)
	if err != nil {
		return nil, err
	}
	return splitLines(b), nil
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	// Allow long lines (minified JS, embedded data) up to the walker's 1 MiB
	// file cap so a single line never overflows the default 64 KiB token.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024+1)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

// Rule is the contract every detector implements. Implementations must be
// deterministic and side-effect free: given the same tree they return the same
// findings, in any order (the Registry sorts). Evaluate must never write files,
// open the network, or execute anything it discovers.
type Rule interface {
	// ID is the stable machine identifier, e.g. "orynval.example.hardcoded-secret".
	ID() string
	// Name is a short human-readable label.
	Name() string
	// Description explains what the rule looks for.
	Description() string
	// Evaluate inspects the tree via ctx and returns any findings.
	Evaluate(ctx *Context) []Finding
}

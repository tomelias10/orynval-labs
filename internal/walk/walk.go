// Package walk provides a safe, deterministic file walker for scanning a source
// tree. "Safe" means it never leaves the root, never follows symlinks, skips
// version-control internals and dependency directories, and never opens huge or
// binary files. These guarantees keep a scan read-only, bounded, and free of
// surprises such as a symlink pointing at /etc or a multi-gigabyte artifact.
package walk

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// DefaultMaxFileSize is the largest file (in bytes) the walker will yield.
// Files above this are skipped: they are almost always build artifacts, media,
// or datasets rather than source worth scanning, and reading them would blow
// the time and memory budget.
const DefaultMaxFileSize int64 = 1 << 20 // 1 MiB

// defaultIgnoreDirs are directory names skipped wholesale by every scan.
var defaultIgnoreDirs = map[string]bool{
	".git":         true, // VCS internals: objects, packs, hooks
	".hg":          true,
	".svn":         true,
	"node_modules": true, // vendored JS dependencies
	"vendor":       true, // vendored Go/PHP dependencies
}

// binarySniffBytes is how many leading bytes are inspected to decide whether a
// file is binary. A NUL byte in this window marks it binary and it is skipped.
const binarySniffBytes = 8000

// Options configures a Walker. The zero value is valid and uses the defaults.
type Options struct {
	// MaxFileSize overrides DefaultMaxFileSize when > 0.
	MaxFileSize int64
	// Ignore holds additional names or globs (matched against each entry's
	// base name via filepath.Match) to skip. It applies to both files and
	// directories and is layered on top of the built-in ignore set.
	Ignore []string
}

// Walker walks a single rooted tree applying the safety rules. Construct it with
// New; it is safe for concurrent use (it holds no mutable state).
type Walker struct {
	root        string // canonical absolute root
	maxFileSize int64
	ignore      []string
}

// New returns a Walker rooted at root. The root is made absolute and its own
// symlinks are resolved once (so a symlinked root is intentional), after which
// no symlink inside the tree is ever followed. It errors if root does not exist
// or is not a directory.
func New(root string, opts Options) (*Walker, error) {
	return newWalker(root, opts, filepath.Abs)
}

func newWalker(root string, opts Options, absFn func(string) (string, error)) (*Walker, error) {
	abs, err := absFn(root)
	if err != nil {
		return nil, fmt.Errorf("walk: resolve root: %w", err)
	}
	// Canonicalize the root itself so later "inside root" reasoning is exact.
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("walk: stat root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("walk: root %q is not a directory", root)
	}
	max := opts.MaxFileSize
	if max <= 0 {
		max = DefaultMaxFileSize
	}
	return &Walker{root: abs, maxFileSize: max, ignore: append([]string(nil), opts.Ignore...)}, nil
}

// Root returns the canonical absolute root of the walk.
func (w *Walker) Root() string { return w.root }

// Walk invokes fn for every file that passes the safety filters, in
// deterministic lexical order (filepath.WalkDir sorts directory entries). fn
// receives the absolute path and the slash-separated path relative to the root.
// If fn returns an error, the walk stops and returns it. Unreadable entries are
// skipped rather than aborting the scan.
func (w *Walker) Walk(fn func(abs, rel string) error) error {
	return filepath.WalkDir(w.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Permission denied or transient error on an entry: skip it (and
			// its subtree if it is a directory) instead of failing the scan.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if path != w.root && w.isIgnored(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}

		// Never follow symlinks. WalkDir reports a symlink (even to a
		// directory) as a non-directory entry and does not descend it, so
		// skipping here guarantees we never read outside the root through a
		// link. This is stronger than "never follow symlinks outside root":
		// phase 0 follows none.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		// Skip anything that is not a regular file (devices, sockets, pipes).
		if !d.Type().IsRegular() {
			return nil
		}
		if w.isIgnored(d.Name()) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil // races with deletion, etc. — skip
		}
		if info.Size() > w.maxFileSize {
			return nil
		}

		binary, err := isBinaryFile(path)
		if err != nil || binary {
			return nil
		}

		// path is w.root itself or a descendant of it and both are absolute, so
		// filepath.Rel always succeeds here; the error cannot occur.
		rel, _ := filepath.Rel(w.root, path)
		return fn(path, filepath.ToSlash(rel))
	})
}

// isIgnored reports whether a base name is skipped by the built-in set or a
// configured Ignore glob.
func (w *Walker) isIgnored(name string) bool {
	if defaultIgnoreDirs[name] {
		return true
	}
	for _, pat := range w.ignore {
		if pat == name {
			return true
		}
		if ok, err := filepath.Match(pat, name); err == nil && ok {
			return true
		}
	}
	return false
}

// isBinaryFile reports whether the file at path appears to be binary, detected
// by the presence of a NUL byte within the first binarySniffBytes bytes. This
// is the same heuristic git uses and reliably separates text (source, config)
// from compiled and media files without a full read.
func isBinaryFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	buf := make([]byte, binarySniffBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		// EOF on an empty file reports n==0; an empty file is not binary.
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		return false, err
	}
	for _, b := range buf[:n] {
		if b == 0 {
			return true, nil
		}
	}
	return false, nil
}

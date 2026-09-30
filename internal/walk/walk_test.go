package walk

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// collect walks and returns the yielded relative paths.
func collect(t *testing.T, w *Walker) []string {
	t.Helper()
	var got []string
	if err := w.Walk(func(abs, rel string) error {
		got = append(got, rel)
		return nil
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return got
}

func TestWalkSkipsVCSAndDeps(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root, "keep.go", "package main\n")
	mustWrite(t, root, "src/app.go", "package app\n")
	mustWrite(t, root, ".git/config", "[core]\n")
	mustWrite(t, root, ".git/objects/ab/cdef", "junk\n")
	mustWrite(t, root, "node_modules/left-pad/index.js", "module.exports={}\n")
	mustWrite(t, root, "vendor/dep/dep.go", "package dep\n")

	w, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := collect(t, w)
	want := []string{"keep.go", "src/app.go"}
	assertSameSet(t, got, want)
}

func TestWalkDeterministicLexicalOrder(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"c.txt", "a.txt", "b.txt", "sub/z.txt", "sub/a.txt"} {
		mustWrite(t, root, name, "x")
	}
	w, _ := New(root, Options{})
	got := collect(t, w)
	// WalkDir yields in lexical order; siblings sorted, dirs walked in place.
	want := []string{"a.txt", "b.txt", "c.txt", "sub/a.txt", "sub/z.txt"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", got, want)
	}
}

func TestWalkSkipsLargeFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root, "small.txt", "tiny")
	big := strings.Repeat("A", 2048)
	mustWrite(t, root, "big.txt", big)

	w, _ := New(root, Options{MaxFileSize: 1024})
	got := collect(t, w)
	assertSameSet(t, got, []string{"small.txt"})
}

func TestWalkSkipsBinaryFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root, "text.txt", "hello world")
	// A file with an embedded NUL byte is treated as binary.
	if err := os.WriteFile(filepath.Join(root, "blob.bin"), []byte("PK\x03\x04\x00\x00binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, _ := New(root, Options{})
	got := collect(t, w)
	assertSameSet(t, got, []string{"text.txt"})
}

func TestWalkConfigurableIgnore(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root, "keep.go", "x")
	mustWrite(t, root, "skip.log", "x")
	mustWrite(t, root, "dist/out.js", "x")

	w, _ := New(root, Options{Ignore: []string{"*.log", "dist"}})
	got := collect(t, w)
	assertSameSet(t, got, []string{"keep.go"})
}

func TestWalkNeverFollowsSymlinkOutsideRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	// A secret file living entirely outside the scan root.
	outside := t.TempDir()
	secretPath := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("TOP-SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	mustWrite(t, root, "real.txt", "ok")
	// Symlink inside root pointing at the outside secret.
	if err := os.Symlink(secretPath, filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	// Symlink inside root pointing at the outside directory.
	if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
		t.Fatal(err)
	}

	w, _ := New(root, Options{})
	var readAbs []string
	err := w.Walk(func(abs, rel string) error {
		readAbs = append(readAbs, abs)
		if strings.Contains(rel, "link") {
			t.Errorf("walker yielded a symlink: %s", rel)
		}
		b, _ := os.ReadFile(abs)
		if strings.Contains(string(b), "TOP-SECRET") {
			t.Errorf("walker read a file outside root via %s", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Compare against the walker's canonical root: New resolves symlinks in the
	// root once (here /tmp -> /private/tmp on macOS), so yielded absolute paths
	// are rooted there, not at the raw t.TempDir() path.
	assertSameSet(t, relOf(w.Root(), readAbs), []string{"real.txt"})
}

func TestNewRejectsNonDir(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(file, Options{}); err == nil {
		t.Error("expected error for a file root")
	}
	if _, err := New(filepath.Join(root, "does-not-exist"), Options{}); err == nil {
		t.Error("expected error for a missing root")
	}
}

func TestWalkEmptyFileIsText(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root, "empty.txt", "")
	w, _ := New(root, Options{})
	got := collect(t, w)
	assertSameSet(t, got, []string{"empty.txt"})
}

// --- helpers ---

func mustWrite(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func relOf(root string, abs []string) []string {
	out := make([]string, 0, len(abs))
	for _, a := range abs {
		r, _ := filepath.Rel(root, a)
		out = append(out, filepath.ToSlash(r))
	}
	return out
}

func assertSameSet(t *testing.T, got, want []string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if strings.Join(g, ",") != strings.Join(w, ",") {
		t.Errorf("set mismatch:\n got: %v\nwant: %v", got, want)
	}
}

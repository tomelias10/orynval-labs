package core

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// sliceWalker is a minimal FileWalker over an in-memory list, used to test
// Context without depending on internal/walk.
type sliceWalker struct {
	root  string
	files []string // rel paths
}

func (w sliceWalker) Walk(fn func(abs, rel string) error) error {
	for _, rel := range w.files {
		if err := fn(filepath.Join(w.root, rel), rel); err != nil {
			return err
		}
	}
	return nil
}

func TestContextReadCachesOneReadPerFile(t *testing.T) {
	dir := t.TempDir()
	rel := "a.txt"
	if err := os.WriteFile(filepath.Join(dir, rel), []byte("line1\nline2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := NewContext(dir, sliceWalker{root: dir, files: []string{rel}}, Options{})

	f := File{Abs: filepath.Join(dir, rel), Rel: rel}
	b1, err := ctx.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate the file on disk; a cached Read must still return the old content.
	if err := os.WriteFile(f.Abs, []byte("CHANGED"), 0o600); err != nil {
		t.Fatal(err)
	}
	b2, err := ctx.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Errorf("expected cached content, got %q then %q", b1, b2)
	}
}

func TestContextLines(t *testing.T) {
	dir := t.TempDir()
	rel := "b.txt"
	if err := os.WriteFile(filepath.Join(dir, rel), []byte("one\ntwo\r\nthree"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := NewContext(dir, sliceWalker{root: dir, files: []string{rel}}, Options{})
	lines, err := ctx.Lines(File{Abs: filepath.Join(dir, rel), Rel: rel})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"one", "two", "three"}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines %q, want %d", len(lines), lines, len(want))
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestContextWalkVisitsFiles(t *testing.T) {
	dir := t.TempDir()
	ctx := NewContext(dir, sliceWalker{root: dir, files: []string{"x", "y"}}, Options{})
	var seen []string
	err := ctx.Walk(func(f File) error {
		seen = append(seen, f.Rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != "x" || seen[1] != "y" {
		t.Errorf("unexpected walk: %v", seen)
	}
}

func TestContextWalkPropagatesError(t *testing.T) {
	dir := t.TempDir()
	ctx := NewContext(dir, sliceWalker{root: dir, files: []string{"x", "y"}}, Options{})
	sentinel := errors.New("stop")
	err := ctx.Walk(func(f File) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

func TestSplitLinesEmpty(t *testing.T) {
	if got := splitLines(nil); got != nil {
		t.Errorf("expected nil for empty input, got %v", got)
	}
}

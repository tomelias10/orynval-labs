package walk

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// TestNewAbsErrorOnRemovedCwd covers the filepath.Abs failure path in New: a
// relative root cannot be made absolute once the working directory is gone.
func TestNewAbsErrorOnRemovedCwd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("removing the working directory is not portable on windows")
	}
	tmp := t.TempDir()
	gone := filepath.Join(tmp, "gone")
	if err := os.Mkdir(gone, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(gone) // testing restores the original wd at cleanup
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	// filepath.Abs of a relative path now fails because os.Getwd fails.
	if _, err := New("relative-root", Options{}); err == nil {
		t.Error("expected New to fail when the working directory no longer exists")
	}
}

// TestWalkToleratesEntriesRemovedMidScan covers two skip-on-error paths: a file
// whose Info() lstat fails after removal, and a subdirectory whose ReadDir fails
// after removal (yielding fs.SkipDir). The walk must skip both, not abort.
func TestWalkToleratesEntriesRemovedMidScan(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, root, "a.txt", "first")       // processed first (lexical order)
	mustWrite(t, root, "b.txt", "second")      // Info() fails once removed
	mustWrite(t, root, "z_sub/inner.txt", "x") // ReadDir fails once removed

	w, _ := New(root, Options{})
	var seen []string
	err := w.Walk(func(abs, rel string) error {
		seen = append(seen, rel)
		if rel == "a.txt" {
			if err := os.Remove(filepath.Join(root, "b.txt")); err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(filepath.Join(root, "z_sub")); err != nil {
				t.Fatal(err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk should tolerate mid-scan removals: %v", err)
	}
	// Only a.txt fully processed; the removed sibling and subtree are skipped.
	assertSameSet(t, seen, []string{"a.txt"})
}

// TestWalkOnRemovedRootYieldsNothing covers the callback branch where WalkDir
// reports an error with a nil DirEntry (the root itself cannot be lstat'd).
func TestWalkOnRemovedRootYieldsNothing(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := New(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	got := collect(t, w)
	if len(got) != 0 {
		t.Errorf("expected no files from a removed root, got %v", got)
	}
}

// TestWalkSkipsNonRegularFiles covers the non-regular-file branch (a named pipe
// is neither a symlink nor a regular file and must be skipped).
func TestWalkSkipsNonRegularFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipes are not available on windows")
	}
	root := t.TempDir()
	mustWrite(t, root, "real.txt", "hello")
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
		t.Skipf("mkfifo unsupported on this platform: %v", err)
	}
	w, _ := New(root, Options{})
	got := collect(t, w)
	assertSameSet(t, got, []string{"real.txt"})
}

// TestIsBinaryFileErrors covers the open-error and read-error return paths of
// the binary sniffer directly, since both are races that are awkward to provoke
// through a full walk.
func TestIsBinaryFileErrors(t *testing.T) {
	// os.Open fails: the path does not exist.
	if _, err := isBinaryFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("expected an open error for a missing file")
	}
	// Read fails with a non-EOF error: a directory opens but cannot be read as a
	// byte stream.
	if _, err := isBinaryFile(t.TempDir()); err == nil {
		t.Error("expected a read error when sniffing a directory")
	}
}

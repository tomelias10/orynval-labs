package core

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoNetworkOrExecImports enforces the product's zero-egress, no-telemetry
// posture at the source level: no non-test file in the shared core (internal/*)
// may import a networking or process-execution package. A regression here would
// let a tool reach the network or shell out, breaking the "offline, read-only,
// no data leaves your machine" guarantee that the whole product rests on.
func TestNoNetworkOrExecImports(t *testing.T) {
	forbidden := func(path string) bool {
		return path == "net" ||
			strings.HasPrefix(path, "net/") ||
			path == "os/exec" ||
			path == "net/http" ||
			path == "net/rpc"
	}

	// The test's working directory is the internal/core package; ".." is the
	// internal/ tree that holds every shared-core package.
	root := ".."
	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parse %s: %v", p, perr)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if forbidden(path) {
				t.Errorf("%s imports forbidden package %q (violates the no-egress guarantee)", p, path)
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk internal tree: %v", walkErr)
	}
}

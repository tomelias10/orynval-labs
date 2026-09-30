package main

import (
	"os"
	"testing"
)

// TestMainWiring exercises the process entry point: it stubs the exit seam and
// os.Args so main() runs end-to-end (here via --version, which is side-effect
// free) and verifies the exit code is forwarded from trustproof.Run.
func TestMainWiring(t *testing.T) {
	origExit, origArgs := exit, os.Args
	t.Cleanup(func() { exit, os.Args = origExit, origArgs })

	var got int
	exit = func(code int) { got = code }
	os.Args = []string{"trust-proof", "--version"}

	main()

	if got != 0 {
		t.Errorf("main forwarded exit code %d, want 0", got)
	}
}

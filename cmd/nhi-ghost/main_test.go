package main

import (
	"os"
	"testing"
)

// TestMainRuns drives main() with the exit hook captured so the process does
// not terminate, verifying the entrypoint wires argv through to the tool and
// propagates its exit code. --version is a no-scan path that returns ExitOK.
func TestMainRuns(t *testing.T) {
	origArgs, origExit := os.Args, exit
	t.Cleanup(func() { os.Args, exit = origArgs, origExit })

	var got int
	exit = func(code int) { got = code }
	os.Args = []string{"nhi-ghost", "--version"}

	main()

	if got != 0 {
		t.Fatalf("exit code = %d, want 0", got)
	}
}

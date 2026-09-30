// Command nhi-ghost is a local-first, read-only, deterministic scanner for
// Non-Human Identity (NHI) risk. It discovers the machine identities in a
// repository or config tree — service accounts, API keys and token references,
// CI/CD and workload identities — and ranks each one's locally observed risk.
//
// The scan never writes to the target, never executes anything it finds, never
// validates a credential against a live service, and never opens the network.
// All behaviour lives in the tested internal/nhi package; this entrypoint only
// wires it to the shared CLI runner.
//
// Usage:
//
//	nhi-ghost [flags] [path]
//
// See `nhi-ghost -h` for flags and internal/nhi for the detector.
package main

import (
	"os"

	"github.com/orynval/orynval-labs/internal/nhi"
)

// exit is indirected through a variable so a test can observe the process exit
// code without terminating the test binary. It is os.Exit in production.
var exit = os.Exit

func main() {
	exit(nhi.NewTool().Run(os.Args[1:], os.Stdout, os.Stderr))
}

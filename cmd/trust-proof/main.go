// Command trust-proof drafts answers to a security questionnaire from a corpus
// of already-approved local evidence. Every drafted answer is extractive and
// cited; anything unsupported is reported as a gap. It runs fully offline —
// no network, no upload, no LLM — and is deterministic.
//
// Usage:
//
//	trust-proof --questions <file> --evidence <dir> [flags]
//
// All logic lives in internal/trustproof so it can be exercised under test;
// this entry point only wires the process to trustproof.Run.
package main

import (
	"os"

	"github.com/orynval/orynval-labs/internal/trustproof"
)

// exit is a seam over os.Exit so main's exit-code wiring can be tested without
// terminating the test binary. It is the only indirection in this entry point.
var exit = os.Exit

func main() {
	exit(trustproof.Run(os.Args[1:], os.Stdout, os.Stderr))
}

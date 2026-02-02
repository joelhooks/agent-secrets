// Package main is the entry point for the secrets CLI.
package main

import "github.com/joelhooks/agent-secrets/internal/output"

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	output.Version = version
	output.Commit = commit
	Execute()
}

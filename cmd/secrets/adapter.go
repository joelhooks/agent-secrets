package main

import (
	"fmt"

	"github.com/joelhooks/agent-secrets/internal/adapters"
	"github.com/joelhooks/agent-secrets/internal/adapters/vercel"
)

// getAdapter returns the appropriate adapter for the given source name.
func getAdapter(source string) (adapters.SourceAdapter, error) {
	switch source {
	case "vercel":
		return vercel.New(), nil
	case "doppler":
		// TODO: Implement Doppler adapter
		return nil, fmt.Errorf("doppler adapter not yet implemented")
	default:
		return nil, fmt.Errorf("unknown source: %q", source)
	}
}

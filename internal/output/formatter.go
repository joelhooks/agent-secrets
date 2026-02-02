package output

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// OutputMode defines the output format
type OutputMode string

const (
	ModeJSON  OutputMode = "json"
	ModeTable OutputMode = "table"
	ModeRaw   OutputMode = "raw"
)

// Formatter handles output formatting
type Formatter interface {
	Format(r Response) error
}

// GetFormatter returns the appropriate formatter based on mode and TTY detection
func GetFormatter(mode OutputMode) Formatter {
	// Auto-detect if mode is empty
	if mode == "" {
		if isTerminal(os.Stdout.Fd()) {
			mode = ModeTable
		} else {
			mode = ModeJSON
		}
	}

	switch mode {
	case ModeJSON:
		return &JSONFormatter{}
	case ModeTable:
		return &TableFormatter{}
	case ModeRaw:
		return &RawFormatter{}
	default:
		// Fallback to JSON for unknown modes
		return &JSONFormatter{}
	}
}

// isTerminal checks if the file descriptor is a terminal
func isTerminal(fd uintptr) bool {
	return term.IsTerminal(int(fd))
}

// ValidateMode checks if the output mode is valid
func ValidateMode(mode string) error {
	if mode == "" {
		return nil // Empty is valid (auto-detect)
	}

	switch OutputMode(mode) {
	case ModeJSON, ModeTable, ModeRaw:
		return nil
	default:
		return fmt.Errorf("invalid output mode: %s (must be json, table, or raw)", mode)
	}
}

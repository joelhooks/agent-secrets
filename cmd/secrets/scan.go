package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	scanPath      string
	scanRecursive bool
	scanExclude   []string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for exposed secrets",
	Long: `Scan files and directories for exposed secrets using pattern matching.

By default, scans recursively and outputs JSON results.
Use --human for readable output.

Examples:
  secrets scan                                    # Scan current directory
  secrets scan --path ./src                       # Scan specific directory
  secrets scan --path ./file.txt                  # Scan specific file
  secrets scan --exclude node_modules,.git        # Exclude patterns
  secrets scan --no-recursive                     # Disable recursive scanning`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Resolve absolute path
		absPath, err := filepath.Abs(scanPath)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to resolve path: %w", err)))
			return err
		}

		// Create scanner with default patterns
		s := scanner.NewScanner(scanner.DefaultPatterns(), scanExclude).
			WithRecursive(scanRecursive)

		// Run scan
		result, err := s.Scan(absPath)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("scan failed: %w", err)))
			return err
		}

		// Format findings for output
		findingsData := make([]map[string]interface{}, len(result.Findings))
		for i, f := range result.Findings {
			findingsData[i] = map[string]interface{}{
				"file":         f.File,
				"line":         f.Line,
				"column":       f.Column,
				"pattern_name": f.PatternName,
				"value":        redactValue(f.Value),
				"severity":     f.Severity.String(),
			}
		}

		// Build response data
		data := map[string]interface{}{
			"findings":      findingsData,
			"scanned_files": result.ScannedFiles,
			"duration":      result.Duration.String(),
			"path":          absPath,
			"recursive":     scanRecursive,
			"excludes":      scanExclude,
		}

		// Success message
		msg := fmt.Sprintf("Scanned %d files", result.ScannedFiles)
		if len(result.Findings) > 0 {
			msg = fmt.Sprintf("Found %d exposed secrets in %d files", len(result.Findings), result.ScannedFiles)
		}

		output.Print(output.Success(
			msg,
			data,
			output.ActionsAfterScan(len(result.Findings))...,
		))

		return nil
	},
}

func init() {
	scanCmd.Flags().StringVar(&scanPath, "path", ".", "Directory or file to scan")
	scanCmd.Flags().BoolVar(&scanRecursive, "recursive", true, "Scan directories recursively")
	scanCmd.Flags().StringSliceVar(&scanExclude, "exclude", []string{"node_modules", ".git", ".hg", ".svn", "vendor", "dist", "build"}, "Patterns to exclude from scanning")
}

// redactValue partially redacts a secret value for display
func redactValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	// Show first 4 and last 4 characters
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

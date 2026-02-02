package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/joelhooks/agent-secrets/internal/cleanup"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/spf13/cobra"
)

var (
	cleanupPath     string
	cleanupWatch    bool
	cleanupInterval time.Duration
)

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up expired .env files",
	Long: `Scan directories for expired .env files and remove them.

By default, performs a one-time check of the current directory.
Use --watch to run continuously.

Examples:
  secrets cleanup                                # Check current directory once
  secrets cleanup --path /path/to/project        # Check specific directory
  secrets cleanup --watch                        # Run continuously with default interval
  secrets cleanup --watch --interval 5m          # Watch with custom interval`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Resolve absolute path
		absPath, err := filepath.Abs(cleanupPath)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to resolve path: %w", err)))
			return err
		}

		// Create watcher
		w := cleanup.New([]string{absPath}, cleanupInterval)

		if cleanupWatch {
			// Watch mode: run continuously until interrupted
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Handle interrupt signals
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

			go func() {
				<-sigCh
				cancel()
			}()

			// Start blocking watch loop
			w.Start(ctx)

			output.Print(output.Success("Cleanup watcher stopped", nil))
			return nil
		}

		// One-time check mode
		wiped, err := w.Check()
		if err != nil {
			output.Print(output.Error(fmt.Errorf("cleanup failed: %w", err)))
			return err
		}

		// Build response data
		data := map[string]interface{}{
			"wiped_files": wiped,
			"count":       len(wiped),
			"path":        absPath,
		}

		// Success message
		msg := "No expired files found"
		if len(wiped) > 0 {
			msg = fmt.Sprintf("Cleaned up %d expired file(s)", len(wiped))
		}

		var actions []output.Action
		if len(wiped) > 0 {
			actions = append(actions, output.Action{
				Name:        "cleanup_result",
				Description: fmt.Sprintf("%d file(s) were removed", len(wiped)),
				Command:     "secrets cleanup --path " + absPath,
			})
		}

		output.Print(output.Success(msg, data, actions...))
		return nil
	},
}

func init() {
	cleanupCmd.Flags().StringVar(&cleanupPath, "path", ".", "Directory to check for expired .env files")
	cleanupCmd.Flags().BoolVar(&cleanupWatch, "watch", false, "Run continuously, checking at regular intervals")
	cleanupCmd.Flags().DurationVar(&cleanupInterval, "interval", 1*time.Minute, "Check interval for watch mode")
}

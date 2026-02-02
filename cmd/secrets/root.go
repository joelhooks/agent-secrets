package main

import (
	"os"

	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/update"
	"github.com/spf13/cobra"
)

var (
	socketPath      string
	configPath      string
	noUpdateCheck   bool
)

var rootCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Portable credential management for AI agents",
	Long: `agent-secrets provides secure, time-bounded credential management with
audit logging, rotation hooks, and killswitch capabilities for AI agents.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip update check if disabled or if running the update command itself
		if noUpdateCheck || cmd.Name() == "update" {
			return nil
		}

		// Run update check in background (non-blocking)
		update.CheckForUpdateInBackground(output.Version)
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&output.HumanMode, "human", false, "Human-readable output (default: JSON)")
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "", "Override Unix socket path")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Override config file path")
	rootCmd.PersistentFlags().BoolVar(&noUpdateCheck, "no-update-check", false, "Disable automatic update check (useful for CI)")

	// Add all subcommands
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(leaseCmd)
	rootCmd.AddCommand(revokeCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(cleanupCmd)
	rootCmd.AddCommand(envCmd)
	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(updateCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

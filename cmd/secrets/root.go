package main

import (
	"os"

	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/spf13/cobra"
)

var (
	socketPath string
	configPath string
)

var rootCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Portable credential management for AI agents",
	Long: `agent-secrets provides secure, time-bounded credential management with
audit logging, rotation hooks, and killswitch capabilities for AI agents.`,
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&output.HumanMode, "human", false, "Human-readable output (default: JSON)")
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "", "Override Unix socket path")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Override config file path")

	// Add all subcommands
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(leaseCmd)
	rootCmd.AddCommand(revokeCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(updateCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

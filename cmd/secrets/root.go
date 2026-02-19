package main

import (
	"os"

	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/update"
	"github.com/spf13/cobra"
)

var (
	socketPath          string
	configPath          string
	noUpdateCheck       bool
	timeoutSeconds      int
	skipPermissionCheck bool
	rootHumanMode       bool
	rootOutputFormat    string
)

var rootCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Portable credential management for AI agents",
	Long: `agent-secrets provides secure, time-bounded credential management with
audit logging, rotation hooks, and killswitch capabilities for AI agents.`,
	Run: func(cmd *cobra.Command, args []string) {
		type commandDoc struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Usage       string `json:"usage"`
		}

		type rootResult struct {
			Description string       `json:"description"`
			Version     string       `json:"version"`
			Commands    []commandDoc `json:"commands"`
		}

		result := rootResult{
			Description: "Portable credential management for AI agents",
			Version:     output.Version,
			Commands: []commandDoc{
				{Name: "init", Description: "Initialize the secrets store", Usage: "secrets init"},
				{Name: "add", Description: "Add a secret to the store", Usage: "secrets add <name> [--value <val>] [--rotate-via <cmd>]"},
				{Name: "list", Description: "List stored secret names", Usage: "secrets list"},
				{Name: "update", Description: "Update an existing secret value", Usage: "secrets update <name> [--value <val>] [--rotate-via <cmd>]"},
				{Name: "delete", Description: "Delete a secret from the store", Usage: "secrets delete <name> [--force] (alias: secrets rm <name>)"},
				{Name: "lease", Description: "Get a secret value (raw by default)", Usage: "secrets lease <name> [--ttl 1h] [--client-id agent-x] [--json]"},
				{Name: "revoke", Description: "Revoke a lease or killswitch", Usage: "secrets revoke <lease-id> | --all"},
				{Name: "status", Description: "Daemon status and active leases", Usage: "secrets status"},
				{Name: "health", Description: "Health check", Usage: "secrets health"},
				{Name: "audit", Description: "View audit log", Usage: "secrets audit [--tail N]"},
				{Name: "scan", Description: "Scan for hardcoded secrets", Usage: "secrets scan [path]"},
				{Name: "env", Description: "Generate .env from .secrets.json", Usage: "secrets env [--force]"},
				{Name: "exec", Description: "Run command with secrets as env vars", Usage: "secrets exec -- <command>"},
				{Name: "cleanup", Description: "Remove expired lease files", Usage: "secrets cleanup"},
				{Name: "serve", Description: "Start the daemon", Usage: "secrets serve"},
				{Name: "self-update", Description: "Update to latest version", Usage: "secrets self-update"},
			},
		}

		output.Print(output.Success(
			"secrets",
			result,
			output.Action{Command: "secrets status", Description: "Check daemon status"},
			output.Action{Command: "secrets health", Description: "Full health check"},
			output.Action{Command: "secrets lease <name>", Description: "Get a secret value"},
		))
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		emitDeprecatedRootFlagWarnings(cmd)

		// Skip update check if disabled or if running the self-update command itself
		if noUpdateCheck || cmd.Name() == "self-update" {
			return nil
		}

		// Run update check in background (non-blocking)
		update.CheckForUpdateInBackground(output.Version)
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "", "Override Unix socket path")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Override config file path")
	rootCmd.PersistentFlags().BoolVar(&noUpdateCheck, "no-update-check", false, "Disable automatic update check (useful for CI)")
	rootCmd.PersistentFlags().IntVar(&timeoutSeconds, "timeout", 5, "Timeout in seconds for daemon socket operations")
	rootCmd.PersistentFlags().BoolVar(&skipPermissionCheck, "skip-permission-check", false, "Skip file permission validation (for edge cases)")
	rootCmd.PersistentFlags().BoolVar(&rootHumanMode, "human", false, "[deprecated] No-op: JSON output is always enabled")
	rootCmd.PersistentFlags().StringVar(&rootOutputFormat, "output", "", "[deprecated] No-op: JSON output is always enabled")
	if err := rootCmd.PersistentFlags().MarkHidden("human"); err != nil {
		panic(err)
	}
	if err := rootCmd.PersistentFlags().MarkHidden("output"); err != nil {
		panic(err)
	}

	// Add all subcommands
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(leaseCmd)
	rootCmd.AddCommand(revokeCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(cleanupCmd)
	rootCmd.AddCommand(envCmd)
	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(selfUpdateCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func emitDeprecatedRootFlagWarnings(cmd *cobra.Command) {
	if cmd.Flags().Lookup("human") != nil && cmd.Flags().Changed("human") {
		output.DeprecationWarning("WARNING: --human is deprecated and ignored. JSON output is always enabled. Will be removed in v0.6.0")
	}
	if cmd.Flags().Lookup("output") != nil && cmd.Flags().Changed("output") {
		output.DeprecationWarning("WARNING: --output is deprecated and ignored. JSON output is always enabled. Will be removed in v0.6.0")
	}
}

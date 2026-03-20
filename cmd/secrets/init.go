package main

import (
	"fmt"

	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/store"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the encrypted credential store",
	Long: `Initialize the agent-secrets encrypted store. This creates a new age identity
and sets up the required directory structure.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		const commandName = "secrets init"
		// Load config (creates defaults if needed)
		cfg := config.DefaultConfig()

		// Create store instance
		st := store.New(cfg)

		// Initialize store (creates directories, identity, and empty secrets file)
		if err := st.Init(); err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to initialize: %w", err)))
		}

		output.Print(output.Success(
			commandName,
			map[string]interface{}{
				"path":    cfg.Directory,
				"message": "Store initialized successfully",
			},
			output.ActionsAfterInit()...,
		))

		return nil
	},
}

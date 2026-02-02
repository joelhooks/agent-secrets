package main

import (
	"encoding/json"
	"fmt"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the encrypted credential store",
	Long: `Initialize the agent-secrets encrypted store. This creates a new age identity
and sets up the required directory structure. The daemon will be started temporarily
if not already running.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := rpcCall(socketPath, daemon.MethodInit, daemon.InitParams{})
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to initialize: %w", err)))
			return fmt.Errorf("failed to initialize: %w", err)
		}

		var result daemon.InitResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse response: %w", err)))
			return fmt.Errorf("failed to parse response: %w", err)
		}
		if err := json.Unmarshal(data, &result); err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse result: %w", err)))
			return fmt.Errorf("failed to parse result: %w", err)
		}

		if result.Success {
			output.Print(output.Success(
				result.Message,
				map[string]interface{}{
					"path": "~/.agent-secrets",
				},
				output.ActionsAfterInit()...,
			))
		} else {
			output.Print(output.ErrorMsg(result.Message))
			return fmt.Errorf("initialization failed: %s", result.Message)
		}

		return nil
	},
}

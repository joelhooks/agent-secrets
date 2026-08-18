package main

import (
	"encoding/json"
	"fmt"
	"time"

	secretsdaemon "github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/types"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage the supervised agent-secrets daemon",
}

var daemonRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Gracefully restart the daemon through its supervisor",
	RunE: func(cmd *cobra.Command, args []string) error {
		const commandName = "secrets daemon restart"
		before, err := daemonStatus()
		if err != nil {
			return output.PrintFail(output.ErrorWithFix(
				commandName,
				fmt.Errorf("daemon must be healthy before an unprivileged restart: %w", err),
				"Use the host's break-glass service restart",
			))
		}

		resp, err := rpcCall(socketPath, secretsdaemon.MethodDaemonRestart, secretsdaemon.DaemonRestartParams{})
		if err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to request restart: %w", err)))
		}

		var accepted secretsdaemon.DaemonRestartResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to parse restart response: %w", err)))
		}
		if err := json.Unmarshal(data, &accepted); err != nil || !accepted.Accepted {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("daemon did not accept restart")))
		}

		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(150 * time.Millisecond)
			after, statusErr := daemonStatus()
			if statusErr == nil && after.StartedAt.After(before.StartedAt) {
				output.Print(output.Success(
					commandName,
					map[string]interface{}{
						"restarted":  true,
						"started_at": after.StartedAt.Format(time.RFC3339),
					},
					output.Action{Command: "secrets status", Description: "Verify daemon status"},
				))
				return nil
			}
		}

		return output.PrintFail(output.ErrorWithFix(
			commandName,
			fmt.Errorf("restart was accepted but no fresh daemon became healthy within 15s"),
			"Use the host's break-glass service restart",
		))
	},
}

func daemonStatus() (*types.DaemonStatus, error) {
	resp, err := rpcCall(socketPath, secretsdaemon.MethodStatus, secretsdaemon.StatusParams{})
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(resp.Result)
	if err != nil {
		return nil, err
	}
	var result types.DaemonStatus
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func init() {
	daemonCmd.AddCommand(daemonRestartCmd)
}

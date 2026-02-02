package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/types"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon status",
	Long:  `Display the current status of the agent-secrets daemon, including uptime, secret count, and active leases.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := rpcCall(socketPath, daemon.MethodStatus, daemon.StatusParams{})
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to get status: %w", err)))
			return fmt.Errorf("failed to get status: %w", err)
		}

		var result types.DaemonStatus
		data, err := json.Marshal(resp.Result)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse response: %w", err)))
			return fmt.Errorf("failed to parse response: %w", err)
		}
		if err := json.Unmarshal(data, &result); err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse result: %w", err)))
			return fmt.Errorf("failed to parse result: %w", err)
		}

		// Build data map for JSON response
		statusData := map[string]interface{}{
			"running":       result.Running,
			"secrets_count": result.SecretsCount,
			"active_leases": result.ActiveLeases,
		}

		if result.Running {
			uptime := time.Since(result.StartedAt)
			statusData["started_at"] = result.StartedAt.Format(time.RFC3339)
			statusData["uptime"] = formatDuration(uptime)

			if result.Heartbeat != nil && result.Heartbeat.Enabled {
				statusData["heartbeat"] = map[string]interface{}{
					"enabled":  true,
					"url":      result.Heartbeat.URL,
					"interval": result.Heartbeat.Interval,
				}
			} else {
				statusData["heartbeat"] = map[string]interface{}{
					"enabled": false,
				}
			}
		}

		// Build contextual actions
		var actions []output.Action
		if result.SecretsCount > 0 {
			// TODO: Get actual secret names from daemon to suggest specific leases
			actions = append(actions,
				output.ActionLease(""),
				output.ActionAdd(""),
				output.ActionAudit(),
			)
		} else {
			// No secrets exist, suggest adding
			actions = output.ActionsWhenEmpty()
		}

		output.Print(output.Success(
			"Daemon status retrieved",
			statusData,
			actions...,
		))

		return nil
	},
}

func formatBool(b bool) string {
	if b {
		return "✓ yes"
	}
	return "✗ no"
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	} else {
		return fmt.Sprintf("%dm", minutes)
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/joelhooks/agent-secrets/internal/daemon"
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
			return fmt.Errorf("failed to get status: %w", err)
		}

		var result types.DaemonStatus
		data, err := json.Marshal(resp.Result)
		if err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("failed to parse result: %w", err)
		}

		// Pretty-print status
		fmt.Println("Agent Secrets Daemon Status")
		fmt.Println("═══════════════════════════")
		fmt.Printf("\nRunning:        %v\n", formatBool(result.Running))

		if result.Running {
			uptime := time.Since(result.StartedAt)
			fmt.Printf("Started at:     %s\n", result.StartedAt.Format(time.RFC3339))
			fmt.Printf("Uptime:         %s\n", formatDuration(uptime))
			fmt.Printf("Secrets:        %d\n", result.SecretsCount)
			fmt.Printf("Active Leases:  %d\n", result.ActiveLeases)

			if result.Heartbeat != nil && result.Heartbeat.Enabled {
				fmt.Printf("\nHeartbeat:      enabled\n")
				fmt.Printf("  URL:          %s\n", result.Heartbeat.URL)
				fmt.Printf("  Interval:     %s\n", result.Heartbeat.Interval)
			} else {
				fmt.Printf("\nHeartbeat:      disabled\n")
			}
		}

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

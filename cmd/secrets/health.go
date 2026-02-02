package main

import (
	"encoding/json"
	"fmt"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/spf13/cobra"
)

var (
	healthWarnings bool
)

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Show secrets health report",
	Long: `Display a comprehensive health report for your secrets store, including:
- Total secrets count
- Active leases count
- Expiring leases (<1h warning)
- Secrets without rotation hooks
- Stale secrets (not accessed in 30 days)

Examples:
  secrets health                  # Full health report
  secrets health --output json    # Machine-readable output
  secrets health --warnings       # Only show warnings`,
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := rpcCall(socketPath, daemon.MethodHealth, daemon.HealthParams{})
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to get health report: %w", err)))
			return fmt.Errorf("failed to get health report: %w", err)
		}

		var result daemon.HealthResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse response: %w", err)))
			return fmt.Errorf("failed to parse response: %w", err)
		}
		if err := json.Unmarshal(data, &result); err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse result: %w", err)))
			return fmt.Errorf("failed to parse result: %w", err)
		}

		// If warnings-only mode and no warnings, short-circuit
		if healthWarnings && len(result.Warnings) == 0 {
			output.Print(output.Success(
				"No health warnings detected",
				map[string]interface{}{
					"status": "healthy",
				},
			))
			return nil
		}

		// Build comprehensive health data
		healthData := map[string]interface{}{
			"total_secrets":  result.TotalSecrets,
			"active_leases":  result.ActiveLeases,
			"expiring_soon":  result.ExpiringSoon,
			"never_rotated":  result.NeverRotated,
			"stale_secrets":  result.StaleSecrets,
			"warnings_count": len(result.Warnings),
		}

		// Add warnings if present
		if len(result.Warnings) > 0 {
			warnings := make([]map[string]interface{}, len(result.Warnings))
			for i, w := range result.Warnings {
				warnings[i] = map[string]interface{}{
					"type":        w.Type,
					"secret_name": w.SecretName,
					"message":     w.Message,
					"severity":    w.Severity,
				}
			}
			healthData["warnings"] = warnings
		}

		// Determine status message
		status := "healthy"
		if len(result.Warnings) > 0 {
			status = fmt.Sprintf("%d warning(s) detected", len(result.Warnings))
		}

		// Build contextual actions
		var actions []output.Action
		if len(result.Warnings) > 0 {
			// Suggest relevant actions based on warnings
			hasRotationWarnings := false
			hasExpiringWarnings := false

			for _, w := range result.Warnings {
				if w.Type == "no_rotation_hook" {
					hasRotationWarnings = true
				}
				if w.Type == "expiring_soon" {
					hasExpiringWarnings = true
				}
			}

			if hasRotationWarnings {
				actions = append(actions, output.Action{
					Name:        "Configure rotation",
					Command:     "secrets update <name> --rotate-via <command>",
					Description: "Add rotation hook to secrets",
				})
			}
			if hasExpiringWarnings {
				actions = append(actions, output.Action{
					Name:        "Revoke expiring leases",
					Command:     "secrets revoke <lease-id>",
					Description: "Manually revoke leases before expiration",
				})
			}

			actions = append(actions, output.ActionAudit())
		} else {
			actions = append(actions,
				output.ActionLease(""),
				output.ActionAdd(""),
			)
		}

		output.Print(output.Success(
			status,
			healthData,
			actions...,
		))

		return nil
	},
}

func init() {
	healthCmd.Flags().BoolVar(&healthWarnings, "warnings", false, "Only show warnings")
}

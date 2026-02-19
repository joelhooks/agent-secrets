package main

import (
	"encoding/json"
	"fmt"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/spf13/cobra"
)

var auditTail int

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View audit log entries",
	Long: `Display audit log entries showing all operations performed on secrets and leases.
Use --tail to limit the number of entries shown.

The response includes suggested filtering actions to help narrow down results.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		const commandName = "secrets audit"
		params := daemon.AuditParams{
			Tail: auditTail,
		}

		resp, err := rpcCall(socketPath, daemon.MethodAudit, params)
		if err != nil {
			output.Print(output.Error(commandName, fmt.Errorf("failed to fetch audit log: %w", err)))
			return nil
		}

		var result daemon.AuditResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			output.Print(output.Error(commandName, fmt.Errorf("failed to parse response: %w", err)))
			return nil
		}
		if err := json.Unmarshal(data, &result); err != nil {
			output.Print(output.Error(commandName, fmt.Errorf("failed to parse result: %w", err)))
			return nil
		}

		if len(result.Entries) == 0 {
			output.Print(output.Success(commandName, map[string]interface{}{
				"message": "No audit entries found",
				"entries": []map[string]interface{}{},
			}))
			return nil
		}

		// Convert entries to array of maps for JSON output
		entries := make([]map[string]interface{}, len(result.Entries))
		for i, entry := range result.Entries {
			entries[i] = map[string]interface{}{
				"timestamp":   entry.Timestamp,
				"action":      entry.Action,
				"success":     entry.Success,
				"secret_name": entry.SecretName,
				"client_id":   entry.ClientID,
				"details":     entry.Details,
			}
		}

		auditData := map[string]interface{}{
			"entries":     entries,
			"total_shown": len(entries),
			"tail_limit":  auditTail,
		}

		// Suggest filtering actions
		actions := []output.Action{
			output.ActionAuditTail(10),
			output.ActionAuditTail(100),
			{
				Description: "Show all audit entries",
				Command:     "secrets audit --tail 0",
			},
			output.ActionStatus(),
		}

		output.Print(output.Success(commandName, auditData, actions...))
		return nil
	},
}

func init() {
	auditCmd.Flags().IntVar(&auditTail, "tail", 50, "Number of recent entries to show (0 = all)")
}

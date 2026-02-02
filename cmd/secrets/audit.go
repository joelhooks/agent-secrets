package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/spf13/cobra"
)

var auditTail int

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View audit log entries",
	Long: `Display audit log entries showing all operations performed on secrets and leases.
Use --tail to limit the number of entries shown.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		params := daemon.AuditParams{
			Tail: auditTail,
		}

		resp, err := rpcCall(socketPath, daemon.MethodAudit, params)
		if err != nil {
			return fmt.Errorf("failed to fetch audit log: %w", err)
		}

		var result daemon.AuditResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("failed to parse result: %w", err)
		}

		if len(result.Entries) == 0 {
			fmt.Println("No audit entries found.")
			return nil
		}

		// Pretty-print audit entries in a table
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TIMESTAMP\tACTION\tSUCCESS\tSECRET\tCLIENT\tDETAILS")
		fmt.Fprintln(w, "─────────\t──────\t───────\t──────\t──────\t───────")

		for _, entry := range result.Entries {
			timestamp := entry.Timestamp.Format(time.RFC3339)
			success := "✓"
			if !entry.Success {
				success = "✗"
			}

			secretName := entry.SecretName
			if secretName == "" {
				secretName = "-"
			}

			clientID := entry.ClientID
			if clientID == "" {
				clientID = "-"
			}

			details := entry.Details
			if details == "" {
				details = "-"
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				timestamp, entry.Action, success, secretName, clientID, details)
		}

		w.Flush()
		return nil
	},
}

func init() {
	auditCmd.Flags().IntVar(&auditTail, "tail", 50, "Number of recent entries to show (0 = all)")
}

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/spf13/cobra"
)

var (
	leaseTTL      string
	leaseClientID string
)

var leaseCmd = &cobra.Command{
	Use:   "lease <name>",
	Short: "Acquire a time-bounded lease on a secret",
	Long: `Acquire a lease on a secret with a specified time-to-live. The lease grants
temporary access to the secret value. The secret value is printed to stdout only,
making it easy to pipe to other commands.

Example:
  TOKEN=$(secrets lease github_token --ttl 1h)
  export API_KEY=$(secrets lease api_key --ttl 30m)`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		// Default client ID to hostname
		if leaseClientID == "" {
			hostname, err := os.Hostname()
			if err != nil {
				leaseClientID = "unknown"
			} else {
				leaseClientID = hostname
			}
		}

		params := daemon.LeaseParams{
			SecretName: name,
			ClientID:   leaseClientID,
			TTL:        leaseTTL,
		}

		resp, err := rpcCall(socketPath, daemon.MethodLease, params)
		if err != nil {
			return fmt.Errorf("failed to acquire lease: %w", err)
		}

		var result daemon.LeaseResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("failed to parse result: %w", err)
		}

		// Print ONLY the secret value to stdout (for piping)
		// No decorations, no newlines (well, one newline for shell convenience)
		fmt.Println(result.Value)

		return nil
	},
}

func init() {
	leaseCmd.Flags().StringVar(&leaseTTL, "ttl", "1h", "Time-to-live for the lease (e.g., 1h, 30m, 2h30m)")
	leaseCmd.Flags().StringVar(&leaseClientID, "client-id", "", "Client identifier (defaults to hostname)")
}

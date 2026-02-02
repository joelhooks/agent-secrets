package main

import (
	"encoding/json"
	"fmt"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/spf13/cobra"
)

var revokeAll bool

var revokeCmd = &cobra.Command{
	Use:   "revoke [lease-id]",
	Short: "Revoke a lease or trigger killswitch",
	Long: `Revoke a specific lease by ID, or use --all to trigger the killswitch and
revoke all active leases.

Examples:
  secrets revoke lease-abc123       # Revoke specific lease
  secrets revoke --all              # Revoke all leases (killswitch)`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if revokeAll {
			// Trigger killswitch - revoke all
			resp, err := rpcCall(socketPath, daemon.MethodRevokeAll, daemon.RevokeAllParams{})
			if err != nil {
				return fmt.Errorf("failed to revoke all leases: %w", err)
			}

			var result daemon.RevokeAllResult
			data, err := json.Marshal(resp.Result)
			if err != nil {
				return fmt.Errorf("failed to parse response: %w", err)
			}
			if err := json.Unmarshal(data, &result); err != nil {
				return fmt.Errorf("failed to parse result: %w", err)
			}

			if result.Success {
				fmt.Printf("✓ Killswitch triggered: revoked %d lease(s)\n", result.LeasesRevoked)
			} else {
				return fmt.Errorf("failed to revoke all: %s", result.Message)
			}

			return nil
		}

		// Revoke specific lease
		if len(args) == 0 {
			return fmt.Errorf("lease-id required (or use --all for killswitch)")
		}

		leaseID := args[0]
		params := daemon.RevokeParams{
			LeaseID: leaseID,
		}

		resp, err := rpcCall(socketPath, daemon.MethodRevoke, params)
		if err != nil {
			return fmt.Errorf("failed to revoke lease: %w", err)
		}

		var result daemon.RevokeResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("failed to parse result: %w", err)
		}

		if result.Success {
			fmt.Printf("✓ Lease '%s' revoked successfully\n", leaseID)
		} else {
			return fmt.Errorf("failed to revoke lease: %s", result.Message)
		}

		return nil
	},
}

func init() {
	revokeCmd.Flags().BoolVar(&revokeAll, "all", false, "Trigger killswitch: revoke all active leases")
}

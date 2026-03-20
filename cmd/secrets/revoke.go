package main

import (
	"encoding/json"
	"fmt"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
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
		const commandName = "secrets revoke"
		if revokeAll {
			// Trigger killswitch - revoke all
			resp, err := rpcCall(socketPath, daemon.MethodRevokeAll, daemon.RevokeAllParams{})
			if err != nil {
				return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to revoke all leases: %w", err)))
			}

			var result daemon.RevokeAllResult
			data, err := json.Marshal(resp.Result)
			if err != nil {
				return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to parse response: %w", err)))
			}
			if err := json.Unmarshal(data, &result); err != nil {
				return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to parse result: %w", err)))
			}

			if !result.Success {
				return output.PrintFail(output.ErrorMsg(commandName, result.Message))
			}

			killswitchData := map[string]interface{}{
				"leases_revoked": result.LeasesRevoked,
			}

			actions := []output.Action{
				output.ActionStatus(),
				output.ActionAudit(),
			}

			output.Print(output.Success(commandName, killswitchData, actions...))
			return nil
		}

		// Revoke specific lease
		if len(args) == 0 {
			return output.PrintFail(output.ErrorMsg(commandName, "lease-id required (or use --all for killswitch)", output.ActionHelp("revoke")))
		}

		leaseID := args[0]
		params := daemon.RevokeParams{
			LeaseID: leaseID,
		}

		resp, err := rpcCall(socketPath, daemon.MethodRevoke, params)
		if err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to revoke lease: %w", err)))
		}

		var result daemon.RevokeResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to parse response: %w", err)))
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to parse result: %w", err)))
		}

		if !result.Success {
			return output.PrintFail(output.ErrorMsg(commandName, result.Message))
		}

		revokeData := map[string]interface{}{
			"lease_id": leaseID,
		}

		actions := []output.Action{
			output.ActionStatus(),
			output.ActionAudit(),
		}

		output.Print(output.Success(commandName, revokeData, actions...))
		return nil
	},
}

func init() {
	revokeCmd.Flags().BoolVar(&revokeAll, "all", false, "Trigger killswitch: revoke all active leases")
}

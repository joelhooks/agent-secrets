package main

import (
	"encoding/json"
	"fmt"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/spf13/cobra"
)

var revokeAll bool
var namespace string

var revokeCmd = &cobra.Command{
	Use:   "revoke [lease-id]",
	Short: "Revoke a lease or trigger killswitch",
	Long: `Revoke a specific lease by ID, or use --all to trigger the killswitch and
revoke all active leases. Use --namespace to revoke all leases in a namespace.

Examples:
  secrets revoke lease-abc123           # Revoke specific lease
  secrets revoke --all                  # Revoke all leases (killswitch)
  secrets revoke --namespace task-123   # Revoke all leases in namespace`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Handle --all or --namespace (both use revokeAll)
		if revokeAll || namespace != "" {
			params := daemon.RevokeAllParams{
				Namespace: namespace,
			}

			resp, err := rpcCall(socketPath, daemon.MethodRevokeAll, params)
			if err != nil {
				output.Print(output.Error(fmt.Errorf("failed to revoke all leases: %w", err)))
				return nil
			}

			var result daemon.RevokeAllResult
			data, err := json.Marshal(resp.Result)
			if err != nil {
				output.Print(output.Error(fmt.Errorf("failed to parse response: %w", err)))
				return nil
			}
			if err := json.Unmarshal(data, &result); err != nil {
				output.Print(output.Error(fmt.Errorf("failed to parse result: %w", err)))
				return nil
			}

			if !result.Success {
				output.Print(output.ErrorMsg(result.Message))
				return nil
			}

			killswitchData := map[string]interface{}{
				"leases_revoked": result.LeasesRevoked,
			}

			actions := []output.Action{
				output.ActionStatus(),
				output.ActionAudit(),
			}

			successMsg := "Killswitch triggered: all leases revoked"
			if namespace != "" {
				successMsg = fmt.Sprintf("Revoked all leases in namespace: %s", namespace)
			}

			output.Print(output.Success(successMsg, killswitchData, actions...))
			return nil
		}

		// Revoke specific lease
		if len(args) == 0 {
			output.Print(output.ErrorMsg("lease-id required (or use --all for killswitch)", output.ActionHelp("revoke")))
			return nil
		}

		leaseID := args[0]
		params := daemon.RevokeParams{
			LeaseID: leaseID,
		}

		resp, err := rpcCall(socketPath, daemon.MethodRevoke, params)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to revoke lease: %w", err)))
			return nil
		}

		var result daemon.RevokeResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse response: %w", err)))
			return nil
		}
		if err := json.Unmarshal(data, &result); err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse result: %w", err)))
			return nil
		}

		if !result.Success {
			output.Print(output.ErrorMsg(result.Message))
			return nil
		}

		revokeData := map[string]interface{}{
			"lease_id": leaseID,
		}

		actions := []output.Action{
			output.ActionStatus(),
			output.ActionAudit(),
		}

		output.Print(output.Success("Lease revoked successfully", revokeData, actions...))
		return nil
	},
}

func init() {
	revokeCmd.Flags().BoolVar(&revokeAll, "all", false, "Trigger killswitch: revoke all active leases")
	revokeCmd.Flags().StringVar(&namespace, "namespace", "", "Revoke all leases in namespace")
}

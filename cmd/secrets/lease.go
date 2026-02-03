package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/store"
	"github.com/joelhooks/agent-secrets/internal/types"
	"github.com/spf13/cobra"
)

var (
	leaseTTL      string
	leaseClientID string
	leaseRaw      bool
)

var leaseCmd = &cobra.Command{
	Use:   "lease <name>",
	Short: "Acquire a time-bounded lease on a secret",
	Long: `Acquire a lease on a secret with a specified time-to-live. The lease grants
temporary access to the secret value.

By default, returns a JSON response with lease details and available actions.
Use --raw to output ONLY the secret value (for piping to shell commands).

Secrets can be namespaced using the syntax: namespace::name

Examples:
  secrets lease github_token                    # JSON response with details
  export TOKEN=$(secrets lease github_token --raw)  # Shell export
  secrets lease api_key --ttl 30m               # Custom TTL
  secrets lease prod::github_token              # Namespace support`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		namespace, name := store.ParseSecretRef(args[0])

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
			Namespace:  namespace,
			SecretName: name,
			ClientID:   leaseClientID,
			TTL:        leaseTTL,
		}

		resp, err := rpcCall(socketPath, daemon.MethodLease, params)
		if err != nil {
			// Check if this is a daemon connection error
			if isDaemonConnectionError(err) {
				userErr := types.NewUserError(
					"Failed to connect to daemon",
					"The daemon doesn't appear to be running. Without the daemon, secrets cannot be leased.",
					"To start it:\n  secrets serve &",
					"secrets --help",
				).WithContext("Socket path", socketPath)
				output.Print(output.Error(userErr))
				return nil
			}
			output.Print(output.Error(fmt.Errorf("failed to acquire lease: %w", err)))
			return nil
		}

		var result daemon.LeaseResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse response: %w", err)))
			return nil
		}
		if err := json.Unmarshal(data, &result); err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse result: %w", err)))
			return nil
		}

		// --raw flag: output ONLY the secret value (for piping)
		if leaseRaw {
			fmt.Print(result.Value)
			return nil
		}

		// Build HATEOAS response
		leaseData := map[string]interface{}{
			"lease_id":    result.LeaseID,
			"secret_name": name,
			"value":       result.Value,
			"expires_at":  result.ExpiresAt,
			"ttl":         leaseTTL,
			"client_id":   leaseClientID,
		}

		// Generate environment variable name suggestion (uppercase with underscores)
		envVarName := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))

		actions := []output.Action{
			{
				Name:        "export",
				Description: "Export to environment",
				Command:     fmt.Sprintf("export %s=$(secrets lease %s --raw)", envVarName, name),
			},
			{
				Name:        "revoke",
				Description: "Revoke this lease",
				Command:     fmt.Sprintf("secrets revoke %s", result.LeaseID),
			},
			output.ActionStatus(),
			output.ActionAudit(),
		}

		output.Print(output.Success("Lease acquired", leaseData, actions...))
		return nil
	},
}

func init() {
	leaseCmd.Flags().StringVar(&leaseTTL, "ttl", "1h", "Time-to-live for the lease (e.g., 1h, 30m, 2h30m)")
	leaseCmd.Flags().StringVar(&leaseClientID, "client-id", "", "Client identifier (defaults to hostname)")
	leaseCmd.Flags().BoolVar(&leaseRaw, "raw", false, "Output only the secret value (for piping to shell)")
}

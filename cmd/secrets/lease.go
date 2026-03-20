package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/types"
	"github.com/spf13/cobra"
)

var (
	leaseTTL      string
	leaseClientID string
	leaseJSON     bool
	leaseRaw      bool
)

var leaseCmd = &cobra.Command{
	Use:   "lease <name>",
	Short: "Acquire a time-bounded lease on a secret",
	Long: `Acquire a lease on a secret with a specified time-to-live. The lease grants
temporary access to the secret value.

By default, outputs ONLY the secret value (no newline), perfect for command substitution.
Use --json to output the full HATEOAS JSON envelope with lease details and next actions.

Examples:
  export TOKEN=$(secrets lease github_token)     # Shell export (default raw value)
  secrets lease github_token --json              # JSON response with details
  secrets lease api_key --ttl 30m                # Custom TTL`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		const commandName = "secrets lease"

		if cmd.Flags().Lookup("raw") != nil && cmd.Flags().Changed("raw") {
			output.DeprecationWarning("WARNING: --raw is deprecated and now the default. Remove from scripts. Will be removed in v0.6.0")
		}

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
			// Check if this is a daemon connection error
			if isDaemonConnectionError(err) {
				userErr := types.NewUserError(
					"Failed to connect to daemon",
					"The daemon doesn't appear to be running. Without the daemon, secrets cannot be leased.",
					"Start the daemon: secrets serve &",
					"secrets --help",
				).WithContext("Socket path", socketPath)
				return output.PrintFail(output.ErrorWithFix(commandName, userErr, "Start the daemon: secrets serve &"))
			}
			if strings.Contains(strings.ToLower(err.Error()), "secret not found") {
				return output.PrintFail(output.ErrorWithFix(
					commandName,
					fmt.Errorf("failed to acquire lease: %w", err),
					"Check available secrets: secrets status",
				))
			}
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to acquire lease: %w", err)))
		}

		var result daemon.LeaseResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to parse response: %w", err)))
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to parse result: %w", err)))
		}

		// Default behavior: output ONLY the secret value (for piping/substitution)
		if !leaseJSON {
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
				Description: "Export to environment",
				Command:     fmt.Sprintf("export %s=$(secrets lease %s)", envVarName, name),
			},
			{
				Description: "Revoke this lease",
				Command:     fmt.Sprintf("secrets revoke %s", result.LeaseID),
			},
			output.ActionStatus(),
			output.ActionAudit(),
		}

		output.Print(output.Success(commandName, leaseData, actions...))
		return nil
	},
}

func init() {
	leaseCmd.Flags().StringVar(&leaseTTL, "ttl", "1h", "Time-to-live for the lease (e.g., 1h, 30m, 2h30m)")
	leaseCmd.Flags().StringVar(&leaseClientID, "client-id", "", "Client identifier (defaults to hostname)")
	leaseCmd.Flags().BoolVar(&leaseJSON, "json", false, "Output full JSON envelope with lease metadata and next actions")
	leaseCmd.Flags().BoolVar(&leaseRaw, "raw", false, "[deprecated] No-op: raw output is now the default")
	if err := leaseCmd.Flags().MarkHidden("raw"); err != nil {
		panic(err)
	}
}

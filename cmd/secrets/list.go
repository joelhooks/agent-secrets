package main

import (
	"encoding/json"
	"fmt"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/types"
	"github.com/spf13/cobra"
)

var (
	listNamespace string
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets",
	Long:  `Display metadata for all secrets, optionally filtered by namespace.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		params := daemon.ListParams{
			Namespace: listNamespace,
		}

		resp, err := rpcCall(socketPath, daemon.MethodList, params)
		if err != nil {
			// Check if this is a daemon connection error
			if isDaemonConnectionError(err) {
				userErr := types.NewUserError(
					"Failed to connect to daemon",
					"The daemon doesn't appear to be running. Without the daemon, secrets cannot be listed.",
					"To start it:\n  secrets serve &",
					"secrets --help",
				).WithContext("Socket path", socketPath)
				output.Print(output.Error(userErr))
				return userErr
			}
			output.Print(output.Error(fmt.Errorf("failed to list secrets: %w", err)))
			return fmt.Errorf("failed to list secrets: %w", err)
		}

		var result daemon.ListResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse response: %w", err)))
			return fmt.Errorf("failed to parse response: %w", err)
		}
		if err := json.Unmarshal(data, &result); err != nil {
			output.Print(output.Error(fmt.Errorf("failed to parse result: %w", err)))
			return fmt.Errorf("failed to parse result: %w", err)
		}

		if len(result.Secrets) == 0 {
			msg := "No secrets found"
			if listNamespace != "" {
				msg = fmt.Sprintf("No secrets found in namespace %q", listNamespace)
			}
			output.Print(output.Success(msg, nil))
			return nil
		}

		// Build data for output - convert secrets to map format with namespace::name
		secretsList := make([]map[string]interface{}, len(result.Secrets))
		for i, s := range result.Secrets {
			fullName := s.Name
			if s.Namespace != "" && s.Namespace != "default" {
				fullName = fmt.Sprintf("%s::%s", s.Namespace, s.Name)
			}

			secretsList[i] = map[string]interface{}{
				"name":         fullName,
				"namespace":    s.Namespace,
				"created_at":   s.CreatedAt.Format("2006-01-02 15:04:05"),
				"updated_at":   s.UpdatedAt.Format("2006-01-02 15:04:05"),
				"rotate_via":   s.RotateVia,
				"last_rotated": s.LastRotated,
			}
		}

		outputData := map[string]interface{}{
			"count":   len(result.Secrets),
			"secrets": secretsList,
		}

		if listNamespace != "" {
			outputData["namespace"] = listNamespace
		}

		// Build contextual actions
		actions := []output.Action{
			output.ActionLease(""),
			output.ActionAdd(""),
			output.ActionAudit(),
		}

		msg := fmt.Sprintf("Found %d secret(s)", len(result.Secrets))
		if listNamespace != "" {
			msg = fmt.Sprintf("Found %d secret(s) in namespace %q", len(result.Secrets), listNamespace)
		}

		output.Print(output.Success(msg, outputData, actions...))
		return nil
	},
}

func init() {
	listCmd.Flags().StringVar(&listNamespace, "namespace", "", "Filter by namespace")
}

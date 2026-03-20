package main

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/types"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored secret names",
	Long:  `List all stored secrets with metadata useful for agent discovery flows.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		const commandName = "secrets list"

		resp, err := rpcCall(socketPath, daemon.MethodList, daemon.ListParams{})
		if err != nil {
			if isDaemonConnectionError(err) {
				userErr := types.NewUserError(
					"Failed to connect to daemon",
					"The daemon doesn't appear to be running. Without the daemon, secrets cannot be listed.",
					"Start the daemon: secrets serve &",
					"secrets --help",
				).WithContext("Socket path", socketPath)
				return output.PrintFail(output.ErrorWithFix(commandName, userErr, "Start the daemon: secrets serve &"))
			}
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to list secrets: %w", err)))
		}

		var listResult daemon.ListResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to parse response: %w", err)))
		}
		if err := json.Unmarshal(data, &listResult); err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to parse result: %w", err)))
		}

		type listedSecret struct {
			Name         string `json:"name"`
			HasRotation  bool   `json:"has_rotation"`
			ActiveLeases int    `json:"active_leases"`
		}

		sortedSecrets := append([]daemon.SecretMetadata(nil), listResult.Secrets...)
		// Keep CLI output deterministic even if older daemons return unsorted lists.
		sort.Slice(sortedSecrets, func(i, j int) bool {
			return sortedSecrets[i].Name < sortedSecrets[j].Name
		})

		secrets := make([]listedSecret, len(sortedSecrets))
		actions := make([]output.Action, 0, len(sortedSecrets)+1)
		for i, secret := range sortedSecrets {
			secrets[i] = listedSecret{
				Name:         secret.Name,
				HasRotation:  secret.RotateVia != "",
				ActiveLeases: secret.ActiveLeases,
			}
			actions = append(actions, output.Action{
				Command:     fmt.Sprintf("secrets lease %s", secret.Name),
				Description: fmt.Sprintf("Lease %s", secret.Name),
			})
		}

		actions = append(actions, output.ActionAdd(""))

		output.Print(output.Success(
			commandName,
			map[string]interface{}{
				"secrets": secrets,
				"count":   len(secrets),
			},
			actions...,
		))
		return nil
	},
}

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/types"
	"github.com/spf13/cobra"
)

var deleteForce bool

var deleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"rm"},
	Short:   "Delete a secret from the store",
	Long:    "Delete a secret from the encrypted store and revoke any active leases for that secret.",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		const commandName = "secrets delete"
		name := args[0]

		if !deleteForce {
			confirmed, err := confirmDeleteSecret(name)
			if err != nil {
				return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to read confirmation: %w", err)))
			}
			if !confirmed {
				return output.PrintFail(output.ErrorMsgWithFix(
					commandName,
					"deletion cancelled",
					"Re-run with --force to skip confirmation",
					output.ActionHelp("delete"),
				))
			}
		}

		resp, err := rpcCall(socketPath, daemon.MethodDelete, daemon.DeleteParams{Name: name})
		if err != nil {
			if isDaemonConnectionError(err) {
				userErr := types.NewUserError(
					"Failed to connect to daemon",
					"The daemon doesn't appear to be running. Without the daemon, secrets cannot be deleted.",
					"Start the daemon: secrets serve &",
					"secrets --help",
				).WithContext("Socket path", socketPath)
				return output.PrintFail(output.ErrorWithFix(commandName, userErr, "Start the daemon: secrets serve &"))
			}

			if strings.Contains(strings.ToLower(err.Error()), "secret not found") {
				return output.PrintFail(output.ErrorWithFix(
					commandName,
					fmt.Errorf("failed to delete secret: %w", err),
					"Check available secrets: secrets list",
					output.Action{Command: "secrets list", Description: "List stored secret names"},
				))
			}

			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to delete secret: %w", err)))
		}

		var result daemon.DeleteResult
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

		output.Print(output.Success(
			commandName,
			map[string]interface{}{
				"name":    name,
				"deleted": true,
				"message": result.Message,
			},
			output.Action{Command: "secrets list", Description: "List stored secret names"},
			output.ActionAdd(name),
			output.ActionAudit(),
		))
		return nil
	},
}

func init() {
	deleteCmd.Flags().BoolVar(&deleteForce, "force", true, "Skip deletion confirmation (default true for agent workflows)")
}

func confirmDeleteSecret(name string) (bool, error) {
	fmt.Printf("Delete secret '%s'? [y/N]: ", name)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}

	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes", nil
}

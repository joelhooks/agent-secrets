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
				output.Print(output.Error(commandName, fmt.Errorf("failed to read confirmation: %w", err)))
				return err
			}
			if !confirmed {
				output.Print(output.ErrorMsgWithFix(
					commandName,
					"deletion cancelled",
					"Re-run with --force to skip confirmation",
					output.ActionHelp("delete"),
				))
				return nil
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
				output.Print(output.ErrorWithFix(commandName, userErr, "Start the daemon: secrets serve &"))
				return nil
			}

			if strings.Contains(strings.ToLower(err.Error()), "secret not found") {
				output.Print(output.ErrorWithFix(
					commandName,
					fmt.Errorf("failed to delete secret: %w", err),
					"Check available secrets: secrets list",
					output.Action{Command: "secrets list", Description: "List stored secret names"},
				))
				return nil
			}

			output.Print(output.Error(commandName, fmt.Errorf("failed to delete secret: %w", err)))
			return nil
		}

		var result daemon.DeleteResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			output.Print(output.Error(commandName, fmt.Errorf("failed to parse response: %w", err)))
			return err
		}
		if err := json.Unmarshal(data, &result); err != nil {
			output.Print(output.Error(commandName, fmt.Errorf("failed to parse result: %w", err)))
			return err
		}

		if !result.Success {
			output.Print(output.ErrorMsg(commandName, result.Message))
			return nil
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

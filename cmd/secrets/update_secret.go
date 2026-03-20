package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/types"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	updateSecretValue     string
	updateSecretRotateVia string
)

var updateCmd = &cobra.Command{
	Use:   "update <name>",
	Short: "Replace the value of an existing secret",
	Long: `Update an existing secret in the encrypted store. The new value can be provided via:
  - The --value flag
  - Piped from stdin (e.g., echo "secret" | secrets update name)
  - Interactive prompt (secure, no echo)`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		const commandName = "secrets update"

		name := args[0]
		value, err := readSecretInputValue(name, updateSecretValue)
		if err != nil {
			return output.PrintFail(output.Error(commandName, err))
		}

		value = strings.TrimSpace(value)
		if value == "" {
			return output.PrintFail(output.ErrorMsgWithFix(
				commandName,
				"secret value cannot be empty",
				"Provide a value via --value, stdin pipe, or interactive prompt",
				output.ActionHelp("update"),
			))
		}

		params := daemon.UpdateParams{
			Name:  name,
			Value: value,
		}
		if cmd.Flags().Changed("rotate-via") {
			params.RotateVia = updateSecretRotateVia
			params.RotateViaSet = true
		}

		resp, err := rpcCall(socketPath, daemon.MethodUpdate, params)
		if err != nil {
			if isDaemonConnectionError(err) {
				userErr := types.NewUserError(
					"Failed to connect to daemon",
					"The daemon doesn't appear to be running. Without the daemon, secrets cannot be updated.",
					"Start the daemon: secrets serve &",
					"secrets --help",
				).WithContext("Socket path", socketPath)
				return output.PrintFail(output.ErrorWithFix(commandName, userErr, "Start the daemon: secrets serve &"))
			}

			if strings.Contains(strings.ToLower(err.Error()), "secret not found") {
				fix := fmt.Sprintf("Secret %q does not exist. Add it first: secrets add %s", name, name)
				return output.PrintFail(output.ErrorWithFix(commandName, fmt.Errorf("failed to update secret: %w", err), fix, output.ActionAdd(name)))
			}

			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to update secret: %w", err), output.ActionAdd(name)))
		}

		var result daemon.UpdateResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to parse response: %w", err)))
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to parse result: %w", err)))
		}

		if !result.Success {
			fix := fmt.Sprintf("Use `secrets add %s --value <value>` to create it first.", name)
			return output.PrintFail(output.ErrorMsgWithFix(commandName, result.Message, fix, output.ActionAdd(name)))
		}

		output.Print(output.Success(
			commandName,
			map[string]interface{}{
				"name":       name,
				"message":    result.Message,
				"rotate_via": params.RotateVia,
			},
			output.Action{Command: fmt.Sprintf("secrets lease %s", name), Description: fmt.Sprintf("Lease %s", name)},
			output.ActionStatus(),
			output.Action{Command: fmt.Sprintf("secrets delete %s --force", name), Description: fmt.Sprintf("Delete %s", name)},
		))

		return nil
	},
}

func init() {
	updateCmd.Flags().StringVar(&updateSecretValue, "value", "", "Updated secret value (if not provided, will prompt or read from stdin)")
	updateCmd.Flags().StringVar(&updateSecretRotateVia, "rotate-via", "", "Update rotation command for this secret")
}

func readSecretInputValue(name, fromFlag string) (string, error) {
	if fromFlag != "" {
		return fromFlag, nil
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", fmt.Errorf("failed to read from stdin: %w", err)
			}
			return scanner.Text(), nil
		}
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("failed to read from stdin: %w", err)
		}
		return "", nil
	}

	fmt.Printf("Enter secret value for '%s': ", name)
	byteValue, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()
	return string(byteValue), nil
}

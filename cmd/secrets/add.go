package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	addValue     string
	addRotateVia string
)

var addCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a secret to the store",
	Long: `Add a new secret to the encrypted store. The secret value can be provided via:
  - The --value flag
  - Piped from stdin (e.g., echo "secret" | secrets add name)
  - Interactive prompt (secure, no echo)`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		value := addValue

		// If no value provided via flag, check stdin or prompt
		if value == "" {
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				// Data is being piped in
				scanner := bufio.NewScanner(os.Stdin)
				if scanner.Scan() {
					value = scanner.Text()
				}
				if err := scanner.Err(); err != nil {
					return fmt.Errorf("failed to read from stdin: %w", err)
				}
			} else {
				// Interactive prompt
				fmt.Printf("Enter secret value for '%s': ", name)
				byteValue, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return fmt.Errorf("failed to read password: %w", err)
				}
				fmt.Println() // Add newline after hidden input
				value = string(byteValue)
			}
		}

		value = strings.TrimSpace(value)
		if value == "" {
			return fmt.Errorf("secret value cannot be empty")
		}

		params := daemon.AddParams{
			Name:      name,
			Value:     value,
			RotateVia: addRotateVia,
		}

		resp, err := rpcCall(socketPath, daemon.MethodAdd, params)
		if err != nil {
			return fmt.Errorf("failed to add secret: %w", err)
		}

		var result daemon.AddResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("failed to parse result: %w", err)
		}

		if result.Success {
			fmt.Printf("✓ Secret '%s' added successfully", name)
			if addRotateVia != "" {
				fmt.Printf(" with rotation via: %s", addRotateVia)
			}
			fmt.Println()
		} else {
			return fmt.Errorf("failed to add secret: %s", result.Message)
		}

		return nil
	},
}

func init() {
	addCmd.Flags().StringVar(&addValue, "value", "", "Secret value (if not provided, will prompt or read from stdin)")
	addCmd.Flags().StringVar(&addRotateVia, "rotate-via", "", "Command to execute for automatic rotation")
}

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/project"
	"github.com/spf13/cobra"
)

var (
	execTTL string
)

var execCmd = &cobra.Command{
	Use:   "exec [flags] -- command [args...]",
	Short: "Execute command with secrets injected as environment variables",
	Long: `Execute a subprocess with secrets from the configured source injected as
environment variables. No secrets are written to disk.

The command requires a .secrets.json file in the current directory or a parent.
Secrets are fetched from the configured source (e.g., Vercel) and injected into
the subprocess environment.

Examples:
  secrets exec -- npm run dev                    # Run with injected secrets
  secrets exec --ttl 1h -- ./my-script.sh        # Kill after 1 hour
  secrets exec -- printenv | grep API            # View injected vars`,
	Args:                  cobra.MinimumNArgs(1),
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Find .secrets.json
		cfg, projectDir, err := project.FindProjectConfig()
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to find project config: %w", err)))
			return err
		}

		// Get adapter for the configured source
		adapter, err := getAdapter(cfg.Source)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to initialize adapter: %w", err)))
			return err
		}

		// Pull secrets
		secrets, err := adapter.Pull(cfg.Project, cfg.Scope)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to pull secrets: %w", err)))
			return err
		}

		if len(secrets) == 0 {
			output.Print(output.Error(fmt.Errorf("no secrets found for project %q in scope %q", cfg.Project, cfg.Scope)))
			return nil
		}

		// Build environment variables
		env := os.Environ()
		secretKeys := make([]string, 0, len(secrets))
		for key, value := range secrets {
			env = append(env, fmt.Sprintf("%s=%s", key, value))
			secretKeys = append(secretKeys, key)
		}

		// Parse optional TTL
		var ctx context.Context
		var cancel context.CancelFunc
		if execTTL != "" {
			ttl, err := time.ParseDuration(execTTL)
			if err != nil {
				output.Print(output.Error(fmt.Errorf("invalid ttl: %w", err)))
				return err
			}
			ctx, cancel = context.WithTimeout(context.Background(), ttl)
		} else {
			ctx, cancel = context.WithCancel(context.Background())
		}
		defer cancel()

		// Create command
		command := exec.CommandContext(ctx, args[0], args[1:]...)
		command.Env = env
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		command.Dir = projectDir // Run in project directory

		// Handle signals (SIGINT, SIGTERM) to propagate to child
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

		// Start subprocess
		if err := command.Start(); err != nil {
			output.Print(output.Error(fmt.Errorf("failed to start command: %w", err)))
			return err
		}

		// Wait for either signal or process completion
		done := make(chan error, 1)
		go func() {
			done <- command.Wait()
		}()

		select {
		case sig := <-sigChan:
			// Forward signal to child process
			if command.Process != nil {
				command.Process.Signal(sig)
			}
			// Wait for child to exit or force kill after 5 seconds
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				if command.Process != nil {
					command.Process.Kill()
				}
			}
			return fmt.Errorf("terminated by signal: %v", sig)

		case err := <-done:
			// Process exited naturally
			if err != nil {
				// Check if it's an exit error
				if exitErr, ok := err.(*exec.ExitError); ok {
					// Return exit code
					os.Exit(exitErr.ExitCode())
				}
				output.Print(output.Error(fmt.Errorf("command failed: %w", err)))
				return err
			}

			// Success
			data := map[string]interface{}{
				"command":      strings.Join(args, " "),
				"source":       cfg.Source,
				"project":      cfg.Project,
				"scope":        cfg.Scope,
				"secrets_count": len(secrets),
				"secret_keys":  secretKeys,
			}

			output.Print(output.Success("Command executed with injected secrets", data))
			return nil

		case <-ctx.Done():
			// TTL timeout
			if command.Process != nil {
				command.Process.Kill()
			}
			output.Print(output.Error(fmt.Errorf("command exceeded TTL: %s", execTTL)))
			return fmt.Errorf("timeout")
		}
	},
}

func init() {
	execCmd.Flags().StringVar(&execTTL, "ttl", "", "Maximum subprocess duration (e.g., 1h, 30m)")
}

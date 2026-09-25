package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sort"
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
	Long: `Execute a subprocess with project secrets injected as environment variables.
No secrets are written to disk.

The command requires a .secrets.json file in the current directory or a parent.
Both configuration shapes are supported:

Store-backed - each secret is leased from the local store and the lease is
revoked when the command exits:

  {"secrets": [{"name": "github_token", "env_var": "GITHUB_TOKEN"}]}

Provider-backed - secret values are pulled from the configured source
(e.g. Vercel) before the command starts:

  {"source": "vercel", "project": "my-app", "scope": "development", "ttl": "1h"}

Examples:
  secrets exec -- npm run dev                    # Run with injected secrets
  secrets exec --ttl 1h -- ./my-script.sh        # Kill after 1 hour
  secrets exec -- printenv | grep API            # View injected vars`,
	Args:                  cobra.MinimumNArgs(1),
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		const commandName = "secrets exec"
		// Find .secrets.json
		cfg, projectDir, err := project.FindProjectConfig()
		if err != nil {
			return output.PrintFail(output.ErrorWithFix(
				commandName,
				fmt.Errorf("failed to find project config: %w", err),
				"Create a .secrets.json in this directory or a parent directory",
			))
		}

		// Resolve secrets for the configured mode
		resolved, err := resolveExecSecrets(cfg)
		if err != nil {
			return output.PrintFail(output.ErrorWithFix(commandName, err, storeLeaseFix(err)))
		}
		// Revoke any leases acquired for this run once the command exits
		defer resolved.Cleanup()

		if len(resolved.Keys) == 0 {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("no secrets found in %s", project.DefaultProjectConfigFile)))
		}

		env := resolved.Env
		secretKeys := resolved.Keys

		// Parse optional TTL
		var ctx context.Context
		var cancel context.CancelFunc
		if execTTL != "" {
			ttl, err := time.ParseDuration(execTTL)
			if err != nil {
				return output.PrintFail(output.Error(commandName, fmt.Errorf("invalid ttl: %w", err)))
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
			return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to start command: %w", err)))
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
				_ = command.Process.Signal(sig)
			}
			// Wait for child to exit or force kill after 5 seconds
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				if command.Process != nil {
					_ = command.Process.Kill()
				}
			}
			return fmt.Errorf("terminated by signal: %v", sig)

		case err := <-done:
			// Process exited naturally
			if err != nil {
				// Preserve the child's exit code, but return it rather than
				// calling os.Exit directly: os.Exit skips deferred functions, so
				// it would leak the leases acquired for this run.
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					return output.PrintFail(output.ErrorWithCode(
						commandName,
						fmt.Errorf("command exited with code %d", exitErr.ExitCode()),
						exitErr.ExitCode(),
					))
				}
				return output.PrintFail(output.Error(commandName, fmt.Errorf("command failed: %w", err)))
			}

			// Success
			data := map[string]interface{}{
				"command":       strings.Join(args, " "),
				"mode":          resolved.Mode,
				"source":        resolved.Source,
				"project":       resolved.Project,
				"scope":         resolved.Scope,
				"secrets_count": len(secretKeys),
				"secret_keys":   secretKeys,
			}

			data["message"] = "Command executed with injected secrets"
			output.Print(output.Success(commandName, data))
			return nil

		case <-ctx.Done():
			// TTL timeout
			if command.Process != nil {
				_ = command.Process.Kill()
			}
			return output.PrintFail(output.Error(commandName, fmt.Errorf("command exceeded TTL: %s", execTTL)))
		}
	},
}

// execSecrets holds the environment to inject into a subprocess along with
// non-sensitive metadata and a cleanup hook for any acquired leases.
type execSecrets struct {
	Env     []string
	Keys    []string
	Mode    string
	Source  string
	Project string
	Scope   string

	cleanup func()
}

// Cleanup releases any resources acquired while resolving secrets.
func (e *execSecrets) Cleanup() {
	if e.cleanup != nil {
		e.cleanup()
	}
}

// resolveExecSecrets resolves the environment variables to inject based on the
// shape of the project config. Store-backed configs acquire leases that are
// revoked by the returned cleanup function; provider-backed configs pull
// values from the external source.
func resolveExecSecrets(cfg *project.ProjectConfig) (*execSecrets, error) {
	resolved := &execSecrets{Env: os.Environ()}

	if cfg.IsStoreBacked() {
		leases, err := acquireProjectLeases(cfg, execTTL)
		if err != nil {
			return nil, err
		}
		resolved.cleanup = func() { revokeLeases(leases) }
		resolved.Mode = "store"
		resolved.Source = storeEnvFileSource
		for _, l := range leases {
			resolved.Env = append(resolved.Env, fmt.Sprintf("%s=%s", l.EnvVar, l.Value))
			resolved.Keys = append(resolved.Keys, l.EnvVar)
		}
		return resolved, nil
	}

	adapter, err := getAdapter(cfg.Source)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize adapter: %w", err)
	}

	secrets, err := adapter.Pull(cfg.Project, cfg.Scope)
	if err != nil {
		return nil, fmt.Errorf("failed to pull secrets: %w", err)
	}
	if len(secrets) == 0 {
		return nil, fmt.Errorf("no secrets found for project %q in scope %q", cfg.Project, cfg.Scope)
	}

	// Inject in a stable order so subprocess environments are reproducible
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		resolved.Env = append(resolved.Env, fmt.Sprintf("%s=%s", name, secrets[name]))
		resolved.Keys = append(resolved.Keys, name)
	}

	resolved.Mode = "source"
	resolved.Source = cfg.Source
	resolved.Project = cfg.Project
	resolved.Scope = cfg.Scope
	return resolved, nil
}

func init() {
	execCmd.Flags().StringVar(&execTTL, "ttl", "", "Maximum subprocess duration (e.g., 1h, 30m)")
}

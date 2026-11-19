package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joelhooks/agent-secrets/internal/envfile"
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/project"
	"github.com/spf13/cobra"
)

var (
	envForce  bool
	envTTL    string
	envDryRun bool
)

var envCmd = &cobra.Command{
	Use:   "env",
	Short: "Write project secrets to an env file",
	Long: `Write environment variables for the current project to an env file.

Reads .secrets.json from the current directory (or a parent directory) and
supports two configuration shapes.

Store-backed - secrets are leased from the local agent-secrets store and
written to .env:

  {
    "secrets": [
      {"name": "github_token", "env_var": "GITHUB_TOKEN"},
      {"name": "stripe_key", "env_var": "STRIPE_SECRET_KEY", "ttl": "30m"}
    ],
    "client_id": "deploy-task"
  }

Provider-backed - secrets are pulled from an external source (e.g. Vercel)
and written to .env.local:

  {
    "source": "vercel",
    "project": "my-app",
    "scope": "development",
    "ttl": "1h"
  }

Both shapes write TTL metadata headers so ` + "`secrets cleanup`" + ` can remove the
file once it expires.

Examples:
  secrets env                           # Write env file using config defaults
  secrets env --force                   # Overwrite existing env file
  secrets env --ttl 2h                  # Override TTL to 2 hours
  secrets env --dry-run                 # Preview without writing`,
	RunE: func(cmd *cobra.Command, args []string) error {
		const commandName = "secrets env"

		// Find project configuration
		cfg, projectDir, err := project.FindProjectConfig()
		if err != nil {
			return output.PrintFail(output.ErrorWithFix(
				commandName,
				fmt.Errorf("failed to find project config: %w", err),
				"Create a .secrets.json in this directory or a parent directory",
			))
		}

		// Build env file path (relative to project directory)
		envFilePath := filepath.Join(projectDir, cfg.GetEnvFile())

		// Check if env file exists and handle --force
		if !envForce && !envDryRun {
			if _, err := os.Stat(envFilePath); err == nil {
				return output.PrintFail(output.ErrorMsg(
					commandName,
					fmt.Sprintf("env file already exists: %s (use --force to overwrite)", envFilePath),
					output.Action{
						Description: "Overwrite existing env file",
						Command:     "secrets env --force",
					},
					output.Action{
						Description: "Check if env file is expired",
						Command:     fmt.Sprintf("cat %s | grep 'secrets-ttl'", envFilePath),
					},
				))
			}
		}

		if cfg.IsStoreBacked() {
			return runStoreBackedEnv(cfg, envFilePath)
		}
		return runSourceBackedEnv(cfg, envFilePath)
	},
}

// runStoreBackedEnv leases each secret listed in .secrets.json and writes the
// values to the project env file.
func runStoreBackedEnv(cfg *project.ProjectConfig, envFilePath string) error {
	const commandName = "secrets env"

	clientID := cfg.GetClientID(hostnameClientID())

	// Dry-run: report the plan without leasing or writing anything
	if envDryRun {
		// Report the TTL actually used per entry, not just the config default,
		// so a per-entry override is visible before anything is leased.
		planned := make([]map[string]string, 0, len(cfg.Secrets))
		envVars := make([]string, 0, len(cfg.Secrets))
		for _, s := range cfg.Secrets {
			ttl := resolveEntryTTL(cfg, s, envTTL)
			if _, err := parseStoreTTL(ttl); err != nil {
				return output.PrintFail(output.Error(commandName, fmt.Errorf("invalid TTL for %s: %w", s.Name, err)))
			}
			envVars = append(envVars, s.EnvVar)
			planned = append(planned, map[string]string{
				"secret":  s.Name,
				"env_var": s.EnvVar,
				"ttl":     ttl,
			})
		}

		output.Print(output.Success(
			commandName,
			map[string]interface{}{
				"mode":        "store",
				"env_file":    envFilePath,
				"secrets":     planned,
				"vars":        envVars,
				"client_id":   clientID,
				"var_count":   len(envVars),
				"would_write": true,
			},
			output.Action{
				Description: "Write the env file",
				Command:     "secrets env",
			},
		))
		return nil
	}

	// Acquire leases for every configured secret
	leases, err := acquireProjectLeases(cfg, envTTL)
	if err != nil {
		return output.PrintFail(output.ErrorWithFix(
			commandName,
			err,
			storeLeaseFix(err),
		))
	}

	// The env file must expire no later than the earliest lease it contains
	expiresAt := leaseExpiry(leases)
	fileTTL := time.Until(expiresAt)
	if fileTTL <= 0 {
		return output.PrintFail(output.Error(
			commandName,
			fmt.Errorf("leases expired before the env file could be written"),
		))
	}

	// Write to env file with TTL
	if err := envfile.WriteWithTTL(envFilePath, leaseVars(leases), fileTTL, storeEnvFileSource); err != nil {
		return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to write env file: %w", err)))
	}

	// Restrict permissions: the file holds plaintext secret values
	if err := os.Chmod(envFilePath, 0600); err != nil {
		return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to secure env file: %w", err)))
	}

	// Success response (never includes secret values)
	output.Print(output.Success(
		commandName,
		map[string]interface{}{
			"mode":       "store",
			"env_file":   envFilePath,
			"expires_at": expiresAt.Format(time.RFC3339),
			"client_id":  clientID,
			"var_count":  len(leases),
			"vars":       leaseVarNames(leases),
			"leases":     leaseSummaries(leases),
		},
		output.Action{
			Description: "Verify env file contents",
			Command:     fmt.Sprintf("cat %s", envFilePath),
		},
		output.Action{
			Description: "Refresh secrets before TTL expires",
			Command:     "secrets env --force",
		},
		output.ActionScan(),
	))

	return nil
}

// runSourceBackedEnv pulls secrets from an external provider (e.g. Vercel) and
// writes them to the project env file.
func runSourceBackedEnv(cfg *project.ProjectConfig, envFilePath string) error {
	const commandName = "secrets env"

	// Determine TTL (flag overrides config)
	ttl, err := parseTTL(cfg, envTTL)
	if err != nil {
		return output.PrintFail(output.Error(commandName, fmt.Errorf("invalid TTL: %w", err)))
	}

	// Get adapter based on source
	adapter, err := getAdapter(cfg.Source)
	if err != nil {
		return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to get adapter: %w", err)))
	}

	// Pull secrets from source
	secrets, err := adapter.Pull(cfg.Project, cfg.Scope)
	if err != nil {
		return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to pull secrets: %w", err)))
	}

	// Check for required vars
	if len(cfg.RequiredVars) > 0 {
		missingVars := []string{}
		for _, required := range cfg.RequiredVars {
			if _, exists := secrets[required]; !exists {
				missingVars = append(missingVars, required)
			}
		}
		if len(missingVars) > 0 {
			return output.PrintFail(output.Error(commandName, fmt.Errorf("missing required vars: %v", missingVars)))
		}
	}

	// Dry-run: show what would be written
	if envDryRun {
		data := map[string]interface{}{
			"source":      cfg.Source,
			"project":     cfg.Project,
			"scope":       cfg.Scope,
			"ttl":         ttl.String(),
			"env_file":    envFilePath,
			"var_count":   len(secrets),
			"vars":        getVarNames(secrets),
			"would_write": true,
		}

		output.Print(output.Success(
			commandName,
			data,
			output.Action{
				Description: "Run sync without --dry-run",
				Command:     "secrets env",
			},
		))
		return nil
	}

	// Write to env file with TTL
	if err := envfile.WriteWithTTL(envFilePath, secrets, ttl, cfg.Source); err != nil {
		return output.PrintFail(output.Error(commandName, fmt.Errorf("failed to write env file: %w", err)))
	}

	// Success response
	expiresAt := time.Now().Add(ttl)
	data := map[string]interface{}{
		"source":     cfg.Source,
		"project":    cfg.Project,
		"scope":      cfg.Scope,
		"ttl":        ttl.String(),
		"expires_at": expiresAt.Format(time.RFC3339),
		"env_file":   envFilePath,
		"var_count":  len(secrets),
	}

	output.Print(output.Success(
		commandName,
		data,
		output.Action{
			Description: "Verify env file contents",
			Command:     fmt.Sprintf("cat %s", envFilePath),
		},
		output.Action{
			Description: "Refresh secrets before TTL expires",
			Command:     "secrets env --force",
		},
		output.ActionScan(),
	))

	return nil
}

func init() {
	envCmd.Flags().BoolVar(&envForce, "force", false, "Overwrite existing env file")
	envCmd.Flags().StringVar(&envTTL, "ttl", "", "Override TTL from config (e.g., '1h', '30m')")
	envCmd.Flags().BoolVar(&envDryRun, "dry-run", false, "Show what would be written without leasing or writing")
}

// parseStoreTTL validates a TTL duration string used for leases.
func parseStoreTTL(ttl string) (time.Duration, error) {
	duration, err := time.ParseDuration(ttl)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %w", err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("duration must be positive")
	}
	if duration > project.MaxTTL {
		return 0, fmt.Errorf("duration exceeds maximum of 24h")
	}
	return duration, nil
}

// parseTTL determines the TTL to use (flag overrides config)
func parseTTL(cfg *project.ProjectConfig, flagTTL string) (time.Duration, error) {
	if flagTTL != "" {
		return parseStoreTTL(flagTTL)
	}
	// Use config TTL
	return cfg.ParseTTL()
}

// getVarNames returns a slice of environment variable names
func getVarNames(secrets map[string]string) []string {
	names := make([]string, 0, len(secrets))
	for name := range secrets {
		names = append(names, name)
	}
	return names
}

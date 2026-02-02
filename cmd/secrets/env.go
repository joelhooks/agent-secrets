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
	Short: "Sync project secrets to .env.local",
	Long: `Sync environment variables from a configured source to .env.local.

Reads .secrets.json from the current directory (or parent directories),
fetches secrets from the configured source (e.g., Vercel), and writes
them to .env.local with a time-to-live (TTL) expiration.

The .env.local file includes metadata headers for TTL tracking and
will automatically expire after the configured duration.

Examples:
  secrets env                           # Sync with config defaults
  secrets env --force                   # Overwrite existing .env.local
  secrets env --ttl 2h                  # Override TTL to 2 hours
  secrets env --dry-run                 # Preview without writing`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Find project configuration
		cfg, projectDir, err := project.FindProjectConfig()
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to find project config: %w", err)))
			return err
		}

		// Determine TTL (flag overrides config)
		ttl, err := parseTTL(cfg, envTTL)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("invalid TTL: %w", err)))
			return err
		}

		// Build env file path (relative to project directory)
		envFilePath := filepath.Join(projectDir, cfg.GetEnvFile())

		// Check if env file exists and handle --force
		if !envForce && !envDryRun {
			if _, err := os.Stat(envFilePath); err == nil {
				output.Print(output.ErrorMsg(
					fmt.Sprintf("env file already exists: %s (use --force to overwrite)", envFilePath),
					output.Action{
						Name:        "force_sync",
						Description: "Overwrite existing env file",
						Command:     "secrets env --force",
					},
					output.Action{
						Name:        "check_expiry",
						Description: "Check if env file is expired",
						Command:     fmt.Sprintf("cat %s | grep 'secrets-ttl'", envFilePath),
					},
				))
				return fmt.Errorf("env file exists")
			}
		}

		// Get adapter based on source
		adapter, err := getAdapter(cfg.Source)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to get adapter: %w", err)))
			return err
		}

		// Pull secrets from source
		secrets, err := adapter.Pull(cfg.Project, cfg.Scope)
		if err != nil {
			output.Print(output.Error(fmt.Errorf("failed to pull secrets: %w", err)))
			return err
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
				output.Print(output.Error(fmt.Errorf("missing required vars: %v", missingVars)))
				return fmt.Errorf("required vars missing")
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
				fmt.Sprintf("Would sync %d vars from %s (dry-run)", len(secrets), cfg.Source),
				data,
				output.Action{
					Name:        "sync",
					Description: "Run sync without --dry-run",
					Command:     "secrets env",
				},
			))
			return nil
		}

		// Write to env file with TTL
		if err := envfile.WriteWithTTL(envFilePath, secrets, ttl, cfg.Source); err != nil {
			output.Print(output.Error(fmt.Errorf("failed to write env file: %w", err)))
			return err
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
			fmt.Sprintf("Synced %d environment variables to %s", len(secrets), envFilePath),
			data,
			output.Action{
				Name:        "verify",
				Description: "Verify env file contents",
				Command:     fmt.Sprintf("cat %s", envFilePath),
			},
			output.Action{
				Name:        "refresh",
				Description: "Refresh secrets before TTL expires",
				Command:     "secrets env --force",
			},
			output.ActionScan(),
		))

		return nil
	},
}

func init() {
	envCmd.Flags().BoolVar(&envForce, "force", false, "Overwrite existing .env.local file")
	envCmd.Flags().StringVar(&envTTL, "ttl", "", "Override TTL from config (e.g., '1h', '30m')")
	envCmd.Flags().BoolVar(&envDryRun, "dry-run", false, "Show what would be fetched without writing")
}

// parseTTL determines the TTL to use (flag overrides config)
func parseTTL(cfg *project.ProjectConfig, flagTTL string) (time.Duration, error) {
	if flagTTL != "" {
		// Parse and validate flag TTL
		duration, err := time.ParseDuration(flagTTL)
		if err != nil {
			return 0, fmt.Errorf("invalid duration format: %w", err)
		}
		if duration <= 0 {
			return 0, fmt.Errorf("duration must be positive")
		}
		// Enforce max limit
		maxTTL := 24 * time.Hour
		if duration > maxTTL {
			return 0, fmt.Errorf("duration exceeds maximum of 24h")
		}
		return duration, nil
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

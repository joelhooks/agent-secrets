// Package project handles project-specific configuration for .secrets.json files.
package project

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultProjectConfigFile is the project-local config filename.
	DefaultProjectConfigFile = ".secrets.json"
	// DefaultEnvFile is the default output filename for provider-backed ("source")
	// configurations.
	DefaultEnvFile = ".env.local"
	// DefaultStoreEnvFile is the default output filename for store-backed
	// configurations, matching the documented `secrets env` behaviour.
	DefaultStoreEnvFile = ".env"
	// MaxTTL is the maximum allowed TTL for any lease.
	MaxTTL = 24 * time.Hour
)

// SecretMapping maps a secret in the local agent-secrets store to an
// environment variable name.
type SecretMapping struct {
	// Name is the secret name as stored by `secrets add`.
	Name string `json:"name"`
	// EnvVar is the environment variable name written to the env file.
	EnvVar string `json:"env_var"`
	// TTL optionally overrides the default lease TTL for this secret.
	TTL string `json:"ttl,omitempty"`
}

// ProjectConfig represents the schema for .secrets.json.
//
// Two shapes are supported:
//
// Store-backed - secrets are leased from the local agent-secrets store:
//
//	{"secrets": [{"name": "github_token", "env_var": "GITHUB_TOKEN"}], "client_id": "deploy"}
//
// Provider-backed - secrets are pulled from an external source (e.g. Vercel):
//
//	{"source": "vercel", "project": "my-app", "scope": "development", "ttl": "1h"}
//
// A configuration with a non-empty "secrets" array is treated as store-backed;
// otherwise it must specify a valid "source".
type ProjectConfig struct {
	// Secrets lists store-backed secret to env var mappings. When set, the
	// source/project/scope fields are not required.
	Secrets []SecretMapping `json:"secrets,omitempty"`

	// ClientID is an optional audit-trail identifier for store-backed leases.
	ClientID string `json:"client_id,omitempty"`

	// Source is the credential provider ("vercel", "doppler", etc).
	Source string `json:"source"`

	// Project is the source-specific project identifier.
	// For Vercel: the project slug.
	// For Doppler: the project name.
	Project string `json:"project"`

	// Scope is the environment scope ("development", "preview", "production").
	Scope string `json:"scope"`

	// TTL is the time-to-live duration string (e.g., "1h", "30m").
	TTL string `json:"ttl"`

	// RequiredVars is an optional list of required environment variable names.
	// If specified, sync will fail if any of these are missing from the source.
	RequiredVars []string `json:"required_vars,omitempty"`

	// EnvFile is the output filename for environment variables.
	// Defaults to ".env.local" if not specified.
	EnvFile string `json:"env_file,omitempty"`
}

// ConfigError represents a configuration validation error.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("project config: %s %s", e.Field, e.Message)
}

// IsStoreBacked reports whether the configuration leases secrets from the local
// store, as opposed to pulling them from an external provider.
func (c *ProjectConfig) IsStoreBacked() bool {
	return len(c.Secrets) > 0
}

// Validate checks if the configuration is valid. The validation rules depend on
// which shape the configuration uses.
func (c *ProjectConfig) Validate() error {
	if c.IsStoreBacked() {
		return c.validateStoreBacked()
	}
	return c.validateSourceBacked()
}

// validateStoreBacked validates the store-backed shape ({"secrets": [...]}).
func (c *ProjectConfig) validateStoreBacked() error {
	seen := make(map[string]bool, len(c.Secrets))
	for i, s := range c.Secrets {
		if s.Name == "" {
			return &ConfigError{Field: fmt.Sprintf("secrets[%d].name", i), Message: "cannot be empty"}
		}
		if s.EnvVar == "" {
			return &ConfigError{Field: fmt.Sprintf("secrets[%d].env_var", i), Message: "cannot be empty"}
		}
		if seen[s.EnvVar] {
			return &ConfigError{
				Field:   fmt.Sprintf("secrets[%d].env_var", i),
				Message: fmt.Sprintf("duplicate env var %q", s.EnvVar),
			}
		}
		seen[s.EnvVar] = true

		if s.TTL != "" {
			if _, err := parseTTLValue(s.TTL); err != nil {
				return &ConfigError{Field: fmt.Sprintf("secrets[%d].ttl", i), Message: err.Error()}
			}
		}
	}

	if c.TTL != "" {
		if _, err := parseTTLValue(c.TTL); err != nil {
			return &ConfigError{Field: "ttl", Message: err.Error()}
		}
	}

	return nil
}

// validateSourceBacked validates the provider-backed shape.
func (c *ProjectConfig) validateSourceBacked() error {
	if c.Source == "" {
		return &ConfigError{
			Field:   "source",
			Message: "cannot be empty (or provide a non-empty \"secrets\" array)",
		}
	}

	// Validate known sources
	validSources := map[string]bool{
		"vercel":  true,
		"doppler": true,
	}
	if !validSources[c.Source] {
		return &ConfigError{
			Field:   "source",
			Message: fmt.Sprintf("must be one of: vercel, doppler (got %q)", c.Source),
		}
	}

	if c.Project == "" {
		return &ConfigError{Field: "project", Message: "cannot be empty"}
	}

	if c.Scope == "" {
		return &ConfigError{Field: "scope", Message: "cannot be empty"}
	}

	// Validate known scopes
	validScopes := map[string]bool{
		"development": true,
		"preview":     true,
		"production":  true,
	}
	if !validScopes[c.Scope] {
		return &ConfigError{
			Field:   "scope",
			Message: fmt.Sprintf("must be one of: development, preview, production (got %q)", c.Scope),
		}
	}

	if c.TTL == "" {
		return &ConfigError{Field: "ttl", Message: "cannot be empty"}
	}

	// Validate TTL format
	if _, err := c.ParseTTL(); err != nil {
		return &ConfigError{Field: "ttl", Message: err.Error()}
	}

	return nil
}

// ParseTTL parses the TTL string into a time.Duration.
func (c *ProjectConfig) ParseTTL() (time.Duration, error) {
	return parseTTLValue(c.TTL)
}

// parseTTLValue parses and validates a TTL duration string.
func parseTTLValue(ttl string) (time.Duration, error) {
	duration, err := time.ParseDuration(ttl)
	if err != nil {
		return 0, fmt.Errorf("invalid duration format: %w", err)
	}

	if duration <= 0 {
		return 0, fmt.Errorf("must be positive")
	}

	// Enforce reasonable limits (max 24 hours)
	if duration > MaxTTL {
		return 0, fmt.Errorf("exceeds maximum of 24h")
	}

	return duration, nil
}

// GetEnvFile returns the output env file path, using the mode-appropriate
// default if not specified.
func (c *ProjectConfig) GetEnvFile() string {
	if c.EnvFile != "" {
		return c.EnvFile
	}
	if c.IsStoreBacked() {
		return DefaultStoreEnvFile
	}
	return DefaultEnvFile
}

// ResolveTTL returns the lease TTL for a store-backed entry, falling back to the
// config-level TTL and finally to fallback.
func (c *ProjectConfig) ResolveTTL(entryTTL, fallback string) string {
	if entryTTL != "" {
		return entryTTL
	}
	if c.TTL != "" {
		return c.TTL
	}
	return fallback
}

// GetClientID returns the configured audit client ID, or fallback if unset.
func (c *ProjectConfig) GetClientID(fallback string) string {
	if c.ClientID != "" {
		return c.ClientID
	}
	return fallback
}

// Load reads a ProjectConfig from the specified path.
func Load(path string) (*ProjectConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg ProjectConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// FindProjectConfig walks up the directory tree from the current working directory
// looking for a .secrets.json file. Returns the config and the directory path where
// it was found, or an error if not found.
func FindProjectConfig() (*ProjectConfig, string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get working directory: %w", err)
	}

	dir := cwd
	for {
		configPath := filepath.Join(dir, DefaultProjectConfigFile)
		if _, err := os.Stat(configPath); err == nil {
			// Found it
			cfg, err := Load(configPath)
			if err != nil {
				return nil, "", err
			}
			return cfg, dir, nil
		}

		// Move up one directory
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
	}

	return nil, "", fmt.Errorf("no %s found in current directory or any parent", DefaultProjectConfigFile)
}

// Save writes the configuration to disk at the specified path.
func (c *ProjectConfig) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write with secure permissions (0644 is fine for project config)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

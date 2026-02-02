// Package config handles configuration for the agent-secrets daemon.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/joelhooks/agent-secrets/internal/types"
)

const (
	// DefaultDir is the default directory for agent-secrets data.
	DefaultDir = ".agent-secrets"
	// DefaultSocket is the default socket filename.
	DefaultSocket = "agent-secrets.sock"
	// DefaultIdentityFile is the default age identity filename.
	DefaultIdentityFile = "identity.age"
	// DefaultSecretsFile is the default encrypted secrets filename.
	DefaultSecretsFile = "secrets.age"
	// DefaultAuditFile is the default audit log filename.
	DefaultAuditFile = "audit.log"
	// DefaultConfigFile is the default config filename.
	DefaultConfigFile = "config.json"
	// DefaultLeasesFile is the default leases persistence filename.
	DefaultLeasesFile = "leases.json"
)

// Config holds the daemon configuration.
type Config struct {
	// Directory is the base directory for all agent-secrets files.
	Directory string `json:"directory"`

	// SocketPath is the full path to the Unix socket.
	SocketPath string `json:"socket_path"`

	// IdentityPath is the full path to the age identity file.
	IdentityPath string `json:"identity_path"`

	// SecretsPath is the full path to the encrypted secrets file.
	SecretsPath string `json:"secrets_path"`

	// AuditPath is the full path to the audit log.
	AuditPath string `json:"audit_path"`

	// LeasesPath is the full path to the leases persistence file.
	LeasesPath string `json:"leases_path"`

	// DefaultLeaseTTL is the default TTL for leases if not specified.
	DefaultLeaseTTL time.Duration `json:"default_lease_ttl"`

	// MaxLeaseTTL is the maximum allowed TTL for leases.
	MaxLeaseTTL time.Duration `json:"max_lease_ttl"`

	// RotationTimeout is the max time allowed for rotation hooks.
	RotationTimeout time.Duration `json:"rotation_timeout"`

	// Heartbeat configuration for optional remote monitoring.
	Heartbeat *types.HeartbeatConfig `json:"heartbeat,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	baseDir := filepath.Join(homeDir, DefaultDir)

	return &Config{
		Directory:       baseDir,
		SocketPath:      filepath.Join(baseDir, DefaultSocket),
		IdentityPath:    filepath.Join(baseDir, DefaultIdentityFile),
		SecretsPath:     filepath.Join(baseDir, DefaultSecretsFile),
		AuditPath:       filepath.Join(baseDir, DefaultAuditFile),
		LeasesPath:      filepath.Join(baseDir, DefaultLeasesFile),
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}
}

// Load reads configuration from the config file in the default directory.
func Load() (*Config, error) {
	cfg := DefaultConfig()
	configPath := filepath.Join(cfg.Directory, DefaultConfigFile)

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file, use defaults
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadFrom reads configuration from a specific path.
func LoadFrom(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save writes the configuration to disk.
func (c *Config) Save() error {
	if err := os.MkdirAll(c.Directory, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	configPath := filepath.Join(c.Directory, DefaultConfigFile)
	return os.WriteFile(configPath, data, 0600)
}

// EnsureDirectories creates all required directories with secure permissions.
func (c *Config) EnsureDirectories() error {
	return os.MkdirAll(c.Directory, 0700)
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Directory == "" {
		return &ConfigError{Field: "directory", Message: "cannot be empty"}
	}
	if c.DefaultLeaseTTL <= 0 {
		return &ConfigError{Field: "default_lease_ttl", Message: "must be positive"}
	}
	if c.MaxLeaseTTL < c.DefaultLeaseTTL {
		return &ConfigError{Field: "max_lease_ttl", Message: "must be >= default_lease_ttl"}
	}
	if c.RotationTimeout <= 0 {
		return &ConfigError{Field: "rotation_timeout", Message: "must be positive"}
	}

	if c.Heartbeat != nil && c.Heartbeat.Enabled {
		if c.Heartbeat.URL == "" {
			return &ConfigError{Field: "heartbeat.url", Message: "required when heartbeat enabled"}
		}
		if c.Heartbeat.Interval <= 0 {
			return &ConfigError{Field: "heartbeat.interval", Message: "must be positive"}
		}
		if c.Heartbeat.Timeout <= 0 {
			return &ConfigError{Field: "heartbeat.timeout", Message: "must be positive"}
		}
	}

	return nil
}

// ConfigError represents a configuration validation error.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return "config: " + e.Field + " " + e.Message
}

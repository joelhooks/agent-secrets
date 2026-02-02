package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Directory == "" {
		t.Error("Directory should not be empty")
	}
	if cfg.DefaultLeaseTTL != 1*time.Hour {
		t.Errorf("DefaultLeaseTTL = %v, want 1h", cfg.DefaultLeaseTTL)
	}
	if cfg.MaxLeaseTTL != 24*time.Hour {
		t.Errorf("MaxLeaseTTL = %v, want 24h", cfg.MaxLeaseTTL)
	}
	if cfg.RotationTimeout != 30*time.Second {
		t.Errorf("RotationTimeout = %v, want 30s", cfg.RotationTimeout)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid default config",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name:    "empty directory",
			modify:  func(c *Config) { c.Directory = "" },
			wantErr: true,
		},
		{
			name:    "zero default TTL",
			modify:  func(c *Config) { c.DefaultLeaseTTL = 0 },
			wantErr: true,
		},
		{
			name:    "max TTL less than default",
			modify:  func(c *Config) { c.MaxLeaseTTL = 30 * time.Minute },
			wantErr: true,
		},
		{
			name:    "zero rotation timeout",
			modify:  func(c *Config) { c.RotationTimeout = 0 },
			wantErr: true,
		},
		{
			name: "heartbeat enabled without URL",
			modify: func(c *Config) {
				c.Heartbeat = &types.HeartbeatConfig{
					Enabled:  true,
					Interval: time.Minute,
					Timeout:  10 * time.Second,
				}
			},
			wantErr: true,
		},
		{
			name: "valid heartbeat config",
			modify: func(c *Config) {
				c.Heartbeat = &types.HeartbeatConfig{
					Enabled:  true,
					URL:      "https://example.com/heartbeat",
					Interval: time.Minute,
					Timeout:  10 * time.Second,
				}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := DefaultConfig()
	cfg.Directory = tmpDir
	cfg.DefaultLeaseTTL = 2 * time.Hour
	cfg.MaxLeaseTTL = 48 * time.Hour

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Check file exists and has correct permissions
	configPath := filepath.Join(tmpDir, DefaultConfigFile)
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("config file not found: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("config file permissions = %v, want 0600", info.Mode().Perm())
	}

	// Load and verify
	loaded, err := LoadFrom(configPath)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	if loaded.DefaultLeaseTTL != cfg.DefaultLeaseTTL {
		t.Errorf("DefaultLeaseTTL = %v, want %v", loaded.DefaultLeaseTTL, cfg.DefaultLeaseTTL)
	}
	if loaded.MaxLeaseTTL != cfg.MaxLeaseTTL {
		t.Errorf("MaxLeaseTTL = %v, want %v", loaded.MaxLeaseTTL, cfg.MaxLeaseTTL)
	}
}

func TestLoadNonExistent(t *testing.T) {
	// Load should return defaults when config doesn't exist
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Should have default values
	if cfg.DefaultLeaseTTL != 1*time.Hour {
		t.Errorf("DefaultLeaseTTL = %v, want 1h", cfg.DefaultLeaseTTL)
	}
}

func TestEnsureDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "deeply", "nested", "dir")

	cfg := DefaultConfig()
	cfg.Directory = nestedDir

	if err := cfg.EnsureDirectories(); err != nil {
		t.Fatalf("EnsureDirectories() error = %v", err)
	}

	info, err := os.Stat(nestedDir)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("created path is not a directory")
	}
	if info.Mode().Perm() != 0700 {
		t.Errorf("directory permissions = %v, want 0700", info.Mode().Perm())
	}
}

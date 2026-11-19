package project

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoad_StoreBackedConfig covers the documented .secrets.json shape, which
// lists secrets to lease from the local store rather than naming an external
// provider. This is the shape that previously failed with
// "project config: source cannot be empty".
func TestLoad_StoreBackedConfig(t *testing.T) {
	content := `{
  "secrets": [
    {"name": "github_token", "env_var": "GITHUB_TOKEN"},
    {"name": "stripe_key", "env_var": "STRIPE_SECRET_KEY", "ttl": "30m"}
  ],
  "client_id": "deploy-task"
}`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, DefaultProjectConfigFile)
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() unexpected error = %v", err)
	}

	if !cfg.IsStoreBacked() {
		t.Error("IsStoreBacked() = false, want true")
	}
	if len(cfg.Secrets) != 2 {
		t.Fatalf("Secrets length = %d, want 2", len(cfg.Secrets))
	}
	if cfg.Secrets[0].Name != "github_token" {
		t.Errorf("Secrets[0].Name = %q, want %q", cfg.Secrets[0].Name, "github_token")
	}
	if cfg.Secrets[0].EnvVar != "GITHUB_TOKEN" {
		t.Errorf("Secrets[0].EnvVar = %q, want %q", cfg.Secrets[0].EnvVar, "GITHUB_TOKEN")
	}
	if cfg.Secrets[1].TTL != "30m" {
		t.Errorf("Secrets[1].TTL = %q, want %q", cfg.Secrets[1].TTL, "30m")
	}
	if cfg.ClientID != "deploy-task" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "deploy-task")
	}

	// Store-backed configs default to .env, matching the documented behaviour
	if got := cfg.GetEnvFile(); got != DefaultStoreEnvFile {
		t.Errorf("GetEnvFile() = %q, want %q", got, DefaultStoreEnvFile)
	}
	if DefaultStoreEnvFile != ".env" {
		t.Errorf("DefaultStoreEnvFile = %q, want %q", DefaultStoreEnvFile, ".env")
	}
}

func TestProjectConfig_ResolveTTL(t *testing.T) {
	tests := []struct {
		name     string
		config   ProjectConfig
		entryTTL string
		fallback string
		want     string
	}{
		{
			name:     "entry ttl wins",
			config:   ProjectConfig{TTL: "2h"},
			entryTTL: "30m",
			fallback: "1h",
			want:     "30m",
		},
		{
			name:     "config ttl used when entry empty",
			config:   ProjectConfig{TTL: "2h"},
			entryTTL: "",
			fallback: "1h",
			want:     "2h",
		},
		{
			name:     "fallback used when both empty",
			config:   ProjectConfig{},
			entryTTL: "",
			fallback: "1h",
			want:     "1h",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.ResolveTTL(tt.entryTTL, tt.fallback); got != tt.want {
				t.Errorf("ResolveTTL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProjectConfig_GetClientID(t *testing.T) {
	cfg := &ProjectConfig{ClientID: "configured"}
	if got := cfg.GetClientID("fallback"); got != "configured" {
		t.Errorf("GetClientID() = %q, want %q", got, "configured")
	}

	empty := &ProjectConfig{}
	if got := empty.GetClientID("fallback"); got != "fallback" {
		t.Errorf("GetClientID() = %q, want %q", got, "fallback")
	}
}

func TestValidate_StoreBackedErrors(t *testing.T) {
	tests := []struct {
		name   string
		config ProjectConfig
		errMsg string
	}{
		{
			name:   "missing secret name",
			config: ProjectConfig{Secrets: []SecretMapping{{EnvVar: "TOKEN"}}},
			errMsg: "secrets[0].name cannot be empty",
		},
		{
			name:   "missing env var",
			config: ProjectConfig{Secrets: []SecretMapping{{Name: "github_token"}}},
			errMsg: "secrets[0].env_var cannot be empty",
		},
		{
			name: "duplicate env var",
			config: ProjectConfig{Secrets: []SecretMapping{
				{Name: "one", EnvVar: "TOKEN"},
				{Name: "two", EnvVar: "TOKEN"},
			}},
			errMsg: `secrets[1].env_var duplicate env var "TOKEN"`,
		},
		{
			name: "invalid per-entry ttl",
			config: ProjectConfig{Secrets: []SecretMapping{
				{Name: "one", EnvVar: "TOKEN", TTL: "not-a-duration"},
			}},
			errMsg: "secrets[0].ttl invalid duration format",
		},
		{
			name: "per-entry ttl exceeds max",
			config: ProjectConfig{Secrets: []SecretMapping{
				{Name: "one", EnvVar: "TOKEN", TTL: "25h"},
			}},
			errMsg: "secrets[0].ttl exceeds maximum",
		},
		{
			name: "invalid config-level ttl",
			config: ProjectConfig{
				Secrets: []SecretMapping{{Name: "one", EnvVar: "TOKEN"}},
				TTL:     "nope",
			},
			errMsg: "ttl invalid duration format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err == nil {
				t.Fatalf("Validate() expected error containing %q, got nil", tt.errMsg)
			}
			if !contains(err.Error(), tt.errMsg) {
				t.Errorf("Validate() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

// TestValidate_StoreBackedValid ensures the store-backed shape does not require
// source/project/scope/ttl.
func TestValidate_StoreBackedValid(t *testing.T) {
	cfg := ProjectConfig{
		Secrets: []SecretMapping{
			{Name: "github_token", EnvVar: "GITHUB_TOKEN"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error = %v", err)
	}
}

// TestValidate_EmptyConfigReportsBothShapes guards the actionable error message
// when neither shape is satisfied.
func TestValidate_EmptyConfigReportsBothShapes(t *testing.T) {
	cfg := ProjectConfig{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error, got nil")
	}
	for _, want := range []string{"source cannot be empty", "secrets"} {
		if !contains(err.Error(), want) {
			t.Errorf("Validate() error = %v, want error containing %q", err, want)
		}
	}
}

// TestValidate_MaxTTLMatchesConstant keeps the exported ceiling in sync with the
// documented 24h maximum.
func TestValidate_MaxTTLMatchesConstant(t *testing.T) {
	if MaxTTL != 24*time.Hour {
		t.Errorf("MaxTTL = %v, want %v", MaxTTL, 24*time.Hour)
	}
}

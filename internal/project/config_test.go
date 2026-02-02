package project

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProjectConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ProjectConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid vercel config",
			config: ProjectConfig{
				Source:  "vercel",
				Project: "my-app",
				Scope:   "development",
				TTL:     "1h",
			},
			wantErr: false,
		},
		{
			name: "valid doppler config",
			config: ProjectConfig{
				Source:  "doppler",
				Project: "my-project",
				Scope:   "production",
				TTL:     "30m",
			},
			wantErr: false,
		},
		{
			name: "valid with required vars",
			config: ProjectConfig{
				Source:       "vercel",
				Project:      "my-app",
				Scope:        "preview",
				TTL:          "2h",
				RequiredVars: []string{"DATABASE_URL", "API_KEY"},
			},
			wantErr: false,
		},
		{
			name: "missing source",
			config: ProjectConfig{
				Project: "my-app",
				Scope:   "development",
				TTL:     "1h",
			},
			wantErr: true,
			errMsg:  "source cannot be empty",
		},
		{
			name: "invalid source",
			config: ProjectConfig{
				Source:  "aws",
				Project: "my-app",
				Scope:   "development",
				TTL:     "1h",
			},
			wantErr: true,
			errMsg:  "source must be one of",
		},
		{
			name: "missing project",
			config: ProjectConfig{
				Source: "vercel",
				Scope:  "development",
				TTL:    "1h",
			},
			wantErr: true,
			errMsg:  "project cannot be empty",
		},
		{
			name: "missing scope",
			config: ProjectConfig{
				Source:  "vercel",
				Project: "my-app",
				TTL:     "1h",
			},
			wantErr: true,
			errMsg:  "scope cannot be empty",
		},
		{
			name: "invalid scope",
			config: ProjectConfig{
				Source:  "vercel",
				Project: "my-app",
				Scope:   "staging",
				TTL:     "1h",
			},
			wantErr: true,
			errMsg:  "scope must be one of",
		},
		{
			name: "missing ttl",
			config: ProjectConfig{
				Source:  "vercel",
				Project: "my-app",
				Scope:   "development",
			},
			wantErr: true,
			errMsg:  "ttl cannot be empty",
		},
		{
			name: "invalid ttl format",
			config: ProjectConfig{
				Source:  "vercel",
				Project: "my-app",
				Scope:   "development",
				TTL:     "invalid",
			},
			wantErr: true,
			errMsg:  "ttl invalid duration format",
		},
		{
			name: "negative ttl",
			config: ProjectConfig{
				Source:  "vercel",
				Project: "my-app",
				Scope:   "development",
				TTL:     "-1h",
			},
			wantErr: true,
			errMsg:  "ttl must be positive",
		},
		{
			name: "ttl exceeds max",
			config: ProjectConfig{
				Source:  "vercel",
				Project: "my-app",
				Scope:   "development",
				TTL:     "25h",
			},
			wantErr: true,
			errMsg:  "ttl exceeds maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestProjectConfig_ParseTTL(t *testing.T) {
	tests := []struct {
		name     string
		ttl      string
		want     time.Duration
		wantErr  bool
		errMsg   string
	}{
		{
			name: "1 hour",
			ttl:  "1h",
			want: time.Hour,
		},
		{
			name: "30 minutes",
			ttl:  "30m",
			want: 30 * time.Minute,
		},
		{
			name: "2 hours 30 minutes",
			ttl:  "2h30m",
			want: 2*time.Hour + 30*time.Minute,
		},
		{
			name: "90 seconds",
			ttl:  "90s",
			want: 90 * time.Second,
		},
		{
			name:    "invalid format",
			ttl:     "invalid",
			wantErr: true,
			errMsg:  "invalid duration format",
		},
		{
			name:    "negative duration",
			ttl:     "-1h",
			wantErr: true,
			errMsg:  "must be positive",
		},
		{
			name:    "zero duration",
			ttl:     "0s",
			wantErr: true,
			errMsg:  "must be positive",
		},
		{
			name:    "exceeds max",
			ttl:     "25h",
			wantErr: true,
			errMsg:  "exceeds maximum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ProjectConfig{TTL: tt.ttl}
			got, err := cfg.ParseTTL()
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseTTL() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("ParseTTL() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ParseTTL() unexpected error = %v", err)
					return
				}
				if got != tt.want {
					t.Errorf("ParseTTL() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestProjectConfig_GetEnvFile(t *testing.T) {
	tests := []struct {
		name    string
		envFile string
		want    string
	}{
		{
			name:    "default",
			envFile: "",
			want:    DefaultEnvFile,
		},
		{
			name:    "custom",
			envFile: ".env.development",
			want:    ".env.development",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ProjectConfig{EnvFile: tt.envFile}
			if got := cfg.GetEnvFile(); got != tt.want {
				t.Errorf("GetEnvFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
		errMsg  string
		check   func(*testing.T, *ProjectConfig)
	}{
		{
			name: "valid config",
			content: `{
  "source": "vercel",
  "project": "my-app",
  "scope": "development",
  "ttl": "1h"
}`,
			wantErr: false,
			check: func(t *testing.T, cfg *ProjectConfig) {
				if cfg.Source != "vercel" {
					t.Errorf("Source = %q, want %q", cfg.Source, "vercel")
				}
				if cfg.Project != "my-app" {
					t.Errorf("Project = %q, want %q", cfg.Project, "my-app")
				}
				if cfg.Scope != "development" {
					t.Errorf("Scope = %q, want %q", cfg.Scope, "development")
				}
				if cfg.TTL != "1h" {
					t.Errorf("TTL = %q, want %q", cfg.TTL, "1h")
				}
			},
		},
		{
			name: "with optional fields",
			content: `{
  "source": "doppler",
  "project": "backend",
  "scope": "production",
  "ttl": "30m",
  "required_vars": ["DATABASE_URL", "API_KEY"],
  "env_file": ".env.production"
}`,
			wantErr: false,
			check: func(t *testing.T, cfg *ProjectConfig) {
				if len(cfg.RequiredVars) != 2 {
					t.Errorf("RequiredVars length = %d, want 2", len(cfg.RequiredVars))
				}
				if cfg.EnvFile != ".env.production" {
					t.Errorf("EnvFile = %q, want %q", cfg.EnvFile, ".env.production")
				}
			},
		},
		{
			name:    "invalid json",
			content: `{invalid json}`,
			wantErr: true,
			errMsg:  "failed to parse",
		},
		{
			name: "invalid config",
			content: `{
  "source": "invalid",
  "project": "my-app",
  "scope": "development",
  "ttl": "1h"
}`,
			wantErr: true,
			errMsg:  "source must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, DefaultProjectConfigFile)

			if err := os.WriteFile(configPath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to write test config: %v", err)
			}

			cfg, err := Load(configPath)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Load() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Load() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Load() unexpected error = %v", err)
					return
				}
				if tt.check != nil {
					tt.check(t, cfg)
				}
			}
		})
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/.secrets.json")
	if err == nil {
		t.Error("Load() expected error for nonexistent file, got nil")
	}
	if !contains(err.Error(), "failed to read") {
		t.Errorf("Load() error = %v, want error containing 'failed to read'", err)
	}
}

func TestFindProjectConfig(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(t *testing.T) (string, string) // Returns tmpDir and startDir
		wantErr  bool
		errMsg   string
		checkDir func(t *testing.T, foundDir, expectedDir string)
	}{
		{
			name: "config in current directory",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, DefaultProjectConfigFile)
				writeValidConfig(t, configPath)
				return tmpDir, tmpDir
			},
			wantErr: false,
			checkDir: func(t *testing.T, foundDir, expectedDir string) {
				if foundDir != expectedDir {
					t.Errorf("Found in %q, want %q", foundDir, expectedDir)
				}
			},
		},
		{
			name: "config in parent directory",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, DefaultProjectConfigFile)
				writeValidConfig(t, configPath)

				// Create subdirectory
				subDir := filepath.Join(tmpDir, "subdir")
				if err := os.Mkdir(subDir, 0755); err != nil {
					t.Fatalf("failed to create subdir: %v", err)
				}
				return tmpDir, subDir
			},
			wantErr: false,
			checkDir: func(t *testing.T, foundDir, expectedDir string) {
				if foundDir != expectedDir {
					t.Errorf("Found in %q, want %q", foundDir, expectedDir)
				}
			},
		},
		{
			name: "config in grandparent directory",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				configPath := filepath.Join(tmpDir, DefaultProjectConfigFile)
				writeValidConfig(t, configPath)

				// Create nested subdirectories
				subDir := filepath.Join(tmpDir, "level1", "level2")
				if err := os.MkdirAll(subDir, 0755); err != nil {
					t.Fatalf("failed to create nested dirs: %v", err)
				}
				return tmpDir, subDir
			},
			wantErr: false,
			checkDir: func(t *testing.T, foundDir, expectedDir string) {
				if foundDir != expectedDir {
					t.Errorf("Found in %q, want %q", foundDir, expectedDir)
				}
			},
		},
		{
			name: "no config found",
			setup: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				return tmpDir, tmpDir
			},
			wantErr: true,
			errMsg:  "no .secrets.json found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectedDir, startDir := tt.setup(t)

			// Change to start directory
			origDir, err := os.Getwd()
			if err != nil {
				t.Fatalf("failed to get working dir: %v", err)
			}
			defer func() {
				if err := os.Chdir(origDir); err != nil {
					t.Errorf("failed to restore working dir: %v", err)
				}
			}()

			if err := os.Chdir(startDir); err != nil {
				t.Fatalf("failed to change to start dir: %v", err)
			}

			cfg, foundDir, err := FindProjectConfig()
			if tt.wantErr {
				if err == nil {
					t.Errorf("FindProjectConfig() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("FindProjectConfig() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("FindProjectConfig() unexpected error = %v", err)
					return
				}
				if cfg == nil {
					t.Error("FindProjectConfig() returned nil config")
					return
				}
				if tt.checkDir != nil {
					tt.checkDir(t, foundDir, expectedDir)
				}
			}
		})
	}
}

func TestProjectConfig_Save(t *testing.T) {
	tests := []struct {
		name    string
		config  ProjectConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: ProjectConfig{
				Source:  "vercel",
				Project: "my-app",
				Scope:   "development",
				TTL:     "1h",
			},
			wantErr: false,
		},
		{
			name: "invalid config",
			config: ProjectConfig{
				Source:  "invalid",
				Project: "my-app",
				Scope:   "development",
				TTL:     "1h",
			},
			wantErr: true,
			errMsg:  "source must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, DefaultProjectConfigFile)

			err := tt.config.Save(configPath)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Save() expected error containing %q, got nil", tt.errMsg)
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Save() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Save() unexpected error = %v", err)
					return
				}

				// Verify file was created and can be loaded
				if _, err := os.Stat(configPath); err != nil {
					t.Errorf("Save() did not create file: %v", err)
					return
				}

				// Load and verify
				loaded, err := Load(configPath)
				if err != nil {
					t.Errorf("Failed to load saved config: %v", err)
					return
				}

				if loaded.Source != tt.config.Source {
					t.Errorf("Loaded Source = %q, want %q", loaded.Source, tt.config.Source)
				}
				if loaded.Project != tt.config.Project {
					t.Errorf("Loaded Project = %q, want %q", loaded.Project, tt.config.Project)
				}
			}
		})
	}
}

func TestProjectConfig_Save_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedPath := filepath.Join(tmpDir, "nested", "dir", DefaultProjectConfigFile)

	cfg := ProjectConfig{
		Source:  "vercel",
		Project: "my-app",
		Scope:   "development",
		TTL:     "1h",
	}

	if err := cfg.Save(nestedPath); err != nil {
		t.Errorf("Save() unexpected error = %v", err)
		return
	}

	if _, err := os.Stat(nestedPath); err != nil {
		t.Errorf("Save() did not create nested file: %v", err)
	}
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func writeValidConfig(t *testing.T, path string) {
	t.Helper()
	content := `{
  "source": "vercel",
  "project": "test-project",
  "scope": "development",
  "ttl": "1h"
}`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
}

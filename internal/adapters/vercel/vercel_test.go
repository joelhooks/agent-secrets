package vercel

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestVercelAdapter_Name(t *testing.T) {
	adapter := New()
	if adapter.Name() != "vercel" {
		t.Errorf("expected name 'vercel', got %q", adapter.Name())
	}
}

func TestVercelAdapter_NewWithBinary(t *testing.T) {
	customPath := "/custom/path/to/vercel"
	adapter := NewWithBinary(customPath)
	if adapter.vercelBinary != customPath {
		t.Errorf("expected binary path %q, got %q", customPath, adapter.vercelBinary)
	}
}

func TestVercelAdapter_checkVercelCLI_NotFound(t *testing.T) {
	adapter := NewWithBinary("nonexistent-vercel-binary-12345")
	err := adapter.checkVercelCLI()
	if err == nil {
		t.Fatal("expected error when vercel CLI not found, got nil")
	}

	var adapterErr types.ErrAdapterNotAvailable
	if !errors.As(err, &adapterErr) {
		t.Errorf("expected ErrAdapterNotAvailable, got %T: %v", err, err)
	}
	if adapterErr.Adapter != "vercel" {
		t.Errorf("expected adapter 'vercel', got %q", adapterErr.Adapter)
	}
}

func TestParseEnvFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    map[string]string
		wantErr bool
	}{
		{
			name: "basic key-value pairs",
			content: `DATABASE_URL=postgresql://localhost/mydb
API_KEY=abc123
PORT=3000`,
			want: map[string]string{
				"DATABASE_URL": "postgresql://localhost/mydb",
				"API_KEY":      "abc123",
				"PORT":         "3000",
			},
			wantErr: false,
		},
		{
			name: "with double quotes",
			content: `NAME="My Application"
DESCRIPTION="A test app"`,
			want: map[string]string{
				"NAME":        "My Application",
				"DESCRIPTION": "A test app",
			},
			wantErr: false,
		},
		{
			name: "with single quotes",
			content: `PATH='/usr/local/bin'
HOME='/home/user'`,
			want: map[string]string{
				"PATH": "/usr/local/bin",
				"HOME": "/home/user",
			},
			wantErr: false,
		},
		{
			name: "with comments and empty lines",
			content: `# This is a comment
DATABASE_URL=postgresql://localhost/mydb

# Another comment
API_KEY=abc123

`,
			want: map[string]string{
				"DATABASE_URL": "postgresql://localhost/mydb",
				"API_KEY":      "abc123",
			},
			wantErr: false,
		},
		{
			name: "empty file",
			content: `
# Just comments
`,
			want:    map[string]string{},
			wantErr: false,
		},
		{
			name: "values with equals signs",
			content: `BASE64_TOKEN=dGVzdD0xMjM=
COMPLEX=key=value=pair`,
			want: map[string]string{
				"BASE64_TOKEN": "dGVzdD0xMjM=",
				"COMPLEX":      "key=value=pair",
			},
			wantErr: false,
		},
		{
			name:    "invalid format - no equals",
			content: `INVALID LINE WITHOUT EQUALS`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary file
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "test.env")
			if err := os.WriteFile(tmpFile, []byte(tt.content), 0600); err != nil {
				t.Fatalf("failed to write temp file: %v", err)
			}

			// Parse the file
			got, err := parseEnvFile(tmpFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseEnvFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("parseEnvFile() got %d entries, want %d", len(got), len(tt.want))
				}
				for k, v := range tt.want {
					if got[k] != v {
						t.Errorf("parseEnvFile() key %q: got %q, want %q", k, got[k], v)
					}
				}
			}
		})
	}
}

func TestUnquote(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`"quoted"`, "quoted"},
		{`'quoted'`, "quoted"},
		{`unquoted`, "unquoted"},
		{`"partial`, `"partial`},
		{`partial"`, `partial"`},
		{`""`, ""},
		{`''`, ""},
		{`"mixed'`, `"mixed'`},
		{`a`, "a"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := unquote(tt.input)
			if got != tt.want {
				t.Errorf("unquote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestVercelAdapter_Pull_InvalidScope(t *testing.T) {
	// Skip if vercel CLI not available
	adapter := New()
	if err := adapter.checkVercelCLI(); err != nil {
		t.Skip("vercel CLI not available, skipping test")
	}

	_, err := adapter.Pull("test-project", "invalid-scope")
	if err == nil {
		t.Fatal("expected error for invalid scope, got nil")
	}
	if !contains(err.Error(), "invalid scope") {
		t.Errorf("expected 'invalid scope' error, got: %v", err)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

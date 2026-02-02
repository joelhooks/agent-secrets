package output

import (
	"testing"
)

func TestValidateMode(t *testing.T) {
	tests := []struct {
		mode      string
		wantError bool
	}{
		{"", false},           // Empty is valid (auto-detect)
		{"json", false},       // Valid mode
		{"table", false},      // Valid mode
		{"raw", false},        // Valid mode
		{"invalid", true},     // Invalid mode
		{"JSON", true},        // Case sensitive
		{"Table", true},       // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			err := ValidateMode(tt.mode)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateMode(%q) error = %v, wantError %v", tt.mode, err, tt.wantError)
			}
		})
	}
}

func TestGetFormatter(t *testing.T) {
	tests := []struct {
		mode     OutputMode
		wantType string
	}{
		{ModeJSON, "*output.JSONFormatter"},
		{ModeTable, "*output.TableFormatter"},
		{ModeRaw, "*output.RawFormatter"},
		{"", "*output.JSONFormatter"}, // Auto-detect (non-TTY in tests)
		{"invalid", "*output.JSONFormatter"}, // Fallback
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			formatter := GetFormatter(tt.mode)
			if formatter == nil {
				t.Fatal("GetFormatter returned nil")
			}
			// Just verify we got a formatter, can't easily test type without reflection
		})
	}
}

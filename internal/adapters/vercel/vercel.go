// Package vercel provides an adapter for syncing secrets from Vercel projects.
package vercel

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/joelhooks/agent-secrets/internal/types"
)

// VercelAdapter implements the SourceAdapter interface for Vercel.
type VercelAdapter struct {
	// vercelBinary is the path to the vercel CLI binary.
	// If empty, "vercel" is assumed to be in PATH.
	vercelBinary string
}

// New creates a new VercelAdapter with default settings.
func New() *VercelAdapter {
	return &VercelAdapter{
		vercelBinary: "vercel",
	}
}

// NewWithBinary creates a new VercelAdapter with a custom vercel binary path.
func NewWithBinary(binaryPath string) *VercelAdapter {
	return &VercelAdapter{
		vercelBinary: binaryPath,
	}
}

// Name returns the name of the adapter.
func (v *VercelAdapter) Name() string {
	return "vercel"
}

// Pull retrieves environment variables from a Vercel project.
// project: the Vercel project name or ID
// scope: the environment scope (production, preview, development)
func (v *VercelAdapter) Pull(project, scope string) (map[string]string, error) {
	// Verify vercel CLI is available
	if err := v.checkVercelCLI(); err != nil {
		return nil, err
	}

	// Validate scope
	validScopes := map[string]bool{
		"production":  true,
		"preview":     true,
		"development": true,
	}
	if !validScopes[scope] {
		return nil, fmt.Errorf("invalid scope %q: must be one of production, preview, development", scope)
	}

	// Create a temporary file for the env output
	tmpFile, err := os.CreateTemp("", "vercel-env-*.env")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close() // Close it so vercel can write to it
	defer os.Remove(tmpPath)

	// Run vercel env pull
	// vercel env pull [file] --yes --environment <scope>
	cmd := exec.Command(
		v.vercelBinary,
		"env", "pull",
		tmpPath,
		"--yes",
		"--environment", scope,
	)

	// Set working directory to ensure we can resolve project context
	// (vercel CLI needs to be run in or reference a project directory)
	// For now, we'll let it use the current directory
	// TODO: Consider adding project path configuration

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("vercel env pull failed: %w (output: %s)", err, string(output))
	}

	// Parse the .env file
	secrets, err := parseEnvFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse env file: %w", err)
	}

	return secrets, nil
}

// checkVercelCLI verifies that the vercel CLI is available.
func (v *VercelAdapter) checkVercelCLI() error {
	path, err := exec.LookPath(v.vercelBinary)
	if err != nil {
		return types.ErrAdapterNotAvailable{
			Adapter: "vercel",
			Reason:  "vercel CLI not found in PATH",
		}
	}

	// Verify it's executable
	info, err := os.Stat(path)
	if err != nil {
		return types.ErrAdapterNotAvailable{
			Adapter: "vercel",
			Reason:  fmt.Sprintf("failed to stat vercel binary: %v", err),
		}
	}

	if info.IsDir() || info.Mode().Perm()&0111 == 0 {
		return types.ErrAdapterNotAvailable{
			Adapter: "vercel",
			Reason:  "vercel binary is not executable",
		}
	}

	return nil
}

// parseEnvFile reads a .env file and returns a map of key-value pairs.
// Format: KEY=value or KEY="value" or KEY='value'
func parseEnvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open env file: %w", err)
	}
	defer file.Close()

	secrets := make(map[string]string)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split on first '='
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid env line %d: %q (expected KEY=value)", lineNum, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		value = unquote(value)

		secrets[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading env file: %w", err)
	}

	return secrets, nil
}

// unquote removes surrounding single or double quotes from a string.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

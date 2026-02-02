//go:build integration

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestFullWorkflow tests the complete secrets workflow:
// init → create project config → env sync → scan → cleanup
func TestFullWorkflow(t *testing.T) {
	// Create temp directory for test
	tmpdir, err := os.MkdirTemp("", "secrets-integration-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	// Set HOME to temp dir so init creates store there
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpdir)
	defer os.Setenv("HOME", originalHome)

	binary := getBinaryPath(t)

	// Step 1: Initialize store
	t.Run("init", func(t *testing.T) {
		out := runCommand(t, binary, "init")
		if !strings.Contains(out, "success") {
			t.Errorf("init failed: %s", out)
		}

		// Verify store was created
		storePath := filepath.Join(tmpdir, ".agent-secrets")
		if _, err := os.Stat(storePath); os.IsNotExist(err) {
			t.Error("store directory not created")
		}
	})

	// Step 2: Create project directory with .secrets.json
	projectDir := filepath.Join(tmpdir, "test-project")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatal(err)
	}

	t.Run("create_project_config", func(t *testing.T) {
		config := map[string]interface{}{
			"source":  "vercel",
			"project": "test-project",
			"scope":   "development",
			"ttl":     "1h",
			"env_file": ".env.local",
		}
		data, _ := json.MarshalIndent(config, "", "  ")
		if err := os.WriteFile(filepath.Join(projectDir, ".secrets.json"), data, 0644); err != nil {
			t.Fatal(err)
		}
	})

	// Step 3: Test scan command (should work even without env vars)
	t.Run("scan_empty", func(t *testing.T) {
		// Create a file with a fake secret
		srcDir := filepath.Join(projectDir, "src")
		if err := os.MkdirAll(srcDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(srcDir, ".env.example"), []byte("API_KEY=test_key_value_12345"), 0644); err != nil {
			t.Fatal(err)
		}

		out := runCommandInDir(t, binary, projectDir, "scan", "--path", ".")
		if !strings.Contains(out, "scanned_files") {
			t.Errorf("scan output missing scanned_files: %s", out)
		}
	})

	// Step 4: Test status command
	t.Run("status", func(t *testing.T) {
		out := runCommand(t, binary, "status")
		// Should report daemon not running or store info
		if !strings.Contains(out, "success") && !strings.Contains(out, "error") {
			t.Errorf("unexpected status output: %s", out)
		}
	})
}

// TestScannerRecursive specifically tests the recursive scanning fix
func TestScannerRecursive(t *testing.T) {
	binary := getBinaryPath(t)

	tmpdir, err := os.MkdirTemp("", "secrets-scan-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	// Create nested directory structure
	dirs := []string{
		"src",
		"src/components",
		"src/components/auth",
		"lib",
		"node_modules/pkg", // should be excluded
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(tmpdir, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Create files with fake secrets
	files := map[string]string{
		"src/config.ts":               "const API_KEY = \"key_1234567890abcdef\"",
		"src/components/auth/login.ts": "PASSWORD=\"super_secret_password123\"",
		"lib/utils.ts":                 "TOKEN=\"tok_test_1234567890\"",
		"node_modules/pkg/index.js":   "SECRET=\"should_be_excluded\"",
		".env":                         "DB_PASSWORD=production_db_pass",
	}
	for path, content := range files {
		if err := os.WriteFile(filepath.Join(tmpdir, path), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	out := runCommandInDir(t, binary, tmpdir, "scan", "--path", ".")

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("failed to parse output: %v\nOutput: %s", err, out)
	}

	data := result["data"].(map[string]interface{})
	scannedFiles := int(data["scanned_files"].(float64))
	findings := data["findings"].([]interface{})

	// Should scan at least 4 files (not node_modules)
	if scannedFiles < 4 {
		t.Errorf("expected at least 4 files scanned, got %d", scannedFiles)
	}

	// Verify node_modules is excluded
	for _, f := range findings {
		finding := f.(map[string]interface{})
		file := finding["file"].(string)
		if strings.Contains(file, "node_modules") {
			t.Errorf("node_modules should be excluded, found: %s", file)
		}
	}
}

// TestCleanupExpired tests that cleanup removes expired .env files
func TestCleanupExpired(t *testing.T) {
	binary := getBinaryPath(t)

	tmpdir, err := os.MkdirTemp("", "secrets-cleanup-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	// Create an expired .env file (TTL in the past)
	expiredTime := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	content := "# secrets-managed: true\n" +
		"# secrets-ttl: " + expiredTime + "\n" +
		"# secrets-source: test\n" +
		"SECRET=value\n"

	envFile := filepath.Join(tmpdir, ".env.local")
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Run cleanup
	out := runCommandInDir(t, binary, tmpdir, "cleanup", "--path", tmpdir)

	// Verify cleanup reported success
	if !strings.Contains(out, "success") {
		t.Errorf("cleanup failed: %s", out)
	}

	// Verify file was removed
	if _, err := os.Stat(envFile); !os.IsNotExist(err) {
		t.Error("expired .env file should have been removed")
	}
}

// TestCleanupKeepsValid tests that cleanup keeps non-expired files
func TestCleanupKeepsValid(t *testing.T) {
	binary := getBinaryPath(t)

	tmpdir, err := os.MkdirTemp("", "secrets-valid-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	// Create a valid .env file (TTL in the future)
	futureTime := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	content := "# secrets-managed: true\n" +
		"# secrets-ttl: " + futureTime + "\n" +
		"# secrets-source: test\n" +
		"SECRET=value\n"

	envFile := filepath.Join(tmpdir, ".env.local")
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Run cleanup
	runCommandInDir(t, binary, tmpdir, "cleanup", "--path", tmpdir)

	// Verify file still exists
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		t.Error("valid .env file should NOT have been removed")
	}
}

// TestExclusionDoesNotMatchSubstrings tests the substring exclusion fix
func TestExclusionDoesNotMatchSubstrings(t *testing.T) {
	binary := getBinaryPath(t)

	tmpdir, err := os.MkdirTemp("", "secrets-exclude-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	// Create "course-builder" directory (contains "build" substring)
	builderDir := filepath.Join(tmpdir, "course-builder", "apps", "main", "src")
	if err := os.MkdirAll(builderDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(builderDir, "config.ts"), []byte("API_KEY=test123456789"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create actual "build" directory (should be excluded)
	buildDir := filepath.Join(tmpdir, "build")
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(buildDir, "output.js"), []byte("API_KEY=shouldbeexcluded"), 0644); err != nil {
		t.Fatal(err)
	}

	out := runCommandInDir(t, binary, tmpdir, "scan", "--path", ".")

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	data := result["data"].(map[string]interface{})
	scannedFiles := int(data["scanned_files"].(float64))

	// Should scan the course-builder file but not the build directory file
	if scannedFiles != 1 {
		t.Errorf("expected 1 file scanned (course-builder, not build), got %d", scannedFiles)
	}
}

// Helper functions

func getBinaryPath(t *testing.T) string {
	t.Helper()

	// Try local build first
	local := "./secrets"
	if _, err := os.Stat(local); err == nil {
		abs, _ := filepath.Abs(local)
		return abs
	}

	// Try go build
	tmpBin := filepath.Join(os.TempDir(), "secrets-test-binary")
	cmd := exec.Command("go", "build", "-o", tmpBin, "./cmd/secrets/")
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build binary: %v", err)
	}
	return tmpBin
}

func runCommand(t *testing.T, binary string, args ...string) string {
	t.Helper()
	cmd := exec.Command(binary, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Don't fail on errors - some commands may report errors in JSON
		t.Logf("command returned error: %v", err)
	}
	return string(out)
}

func runCommandInDir(t *testing.T, binary, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("command returned error: %v", err)
	}
	return string(out)
}

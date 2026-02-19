//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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
	_ = os.Setenv("HOME", tmpdir)
	defer os.Setenv("HOME", originalHome)

	binary := getBinaryPath(t)

	// Step 1: Initialize store
	t.Run("init", func(t *testing.T) {
		out := runCommand(t, binary, "--no-update-check", "init")
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
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("create_project_config", func(t *testing.T) {
		config := map[string]interface{}{
			"source":   "vercel",
			"project":  "test-project",
			"scope":    "development",
			"ttl":      "1h",
			"env_file": ".env.local",
		}
		data, _ := json.MarshalIndent(config, "", "  ")
		if err := os.WriteFile(filepath.Join(projectDir, ".secrets.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	})

	// Step 3: Test scan command (should work even without env vars)
	t.Run("scan_empty", func(t *testing.T) {
		// Create a file with a fake secret
		srcDir := filepath.Join(projectDir, "src")
		if err := os.MkdirAll(srcDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(srcDir, ".env.example"), []byte("API_KEY=test_key_value_12345"), 0o644); err != nil {
			t.Fatal(err)
		}

		out := runCommandInDir(t, binary, projectDir, "--no-update-check", "scan", "--path", ".")
		if !strings.Contains(out, "scanned_files") {
			t.Errorf("scan output missing scanned_files: %s", out)
		}
	})

	// Step 4: Test status command
	t.Run("status", func(t *testing.T) {
		out := runCommand(t, binary, "--no-update-check", "status")
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
		if err := os.MkdirAll(filepath.Join(tmpdir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Create files with fake secrets
	files := map[string]string{
		"src/config.ts":                "const API_KEY = \"key_1234567890abcdef\"",
		"src/components/auth/login.ts": "PASSWORD=\"super_secret_password123\"",
		"lib/utils.ts":                 "TOKEN=\"tok_test_1234567890\"",
		"node_modules/pkg/index.js":    "SECRET=\"should_be_excluded\"",
		".env":                         "DB_PASSWORD=production_db_pass",
	}
	for path, content := range files {
		if err := os.WriteFile(filepath.Join(tmpdir, path), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	out := runCommandInDir(t, binary, tmpdir, "--no-update-check", "scan", "--path", ".")

	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatalf("failed to parse output: %v\nOutput: %s", err, out)
	}

	resultData := mustMap(t, envelope["result"], "scan result")
	scannedFiles := mustNumber(t, resultData["scanned_files"], "scanned_files")
	findings := mustSlice(t, resultData["findings"], "findings")

	// Should scan at least 4 files (not node_modules)
	if scannedFiles < 4 {
		t.Errorf("expected at least 4 files scanned, got %d", scannedFiles)
	}

	// Verify node_modules is excluded
	for _, f := range findings {
		finding := mustMap(t, f, "finding")
		file := mustString(t, finding["file"], "finding.file")
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
	if err := os.WriteFile(envFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run cleanup
	out := runCommandInDir(t, binary, tmpdir, "--no-update-check", "cleanup", "--path", tmpdir)

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
	if err := os.WriteFile(envFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run cleanup
	runCommandInDir(t, binary, tmpdir, "--no-update-check", "cleanup", "--path", tmpdir)

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
	if err := os.MkdirAll(builderDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(builderDir, "config.ts"), []byte("API_KEY=test123456789"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create actual "build" directory (should be excluded)
	buildDir := filepath.Join(tmpdir, "build")
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(buildDir, "output.js"), []byte("API_KEY=shouldbeexcluded"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := runCommandInDir(t, binary, tmpdir, "--no-update-check", "scan", "--path", ".")

	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	resultData := mustMap(t, envelope["result"], "scan result")
	scannedFiles := mustNumber(t, resultData["scanned_files"], "scanned_files")

	// Should scan the course-builder file but not the build directory file
	if scannedFiles != 1 {
		t.Errorf("expected 1 file scanned (course-builder, not build), got %d", scannedFiles)
	}
}

func TestAgentWorkflow(t *testing.T) {
	tmpHome := setupTempHome(t)
	binary := getBinaryPath(t)

	initOut := runCommand(t, binary, "--no-update-check", "init")
	initEnvelope := parseEnvelope(t, initOut)
	assertSuccessEnvelope(t, initEnvelope)

	storePath := filepath.Join(tmpHome, ".agent-secrets")
	if _, err := os.Stat(storePath); err != nil {
		t.Fatalf("expected initialized store at %s: %v", storePath, err)
	}

	daemon := startDaemon(t, binary)
	defer daemon.stop(t)

	rootOut := runCommand(t, binary, "--no-update-check")
	rootEnvelope := parseEnvelope(t, rootOut)
	assertSuccessEnvelope(t, rootEnvelope)
	rootResult := mustMap(t, rootEnvelope["result"], "root result")
	rootCommands := mustSlice(t, rootResult["commands"], "root commands")

	expectedCommands := []string{
		"init", "add", "list", "update", "delete", "lease", "revoke", "status", "health",
		"audit", "scan", "env", "exec", "cleanup", "serve", "self-update",
	}
	for _, expected := range expectedCommands {
		if !commandExists(rootCommands, expected) {
			t.Fatalf("root output missing command %q: %s", expected, rootOut)
		}
	}

	assertSuccessEnvelope(t, parseEnvelope(t, runCommand(t, binary, "--no-update-check", "add", "test_key", "--value", "sk-test123")))
	assertSuccessEnvelope(t, parseEnvelope(t, runCommand(t, binary, "--no-update-check", "add", "another_key", "--value", "val2")))

	listEnvelope := parseEnvelope(t, runCommand(t, binary, "--no-update-check", "list"))
	assertSuccessEnvelope(t, listEnvelope)
	assertSecretNames(t, listEnvelope, []string{"another_key", "test_key"})

	rawLease := runCommand(t, binary, "--no-update-check", "lease", "test_key")
	if rawLease != "sk-test123" {
		t.Fatalf("expected raw lease value sk-test123, got %q", rawLease)
	}

	leaseEnvelope := parseEnvelope(t, runCommand(t, binary, "--no-update-check", "lease", "test_key", "--json"))
	assertSuccessEnvelope(t, leaseEnvelope)
	leaseResult := mustMap(t, leaseEnvelope["result"], "lease result")
	if mustString(t, leaseResult["value"], "lease result.value") != "sk-test123" {
		t.Fatalf("expected lease --json to include value sk-test123: %#v", leaseResult)
	}
	if strings.TrimSpace(mustString(t, leaseResult["lease_id"], "lease result.lease_id")) == "" {
		t.Fatalf("expected non-empty lease_id in lease result: %#v", leaseResult)
	}
	assertNextActionsShape(t, leaseEnvelope)

	assertSuccessEnvelope(t, parseEnvelope(t, runCommand(t, binary, "--no-update-check", "update", "test_key", "--value", "sk-updated")))

	rawUpdatedLease := runCommand(t, binary, "--no-update-check", "lease", "test_key")
	if rawUpdatedLease != "sk-updated" {
		t.Fatalf("expected updated raw lease value sk-updated, got %q", rawUpdatedLease)
	}

	assertSuccessEnvelope(t, parseEnvelope(t, runCommand(t, binary, "--no-update-check", "delete", "another_key", "--force")))

	listAfterDelete := parseEnvelope(t, runCommand(t, binary, "--no-update-check", "list"))
	assertSuccessEnvelope(t, listAfterDelete)
	assertSecretNames(t, listAfterDelete, []string{"test_key"})

	assertSuccessEnvelope(t, parseEnvelope(t, runCommand(t, binary, "--no-update-check", "revoke", "--all")))

	statusEnvelope := parseEnvelope(t, runCommand(t, binary, "--no-update-check", "status"))
	assertSuccessEnvelope(t, statusEnvelope)
	statusResult := mustMap(t, statusEnvelope["result"], "status result")
	if active := mustNumber(t, statusResult["active_leases"], "status result.active_leases"); active != 0 {
		t.Fatalf("expected active_leases=0 after revoke --all, got %d", active)
	}

	daemon.stop(t)
}

func TestDeprecatedFlags(t *testing.T) {
	setupTempHome(t)
	binary := getBinaryPath(t)

	runAndAssertSuccessEnvelope(t, binary, "--no-update-check", "init")
	daemon := startDaemon(t, binary)
	defer daemon.stop(t)

	runAndAssertSuccessEnvelope(t, binary, "--no-update-check", "add", "test_key", "--value", "sk-test123")

	leaseStdout, leaseStderr, leaseErr := runCommandCapture(t, binary, "--no-update-check", "lease", "test_key", "--raw")
	if leaseErr != nil {
		t.Fatalf("lease --raw failed: %v\nstderr: %s", leaseErr, leaseStderr)
	}
	if leaseStdout != "sk-test123" {
		t.Fatalf("expected lease --raw stdout sk-test123, got %q", leaseStdout)
	}
	if !strings.Contains(leaseStderr, "deprecated") || !strings.Contains(leaseStderr, "--raw") {
		t.Fatalf("expected --raw deprecation warning on stderr, got %q", leaseStderr)
	}

	statusHumanStdout, statusHumanStderr, statusHumanErr := runCommandCapture(t, binary, "--no-update-check", "status", "--human")
	if statusHumanErr != nil {
		t.Fatalf("status --human failed: %v\nstderr: %s", statusHumanErr, statusHumanStderr)
	}
	assertSuccessEnvelope(t, parseEnvelope(t, statusHumanStdout))
	if !strings.Contains(statusHumanStderr, "deprecated") || !strings.Contains(statusHumanStderr, "--human") {
		t.Fatalf("expected --human deprecation warning on stderr, got %q", statusHumanStderr)
	}

	statusOutputStdout, statusOutputStderr, statusOutputErr := runCommandCapture(t, binary, "--no-update-check", "status", "--output", "json")
	if statusOutputErr != nil {
		t.Fatalf("status --output json failed: %v\nstderr: %s", statusOutputErr, statusOutputStderr)
	}
	assertSuccessEnvelope(t, parseEnvelope(t, statusOutputStdout))
	if !strings.Contains(statusOutputStderr, "deprecated") || !strings.Contains(statusOutputStderr, "--output") {
		t.Fatalf("expected --output deprecation warning on stderr, got %q", statusOutputStderr)
	}
}

func TestErrorResponses(t *testing.T) {
	setupTempHome(t)
	binary := getBinaryPath(t)

	runAndAssertSuccessEnvelope(t, binary, "--no-update-check", "init")
	daemon := startDaemon(t, binary)
	defer daemon.stop(t)

	leaseMissing := parseEnvelope(t, runCommand(t, binary, "--no-update-check", "lease", "nonexistent", "--json"))
	assertErrorEnvelope(t, leaseMissing)

	deleteMissing := parseEnvelope(t, runCommand(t, binary, "--no-update-check", "delete", "nonexistent", "--force"))
	assertErrorEnvelope(t, deleteMissing)
	deleteFix := mustString(t, deleteMissing["fix"], "delete fix")
	if !strings.Contains(strings.ToLower(deleteFix), "list") {
		t.Fatalf("expected delete fix to suggest list command, got %q", deleteFix)
	}

	updateMissing := parseEnvelope(t, runCommand(t, binary, "--no-update-check", "update", "nonexistent", "--value", "x"))
	assertErrorEnvelope(t, updateMissing)
}

func TestJSONEnvelopeShape(t *testing.T) {
	setupTempHome(t)
	binary := getBinaryPath(t)

	initEnvelope := runAndAssertSuccessEnvelope(t, binary, "--no-update-check", "init")
	assertEnvelopeShape(t, initEnvelope, false, true)

	daemon := startDaemon(t, binary)
	defer daemon.stop(t)

	rootEnvelope := parseEnvelope(t, runCommand(t, binary, "--no-update-check"))
	assertEnvelopeShape(t, rootEnvelope, false, true)

	addEnvelope := runAndAssertSuccessEnvelope(t, binary, "--no-update-check", "add", "shape_key", "--value", "shape-val")
	assertEnvelopeShape(t, addEnvelope, false, true)

	listEnvelope := runAndAssertSuccessEnvelope(t, binary, "--no-update-check", "list")
	assertEnvelopeShape(t, listEnvelope, false, true)

	leaseEnvelope := runAndAssertSuccessEnvelope(t, binary, "--no-update-check", "lease", "shape_key", "--json")
	assertEnvelopeShape(t, leaseEnvelope, false, true)

	statusEnvelope := runAndAssertSuccessEnvelope(t, binary, "--no-update-check", "status")
	assertEnvelopeShape(t, statusEnvelope, false, true)

	updateEnvelope := runAndAssertSuccessEnvelope(t, binary, "--no-update-check", "update", "shape_key", "--value", "shape-updated")
	assertEnvelopeShape(t, updateEnvelope, false, true)

	deleteEnvelope := runAndAssertSuccessEnvelope(t, binary, "--no-update-check", "delete", "shape_key", "--force")
	assertEnvelopeShape(t, deleteEnvelope, false, true)

	revokeEnvelope := runAndAssertSuccessEnvelope(t, binary, "--no-update-check", "revoke", "--all")
	assertEnvelopeShape(t, revokeEnvelope, false, true)

	deleteMissingEnvelope := parseEnvelope(t, runCommand(t, binary, "--no-update-check", "delete", "missing_shape_key", "--force"))
	assertEnvelopeShape(t, deleteMissingEnvelope, true, true)
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

func runCommandCapture(t *testing.T, binary string, args ...string) (string, string, error) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func setupTempHome(t *testing.T) string {
	t.Helper()
	tmpHome, err := os.MkdirTemp("", "secrets-home-*")
	if err != nil {
		t.Fatal(err)
	}

	originalHome := os.Getenv("HOME")
	if err := os.Setenv("HOME", tmpHome); err != nil {
		t.Fatalf("failed setting HOME: %v", err)
	}

	t.Cleanup(func() {
		_ = os.Setenv("HOME", originalHome)
		_ = os.RemoveAll(tmpHome)
	})

	return tmpHome
}

type daemonProcess struct {
	cmd      *exec.Cmd
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	stopOnce sync.Once
}

func startDaemon(t *testing.T, binary string) *daemonProcess {
	t.Helper()
	d := &daemonProcess{}
	d.cmd = exec.Command(binary, "--no-update-check", "serve")
	d.cmd.Stdout = &d.stdout
	d.cmd.Stderr = &d.stderr

	if err := d.cmd.Start(); err != nil {
		t.Fatalf("failed to start daemon: %v", err)
	}

	waitForDaemonReady(t, binary, d)
	t.Cleanup(func() {
		d.stop(t)
	})
	return d
}

func (d *daemonProcess) stop(t *testing.T) {
	t.Helper()
	if d == nil || d.cmd == nil || d.cmd.Process == nil {
		return
	}

	d.stopOnce.Do(func() {
		if d.cmd.ProcessState != nil && d.cmd.ProcessState.Exited() {
			return
		}

		waitDone := make(chan error, 1)
		go func() {
			waitDone <- d.cmd.Wait()
		}()

		if err := d.cmd.Process.Signal(os.Interrupt); err != nil {
			_ = d.cmd.Process.Kill()
		}

		select {
		case err := <-waitDone:
			if err != nil {
				t.Fatalf("daemon exited with error: %v\nstdout:\n%s\nstderr:\n%s", err, d.stdout.String(), d.stderr.String())
			}
		case <-time.After(5 * time.Second):
			_ = d.cmd.Process.Kill()
			<-waitDone
			t.Fatalf("timed out stopping daemon\nstdout:\n%s\nstderr:\n%s", d.stdout.String(), d.stderr.String())
		}
	})
}

func waitForDaemonReady(t *testing.T, binary string, d *daemonProcess) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		statusOut, _, _ := runCommandCapture(t, binary, "--no-update-check", "status")
		envelope, err := parseEnvelopeSafe(statusOut)
		if err == nil {
			if ok, exists := envelope["ok"].(bool); exists && ok {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("daemon failed to become ready\nstdout:\n%s\nstderr:\n%s", d.stdout.String(), d.stderr.String())
}

func runAndAssertSuccessEnvelope(t *testing.T, binary string, args ...string) map[string]interface{} {
	t.Helper()
	envelope := parseEnvelope(t, runCommand(t, binary, args...))
	assertSuccessEnvelope(t, envelope)
	return envelope
}

func parseEnvelope(t *testing.T, out string) map[string]interface{} {
	t.Helper()
	envelope, err := parseEnvelopeSafe(out)
	if err != nil {
		t.Fatalf("failed to parse JSON output: %v\noutput:\n%s", err, out)
	}
	return envelope
}

func parseEnvelopeSafe(out string) (map[string]interface{}, error) {
	var envelope map[string]interface{}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		return nil, err
	}
	return envelope, nil
}

func assertSuccessEnvelope(t *testing.T, envelope map[string]interface{}) {
	t.Helper()
	ok := mustBool(t, envelope["ok"], "ok")
	if !ok {
		t.Fatalf("expected success envelope, got error envelope: %#v", envelope)
	}
	if strings.TrimSpace(mustString(t, envelope["command"], "command")) == "" {
		t.Fatalf("command field should not be empty: %#v", envelope)
	}
	if _, exists := envelope["result"]; !exists {
		t.Fatalf("success envelope missing result field: %#v", envelope)
	}
}

func assertErrorEnvelope(t *testing.T, envelope map[string]interface{}) {
	t.Helper()
	ok := mustBool(t, envelope["ok"], "ok")
	if ok {
		t.Fatalf("expected error envelope, got success envelope: %#v", envelope)
	}
	if strings.TrimSpace(mustString(t, envelope["command"], "command")) == "" {
		t.Fatalf("command field should not be empty: %#v", envelope)
	}
	errObj := mustMap(t, envelope["error"], "error")
	if strings.TrimSpace(mustString(t, errObj["message"], "error.message")) == "" {
		t.Fatalf("error.message should not be empty: %#v", errObj)
	}
	if strings.TrimSpace(mustString(t, errObj["code"], "error.code")) == "" {
		t.Fatalf("error.code should not be empty: %#v", errObj)
	}
	if strings.TrimSpace(mustString(t, envelope["fix"], "fix")) == "" {
		t.Fatalf("error envelope missing non-empty fix field: %#v", envelope)
	}
}

func assertEnvelopeShape(t *testing.T, envelope map[string]interface{}, expectError bool, requireNextActions bool) {
	t.Helper()
	if expectError {
		assertErrorEnvelope(t, envelope)
	} else {
		assertSuccessEnvelope(t, envelope)
	}

	if requireNextActions {
		assertNextActionsShape(t, envelope)
	}
}

func assertNextActionsShape(t *testing.T, envelope map[string]interface{}) {
	t.Helper()
	actions := mustSlice(t, envelope["next_actions"], "next_actions")
	for i, action := range actions {
		actionObj := mustMap(t, action, fmt.Sprintf("next_actions[%d]", i))
		if strings.TrimSpace(mustString(t, actionObj["command"], fmt.Sprintf("next_actions[%d].command", i))) == "" {
			t.Fatalf("next_actions[%d].command is empty", i)
		}
		if strings.TrimSpace(mustString(t, actionObj["description"], fmt.Sprintf("next_actions[%d].description", i))) == "" {
			t.Fatalf("next_actions[%d].description is empty", i)
		}
	}
}

func commandExists(commands []interface{}, expected string) bool {
	for _, raw := range commands {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if name, ok := entry["name"].(string); ok && name == expected {
			return true
		}
	}
	return false
}

func assertSecretNames(t *testing.T, envelope map[string]interface{}, expected []string) {
	t.Helper()
	result := mustMap(t, envelope["result"], "list result")
	secrets := mustSlice(t, result["secrets"], "list result.secrets")

	names := make([]string, 0, len(secrets))
	for _, secretRaw := range secrets {
		secret := mustMap(t, secretRaw, "secret")
		names = append(names, mustString(t, secret["name"], "secret.name"))
	}

	if len(names) != len(expected) {
		t.Fatalf("unexpected secret count: got %v want %v", names, expected)
	}

	nameSet := make(map[string]bool, len(names))
	for _, name := range names {
		nameSet[name] = true
	}
	for _, expectedName := range expected {
		if !nameSet[expectedName] {
			t.Fatalf("missing secret %q in list %v", expectedName, names)
		}
	}
}

func mustMap(t *testing.T, raw interface{}, field string) map[string]interface{} {
	t.Helper()
	value, ok := raw.(map[string]interface{})
	if !ok {
		t.Fatalf("field %s is not an object: %#v", field, raw)
	}
	return value
}

func mustSlice(t *testing.T, raw interface{}, field string) []interface{} {
	t.Helper()
	value, ok := raw.([]interface{})
	if !ok {
		t.Fatalf("field %s is not an array: %#v", field, raw)
	}
	return value
}

func mustString(t *testing.T, raw interface{}, field string) string {
	t.Helper()
	value, ok := raw.(string)
	if !ok {
		t.Fatalf("field %s is not a string: %#v", field, raw)
	}
	return value
}

func mustBool(t *testing.T, raw interface{}, field string) bool {
	t.Helper()
	value, ok := raw.(bool)
	if !ok {
		t.Fatalf("field %s is not a boolean: %#v", field, raw)
	}
	return value
}

func mustNumber(t *testing.T, raw interface{}, field string) int {
	t.Helper()
	value, ok := raw.(float64)
	if !ok {
		t.Fatalf("field %s is not numeric: %#v", field, raw)
	}
	return int(value)
}

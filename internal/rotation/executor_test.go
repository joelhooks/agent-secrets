package rotation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/audit"
	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/store"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// setupTest creates a temporary test environment with store, config, and audit logger.
func setupTest(t *testing.T) (*config.Config, *store.Store, *audit.Logger, func()) {
	t.Helper()

	tmpDir := t.TempDir()

	cfg := &config.Config{
		Directory:       tmpDir,
		IdentityPath:    filepath.Join(tmpDir, "identity.age"),
		SecretsPath:     filepath.Join(tmpDir, "secrets.age"),
		AuditPath:       filepath.Join(tmpDir, "audit.log"),
		RotationTimeout: 5 * time.Second,
	}

	st := store.New(cfg)
	if err := st.Init(); err != nil {
		t.Fatalf("failed to initialize store: %v", err)
	}

	if err := st.Load(); err != nil {
		t.Fatalf("failed to load store: %v", err)
	}

	auditLogger, err := audit.New(cfg.AuditPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	cleanup := func() {
		_ = auditLogger.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return cfg, st, auditLogger, cleanup
}

func TestNewExecutor(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	executor := NewExecutor(cfg, st, auditLogger)

	if executor == nil {
		t.Fatal("expected non-nil executor")
	}

	if executor.cfg != cfg {
		t.Error("executor config not set correctly")
	}

	if executor.store != st {
		t.Error("executor store not set correctly")
	}

	if executor.auditLogger != auditLogger {
		t.Error("executor audit logger not set correctly")
	}
}

func TestRotate_Success(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Add a secret with a simple rotation command
	if err := st.Add("test_secret", "test_value", "echo 'rotation successful'"); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	executor := NewExecutor(cfg, st, auditLogger)
	result, err := executor.Rotate("test_secret")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if !result.Success {
		t.Errorf("expected success, got failure: %v", result.Error)
	}

	if result.SecretName != "test_secret" {
		t.Errorf("expected secret name 'test_secret', got %q", result.SecretName)
	}

	if result.Output == "" {
		t.Error("expected some output from command")
	}

	// Verify that LastRotated was updated
	secrets, err := st.List()
	if err != nil {
		t.Fatalf("failed to list secrets: %v", err)
	}

	var found bool
	for _, s := range secrets {
		if s.Name == "test_secret" {
			found = true
			if s.LastRotated.IsZero() {
				t.Error("expected LastRotated to be set")
			}
			break
		}
	}

	if !found {
		t.Error("secret not found in store")
	}
}

func TestRotate_CommandFailure(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Add a secret with a command that will fail
	if err := st.Add("failing_secret", "test_value", "exit 1"); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	executor := NewExecutor(cfg, st, auditLogger)
	result, err := executor.Rotate("failing_secret")

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if result.Success {
		t.Error("expected failure, got success")
	}

	if result.Error == "" {
		t.Error("expected error message in result")
	}

	var rotErr *types.RotationError
	if !errors.As(err, &rotErr) {
		t.Errorf("expected RotationError, got %T", err)
	}

	if !errors.Is(err, types.ErrRotationFailed) {
		t.Error("expected ErrRotationFailed")
	}
}

func TestRotate_Timeout(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Set a very short timeout
	cfg.RotationTimeout = 100 * time.Millisecond

	// Add a secret with a command that will timeout (sleep longer than timeout)
	if err := st.Add("slow_secret", "test_value", "sleep 10"); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	executor := NewExecutor(cfg, st, auditLogger)
	result, err := executor.Rotate("slow_secret")

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if result.Success {
		t.Error("expected failure due to timeout")
	}

	if result.Error != "command timed out" {
		t.Errorf("expected timeout error, got: %s", result.Error)
	}

	if !errors.Is(err, types.ErrRotationTimeout) {
		t.Error("expected ErrRotationTimeout")
	}
}

func TestRotate_NoRotationHook(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Add a secret without a rotation hook
	if err := st.Add("no_rotation", "test_value", ""); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	executor := NewExecutor(cfg, st, auditLogger)
	result, err := executor.Rotate("no_rotation")

	if err == nil {
		t.Fatal("expected error for missing rotation hook, got nil")
	}

	if !errors.Is(err, types.ErrNoRotationHook) {
		t.Errorf("expected ErrNoRotationHook, got: %v", err)
	}

	if result != nil {
		t.Error("expected nil result for missing rotation hook")
	}
}

func TestRotate_SecretNotFound(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	executor := NewExecutor(cfg, st, auditLogger)
	result, err := executor.Rotate("nonexistent")

	if err == nil {
		t.Fatal("expected error for nonexistent secret, got nil")
	}

	if !errors.Is(err, types.ErrSecretNotFound) {
		t.Errorf("expected ErrSecretNotFound, got: %v", err)
	}

	if result != nil {
		t.Error("expected nil result for nonexistent secret")
	}
}

func TestRotateAll(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Add multiple secrets with rotation hooks
	secrets := []struct {
		name    string
		command string
	}{
		{"secret1", "echo 'rotated secret1'"},
		{"secret2", "echo 'rotated secret2'"},
		{"secret3", ""}, // No rotation hook
		{"secret4", "echo 'rotated secret4'"},
	}

	for _, s := range secrets {
		if err := st.Add(s.name, "value", s.command); err != nil {
			t.Fatalf("failed to add secret %s: %v", s.name, err)
		}
	}

	executor := NewExecutor(cfg, st, auditLogger)
	results, err := executor.RotateAll()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have 3 results (secret3 skipped because no rotation hook)
	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	// Verify all rotations succeeded
	for _, r := range results {
		if !r.Success {
			t.Errorf("expected success for %s, got failure: %v", r.SecretName, r.Error)
		}
	}
}

func TestRotateAll_WithFailures(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Add secrets with mix of success and failure
	secrets := []struct {
		name    string
		command string
	}{
		{"good1", "echo 'success'"},
		{"bad1", "exit 1"},
		{"good2", "echo 'success'"},
	}

	for _, s := range secrets {
		if err := st.Add(s.name, "value", s.command); err != nil {
			t.Fatalf("failed to add secret %s: %v", s.name, err)
		}
	}

	executor := NewExecutor(cfg, st, auditLogger)
	results, err := executor.RotateAll()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}

	// Count successes and failures
	successCount := 0
	failureCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		} else {
			failureCount++
		}
	}

	if successCount != 2 {
		t.Errorf("expected 2 successes, got %d", successCount)
	}

	if failureCount != 1 {
		t.Errorf("expected 1 failure, got %d", failureCount)
	}
}

func TestCanRotate(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Add secrets with and without rotation hooks
	if err := st.Add("with_hook", "value", "echo test"); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	if err := st.Add("without_hook", "value", ""); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	executor := NewExecutor(cfg, st, auditLogger)

	if !executor.CanRotate("with_hook") {
		t.Error("expected CanRotate to return true for secret with hook")
	}

	if executor.CanRotate("without_hook") {
		t.Error("expected CanRotate to return false for secret without hook")
	}

	if executor.CanRotate("nonexistent") {
		t.Error("expected CanRotate to return false for nonexistent secret")
	}
}

func TestRotate_OutputCapture(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Add a secret with a command that outputs to both stdout and stderr
	cmd := "echo 'stdout message'; echo 'stderr message' >&2"
	if err := st.Add("output_test", "value", cmd); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	executor := NewExecutor(cfg, st, auditLogger)
	result, err := executor.Rotate("output_test")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output == "" {
		t.Error("expected output to be captured")
	}

	// Both stdout and stderr should be in the output
	if len(result.Output) < 10 {
		t.Errorf("expected combined output, got: %q", result.Output)
	}
}

func TestRotate_ConcurrentExecution(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	if err := st.Add("concurrent_secret", "value", "echo 'test'"); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	executor := NewExecutor(cfg, st, auditLogger)

	// Try concurrent rotations - should be serialized by mutex
	done := make(chan error, 2)

	go func() {
		_, err := executor.Rotate("concurrent_secret")
		done <- err
	}()

	go func() {
		_, err := executor.Rotate("concurrent_secret")
		done <- err
	}()

	// Wait for both to complete
	for i := 0; i < 2; i++ {
		err := <-done
		if err != nil {
			t.Errorf("concurrent rotation failed: %v", err)
		}
	}
}

func TestRotate_AuditLogging(t *testing.T) {
	cfg, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	if err := st.Add("audit_test", "value", "echo 'test'"); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	executor := NewExecutor(cfg, st, auditLogger)
	_, err := executor.Rotate("audit_test")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check audit log
	entries, err := auditLogger.Tail(10)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}

	if len(entries) == 0 {
		t.Fatal("expected audit entries, got none")
	}

	found := false
	for _, entry := range entries {
		if entry.Action == types.ActionSecretRotate && entry.SecretName == "audit_test" {
			found = true
			if !entry.Success {
				t.Error("expected successful audit entry")
			}
			break
		}
	}

	if !found {
		t.Error("expected to find rotation audit entry")
	}
}

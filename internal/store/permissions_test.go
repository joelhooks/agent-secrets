package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateKeyFilePermissions_SecureFile(t *testing.T) {
	// Create temp file with secure permissions
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.age")

	// Create file with 0600 permissions
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Should pass validation
	if err := ValidateKeyFilePermissions(testFile); err != nil {
		t.Errorf("expected no error for 0600 file, got: %v", err)
	}
}

func TestValidateKeyFilePermissions_InsecureFile(t *testing.T) {
	// Create temp file with insecure permissions
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.age")

	// Create file with 0644 permissions (world-readable)
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Should fail validation
	err := ValidateKeyFilePermissions(testFile)
	if err == nil {
		t.Error("expected error for 0644 file, got nil")
	}

	// Check that it's a PermissionError
	if _, ok := err.(*PermissionError); !ok {
		t.Errorf("expected PermissionError, got %T", err)
	}
}

func TestValidateKeyFilePermissions_NonexistentFile(t *testing.T) {
	// Non-existent files should pass (they'll be created with correct permissions)
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "nonexistent.age")

	if err := ValidateKeyFilePermissions(testFile); err != nil {
		t.Errorf("expected no error for nonexistent file, got: %v", err)
	}
}

func TestValidateAllKeyFiles(t *testing.T) {
	tmpDir := t.TempDir()
	identityFile := filepath.Join(tmpDir, "identity.age")
	secretsFile := filepath.Join(tmpDir, "secrets.age")

	// Create both files with secure permissions
	if err := os.WriteFile(identityFile, []byte("test"), 0600); err != nil {
		t.Fatalf("failed to create identity file: %v", err)
	}
	if err := os.WriteFile(secretsFile, []byte("test"), 0600); err != nil {
		t.Fatalf("failed to create secrets file: %v", err)
	}

	// Should pass
	if err := ValidateAllKeyFiles(identityFile, secretsFile, false); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Create insecure identity file
	insecureIdentity := filepath.Join(tmpDir, "insecure_identity.age")
	if err := os.WriteFile(insecureIdentity, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create insecure identity file: %v", err)
	}

	// Should fail on identity
	if err := ValidateAllKeyFiles(insecureIdentity, secretsFile, false); err == nil {
		t.Error("expected error for insecure identity file, got nil")
	}

	// Create insecure secrets file
	insecureSecrets := filepath.Join(tmpDir, "insecure_secrets.age")
	if err := os.WriteFile(insecureSecrets, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create insecure secrets file: %v", err)
	}

	// Should fail on secrets
	if err := ValidateAllKeyFiles(identityFile, insecureSecrets, false); err == nil {
		t.Error("expected error for insecure secrets file, got nil")
	}
}

func TestValidateAllKeyFiles_SkipCheck(t *testing.T) {
	tmpDir := t.TempDir()
	insecureFile := filepath.Join(tmpDir, "insecure.age")

	// Create file with insecure permissions
	if err := os.WriteFile(insecureFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create insecure file: %v", err)
	}

	// Should pass when skipCheck is true
	if err := ValidateAllKeyFiles(insecureFile, insecureFile, true); err != nil {
		t.Errorf("expected no error when skipCheck=true, got: %v", err)
	}
}

func TestEnsureSecurePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.age")

	// Create file with insecure permissions
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Fix permissions
	if err := EnsureSecurePermissions(testFile); err != nil {
		t.Fatalf("failed to ensure secure permissions: %v", err)
	}

	// Verify permissions are now 0600
	info, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("failed to stat file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %04o", info.Mode().Perm())
	}
}

func TestPermissionError_Error(t *testing.T) {
	err := &PermissionError{
		Path:     "/tmp/test.age",
		Current:  0644,
		Expected: 0600,
	}

	// Should contain key information
	errMsg := err.Error()
	if errMsg == "" {
		t.Error("error message should not be empty")
	}

	// Should contain the file path
	if !contains(errMsg, "/tmp/test.age") {
		t.Error("error message should contain file path")
	}

	// Should contain fix command
	if !contains(errMsg, "chmod 0600") {
		t.Error("error message should contain fix command")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

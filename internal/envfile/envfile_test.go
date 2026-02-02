package envfile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteWithTTL(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, ".env.test")

	vars := map[string]string{
		"DATABASE_URL": "postgres://localhost/db",
		"API_KEY":      "sk_test_12345",
	}

	err := WriteWithTTL(testFile, vars, 1*time.Hour, "vercel/production")
	if err != nil {
		t.Fatalf("WriteWithTTL failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Fatal("File was not created")
	}

	// Read and verify content
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	contentStr := string(content)

	// Check for required headers
	if !contains(contentStr, "# secrets-managed: true") {
		t.Error("Missing managed header")
	}
	if !contains(contentStr, "# secrets-ttl:") {
		t.Error("Missing TTL header")
	}
	if !contains(contentStr, "# secrets-source: vercel/production") {
		t.Error("Missing source header")
	}

	// Check for variables
	if !contains(contentStr, "DATABASE_URL=postgres://localhost/db") {
		t.Error("Missing DATABASE_URL variable")
	}
	if !contains(contentStr, "API_KEY=sk_test_12345") {
		t.Error("Missing API_KEY variable")
	}
}

func TestWriteWithTTL_NoSource(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, ".env.test")

	vars := map[string]string{
		"TEST_VAR": "value",
	}

	err := WriteWithTTL(testFile, vars, 30*time.Minute, "")
	if err != nil {
		t.Fatalf("WriteWithTTL failed: %v", err)
	}

	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	contentStr := string(content)

	// Should have managed and TTL headers but no source
	if !contains(contentStr, "# secrets-managed: true") {
		t.Error("Missing managed header")
	}
	if !contains(contentStr, "# secrets-ttl:") {
		t.Error("Missing TTL header")
	}
	if contains(contentStr, "# secrets-source:") {
		t.Error("Should not have source header when source is empty")
	}
}

func TestRead(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, ".env.test")

	vars := map[string]string{
		"DATABASE_URL": "postgres://localhost/db",
		"API_KEY":      "sk_test_12345",
	}

	ttl := 2 * time.Hour
	source := "vercel/production"

	// Write file
	if err := WriteWithTTL(testFile, vars, ttl, source); err != nil {
		t.Fatalf("WriteWithTTL failed: %v", err)
	}

	// Read it back
	envFile, err := Read(testFile)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Verify path
	if envFile.Path != testFile {
		t.Errorf("Expected path %s, got %s", testFile, envFile.Path)
	}

	// Verify source
	if envFile.Source != source {
		t.Errorf("Expected source %s, got %s", source, envFile.Source)
	}

	// Verify TTL is approximately correct (within 1 second)
	expectedExpiry := time.Now().Add(ttl)
	diff := envFile.ExpiresAt.Sub(expectedExpiry).Abs()
	if diff > time.Second {
		t.Errorf("ExpiresAt differs by %v, expected within 1s", diff)
	}

	// Verify variables
	if len(envFile.Vars) != len(vars) {
		t.Errorf("Expected %d vars, got %d", len(vars), len(envFile.Vars))
	}

	for key, expectedValue := range vars {
		if actualValue, ok := envFile.Vars[key]; !ok {
			t.Errorf("Missing variable %s", key)
		} else if actualValue != expectedValue {
			t.Errorf("Variable %s: expected %s, got %s", key, expectedValue, actualValue)
		}
	}
}

func TestRead_NoTTLHeader(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, ".env.test")

	// Create file without TTL headers (graceful fallback)
	content := `# This is a regular .env file
DATABASE_URL=postgres://localhost/db
API_KEY=sk_test_12345
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	envFile, err := Read(testFile)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Should parse variables even without TTL
	if len(envFile.Vars) != 2 {
		t.Errorf("Expected 2 vars, got %d", len(envFile.Vars))
	}

	// ExpiresAt should be zero
	if !envFile.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be zero when no TTL header present")
	}

	// Source should be empty
	if envFile.Source != "" {
		t.Errorf("Expected empty source, got %s", envFile.Source)
	}
}

func TestIsExpired(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("expired file", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, ".env.expired")

		vars := map[string]string{"TEST": "value"}
		// Use negative TTL to create already-expired file
		if err := WriteWithTTL(testFile, vars, -1*time.Hour, "test"); err != nil {
			t.Fatalf("WriteWithTTL failed: %v", err)
		}

		expired, err := IsExpired(testFile)
		if err != nil {
			t.Fatalf("IsExpired failed: %v", err)
		}

		if !expired {
			t.Error("Expected file to be expired")
		}
	})

	t.Run("not expired file", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, ".env.valid")

		vars := map[string]string{"TEST": "value"}
		if err := WriteWithTTL(testFile, vars, 1*time.Hour, "test"); err != nil {
			t.Fatalf("WriteWithTTL failed: %v", err)
		}

		expired, err := IsExpired(testFile)
		if err != nil {
			t.Fatalf("IsExpired failed: %v", err)
		}

		if expired {
			t.Error("Expected file to not be expired")
		}
	})

	t.Run("no TTL header", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, ".env.nottl")

		// Create file without TTL
		content := "TEST=value\n"
		if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}

		expired, err := IsExpired(testFile)
		if err != nil {
			t.Fatalf("IsExpired failed: %v", err)
		}

		// Should not be considered expired if no TTL
		if expired {
			t.Error("File without TTL should not be considered expired")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, ".env.missing")

		_, err := IsExpired(testFile)
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})
}

func TestWipe(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("existing file", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, ".env.test")

		vars := map[string]string{"TEST": "value"}
		if err := WriteWithTTL(testFile, vars, 1*time.Hour, "test"); err != nil {
			t.Fatalf("WriteWithTTL failed: %v", err)
		}

		// Verify file exists
		if _, err := os.Stat(testFile); os.IsNotExist(err) {
			t.Fatal("File should exist before wipe")
		}

		// Wipe it
		if err := Wipe(testFile); err != nil {
			t.Fatalf("Wipe failed: %v", err)
		}

		// Verify file is gone
		if _, err := os.Stat(testFile); !os.IsNotExist(err) {
			t.Error("File should not exist after wipe")
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, ".env.missing")

		// Should not error if file doesn't exist
		if err := Wipe(testFile); err != nil {
			t.Errorf("Wipe should not error on nonexistent file: %v", err)
		}
	})
}

func TestRead_EmptyLines(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, ".env.test")

	content := `# secrets-managed: true
# secrets-ttl: 2024-01-15T10:00:00Z
# secrets-source: test/source

DATABASE_URL=postgres://localhost/db

API_KEY=sk_test_12345

`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	envFile, err := Read(testFile)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	// Should have exactly 2 variables
	if len(envFile.Vars) != 2 {
		t.Errorf("Expected 2 vars, got %d", len(envFile.Vars))
	}
}

func TestRead_ValuesWithEquals(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, ".env.test")

	content := `# secrets-managed: true
# secrets-ttl: 2024-01-15T10:00:00Z
CONNECTION_STRING=Server=localhost;User=admin;Password=p@ss=w0rd
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	envFile, err := Read(testFile)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	expected := "Server=localhost;User=admin;Password=p@ss=w0rd"
	if actual := envFile.Vars["CONNECTION_STRING"]; actual != expected {
		t.Errorf("Expected %s, got %s", expected, actual)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsAny(s, substr))
}

func containsAny(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

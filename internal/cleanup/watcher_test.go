package cleanup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/envfile"
)

func TestWatcher_Check_FindsExpiredFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an expired .env.local file
	expiredPath := filepath.Join(tmpDir, ".env.local")
	vars := map[string]string{"KEY": "value"}
	if err := envfile.WriteWithTTL(expiredPath, vars, -1*time.Hour, "test"); err != nil {
		t.Fatalf("failed to create expired file: %v", err)
	}

	// Create watcher and check
	w := New([]string{tmpDir}, 1*time.Minute)
	wiped, err := w.Check()
	if err != nil {
		t.Fatalf("Check() failed: %v", err)
	}

	// Verify the file was wiped
	if len(wiped) != 1 {
		t.Fatalf("expected 1 wiped file, got %d", len(wiped))
	}

	if wiped[0] != expiredPath {
		t.Errorf("expected wiped file %s, got %s", expiredPath, wiped[0])
	}

	// Verify file no longer exists
	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Errorf("expected file to be removed, but it still exists")
	}
}

func TestWatcher_Check_IgnoresNonExpiredFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a non-expired .env.local file
	validPath := filepath.Join(tmpDir, ".env.local")
	vars := map[string]string{"KEY": "value"}
	if err := envfile.WriteWithTTL(validPath, vars, 1*time.Hour, "test"); err != nil {
		t.Fatalf("failed to create valid file: %v", err)
	}

	// Create watcher and check
	w := New([]string{tmpDir}, 1*time.Minute)
	wiped, err := w.Check()
	if err != nil {
		t.Fatalf("Check() failed: %v", err)
	}

	// Verify no files were wiped
	if len(wiped) != 0 {
		t.Fatalf("expected 0 wiped files, got %d", len(wiped))
	}

	// Verify file still exists
	if _, err := os.Stat(validPath); err != nil {
		t.Errorf("expected file to exist, but got error: %v", err)
	}
}

func TestWatcher_Check_HandlesMissingDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentPath := filepath.Join(tmpDir, "does-not-exist")

	// Create watcher pointing to non-existent path
	w := New([]string{nonExistentPath}, 1*time.Minute)
	wiped, err := w.Check()

	// Should not error, just skip the missing path
	if err != nil {
		t.Fatalf("Check() should not error on missing path: %v", err)
	}

	if len(wiped) != 0 {
		t.Fatalf("expected 0 wiped files, got %d", len(wiped))
	}
}

func TestWatcher_Check_HandlesNonEnvFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a non-.env file
	otherFile := filepath.Join(tmpDir, "other.txt")
	if err := os.WriteFile(otherFile, []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create other file: %v", err)
	}

	// Create watcher and check
	w := New([]string{tmpDir}, 1*time.Minute)
	wiped, err := w.Check()
	if err != nil {
		t.Fatalf("Check() failed: %v", err)
	}

	// Verify no files were wiped
	if len(wiped) != 0 {
		t.Fatalf("expected 0 wiped files, got %d", len(wiped))
	}

	// Verify file still exists
	if _, err := os.Stat(otherFile); err != nil {
		t.Errorf("expected file to exist, but got error: %v", err)
	}
}

func TestWatcher_Check_HandlesFileWithoutTTL(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a .env file without TTL metadata
	noTTLPath := filepath.Join(tmpDir, ".env.local")
	content := []byte("KEY=value\nOTHER=data\n")
	if err := os.WriteFile(noTTLPath, content, 0644); err != nil {
		t.Fatalf("failed to create file without TTL: %v", err)
	}

	// Create watcher and check
	w := New([]string{tmpDir}, 1*time.Minute)
	wiped, err := w.Check()
	if err != nil {
		t.Fatalf("Check() failed: %v", err)
	}

	// Verify no files were wiped (files without TTL are not considered expired)
	if len(wiped) != 0 {
		t.Fatalf("expected 0 wiped files, got %d", len(wiped))
	}

	// Verify file still exists
	if _, err := os.Stat(noTTLPath); err != nil {
		t.Errorf("expected file to exist, but got error: %v", err)
	}
}

func TestWatcher_Check_MultiplePaths(t *testing.T) {
	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()

	// Create expired files in both directories
	expiredPath1 := filepath.Join(tmpDir1, ".env.local")
	expiredPath2 := filepath.Join(tmpDir2, ".env.local")
	vars := map[string]string{"KEY": "value"}

	if err := envfile.WriteWithTTL(expiredPath1, vars, -1*time.Hour, "test"); err != nil {
		t.Fatalf("failed to create expired file 1: %v", err)
	}
	if err := envfile.WriteWithTTL(expiredPath2, vars, -1*time.Hour, "test"); err != nil {
		t.Fatalf("failed to create expired file 2: %v", err)
	}

	// Create watcher with multiple paths
	w := New([]string{tmpDir1, tmpDir2}, 1*time.Minute)
	wiped, err := w.Check()
	if err != nil {
		t.Fatalf("Check() failed: %v", err)
	}

	// Verify both files were wiped
	if len(wiped) != 2 {
		t.Fatalf("expected 2 wiped files, got %d", len(wiped))
	}
}

func TestWatcher_Start_StopsOnContext(t *testing.T) {
	tmpDir := t.TempDir()

	// Create watcher with short interval
	w := New([]string{tmpDir}, 100*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	// Start should block until context is cancelled
	done := make(chan struct{})
	go func() {
		w.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// Success: Start returned when context was cancelled
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Start() did not stop when context was cancelled")
	}
}

func TestWatcher_Stop(t *testing.T) {
	tmpDir := t.TempDir()

	// Create watcher with long interval
	w := New([]string{tmpDir}, 1*time.Hour)

	ctx := context.Background()

	// Start in background
	done := make(chan struct{})
	go func() {
		w.Start(ctx)
		close(done)
	}()

	// Stop after short delay
	time.Sleep(100 * time.Millisecond)
	w.Stop()

	// Verify Start returned
	select {
	case <-done:
		// Success: Start returned when Stop was called
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Start() did not stop when Stop() was called")
	}
}

func TestWatcher_Check_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create an expired .env.local file
	expiredPath := filepath.Join(tmpDir, ".env.local")
	vars := map[string]string{"KEY": "value"}
	if err := envfile.WriteWithTTL(expiredPath, vars, -1*time.Hour, "test"); err != nil {
		t.Fatalf("failed to create expired file: %v", err)
	}

	// Create watcher pointing to specific file (not directory)
	w := New([]string{expiredPath}, 1*time.Minute)
	wiped, err := w.Check()
	if err != nil {
		t.Fatalf("Check() failed: %v", err)
	}

	// Verify the file was wiped
	if len(wiped) != 1 {
		t.Fatalf("expected 1 wiped file, got %d", len(wiped))
	}

	if wiped[0] != expiredPath {
		t.Errorf("expected wiped file %s, got %s", expiredPath, wiped[0])
	}
}

package store

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestValidateKeyFilePermissions_SecureModes documents that validation accepts
// any mode that denies group and other, not only exactly 0600. Demanding an
// exact match rejected safe files such as 0400 backup copies.
func TestValidateKeyFilePermissions_SecureModes(t *testing.T) {
	if !permissionModeIsMeaningful() {
		t.Skip("permission bits are not enforced on this platform")
	}

	for _, mode := range []os.FileMode{0600, 0400, 0500} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.age")
			if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
				t.Fatalf("failed to create file: %v", err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("failed to chmod: %v", err)
			}

			if err := ValidateKeyFilePermissions(path); err != nil {
				t.Errorf("mode %04o should be accepted, got: %v", mode, err)
			}
		})
	}
}

// TestValidateKeyFilePermissions_RejectsGroupOrOtherAccess checks that the check
// still rejects the modes it exists to catch.
func TestValidateKeyFilePermissions_RejectsGroupOrOtherAccess(t *testing.T) {
	if !permissionModeIsMeaningful() {
		t.Skip("permission bits are not enforced on this platform")
	}

	for _, mode := range []os.FileMode{0644, 0640, 0666, 0604, 0602} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.age")
			if err := os.WriteFile(path, []byte("test"), 0600); err != nil {
				t.Fatalf("failed to create file: %v", err)
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("failed to chmod: %v", err)
			}

			err := ValidateKeyFilePermissions(path)
			if err == nil {
				t.Fatalf("mode %04o must be rejected", mode)
			}
			if !errors.Is(err, ErrKeyPermissionsTooOpen) {
				t.Errorf("error should match ErrKeyPermissionsTooOpen, got: %v", err)
			}
		})
	}
}

// TestValidateKeyFilePermissions_SkippedOnWindows documents that the check is a
// no-op where permission bits do not describe real access control. On Windows
// os.Stat().Mode().Perm() reports 0666 for every file, so enforcing it made the
// daemon reject every store on each restart.
func TestValidateKeyFilePermissions_SkippedOnWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.age")
	if err := os.WriteFile(path, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	err := ValidateKeyFilePermissions(path)
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Errorf("validation must be skipped on Windows, got: %v", err)
		}
		return
	}

	// This test documents intent; on Unix the same file must still be rejected.
	if err == nil {
		t.Error("expected rejection on a non-Windows platform")
	}
}

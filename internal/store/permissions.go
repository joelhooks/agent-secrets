// Package store provides encrypted secret storage using Age encryption.
package store

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// RequiredKeyPermissions is the expected file mode for key files (0600 = owner read/write only)
	RequiredKeyPermissions os.FileMode = 0600
)

// PermissionError represents a file permission security issue.
type PermissionError struct {
	Path     string
	Current  os.FileMode
	Expected os.FileMode
}

func (e *PermissionError) Error() string {
	return fmt.Sprintf(
		"Error: Key file has insecure permissions\n"+
			"  File: %s\n"+
			"  Current: %04o (world-readable!)\n"+
			"  Expected: %04o (owner read/write only)\n\n"+
			"Fix with: chmod %04o %s",
		e.Path,
		e.Current,
		e.Expected,
		e.Expected,
		e.Path,
	)
}

// ValidateKeyFilePermissions checks that a key file has secure permissions (0600).
// Returns a PermissionError if the file has incorrect permissions.
func ValidateKeyFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		// File doesn't exist yet - that's fine, it will be created with correct permissions
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to check permissions for %s: %w", path, err)
	}

	// Get the file mode (permissions)
	mode := info.Mode().Perm()

	// Check if permissions are exactly 0600
	if mode != RequiredKeyPermissions {
		return &PermissionError{
			Path:     path,
			Current:  mode,
			Expected: RequiredKeyPermissions,
		}
	}

	return nil
}

// ValidateAllKeyFiles checks permissions for both identity.age and secrets.age.
// If skipCheck is true, validation is skipped (for edge cases).
func ValidateAllKeyFiles(identityPath, secretsPath string, skipCheck bool) error {
	if skipCheck {
		return nil
	}

	// Validate identity.age
	if err := ValidateKeyFilePermissions(identityPath); err != nil {
		return err
	}

	// Validate secrets.age
	if err := ValidateKeyFilePermissions(secretsPath); err != nil {
		return err
	}

	return nil
}

// EnsureSecurePermissions sets secure permissions on a file after creation.
// This is a helper for ensuring files are created with the correct permissions.
func EnsureSecurePermissions(path string) error {
	// Check if file exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", path)
		}
		return fmt.Errorf("failed to stat file %s: %w", path, err)
	}

	// Set permissions to 0600
	if err := os.Chmod(path, RequiredKeyPermissions); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", filepath.Base(path), err)
	}

	return nil
}

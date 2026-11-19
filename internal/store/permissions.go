// Package store provides encrypted secret storage using Age encryption.
package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// RequiredKeyPermissions is the expected file mode for key files (0600 = owner read/write only)
	RequiredKeyPermissions os.FileMode = 0600
)

// ErrKeyPermissionsTooOpen reports that a key file grants access to group or
// other. It is exported so callers can tell a permissions mismatch apart from
// a genuine read or decrypt failure: the code on disk is fine, only its mode
// is too permissive.
var ErrKeyPermissionsTooOpen = errors.New("key file permissions are too open")

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
			"  Current: %04o (readable or writable by group or other)\n"+
			"  Expected: %04o (owner read/write only)\n\n"+
			"Fix with: chmod %04o %s",
		e.Path,
		e.Current,
		e.Expected,
		e.Expected,
		e.Path,
	)
}

// Unwrap exposes the sentinel so callers can classify this failure with
// errors.Is instead of matching on the concrete type.
func (e *PermissionError) Unwrap() error {
	return ErrKeyPermissionsTooOpen
}

// ValidateKeyFilePermissions checks that a key file has secure permissions (0600).
// Returns a PermissionError if the file has incorrect permissions.
func ValidateKeyFilePermissions(path string) error {
	if !permissionModeIsMeaningful() {
		// Permission bits do not describe the real access control on this
		// platform, so there is nothing meaningful to validate.
		return nil
	}

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

	// Reject anything readable or writable by group or other. A stricter mode
	// such as 0400 or 0500 is fine, so this must not demand exactly 0600: doing
	// so rejected perfectly safe files (and, on Windows, every file, because
	// os.Stat().Mode().Perm() there reports 0666).
	if mode&0077 != 0 {
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

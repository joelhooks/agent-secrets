package envfile

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// EnvFile represents a .env file with TTL metadata
type EnvFile struct {
	Path      string
	ExpiresAt time.Time
	Source    string
	Vars      map[string]string
}

const (
	managedHeader = "# secrets-managed: true"
	ttlPrefix     = "# secrets-ttl: "
	sourcePrefix  = "# secrets-source: "
)

// WriteWithTTL writes an .env file with TTL metadata header
func WriteWithTTL(path string, vars map[string]string, ttl time.Duration, source string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	expiresAt := time.Now().Add(ttl)

	// Write metadata header
	if _, err := fmt.Fprintln(f, managedHeader); err != nil {
		return fmt.Errorf("write managed header: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%s%s\n", ttlPrefix, expiresAt.Format(time.RFC3339)); err != nil {
		return fmt.Errorf("write ttl header: %w", err)
	}
	if source != "" {
		if _, err := fmt.Fprintf(f, "%s%s\n", sourcePrefix, source); err != nil {
			return fmt.Errorf("write source header: %w", err)
		}
	}

	// Write environment variables
	for key, value := range vars {
		if _, err := fmt.Fprintf(f, "%s=%s\n", key, value); err != nil {
			return fmt.Errorf("write var %s: %w", key, err)
		}
	}

	return nil
}

// Read parses an .env file including TTL metadata
func Read(path string) (*EnvFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	envFile := &EnvFile{
		Path: path,
		Vars: make(map[string]string),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Parse TTL header
		if strings.HasPrefix(line, ttlPrefix) {
			ttlStr := strings.TrimPrefix(line, ttlPrefix)
			expiresAt, err := time.Parse(time.RFC3339, ttlStr)
			if err != nil {
				return nil, fmt.Errorf("parse ttl: %w", err)
			}
			envFile.ExpiresAt = expiresAt
			continue
		}

		// Parse source header
		if strings.HasPrefix(line, sourcePrefix) {
			envFile.Source = strings.TrimPrefix(line, sourcePrefix)
			continue
		}

		// Skip other comment lines
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			envFile.Vars[parts[0]] = parts[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan file: %w", err)
	}

	return envFile, nil
}

// IsExpired checks if a file's TTL has passed
func IsExpired(path string) (bool, error) {
	envFile, err := Read(path)
	if err != nil {
		return false, err
	}

	// If no TTL was set, consider it not expired
	if envFile.ExpiresAt.IsZero() {
		return false, nil
	}

	return time.Now().After(envFile.ExpiresAt), nil
}

// Wipe removes the .env file securely
func Wipe(path string) error {
	// For now, just remove the file
	// Future: consider secure deletion (overwrite before delete)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove file: %w", err)
	}
	return nil
}

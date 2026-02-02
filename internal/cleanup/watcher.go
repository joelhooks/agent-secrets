package cleanup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/joelhooks/agent-secrets/internal/envfile"
)

// Watcher monitors directories for expired .env files
type Watcher struct {
	paths    []string
	interval time.Duration
	stopCh   chan struct{}
}

// New creates a new Watcher for the given paths with the specified check interval
func New(paths []string, interval time.Duration) *Watcher {
	return &Watcher{
		paths:    paths,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Check scans all configured paths for expired .env files and wipes them.
// Returns a slice of wiped file paths.
func (w *Watcher) Check() ([]string, error) {
	var wiped []string

	for _, basePath := range w.paths {
		// Check if path exists
		info, err := os.Stat(basePath)
		if err != nil {
			if os.IsNotExist(err) {
				continue // Skip non-existent paths
			}
			return wiped, fmt.Errorf("stat %s: %w", basePath, err)
		}

		// If it's a file, check it directly
		if !info.IsDir() {
			if shouldWipe, err := w.checkFile(basePath); err != nil {
				return wiped, err
			} else if shouldWipe {
				if err := envfile.Wipe(basePath); err != nil {
					return wiped, fmt.Errorf("wipe %s: %w", basePath, err)
				}
				wiped = append(wiped, basePath)
			}
			continue
		}

		// Walk directory to find .env files
		err = filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip directories
			if info.IsDir() {
				return nil
			}

			// Only process .env files
			if filepath.Base(path) != ".env.local" && filepath.Base(path) != ".env" {
				return nil
			}

			shouldWipe, err := w.checkFile(path)
			if err != nil {
				return err
			}

			if shouldWipe {
				if err := envfile.Wipe(path); err != nil {
					return fmt.Errorf("wipe %s: %w", path, err)
				}
				wiped = append(wiped, path)
			}

			return nil
		})

		if err != nil {
			return wiped, fmt.Errorf("walk %s: %w", basePath, err)
		}
	}

	return wiped, nil
}

// checkFile determines if a file should be wiped based on TTL expiration
func (w *Watcher) checkFile(path string) (bool, error) {
	expired, err := envfile.IsExpired(path)
	if err != nil {
		// If file can't be read or parsed, don't wipe it
		return false, nil
	}
	return expired, nil
}

// Start begins the background cleanup loop with the configured interval.
// It blocks until the context is cancelled or Stop is called.
func (w *Watcher) Start(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Run initial check immediately
	w.Check()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.Check()
		}
	}
}

// Stop signals the watcher to stop its background loop
func (w *Watcher) Stop() {
	close(w.stopCh)
}

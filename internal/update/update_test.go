package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadCache(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(dir string) error
		wantCache *UpdateCheckCache
		wantErr   bool
	}{
		{
			name: "valid cache file",
			setup: func(dir string) error {
				cache := &UpdateCheckCache{
					LatestVersion:   "v0.2.0",
					CurrentVersion:  "v0.1.0",
					CheckedAt:       time.Now().Add(-1 * time.Hour),
					UpdateAvailable: true,
				}
				data, err := json.Marshal(cache)
				if err != nil {
					return err
				}
				return os.WriteFile(filepath.Join(dir, DefaultUpdateCheckFile), data, 0644)
			},
			wantCache: &UpdateCheckCache{
				LatestVersion:   "v0.2.0",
				CurrentVersion:  "v0.1.0",
				UpdateAvailable: true,
			},
			wantErr: false,
		},
		{
			name: "missing cache file returns nil",
			setup: func(dir string) error {
				// Don't create file
				return nil
			},
			wantCache: nil,
			wantErr:   false,
		},
		{
			name: "invalid JSON returns error",
			setup: func(dir string) error {
				return os.WriteFile(
					filepath.Join(dir, DefaultUpdateCheckFile),
					[]byte("{invalid json"),
					0644,
				)
			},
			wantCache: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if err := tt.setup(dir); err != nil {
				t.Fatalf("setup failed: %v", err)
			}

			got, err := LoadCache(dir)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantCache == nil {
				if got != nil {
					t.Errorf("LoadCache() = %v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatal("LoadCache() returned nil, expected cache")
			}

			// Compare fields (ignore CheckedAt since it varies)
			if got.LatestVersion != tt.wantCache.LatestVersion {
				t.Errorf("LatestVersion = %v, want %v", got.LatestVersion, tt.wantCache.LatestVersion)
			}
			if got.CurrentVersion != tt.wantCache.CurrentVersion {
				t.Errorf("CurrentVersion = %v, want %v", got.CurrentVersion, tt.wantCache.CurrentVersion)
			}
			if got.UpdateAvailable != tt.wantCache.UpdateAvailable {
				t.Errorf("UpdateAvailable = %v, want %v", got.UpdateAvailable, tt.wantCache.UpdateAvailable)
			}
		})
	}
}

func TestSaveCache(t *testing.T) {
	tests := []struct {
		name    string
		cache   *UpdateCheckCache
		wantErr bool
	}{
		{
			name: "valid cache saves successfully",
			cache: &UpdateCheckCache{
				LatestVersion:   "v0.2.0",
				CurrentVersion:  "v0.1.0",
				CheckedAt:       time.Now(),
				UpdateAvailable: true,
			},
			wantErr: false,
		},
		{
			name: "cache with no update available",
			cache: &UpdateCheckCache{
				LatestVersion:   "v0.1.0",
				CurrentVersion:  "v0.1.0",
				CheckedAt:       time.Now(),
				UpdateAvailable: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			err := SaveCache(dir, tt.cache)
			if (err != nil) != tt.wantErr {
				t.Errorf("SaveCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify file was created
			cachePath := filepath.Join(dir, DefaultUpdateCheckFile)
			if _, err := os.Stat(cachePath); os.IsNotExist(err) {
				t.Error("SaveCache() did not create cache file")
				return
			}

			// Verify content is valid JSON
			data, err := os.ReadFile(cachePath)
			if err != nil {
				t.Fatalf("failed to read saved cache: %v", err)
			}

			var loaded UpdateCheckCache
			if err := json.Unmarshal(data, &loaded); err != nil {
				t.Errorf("saved cache is not valid JSON: %v", err)
				return
			}

			// Verify fields match
			if loaded.LatestVersion != tt.cache.LatestVersion {
				t.Errorf("LatestVersion = %v, want %v", loaded.LatestVersion, tt.cache.LatestVersion)
			}
			if loaded.CurrentVersion != tt.cache.CurrentVersion {
				t.Errorf("CurrentVersion = %v, want %v", loaded.CurrentVersion, tt.cache.CurrentVersion)
			}
			if loaded.UpdateAvailable != tt.cache.UpdateAvailable {
				t.Errorf("UpdateAvailable = %v, want %v", loaded.UpdateAvailable, tt.cache.UpdateAvailable)
			}
		})
	}
}

func TestCacheExpiration(t *testing.T) {
	tests := []struct {
		name       string
		checkedAt  time.Time
		wantFresh  bool
		description string
	}{
		{
			name:       "fresh cache (1 hour ago)",
			checkedAt:  time.Now().Add(-1 * time.Hour),
			wantFresh:  true,
			description: "Cache checked 1 hour ago should be considered fresh",
		},
		{
			name:       "fresh cache (23 hours ago)",
			checkedAt:  time.Now().Add(-23 * time.Hour),
			wantFresh:  true,
			description: "Cache checked 23 hours ago should be considered fresh",
		},
		{
			name:       "expired cache (25 hours ago)",
			checkedAt:  time.Now().Add(-25 * time.Hour),
			wantFresh:  false,
			description: "Cache checked 25 hours ago should be considered expired",
		},
		{
			name:       "expired cache (48 hours ago)",
			checkedAt:  time.Now().Add(-48 * time.Hour),
			wantFresh:  false,
			description: "Cache checked 48 hours ago should be considered expired",
		},
		{
			name:       "just created cache",
			checkedAt:  time.Now(),
			wantFresh:  true,
			description: "Freshly created cache should be considered fresh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &UpdateCheckCache{
				LatestVersion:   "v0.2.0",
				CurrentVersion:  "v0.1.0",
				CheckedAt:       tt.checkedAt,
				UpdateAvailable: true,
			}

			// Calculate if cache is fresh (same logic as CheckForUpdate)
			isFresh := time.Since(cache.CheckedAt) < CacheDuration

			if isFresh != tt.wantFresh {
				t.Errorf("%s: got fresh=%v, want %v (age=%v, duration=%v)",
					tt.description,
					isFresh,
					tt.wantFresh,
					time.Since(cache.CheckedAt),
					CacheDuration,
				)
			}
		})
	}
}

func TestSaveCacheAtomicWrite(t *testing.T) {
	t.Run("atomic write prevents corruption", func(t *testing.T) {
		dir := t.TempDir()

		cache := &UpdateCheckCache{
			LatestVersion:   "v0.2.0",
			CurrentVersion:  "v0.1.0",
			CheckedAt:       time.Now(),
			UpdateAvailable: true,
		}

		// Save cache
		if err := SaveCache(dir, cache); err != nil {
			t.Fatalf("SaveCache() failed: %v", err)
		}

		// Verify no temp files left behind
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("failed to read dir: %v", err)
		}

		for _, entry := range entries {
			if entry.Name() != DefaultUpdateCheckFile {
				t.Errorf("found unexpected file: %s", entry.Name())
			}
		}
	})
}

func TestLoadCacheRoundTrip(t *testing.T) {
	t.Run("save and load cache preserves data", func(t *testing.T) {
		dir := t.TempDir()

		original := &UpdateCheckCache{
			LatestVersion:   "v0.3.0",
			CurrentVersion:  "v0.2.0",
			CheckedAt:       time.Now().Round(time.Second), // Round to avoid precision issues
			UpdateAvailable: true,
		}

		// Save
		if err := SaveCache(dir, original); err != nil {
			t.Fatalf("SaveCache() failed: %v", err)
		}

		// Load
		loaded, err := LoadCache(dir)
		if err != nil {
			t.Fatalf("LoadCache() failed: %v", err)
		}

		if loaded == nil {
			t.Fatal("LoadCache() returned nil")
		}

		// Compare all fields
		if loaded.LatestVersion != original.LatestVersion {
			t.Errorf("LatestVersion = %v, want %v", loaded.LatestVersion, original.LatestVersion)
		}
		if loaded.CurrentVersion != original.CurrentVersion {
			t.Errorf("CurrentVersion = %v, want %v", loaded.CurrentVersion, original.CurrentVersion)
		}
		if loaded.UpdateAvailable != original.UpdateAvailable {
			t.Errorf("UpdateAvailable = %v, want %v", loaded.UpdateAvailable, original.UpdateAvailable)
		}

		// Check timestamp is within 1 second (JSON marshaling may affect precision)
		timeDiff := loaded.CheckedAt.Sub(original.CheckedAt)
		if timeDiff < -time.Second || timeDiff > time.Second {
			t.Errorf("CheckedAt = %v, want %v (diff: %v)", loaded.CheckedAt, original.CheckedAt, timeDiff)
		}
	})
}

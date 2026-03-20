package update

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/output"
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func installMockHTTPClient(t *testing.T, rt roundTripFunc) {
	t.Helper()

	mockClient := &http.Client{Transport: rt}

	prev := http.DefaultClient
	prevHTTP := httpClient
	prevDL := downloadClient

	http.DefaultClient = mockClient
	httpClient = mockClient
	downloadClient = mockClient

	t.Cleanup(func() {
		http.DefaultClient = prev
		httpClient = prevHTTP
		downloadClient = prevDL
	})
}

func setupHomeConfigDir(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)

	configDir := filepath.Join(home, ".agent-secrets")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	return configDir
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestCheckForUpdate(t *testing.T) {
	t.Run("dev build skips update checks", func(t *testing.T) {
		info, err := CheckForUpdate("dev")
		if err != nil {
			t.Fatalf("CheckForUpdate(dev) returned error: %v", err)
		}
		if info != nil {
			t.Fatalf("CheckForUpdate(dev) = %+v, want nil", info)
		}
	})

	t.Run("fresh cache is used without network call", func(t *testing.T) {
		configDir := setupHomeConfigDir(t)

		cached := &UpdateCheckCache{
			LatestVersion:   "v9.9.9",
			CurrentVersion:  "v1.0.0",
			CheckedAt:       time.Now().Add(-1 * time.Hour),
			UpdateAvailable: true,
		}
		if err := SaveCache(configDir, cached); err != nil {
			t.Fatalf("SaveCache() failed: %v", err)
		}

		var calls atomic.Int32
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			calls.Add(1)
			t.Fatalf("unexpected network call to %s", req.URL.String())
			return nil, nil
		})

		info, err := CheckForUpdate("v1.0.0")
		if err != nil {
			t.Fatalf("CheckForUpdate() returned error: %v", err)
		}
		if info == nil {
			t.Fatal("CheckForUpdate() returned nil info")
		}
		if !info.Available {
			t.Fatalf("Available = false, want true")
		}
		if info.LatestVersion != "v9.9.9" {
			t.Fatalf("LatestVersion = %q, want v9.9.9", info.LatestVersion)
		}
		if info.Command != "secrets self-update" {
			t.Fatalf("Command = %q, want secrets self-update", info.Command)
		}
		if calls.Load() != 0 {
			t.Fatalf("network calls = %d, want 0", calls.Load())
		}
	})

	t.Run("stale cache refreshes from API and saves new cache", func(t *testing.T) {
		configDir := setupHomeConfigDir(t)

		stale := &UpdateCheckCache{
			LatestVersion:   "v0.9.0",
			CurrentVersion:  "v1.0.0",
			CheckedAt:       time.Now().Add(-25 * time.Hour),
			UpdateAvailable: false,
		}
		if err := SaveCache(configDir, stale); err != nil {
			t.Fatalf("SaveCache() failed: %v", err)
		}

		var calls atomic.Int32
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			calls.Add(1)
			if req.URL.String() != apiURL {
				t.Fatalf("request URL = %q, want %q", req.URL.String(), apiURL)
			}
			return response(http.StatusOK, `{"tag_name":"v1.2.0","assets":[]}`), nil
		})

		info, err := CheckForUpdate("v1.0.0")
		if err != nil {
			t.Fatalf("CheckForUpdate() returned error: %v", err)
		}
		if info == nil {
			t.Fatal("CheckForUpdate() returned nil info")
		}
		if !info.Available {
			t.Fatalf("Available = false, want true")
		}
		if info.LatestVersion != "v1.2.0" {
			t.Fatalf("LatestVersion = %q, want v1.2.0", info.LatestVersion)
		}
		if calls.Load() != 1 {
			t.Fatalf("network calls = %d, want 1", calls.Load())
		}

		updated, err := LoadCache(configDir)
		if err != nil {
			t.Fatalf("LoadCache() returned error: %v", err)
		}
		if updated == nil {
			t.Fatal("LoadCache() returned nil cache")
		}
		if updated.LatestVersion != "v1.2.0" {
			t.Fatalf("cache LatestVersion = %q, want v1.2.0", updated.LatestVersion)
		}
		if !updated.UpdateAvailable {
			t.Fatalf("cache UpdateAvailable = false, want true")
		}
	})

	t.Run("version comparison treats v-prefix and non-prefix as equal", func(t *testing.T) {
		tests := []string{"v1.2.3", "1.2.3"}
		for _, current := range tests {
			current := current
			t.Run(current, func(t *testing.T) {
				setupHomeConfigDir(t)
				installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
					return response(http.StatusOK, `{"tag_name":"v1.2.3","assets":[]}`), nil
				})

				info, err := CheckForUpdate(current)
				if err != nil {
					t.Fatalf("CheckForUpdate() returned error: %v", err)
				}
				if info == nil {
					t.Fatal("CheckForUpdate() returned nil info")
				}
				if info.Available {
					t.Fatalf("Available = true, want false for current version %q", current)
				}
			})
		}
	})
}

func TestGetLatestRelease(t *testing.T) {
	t.Run("returns parsed release and sets user-agent header", func(t *testing.T) {
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("User-Agent") != repoName+"-cli" {
				t.Fatalf("User-Agent = %q, want %q", req.Header.Get("User-Agent"), repoName+"-cli")
			}
			return response(http.StatusOK, `{"tag_name":"v3.1.4","assets":[{"name":"asset","browser_download_url":"https://example.com/a"}],"html_url":"https://example.com/release"}`), nil
		})

		release, err := getLatestRelease()
		if err != nil {
			t.Fatalf("getLatestRelease() returned error: %v", err)
		}
		if release.TagName != "v3.1.4" {
			t.Fatalf("TagName = %q, want v3.1.4", release.TagName)
		}
		if len(release.Assets) != 1 || release.Assets[0].BrowserDownloadURL != "https://example.com/a" {
			t.Fatalf("Assets parsed incorrectly: %+v", release.Assets)
		}
	})

	t.Run("returns error when API status is non-200", func(t *testing.T) {
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			return response(http.StatusInternalServerError, `{"message":"boom"}`), nil
		})

		_, err := getLatestRelease()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "status 500") {
			t.Fatalf("error = %q, want to contain status 500", err.Error())
		}
	})

	t.Run("returns error when JSON is invalid", func(t *testing.T) {
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			return response(http.StatusOK, "{not json"), nil
		})

		_, err := getLatestRelease()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestDownloadBinary(t *testing.T) {
	t.Run("downloads and writes file contents", func(t *testing.T) {
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != "https://example.com/bin" {
				t.Fatalf("request URL = %q, want https://example.com/bin", req.URL.String())
			}
			return response(http.StatusOK, "binary-bytes"), nil
		})

		path, err := downloadBinary("https://example.com/bin")
		if err != nil {
			t.Fatalf("downloadBinary() returned error: %v", err)
		}
		defer os.Remove(path)

		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read downloaded file: %v", err)
		}
		if string(content) != "binary-bytes" {
			t.Fatalf("downloaded content = %q, want binary-bytes", string(content))
		}
	})

	t.Run("returns error when download status is non-200", func(t *testing.T) {
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			return response(http.StatusNotFound, "missing"), nil
		})

		_, err := downloadBinary("https://example.com/missing")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "status 404") {
			t.Fatalf("error = %q, want to contain status 404", err.Error())
		}
	})
}

func TestDoUpdate(t *testing.T) {
	t.Run("rejects dev builds", func(t *testing.T) {
		err := DoUpdate("dev")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "cannot update dev build") {
			t.Fatalf("error = %q, want to contain dev build", err.Error())
		}
	})

	t.Run("returns already latest when versions match", func(t *testing.T) {
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			return response(http.StatusOK, `{"tag_name":"v1.2.3","assets":[]}`), nil
		})

		err := DoUpdate("v1.2.3")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "already at latest version") {
			t.Fatalf("error = %q, want already latest", err.Error())
		}
	})

	t.Run("returns error when release has no binary for current platform", func(t *testing.T) {
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			return response(http.StatusOK, `{"tag_name":"v2.0.0","assets":[{"name":"secrets_2.0.0_other_other","browser_download_url":"https://example.com/bin"}]}`), nil
		})

		err := DoUpdate("v1.0.0")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "no binary found") {
			t.Fatalf("error = %q, want no binary found", err.Error())
		}
	})

	t.Run("returns error when binary download fails", func(t *testing.T) {
		assetName := "secrets_2.0.0_" + runtime.GOOS + "_" + runtime.GOARCH

		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			switch req.URL.String() {
			case apiURL:
				return response(http.StatusOK, `{"tag_name":"v2.0.0","assets":[{"name":"`+assetName+`","browser_download_url":"https://example.com/bin"}]}`), nil
			case "https://example.com/bin":
				return response(http.StatusBadGateway, "bad gateway"), nil
			default:
				t.Fatalf("unexpected URL: %s", req.URL.String())
				return nil, nil
			}
		})

		err := DoUpdate("v1.0.0")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to download binary") {
			t.Fatalf("error = %q, want failed to download binary", err.Error())
		}
	})
}

func TestCheckForUpdateInBackground(t *testing.T) {
	setupHomeConfigDir(t)

	done := make(chan struct{}, 1)
	installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
		time.Sleep(200 * time.Millisecond)
		select {
		case done <- struct{}{}:
		default:
		}
		return response(http.StatusOK, `{"tag_name":"v9.0.0","assets":[]}`), nil
	})

	start := time.Now()
	CheckForUpdateInBackground("v1.0.0")
	elapsed := time.Since(start)
	if elapsed > 50*time.Millisecond {
		t.Fatalf("background update check blocked for %v", elapsed)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("background update check did not execute")
	}
}

func TestUpdateMetadataAccessors(t *testing.T) {
	prevVersion := output.Version
	prevCommit := output.Commit
	prevBuildDate := output.BuildDate
	t.Cleanup(func() {
		output.Version = prevVersion
		output.Commit = prevCommit
		output.BuildDate = prevBuildDate
	})

	output.Version = "v1.2.3"
	output.Commit = "abc123"
	output.BuildDate = "2026-02-19T00:00:00Z"

	if got := GetVersion(); got != "v1.2.3" {
		t.Fatalf("GetVersion() = %q, want v1.2.3", got)
	}
	if got := GetCommit(); got != "abc123" {
		t.Fatalf("GetCommit() = %q, want abc123", got)
	}
	if got := GetBuildDate(); got != "2026-02-19T00:00:00Z" {
		t.Fatalf("GetBuildDate() = %q, want 2026-02-19T00:00:00Z", got)
	}

	info := VersionInfo()
	if info["version"] != "v1.2.3" || info["commit"] != "abc123" || info["build_date"] != "2026-02-19T00:00:00Z" {
		t.Fatalf("VersionInfo() missing expected values: %+v", info)
	}
	if info["os"] != runtime.GOOS || info["arch"] != runtime.GOARCH {
		t.Fatalf("VersionInfo() platform mismatch: %+v", info)
	}
}

func TestSelfReplace(t *testing.T) {
	newBinary := filepath.Join(t.TempDir(), "secrets-new")
	if err := os.WriteFile(newBinary, []byte("binary"), 0644); err != nil {
		t.Fatalf("failed to create fake binary: %v", err)
	}

	// Ensure "sudo" is not found so the command fails fast and predictably.
	t.Setenv("PATH", t.TempDir())

	err := SelfReplace(newBinary)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to replace binary with sudo") {
		t.Fatalf("error = %q, want sudo replacement failure", err.Error())
	}
}

func TestAdditionalErrorBranches(t *testing.T) {
	t.Run("save cache fails when config dir is missing", func(t *testing.T) {
		cache := &UpdateCheckCache{LatestVersion: "v1.0.0", CurrentVersion: "v0.9.0", CheckedAt: time.Now()}
		missingDir := filepath.Join(t.TempDir(), "missing-dir")
		if err := SaveCache(missingDir, cache); err == nil {
			t.Fatal("expected SaveCache error for missing dir")
		}
	})

	t.Run("getLatestRelease propagates transport errors", func(t *testing.T) {
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("transport unavailable")
		})
		if _, err := getLatestRelease(); err == nil {
			t.Fatal("expected getLatestRelease error")
		}
	})

	t.Run("downloadBinary propagates transport errors", func(t *testing.T) {
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})
		if _, err := downloadBinary("https://example.com/bin"); err == nil {
			t.Fatal("expected downloadBinary error")
		}
	})

	t.Run("check for update returns API errors", func(t *testing.T) {
		setupHomeConfigDir(t)
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("api unavailable")
		})
		if _, err := CheckForUpdate("v1.0.0"); err == nil {
			t.Fatal("expected CheckForUpdate error")
		}
	})

	t.Run("do update returns release lookup errors", func(t *testing.T) {
		installMockHTTPClient(t, func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("api unavailable")
		})
		if err := DoUpdate("v1.0.0"); err == nil {
			t.Fatal("expected DoUpdate error")
		}
	})
}

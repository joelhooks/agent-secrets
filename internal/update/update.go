// Package update provides self-update functionality for the CLI.
package update

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/joelhooks/agent-secrets/internal/output"
)

const (
	repoOwner = "joelhooks"
	repoName  = "agent-secrets"
	apiURL    = "https://api.github.com/repos/joelhooks/agent-secrets/releases/latest"
)

// ReleaseInfo represents GitHub release information
type ReleaseInfo struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
	HTMLURL string  `json:"html_url"`
}

// Asset represents a release asset
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// CheckForUpdate checks if a newer version is available
func CheckForUpdate(currentVersion string) (*output.UpdateInfo, error) {
	if currentVersion == "dev" {
		return nil, nil // Skip update check for dev builds
	}

	latest, err := getLatestRelease()
	if err != nil {
		return nil, err
	}

	// Strip 'v' prefix for comparison
	latestVersion := strings.TrimPrefix(latest.TagName, "v")
	current := strings.TrimPrefix(currentVersion, "v")

	if latestVersion != current {
		return &output.UpdateInfo{
			Available:      true,
			CurrentVersion: currentVersion,
			LatestVersion:  latest.TagName,
			Command:        "secrets update",
		}, nil
	}

	return &output.UpdateInfo{
		Available:      false,
		CurrentVersion: currentVersion,
	}, nil
}

// DoUpdate performs the self-update
func DoUpdate(currentVersion string) error {
	if currentVersion == "dev" {
		return fmt.Errorf("cannot update dev build")
	}

	latest, err := getLatestRelease()
	if err != nil {
		return fmt.Errorf("failed to fetch latest release: %w", err)
	}

	// Strip 'v' prefix for comparison
	latestVersion := strings.TrimPrefix(latest.TagName, "v")
	current := strings.TrimPrefix(currentVersion, "v")

	if latestVersion == current {
		return fmt.Errorf("already at latest version %s", currentVersion)
	}

	// Find the asset for current OS/arch
	assetName := fmt.Sprintf("secrets_%s_%s_%s", strings.TrimPrefix(latest.TagName, "v"), runtime.GOOS, runtime.GOARCH)
	var downloadURL string

	for _, asset := range latest.Assets {
		if strings.Contains(asset.Name, assetName) {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("no binary found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	// Download the new binary
	tmpFile, err := downloadBinary(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download binary: %w", err)
	}
	defer os.Remove(tmpFile)

	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Resolve symlinks
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// Make the new binary executable
	if err := os.Chmod(tmpFile, 0755); err != nil {
		return fmt.Errorf("failed to make binary executable: %w", err)
	}

	// Replace the current binary
	// On Unix systems, we can replace the running binary
	if err := os.Rename(tmpFile, exePath); err != nil {
		return fmt.Errorf("failed to replace binary: %w (may need sudo)", err)
	}

	return nil
}

func getLatestRelease() (*ReleaseInfo, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	// Set User-Agent to avoid rate limiting
	req.Header.Set("User-Agent", fmt.Sprintf("%s-cli", repoName))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	return &release, nil
}

func downloadBinary(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Create temp file
	tmpFile, err := os.CreateTemp("", "secrets-update-*")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// Copy the downloaded data
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}

// GetVersion returns the current version (from ldflags)
func GetVersion() string {
	return output.Version
}

// GetCommit returns the current commit (from ldflags)
func GetCommit() string {
	return output.Commit
}

// VersionInfo returns structured version information
func VersionInfo() map[string]interface{} {
	return map[string]interface{}{
		"version": GetVersion(),
		"commit":  GetCommit(),
		"go":      runtime.Version(),
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
	}
}

// CheckForUpdateInBackground runs update check asynchronously and prints warning
func CheckForUpdateInBackground(currentVersion string) {
	go func() {
		info, err := CheckForUpdate(currentVersion)
		if err != nil || info == nil || !info.Available {
			return
		}

		// Only print in human mode
		if output.HumanMode {
			fmt.Fprintf(os.Stderr, "\n⚠ Update available: %s → %s\n", info.CurrentVersion, info.LatestVersion)
			fmt.Fprintf(os.Stderr, "  Run: %s\n\n", info.Command)
		}
	}()
}

// SelfReplace replaces the current binary with a new one
// This is a fallback for systems where os.Rename fails due to permissions
func SelfReplace(newBinaryPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// Try to use sudo if we don't have permissions
	cmd := exec.Command("sudo", "mv", newBinaryPath, exePath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to replace binary with sudo: %w", err)
	}

	return nil
}

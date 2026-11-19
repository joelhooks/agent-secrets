package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// TestEnvRunE_StoreBackedConfig is a regression test for:
//
//	secrets env -> "failed to find project config: project config: source cannot be empty"
//
// when run in a directory containing a documented, store-backed .secrets.json.
func TestEnvRunE_StoreBackedConfig(t *testing.T) {
	projectDir := t.TempDir()
	config := `{
  "secrets": [
    {"name": "github_token", "env_var": "GITHUB_TOKEN"},
    {"name": "stripe_key", "env_var": "STRIPE_SECRET_KEY", "ttl": "30m"}
  ],
  "client_id": "deploy-task"
}`
	if err := os.WriteFile(filepath.Join(projectDir, ".secrets.json"), []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	socket, leaseCount := startEnvLeaseServer(t, map[string]string{
		"github_token": "gh-value",
		"stripe_key":   "stripe-value",
	}, expiresAt)

	restore := setEnvTestGlobals(socket, projectDir)
	defer restore()

	out := captureEnvStdout(t, func() {
		if err := envCmd.RunE(envCmd, nil); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})

	// The original bug reported this exact error message
	if strings.Contains(out, "source cannot be empty") {
		t.Fatalf("store-backed config still rejected: %s", out)
	}

	var resp struct {
		OK     bool `json:"ok"`
		Result struct {
			Mode     string   `json:"mode"`
			EnvFile  string   `json:"env_file"`
			Vars     []string `json:"vars"`
			VarCount int      `json:"var_count"`
			Leases   []struct {
				Secret    string `json:"secret"`
				EnvVar    string `json:"env_var"`
				LeaseID   string `json:"lease_id"`
				ExpiresAt string `json:"expires_at"`
			} `json:"leases"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("expected JSON output, got decode error: %v\noutput: %s", err, out)
	}
	if !resp.OK {
		t.Fatalf("expected ok=true, got false. output: %s", out)
	}
	if resp.Result.Mode != "store" {
		t.Errorf("Mode = %q, want %q", resp.Result.Mode, "store")
	}
	if resp.Result.VarCount != 2 {
		t.Errorf("VarCount = %d, want 2", resp.Result.VarCount)
	}
	if got := resp.Result.Vars; len(got) != 2 || got[0] != "GITHUB_TOKEN" || got[1] != "STRIPE_SECRET_KEY" {
		t.Errorf("Vars = %v, want [GITHUB_TOKEN STRIPE_SECRET_KEY] in config order", got)
	}
	if len(resp.Result.Leases) != 2 {
		t.Fatalf("Leases length = %d, want 2", len(resp.Result.Leases))
	}
	for i, want := range []string{"github_token", "stripe_key"} {
		if resp.Result.Leases[i].Secret != want {
			t.Errorf("Leases[%d].Secret = %q, want %q", i, resp.Result.Leases[i].Secret, want)
		}
		if resp.Result.Leases[i].LeaseID == "" {
			t.Errorf("Leases[%d].LeaseID is empty", i)
		}
	}

	// Secret values must never appear in the JSON envelope
	if strings.Contains(out, "gh-value") || strings.Contains(out, "stripe-value") {
		t.Errorf("secret values leaked into CLI output: %s", out)
	}

	if got := leaseCount(); got != 2 {
		t.Errorf("expected 2 lease RPC calls, got %d", got)
	}

	// The env file must be the documented store-backed default
	envPath := filepath.Join(projectDir, ".env")
	if resp.Result.EnvFile != envPath {
		t.Errorf("EnvFile = %q, want %q", resp.Result.EnvFile, envPath)
	}

	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatalf("env file was not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("env file permissions = %o, want 600", perm)
	}

	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read env file: %v", err)
	}
	content := string(data)

	for _, want := range []string{
		"GITHUB_TOKEN=gh-value",
		"STRIPE_SECRET_KEY=stripe-value",
		"# secrets-managed: true",
		"# secrets-ttl:",
		"# secrets-source: store",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("env file missing %q. content:\n%s", want, content)
		}
	}
}

// TestEnvRunE_StoreBackedMissingSecretFails ensures a lease failure is reported
// with an actionable fix instead of a generic error.
func TestEnvRunE_StoreBackedMissingSecretFails(t *testing.T) {
	projectDir := t.TempDir()
	config := `{"secrets": [{"name": "missing", "env_var": "MISSING"}]}`
	if err := os.WriteFile(filepath.Join(projectDir, ".secrets.json"), []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// Point at a socket that does not exist to simulate an unreachable daemon
	restore := setEnvTestGlobals(filepath.Join(t.TempDir(), "missing.sock"), projectDir)
	defer restore()

	out := captureEnvStdout(t, func() {
		if err := envCmd.RunE(envCmd, nil); err == nil {
			t.Fatal("RunE expected error, got nil")
		}
	})

	var resp struct {
		OK  bool   `json:"ok"`
		Fix string `json:"fix"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("expected JSON output, got decode error: %v\noutput: %s", err, out)
	}
	if resp.OK {
		t.Error("expected ok=false")
	}
	if !strings.Contains(resp.Fix, "secrets serve") {
		t.Errorf("expected fix to mention starting the daemon, got %q", resp.Fix)
	}
	if _, err := os.Stat(filepath.Join(projectDir, ".env")); err == nil {
		t.Error("env file should not be written when leasing fails")
	}
}

// TestEnvRunE_StoreBackedUnknownSecretFix ensures a missing secret is reported
// with a secret-listing fix rather than the daemon fix.
func TestEnvRunE_StoreBackedUnknownSecretFix(t *testing.T) {
	projectDir := t.TempDir()
	config := `{"secrets": [{"name": "does_not_exist", "env_var": "X"}]}`
	if err := os.WriteFile(filepath.Join(projectDir, ".secrets.json"), []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	// A reachable daemon that reports the secret is missing
	socket, _ := startEnvLeaseServer(t, map[string]string{"other": "value"}, time.Now().Add(time.Hour))
	restore := setEnvTestGlobals(socket, projectDir)
	defer restore()

	out := captureEnvStdout(t, func() {
		if err := envCmd.RunE(envCmd, nil); err == nil {
			t.Fatal("RunE expected error, got nil")
		}
	})

	var resp struct {
		OK  bool   `json:"ok"`
		Fix string `json:"fix"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("expected JSON output, got decode error: %v\noutput: %s", err, out)
	}
	if !strings.Contains(resp.Fix, "secrets list") {
		t.Errorf("expected fix to suggest listing secrets, got %q", resp.Fix)
	}
	if strings.Contains(resp.Fix, "serve") {
		t.Errorf("missing secret must not be reported as a stopped daemon, got %q", resp.Fix)
	}
}

// TestEnvRunEDryRunReportsPerEntryTTL ensures the preview shows the TTL each
// secret will actually be leased with, matching the real path's precedence.
func TestEnvRunEDryRunReportsPerEntryTTL(t *testing.T) {
	projectDir := t.TempDir()
	config := `{
  "secrets": [
    {"name": "a", "env_var": "A", "ttl": "30m"},
    {"name": "b", "env_var": "B"}
  ],
  "ttl": "2h"
}`
	if err := os.WriteFile(filepath.Join(projectDir, ".secrets.json"), []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	restore := setEnvTestGlobals(filepath.Join(t.TempDir(), "unused.sock"), projectDir)
	defer restore()

	restoreDryRun := setEnvDryRun(t, true)
	defer restoreDryRun()

	var resp struct {
		OK     bool `json:"ok"`
		Result struct {
			Secrets []struct {
				EnvVar string `json:"env_var"`
				TTL    string `json:"ttl"`
			} `json:"secrets"`
		} `json:"result"`
	}

	// dry-run must not require a daemon, so no lease calls are attempted
	out := captureEnvStdout(t, func() {
		if err := envCmd.RunE(envCmd, nil); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("expected JSON output, got decode error: %v\noutput: %s", err, out)
	}
	if len(resp.Result.Secrets) != 2 {
		t.Fatalf("expected 2 planned secrets, got %d", len(resp.Result.Secrets))
	}
	if got := resp.Result.Secrets[0].TTL; got != "30m" {
		t.Errorf("A ttl = %q, want %q (per-entry wins over config)", got, "30m")
	}
	if got := resp.Result.Secrets[1].TTL; got != "2h" {
		t.Errorf("B ttl = %q, want %q (config-level fallback)", got, "2h")
	}

	// A --ttl flag overrides both
	restoreTTLFlag := setEnvFlag(t, "ttl", "5m")
	defer restoreTTLFlag()

	out = captureEnvStdout(t, func() {
		if err := envCmd.RunE(envCmd, nil); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("expected JSON output, got decode error: %v\noutput: %s", err, out)
	}
	for _, s := range resp.Result.Secrets {
		if s.TTL != "5m" {
			t.Errorf("%s ttl = %q, want %q (flag overrides)", s.EnvVar, s.TTL, "5m")
		}
	}
}

// setEnvDryRun toggles the dry-run global.
func setEnvDryRun(t *testing.T, value bool) func() {
	t.Helper()
	orig := envDryRun
	envDryRun = value
	return func() { envDryRun = orig }
}

// setEnvFlag sets an env command flag and restores it afterwards.
func setEnvFlag(t *testing.T, name, value string) func() {
	t.Helper()

	flag := envCmd.Flags().Lookup(name)
	if flag == nil {
		t.Fatalf("expected flag %q to exist", name)
	}

	origValue := flag.Value.String()
	origChanged := flag.Changed

	if err := envCmd.Flags().Set(name, value); err != nil {
		t.Fatalf("failed to set --%s flag: %v", name, err)
	}

	return func() {
		_ = envCmd.Flags().Set(name, origValue)
		flag.Changed = origChanged
	}
}

// setEnvTestGlobals points the env command at a test socket and directory.
func setEnvTestGlobals(testSocket, dir string) func() {
	origSocketPath := socketPath
	origEnvForce := envForce
	origEnvTTL := envTTL
	origEnvDryRun := envDryRun
	origDir, err := os.Getwd()

	socketPath = testSocket
	envForce = true // overwrite without prompting; env file must not exist anyway
	envTTL = ""
	envDryRun = false
	if err == nil {
		_ = os.Chdir(dir)
	}

	return func() {
		socketPath = origSocketPath
		envForce = origEnvForce
		envTTL = origEnvTTL
		envDryRun = origEnvDryRun
		if err == nil {
			_ = os.Chdir(origDir)
		}
	}
}

// startEnvLeaseServer serves lease RPC calls for the given secrets and records
// how many lease calls it handled.
func startEnvLeaseServer(t *testing.T, values map[string]string, expiresAt time.Time) (string, func() int) {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "agent-secrets-env.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	var calls int32
	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			var req types.RPCRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				_ = conn.Close()
				continue
			}

			params, _ := json.Marshal(req.Params)
			var leaseParams daemon.LeaseParams
			_ = json.Unmarshal(params, &leaseParams)

			atomic.AddInt32(&calls, 1)

			value, ok := values[leaseParams.SecretName]
			if !ok {
				resp := types.RPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error:   &types.RPCError{Code: -32001, Message: "secret not found"},
				}
				_ = json.NewEncoder(conn).Encode(resp)
				_ = conn.Close()
				continue
			}

			resp := types.RPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: daemon.LeaseResult{
					LeaseID:   "lease-" + leaseParams.SecretName,
					Value:     value,
					ExpiresAt: expiresAt,
				},
			}
			_ = json.NewEncoder(conn).Encode(resp)
			_ = conn.Close()
		}
	}()

	return socket, func() int { return int(atomic.LoadInt32(&calls)) }
}

func captureEnvStdout(t *testing.T, fn func()) string {
	t.Helper()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = origStdout

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout failed: %v", err)
	}
	return string(out)
}

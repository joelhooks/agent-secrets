package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestLeaseCommandFlagsJSONOptIn(t *testing.T) {
	if leaseCmd.Flags().Lookup("json") == nil {
		t.Fatalf("expected --json flag to exist")
	}
	rawFlag := leaseCmd.Flags().Lookup("raw")
	if rawFlag == nil {
		t.Fatalf("expected --raw flag to exist for backward compatibility")
	}
	if !rawFlag.Hidden {
		t.Fatalf("expected --raw flag to be hidden")
	}
}

func TestLeaseRunEDefaultOutputsRawValue(t *testing.T) {
	socket := startLeaseRPCServer(t, daemon.LeaseResult{
		LeaseID:   "lease-123",
		Value:     "super-secret-value",
		ExpiresAt: time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC),
	})

	restore := setLeaseTestGlobals(socket)
	defer restore()

	out := captureLeaseStdout(t, func() {
		if err := leaseCmd.RunE(leaseCmd, []string{"github_token"}); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})

	if out != "super-secret-value" {
		t.Fatalf("expected raw value output, got %q", out)
	}
}

func TestLeaseRunEWithJSONFlagOutputsEnvelope(t *testing.T) {
	if leaseCmd.Flags().Lookup("json") == nil {
		t.Fatalf("expected --json flag to exist")
	}

	socket := startLeaseRPCServer(t, daemon.LeaseResult{
		LeaseID:   "lease-456",
		Value:     "another-secret",
		ExpiresAt: time.Date(2026, 2, 19, 13, 0, 0, 0, time.UTC),
	})

	restore := setLeaseTestGlobals(socket)
	defer restore()

	restoreJSONFlag := setLeaseFlag(t, "json", "true")
	defer restoreJSONFlag()

	out := captureLeaseStdout(t, func() {
		if err := leaseCmd.RunE(leaseCmd, []string{"github_token"}); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})

	if !strings.Contains(out, `"ok": true`) {
		t.Fatalf("expected JSON response with ok=true, got %q", out)
	}
	if !strings.Contains(out, `"command": "secrets lease"`) {
		t.Fatalf("expected JSON response with command, got %q", out)
	}
	if !strings.Contains(out, `"next_actions"`) {
		t.Fatalf("expected JSON response with next_actions, got %q", out)
	}
}

func TestLeaseRunEDaemonConnectionErrorUsesStandardFix(t *testing.T) {
	restore := setLeaseTestGlobals(filepath.Join(t.TempDir(), "missing.sock"))
	defer restore()

	restoreJSONFlag := setLeaseFlag(t, "json", "true")
	defer restoreJSONFlag()

	out := captureLeaseStdout(t, func() {
		// RunE now returns ExitError for error paths (non-zero exit code).
		_ = leaseCmd.RunE(leaseCmd, []string{"github_token"})
	})

	if !strings.Contains(out, `"fix": "Start the daemon: secrets serve \u0026"`) {
		t.Fatalf("expected daemon fix in output, got %q", out)
	}
}

func TestLeaseRunESecretNotFoundUsesStandardFix(t *testing.T) {
	socket := startLeaseRPCErrorServer(t, types.RPCSecretNotFound, "secret \"github_token\": secret not found")

	restore := setLeaseTestGlobals(socket)
	defer restore()

	restoreJSONFlag := setLeaseFlag(t, "json", "true")
	defer restoreJSONFlag()

	out := captureLeaseStdout(t, func() {
		if err := leaseCmd.RunE(leaseCmd, []string{"github_token"}); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})

	if !strings.Contains(out, `"fix": "Check available secrets: secrets status"`) {
		t.Fatalf("expected secret-not-found fix in output, got %q", out)
	}
}

func TestLeaseRunEWithRawFlagWarnsOnStderr(t *testing.T) {
	socket := startLeaseRPCServer(t, daemon.LeaseResult{
		LeaseID:   "lease-789",
		Value:     "raw-secret",
		ExpiresAt: time.Date(2026, 2, 19, 14, 0, 0, 0, time.UTC),
	})

	restore := setLeaseTestGlobals(socket)
	defer restore()

	restoreRawFlag := setLeaseFlag(t, "raw", "true")
	defer restoreRawFlag()

	var out string
	errOut := captureLeaseStderr(t, func() {
		out = captureLeaseStdout(t, func() {
			if err := leaseCmd.RunE(leaseCmd, []string{"github_token"}); err != nil {
				t.Fatalf("RunE failed: %v", err)
			}
		})
	})

	if out != "raw-secret" {
		t.Fatalf("expected raw value output, got %q", out)
	}

	expected := "WARNING: --raw is deprecated and now the default. Remove from scripts. Will be removed in v0.6.0"
	if !strings.Contains(errOut, expected) {
		t.Fatalf("expected raw deprecation warning in stderr, got %q", errOut)
	}
}

func setLeaseFlag(t *testing.T, name, value string) func() {
	t.Helper()

	flag := leaseCmd.Flags().Lookup(name)
	if flag == nil {
		t.Fatalf("expected flag %q to exist", name)
	}

	origValue := flag.Value.String()
	origChanged := flag.Changed

	if err := leaseCmd.Flags().Set(name, value); err != nil {
		t.Fatalf("failed to set --%s flag: %v", name, err)
	}

	return func() {
		_ = leaseCmd.Flags().Set(name, origValue)
		flag.Changed = origChanged
	}
}

func setLeaseTestGlobals(testSocket string) func() {
	origSocketPath := socketPath
	origLeaseTTL := leaseTTL
	origLeaseClientID := leaseClientID
	origLeaseJSON := leaseJSON

	socketPath = testSocket
	leaseTTL = "1h"
	leaseClientID = "test-client"
	leaseJSON = false

	return func() {
		socketPath = origSocketPath
		leaseTTL = origLeaseTTL
		leaseClientID = origLeaseClientID
		leaseJSON = origLeaseJSON
	}
}

func startLeaseRPCServer(t *testing.T, result daemon.LeaseResult) string {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "agent-secrets.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var req types.RPCRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}

		resp := types.RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
		}
		_ = json.NewEncoder(conn).Encode(resp)
	}()

	return socket
}

func startLeaseRPCErrorServer(t *testing.T, code int, message string) string {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "agent-secrets-error.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var req types.RPCRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}

		resp := types.RPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &types.RPCError{
				Code:    code,
				Message: message,
			},
		}
		_ = json.NewEncoder(conn).Encode(resp)
	}()

	return socket
}

func captureLeaseStdout(t *testing.T, fn func()) string {
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

func captureLeaseStderr(t *testing.T, fn func()) string {
	t.Helper()

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	os.Stderr = w

	fn()

	_ = w.Close()
	os.Stderr = origStderr

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stderr failed: %v", err)
	}
	return string(out)
}

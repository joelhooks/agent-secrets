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
	if leaseCmd.Flags().Lookup("raw") != nil {
		t.Fatalf("expected --raw flag to be removed")
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

	if err := leaseCmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("failed to set --json flag: %v", err)
	}
	t.Cleanup(func() {
		_ = leaseCmd.Flags().Set("json", "false")
	})

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

func setLeaseTestGlobals(testSocket string) func() {
	origSocketPath := socketPath
	origLeaseTTL := leaseTTL
	origLeaseClientID := leaseClientID

	socketPath = testSocket
	leaseTTL = "1h"
	leaseClientID = "test-client"

	return func() {
		socketPath = origSocketPath
		leaseTTL = origLeaseTTL
		leaseClientID = origLeaseClientID
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

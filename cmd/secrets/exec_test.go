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
	"github.com/joelhooks/agent-secrets/internal/output"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// TestExecRunE_StoreBackedRevokesLeasesOnFailure is a regression test for a
// lease leak: the failing-command path used to call os.Exit directly, which
// skips deferred cleanup and left the acquired leases active. A leaked
// credential lease outlives the command that needed it.
func TestExecRunE_StoreBackedRevokesLeasesOnFailure(t *testing.T) {
	projectDir := t.TempDir()
	config := `{"secrets": [{"name": "github_token", "env_var": "GH"}], "client_id": "exec-test"}`
	if err := os.WriteFile(filepath.Join(projectDir, ".secrets.json"), []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	expiresAt := time.Now().Add(time.Hour).UTC()
	socket, leases, revokes := startExecRPCServer(t, map[string]string{"github_token": "gh-value"}, expiresAt)

	restoreSocket := socketPath
	socketPath = socket
	defer func() { socketPath = restoreSocket }()

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	origTTL := execTTL
	execTTL = ""
	defer func() { execTTL = origTTL }()

	// Run a command that fails. The error path must still revoke the lease.
	err = execCmd.RunE(execCmd, []string{"sh", "-c", "exit 3"})
	if err == nil {
		t.Fatal("expected an error for a failing command")
	}

	exitErr, ok := err.(*output.ExitError)
	if !ok {
		t.Fatalf("expected *output.ExitError, got %T (%v)", err, err)
	}
	if exitErr.Code != 3 {
		t.Errorf("exit code = %d, want 3 (the child's exit code must be preserved)", exitErr.Code)
	}

	if got := leases(); got != 1 {
		t.Errorf("leases acquired = %d, want 1", got)
	}
	if got := revokes(); got != 1 {
		t.Errorf("leases revoked = %d, want 1 (a failing command must not leak its lease)", got)
	}
}

// TestExecRunE_StoreBackedRevokesLeasesOnSuccess covers the happy path.
func TestExecRunE_StoreBackedRevokesLeasesOnSuccess(t *testing.T) {
	projectDir := t.TempDir()
	config := `{"secrets": [{"name": "github_token", "env_var": "GH"}], "client_id": "exec-test"}`
	if err := os.WriteFile(filepath.Join(projectDir, ".secrets.json"), []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	expiresAt := time.Now().Add(time.Hour).UTC()
	socket, leases, revokes := startExecRPCServer(t, map[string]string{"github_token": "gh-value"}, expiresAt)

	restoreSocket := socketPath
	socketPath = socket
	defer func() { socketPath = restoreSocket }()

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working dir: %v", err)
	}
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	origTTL := execTTL
	execTTL = ""
	defer func() { execTTL = origTTL }()

	// The success path prints the JSON envelope to stdout; discard it.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	os.Stdout = w
	runErr := execCmd.RunE(execCmd, []string{"true"})
	_ = w.Close()
	os.Stdout = origStdout
	_, _ = io.ReadAll(r)

	if runErr != nil {
		t.Fatalf("RunE failed: %v", runErr)
	}
	if leases() != 1 || revokes() != 1 {
		t.Errorf("leases=%d revokes=%d, want 1 and 1", leases(), revokes())
	}
}

// TestExecRunE_MissingSecretFixIsActionable ensures a missing secret is not
// reported as a stopped daemon.
func TestExecRunE_MissingSecretFixIsActionable(t *testing.T) {
	projectDir := t.TempDir()
	config := `{"secrets": [{"name": "nope", "env_var": "X"}]}`
	if err := os.WriteFile(filepath.Join(projectDir, ".secrets.json"), []byte(config), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	expiresAt := time.Now().Add(time.Hour).UTC()
	socket, _, _ := startExecRPCServer(t, map[string]string{"other": "v"}, expiresAt)

	restoreSocket := socketPath
	socketPath = socket
	defer func() { socketPath = restoreSocket }()

	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	if err := os.Chdir(projectDir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	os.Stdout = w
	_ = execCmd.RunE(execCmd, []string{"true"})
	_ = w.Close()
	os.Stdout = origStdout

	data, _ := io.ReadAll(r)
	out := string(data)
	if !strings.Contains(out, "secrets list") {
		t.Errorf("expected fix to suggest listing secrets, got: %s", out)
	}
}

// startExecRPCServer serves lease and revoke RPCs, counting each so tests can
// assert that leases are released.
func startExecRPCServer(t *testing.T, values map[string]string, expiresAt time.Time) (socket string, leases, revokes func() int) {
	t.Helper()

	socket = filepath.Join(t.TempDir(), "exec.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var nLease, nRevoke int32

	go func() {
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

			var resp types.RPCResponse
			resp.JSONRPC = "2.0"
			resp.ID = req.ID

			switch req.Method {
			case daemon.MethodLease:
				params, _ := json.Marshal(req.Params)
				var lp daemon.LeaseParams
				_ = json.Unmarshal(params, &lp)
				atomic.AddInt32(&nLease, 1)

				value, ok := values[lp.SecretName]
				if !ok {
					resp.Error = &types.RPCError{Code: -32000, Message: `secret "` + lp.SecretName + `": secret not found`}
				} else {
					resp.Result = daemon.LeaseResult{
						LeaseID:   "lease-" + lp.SecretName,
						Value:     value,
						ExpiresAt: expiresAt,
					}
				}
			case daemon.MethodRevoke:
				atomic.AddInt32(&nRevoke, 1)
				resp.Result = daemon.RevokeResult{Success: true, Message: "revoked"}
			default:
				resp.Error = &types.RPCError{Code: -32601, Message: "method not found"}
			}

			_ = json.NewEncoder(conn).Encode(resp)
			_ = conn.Close()
		}
	}()

	return socket,
		func() int { return int(atomic.LoadInt32(&nLease)) },
		func() int { return int(atomic.LoadInt32(&nRevoke)) }
}

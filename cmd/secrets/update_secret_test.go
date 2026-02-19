package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestUpdateRunEOutputsSuccessEnvelope(t *testing.T) {
	socket := startUpdateRPCServer(t, daemon.UpdateResult{
		Success: true,
		Message: "secret \"github_token\" updated successfully",
	})

	restore := setUpdateTestGlobals(socket)
	defer restore()

	updateSecretValue = "updated-value"

	out := captureUpdateStdout(t, func() {
		if err := updateCmd.RunE(updateCmd, []string{"github_token"}); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})

	var resp struct {
		OK      bool   `json:"ok"`
		Command string `json:"command"`
		Result  struct {
			Name string `json:"name"`
		} `json:"result"`
		NextActions []struct {
			Command string `json:"command"`
		} `json:"next_actions"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("expected JSON output, got decode error: %v\noutput: %s", err, out)
	}

	if !resp.OK {
		t.Fatalf("expected ok=true")
	}
	if resp.Command != "secrets update" {
		t.Fatalf("expected command=secrets update, got %q", resp.Command)
	}
	if resp.Result.Name != "github_token" {
		t.Fatalf("expected result name github_token, got %q", resp.Result.Name)
	}
	if len(resp.NextActions) < 1 || resp.NextActions[0].Command != "secrets lease github_token" {
		t.Fatalf("expected first action to lease updated secret, got %#v", resp.NextActions)
	}
}

func TestUpdateRunESecretNotFoundProvidesAddFix(t *testing.T) {
	socket := startUpdateRPCErrorServer(t, types.RPCSecretNotFound, `secret "github_token": secret not found`)
	restore := setUpdateTestGlobals(socket)
	defer restore()

	updateSecretValue = "updated-value"

	out := captureUpdateStdout(t, func() {
		if err := updateCmd.RunE(updateCmd, []string{"github_token"}); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})

	if !strings.Contains(out, `"fix": "Secret \"github_token\" does not exist. Add it first: secrets add github_token"`) {
		t.Fatalf("expected add-first fix, got %q", out)
	}
}

func setUpdateTestGlobals(testSocket string) func() {
	origSocketPath := socketPath
	origValue := updateSecretValue
	origRotate := updateSecretRotateVia

	socketPath = testSocket
	updateSecretValue = ""
	updateSecretRotateVia = ""

	return func() {
		socketPath = origSocketPath
		updateSecretValue = origValue
		updateSecretRotateVia = origRotate
	}
}

func startUpdateRPCServer(t *testing.T, result daemon.UpdateResult) string {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "agent-secrets-update.sock")
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

func startUpdateRPCErrorServer(t *testing.T, code int, message string) string {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "agent-secrets-update-error.sock")
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

func captureUpdateStdout(t *testing.T, fn func()) string {
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

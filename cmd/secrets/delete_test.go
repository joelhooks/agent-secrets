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

func TestDeleteCommandHasRMAlias(t *testing.T) {
	found := false
	for _, alias := range deleteCmd.Aliases {
		if alias == "rm" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected delete command to include rm alias")
	}
}

func TestDeleteRunEOutputsSuccessEnvelope(t *testing.T) {
	socket := startDeleteRPCServer(t, daemon.DeleteResult{
		Success: true,
		Message: "secret \"github_token\" deleted successfully",
	})

	restore := setDeleteTestGlobals(socket)
	defer restore()

	out := captureDeleteStdout(t, func() {
		if err := deleteCmd.RunE(deleteCmd, []string{"github_token"}); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})

	var resp struct {
		OK      bool   `json:"ok"`
		Command string `json:"command"`
		Result  struct {
			Name    string `json:"name"`
			Deleted bool   `json:"deleted"`
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
	if resp.Command != "secrets delete" {
		t.Fatalf("expected command=secrets delete, got %q", resp.Command)
	}
	if resp.Result.Name != "github_token" || !resp.Result.Deleted {
		t.Fatalf("unexpected delete result: %#v", resp.Result)
	}
	if len(resp.NextActions) < 1 || resp.NextActions[0].Command != "secrets list" {
		t.Fatalf("expected first next action to list secrets, got %#v", resp.NextActions)
	}
}

func TestDeleteRunESecretNotFoundUsesListFix(t *testing.T) {
	socket := startDeleteRPCErrorServer(t, types.RPCSecretNotFound, `secret "github_token": secret not found`)
	restore := setDeleteTestGlobals(socket)
	defer restore()

	out := captureDeleteStdout(t, func() {
		_ = deleteCmd.RunE(deleteCmd, []string{"github_token"})
	})

	if !strings.Contains(out, `"fix": "Check available secrets: secrets list"`) {
		t.Fatalf("expected list fix in output, got %q", out)
	}
}

func setDeleteTestGlobals(testSocket string) func() {
	origSocketPath := socketPath
	origDeleteForce := deleteForce

	socketPath = testSocket
	deleteForce = true

	return func() {
		socketPath = origSocketPath
		deleteForce = origDeleteForce
	}
}

func startDeleteRPCServer(t *testing.T, result daemon.DeleteResult) string {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "agent-secrets-delete.sock")
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

func startDeleteRPCErrorServer(t *testing.T, code int, message string) string {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "agent-secrets-delete-error.sock")
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

func captureDeleteStdout(t *testing.T, fn func()) string {
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

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

func TestListRunEOutputsSecretsAndActions(t *testing.T) {
	socket := startListRPCServer(t, daemon.ListResult{
		Secrets: []daemon.SecretMetadata{
			{
				Name:         "github_token",
				RotateVia:    "bin/rotate-github",
				ActiveLeases: 1,
				CreatedAt:    time.Date(2026, 2, 19, 12, 0, 0, 0, time.UTC),
				UpdatedAt:    time.Date(2026, 2, 19, 12, 5, 0, 0, time.UTC),
			},
			{
				Name:         "anthropic_key",
				ActiveLeases: 0,
				CreatedAt:    time.Date(2026, 2, 19, 12, 10, 0, 0, time.UTC),
				UpdatedAt:    time.Date(2026, 2, 19, 12, 10, 0, 0, time.UTC),
			},
		},
	})

	restore := setListTestGlobals(socket)
	defer restore()

	out := captureListStdout(t, func() {
		if err := listCmd.RunE(listCmd, nil); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})

	var resp struct {
		OK      bool   `json:"ok"`
		Command string `json:"command"`
		Result  struct {
			Secrets []struct {
				Name         string `json:"name"`
				HasRotation  bool   `json:"has_rotation"`
				ActiveLeases int    `json:"active_leases"`
			} `json:"secrets"`
			Count int `json:"count"`
		} `json:"result"`
		NextActions []struct {
			Command     string `json:"command"`
			Description string `json:"description"`
		} `json:"next_actions"`
	}

	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("expected JSON output, got decode error: %v\noutput: %s", err, out)
	}

	if !resp.OK {
		t.Fatalf("expected ok=true")
	}
	if resp.Command != "secrets list" {
		t.Fatalf("expected command=secrets list, got %q", resp.Command)
	}
	if resp.Result.Count != 2 {
		t.Fatalf("expected count=2, got %d", resp.Result.Count)
	}

	if len(resp.Result.Secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(resp.Result.Secrets))
	}

	if resp.Result.Secrets[0].Name != "anthropic_key" {
		t.Fatalf("expected first secret anthropic_key, got %q", resp.Result.Secrets[0].Name)
	}
	if resp.Result.Secrets[0].HasRotation {
		t.Fatalf("expected anthropic_key has_rotation=false")
	}
	if resp.Result.Secrets[0].ActiveLeases != 0 {
		t.Fatalf("expected anthropic_key active_leases=0, got %d", resp.Result.Secrets[0].ActiveLeases)
	}

	if resp.Result.Secrets[1].Name != "github_token" {
		t.Fatalf("expected second secret github_token, got %q", resp.Result.Secrets[1].Name)
	}
	if !resp.Result.Secrets[1].HasRotation {
		t.Fatalf("expected github_token has_rotation=true")
	}
	if resp.Result.Secrets[1].ActiveLeases != 1 {
		t.Fatalf("expected github_token active_leases=1, got %d", resp.Result.Secrets[1].ActiveLeases)
	}

	if len(resp.NextActions) != 3 {
		t.Fatalf("expected 3 next_actions, got %d", len(resp.NextActions))
	}
	if resp.NextActions[0].Command != "secrets lease anthropic_key" {
		t.Fatalf("expected first action for anthropic_key lease, got %q", resp.NextActions[0].Command)
	}
	if resp.NextActions[1].Command != "secrets lease github_token" {
		t.Fatalf("expected second action for github_token lease, got %q", resp.NextActions[1].Command)
	}
	if resp.NextActions[2].Command != "secrets add <name>" {
		t.Fatalf("expected final action to add secret, got %q", resp.NextActions[2].Command)
	}
}

func TestListRunEDaemonConnectionErrorUsesStandardFix(t *testing.T) {
	restore := setListTestGlobals(filepath.Join(t.TempDir(), "missing.sock"))
	defer restore()

	out := captureListStdout(t, func() {
		if err := listCmd.RunE(listCmd, nil); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})

	if !strings.Contains(out, `"fix": "Start the daemon: secrets serve \u0026"`) {
		t.Fatalf("expected daemon fix in output, got %q", out)
	}
}

func TestListRunESortsSecretsAndActionsByName(t *testing.T) {
	socket := startListRPCServer(t, daemon.ListResult{
		Secrets: []daemon.SecretMetadata{
			{Name: "zeta_key"},
			{Name: "alpha_key"},
			{Name: "middle_key"},
		},
	})

	restore := setListTestGlobals(socket)
	defer restore()

	out := captureListStdout(t, func() {
		if err := listCmd.RunE(listCmd, nil); err != nil {
			t.Fatalf("RunE failed: %v", err)
		}
	})

	var resp struct {
		Result struct {
			Secrets []struct {
				Name string `json:"name"`
			} `json:"secrets"`
		} `json:"result"`
		NextActions []struct {
			Command string `json:"command"`
		} `json:"next_actions"`
	}

	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("expected JSON output, got decode error: %v\noutput: %s", err, out)
	}

	if len(resp.Result.Secrets) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(resp.Result.Secrets))
	}

	orderedNames := []string{"alpha_key", "middle_key", "zeta_key"}
	for i, expected := range orderedNames {
		if resp.Result.Secrets[i].Name != expected {
			t.Fatalf("expected secret[%d] to be %q, got %q", i, expected, resp.Result.Secrets[i].Name)
		}
	}

	if len(resp.NextActions) < 3 {
		t.Fatalf("expected at least 3 actions, got %d", len(resp.NextActions))
	}

	orderedActions := []string{
		"secrets lease alpha_key",
		"secrets lease middle_key",
		"secrets lease zeta_key",
	}
	for i, expected := range orderedActions {
		if resp.NextActions[i].Command != expected {
			t.Fatalf("expected action[%d] command %q, got %q", i, expected, resp.NextActions[i].Command)
		}
	}
}

func setListTestGlobals(testSocket string) func() {
	origSocketPath := socketPath
	socketPath = testSocket
	return func() {
		socketPath = origSocketPath
	}
}

func startListRPCServer(t *testing.T, result daemon.ListResult) string {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "agent-secrets-list.sock")
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

func captureListStdout(t *testing.T, fn func()) string {
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

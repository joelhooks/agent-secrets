package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestRPCCallHonorsConfigFlag(t *testing.T) {
	socket := fmt.Sprintf("/tmp/agent-secrets-client-%d.sock", os.Getpid())
	_ = os.Remove(socket)
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		listener.Close()
		_ = os.Remove(socket)
	})

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var request types.RPCRequest
		_ = json.NewDecoder(conn).Decode(&request)
		_ = json.NewEncoder(conn).Encode(types.RPCResponse{
			JSONRPC: "2.0",
			ID:      request.ID,
			Result:  types.DaemonStatus{Running: true},
		})
	}()

	path := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"socket_path":%q}`, socket)), 0600); err != nil {
		t.Fatal(err)
	}
	previousConfig, previousSocket := configPath, socketPath
	configPath, socketPath = path, ""
	t.Cleanup(func() { configPath, socketPath = previousConfig, previousSocket })

	response, err := rpcCall("", daemon.MethodStatus, daemon.StatusParams{})
	if err != nil {
		t.Fatalf("rpcCall() error = %v", err)
	}
	if response.Error != nil {
		t.Fatalf("rpcCall() response error = %v", response.Error)
	}
}

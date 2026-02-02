package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestNewDaemon(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.Config{
		Directory:       tempDir,
		SocketPath:      tempDir + "/test.sock",
		IdentityPath:    tempDir + "/identity.age",
		SecretsPath:     tempDir + "/secrets.age",
		AuditPath:       tempDir + "/audit.log",
		LeasesPath:      tempDir + "/leases.json",
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}

	if d == nil {
		t.Fatal("expected non-nil daemon")
	}

	if d.cfg.SocketPath != cfg.SocketPath {
		t.Errorf("expected socket path %s, got %s", cfg.SocketPath, d.cfg.SocketPath)
	}
}

func TestNewDaemonInvalidConfig(t *testing.T) {
	cfg := &config.Config{
		Directory:       "",
		DefaultLeaseTTL: -1 * time.Hour,
	}

	_, err := NewDaemon(cfg)
	if err == nil {
		t.Error("expected error for invalid config, got nil")
	}
}

func TestDaemonStartStop(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.Config{
		Directory:       tempDir,
		SocketPath:      tempDir + "/test.sock",
		IdentityPath:    tempDir + "/identity.age",
		SecretsPath:     tempDir + "/secrets.age",
		AuditPath:       tempDir + "/audit.log",
		LeasesPath:      tempDir + "/leases.json",
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}

	// Start daemon
	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	if !d.IsRunning() {
		t.Error("expected daemon to be running")
	}

	// Verify socket was created
	if _, err := os.Stat(cfg.SocketPath); os.IsNotExist(err) {
		t.Error("socket file was not created")
	}

	// Verify socket permissions
	info, err := os.Stat(cfg.SocketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected socket permissions 0600, got %o", info.Mode().Perm())
	}

	// Stop daemon
	if err := d.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if d.IsRunning() {
		t.Error("expected daemon to be stopped")
	}
}

func TestDaemonStartAlreadyRunning(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.Config{
		Directory:       tempDir,
		SocketPath:      tempDir + "/test.sock",
		IdentityPath:    tempDir + "/identity.age",
		SecretsPath:     tempDir + "/secrets.age",
		AuditPath:       tempDir + "/audit.log",
		LeasesPath:      tempDir + "/leases.json",
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer d.Stop()

	// Try to start again
	err = d.Start()
	if err != types.ErrDaemonAlreadyRunning {
		t.Errorf("expected ErrDaemonAlreadyRunning, got %v", err)
	}
}

func TestDaemonStopNotRunning(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.Config{
		Directory:       tempDir,
		SocketPath:      tempDir + "/test.sock",
		IdentityPath:    tempDir + "/identity.age",
		SecretsPath:     tempDir + "/secrets.age",
		AuditPath:       tempDir + "/audit.log",
		LeasesPath:      tempDir + "/leases.json",
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}

	// Try to stop without starting
	err = d.Stop()
	if err != types.ErrDaemonNotRunning {
		t.Errorf("expected ErrDaemonNotRunning, got %v", err)
	}
}

func TestDaemonHandleConnection(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.Config{
		Directory:       tempDir,
		SocketPath:      tempDir + "/test.sock",
		IdentityPath:    tempDir + "/identity.age",
		SecretsPath:     tempDir + "/secrets.age",
		AuditPath:       tempDir + "/audit.log",
		LeasesPath:      tempDir + "/leases.json",
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer d.Stop()

	// Connect to the daemon
	conn, err := net.Dial("unix", cfg.SocketPath)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Send init request
	req := types.RPCRequest{
		JSONRPC: "2.0",
		Method:  MethodInit,
		Params:  InitParams{},
		ID:      1,
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		t.Fatalf("failed to send request: %v", err)
	}

	// Read response
	var resp types.RPCResponse
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("unexpected error: %v", resp.Error.Message)
	}

	if resp.Result == nil {
		t.Error("expected result, got nil")
	}
}

func TestDaemonMultipleRequests(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.Config{
		Directory:       tempDir,
		SocketPath:      tempDir + "/test.sock",
		IdentityPath:    tempDir + "/identity.age",
		SecretsPath:     tempDir + "/secrets.age",
		AuditPath:       tempDir + "/audit.log",
		LeasesPath:      tempDir + "/leases.json",
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer d.Stop()

	// Connect to the daemon
	conn, err := net.Dial("unix", cfg.SocketPath)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	scanner := bufio.NewScanner(conn)

	// Send multiple requests sequentially
	requests := []types.RPCRequest{
		{JSONRPC: "2.0", Method: MethodInit, Params: InitParams{}, ID: 1},
		{JSONRPC: "2.0", Method: MethodAdd, Params: AddParams{Name: "test", Value: "val"}, ID: 2},
		{JSONRPC: "2.0", Method: MethodList, Params: ListParams{}, ID: 3},
		{JSONRPC: "2.0", Method: MethodStatus, Params: StatusParams{}, ID: 4},
	}

	for i, req := range requests {
		if err := encoder.Encode(req); err != nil {
			t.Fatalf("failed to send request %d: %v", i, err)
		}

		if !scanner.Scan() {
			t.Fatalf("failed to read response %d: %v", i, scanner.Err())
		}

		var resp types.RPCResponse
		if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response %d: %v", i, err)
		}

		if resp.Error != nil {
			t.Errorf("request %d error: %v", i, resp.Error.Message)
		}
	}
}

func TestDaemonInvalidJSON(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.Config{
		Directory:       tempDir,
		SocketPath:      tempDir + "/test.sock",
		IdentityPath:    tempDir + "/identity.age",
		SecretsPath:     tempDir + "/secrets.age",
		AuditPath:       tempDir + "/audit.log",
		LeasesPath:      tempDir + "/leases.json",
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer d.Stop()

	conn, err := net.Dial("unix", cfg.SocketPath)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	// Send invalid JSON
	if _, err := conn.Write([]byte("{invalid json}\n")); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// Read response
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		t.Fatalf("failed to read response: %v", scanner.Err())
	}

	var resp types.RPCResponse
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if resp.Error == nil {
		t.Error("expected parse error, got nil")
	}

	if resp.Error.Code != types.RPCParseError {
		t.Errorf("expected parse error code, got %d", resp.Error.Code)
	}
}

func TestDaemonConcurrentConnections(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.Config{
		Directory:       tempDir,
		SocketPath:      tempDir + "/test.sock",
		IdentityPath:    tempDir + "/identity.age",
		SecretsPath:     tempDir + "/secrets.age",
		AuditPath:       tempDir + "/audit.log",
		LeasesPath:      tempDir + "/leases.json",
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer d.Stop()

	// Initialize store first
	conn, _ := net.Dial("unix", cfg.SocketPath)
	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)
	req := types.RPCRequest{JSONRPC: "2.0", Method: MethodInit, Params: InitParams{}, ID: 0}
	encoder.Encode(req)
	var initResp types.RPCResponse
	decoder.Decode(&initResp)
	conn.Close()

	// Spawn multiple concurrent connections
	const numClients = 10
	done := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		go func(clientID int) {
			conn, err := net.Dial("unix", cfg.SocketPath)
			if err != nil {
				done <- err
				return
			}
			defer conn.Close()

			// Send a status request
			req := types.RPCRequest{
				JSONRPC: "2.0",
				Method:  MethodStatus,
				Params:  StatusParams{},
				ID:      clientID,
			}

			encoder := json.NewEncoder(conn)
			if err := encoder.Encode(req); err != nil {
				done <- err
				return
			}

			// Read response
			var resp types.RPCResponse
			decoder := json.NewDecoder(conn)
			if err := decoder.Decode(&resp); err != nil {
				done <- err
				return
			}

			if resp.Error != nil {
				done <- fmt.Errorf("RPC error: %s", resp.Error.Message)
				return
			}

			done <- nil
		}(i)
	}

	// Wait for all clients
	for i := 0; i < numClients; i++ {
		if err := <-done; err != nil {
			t.Errorf("client %d failed: %v", i, err)
		}
	}
}

func TestDaemonStatus(t *testing.T) {
	tempDir := t.TempDir()

	cfg := &config.Config{
		Directory:       tempDir,
		SocketPath:      tempDir + "/test.sock",
		IdentityPath:    tempDir + "/identity.age",
		SecretsPath:     tempDir + "/secrets.age",
		AuditPath:       tempDir + "/audit.log",
		LeasesPath:      tempDir + "/leases.json",
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}

	if err := d.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer d.Stop()

	status := d.Status()
	if !status.Running {
		t.Error("expected status.Running to be true")
	}

	if status.StartedAt.IsZero() {
		t.Error("expected non-zero StartedAt")
	}

	if status.SecretsCount < 0 {
		t.Error("expected non-negative SecretsCount")
	}

	if status.ActiveLeases < 0 {
		t.Error("expected non-negative ActiveLeases")
	}
}

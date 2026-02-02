package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"

	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// rpcCall connects to the daemon via Unix socket and executes an RPC call.
func rpcCall(socketPath, method string, params interface{}) (*types.RPCResponse, error) {
	if socketPath == "" {
		cfg, err := config.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
		socketPath = cfg.SocketPath
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to daemon at %s: %w (is the daemon running?)", socketPath, err)
	}
	defer conn.Close()

	// Create JSON-RPC request
	req := types.RPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}

	// Send request
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	var resp types.RPCResponse
	decoder := json.NewDecoder(bufio.NewReader(conn))
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for RPC error
	if resp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	return &resp, nil
}

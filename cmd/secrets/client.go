package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// rpcCall connects to the daemon via Unix socket and executes an RPC call.
func rpcCall(socketPath, method string, params interface{}) (*types.RPCResponse, error) {
	// Create context with timeout from global flag (default 5s)
	timeout := time.Duration(timeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if socketPath == "" {
		cfg, err := config.Load()
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
		socketPath = cfg.SocketPath
	}

	// Use DialContext for timeout support
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("daemon connection timeout after %s (is the daemon running?)", timeout)
		}
		return nil, fmt.Errorf("failed to connect to daemon at %s: %w (is the daemon running?)", socketPath, err)
	}
	defer conn.Close()

	// Set deadline for all I/O operations on this connection
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

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
		if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
			return nil, fmt.Errorf("daemon unresponsive (timeout after %s)", timeout)
		}
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	var resp types.RPCResponse
	decoder := json.NewDecoder(bufio.NewReader(conn))
	if err := decoder.Decode(&resp); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
			return nil, fmt.Errorf("daemon unresponsive (timeout after %s)", timeout)
		}
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for RPC error
	if resp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	return &resp, nil
}

// isTimeoutError checks if the error is a network timeout error
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// isDaemonConnectionError checks if the error is related to daemon connectivity
func isDaemonConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Check for common connection error patterns
	return strings.Contains(errStr, "failed to connect to daemon") ||
		strings.Contains(errStr, "daemon connection timeout") ||
		strings.Contains(errStr, "is the daemon running?") ||
		strings.Contains(errStr, "connection refused")
}

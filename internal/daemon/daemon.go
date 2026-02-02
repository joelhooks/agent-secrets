package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/joelhooks/agent-secrets/internal/audit"
	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/killswitch"
	"github.com/joelhooks/agent-secrets/internal/lease"
	"github.com/joelhooks/agent-secrets/internal/rotation"
	"github.com/joelhooks/agent-secrets/internal/store"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// Daemon manages the Unix socket server and request handling.
type Daemon struct {
	cfg       *config.Config
	listener  net.Listener
	handler   *Handler
	startedAt time.Time
	running   bool
	mu        sync.RWMutex

	// Components
	store            *store.Store
	leaseManager     *lease.Manager
	rotationExecutor *rotation.Executor
	killswitch       *killswitch.Killswitch
	auditLogger      *audit.Logger

	// Shutdown coordination
	done chan struct{}
	wg   sync.WaitGroup
}

// NewDaemon creates a new daemon with the provided configuration.
// It initializes all components (store, lease manager, rotation executor, etc.).
func NewDaemon(cfg *config.Config) (*Daemon, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Ensure directories exist
	if err := cfg.EnsureDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	// Initialize audit logger
	auditLogger, err := audit.New(cfg.AuditPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Initialize store
	st := store.New(cfg)
	if err := st.Load(); err != nil {
		// If load fails, try to init
		if err := st.Init(); err != nil {
			return nil, fmt.Errorf("failed to initialize store: %w", err)
		}
	}

	// Initialize lease manager
	leaseManager, err := lease.NewManager(cfg, auditLogger)
	if err != nil {
		return nil, fmt.Errorf("failed to create lease manager: %w", err)
	}

	// Initialize rotation executor
	rotationExecutor := rotation.NewExecutor(cfg, st, auditLogger)

	// Initialize killswitch
	ks := killswitch.NewKillswitch(leaseManager, rotationExecutor, st, auditLogger)

	// Create handler
	handler := NewHandler(st, leaseManager, rotationExecutor, ks, auditLogger)

	return &Daemon{
		cfg:              cfg,
		handler:          handler,
		store:            st,
		leaseManager:     leaseManager,
		rotationExecutor: rotationExecutor,
		killswitch:       ks,
		auditLogger:      auditLogger,
		done:             make(chan struct{}),
	}, nil
}

// Start starts the daemon and begins listening on the Unix socket.
func (d *Daemon) Start() error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return types.ErrDaemonAlreadyRunning
	}

	// Remove existing socket file if present
	if err := os.Remove(d.cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		d.mu.Unlock()
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		d.mu.Unlock()
		return fmt.Errorf("failed to listen on socket: %w", err)
	}

	// Set socket permissions to 0600 (owner only)
	if err := os.Chmod(d.cfg.SocketPath, 0600); err != nil {
		listener.Close()
		d.mu.Unlock()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	d.listener = listener
	d.startedAt = time.Now()
	d.running = true
	d.mu.Unlock()

	// Log daemon start
	entry := audit.NewEntry(types.ActionDaemonStart, true).
		WithDetails(fmt.Sprintf("listening on %s", d.cfg.SocketPath)).
		Build()
	_ = d.auditLogger.Log(entry)

	// Start lease cleanup loop
	d.leaseManager.StartCleanupLoop(1 * time.Minute)

	// Accept connections in a goroutine
	d.wg.Add(1)
	go d.acceptLoop()

	return nil
}

// Stop gracefully shuts down the daemon.
func (d *Daemon) Stop() error {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return types.ErrDaemonNotRunning
	}
	d.running = false
	d.mu.Unlock()

	// Close the listener to stop accepting new connections
	if d.listener != nil {
		d.listener.Close()
	}

	// Signal shutdown and wait for all connections to finish
	close(d.done)
	d.wg.Wait()

	// Stop lease cleanup loop
	d.leaseManager.StopCleanupLoop()

	// Persist state
	if err := d.leaseManager.Save(); err != nil {
		// Log but don't fail shutdown
		entry := audit.NewEntry(types.ActionDaemonStop, false).
			WithDetails(fmt.Sprintf("failed to save leases: %v", err)).
			Build()
		_ = d.auditLogger.Log(entry)
	}

	// Log daemon stop
	entry := audit.NewEntry(types.ActionDaemonStop, true).
		WithDetails("daemon stopped gracefully").
		Build()
	_ = d.auditLogger.Log(entry)

	// Close audit logger
	if err := d.auditLogger.Close(); err != nil {
		return fmt.Errorf("failed to close audit logger: %w", err)
	}

	return nil
}

// acceptLoop accepts incoming connections and spawns handlers.
func (d *Daemon) acceptLoop() {
	defer d.wg.Done()

	for {
		conn, err := d.listener.Accept()
		if err != nil {
			// Check if we're shutting down
			select {
			case <-d.done:
				return
			default:
				// Log error and continue
				continue
			}
		}

		// Handle connection in a goroutine
		d.wg.Add(1)
		go d.handleConnection(conn)
	}
}

// handleConnection processes requests from a single connection.
// Each line is expected to be a JSON-RPC request.
func (d *Daemon) handleConnection(conn net.Conn) {
	defer d.wg.Done()
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	encoder := json.NewEncoder(conn)

	for scanner.Scan() {
		// Check if we're shutting down
		select {
		case <-d.done:
			return
		default:
		}

		// Parse JSON-RPC request
		var req types.RPCRequest
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			// Send parse error response
			resp := &types.RPCResponse{
				JSONRPC: "2.0",
				Error: &types.RPCError{
					Code:    types.RPCParseError,
					Message: fmt.Sprintf("parse error: %v", err),
				},
				ID: nil,
			}
			_ = encoder.Encode(resp)
			continue
		}

		// Dispatch to handler
		resp := d.handler.HandleRequest(&req)

		// Inject startedAt into status responses
		if req.Method == MethodStatus && resp.Result != nil {
			if status, ok := resp.Result.(*types.DaemonStatus); ok {
				d.mu.RLock()
				status.StartedAt = d.startedAt
				status.Running = d.running
				d.mu.RUnlock()
			}
		}

		// Write response
		if err := encoder.Encode(resp); err != nil {
			// Connection error, close and return
			return
		}
	}

	if err := scanner.Err(); err != nil {
		// Log connection error
		entry := audit.NewEntry(types.ActionDaemonStop, false).
			WithDetails(fmt.Sprintf("connection error: %v", err)).
			Build()
		_ = d.auditLogger.Log(entry)
	}
}

// IsRunning returns true if the daemon is currently running.
func (d *Daemon) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}

// Status returns the current daemon status.
func (d *Daemon) Status() *types.DaemonStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	secrets, _ := d.store.List()
	activeLeases := d.leaseManager.List()

	return &types.DaemonStatus{
		Running:      d.running,
		StartedAt:    d.startedAt,
		SecretsCount: len(secrets),
		ActiveLeases: len(activeLeases),
		Heartbeat:    d.cfg.Heartbeat,
	}
}

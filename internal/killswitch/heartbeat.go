// Package killswitch provides emergency revocation capabilities.
package killswitch

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/joelhooks/agent-secrets/internal/audit"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// HeartbeatMonitor monitors a remote endpoint and triggers killswitch on failure.
type HeartbeatMonitor struct {
	config      types.HeartbeatConfig
	killswitch  *Killswitch
	auditLogger *audit.Logger
	client      *http.Client
	done        chan struct{}
	stopOnce    sync.Once
	mu          sync.Mutex
	running     bool
}

// NewHeartbeatMonitor creates a new heartbeat monitor.
func NewHeartbeatMonitor(
	config types.HeartbeatConfig,
	killswitch *Killswitch,
	auditLogger *audit.Logger,
) *HeartbeatMonitor {
	return &HeartbeatMonitor{
		config:      config,
		killswitch:  killswitch,
		auditLogger: auditLogger,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		done: make(chan struct{}),
	}
}

// Start begins monitoring the heartbeat endpoint in a background goroutine.
func (h *HeartbeatMonitor) Start() {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}
	h.running = true
	h.mu.Unlock()

	go h.monitorLoop()
}

// Stop stops the heartbeat monitor gracefully.
func (h *HeartbeatMonitor) Stop() {
	h.stopOnce.Do(func() {
		close(h.done)
	})
}

// monitorLoop is the main monitoring loop that runs in a goroutine.
func (h *HeartbeatMonitor) monitorLoop() {
	ticker := time.NewTicker(h.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := h.check(); err != nil {
				// Log heartbeat failure
				entry := audit.NewEntry(types.ActionHeartbeatFail, false).
					WithDetails(err.Error()).
					Build()
				_ = h.auditLogger.Log(entry)

				// Trigger killswitch with configured fail action
				if err := h.killswitch.Activate(h.config.FailAction); err != nil {
					// Log killswitch failure but don't retry
					entry := audit.NewEntry(types.ActionKillswitch, false).
						WithDetails(fmt.Sprintf("triggered by heartbeat failure: %v", err)).
						Build()
					_ = h.auditLogger.Log(entry)
				}

				// Stop monitoring after first failure
				h.mu.Lock()
				h.running = false
				h.mu.Unlock()
				return
			}
		case <-h.done:
			h.mu.Lock()
			h.running = false
			h.mu.Unlock()
			return
		}
	}
}

// check performs a single heartbeat check against the configured URL.
func (h *HeartbeatMonitor) check() error {
	resp, err := h.client.Get(h.config.URL)
	if err != nil {
		return fmt.Errorf("%w: %v", types.ErrHeartbeatFailed, err)
	}
	defer resp.Body.Close()

	// Consider any 2xx status code as success
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: HTTP %d", types.ErrHeartbeatFailed, resp.StatusCode)
	}

	return nil
}

// IsRunning returns whether the monitor is currently running.
func (h *HeartbeatMonitor) IsRunning() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.running
}

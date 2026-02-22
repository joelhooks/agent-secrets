// Package otel provides best-effort OTEL event emission for the agent-secrets daemon.
// Events are sent to the joelclaw system-bus worker's observability endpoint.
// All emission is fire-and-forget — failures never block daemon operation.
package otel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	defaultEndpoint = "http://localhost:3111/observability/emit"
	source          = "agent-secrets"
	httpTimeout     = 2 * time.Second
)

// Event represents a structured OTEL event matching the joelclaw schema.
type Event struct {
	ID         string                 `json:"id"`
	Timestamp  int64                  `json:"timestamp"`
	Level      string                 `json:"level"`
	Source     string                 `json:"source"`
	Component  string                 `json:"component"`
	Action     string                 `json:"action"`
	Success    bool                   `json:"success"`
	DurationMs *int64                 `json:"duration_ms,omitempty"`
	Error      string                 `json:"error,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// Emitter sends OTEL events to the system-bus worker.
type Emitter struct {
	endpoint string
	token    string
	client   *http.Client
	enabled  bool
	mu       sync.RWMutex
}

// NewEmitter creates an OTEL emitter. Checks for the system-bus endpoint
// on creation; if unreachable, emission is disabled (no-op).
func NewEmitter() *Emitter {
	endpoint := os.Getenv("OTEL_EMIT_ENDPOINT")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	token := os.Getenv("OTEL_EMIT_TOKEN")

	e := &Emitter{
		endpoint: endpoint,
		token:    token,
		client: &http.Client{
			Timeout: httpTimeout,
		},
		enabled: true,
	}

	// Quick probe — if the worker isn't running, disable emission silently
	go e.probe()

	return e
}

func (e *Emitter) probe() {
	resp, err := e.client.Get("http://localhost:3111/")
	if err != nil {
		e.mu.Lock()
		e.enabled = false
		e.mu.Unlock()
		return
	}
	resp.Body.Close()
	e.mu.Lock()
	e.enabled = resp.StatusCode == 200
	e.mu.Unlock()
}

// Emit sends an OTEL event. Best-effort, never returns an error.
func (e *Emitter) Emit(evt Event) {
	e.mu.RLock()
	enabled := e.enabled
	e.mu.RUnlock()
	if !enabled {
		return
	}

	evt.ID = uuid.New().String()
	evt.Timestamp = time.Now().UnixMilli()
	evt.Source = source
	go e.send(evt)
}

func (e *Emitter) send(evt Event) {
	body, err := json.Marshal(evt)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", e.endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if e.token != "" {
		req.Header.Set("X-Otel-Emit-Token", e.token)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		// Worker might have gone down — disable for now
		e.mu.Lock()
		e.enabled = false
		e.mu.Unlock()
		return
	}
	resp.Body.Close()
}

// EmitDaemonStart emits a daemon lifecycle start event.
func (e *Emitter) EmitDaemonStart(socketPath string, secretsCount int) {
	e.Emit(Event{
		Level:     "info",
		Component: "daemon",
		Action:    "daemon.started",
		Success:   true,
		Metadata: map[string]interface{}{
			"socket":        socketPath,
			"secrets_count": secretsCount,
			"pid":           os.Getpid(),
		},
	})
}

// EmitDaemonStop emits a daemon lifecycle stop event.
func (e *Emitter) EmitDaemonStop(uptime time.Duration) {
	uptimeMs := uptime.Milliseconds()
	e.Emit(Event{
		Level:      "info",
		Component:  "daemon",
		Action:     "daemon.stopped",
		Success:    true,
		DurationMs: &uptimeMs,
		Metadata: map[string]interface{}{
			"uptime_seconds": int64(uptime.Seconds()),
		},
	})
}

// EmitLeaseReplaced emits when an existing lease is replaced (dedup).
func (e *Emitter) EmitLeaseReplaced(secretName, clientID, oldLeaseID, newLeaseID string) {
	e.Emit(Event{
		Level:     "info",
		Component: "lease",
		Action:    "lease.replaced",
		Success:   true,
		Metadata: map[string]interface{}{
			"secret_name":  secretName,
			"client_id":    clientID,
			"old_lease_id": oldLeaseID,
			"new_lease_id": newLeaseID,
		},
	})
}

// EmitLeaseCleanup emits when expired leases are cleaned up.
func (e *Emitter) EmitLeaseCleanup(expiredCount int) {
	if expiredCount == 0 {
		return
	}
	e.Emit(Event{
		Level:     "debug",
		Component: "lease",
		Action:    "lease.cleanup",
		Success:   true,
		Metadata: map[string]interface{}{
			"expired_count": expiredCount,
		},
	})
}

// EmitCrashRecovery emits when startup detects and cleans stale state.
func (e *Emitter) EmitCrashRecovery(detail string) {
	e.Emit(Event{
		Level:     "warn",
		Component: "daemon",
		Action:    "daemon.crash_recovered",
		Success:   true,
		Metadata: map[string]interface{}{
			"detail": detail,
		},
	})
}

// EmitError emits an error event.
func (e *Emitter) EmitError(component, action, errMsg string, metadata map[string]interface{}) {
	e.Emit(Event{
		Level:     "error",
		Component: component,
		Action:    action,
		Success:   false,
		Error:     errMsg,
		Metadata:  metadata,
	})
}

// String returns a human-readable status.
func (e *Emitter) String() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.enabled {
		return fmt.Sprintf("otel: enabled (endpoint=%s)", e.endpoint)
	}
	return "otel: disabled (worker unreachable)"
}

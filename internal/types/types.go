// Package types defines shared types for the agent-secrets daemon.
package types

import (
	"time"
)

// Secret represents an encrypted secret with optional rotation configuration.
type Secret struct {
	Name        string    `json:"name"`
	Namespace   string    `json:"namespace"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	RotateVia   string    `json:"rotate_via,omitempty"` // Command to execute for rotation
	LastRotated time.Time `json:"last_rotated,omitempty"`
}

// FullName returns the fully qualified secret reference "namespace::name"
func (s *Secret) FullName() string {
	return s.Namespace + "::" + s.Name
}

// Lease represents a time-bounded access grant to a secret.
type Lease struct {
	ID         string    `json:"id"`
	Namespace  string    `json:"namespace"`
	SecretName string    `json:"secret_name"`
	ClientID   string    `json:"client_id"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Revoked    bool      `json:"revoked"`
}

// LeaseRequest represents a request to acquire a lease on a secret.
type LeaseRequest struct {
	Namespace  string        `json:"namespace"`
	SecretName string        `json:"secret_name"`
	ClientID   string        `json:"client_id"`
	TTL        time.Duration `json:"ttl"`
}

// LeaseResponse contains the lease details and the decrypted secret value.
type LeaseResponse struct {
	Lease *Lease `json:"lease"`
	Value string `json:"value"`
}

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Action     Action    `json:"action"`
	Namespace  string    `json:"namespace,omitempty"`
	SecretName string    `json:"secret_name,omitempty"`
	ClientID   string    `json:"client_id,omitempty"`
	LeaseID    string    `json:"lease_id,omitempty"`
	Details    string    `json:"details,omitempty"`
	Success    bool      `json:"success"`
}

// Action represents the type of operation being audited.
type Action string

const (
	ActionSecretAdd     Action = "secret_add"
	ActionSecretDelete  Action = "secret_delete"
	ActionSecretRotate  Action = "secret_rotate"
	ActionLeaseAcquire  Action = "lease_acquire"
	ActionLeaseRevoke   Action = "lease_revoke"
	ActionLeaseExpire   Action = "lease_expire"
	ActionKillswitch    Action = "killswitch"
	ActionDaemonStart   Action = "daemon_start"
	ActionDaemonStop    Action = "daemon_stop"
	ActionHeartbeatFail Action = "heartbeat_fail"
)

// RotationResult contains the outcome of a rotation hook execution.
type RotationResult struct {
	SecretName string    `json:"secret_name"`
	Success    bool      `json:"success"`
	Output     string    `json:"output,omitempty"`
	Error      string    `json:"error,omitempty"`
	ExecutedAt time.Time `json:"executed_at"`
}

// KillswitchOptions controls killswitch behavior.
type KillswitchOptions struct {
	RevokeAll  bool `json:"revoke_all"`
	RotateAll  bool `json:"rotate_all"`
	WipeStore  bool `json:"wipe_store"`
}

// HeartbeatConfig configures optional remote heartbeat monitoring.
type HeartbeatConfig struct {
	Enabled  bool          `json:"enabled"`
	URL      string        `json:"url,omitempty"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	// FailAction determines what happens on heartbeat failure
	FailAction KillswitchOptions `json:"fail_action"`
}

// DaemonStatus represents the current state of the daemon.
type DaemonStatus struct {
	Running       bool          `json:"running"`
	StartedAt     time.Time     `json:"started_at"`
	SecretsCount  int           `json:"secrets_count"`
	ActiveLeases  int           `json:"active_leases"`
	Heartbeat     *HeartbeatConfig `json:"heartbeat,omitempty"`
}

// RPCRequest represents a JSON-RPC 2.0 request.
type RPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      interface{} `json:"id"`
}

// RPCResponse represents a JSON-RPC 2.0 response.
type RPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// RPCError represents a JSON-RPC 2.0 error.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	RPCParseError     = -32700
	RPCInvalidRequest = -32600
	RPCMethodNotFound = -32601
	RPCInvalidParams  = -32602
	RPCInternalError  = -32603
)

// Application-specific error codes (starting at -32000).
const (
	RPCSecretNotFound  = -32000
	RPCLeaseNotFound   = -32001
	RPCLeaseExpired    = -32002
	RPCRotationFailed  = -32003
	RPCEncryptionError = -32004
	RPCDecryptionError = -32005
	RPCUnauthorized    = -32006
)

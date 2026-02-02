// Package daemon implements a JSON-RPC daemon over Unix sockets.
package daemon

import "time"

// JSON-RPC method names
const (
	MethodInit      = "secrets.init"
	MethodAdd       = "secrets.add"
	MethodGet       = "secrets.get"
	MethodDelete    = "secrets.delete"
	MethodList      = "secrets.list"
	MethodLease     = "secrets.lease"
	MethodRevoke    = "secrets.revoke"
	MethodRevokeAll = "secrets.revokeAll"
	MethodRotate    = "secrets.rotate"
	MethodAudit     = "secrets.audit"
	MethodStatus    = "secrets.status"
)

// InitParams are parameters for secrets.init
type InitParams struct {
	// No parameters needed - uses default config
}

// InitResult is the result of secrets.init
type InitResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// AddParams are parameters for secrets.add
type AddParams struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	RotateVia string `json:"rotate_via,omitempty"`
}

// AddResult is the result of secrets.add
type AddResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// GetParams are parameters for secrets.get (not allowed directly)
type GetParams struct {
	Name string `json:"name"`
}

// DeleteParams are parameters for secrets.delete
type DeleteParams struct {
	Name string `json:"name"`
}

// DeleteResult is the result of secrets.delete
type DeleteResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ListParams are parameters for secrets.list
type ListParams struct {
	// No parameters needed
}

// ListResult is the result of secrets.list
type ListResult struct {
	Secrets []SecretMetadata `json:"secrets"`
}

// SecretMetadata contains non-sensitive secret information
type SecretMetadata struct {
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	RotateVia   string    `json:"rotate_via,omitempty"`
	LastRotated time.Time `json:"last_rotated,omitempty"`
}

// LeaseParams are parameters for secrets.lease
type LeaseParams struct {
	SecretName string `json:"secret_name"`
	ClientID   string `json:"client_id"`
	TTL        string `json:"ttl"` // Duration string like "1h", "30m"
}

// LeaseResult is the result of secrets.lease
type LeaseResult struct {
	LeaseID   string    `json:"lease_id"`
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RevokeParams are parameters for secrets.revoke
type RevokeParams struct {
	LeaseID string `json:"lease_id"`
}

// RevokeResult is the result of secrets.revoke
type RevokeResult struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// RevokeAllParams are parameters for secrets.revokeAll
type RevokeAllParams struct {
	// No parameters needed
}

// RevokeAllResult is the result of secrets.revokeAll
type RevokeAllResult struct {
	Success        bool   `json:"success"`
	LeasesRevoked  int    `json:"leases_revoked"`
	Message        string `json:"message"`
}

// RotateParams are parameters for secrets.rotate
type RotateParams struct {
	SecretName string `json:"secret_name"`
}

// RotateResult is the result of secrets.rotate
type RotateResult struct {
	Success    bool      `json:"success"`
	Output     string    `json:"output,omitempty"`
	Error      string    `json:"error,omitempty"`
	ExecutedAt time.Time `json:"executed_at"`
}

// AuditParams are parameters for secrets.audit
type AuditParams struct {
	Tail int `json:"tail"` // Number of recent entries to return (0 = all)
}

// AuditResult is the result of secrets.audit
type AuditResult struct {
	Entries []AuditEntryJSON `json:"entries"`
}

// AuditEntryJSON is a JSON-friendly audit entry
type AuditEntryJSON struct {
	Timestamp  time.Time `json:"timestamp"`
	Action     string    `json:"action"`
	SecretName string    `json:"secret_name,omitempty"`
	ClientID   string    `json:"client_id,omitempty"`
	LeaseID    string    `json:"lease_id,omitempty"`
	Details    string    `json:"details,omitempty"`
	Success    bool      `json:"success"`
}

// StatusParams are parameters for secrets.status
type StatusParams struct {
	// No parameters needed
}

// StatusResult is the result of secrets.status (uses types.DaemonStatus)

// Package lease implements session-scoped lease management with TTL-based access control.
package lease

import (
	"time"

	"github.com/joelhooks/agent-secrets/internal/types"
)

// LeaseOptions configures lease creation parameters.
type LeaseOptions struct {
	SecretName string
	ClientID   string
	TTL        time.Duration
}

// IsExpired returns true if the lease has expired.
func IsExpired(lease *types.Lease) bool {
	return time.Now().After(lease.ExpiresAt)
}

// IsValid returns true if the lease is neither expired nor revoked.
func IsValid(lease *types.Lease) bool {
	if lease == nil {
		return false
	}
	return !lease.Revoked && !IsExpired(lease)
}

// TimeRemaining returns the duration until the lease expires.
// Returns 0 if the lease has already expired or is revoked.
func TimeRemaining(lease *types.Lease) time.Duration {
	if lease == nil || lease.Revoked {
		return 0
	}
	remaining := time.Until(lease.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

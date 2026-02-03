// Package audit provides append-only audit logging for secret operations.
package audit

import (
	"time"

	"github.com/joelhooks/agent-secrets/internal/types"
)

// EntryBuilder provides a fluent interface for creating audit entries.
type EntryBuilder struct {
	entry *types.AuditEntry
}

// NewEntry creates a new audit entry builder with the given action and success status.
// The timestamp is set to the current time.
func NewEntry(action types.Action, success bool) *EntryBuilder {
	return &EntryBuilder{
		entry: &types.AuditEntry{
			Timestamp: time.Now(),
			Action:    action,
			Success:   success,
		},
	}
}

// WithSecret adds the secret name to the audit entry.
func (b *EntryBuilder) WithSecret(name string) *EntryBuilder {
	b.entry.SecretName = name
	return b
}

// WithClient adds the client ID to the audit entry.
func (b *EntryBuilder) WithClient(id string) *EntryBuilder {
	b.entry.ClientID = id
	return b
}

// WithLease adds the lease ID to the audit entry.
func (b *EntryBuilder) WithLease(id string) *EntryBuilder {
	b.entry.LeaseID = id
	return b
}

// WithDetails adds additional details to the audit entry.
func (b *EntryBuilder) WithDetails(details string) *EntryBuilder {
	b.entry.Details = details
	return b
}

// WithNamespace adds the namespace to the audit entry.
func (b *EntryBuilder) WithNamespace(namespace string) *EntryBuilder {
	b.entry.Namespace = namespace
	return b
}

// Build returns the constructed audit entry.
func (b *EntryBuilder) Build() *types.AuditEntry {
	return b.entry
}

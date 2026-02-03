package lease

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/joelhooks/agent-secrets/internal/audit"
	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// Manager handles lease lifecycle with TTL-based access control.
type Manager struct {
	mu          sync.RWMutex
	leases      map[string]*types.Lease
	cfg         *config.Config
	auditLogger *audit.Logger

	// Cleanup loop control
	cleanupDone chan struct{}
	cleanupStop chan struct{}
}

// NewManager creates a new lease manager and loads persisted leases.
func NewManager(cfg *config.Config, auditLogger *audit.Logger) (*Manager, error) {
	m := &Manager{
		leases:      make(map[string]*types.Lease),
		cfg:         cfg,
		auditLogger: auditLogger,
		cleanupDone: make(chan struct{}),
		cleanupStop: make(chan struct{}),
	}

	// Load persisted leases
	if err := m.Load(); err != nil {
		// Log but don't fail if leases file doesn't exist
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load leases: %w", err)
		}
	}

	return m, nil
}

// Acquire creates a new lease for the specified secret.
func (m *Manager) Acquire(namespace, secretName, clientID string, ttl time.Duration) (*types.Lease, error) {
	// Validate TTL
	if ttl <= 0 {
		ttl = m.cfg.DefaultLeaseTTL
	}
	if ttl > m.cfg.MaxLeaseTTL {
		entry := audit.NewEntry(types.ActionLeaseAcquire, false).
			WithNamespace(namespace).
			WithSecret(secretName).
			WithClient(clientID).
			WithDetails(fmt.Sprintf("TTL %v exceeds max %v", ttl, m.cfg.MaxLeaseTTL)).
			Build()
		_ = m.auditLogger.Log(entry)
		return nil, types.ErrInvalidTTL
	}

	now := time.Now()
	lease := &types.Lease{
		ID:         uuid.New().String(),
		Namespace:  namespace,
		SecretName: secretName,
		ClientID:   clientID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
		Revoked:    false,
	}

	m.mu.Lock()
	m.leases[lease.ID] = lease
	m.mu.Unlock()

	// Persist and log
	_ = m.Save()

	entry := audit.NewEntry(types.ActionLeaseAcquire, true).
		WithNamespace(namespace).
		WithSecret(secretName).
		WithClient(clientID).
		WithLease(lease.ID).
		WithDetails(fmt.Sprintf("TTL: %v", ttl)).
		Build()
	_ = m.auditLogger.Log(entry)

	return lease, nil
}

// Revoke marks a lease as revoked.
func (m *Manager) Revoke(leaseID string) error {
	m.mu.Lock()
	lease, exists := m.leases[leaseID]
	if !exists {
		m.mu.Unlock()
		entry := audit.NewEntry(types.ActionLeaseRevoke, false).
			WithLease(leaseID).
			WithDetails("lease not found").
			Build()
		_ = m.auditLogger.Log(entry)
		return types.ErrLeaseNotFound
	}

	lease.Revoked = true
	m.mu.Unlock()

	_ = m.Save()

	entry := audit.NewEntry(types.ActionLeaseRevoke, true).
		WithNamespace(lease.Namespace).
		WithSecret(lease.SecretName).
		WithClient(lease.ClientID).
		WithLease(leaseID).
		Build()
	_ = m.auditLogger.Log(entry)

	return nil
}

// RevokeAll revokes all active leases (for killswitch).
func (m *Manager) RevokeAll() error {
	m.mu.Lock()
	count := 0
	for _, lease := range m.leases {
		if !lease.Revoked {
			lease.Revoked = true
			count++
		}
	}
	m.mu.Unlock()

	_ = m.Save()

	entry := audit.NewEntry(types.ActionKillswitch, true).
		WithDetails(fmt.Sprintf("revoked %d leases", count)).
		Build()
	_ = m.auditLogger.Log(entry)

	return nil
}

// RevokeBySecret revokes all leases for a specific secret in a namespace.
func (m *Manager) RevokeBySecret(namespace, secretName string) int {
	m.mu.Lock()
	count := 0
	for _, lease := range m.leases {
		if lease.Namespace == namespace && lease.SecretName == secretName && !lease.Revoked {
			lease.Revoked = true
			count++
		}
	}
	m.mu.Unlock()

	_ = m.Save()

	entry := audit.NewEntry(types.ActionLeaseRevoke, true).
		WithNamespace(namespace).
		WithSecret(secretName).
		WithDetails(fmt.Sprintf("revoked %d leases", count)).
		Build()
	_ = m.auditLogger.Log(entry)

	return count
}

// RevokeByNamespace revokes all leases in a specific namespace.
func (m *Manager) RevokeByNamespace(namespace string) int {
	m.mu.Lock()
	count := 0
	for _, lease := range m.leases {
		if lease.Namespace == namespace && !lease.Revoked {
			lease.Revoked = true
			count++
		}
	}
	m.mu.Unlock()

	_ = m.Save()

	entry := audit.NewEntry(types.ActionLeaseRevoke, true).
		WithNamespace(namespace).
		WithDetails(fmt.Sprintf("revoked %d leases in namespace", count)).
		Build()
	_ = m.auditLogger.Log(entry)

	return count
}

// Get retrieves a lease by ID.
func (m *Manager) Get(leaseID string) (*types.Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lease, exists := m.leases[leaseID]
	if !exists {
		return nil, types.ErrLeaseNotFound
	}

	// Return a copy to avoid race conditions
	leaseCopy := *lease
	return &leaseCopy, nil
}

// List returns all active (non-expired, non-revoked) leases.
func (m *Manager) List() []*types.Lease {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var active []*types.Lease
	for _, lease := range m.leases {
		if IsValid(lease) {
			// Return a copy
			leaseCopy := *lease
			active = append(active, &leaseCopy)
		}
	}

	return active
}

// CleanupExpired removes expired leases and logs expirations.
func (m *Manager) CleanupExpired() {
	m.mu.Lock()
	var expired []string
	for id, lease := range m.leases {
		if !lease.Revoked && IsExpired(lease) {
			expired = append(expired, id)

			entry := audit.NewEntry(types.ActionLeaseExpire, true).
				WithNamespace(lease.Namespace).
				WithSecret(lease.SecretName).
				WithClient(lease.ClientID).
				WithLease(id).
				Build()
			_ = m.auditLogger.Log(entry)
		}
	}

	// Remove expired leases
	for _, id := range expired {
		delete(m.leases, id)
	}
	m.mu.Unlock()

	if len(expired) > 0 {
		_ = m.Save()
	}
}

// StartCleanupLoop starts a background goroutine that periodically cleans up expired leases.
func (m *Manager) StartCleanupLoop(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		defer close(m.cleanupDone)

		for {
			select {
			case <-ticker.C:
				m.CleanupExpired()
			case <-m.cleanupStop:
				return
			}
		}
	}()
}

// StopCleanupLoop stops the cleanup goroutine.
func (m *Manager) StopCleanupLoop() {
	close(m.cleanupStop)
	<-m.cleanupDone
}

// Save persists non-expired, non-revoked leases to disk.
func (m *Manager) Save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Only persist active leases
	var toSave []*types.Lease
	for _, lease := range m.leases {
		if !lease.Revoked && !IsExpired(lease) {
			toSave = append(toSave, lease)
		}
	}

	data, err := json.MarshalIndent(toSave, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal leases: %w", err)
	}

	if err := os.WriteFile(m.cfg.LeasesPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write leases: %w", err)
	}

	return nil
}

// Load restores leases from disk.
func (m *Manager) Load() error {
	data, err := os.ReadFile(m.cfg.LeasesPath)
	if err != nil {
		return err
	}

	var leases []*types.Lease
	if err := json.Unmarshal(data, &leases); err != nil {
		return fmt.Errorf("failed to unmarshal leases: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Load only non-expired, non-revoked leases
	for _, lease := range leases {
		if !lease.Revoked && !IsExpired(lease) {
			m.leases[lease.ID] = lease
		}
	}

	return nil
}

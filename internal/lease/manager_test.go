package lease

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/audit"
	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/types"
)

func setupTestManager(t *testing.T) (*Manager, string) {
	t.Helper()

	tmpDir := t.TempDir()
	cfg := &config.Config{
		Directory:       tmpDir,
		LeasesPath:      filepath.Join(tmpDir, "leases.json"),
		AuditPath:       filepath.Join(tmpDir, "audit.log"),
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
	}

	auditLogger, err := audit.New(cfg.AuditPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	t.Cleanup(func() { auditLogger.Close() })

	mgr, err := NewManager(cfg, auditLogger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	return mgr, tmpDir
}

func TestNewManager(t *testing.T) {
	mgr, _ := setupTestManager(t)

	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}

	if mgr.leases == nil {
		t.Error("leases map is nil")
	}
}

func TestAcquire(t *testing.T) {
	mgr, _ := setupTestManager(t)

	tests := []struct {
		name       string
		secretName string
		clientID   string
		ttl        time.Duration
		wantErr    bool
		errType    error
	}{
		{
			name:       "valid lease with default TTL",
			secretName: "test-secret",
			clientID:   "client-1",
			ttl:        0, // should use default
			wantErr:    false,
		},
		{
			name:       "valid lease with custom TTL",
			secretName: "test-secret-2",
			clientID:   "client-2",
			ttl:        2 * time.Hour,
			wantErr:    false,
		},
		{
			name:       "TTL exceeds max",
			secretName: "test-secret-3",
			clientID:   "client-3",
			ttl:        48 * time.Hour,
			wantErr:    true,
			errType:    types.ErrInvalidTTL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lease, err := mgr.Acquire(tt.secretName, tt.clientID, tt.ttl)

			if tt.wantErr {
				if err == nil {
					t.Error("Acquire() expected error, got nil")
				}
				if tt.errType != nil && err != tt.errType {
					t.Errorf("Acquire() error = %v, want %v", err, tt.errType)
				}
				return
			}

			if err != nil {
				t.Fatalf("Acquire() unexpected error: %v", err)
			}

			if lease == nil {
				t.Fatal("Acquire() returned nil lease")
			}

			if lease.ID == "" {
				t.Error("lease ID is empty")
			}

			if lease.SecretName != tt.secretName {
				t.Errorf("lease.SecretName = %v, want %v", lease.SecretName, tt.secretName)
			}

			if lease.ClientID != tt.clientID {
				t.Errorf("lease.ClientID = %v, want %v", lease.ClientID, tt.clientID)
			}

			if lease.CreatedAt.IsZero() {
				t.Error("lease.CreatedAt is zero")
			}

			if lease.ExpiresAt.IsZero() {
				t.Error("lease.ExpiresAt is zero")
			}

			if lease.Revoked {
				t.Error("lease.Revoked should be false")
			}

			if !lease.ExpiresAt.After(lease.CreatedAt) {
				t.Error("lease.ExpiresAt should be after CreatedAt")
			}
		})
	}
}

func TestGet(t *testing.T) {
	mgr, _ := setupTestManager(t)

	// Create a lease
	lease, err := mgr.Acquire("test-secret", "client-1", 1*time.Hour)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	// Get the lease
	retrieved, err := mgr.Get(lease.ID)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	if retrieved.ID != lease.ID {
		t.Errorf("Get() ID = %v, want %v", retrieved.ID, lease.ID)
	}

	// Get non-existent lease
	_, err = mgr.Get("non-existent")
	if err != types.ErrLeaseNotFound {
		t.Errorf("Get() error = %v, want %v", err, types.ErrLeaseNotFound)
	}
}

func TestRevoke(t *testing.T) {
	mgr, _ := setupTestManager(t)

	// Create a lease
	lease, err := mgr.Acquire("test-secret", "client-1", 1*time.Hour)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	// Revoke it
	err = mgr.Revoke(lease.ID)
	if err != nil {
		t.Fatalf("Revoke() failed: %v", err)
	}

	// Verify it's revoked
	retrieved, err := mgr.Get(lease.ID)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	if !retrieved.Revoked {
		t.Error("lease should be revoked")
	}

	// Try to revoke non-existent lease
	err = mgr.Revoke("non-existent")
	if err != types.ErrLeaseNotFound {
		t.Errorf("Revoke() error = %v, want %v", err, types.ErrLeaseNotFound)
	}
}

func TestRevokeAll(t *testing.T) {
	mgr, _ := setupTestManager(t)

	// Create multiple leases
	_, err := mgr.Acquire("secret-1", "client-1", 1*time.Hour)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	_, err = mgr.Acquire("secret-2", "client-2", 1*time.Hour)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	// Revoke all
	err = mgr.RevokeAll()
	if err != nil {
		t.Fatalf("RevokeAll() failed: %v", err)
	}

	// Verify all are revoked
	active := mgr.List()
	if len(active) != 0 {
		t.Errorf("List() returned %d active leases, want 0", len(active))
	}
}

func TestRevokeBySecret(t *testing.T) {
	mgr, _ := setupTestManager(t)

	// Create leases for different secrets
	_, err := mgr.Acquire("secret-1", "client-1", 1*time.Hour)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	lease2, err := mgr.Acquire("secret-1", "client-2", 1*time.Hour)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	lease3, err := mgr.Acquire("secret-2", "client-3", 1*time.Hour)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	// Revoke all leases for secret-1
	err = mgr.RevokeBySecret("secret-1")
	if err != nil {
		t.Fatalf("RevokeBySecret() failed: %v", err)
	}

	// Verify secret-1 leases are revoked
	retrieved, _ := mgr.Get(lease2.ID)
	if !retrieved.Revoked {
		t.Error("lease for secret-1 should be revoked")
	}

	// Verify secret-2 lease is still active
	retrieved, _ = mgr.Get(lease3.ID)
	if retrieved.Revoked {
		t.Error("lease for secret-2 should not be revoked")
	}
}

func TestList(t *testing.T) {
	mgr, _ := setupTestManager(t)

	// Create some leases
	lease1, _ := mgr.Acquire("secret-1", "client-1", 1*time.Hour)
	_, _ = mgr.Acquire("secret-2", "client-2", 1*time.Hour)

	// List should return both
	active := mgr.List()
	if len(active) != 2 {
		t.Errorf("List() returned %d leases, want 2", len(active))
	}

	// Revoke one
	_ = mgr.Revoke(lease1.ID)

	// List should return only one
	active = mgr.List()
	if len(active) != 1 {
		t.Errorf("List() returned %d leases, want 1", len(active))
	}
}

func TestCleanupExpired(t *testing.T) {
	mgr, _ := setupTestManager(t)

	// Create a lease that expires immediately
	lease, err := mgr.Acquire("test-secret", "client-1", 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	// Wait for it to expire
	time.Sleep(10 * time.Millisecond)

	// Run cleanup
	mgr.CleanupExpired()

	// Verify it's been removed
	_, err = mgr.Get(lease.ID)
	if err != types.ErrLeaseNotFound {
		t.Errorf("Get() error = %v, want %v", err, types.ErrLeaseNotFound)
	}
}

func TestSaveLoad(t *testing.T) {
	mgr, tmpDir := setupTestManager(t)

	// Create a lease
	lease, err := mgr.Acquire("test-secret", "client-1", 1*time.Hour)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	// Save
	err = mgr.Save()
	if err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Create a new manager and load
	cfg := &config.Config{
		Directory:       tmpDir,
		LeasesPath:      filepath.Join(tmpDir, "leases.json"),
		AuditPath:       filepath.Join(tmpDir, "audit.log"),
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
	}

	auditLogger, err := audit.New(cfg.AuditPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}
	defer auditLogger.Close()

	mgr2, err := NewManager(cfg, auditLogger)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Verify lease was loaded
	retrieved, err := mgr2.Get(lease.ID)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	if retrieved.ID != lease.ID {
		t.Errorf("loaded lease ID = %v, want %v", retrieved.ID, lease.ID)
	}

	if retrieved.SecretName != lease.SecretName {
		t.Errorf("loaded lease SecretName = %v, want %v", retrieved.SecretName, lease.SecretName)
	}
}

func TestSaveLoadExcludesExpiredAndRevoked(t *testing.T) {
	mgr, tmpDir := setupTestManager(t)

	// Create an expired lease
	_, _ = mgr.Acquire("expired-secret", "client-1", 1*time.Millisecond)
	time.Sleep(10 * time.Millisecond)

	// Create a revoked lease
	revoked, _ := mgr.Acquire("revoked-secret", "client-2", 1*time.Hour)
	_ = mgr.Revoke(revoked.ID)

	// Create a valid lease
	valid, _ := mgr.Acquire("valid-secret", "client-3", 1*time.Hour)

	// Save
	err := mgr.Save()
	if err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	// Load into new manager
	cfg := &config.Config{
		Directory:       tmpDir,
		LeasesPath:      filepath.Join(tmpDir, "leases.json"),
		AuditPath:       filepath.Join(tmpDir, "audit.log"),
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
	}

	auditLogger, _ := audit.New(cfg.AuditPath)
	defer auditLogger.Close()

	mgr2, err := NewManager(cfg, auditLogger)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	// Only the valid lease should be loaded
	active := mgr2.List()
	if len(active) != 1 {
		t.Errorf("List() returned %d leases, want 1", len(active))
	}

	if active[0].ID != valid.ID {
		t.Errorf("loaded lease ID = %v, want %v", active[0].ID, valid.ID)
	}
}

func TestLoadNonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &config.Config{
		Directory:       tmpDir,
		LeasesPath:      filepath.Join(tmpDir, "nonexistent.json"),
		AuditPath:       filepath.Join(tmpDir, "audit.log"),
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
	}

	auditLogger, _ := audit.New(cfg.AuditPath)
	defer auditLogger.Close()

	// Should not fail if file doesn't exist
	mgr, err := NewManager(cfg, auditLogger)
	if err != nil {
		t.Fatalf("NewManager() failed: %v", err)
	}

	if mgr == nil {
		t.Fatal("NewManager() returned nil")
	}
}

func TestCleanupLoop(t *testing.T) {
	mgr, _ := setupTestManager(t)

	// Create a lease that expires quickly
	_, err := mgr.Acquire("test-secret", "client-1", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Acquire() failed: %v", err)
	}

	// Start cleanup loop with short interval
	mgr.StartCleanupLoop(25 * time.Millisecond)

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Stop cleanup
	mgr.StopCleanupLoop()

	// Verify lease was cleaned up
	active := mgr.List()
	if len(active) != 0 {
		t.Errorf("List() returned %d leases, want 0", len(active))
	}
}

func TestIsExpiredHelper(t *testing.T) {
	// Test the helper functions used by manager
	validLease := &types.Lease{
		ID:        "test",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Revoked:   false,
	}

	if !IsValid(validLease) {
		t.Error("IsValid() should return true for valid lease")
	}

	if IsExpired(validLease) {
		t.Error("IsExpired() should return false for valid lease")
	}

	remaining := TimeRemaining(validLease)
	if remaining <= 0 {
		t.Error("TimeRemaining() should return positive duration for valid lease")
	}
}

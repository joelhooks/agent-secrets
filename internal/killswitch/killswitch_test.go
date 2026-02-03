package killswitch

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/audit"
	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/lease"
	"github.com/joelhooks/agent-secrets/internal/rotation"
	"github.com/joelhooks/agent-secrets/internal/store"
	"github.com/joelhooks/agent-secrets/internal/types"
)

func setupTest(t *testing.T) (*Killswitch, *lease.Manager, *store.Store, *audit.Logger, func()) {
	t.Helper()

	tmpDir := t.TempDir()
	cfg := &config.Config{
		Directory:        tmpDir,
		IdentityPath:     filepath.Join(tmpDir, "identity"),
		SecretsPath:      filepath.Join(tmpDir, "secrets.age"),
		LeasesPath:       filepath.Join(tmpDir, "leases.json"),
		AuditPath:        filepath.Join(tmpDir, "audit.log"),
		DefaultLeaseTTL:  5 * time.Minute,
		MaxLeaseTTL:      1 * time.Hour,
		RotationTimeout:  30 * time.Second,
	}

	// Initialize store
	st := store.New(cfg)
	if err := st.Init(); err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	if err := st.Load(); err != nil {
		t.Fatalf("failed to load store: %v", err)
	}

	// Create audit logger
	auditLogger, err := audit.New(cfg.AuditPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	// Create lease manager
	lm, err := lease.NewManager(cfg, auditLogger)
	if err != nil {
		t.Fatalf("failed to create lease manager: %v", err)
	}

	// Create rotation executor
	re := rotation.NewExecutor(cfg, st, auditLogger)

	// Create killswitch
	ks := NewKillswitch(lm, re, st, auditLogger)

	cleanup := func() {
		auditLogger.Close()
		os.RemoveAll(tmpDir)
	}

	return ks, lm, st, auditLogger, cleanup
}

func TestKillswitch_Activate_RevokeAll(t *testing.T) {
	ks, lm, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Add a secret
	if err := st.Add("test-secret", "secret-value", ""); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	// Create some leases
	_, err := lm.Acquire("default", "test-secret", "client-1", 5*time.Minute)
	if err != nil {
		t.Fatalf("failed to acquire lease: %v", err)
	}

	_, err = lm.Acquire("default", "test-secret", "client-2", 5*time.Minute)
	if err != nil {
		t.Fatalf("failed to acquire lease: %v", err)
	}

	// Verify we have active leases
	activeLeases := lm.List()
	if len(activeLeases) != 2 {
		t.Fatalf("expected 2 active leases, got %d", len(activeLeases))
	}

	// Activate killswitch with revoke all
	err = ks.Activate(types.KillswitchOptions{RevokeAll: true})
	if err != nil {
		t.Fatalf("killswitch activation failed: %v", err)
	}

	// Verify all leases are revoked
	activeLeases = lm.List()
	if len(activeLeases) != 0 {
		t.Fatalf("expected 0 active leases after revoke, got %d", len(activeLeases))
	}

	// Verify audit log entry
	entries, err := auditLogger.Tail(1)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected audit log entry")
	}
	if entries[0].Action != types.ActionKillswitch {
		t.Errorf("expected action %s, got %s", types.ActionKillswitch, entries[0].Action)
	}
	if !entries[0].Success {
		t.Error("expected success=true in audit log")
	}
}

func TestKillswitch_Activate_WipeStore(t *testing.T) {
	ks, _, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Add some secrets
	if err := st.Add("secret-1", "value-1", ""); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}
	if err := st.Add("secret-2", "value-2", ""); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	// Verify secrets exist
	secrets, err := st.List()
	if err != nil {
		t.Fatalf("failed to list secrets: %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}

	// Activate killswitch with wipe store
	err = ks.Activate(types.KillswitchOptions{WipeStore: true})
	if err != nil {
		t.Fatalf("killswitch activation failed: %v", err)
	}

	// Verify store is wiped
	secrets, err = st.List()
	if err != nil {
		t.Fatalf("failed to list secrets: %v", err)
	}
	if len(secrets) != 0 {
		t.Fatalf("expected 0 secrets after wipe, got %d", len(secrets))
	}

	// Verify audit log entry
	entries, err := auditLogger.Tail(1)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected audit log entry")
	}
	if entries[0].Action != types.ActionKillswitch {
		t.Errorf("expected action %s, got %s", types.ActionKillswitch, entries[0].Action)
	}
}

func TestKillswitch_Activate_RotateAll(t *testing.T) {
	ks, _, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Add a secret with a rotation hook (echo command)
	if err := st.Add("test-secret", "secret-value", "echo 'rotated'"); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	// Activate killswitch with rotate all
	err := ks.Activate(types.KillswitchOptions{RotateAll: true})
	if err != nil {
		t.Fatalf("killswitch activation failed: %v", err)
	}

	// Verify audit log entry for killswitch
	entries, err := auditLogger.Tail(1)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected audit log entry")
	}
	if entries[0].Action != types.ActionKillswitch {
		t.Errorf("expected action %s, got %s", types.ActionKillswitch, entries[0].Action)
	}
}

func TestKillswitch_Activate_AllOptions(t *testing.T) {
	ks, lm, st, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Add a secret with rotation hook
	if err := st.Add("test-secret", "secret-value", "echo 'rotated'"); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	// Create a lease
	_, err := lm.Acquire("default", "test-secret", "client-1", 5*time.Minute)
	if err != nil {
		t.Fatalf("failed to acquire lease: %v", err)
	}

	// Activate killswitch with all options
	err = ks.Activate(types.KillswitchOptions{
		RevokeAll:  true,
		RotateAll:  true,
		WipeStore:  true,
	})
	if err != nil {
		t.Fatalf("killswitch activation failed: %v", err)
	}

	// Verify all leases are revoked
	activeLeases := lm.List()
	if len(activeLeases) != 0 {
		t.Fatalf("expected 0 active leases, got %d", len(activeLeases))
	}

	// Verify store is wiped
	secrets, err := st.List()
	if err != nil {
		t.Fatalf("failed to list secrets: %v", err)
	}
	if len(secrets) != 0 {
		t.Fatalf("expected 0 secrets, got %d", len(secrets))
	}

	// Verify audit log entry
	entries, err := auditLogger.Tail(1)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected audit log entry")
	}
	if entries[0].Action != types.ActionKillswitch {
		t.Errorf("expected action %s, got %s", types.ActionKillswitch, entries[0].Action)
	}
	if !entries[0].Success {
		t.Error("expected success=true in audit log")
	}
}

func TestKillswitch_Activate_NoOptions(t *testing.T) {
	ks, _, _, auditLogger, cleanup := setupTest(t)
	defer cleanup()

	// Activate killswitch with no options
	err := ks.Activate(types.KillswitchOptions{})
	if err != nil {
		t.Fatalf("killswitch activation failed: %v", err)
	}

	// Should still log audit entry
	entries, err := auditLogger.Tail(1)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected audit log entry")
	}
	if entries[0].Action != types.ActionKillswitch {
		t.Errorf("expected action %s, got %s", types.ActionKillswitch, entries[0].Action)
	}
}

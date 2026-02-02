package killswitch

import (
	"net/http"
	"net/http/httptest"
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

func setupHeartbeatTest(t *testing.T) (*HeartbeatMonitor, *Killswitch, *store.Store, *audit.Logger, func()) {
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

	// Create heartbeat config (will be updated with server URL in tests)
	hbConfig := types.HeartbeatConfig{
		Enabled:  true,
		Interval: 100 * time.Millisecond,
		Timeout:  1 * time.Second,
		FailAction: types.KillswitchOptions{
			RevokeAll: true,
		},
	}

	// Create heartbeat monitor
	hm := NewHeartbeatMonitor(hbConfig, ks, auditLogger)

	cleanup := func() {
		hm.Stop()
		auditLogger.Close()
		os.RemoveAll(tmpDir)
	}

	return hm, ks, st, auditLogger, cleanup
}

func TestHeartbeatMonitor_Success(t *testing.T) {
	// Create a test server that always returns 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hm, _, _, _, cleanup := setupHeartbeatTest(t)
	defer cleanup()

	// Update config with server URL
	hm.config.URL = server.URL

	// Start monitoring
	hm.Start()

	// Verify monitor is running
	if !hm.IsRunning() {
		t.Error("expected monitor to be running")
	}

	// Wait for a few heartbeat intervals
	time.Sleep(300 * time.Millisecond)

	// Stop monitoring
	hm.Stop()

	// Give it a moment to fully stop
	time.Sleep(50 * time.Millisecond)

	// Verify monitor is not running
	if hm.IsRunning() {
		t.Error("expected monitor to be stopped")
	}

	// No killswitch should have been triggered
	// (We can't easily verify this without more extensive mocking)
}

func TestHeartbeatMonitor_FailureTriggersKillswitch(t *testing.T) {
	// Create a test server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	hm, _, st, auditLogger, cleanup := setupHeartbeatTest(t)
	defer cleanup()

	// Add a secret to verify wipe
	if err := st.Add("test-secret", "secret-value", ""); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	// Update config with server URL and wipe action
	hm.config.URL = server.URL
	hm.config.FailAction = types.KillswitchOptions{
		WipeStore: true,
	}

	// Start monitoring
	hm.Start()

	// Wait for heartbeat to fail and killswitch to trigger
	time.Sleep(300 * time.Millisecond)

	// Verify store was wiped
	secrets, err := st.List()
	if err != nil {
		t.Fatalf("failed to list secrets: %v", err)
	}
	if len(secrets) != 0 {
		t.Fatalf("expected store to be wiped, got %d secrets", len(secrets))
	}

	// Verify audit log has heartbeat failure entry
	entries, err := auditLogger.Tail(10)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}

	foundHeartbeatFail := false
	foundKillswitch := false
	for _, entry := range entries {
		if entry.Action == types.ActionHeartbeatFail {
			foundHeartbeatFail = true
		}
		if entry.Action == types.ActionKillswitch {
			foundKillswitch = true
		}
	}

	if !foundHeartbeatFail {
		t.Error("expected ActionHeartbeatFail in audit log")
	}
	if !foundKillswitch {
		t.Error("expected ActionKillswitch in audit log")
	}

	// Monitor should have stopped after failure
	if hm.IsRunning() {
		t.Error("expected monitor to stop after failure")
	}
}

func TestHeartbeatMonitor_NetworkError(t *testing.T) {
	hm, _, st, auditLogger, cleanup := setupHeartbeatTest(t)
	defer cleanup()

	// Add a secret to verify wipe
	if err := st.Add("test-secret", "secret-value", ""); err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	// Use an invalid URL to trigger network error
	hm.config.URL = "http://localhost:9999"
	hm.config.FailAction = types.KillswitchOptions{
		WipeStore: true,
	}

	// Start monitoring
	hm.Start()

	// Wait for heartbeat to fail
	time.Sleep(300 * time.Millisecond)

	// Verify store was wiped
	secrets, err := st.List()
	if err != nil {
		t.Fatalf("failed to list secrets: %v", err)
	}
	if len(secrets) != 0 {
		t.Fatalf("expected store to be wiped, got %d secrets", len(secrets))
	}

	// Verify audit log has heartbeat failure
	entries, err := auditLogger.Tail(10)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}

	foundHeartbeatFail := false
	for _, entry := range entries {
		if entry.Action == types.ActionHeartbeatFail {
			foundHeartbeatFail = true
			break
		}
	}

	if !foundHeartbeatFail {
		t.Error("expected ActionHeartbeatFail in audit log")
	}

	// Monitor should have stopped after failure
	if hm.IsRunning() {
		t.Error("expected monitor to stop after failure")
	}
}

func TestHeartbeatMonitor_Check_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hm, _, _, _, cleanup := setupHeartbeatTest(t)
	defer cleanup()

	hm.config.URL = server.URL

	if err := hm.check(); err != nil {
		t.Errorf("expected check to succeed, got error: %v", err)
	}
}

func TestHeartbeatMonitor_Check_Non2xxStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	hm, _, _, _, cleanup := setupHeartbeatTest(t)
	defer cleanup()

	hm.config.URL = server.URL

	err := hm.check()
	if err == nil {
		t.Error("expected check to fail for non-2xx status")
	}
}

func TestHeartbeatMonitor_Check_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hm, _, _, _, cleanup := setupHeartbeatTest(t)
	defer cleanup()

	hm.config.URL = server.URL
	hm.config.Timeout = 100 * time.Millisecond
	hm.client.Timeout = hm.config.Timeout

	err := hm.check()
	if err == nil {
		t.Error("expected check to timeout")
	}
}

func TestHeartbeatMonitor_StartStopIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hm, _, _, _, cleanup := setupHeartbeatTest(t)
	defer cleanup()

	hm.config.URL = server.URL

	// Start multiple times
	hm.Start()
	hm.Start()
	hm.Start()

	if !hm.IsRunning() {
		t.Error("expected monitor to be running")
	}

	// Stop multiple times
	hm.Stop()
	hm.Stop()
	hm.Stop()

	// Give it a moment to fully stop
	time.Sleep(50 * time.Millisecond)

	if hm.IsRunning() {
		t.Error("expected monitor to be stopped")
	}
}

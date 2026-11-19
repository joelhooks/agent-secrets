package daemon

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/store"
)

// testStoreConfig returns a daemon config rooted in a fresh temp directory.
func testStoreConfig(t *testing.T) *config.Config {
	t.Helper()
	tempDir := t.TempDir()
	return &config.Config{
		Directory:       tempDir,
		SocketPath:      tempDir + "/store.sock",
		IdentityPath:    tempDir + "/identity.age",
		SecretsPath:     tempDir + "/secrets.age",
		AuditPath:       tempDir + "/audit.log",
		LeasesPath:      tempDir + "/leases.json",
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}
}

// closeLogger shuts down an audit logger, tolerating its error the way the
// production code does for best-effort cleanup.
func closeLogger(t *testing.T, logger interface{ Close() error }) {
	t.Helper()
	t.Cleanup(func() { _ = logger.Close() })
}

// seedStore initializes a store on disk and adds the named secrets.
func seedStore(t *testing.T, cfg *config.Config, secrets map[string]string) {
	t.Helper()
	st := store.New(cfg)
	if err := st.Init(); err != nil {
		t.Fatalf("failed to seed store: %v", err)
	}
	for name, value := range secrets {
		if err := st.Add(name, value, ""); err != nil {
			t.Fatalf("failed to seed secret %q: %v", name, err)
		}
	}
}

// TestNewDaemonInitializesWhenStoreAbsent covers the genuine first run: with no
// files on disk the daemon must create the store rather than refuse to start.
func TestNewDaemonInitializesWhenStoreAbsent(t *testing.T) {
	cfg := testStoreConfig(t)

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon on a fresh directory failed: %v", err)
	}
	if d.storeState != StoreStateInitialized {
		t.Errorf("storeState = %q, want %q", d.storeState, StoreStateInitialized)
	}
	if count := d.Status().SecretsCount; count != 0 {
		t.Errorf("secrets count = %d, want 0 for a new store", count)
	}
}

// TestNewDaemonReloadsExistingSecretsAcrossRestart is the round-trip from the
// issue: init, add, stop, start again, and the count must be unchanged.
func TestNewDaemonReloadsExistingSecretsAcrossRestart(t *testing.T) {
	cfg := testStoreConfig(t)
	seedStore(t, cfg, map[string]string{"mytoken": "topsecret-value-1"})

	first, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("first start failed: %v", err)
	}
	if count := first.Status().SecretsCount; count != 1 {
		t.Fatalf("before restart secrets count = %d, want 1", count)
	}
	if err := first.auditLogger.Close(); err != nil {
		t.Fatalf("failed to close audit logger: %v", err)
	}

	second, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("restart failed: %v", err)
	}
	closeLogger(t, second.auditLogger)

	if count := second.Status().SecretsCount; count != 1 {
		t.Errorf("after restart secrets count = %d, want 1", count)
	}
	if second.storeState != StoreStateLoaded {
		t.Errorf("storeState = %q, want %q", second.storeState, StoreStateLoaded)
	}
	if _, err := second.store.Get("mytoken"); err != nil {
		t.Errorf("secret was not reloaded: %v", err)
	}
}

// TestNewDaemonRefusesToStartOnCorruptStore is the core of the fix: a store
// that exists but cannot be read must not be silently re-initialized. Before
// the fix this produced an empty, healthy-looking daemon whose next write
// destroyed the ciphertext on disk.
func TestNewDaemonRefusesToStartOnCorruptStore(t *testing.T) {
	cfg := testStoreConfig(t)
	seedStore(t, cfg, map[string]string{"mytoken": "topsecret-value-1"})

	// Replace the ciphertext with something that cannot be decrypted.
	if err := os.WriteFile(cfg.SecretsPath, []byte("not a valid age file"), 0600); err != nil {
		t.Fatalf("failed to corrupt store: %v", err)
	}

	d, err := NewDaemon(cfg)
	if err == nil {
		if d != nil && d.auditLogger != nil {
			_ = d.auditLogger.Close()
		}
		t.Fatal("NewDaemon accepted a corrupt store; it must fail closed")
	}
}

// TestNewDaemonTightensOverPermissiveStore covers the Windows trigger on any
// platform: the bytes on disk are intact and only the file mode is wrong, so
// the daemon should repair the mode and load the secrets rather than discard
// them.
func TestNewDaemonTightensOverPermissiveStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows; the check is skipped there")
	}

	cfg := testStoreConfig(t)
	seedStore(t, cfg, map[string]string{"mytoken": "topsecret-value-1"})

	if err := os.Chmod(cfg.SecretsPath, 0644); err != nil {
		t.Fatalf("failed to relax permissions: %v", err)
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("NewDaemon should repair permissions and start, got: %v", err)
	}
	closeLogger(t, d.auditLogger)

	if count := d.Status().SecretsCount; count != 1 {
		t.Errorf("secrets count = %d, want 1 (secrets must survive the restart)", count)
	}
	if d.storeWarning == "" {
		t.Error("expected a store warning describing the permission repair")
	}

	info, err := os.Stat(cfg.SecretsPath)
	if err != nil {
		t.Fatalf("failed to stat store: %v", err)
	}
	if mode := info.Mode().Perm(); mode != store.RequiredKeyPermissions {
		t.Errorf("store permissions = %04o, want %04o", mode, store.RequiredKeyPermissions)
	}
}

// TestNoSecretIsLostWhenStorePermissionsAreRelaxed is the escalation from the
// issue: it is not enough that the count survives, the previously stored secret
// must still be resolvable after a restart and a subsequent write.
func TestNoSecretIsLostWhenStorePermissionsAreRelaxed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows; the check is skipped there")
	}

	cfg := testStoreConfig(t)
	seedStore(t, cfg, map[string]string{"mytoken": "topsecret-value-1"})

	if err := os.Chmod(cfg.SecretsPath, 0644); err != nil {
		t.Fatalf("failed to relax permissions: %v", err)
	}

	d, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("restart failed: %v", err)
	}
	closeLogger(t, d.auditLogger)

	// Write a second secret, which is the operation that used to destroy the
	// first one by persisting the daemon's empty in-memory state.
	if err := d.store.Add("secondtoken", "topsecret-value-2", ""); err != nil {
		t.Fatalf("failed to add second secret: %v", err)
	}

	value, err := d.store.Get("mytoken")
	if err != nil {
		t.Fatalf("the original secret was lost: %v", err)
	}
	if value != "topsecret-value-1" {
		t.Errorf("original secret value = %q, want %q", value, "topsecret-value-1")
	}

	// And it must survive a further restart, read back from disk.
	if err := d.auditLogger.Close(); err != nil {
		t.Fatalf("failed to close audit logger: %v", err)
	}
	restarted, err := NewDaemon(cfg)
	if err != nil {
		t.Fatalf("second restart failed: %v", err)
	}
	closeLogger(t, restarted.auditLogger)

	if count := restarted.Status().SecretsCount; count != 2 {
		t.Errorf("secrets count after second restart = %d, want 2", count)
	}
	if _, err := restarted.store.Get("mytoken"); err != nil {
		t.Errorf("original secret did not survive the second restart: %v", err)
	}
}

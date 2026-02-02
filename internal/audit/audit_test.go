package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestNewEntry(t *testing.T) {
	builder := NewEntry(types.ActionSecretAdd, true)

	if builder == nil {
		t.Fatal("NewEntry returned nil")
	}

	entry := builder.Build()

	if entry.Action != types.ActionSecretAdd {
		t.Errorf("expected action %v, got %v", types.ActionSecretAdd, entry.Action)
	}

	if !entry.Success {
		t.Error("expected success to be true")
	}

	if entry.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}
}

func TestEntryBuilders(t *testing.T) {
	entry := NewEntry(types.ActionLeaseAcquire, true).
		WithSecret("test-secret").
		WithClient("test-client").
		WithLease("test-lease").
		WithDetails("test details").
		Build()

	if entry.SecretName != "test-secret" {
		t.Errorf("expected secret name 'test-secret', got %q", entry.SecretName)
	}

	if entry.ClientID != "test-client" {
		t.Errorf("expected client ID 'test-client', got %q", entry.ClientID)
	}

	if entry.LeaseID != "test-lease" {
		t.Errorf("expected lease ID 'test-lease', got %q", entry.LeaseID)
	}

	if entry.Details != "test details" {
		t.Errorf("expected details 'test details', got %q", entry.Details)
	}
}

func TestLogger(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	// Create logger
	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	// Log some entries
	entries := []*types.AuditEntry{
		NewEntry(types.ActionDaemonStart, true).WithDetails("started").Build(),
		NewEntry(types.ActionSecretAdd, true).WithSecret("api-key").Build(),
		NewEntry(types.ActionLeaseAcquire, true).
			WithSecret("api-key").
			WithClient("client-1").
			WithLease("lease-1").
			Build(),
		NewEntry(types.ActionLeaseRevoke, true).WithLease("lease-1").Build(),
		NewEntry(types.ActionSecretDelete, false).
			WithSecret("api-key").
			WithDetails("in use").
			Build(),
	}

	for _, entry := range entries {
		if err := logger.Log(entry); err != nil {
			t.Fatalf("failed to log entry: %v", err)
		}
	}

	// Verify file exists and has correct permissions
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("failed to stat log file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
	}

	// Test Tail
	tail, err := logger.Tail(3)
	if err != nil {
		t.Fatalf("failed to tail log: %v", err)
	}

	if len(tail) != 3 {
		t.Errorf("expected 3 entries, got %d", len(tail))
	}

	// Verify last entry
	lastEntry := tail[len(tail)-1]
	if lastEntry.Action != types.ActionSecretDelete {
		t.Errorf("expected last action to be secret_delete, got %v", lastEntry.Action)
	}

	if lastEntry.Success {
		t.Error("expected last entry success to be false")
	}
}

func TestTailLessThanN(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	// Log 2 entries
	logger.Log(NewEntry(types.ActionDaemonStart, true).Build())
	logger.Log(NewEntry(types.ActionDaemonStop, true).Build())

	// Request more than exist
	tail, err := logger.Tail(10)
	if err != nil {
		t.Fatalf("failed to tail log: %v", err)
	}

	if len(tail) != 2 {
		t.Errorf("expected 2 entries, got %d", len(tail))
	}
}

func TestQuery(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	// Log entries with different actions and secrets
	now := time.Now()
	entries := []*types.AuditEntry{
		NewEntry(types.ActionSecretAdd, true).WithSecret("secret1").Build(),
		NewEntry(types.ActionSecretAdd, true).WithSecret("secret2").Build(),
		NewEntry(types.ActionLeaseAcquire, true).WithSecret("secret1").Build(),
		NewEntry(types.ActionLeaseRevoke, true).WithSecret("secret1").Build(),
	}

	for _, entry := range entries {
		if err := logger.Log(entry); err != nil {
			t.Fatalf("failed to log entry: %v", err)
		}
		time.Sleep(time.Millisecond) // Ensure timestamps differ
	}

	// Test query by action
	action := types.ActionSecretAdd
	results, err := logger.Query(QueryFilter{Action: &action})
	if err != nil {
		t.Fatalf("failed to query log: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 secret_add entries, got %d", len(results))
	}

	// Test query by secret name
	secretName := "secret1"
	results, err = logger.Query(QueryFilter{SecretName: &secretName})
	if err != nil {
		t.Fatalf("failed to query log: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 entries for secret1, got %d", len(results))
	}

	// Test query by time range
	startTime := now.Add(-time.Second)
	endTime := now.Add(time.Hour)
	results, err = logger.Query(QueryFilter{
		StartTime: &startTime,
		EndTime:   &endTime,
	})
	if err != nil {
		t.Fatalf("failed to query log: %v", err)
	}

	if len(results) != 4 {
		t.Errorf("expected 4 entries in time range, got %d", len(results))
	}

	// Test combined filters
	results, err = logger.Query(QueryFilter{
		Action:     &action,
		SecretName: &secretName,
	})
	if err != nil {
		t.Fatalf("failed to query log: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 entry matching both filters, got %d", len(results))
	}
}

func TestQueryEmptyLog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	results, err := logger.Query(QueryFilter{})
	if err != nil {
		t.Fatalf("failed to query empty log: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected 0 entries from empty log, got %d", len(results))
	}
}

func TestConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	// Write from multiple goroutines
	const numGoroutines = 10
	const entriesPerGoroutine = 10

	done := make(chan bool)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < entriesPerGoroutine; j++ {
				entry := NewEntry(types.ActionLeaseAcquire, true).
					WithClient("client-" + string(rune(id))).
					Build()
				if err := logger.Log(entry); err != nil {
					t.Errorf("goroutine %d failed to log: %v", id, err)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all entries were written
	tail, err := logger.Tail(numGoroutines * entriesPerGoroutine)
	if err != nil {
		t.Fatalf("failed to tail log: %v", err)
	}

	if len(tail) != numGoroutines*entriesPerGoroutine {
		t.Errorf("expected %d entries, got %d", numGoroutines*entriesPerGoroutine, len(tail))
	}
}

func TestClose(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	// Log an entry
	if err := logger.Log(NewEntry(types.ActionDaemonStart, true).Build()); err != nil {
		t.Fatalf("failed to log entry: %v", err)
	}

	// Close logger
	if err := logger.Close(); err != nil {
		t.Fatalf("failed to close logger: %v", err)
	}

	// Verify subsequent operations fail gracefully
	err = logger.Log(NewEntry(types.ActionDaemonStop, true).Build())
	if err == nil {
		t.Error("expected error when logging to closed logger")
	}
}

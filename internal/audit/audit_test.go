package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/types"
)

type countingAuditTailReader struct {
	*os.File
	bytesRead int64
}

func (r *countingAuditTailReader) ReadAt(p []byte, offset int64) (int, error) {
	n, err := r.File.ReadAt(p, offset)
	r.bytesRead += int64(n)
	return n, err
}

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

func TestTailLargeLimitDoesNotPreallocateRequestedSize(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	if err := logger.Log(NewEntry(types.ActionDaemonStart, true).Build()); err != nil {
		t.Fatalf("failed to log entry: %v", err)
	}

	got, err := logger.Tail(int(^uint(0) >> 1))
	if err != nil {
		t.Fatalf("failed to tail with a large limit: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Tail() returned %d entries, want 1", len(got))
	}
}

func TestTailDoesNotScanOversizedPrefix(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	// A bounded tail should not inspect an unrelated oversized prefix. A hard
	// crash can leave the audit log cold, so scanning from byte zero makes
	// health checks depend on the log's lifetime size.
	const prefixSize = int64(256 << 20)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("failed to create sparse audit log: %v", err)
	}
	if err := f.Truncate(prefixSize); err != nil {
		f.Close()
		t.Fatalf("failed to create oversized prefix: %v", err)
	}
	if _, err := f.WriteAt([]byte{'\n'}, prefixSize-1); err != nil {
		f.Close()
		t.Fatalf("failed to terminate oversized prefix: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close sparse audit log: %v", err)
	}

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	want := []*types.AuditEntry{
		NewEntry(types.ActionSecretAdd, true).WithSecret("first").Build(),
		NewEntry(types.ActionLeaseAcquire, true).WithSecret("second").Build(),
	}
	for _, entry := range want {
		if err := logger.Log(entry); err != nil {
			t.Fatalf("failed to log entry: %v", err)
		}
	}

	got, err := logger.Tail(len(want))
	if err != nil {
		t.Fatalf("failed to tail bounded audit entries: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("Tail() returned %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Action != want[i].Action || got[i].SecretName != want[i].SecretName {
			t.Errorf("Tail()[%d] = action %q secret %q, want action %q secret %q", i, got[i].Action, got[i].SecretName, want[i].Action, want[i].SecretName)
		}
	}

	f, err = os.Open(logPath)
	if err != nil {
		t.Fatalf("failed to reopen audit log: %v", err)
	}
	defer f.Close()
	countingReader := &countingAuditTailReader{File: f}
	if _, err := readTailEntries(countingReader, len(want)); err != nil {
		t.Fatalf("failed to measure bounded tail: %v", err)
	}
	if countingReader.bytesRead > 1024*1024 {
		t.Fatalf("bounded tail read %d bytes from an unrelated prefix", countingReader.bytesRead)
	}
}

func TestTailSupportsEntryAcrossReadBlocks(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	largeDetails := strings.Repeat("x", 96*1024)
	want := []*types.AuditEntry{
		NewEntry(types.ActionSecretAdd, true).WithSecret("first").Build(),
		NewEntry(types.ActionLeaseAcquire, true).WithSecret("large").WithDetails(largeDetails).Build(),
		NewEntry(types.ActionLeaseRevoke, true).WithSecret("last").Build(),
	}
	for _, entry := range want {
		if err := logger.Log(entry); err != nil {
			t.Fatalf("failed to log entry: %v", err)
		}
	}

	got, err := logger.Tail(len(want))
	if err != nil {
		t.Fatalf("failed to tail entries spanning read blocks: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("Tail() returned %d entries, want %d", len(got), len(want))
	}
	if got[1].SecretName != "large" || got[1].Details != largeDetails {
		t.Errorf("Tail() did not reassemble the entry spanning read blocks")
	}
	if got[2].SecretName != "last" {
		t.Errorf("Tail() returned entries out of order, last secret = %q", got[2].SecretName)
	}
}

func TestLoggerRejectsOversizedEntry(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	entry := NewEntry(types.ActionLeaseAcquire, true).
		WithDetails(strings.Repeat("x", int(maxAuditEntrySize))).
		Build()
	if err := logger.Log(entry); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("Log() error = %v, want maximum size error", err)
	}
}

func TestTailReportsOversizedTerminatedEntry(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	entry := NewEntry(types.ActionLeaseAcquire, true).
		WithDetails(strings.Repeat("x", int(maxAuditEntrySize))).
		Build()
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal oversized entry: %v", err)
	}
	if err := os.WriteFile(logPath, append(data, '\n'), 0600); err != nil {
		t.Fatalf("failed to write oversized entry: %v", err)
	}

	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	if _, err := logger.Tail(1); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("Tail() error = %v, want maximum size error", err)
	}
}

func TestTailSkipsMalformedAndCrashTruncatedLines(t *testing.T) {
	tests := []struct {
		name        string
		between     string
		truncatedAt string
	}{
		{name: "malformed line between valid entries", between: "not-json\n"},
		{name: "unterminated final fragment", truncatedAt: `{"timestamp":`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "audit.log")
			logger, err := New(logPath)
			if err != nil {
				t.Fatalf("failed to create logger: %v", err)
			}
			defer logger.Close()

			if err := logger.Log(NewEntry(types.ActionSecretAdd, true).WithSecret("first").Build()); err != nil {
				t.Fatalf("failed to log first entry: %v", err)
			}
			if tt.between != "" {
				f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatalf("failed to open audit log: %v", err)
				}
				if _, err := f.WriteString(tt.between); err != nil {
					f.Close()
					t.Fatalf("failed to append malformed line: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Fatalf("failed to close audit log: %v", err)
				}
			}
			if err := logger.Log(NewEntry(types.ActionLeaseAcquire, true).WithSecret("second").Build()); err != nil {
				t.Fatalf("failed to log second entry: %v", err)
			}
			if tt.truncatedAt != "" {
				f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatalf("failed to open audit log: %v", err)
				}
				if _, err := f.WriteString(tt.truncatedAt); err != nil {
					f.Close()
					t.Fatalf("failed to append truncated fragment: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Fatalf("failed to close audit log: %v", err)
				}
			}

			got, err := logger.Tail(2)
			if err != nil {
				t.Fatalf("failed to tail audit log: %v", err)
			}
			if len(got) != 2 {
				t.Fatalf("Tail() returned %d entries, want 2", len(got))
			}
			if got[0].SecretName != "first" || got[1].SecretName != "second" {
				t.Fatalf("Tail() returned secrets %q, %q", got[0].SecretName, got[1].SecretName)
			}
		})
	}
}

func TestTailSkipsOversizedCrashSuffix(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := New(logPath)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	defer logger.Close()

	if err := logger.Log(NewEntry(types.ActionDaemonStart, true).WithSecret("valid").Build()); err != nil {
		t.Fatalf("failed to log entry: %v", err)
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("failed to stat audit log: %v", err)
	}
	if err := os.Truncate(logPath, info.Size()+maxAuditEntrySize+1); err != nil {
		t.Fatalf("failed to append oversized crash suffix: %v", err)
	}

	got, err := logger.Tail(1)
	if err != nil {
		t.Fatalf("failed to tail past oversized crash suffix: %v", err)
	}
	if len(got) != 1 || got[0].SecretName != "valid" {
		t.Fatalf("Tail() did not recover the last valid entry")
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

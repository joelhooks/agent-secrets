package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/joelhooks/agent-secrets/internal/types"
)

// Logger provides thread-safe append-only audit logging.
type Logger struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// New creates a new audit logger that writes to the specified path.
// The file is opened in append mode with 0600 permissions.
func New(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}

	return &Logger{
		file: f,
		path: path,
	}, nil
}

// Log writes an audit entry to the log file as a JSON line and syncs immediately.
func (l *Logger) Log(entry *types.AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}

	if _, err := l.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write audit entry: %w", err)
	}

	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync audit log: %w", err)
	}

	return nil
}

// Tail returns the last n entries from the audit log.
func (l *Logger) Tail(n int) ([]*types.AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Reopen file for reading
	f, err := os.Open(l.path)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log for reading: %w", err)
	}
	defer f.Close()

	// Read all entries
	var entries []*types.AuditEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry types.AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			// Skip malformed lines
			continue
		}
		entries = append(entries, &entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}

	// Return last n entries
	if len(entries) <= n {
		return entries, nil
	}
	return entries[len(entries)-n:], nil
}

// QueryFilter defines criteria for filtering audit entries.
type QueryFilter struct {
	Action     *types.Action
	SecretName *string
	Namespace  *string
	StartTime  *time.Time
	EndTime    *time.Time
}

// Query returns all audit entries that match the given filter.
func (l *Logger) Query(filter QueryFilter) ([]*types.AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Reopen file for reading
	f, err := os.Open(l.path)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log for reading: %w", err)
	}
	defer f.Close()

	var entries []*types.AuditEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry types.AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			// Skip malformed lines
			continue
		}

		// Apply filters
		if filter.Action != nil && entry.Action != *filter.Action {
			continue
		}
		if filter.SecretName != nil && entry.SecretName != *filter.SecretName {
			continue
		}
		if filter.Namespace != nil && entry.Namespace != *filter.Namespace {
			continue
		}
		if filter.StartTime != nil && entry.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && entry.Timestamp.After(*filter.EndTime) {
			continue
		}

		entries = append(entries, &entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}

	return entries, nil
}

// Close closes the audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		if err := l.file.Close(); err != nil {
			return fmt.Errorf("failed to close audit log: %w", err)
		}
		l.file = nil
	}
	return nil
}

// Ensure Logger implements io.Closer
var _ io.Closer = (*Logger)(nil)

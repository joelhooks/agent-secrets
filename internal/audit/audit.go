package audit

import (
	"bufio"
	"bytes"
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
	if int64(len(data)) > maxAuditEntrySize {
		return fmt.Errorf("audit entry exceeds maximum size of %d bytes", maxAuditEntrySize)
	}

	if _, err := l.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write audit entry: %w", err)
	}

	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("failed to sync audit log: %w", err)
	}

	return nil
}

// Tail returns the last n valid entries without scanning the audit log from the
// beginning. Runtime is bounded by the requested tail and nearby malformed
// lines instead of the log's lifetime size.
func (l *Logger) Tail(n int) ([]*types.AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if n <= 0 {
		return []*types.AuditEntry{}, nil
	}

	f, err := os.Open(l.path)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log for reading: %w", err)
	}
	defer f.Close()

	entries, err := readTailEntries(f, n)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}
	return entries, nil
}

const (
	tailReadBlockSize      int64 = 64 * 1024
	maxAuditEntrySize      int64 = 1024 * 1024
	maxTailInitialCapacity       = 1000
)

type auditTailReader interface {
	io.ReaderAt
	Stat() (os.FileInfo, error)
}

func readTailEntries(f auditTailReader, n int) ([]*types.AuditEntry, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	position := info.Size()
	lineEnd := position
	unterminatedSuffixEnd := int64(-1)
	if position > 0 {
		var lastByte [1]byte
		if _, err := f.ReadAt(lastByte[:], position-1); err != nil {
			return nil, err
		}
		if lastByte[0] != '\n' {
			unterminatedSuffixEnd = position
		}
	}

	initialCapacity := n
	if initialCapacity > maxTailInitialCapacity {
		initialCapacity = maxTailInitialCapacity
	}
	reversed := make([]*types.AuditEntry, 0, initialCapacity)
	block := make([]byte, int(tailReadBlockSize))

	for position > 0 && len(reversed) < n {
		readSize := tailReadBlockSize
		if position < readSize {
			readSize = position
		}
		position -= readSize

		chunk := block[:int(readSize)]
		if _, err := f.ReadAt(chunk, position); err != nil {
			return nil, err
		}

		for i := len(chunk) - 1; i >= 0 && len(reversed) < n; i-- {
			if chunk[i] != '\n' {
				continue
			}

			lineStart := position + int64(i) + 1
			entry, err := readAuditEntry(f, lineStart, lineEnd, lineEnd == unterminatedSuffixEnd)
			if err != nil {
				return nil, err
			}
			if entry != nil {
				reversed = append(reversed, entry)
			}
			lineEnd = position + int64(i)
		}
	}

	if position == 0 && len(reversed) < n {
		entry, err := readAuditEntry(f, 0, lineEnd, lineEnd == unterminatedSuffixEnd)
		if err != nil {
			return nil, err
		}
		if entry != nil {
			reversed = append(reversed, entry)
		}
	}

	entries := make([]*types.AuditEntry, len(reversed))
	for i, entry := range reversed {
		entries[len(reversed)-1-i] = entry
	}
	return entries, nil
}

func readAuditEntry(f io.ReaderAt, start, end int64, skipOversized bool) (*types.AuditEntry, error) {
	lineSize := end - start
	if lineSize <= 0 {
		return nil, nil
	}
	if lineSize > maxAuditEntrySize {
		if skipOversized {
			return nil, nil
		}
		return nil, fmt.Errorf("audit entry exceeds maximum size of %d bytes", maxAuditEntrySize)
	}

	line := make([]byte, int(lineSize))
	if _, err := f.ReadAt(line, start); err != nil {
		return nil, err
	}
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil, nil
	}

	var entry types.AuditEntry
	if err := json.Unmarshal(line, &entry); err != nil {
		return nil, nil
	}
	return &entry, nil
}

// QueryFilter defines criteria for filtering audit entries.
type QueryFilter struct {
	Action     *types.Action
	SecretName *string
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

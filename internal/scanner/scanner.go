package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Finding represents a detected secret in a file.
type Finding struct {
	File        string
	Line        int
	Column      int
	PatternName string
	Value       string
	Severity    Severity
}

// ScanResult represents the result of a scan operation.
type ScanResult struct {
	Findings     []Finding
	ScannedFiles int
	Duration     time.Duration
}

// Scanner scans files for exposed secrets.
type Scanner struct {
	patterns  []Pattern
	excludes  []string
	maxSize   int64 // max file size in bytes
	recursive bool
}

// NewScanner creates a new Scanner with the specified patterns and exclusions.
func NewScanner(patterns []Pattern, excludes []string) *Scanner {
	return &Scanner{
		patterns:  patterns,
		excludes:  excludes,
		maxSize:   10 * 1024 * 1024, // 10MB default
		recursive: false,
	}
}

// WithMaxSize sets the maximum file size to scan.
func (s *Scanner) WithMaxSize(maxBytes int64) *Scanner {
	s.maxSize = maxBytes
	return s
}

// WithRecursive enables or disables recursive scanning.
func (s *Scanner) WithRecursive(recursive bool) *Scanner {
	s.recursive = recursive
	return s
}

// Scan scans the specified path (file or directory) for secrets.
func (s *Scanner) Scan(path string) (ScanResult, error) {
	start := time.Now()
	result := ScanResult{
		Findings: []Finding{},
	}

	info, err := os.Stat(path)
	if err != nil {
		return result, fmt.Errorf("failed to stat path: %w", err)
	}

	if info.IsDir() {
		if err := s.scanDirectory(path, &result); err != nil {
			return result, err
		}
	} else {
		findings, err := s.ScanFile(path)
		if err != nil {
			return result, err
		}
		result.Findings = append(result.Findings, findings...)
		result.ScannedFiles = 1
	}

	result.Duration = time.Since(start)
	return result, nil
}

// scanDirectory scans all files in a directory.
func (s *Scanner) scanDirectory(dirPath string, result *ScanResult) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		fullPath := filepath.Join(dirPath, entry.Name())

		// Skip excluded paths
		if s.isExcluded(fullPath) {
			continue
		}

		if entry.IsDir() {
			if s.recursive {
				if err := s.scanDirectory(fullPath, result); err != nil {
					return err
				}
			}
			continue
		}

		// Scan file
		findings, err := s.ScanFile(fullPath)
		if err != nil {
			// Log error but continue scanning
			continue
		}

		result.Findings = append(result.Findings, findings...)
		result.ScannedFiles++
	}

	return nil
}

// ScanFile scans a single file for secrets.
func (s *Scanner) ScanFile(filePath string) ([]Finding, error) {
	// Check file size
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	if info.Size() > s.maxSize {
		return nil, fmt.Errorf("file too large: %d bytes (max: %d)", info.Size(), s.maxSize)
	}

	// Skip binary files
	if isBinaryFile(filePath) {
		return nil, nil
	}

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var findings []Finding
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check each pattern
		for _, pattern := range s.patterns {
			matches := pattern.Regex.FindAllStringIndex(line, -1)
			if matches == nil {
				continue
			}

			for _, match := range matches {
				value := line[match[0]:match[1]]
				findings = append(findings, Finding{
					File:        filePath,
					Line:        lineNum,
					Column:      match[0] + 1, // 1-indexed
					PatternName: pattern.Name,
					Value:       value,
					Severity:    pattern.Severity,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan file: %w", err)
	}

	return findings, nil
}

// isExcluded checks if a path matches any exclusion pattern.
// Matches against directory/file base names, not arbitrary substrings.
func (s *Scanner) isExcluded(path string) bool {
	// Check each path component against exclusion patterns
	parts := strings.Split(path, string(filepath.Separator))
	for _, exclude := range s.excludes {
		for _, part := range parts {
			if part == exclude {
				return true
			}
		}
	}
	return false
}

// isBinaryFile performs a simple heuristic check for binary files.
func isBinaryFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".zip": true, ".tar": true, ".gz": true, ".bz2": true,
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
		".pdf": true, ".doc": true, ".docx": true, ".xls": true,
		".xlsx": true, ".ppt": true, ".pptx": true,
		".bin": true, ".dat": true, ".db": true,
	}
	return binaryExts[ext]
}

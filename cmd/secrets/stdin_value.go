package main

import (
	"fmt"
	"io"
)

// maxPipedSecretBytes bounds a secret read from piped stdin. PEM keys, service-account JSON and
// similar multi-line values fit comfortably; anything larger is refused rather than truncated.
const maxPipedSecretBytes = 1 << 20

// readPipedSecret reads the whole piped value, newlines included. Callers trim surrounding
// whitespace as before. The old bufio.Scanner path kept only the first line, which silently
// stored the header line of a PEM key and pushed callers onto --value (argv) instead.
func readPipedSecret(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxPipedSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("failed to read from stdin: %w", err)
	}
	if len(data) > maxPipedSecretBytes {
		return "", fmt.Errorf("stdin value is larger than %d bytes; refusing to store a truncated secret", maxPipedSecretBytes)
	}
	return string(data), nil
}

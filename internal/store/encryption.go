// Package store provides encrypted secret storage using Age encryption.
package store

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// GenerateIdentity creates a new age X25519 identity and saves it to the specified path.
func GenerateIdentity(path string) (*age.X25519Identity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", types.ErrEncryptionFailed, err)
	}

	// Marshal identity to armored format
	identityBytes := []byte(identity.String())

	// Write with secure permissions (0600)
	if err := os.WriteFile(path, identityBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write identity: %w", err)
	}

	return identity, nil
}

// LoadIdentity loads an age identity from the specified path.
func LoadIdentity(path string) (*age.X25519Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, types.ErrIdentityNotFound
		}
		return nil, fmt.Errorf("failed to read identity: %w", err)
	}

	// Parse the identity from the armored format
	identity, err := age.ParseX25519Identity(string(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", types.ErrInvalidIdentity, err)
	}

	return identity, nil
}

// Encrypt encrypts plaintext bytes using the provided age recipient.
func Encrypt(plaintext []byte, recipient age.Recipient) ([]byte, error) {
	if recipient == nil {
		return nil, fmt.Errorf("%w: recipient is nil", types.ErrEncryptionFailed)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", types.ErrEncryptionFailed, err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("%w: write failed: %v", types.ErrEncryptionFailed, err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("%w: close failed: %v", types.ErrEncryptionFailed, err)
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts ciphertext bytes using the provided age identity.
func Decrypt(ciphertext []byte, identity age.Identity) ([]byte, error) {
	if identity == nil {
		return nil, fmt.Errorf("%w: identity is nil", types.ErrDecryptionFailed)
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", types.ErrDecryptionFailed, err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("%w: read failed: %v", types.ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

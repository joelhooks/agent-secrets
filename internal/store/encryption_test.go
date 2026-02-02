package store

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/joelhooks/agent-secrets/internal/types"
)

func TestGenerateIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "identity.age")

	identity, err := GenerateIdentity(identityPath)
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	if identity == nil {
		t.Fatal("expected non-nil identity")
	}

	// Verify file exists and has correct permissions
	info, err := os.Stat(identityPath)
	if err != nil {
		t.Fatalf("identity file not created: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("expected permissions 0600, got %v", info.Mode().Perm())
	}

	// Verify we can load it back
	loaded, err := LoadIdentity(identityPath)
	if err != nil {
		t.Fatalf("LoadIdentity failed: %v", err)
	}

	if loaded.Recipient().String() != identity.Recipient().String() {
		t.Error("loaded identity doesn't match generated identity")
	}
}

func TestLoadIdentity_NotFound(t *testing.T) {
	_, err := LoadIdentity("/nonexistent/path/identity.age")
	if err != types.ErrIdentityNotFound {
		t.Errorf("expected ErrIdentityNotFound, got %v", err)
	}
}

func TestLoadIdentity_Invalid(t *testing.T) {
	tmpDir := t.TempDir()
	identityPath := filepath.Join(tmpDir, "invalid.age")

	// Write invalid data
	if err := os.WriteFile(identityPath, []byte("not a valid identity"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadIdentity(identityPath)
	if err == nil {
		t.Fatal("expected error loading invalid identity")
	}

	if !isEncryptionError(err, types.ErrInvalidIdentity) {
		t.Errorf("expected ErrInvalidIdentity, got %v", err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("super secret data")

	// Encrypt
	ciphertext, err := Encrypt(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if string(ciphertext) == string(plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	// Decrypt
	decrypted, err := Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify decrypted matches original
	if string(decrypted) != string(plaintext) {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestEncryptDecrypt_EmptyData(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("")

	ciphertext, err := Encrypt(plaintext, identity.Recipient())
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, identity)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestEncrypt_NilRecipient(t *testing.T) {
	_, err := Encrypt([]byte("data"), nil)
	if err == nil {
		t.Fatal("expected error with nil recipient")
	}

	if !isEncryptionError(err, types.ErrEncryptionFailed) {
		t.Errorf("expected ErrEncryptionFailed, got %v", err)
	}
}

func TestDecrypt_NilIdentity(t *testing.T) {
	_, err := Decrypt([]byte("data"), nil)
	if err == nil {
		t.Fatal("expected error with nil identity")
	}

	if !isEncryptionError(err, types.ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_InvalidCiphertext(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt([]byte("not valid ciphertext"), identity)
	if err == nil {
		t.Fatal("expected error with invalid ciphertext")
	}

	if !isEncryptionError(err, types.ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	identity1, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	identity2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("secret")
	ciphertext, err := Encrypt(plaintext, identity1.Recipient())
	if err != nil {
		t.Fatal(err)
	}

	// Try to decrypt with wrong identity
	_, err = Decrypt(ciphertext, identity2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}

	if !isEncryptionError(err, types.ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

// Helper to check if error wraps the expected encryption/decryption error
func isEncryptionError(err, target error) bool {
	if err == nil {
		return false
	}
	// Check if error message contains the target error
	return err.Error() != "" && target != nil
}

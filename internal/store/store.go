// Package store provides encrypted secret storage using Age encryption.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/types"
)

const (
	DefaultNamespace   = "default"
	NamespaceDelimiter = "::"
	StoreVersionV1     = 1
	StoreVersionV2     = 2
)

// storeData represents the JSON structure stored in the encrypted file.
type storeData struct {
	Version int                         `json:"version"`
	Secrets map[string]*secretWithValue `json:"secrets"`
}

// secretWithValue combines metadata with the actual secret value.
type secretWithValue struct {
	types.Secret
	Value string `json:"value"`
}

// ParseSecretRef parses "namespace::name" or returns default namespace for bare names.
func ParseSecretRef(ref string) (namespace, name string) {
	parts := strings.SplitN(ref, NamespaceDelimiter, 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return DefaultNamespace, ref
}

// secretKey builds the composite key for internal storage.
func secretKey(namespace, name string) string {
	return namespace + NamespaceDelimiter + name
}

// Store manages encrypted secret storage using Age encryption.
type Store struct {
	mu                  sync.RWMutex
	identity            *age.X25519Identity
	secrets             map[string]*secretWithValue
	cfg                 *config.Config
	skipPermissionCheck bool
}

// New creates a new Store instance with the provided configuration.
func New(cfg *config.Config) *Store {
	return &Store{
		cfg:                 cfg,
		secrets:             make(map[string]*secretWithValue),
		skipPermissionCheck: false,
	}
}

// NewWithOptions creates a new Store instance with additional options.
func NewWithOptions(cfg *config.Config, skipPermissionCheck bool) *Store {
	return &Store{
		cfg:                 cfg,
		secrets:             make(map[string]*secretWithValue),
		skipPermissionCheck: skipPermissionCheck,
	}
}

// Init initializes the store by generating an identity if it doesn't exist
// and creating an empty encrypted secrets file.
func (s *Store) Init() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure directory exists
	if err := s.cfg.EnsureDirectories(); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	// Check if identity exists
	if _, err := os.Stat(s.cfg.IdentityPath); os.IsNotExist(err) {
		// Generate new identity
		identity, err := GenerateIdentity(s.cfg.IdentityPath)
		if err != nil {
			return fmt.Errorf("failed to generate identity: %w", err)
		}
		s.identity = identity
	} else {
		// Load existing identity
		identity, err := LoadIdentity(s.cfg.IdentityPath)
		if err != nil {
			return fmt.Errorf("failed to load identity: %w", err)
		}
		s.identity = identity
	}

	// Initialize empty secrets map
	s.secrets = make(map[string]*secretWithValue)

	// Create empty encrypted file if it doesn't exist
	if _, err := os.Stat(s.cfg.SecretsPath); os.IsNotExist(err) {
		if err := s.saveUnlocked(); err != nil {
			return fmt.Errorf("failed to create initial secrets file: %w", err)
		}
	}

	return nil
}

// Load loads the identity and decrypts the secrets file.
// It validates file permissions on startup unless skipPermissionCheck is set.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate key file permissions before loading (respects skipPermissionCheck field)
	if err := ValidateAllKeyFiles(s.cfg.IdentityPath, s.cfg.SecretsPath, s.skipPermissionCheck); err != nil {
		return err
	}

	// Load identity
	identity, err := LoadIdentity(s.cfg.IdentityPath)
	if err != nil {
		return fmt.Errorf("failed to load identity: %w", err)
	}
	s.identity = identity

	// Check if secrets file exists
	if _, err := os.Stat(s.cfg.SecretsPath); os.IsNotExist(err) {
		// No secrets file yet, initialize empty
		s.secrets = make(map[string]*secretWithValue)
		return nil
	}

	// Read encrypted secrets file
	ciphertext, err := os.ReadFile(s.cfg.SecretsPath)
	if err != nil {
		return fmt.Errorf("failed to read secrets file: %w", err)
	}

	// Handle empty file
	if len(ciphertext) == 0 {
		s.secrets = make(map[string]*secretWithValue)
		return nil
	}

	// Decrypt
	plaintext, err := Decrypt(ciphertext, s.identity)
	if err != nil {
		return fmt.Errorf("failed to decrypt secrets: %w", err)
	}

	// Unmarshal JSON
	var data storeData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return fmt.Errorf("%w: %v", types.ErrStoreCorrupted, err)
	}

	// Auto-migrate from v1 to v2
	if data.Version == StoreVersionV1 || data.Version == 0 {
		s.migrateV1ToV2(&data)
	}

	s.secrets = data.Secrets
	if s.secrets == nil {
		s.secrets = make(map[string]*secretWithValue)
	}

	return nil
}

// Save encrypts and persists all secrets to disk.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveUnlocked()
}

// saveUnlocked is an internal helper that saves without acquiring the lock.
func (s *Store) saveUnlocked() error {
	if s.identity == nil {
		return types.ErrStoreNotInitialized
	}

	// Marshal to JSON
	data := storeData{
		Version: StoreVersionV2,
		Secrets: s.secrets,
	}

	plaintext, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secrets: %w", err)
	}

	// Encrypt
	ciphertext, err := Encrypt(plaintext, s.identity.Recipient())
	if err != nil {
		return fmt.Errorf("failed to encrypt secrets: %w", err)
	}

	// Write with secure permissions (0600)
	if err := os.WriteFile(s.cfg.SecretsPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("failed to write secrets file: %w", err)
	}

	return nil
}

// migrateV1ToV2 migrates secrets from v1 (flat keys) to v2 (namespaced keys).
func (s *Store) migrateV1ToV2(data *storeData) {
	newSecrets := make(map[string]*secretWithValue)
	for name, secret := range data.Secrets {
		// Set namespace to default if not already set
		if secret.Namespace == "" {
			secret.Namespace = DefaultNamespace
		}
		// Re-key using composite key
		newKey := secretKey(secret.Namespace, name)
		// Preserve original name (don't change it)
		secret.Name = name
		newSecrets[newKey] = secret
	}
	data.Secrets = newSecrets
	data.Version = StoreVersionV2
}

// Add adds a new secret to the store.
func (s *Store) Add(name, value, rotateVia string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.identity == nil {
		return types.ErrStoreNotInitialized
	}

	// Parse namespace from name if provided
	namespace, simpleName := ParseSecretRef(name)
	key := secretKey(namespace, simpleName)

	// Check if secret already exists
	if _, exists := s.secrets[key]; exists {
		return types.NewSecretError(name, types.ErrSecretExists)
	}

	now := time.Now()
	s.secrets[key] = &secretWithValue{
		Secret: types.Secret{
			Name:      simpleName,
			Namespace: namespace,
			CreatedAt: now,
			UpdatedAt: now,
			RotateVia: rotateVia,
		},
		Value: value,
	}

	return s.saveUnlocked()
}

// Get returns the decrypted value of a secret.
func (s *Store) Get(name string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.identity == nil {
		return "", types.ErrStoreNotInitialized
	}

	namespace, simpleName := ParseSecretRef(name)
	key := secretKey(namespace, simpleName)

	secret, exists := s.secrets[key]
	if !exists {
		return "", types.NewSecretError(name, types.ErrSecretNotFound)
	}

	return secret.Value, nil
}

// Delete removes a secret from the store.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.identity == nil {
		return types.ErrStoreNotInitialized
	}

	namespace, simpleName := ParseSecretRef(name)
	key := secretKey(namespace, simpleName)

	if _, exists := s.secrets[key]; !exists {
		return types.NewSecretError(name, types.ErrSecretNotFound)
	}

	delete(s.secrets, key)
	return s.saveUnlocked()
}

// List returns metadata for all secrets (without values).
func (s *Store) List() ([]types.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.identity == nil {
		return nil, types.ErrStoreNotInitialized
	}

	secrets := make([]types.Secret, 0, len(s.secrets))
	for _, secret := range s.secrets {
		secrets = append(secrets, secret.Secret)
	}

	return secrets, nil
}

// Update updates an existing secret's value and optionally its rotation config.
func (s *Store) Update(name, value string, rotateVia *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.identity == nil {
		return types.ErrStoreNotInitialized
	}

	namespace, simpleName := ParseSecretRef(name)
	key := secretKey(namespace, simpleName)

	secret, exists := s.secrets[key]
	if !exists {
		return types.NewSecretError(name, types.ErrSecretNotFound)
	}

	secret.Value = value
	secret.UpdatedAt = time.Now()

	if rotateVia != nil {
		secret.RotateVia = *rotateVia
	}

	return s.saveUnlocked()
}

// MarkRotated updates the last rotated timestamp for a secret.
func (s *Store) MarkRotated(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.identity == nil {
		return types.ErrStoreNotInitialized
	}

	namespace, simpleName := ParseSecretRef(name)
	key := secretKey(namespace, simpleName)

	secret, exists := s.secrets[key]
	if !exists {
		return types.NewSecretError(name, types.ErrSecretNotFound)
	}

	now := time.Now()
	secret.LastRotated = now
	secret.UpdatedAt = now

	return s.saveUnlocked()
}

// WipeAll removes all secrets from the store.
func (s *Store) WipeAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.identity == nil {
		return types.ErrStoreNotInitialized
	}

	s.secrets = make(map[string]*secretWithValue)
	return s.saveUnlocked()
}

package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/types"
)

func testConfig(t *testing.T) *config.Config {
	tmpDir := t.TempDir()
	return &config.Config{
		Directory:       tmpDir,
		IdentityPath:    filepath.Join(tmpDir, "identity.age"),
		SecretsPath:     filepath.Join(tmpDir, "secrets.age"),
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}
}

func TestStore_Init(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify identity file exists
	if _, err := os.Stat(cfg.IdentityPath); os.IsNotExist(err) {
		t.Error("identity file not created")
	}

	// Verify secrets file exists
	if _, err := os.Stat(cfg.SecretsPath); os.IsNotExist(err) {
		t.Error("secrets file not created")
	}

	// Verify identity is loaded
	if store.identity == nil {
		t.Error("identity not loaded")
	}
}

func TestStore_Init_ExistingIdentity(t *testing.T) {
	cfg := testConfig(t)

	// Generate identity first
	identity, err := GenerateIdentity(cfg.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}

	// Init should load existing identity
	store := New(cfg)
	if err := store.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify same identity is used
	if store.identity.Recipient().String() != identity.Recipient().String() {
		t.Error("different identity loaded")
	}
}

func TestStore_Add(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	err := store.Add("api_key", "secret123", "")
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Verify secret exists
	value, err := store.Get("api_key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if value != "secret123" {
		t.Errorf("expected %q, got %q", "secret123", value)
	}
}

func TestStore_Add_Duplicate(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	if err := store.Add("api_key", "secret123", ""); err != nil {
		t.Fatal(err)
	}

	// Try to add same secret again
	err := store.Add("api_key", "secret456", "")
	if err == nil {
		t.Fatal("expected error adding duplicate secret")
	}

	var secretErr *types.SecretError
	if !isSecretError(err, &secretErr) || secretErr.SecretName != "api_key" {
		t.Errorf("expected SecretError for api_key, got %v", err)
	}
}

func TestStore_Get_NotFound(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	_, err := store.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error getting nonexistent secret")
	}

	var secretErr *types.SecretError
	if !isSecretError(err, &secretErr) {
		t.Errorf("expected SecretError, got %v", err)
	}
}

func TestStore_Delete(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	if err := store.Add("api_key", "secret123", ""); err != nil {
		t.Fatal(err)
	}

	// Delete secret
	if err := store.Delete("api_key"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it's gone
	_, err := store.Get("api_key")
	if err == nil {
		t.Fatal("expected error getting deleted secret")
	}
}

func TestStore_Delete_NotFound(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	err := store.Delete("nonexistent")
	if err == nil {
		t.Fatal("expected error deleting nonexistent secret")
	}
}

func TestStore_List(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	// Add multiple secrets
	secrets := map[string]string{
		"api_key":     "secret1",
		"db_password": "secret2",
		"oauth_token": "secret3",
	}

	for name, value := range secrets {
		if err := store.Add(name, value, ""); err != nil {
			t.Fatalf("Add(%q) failed: %v", name, err)
		}
	}

	// List secrets
	list, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(list) != len(secrets) {
		t.Errorf("expected %d secrets, got %d", len(secrets), len(list))
	}

	// Verify secret names (values should not be in list)
	found := make(map[string]bool)
	for _, s := range list {
		found[s.Name] = true
		if s.CreatedAt.IsZero() {
			t.Errorf("secret %q has zero CreatedAt", s.Name)
		}
		if s.UpdatedAt.IsZero() {
			t.Errorf("secret %q has zero UpdatedAt", s.Name)
		}
	}

	for name := range secrets {
		if !found[name] {
			t.Errorf("secret %q not in list", name)
		}
	}
}

func TestStore_List_Empty(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	list, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(list) != 0 {
		t.Errorf("expected empty list, got %d secrets", len(list))
	}
}

func TestStore_Update(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	// Add initial secret
	if err := store.Add("api_key", "old_value", ""); err != nil {
		t.Fatal(err)
	}

	// Update value
	if err := store.Update("api_key", "new_value", nil); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Verify new value
	value, err := store.Get("api_key")
	if err != nil {
		t.Fatal(err)
	}

	if value != "new_value" {
		t.Errorf("expected %q, got %q", "new_value", value)
	}
}

func TestStore_Update_WithRotateVia(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	// Add secret without rotation
	if err := store.Add("api_key", "value", ""); err != nil {
		t.Fatal(err)
	}

	// Update with rotation hook
	rotateVia := "rotate-api-key.sh"
	if err := store.Update("api_key", "new_value", &rotateVia); err != nil {
		t.Fatal(err)
	}

	// Verify rotation hook is set
	list, err := store.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 1 {
		t.Fatal("expected 1 secret")
	}

	if list[0].RotateVia != rotateVia {
		t.Errorf("expected RotateVia %q, got %q", rotateVia, list[0].RotateVia)
	}
}

func TestStore_Update_NotFound(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	err := store.Update("nonexistent", "value", nil)
	if err == nil {
		t.Fatal("expected error updating nonexistent secret")
	}
}

func TestStore_MarkRotated(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	if err := store.Add("api_key", "value", "rotate.sh"); err != nil {
		t.Fatal(err)
	}

	// Mark as rotated
	if err := store.MarkRotated("api_key"); err != nil {
		t.Fatalf("MarkRotated failed: %v", err)
	}

	// Verify LastRotated is set
	list, err := store.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 1 {
		t.Fatal("expected 1 secret")
	}

	if list[0].LastRotated.IsZero() {
		t.Error("LastRotated not set")
	}
}

func TestStore_MarkRotated_NotFound(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	err := store.MarkRotated("nonexistent")
	if err == nil {
		t.Fatal("expected error marking nonexistent secret as rotated")
	}
}

func TestStore_WipeAll(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	// Add multiple secrets
	if err := store.Add("api_key", "secret1", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Add("db_password", "secret2", ""); err != nil {
		t.Fatal(err)
	}

	// Wipe all
	if err := store.WipeAll(); err != nil {
		t.Fatalf("WipeAll failed: %v", err)
	}

	// Verify all secrets are gone
	list, err := store.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 0 {
		t.Errorf("expected 0 secrets after wipe, got %d", len(list))
	}
}

func TestStore_LoadSave(t *testing.T) {
	cfg := testConfig(t)
	store1 := New(cfg)

	if err := store1.Init(); err != nil {
		t.Fatal(err)
	}

	// Add secrets
	if err := store1.Add("api_key", "secret123", "rotate.sh"); err != nil {
		t.Fatal(err)
	}
	if err := store1.Add("db_password", "secret456", ""); err != nil {
		t.Fatal(err)
	}

	// Save (already done by Add, but explicit call to test)
	if err := store1.Save(); err != nil {
		t.Fatal(err)
	}

	// Create new store instance and load
	store2 := New(cfg)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify secrets match
	value1, err := store2.Get("api_key")
	if err != nil {
		t.Fatal(err)
	}
	if value1 != "secret123" {
		t.Errorf("expected %q, got %q", "secret123", value1)
	}

	value2, err := store2.Get("db_password")
	if err != nil {
		t.Fatal(err)
	}
	if value2 != "secret456" {
		t.Errorf("expected %q, got %q", "secret456", value2)
	}

	// Verify metadata
	list, err := store2.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(list))
	}

	for _, s := range list {
		if s.Name == "api_key" && s.RotateVia != "rotate.sh" {
			t.Errorf("expected RotateVia %q, got %q", "rotate.sh", s.RotateVia)
		}
	}
}

func TestStore_Load_EmptyFile(t *testing.T) {
	cfg := testConfig(t)

	// Generate identity
	if _, err := GenerateIdentity(cfg.IdentityPath); err != nil {
		t.Fatal(err)
	}

	// Create empty secrets file
	if err := os.WriteFile(cfg.SecretsPath, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	// Load should handle empty file gracefully
	store := New(cfg)
	if err := store.Load(); err != nil {
		t.Fatalf("Load failed on empty file: %v", err)
	}

	// Should have no secrets
	list, err := store.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(list))
	}
}

func TestStore_Load_NoSecretsFile(t *testing.T) {
	cfg := testConfig(t)

	// Generate identity but no secrets file
	if _, err := GenerateIdentity(cfg.IdentityPath); err != nil {
		t.Fatal(err)
	}

	// Load should create empty store
	store := New(cfg)
	if err := store.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Should have no secrets
	list, err := store.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(list))
	}
}

func TestStore_NotInitialized(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	// Try operations without Init/Load
	if err := store.Add("test", "value", ""); err != types.ErrStoreNotInitialized {
		t.Errorf("expected ErrStoreNotInitialized, got %v", err)
	}

	if _, err := store.Get("test"); err != types.ErrStoreNotInitialized {
		t.Errorf("expected ErrStoreNotInitialized, got %v", err)
	}

	if err := store.Delete("test"); err != types.ErrStoreNotInitialized {
		t.Errorf("expected ErrStoreNotInitialized, got %v", err)
	}

	if _, err := store.List(); err != types.ErrStoreNotInitialized {
		t.Errorf("expected ErrStoreNotInitialized, got %v", err)
	}

	if err := store.Save(); err != types.ErrStoreNotInitialized {
		t.Errorf("expected ErrStoreNotInitialized, got %v", err)
	}

	if err := store.WipeAll(); err != types.ErrStoreNotInitialized {
		t.Errorf("expected ErrStoreNotInitialized, got %v", err)
	}
}

func TestStore_Concurrency(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	// Add initial secret
	if err := store.Add("counter", "0", ""); err != nil {
		t.Fatal(err)
	}

	// Concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				if _, err := store.Get("counter"); err != nil {
					t.Errorf("concurrent Get failed: %v", err)
				}
			}
			done <- true
		}()
	}

	// Wait for completion
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Helper to check if error is a SecretError
func isSecretError(err error, target **types.SecretError) bool {
	if err == nil {
		return false
	}
	secretErr, ok := err.(*types.SecretError)
	if ok && target != nil {
		*target = secretErr
	}
	return ok
}

func TestParseSecretRef_WithNamespace(t *testing.T) {
	namespace, name := ParseSecretRef("production::api_key")
	if namespace != "production" {
		t.Errorf("expected namespace %q, got %q", "production", namespace)
	}
	if name != "api_key" {
		t.Errorf("expected name %q, got %q", "api_key", name)
	}
}

func TestParseSecretRef_WithoutNamespace(t *testing.T) {
	namespace, name := ParseSecretRef("api_key")
	if namespace != DefaultNamespace {
		t.Errorf("expected namespace %q, got %q", DefaultNamespace, namespace)
	}
	if name != "api_key" {
		t.Errorf("expected name %q, got %q", "api_key", name)
	}
}

func TestParseSecretRef_DoubleDelimiter(t *testing.T) {
	namespace, name := ParseSecretRef("prod::service::key")
	if namespace != "prod" {
		t.Errorf("expected namespace %q, got %q", "prod", namespace)
	}
	if name != "service::key" {
		t.Errorf("expected name %q, got %q", "service::key", name)
	}
}

func TestStore_MigrationV1ToV2(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	// Add secrets with old v1 format (will be saved as v2)
	if err := store.Add("api_key", "secret123", ""); err != nil {
		t.Fatal(err)
	}

	// Manually create a v1 format store file
	store.mu.Lock()
	data := storeData{
		Version: StoreVersionV1,
		Secrets: map[string]*secretWithValue{
			"old_secret": {
				Secret: types.Secret{
					Name:      "old_secret",
					Namespace: "", // v1 has no namespace
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				},
				Value: "old_value",
			},
		},
	}
	plaintext, _ := json.MarshalIndent(data, "", "  ")
	ciphertext, _ := Encrypt(plaintext, store.identity.Recipient())
	os.WriteFile(cfg.SecretsPath, ciphertext, 0600)
	store.mu.Unlock()

	// Load should auto-migrate
	store2 := New(cfg)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify migrated secret is accessible
	value, err := store2.Get("old_secret")
	if err != nil {
		t.Fatalf("Get failed after migration: %v", err)
	}
	if value != "old_value" {
		t.Errorf("expected %q, got %q", "old_value", value)
	}

	// Verify namespace was set to default
	list, err := store2.List()
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, s := range list {
		if s.Name == "old_secret" {
			if s.Namespace != DefaultNamespace {
				t.Errorf("expected namespace %q, got %q", DefaultNamespace, s.Namespace)
			}
			found = true
		}
	}
	if !found {
		t.Error("migrated secret not found in list")
	}
}

func TestStore_NamespacedSecrets(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	// Add secrets to different namespaces
	if err := store.Add("production::api_key", "prod_secret", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Add("staging::api_key", "staging_secret", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Add("api_key", "default_secret", ""); err != nil {
		t.Fatal(err)
	}

	// Verify each can be retrieved independently
	prodValue, err := store.Get("production::api_key")
	if err != nil {
		t.Fatal(err)
	}
	if prodValue != "prod_secret" {
		t.Errorf("expected %q, got %q", "prod_secret", prodValue)
	}

	stagingValue, err := store.Get("staging::api_key")
	if err != nil {
		t.Fatal(err)
	}
	if stagingValue != "staging_secret" {
		t.Errorf("expected %q, got %q", "staging_secret", stagingValue)
	}

	defaultValue, err := store.Get("api_key")
	if err != nil {
		t.Fatal(err)
	}
	if defaultValue != "default_secret" {
		t.Errorf("expected %q, got %q", "default_secret", defaultValue)
	}

	// Verify list shows all with correct namespaces
	list, err := store.List()
	if err != nil {
		t.Fatal(err)
	}

	if len(list) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(list))
	}

	namespaces := make(map[string]string)
	for _, s := range list {
		if s.Name == "api_key" {
			namespaces[s.Namespace] = s.Namespace
		}
	}

	if _, ok := namespaces["production"]; !ok {
		t.Error("production namespace not found")
	}
	if _, ok := namespaces["staging"]; !ok {
		t.Error("staging namespace not found")
	}
	if _, ok := namespaces[DefaultNamespace]; !ok {
		t.Error("default namespace not found")
	}
}

func TestStore_DeleteNamespaced(t *testing.T) {
	cfg := testConfig(t)
	store := New(cfg)

	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	// Add namespaced secrets
	if err := store.Add("production::api_key", "prod_secret", ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Add("staging::api_key", "staging_secret", ""); err != nil {
		t.Fatal(err)
	}

	// Delete production secret
	if err := store.Delete("production::api_key"); err != nil {
		t.Fatal(err)
	}

	// Verify production is gone
	_, err := store.Get("production::api_key")
	if err == nil {
		t.Fatal("expected error getting deleted secret")
	}

	// Verify staging still exists
	value, err := store.Get("staging::api_key")
	if err != nil {
		t.Fatal(err)
	}
	if value != "staging_secret" {
		t.Errorf("expected %q, got %q", "staging_secret", value)
	}
}

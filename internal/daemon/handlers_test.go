package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/joelhooks/agent-secrets/internal/audit"
	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/killswitch"
	"github.com/joelhooks/agent-secrets/internal/lease"
	"github.com/joelhooks/agent-secrets/internal/rotation"
	"github.com/joelhooks/agent-secrets/internal/store"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// setupTestHandler creates a handler with all dependencies for testing.
func setupTestHandler(t *testing.T) (*Handler, *config.Config, func()) {
	t.Helper()

	// Create temp directory for test data
	tempDir := t.TempDir()

	cfg := &config.Config{
		Directory:       tempDir,
		SocketPath:      tempDir + "/test.sock",
		IdentityPath:    tempDir + "/identity.age",
		SecretsPath:     tempDir + "/secrets.age",
		AuditPath:       tempDir + "/audit.log",
		LeasesPath:      tempDir + "/leases.json",
		DefaultLeaseTTL: 1 * time.Hour,
		MaxLeaseTTL:     24 * time.Hour,
		RotationTimeout: 30 * time.Second,
	}

	// Initialize components
	auditLogger, err := audit.New(cfg.AuditPath)
	if err != nil {
		t.Fatalf("failed to create audit logger: %v", err)
	}

	st := store.New(cfg)
	if err := st.Init(); err != nil {
		t.Fatalf("failed to initialize store: %v", err)
	}

	lm, err := lease.NewManager(cfg, auditLogger)
	if err != nil {
		t.Fatalf("failed to create lease manager: %v", err)
	}

	re := rotation.NewExecutor(cfg, st, auditLogger)
	ks := killswitch.NewKillswitch(lm, re, st, auditLogger)

	handler := NewHandler(st, lm, re, ks, auditLogger)

	cleanup := func() {
		auditLogger.Close()
	}

	return handler, cfg, cleanup
}

func TestHandleInit(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	result := handler.handleInit()
	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}
}

func TestHandleAdd(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	params := AddParams{
		Name:      "test-secret",
		Value:     "test-value",
		RotateVia: "echo new-value",
	}

	result, err := handler.handleAdd(params)
	if err != nil {
		t.Fatalf("handleAdd failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}

	// Verify secret was added
	secrets, err := handler.store.List()
	if err != nil {
		t.Fatalf("failed to list secrets: %v", err)
	}

	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}

	if secrets[0].Name != "test-secret" {
		t.Errorf("expected secret name 'test-secret', got %s", secrets[0].Name)
	}
}

func TestHandleAddInvalidParams(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	tests := []struct {
		name   string
		params AddParams
	}{
		{"empty name", AddParams{Name: "", Value: "value"}},
		{"empty value", AddParams{Name: "name", Value: ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := handler.handleAdd(tt.params)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestHandleDelete(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	// Add a secret first
	err := handler.store.Add("test-secret", "test-value", "")
	if err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	// Delete it
	params := DeleteParams{Name: "test-secret"}
	result, err := handler.handleDelete(params)
	if err != nil {
		t.Fatalf("handleDelete failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}

	// Verify secret was deleted
	secrets, err := handler.store.List()
	if err != nil {
		t.Fatalf("failed to list secrets: %v", err)
	}

	if len(secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(secrets))
	}
}

func TestHandleList(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	// Add multiple secrets
	secrets := []struct{ name, value string }{
		{"secret1", "value1"},
		{"secret2", "value2"},
		{"secret3", "value3"},
	}

	for _, s := range secrets {
		if err := handler.store.Add(s.name, s.value, ""); err != nil {
			t.Fatalf("failed to add secret: %v", err)
		}
	}

	result, err := handler.handleList()
	if err != nil {
		t.Fatalf("handleList failed: %v", err)
	}

	if len(result.Secrets) != 3 {
		t.Errorf("expected 3 secrets, got %d", len(result.Secrets))
	}

	// Verify values are not included (only metadata)
	for _, meta := range result.Secrets {
		if meta.Name == "" {
			t.Error("expected non-empty secret name")
		}
	}
}

func TestHandleLease(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	// Add a secret
	err := handler.store.Add("test-secret", "test-value", "")
	if err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	params := LeaseParams{
		SecretName: "test-secret",
		ClientID:   "test-client",
		TTL:        "1h",
	}

	result, err := handler.handleLease(params)
	if err != nil {
		t.Fatalf("handleLease failed: %v", err)
	}

	if result.LeaseID == "" {
		t.Error("expected non-empty lease ID")
	}

	if result.Value != "test-value" {
		t.Errorf("expected value 'test-value', got %s", result.Value)
	}

	if result.ExpiresAt.IsZero() {
		t.Error("expected non-zero expiration time")
	}
}

func TestHandleLeaseInvalidTTL(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	// Add a secret
	err := handler.store.Add("test-secret", "test-value", "")
	if err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	params := LeaseParams{
		SecretName: "test-secret",
		ClientID:   "test-client",
		TTL:        "invalid",
	}

	_, err = handler.handleLease(params)
	if err == nil {
		t.Error("expected error for invalid TTL, got nil")
	}
}

func TestHandleRevoke(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	// Add a secret and acquire a lease
	err := handler.store.Add("test-secret", "test-value", "")
	if err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	lse, err := handler.leaseManager.Acquire("test-secret", "test-client", 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to acquire lease: %v", err)
	}

	// Revoke it
	params := RevokeParams{LeaseID: lse.ID}
	result, err := handler.handleRevoke(params)
	if err != nil {
		t.Fatalf("handleRevoke failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}

	// Verify lease was revoked
	active := handler.leaseManager.List()
	if len(active) != 0 {
		t.Errorf("expected 0 active leases, got %d", len(active))
	}
}

func TestHandleRevokeAll(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	// Add a secret and acquire multiple leases
	err := handler.store.Add("test-secret", "test-value", "")
	if err != nil {
		t.Fatalf("failed to add secret: %v", err)
	}

	for i := 0; i < 3; i++ {
		_, err := handler.leaseManager.Acquire("test-secret", "test-client", 1*time.Hour)
		if err != nil {
			t.Fatalf("failed to acquire lease: %v", err)
		}
	}

	result, err := handler.handleRevokeAll()
	if err != nil {
		t.Fatalf("handleRevokeAll failed: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}

	if result.LeasesRevoked != 3 {
		t.Errorf("expected 3 leases revoked, got %d", result.LeasesRevoked)
	}

	// Verify all leases were revoked
	active := handler.leaseManager.List()
	if len(active) != 0 {
		t.Errorf("expected 0 active leases, got %d", len(active))
	}
}

func TestHandleAudit(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	// Perform some operations to generate audit entries
	handler.store.Add("test-secret", "test-value", "")
	handler.leaseManager.Acquire("test-secret", "test-client", 1*time.Hour)

	params := AuditParams{Tail: 10}
	result, err := handler.handleAudit(params)
	if err != nil {
		t.Fatalf("handleAudit failed: %v", err)
	}

	if len(result.Entries) == 0 {
		t.Error("expected at least one audit entry")
	}
}

func TestHandleStatus(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	// Add some secrets and leases
	handler.store.Add("secret1", "value1", "")
	handler.store.Add("secret2", "value2", "")
	handler.leaseManager.Acquire("secret1", "client1", 1*time.Hour)

	status, err := handler.handleStatus()
	if err != nil {
		t.Fatalf("handleStatus failed: %v", err)
	}

	if status.SecretsCount != 2 {
		t.Errorf("expected 2 secrets, got %d", status.SecretsCount)
	}

	if status.ActiveLeases != 1 {
		t.Errorf("expected 1 active lease, got %d", status.ActiveLeases)
	}
}

func TestHandleRequest(t *testing.T) {
	handler, _, cleanup := setupTestHandler(t)
	defer cleanup()

	tests := []struct {
		name       string
		method     string
		params     interface{}
		expectErr  bool
		errCode    int
	}{
		{
			name:   "init method",
			method: MethodInit,
			params: InitParams{},
		},
		{
			name:   "add method",
			method: MethodAdd,
			params: AddParams{Name: "test", Value: "value"},
		},
		{
			name:      "get method (not allowed)",
			method:    MethodGet,
			params:    GetParams{Name: "test"},
			expectErr: true,
			errCode:   types.RPCUnauthorized,
		},
		{
			name:      "unknown method",
			method:    "secrets.unknown",
			params:    nil,
			expectErr: true,
			errCode:   types.RPCMethodNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.RPCRequest{
				JSONRPC: "2.0",
				Method:  tt.method,
				Params:  tt.params,
				ID:      1,
			}

			resp := handler.HandleRequest(req)

			if tt.expectErr {
				if resp.Error == nil {
					t.Error("expected error, got nil")
				}
				if resp.Error != nil && tt.errCode != 0 && resp.Error.Code != tt.errCode {
					t.Errorf("expected error code %d, got %d", tt.errCode, resp.Error.Code)
				}
			} else {
				if resp.Error != nil {
					t.Errorf("unexpected error: %v", resp.Error.Message)
				}
				if resp.Result == nil {
					t.Error("expected result, got nil")
				}
			}
		})
	}
}

func TestUnmarshalParams(t *testing.T) {
	tests := []struct {
		name      string
		input     interface{}
		target    interface{}
		expectErr bool
	}{
		{
			name:   "valid map params",
			input:  map[string]interface{}{"name": "test", "value": "val"},
			target: &AddParams{},
		},
		{
			name:   "valid struct params",
			input:  AddParams{Name: "test", Value: "val"},
			target: &AddParams{},
		},
		{
			name:      "nil params",
			input:     nil,
			target:    &AddParams{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := unmarshalParams(tt.input, tt.target)
			if tt.expectErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestJSONSerialization(t *testing.T) {
	// Test that all param/result types serialize correctly
	tests := []interface{}{
		AddParams{Name: "test", Value: "val", RotateVia: "cmd"},
		DeleteParams{Name: "test"},
		LeaseParams{SecretName: "test", ClientID: "client", TTL: "1h"},
		RevokeParams{LeaseID: "id"},
		RotateParams{SecretName: "test"},
		AuditParams{Tail: 10},
		AddResult{Success: true, Message: "ok"},
		LeaseResult{LeaseID: "id", Value: "val", ExpiresAt: time.Now()},
	}

	for _, obj := range tests {
		t.Run("", func(t *testing.T) {
			data, err := json.Marshal(obj)
			if err != nil {
				t.Errorf("marshal failed: %v", err)
			}

			// Unmarshal back to verify round-trip
			if err := json.Unmarshal(data, &obj); err != nil {
				t.Errorf("unmarshal failed: %v", err)
			}
		})
	}
}

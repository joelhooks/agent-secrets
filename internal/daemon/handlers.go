package daemon

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/joelhooks/agent-secrets/internal/audit"
	"github.com/joelhooks/agent-secrets/internal/killswitch"
	"github.com/joelhooks/agent-secrets/internal/lease"
	"github.com/joelhooks/agent-secrets/internal/rotation"
	"github.com/joelhooks/agent-secrets/internal/store"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// Handler dispatches RPC requests to appropriate methods.
type Handler struct {
	store            *store.Store
	leaseManager     *lease.Manager
	rotationExecutor *rotation.Executor
	killswitch       *killswitch.Killswitch
	auditLogger      *audit.Logger
}

// NewHandler creates a new RPC handler with all required dependencies.
func NewHandler(
	st *store.Store,
	lm *lease.Manager,
	re *rotation.Executor,
	ks *killswitch.Killswitch,
	al *audit.Logger,
) *Handler {
	return &Handler{
		store:            st,
		leaseManager:     lm,
		rotationExecutor: re,
		killswitch:       ks,
		auditLogger:      al,
	}
}

// HandleRequest dispatches an RPC request to the appropriate handler method.
func (h *Handler) HandleRequest(req *types.RPCRequest) *types.RPCResponse {
	resp := &types.RPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case MethodInit:
		resp.Result = h.handleInit()
	case MethodAdd:
		result, err := h.handleAdd(req.Params)
		if err != nil {
			resp.Error = types.RPCErrorFromError(err)
		} else {
			resp.Result = result
		}
	case MethodGet:
		// Direct get is not allowed - must use lease
		resp.Error = &types.RPCError{
			Code:    types.RPCUnauthorized,
			Message: "direct secret access not allowed; use secrets.lease instead",
		}
	case MethodDelete:
		result, err := h.handleDelete(req.Params)
		if err != nil {
			resp.Error = types.RPCErrorFromError(err)
		} else {
			resp.Result = result
		}
	case MethodList:
		result, err := h.handleList()
		if err != nil {
			resp.Error = types.RPCErrorFromError(err)
		} else {
			resp.Result = result
		}
	case MethodLease:
		result, err := h.handleLease(req.Params)
		if err != nil {
			resp.Error = types.RPCErrorFromError(err)
		} else {
			resp.Result = result
		}
	case MethodRevoke:
		result, err := h.handleRevoke(req.Params)
		if err != nil {
			resp.Error = types.RPCErrorFromError(err)
		} else {
			resp.Result = result
		}
	case MethodRevokeAll:
		result, err := h.handleRevokeAll()
		if err != nil {
			resp.Error = types.RPCErrorFromError(err)
		} else {
			resp.Result = result
		}
	case MethodRotate:
		result, err := h.handleRotate(req.Params)
		if err != nil {
			resp.Error = types.RPCErrorFromError(err)
		} else {
			resp.Result = result
		}
	case MethodAudit:
		result, err := h.handleAudit(req.Params)
		if err != nil {
			resp.Error = types.RPCErrorFromError(err)
		} else {
			resp.Result = result
		}
	case MethodStatus:
		result, err := h.handleStatus()
		if err != nil {
			resp.Error = types.RPCErrorFromError(err)
		} else {
			resp.Result = result
		}
	default:
		resp.Error = &types.RPCError{
			Code:    types.RPCMethodNotFound,
			Message: fmt.Sprintf("method %q not found", req.Method),
		}
	}

	return resp
}

// handleInit initializes the store if it doesn't exist.
func (h *Handler) handleInit() *InitResult {
	if err := h.store.Init(); err != nil {
		return &InitResult{
			Success: false,
			Message: fmt.Sprintf("initialization failed: %v", err),
		}
	}

	return &InitResult{
		Success: true,
		Message: "store initialized successfully",
	}
}

// handleAdd adds a new secret to the store.
func (h *Handler) handleAdd(params interface{}) (*AddResult, error) {
	var p AddParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	if p.Name == "" {
		return nil, fmt.Errorf("secret name is required")
	}
	if p.Value == "" {
		return nil, fmt.Errorf("secret value is required")
	}

	if err := h.store.Add(p.Name, p.Value, p.RotateVia); err != nil {
		return nil, err
	}

	return &AddResult{
		Success: true,
		Message: fmt.Sprintf("secret %q added successfully", p.Name),
	}, nil
}

// handleDelete removes a secret from the store.
func (h *Handler) handleDelete(params interface{}) (*DeleteResult, error) {
	var p DeleteParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	if p.Name == "" {
		return nil, fmt.Errorf("secret name is required")
	}

	// Revoke all leases for this secret before deleting
	if err := h.leaseManager.RevokeBySecret(p.Name); err != nil {
		// Log but don't fail deletion
		_ = h.auditLogger.Log(audit.NewEntry(types.ActionSecretDelete, false).
			WithSecret(p.Name).
			WithDetails(fmt.Sprintf("failed to revoke leases: %v", err)).
			Build())
	}

	if err := h.store.Delete(p.Name); err != nil {
		return nil, err
	}

	return &DeleteResult{
		Success: true,
		Message: fmt.Sprintf("secret %q deleted successfully", p.Name),
	}, nil
}

// handleList returns metadata for all secrets.
func (h *Handler) handleList() (*ListResult, error) {
	secrets, err := h.store.List()
	if err != nil {
		return nil, err
	}

	metadata := make([]SecretMetadata, len(secrets))
	for i, s := range secrets {
		metadata[i] = SecretMetadata{
			Name:        s.Name,
			CreatedAt:   s.CreatedAt,
			UpdatedAt:   s.UpdatedAt,
			RotateVia:   s.RotateVia,
			LastRotated: s.LastRotated,
		}
	}

	return &ListResult{Secrets: metadata}, nil
}

// handleLease acquires a lease and returns the secret value.
func (h *Handler) handleLease(params interface{}) (*LeaseResult, error) {
	var p LeaseParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	if p.SecretName == "" {
		return nil, fmt.Errorf("secret_name is required")
	}
	if p.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	// Parse TTL duration
	var ttl time.Duration
	var err error
	if p.TTL != "" {
		ttl, err = time.ParseDuration(p.TTL)
		if err != nil {
			return nil, fmt.Errorf("invalid ttl duration: %w", err)
		}
	}

	// Get the secret value first
	value, err := h.store.Get(p.SecretName)
	if err != nil {
		return nil, err
	}

	// Acquire the lease
	lse, err := h.leaseManager.Acquire(p.SecretName, p.ClientID, ttl)
	if err != nil {
		return nil, err
	}

	return &LeaseResult{
		LeaseID:   lse.ID,
		Value:     value,
		ExpiresAt: lse.ExpiresAt,
	}, nil
}

// handleRevoke revokes a specific lease.
func (h *Handler) handleRevoke(params interface{}) (*RevokeResult, error) {
	var p RevokeParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	if p.LeaseID == "" {
		return nil, fmt.Errorf("lease_id is required")
	}

	if err := h.leaseManager.Revoke(p.LeaseID); err != nil {
		return nil, err
	}

	return &RevokeResult{
		Success: true,
		Message: fmt.Sprintf("lease %q revoked successfully", p.LeaseID),
	}, nil
}

// handleRevokeAll triggers killswitch to revoke all leases.
func (h *Handler) handleRevokeAll() (*RevokeAllResult, error) {
	// Count active leases before revoking
	activeLeases := h.leaseManager.List()
	count := len(activeLeases)

	// Trigger killswitch with revoke-only option
	if err := h.killswitch.Activate(types.KillswitchOptions{
		RevokeAll: true,
	}); err != nil {
		return nil, fmt.Errorf("killswitch revoke failed: %w", err)
	}

	return &RevokeAllResult{
		Success:       true,
		LeasesRevoked: count,
		Message:       fmt.Sprintf("all %d active leases revoked", count),
	}, nil
}

// handleRotate rotates a specific secret using its rotation hook.
func (h *Handler) handleRotate(params interface{}) (*RotateResult, error) {
	var p RotateParams
	if err := unmarshalParams(params, &p); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	if p.SecretName == "" {
		return nil, fmt.Errorf("secret_name is required")
	}

	result, err := h.rotationExecutor.Rotate(p.SecretName)
	if err != nil {
		// Return the result even on error (contains output)
		if result != nil {
			return &RotateResult{
				Success:    result.Success,
				Output:     result.Output,
				Error:      result.Error,
				ExecutedAt: result.ExecutedAt,
			}, err
		}
		return nil, err
	}

	return &RotateResult{
		Success:    result.Success,
		Output:     result.Output,
		Error:      result.Error,
		ExecutedAt: result.ExecutedAt,
	}, nil
}

// handleAudit returns recent audit log entries.
func (h *Handler) handleAudit(params interface{}) (*AuditResult, error) {
	var p AuditParams
	if err := unmarshalParams(params, &p); err != nil {
		// Default to last 100 entries if no params provided
		p.Tail = 100
	}

	if p.Tail == 0 {
		p.Tail = 100 // Default limit
	}

	entries, err := h.auditLogger.Tail(p.Tail)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit log: %w", err)
	}

	jsonEntries := make([]AuditEntryJSON, len(entries))
	for i, e := range entries {
		jsonEntries[i] = AuditEntryJSON{
			Timestamp:  e.Timestamp,
			Action:     string(e.Action),
			SecretName: e.SecretName,
			ClientID:   e.ClientID,
			LeaseID:    e.LeaseID,
			Details:    e.Details,
			Success:    e.Success,
		}
	}

	return &AuditResult{Entries: jsonEntries}, nil
}

// handleStatus returns the current daemon status.
func (h *Handler) handleStatus() (*types.DaemonStatus, error) {
	secrets, err := h.store.List()
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets count: %w", err)
	}

	activeLeases := h.leaseManager.List()

	// Note: StartedAt and Running will be populated by the daemon itself
	return &types.DaemonStatus{
		Running:      true,
		SecretsCount: len(secrets),
		ActiveLeases: len(activeLeases),
	}, nil
}

// unmarshalParams is a helper to unmarshal interface{} params to a specific type.
func unmarshalParams(params interface{}, target interface{}) error {
	if params == nil {
		return fmt.Errorf("parameters are required")
	}

	// Convert to JSON and back (handles map[string]interface{} from JSON decoder)
	data, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal params: %w", err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("failed to unmarshal params: %w", err)
	}

	return nil
}

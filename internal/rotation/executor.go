package rotation

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/joelhooks/agent-secrets/internal/audit"
	"github.com/joelhooks/agent-secrets/internal/config"
	"github.com/joelhooks/agent-secrets/internal/store"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// Executor handles rotation hook execution with audit logging.
type Executor struct {
	mu          sync.Mutex
	cfg         *config.Config
	store       *store.Store
	auditLogger *audit.Logger
}

// NewExecutor creates a new rotation executor.
func NewExecutor(cfg *config.Config, st *store.Store, auditLogger *audit.Logger) *Executor {
	return &Executor{
		cfg:         cfg,
		store:       st,
		auditLogger: auditLogger,
	}
}

// Rotate executes the rotation hook for a single secret.
func (e *Executor) Rotate(secretName string) (*types.RotationResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Get secret metadata
	secrets, err := e.store.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	var secret *types.Secret
	for i := range secrets {
		if secrets[i].Name == secretName {
			secret = &secrets[i]
			break
		}
	}

	if secret == nil {
		return nil, types.NewSecretError(secretName, types.ErrSecretNotFound)
	}

	// Check if rotation hook is configured
	if secret.RotateVia == "" {
		return nil, types.NewSecretError(secretName, types.ErrNoRotationHook)
	}

	// Execute the command
	result := &types.RotationResult{
		SecretName: secretName,
		ExecutedAt: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.cfg.RotationTimeout)
	defer cancel()

	// Use sh -c to support shell features
	cmd := exec.CommandContext(ctx, "sh", "-c", secret.RotateVia)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err = cmd.Run()

	// Combine stdout and stderr for output
	combinedOutput := outBuf.String()
	if errBuf.Len() > 0 {
		if len(combinedOutput) > 0 {
			combinedOutput += "\n"
		}
		combinedOutput += errBuf.String()
	}
	result.Output = combinedOutput

	if err != nil {
		// Check if it was a timeout
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = "command timed out"
			result.Success = false
			e.logAudit(secretName, false, result.Output, types.ErrRotationTimeout.Error())
			return result, types.NewRotationError(secretName, secret.RotateVia, result.Output, types.ErrRotationTimeout)
		}

		// Command failed
		result.Error = err.Error()
		result.Success = false
		e.logAudit(secretName, false, result.Output, err.Error())
		return result, types.NewRotationError(secretName, secret.RotateVia, result.Output, types.ErrRotationFailed)
	}

	// Success - mark as rotated
	result.Success = true
	if err := e.store.MarkRotated(secretName); err != nil {
		result.Error = fmt.Sprintf("rotation succeeded but failed to update store: %v", err)
		result.Success = false
		e.logAudit(secretName, false, result.Output, result.Error)
		return result, fmt.Errorf("failed to mark rotated: %w", err)
	}

	e.logAudit(secretName, true, result.Output, "")
	return result, nil
}

// RotateAll executes rotation hooks for all secrets that have them configured.
func (e *Executor) RotateAll() ([]types.RotationResult, error) {
	secrets, err := e.store.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	var results []types.RotationResult
	for _, secret := range secrets {
		if secret.RotateVia == "" {
			continue // Skip secrets without rotation hooks
		}

		result, err := e.Rotate(secret.Name)
		if err != nil {
			// Still add to results, but continue with other secrets
			if result != nil {
				results = append(results, *result)
			}
			continue
		}

		results = append(results, *result)
	}

	return results, nil
}

// CanRotate checks if a secret has a rotation hook configured.
func (e *Executor) CanRotate(secretName string) bool {
	secrets, err := e.store.List()
	if err != nil {
		return false
	}

	for _, secret := range secrets {
		if secret.Name == secretName && secret.RotateVia != "" {
			return true
		}
	}

	return false
}

// logAudit writes an audit entry for a rotation attempt.
func (e *Executor) logAudit(secretName string, success bool, output, errMsg string) {
	details := output
	if errMsg != "" {
		details = fmt.Sprintf("error: %s\noutput: %s", errMsg, output)
	}

	entry := &types.AuditEntry{
		Timestamp:  time.Now(),
		Action:     types.ActionSecretRotate,
		SecretName: secretName,
		Success:    success,
		Details:    details,
	}

	// Best effort logging - don't fail rotation on audit failure
	_ = e.auditLogger.Log(entry)
}

// Package killswitch provides emergency revocation capabilities.
package killswitch

import (
	"fmt"
	"strings"

	"github.com/joelhooks/agent-secrets/internal/audit"
	"github.com/joelhooks/agent-secrets/internal/lease"
	"github.com/joelhooks/agent-secrets/internal/rotation"
	"github.com/joelhooks/agent-secrets/internal/store"
	"github.com/joelhooks/agent-secrets/internal/types"
)

// Killswitch provides multi-factor emergency revocation capabilities.
type Killswitch struct {
	leaseManager     *lease.Manager
	rotationExecutor *rotation.Executor
	store            *store.Store
	auditLogger      *audit.Logger
}

// NewKillswitch creates a new killswitch with the provided dependencies.
func NewKillswitch(
	leaseManager *lease.Manager,
	rotationExecutor *rotation.Executor,
	store *store.Store,
	auditLogger *audit.Logger,
) *Killswitch {
	return &Killswitch{
		leaseManager:     leaseManager,
		rotationExecutor: rotationExecutor,
		store:            store,
		auditLogger:      auditLogger,
	}
}

// Activate triggers the killswitch with the specified options.
// Operations are attempted in order: RevokeAll, RotateAll, WipeStore.
// All operations are attempted even if one fails; errors are collected and combined.
func (k *Killswitch) Activate(options types.KillswitchOptions) error {
	var errs []string
	details := []string{}

	// Track what operations were requested
	if options.RevokeAll {
		if err := k.leaseManager.RevokeAll(); err != nil {
			errs = append(errs, fmt.Sprintf("revoke failed: %v", err))
		} else {
			details = append(details, "all leases revoked")
		}
	}

	if options.RotateAll {
		results, err := k.rotationExecutor.RotateAll()
		if err != nil {
			errs = append(errs, fmt.Sprintf("rotate failed: %v", err))
		} else {
			// Count successes and failures
			successCount := 0
			failCount := 0
			for _, result := range results {
				if result.Success {
					successCount++
				} else {
					failCount++
				}
			}
			if successCount > 0 || failCount > 0 {
				details = append(details, fmt.Sprintf("rotated %d secrets (%d failed)", successCount, failCount))
			}
		}
	}

	if options.WipeStore {
		if err := k.store.WipeAll(); err != nil {
			errs = append(errs, fmt.Sprintf("wipe failed: %v", err))
		} else {
			details = append(details, "store wiped")
		}
	}

	// Log the killswitch activation
	success := len(errs) == 0
	entry := audit.NewEntry(types.ActionKillswitch, success).
		WithDetails(strings.Join(details, "; ")).
		Build()
	_ = k.auditLogger.Log(entry)

	// Return combined errors if any
	if len(errs) > 0 {
		return fmt.Errorf("killswitch partial failure: %s", strings.Join(errs, "; "))
	}

	return nil
}

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joelhooks/agent-secrets/internal/daemon"
	"github.com/joelhooks/agent-secrets/internal/project"
)

// defaultStoreLeaseTTL is the lease TTL used for store-backed .secrets.json
// entries that don't specify a TTL of their own.
const defaultStoreLeaseTTL = "1h"

// storeEnvFileSource is the source label written into the env file metadata
// header for store-backed configurations.
const storeEnvFileSource = "store"

// projectLease is a leased secret value together with its lease metadata.
type projectLease struct {
	SecretName string
	EnvVar     string
	LeaseID    string
	Value      string
	ExpiresAt  time.Time
}

// resolveEntryTTL returns the effective lease TTL for a single store-backed
// entry. This is the single source of truth for TTL precedence, shared by the
// dry-run preview and the real lease path: an explicit override wins, then the
// per-entry TTL, then the config-level TTL, then defaultStoreLeaseTTL.
func resolveEntryTTL(cfg *project.ProjectConfig, entry project.SecretMapping, ttlOverride string) string {
	if ttlOverride != "" {
		return ttlOverride
	}
	return cfg.ResolveTTL(entry.TTL, defaultStoreLeaseTTL)
}

// storeLeaseFix returns an actionable remediation for a store-backed lease
// failure, so a missing secret is not misreported as a stopped daemon.
func storeLeaseFix(err error) string {
	if isDaemonConnectionError(err) {
		return "Start the daemon: secrets serve &"
	}
	if strings.Contains(strings.ToLower(err.Error()), "not found") {
		return "Check available secrets: secrets list"
	}
	return "Check daemon status: secrets status"
}

// acquireProjectLeases leases every secret referenced by a store-backed
// .secrets.json and returns them in configuration order.
func acquireProjectLeases(cfg *project.ProjectConfig, ttlOverride string) ([]projectLease, error) {
	leases := make([]projectLease, 0, len(cfg.Secrets))
	clientID := cfg.GetClientID(hostnameClientID())

	for _, entry := range cfg.Secrets {
		ttl := resolveEntryTTL(cfg, entry, ttlOverride)

		params := daemon.LeaseParams{
			SecretName: entry.Name,
			ClientID:   clientID,
			TTL:        ttl,
		}

		resp, err := rpcCall(socketPath, daemon.MethodLease, params)
		if err != nil {
			return nil, fmt.Errorf("failed to lease %q: %w", entry.Name, err)
		}

		var result daemon.LeaseResult
		data, err := json.Marshal(resp.Result)
		if err != nil {
			return nil, fmt.Errorf("failed to parse lease for %q: %w", entry.Name, err)
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, fmt.Errorf("failed to parse lease for %q: %w", entry.Name, err)
		}

		leases = append(leases, projectLease{
			SecretName: entry.Name,
			EnvVar:     entry.EnvVar,
			LeaseID:    result.LeaseID,
			Value:      result.Value,
			ExpiresAt:  result.ExpiresAt,
		})
	}

	return leases, nil
}

// leaseVars converts leases into an env-var to value map for writing to disk.
func leaseVars(leases []projectLease) map[string]string {
	vars := make(map[string]string, len(leases))
	for _, l := range leases {
		vars[l.EnvVar] = l.Value
	}
	return vars
}

// leaseVarNames returns the env var names in configuration order so output is
// stable between runs.
func leaseVarNames(leases []projectLease) []string {
	names := make([]string, 0, len(leases))
	for _, l := range leases {
		names = append(names, l.EnvVar)
	}
	return names
}

// leaseSummaries returns non-sensitive lease metadata for the JSON envelope.
// Secret values are deliberately never included.
func leaseSummaries(leases []projectLease) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(leases))
	for _, l := range leases {
		out = append(out, map[string]interface{}{
			"secret":     l.SecretName,
			"env_var":    l.EnvVar,
			"lease_id":   l.LeaseID,
			"expires_at": l.ExpiresAt.Format(time.RFC3339),
		})
	}
	return out
}

// leaseExpiry returns the earliest expiry across all leases. The env file must
// not outlive the shortest-lived lease it contains.
func leaseExpiry(leases []projectLease) time.Time {
	var earliest time.Time
	for _, l := range leases {
		if earliest.IsZero() || l.ExpiresAt.Before(earliest) {
			earliest = l.ExpiresAt
		}
	}
	return earliest
}

// revokeLeases revokes the supplied leases and returns the IDs that could not
// be revoked. Revocation failures are non-fatal: every lease still expires on
// its own TTL.
func revokeLeases(leases []projectLease) []string {
	var failed []string
	for _, l := range leases {
		if _, err := rpcCall(socketPath, daemon.MethodRevoke, daemon.RevokeParams{LeaseID: l.LeaseID}); err != nil {
			failed = append(failed, l.LeaseID)
		}
	}
	return failed
}

// hostnameClientID returns the hostname, used as the default audit client ID.
func hostnameClientID() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

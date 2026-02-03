# ADR 003: Namespace Support for Secrets

## Status
Proposed

## Context
Secrets are currently keyed by simple string names (`github_token`, `openai_key`). This creates problems:

1. **Collision risk** - Multiple projects using same secret names
2. **No permission scoping** - Can't grant agent access to a subset of secrets
3. **No environment separation** - `prod` vs `staging` secrets mixed together
4. **Multi-tenant awkwardness** - Agents from different contexts see everything

## Decision

Add required namespaces with a `default` fallback for backwards compatibility.

### Format
```
namespace::secret_name
```

Uses `::` as delimiter (not `/`) because:
- Established namespace separator in Rust, C++, Ruby
- No ambiguity with file paths or URLs
- Allows slashes in secret names if needed (`myproject::oauth/callback`)
- More visually distinct and deliberate

Examples:
- `egghead::OPENAI_KEY` - Project-specific
- `prod::DATABASE_URL` - Environment-specific
- `shared::GITHUB_TOKEN` - Cross-project
- `default::API_KEY` - Implicit namespace (backwards compat)

### Type Changes

```go
// types.go
type Secret struct {
    Namespace   string    `json:"namespace"`           // NEW
    Name        string    `json:"name"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
    RotateVia   string    `json:"rotate_via,omitempty"`
    LastRotated time.Time `json:"last_rotated,omitempty"`
}

// FullName returns "namespace::name"
func (s *Secret) FullName() string {
    return s.Namespace + "::" + s.Name
}

type Lease struct {
    ID         string    `json:"id"`
    Namespace  string    `json:"namespace"`            // NEW
    SecretName string    `json:"secret_name"`
    ClientID   string    `json:"client_id"`
    CreatedAt  time.Time `json:"created_at"`
    ExpiresAt  time.Time `json:"expires_at"`
    Revoked    bool      `json:"revoked"`
}

type LeaseRequest struct {
    Namespace  string        `json:"namespace"`        // NEW
    SecretName string        `json:"secret_name"`
    ClientID   string        `json:"client_id"`
    TTL        time.Duration `json:"ttl"`
    // Optional: request multiple namespaces
    Namespaces []string      `json:"namespaces,omitempty"`
}
```

### Store Changes

```go
// store.go
type storeData struct {
    Version int                         `json:"version"`  // Bump to 2
    Secrets map[string]*secretWithValue `json:"secrets"`  // Key: "namespace/name"
}

const (
    DefaultNamespace   = "default"
    NamespaceDelimiter = "::"
)

// ParseSecretRef parses "namespace::name" or returns default namespace
func ParseSecretRef(ref string) (namespace, name string) {
    parts := strings.SplitN(ref, NamespaceDelimiter, 2)
    if len(parts) == 2 {
        return parts[0], parts[1]
    }
    return DefaultNamespace, ref
}

// secretKey returns the map key for a secret
func secretKey(namespace, name string) string {
    return namespace + NamespaceDelimiter + name
}
```

### CLI Changes

```bash
# Explicit namespace
secrets add egghead::OPENAI_KEY --value "sk-..."
secrets lease egghead::OPENAI_KEY --ttl 1h

# Implicit default namespace
secrets add API_KEY --value "..."        # stored as default::API_KEY
secrets lease API_KEY                    # looks up default::API_KEY

# List by namespace
secrets list                             # all, grouped by namespace
secrets list --namespace egghead         # only egghead::*
secrets list --namespace default         # only default::*

# Revoke by namespace
secrets revoke --namespace egghead       # revoke all leases in namespace
secrets revoke --all                     # killswitch (all namespaces)
```

### Permission Model (Future)

```go
// LeaseRequest can specify allowed namespaces
type LeaseRequest struct {
    Namespaces []string `json:"namespaces"` // ["egghead", "shared"]
    // ...
}

// Daemon can enforce namespace ACLs
type NamespaceACL struct {
    ClientPattern string   `json:"client_pattern"` // "agent-*"
    Namespaces    []string `json:"namespaces"`     // allowed namespaces
}
```

### Audit Changes

```go
type AuditEntry struct {
    Timestamp  time.Time `json:"timestamp"`
    Action     Action    `json:"action"`
    Namespace  string    `json:"namespace,omitempty"`  // NEW
    SecretName string    `json:"secret_name,omitempty"`
    ClientID   string    `json:"client_id,omitempty"`
    LeaseID    string    `json:"lease_id,omitempty"`
    Details    string    `json:"details,omitempty"`
    Success    bool      `json:"success"`
}
```

## Migration

### Store Version Bump

```go
const (
    StoreVersionV1 = 1  // No namespaces
    StoreVersionV2 = 2  // With namespaces
)
```

### Automatic Migration on Load

```go
func (s *Store) Load() error {
    // ... decrypt and unmarshal ...

    if data.Version == StoreVersionV1 {
        data = s.migrateV1ToV2(data)
    }

    // ... continue loading ...
}

func (s *Store) migrateV1ToV2(old storeData) storeData {
    newSecrets := make(map[string]*secretWithValue)

    for name, secret := range old.Secrets {
        // All v1 secrets go to "default" namespace
        secret.Namespace = DefaultNamespace
        newKey := secretKey(DefaultNamespace, name)  // "default::name"
        newSecrets[newKey] = secret
    }

    return storeData{
        Version: StoreVersionV2,
        Secrets: newSecrets,
    }
}
```

### Migration is Automatic and Transparent

1. User runs any command
2. Store loads, detects v1 format
3. Auto-migrates to v2 with all secrets in `default::` namespace
4. Saves in v2 format
5. **No data loss, no manual steps**

### CLI Backwards Compatibility

```bash
# These are equivalent after migration:
secrets lease API_KEY                    # works (uses default namespace)
secrets lease default::API_KEY           # explicit

# Old .secrets.json files work unchanged
# because omitted namespace → default
```

### Migration CLI Command (Optional)

```bash
# Preview migration (dry run)
secrets migrate --dry-run

# Force migration if auto didn't trigger
secrets migrate

# Output:
# Migrating store from v1 to v2...
# - github_token → default::github_token
# - openai_key → default::openai_key
# - anthropic_key → default::anthropic_key
# Migration complete. 3 secrets moved to 'default' namespace.
```

### Rollback (Emergency)

If something goes wrong, user can restore from backup:

```bash
# Store creates backup before migration
~/.agent-secrets/secrets.age.v1.bak

# Manual restore
cp ~/.agent-secrets/secrets.age.v1.bak ~/.agent-secrets/secrets.age
```

## Implementation Order

1. **types.go** - Add Namespace field to Secret, Lease, AuditEntry
2. **store.go** - Add ParseSecretRef, secretKey helpers, migration logic
3. **store.go** - Update Add/Get/Delete/List to use namespaced keys
4. **lease/manager.go** - Update to include namespace
5. **audit/audit.go** - Add namespace to log entries
6. **cmd/secrets/*.go** - Update CLI to parse namespace/name syntax
7. **cmd/secrets/list.go** - Add --namespace flag, grouped output
8. **cmd/secrets/migrate.go** - Add explicit migrate command (optional)
9. **Tests** - Migration tests, namespace parsing tests

## Consequences

### Positive
- Clear organization of secrets by project/environment
- Foundation for namespace-scoped permissions
- Backwards compatible - existing secrets auto-migrate
- CLI syntax is intuitive (`project::SECRET_NAME`)

### Negative
- Slightly more complex mental model
- Store format version bump requires migration
- Audit log entries slightly larger

### Neutral
- Default namespace means simple use cases stay simple
- Migration is automatic, no manual intervention needed

## References
- HashiCorp Vault namespaces: https://developer.hashicorp.com/vault/docs/enterprise/namespaces
- Kubernetes secrets namespacing: https://kubernetes.io/docs/concepts/configuration/secret/

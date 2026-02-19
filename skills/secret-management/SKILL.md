---
name: secret-management
description: Portable credential management for AI agents using age encryption, session-scoped leases, auto-rotation, and killswitch. Use this skill when agents need secure, time-bounded access to API keys, tokens, or credentials without direct exposure to plaintext secrets.
license: MIT
compatibility:
  os: [linux, macos]
  shell: [bash, zsh, sh]
metadata:
  version: 0.1.0
  requires:
    - age encryption library
    - unix socket support
---

# Secret Management for AI Agents

This skill enables AI agents to securely manage and access credentials using `agent-secrets`, a Go CLI that provides:

- 🔐 Age encryption for secrets at rest
- ⏱️ Session-scoped leases with automatic expiration
- 🔄 Auto-rotation hooks for dynamic credentials
- 🚨 Multi-factor killswitch for emergency revocation
- 📋 Append-only audit logging

## When to Use This Skill

Use `agent-secrets` when your agent needs to:
- Access API keys, tokens, or credentials securely
- Prevent credential exfiltration in case of compromise
- Maintain an audit trail of secret access
- Enable time-bounded credential access with automatic expiration
- Support credential rotation without manual intervention
- Implement emergency revocation across all active sessions

## Prerequisites

The `secrets` CLI must be installed and in your PATH:

```bash
# Install (see repo README for build instructions)
# https://github.com/joelhooks/agent-secrets

# Initialize the encrypted store (run once per machine)
secrets init

# Discover command tree and capabilities
secrets
```

This creates:
- `~/.agent-secrets/identity.age` — X25519 private key (0600 permissions)
- `~/.agent-secrets/secrets.age` — encrypted secrets store
- `~/.agent-secrets/config.json` — configuration
- `~/.agent-secrets/agent-secrets.sock` — daemon socket

## Core Workflows

### 1. Discover Commands and Secret Names

Use discovery-first commands before requesting a lease:

```bash
# Root command returns JSON command tree with usage and next_actions
secrets

# List all stored secret names and lease metadata
secrets list
```

### 2. Adding Secrets

**Interactive mode** (prompts for secret value):
```bash
secrets add my_secret
```

**With rotation hook** (auto-refresh on expiration):
```bash
secrets add github_token --rotate-via "gh auth refresh"
secrets add aws_token --rotate-via "aws sts get-session-token --duration-seconds 3600"
```

**From stdin** (pipe secret value):
```bash
echo "sk-ant-api03-..." | secrets add anthropic_key
cat service-account.json | secrets add gcp_credentials
```

### 3. Leasing Secrets

`secrets lease <name>` returns ONLY the raw secret value by default, so no extra flags are needed for shell export:
```bash
# Primary pattern
export GITHUB_TOKEN=$(secrets lease github_token)

# Custom TTL
export ANTHROPIC_API_KEY=$(secrets lease anthropic_key --ttl 30m)

# With client ID for audit trail
export OPENAI_KEY=$(secrets lease openai_key --ttl 2h --client-id "claude-code-worker")

# Use --json when you need lease metadata and next_actions
secrets lease github_token --json
```

Example JSON envelope (`--json`):
```json
{
  "ok": true,
  "command": "secrets lease",
  "result": {
    "lease_id": "lease-123",
    "secret_name": "github_token",
    "value": "ghp_xxx",
    "expires_at": "2026-02-19T12:00:00Z",
    "ttl": "1h",
    "client_id": "claude-code-worker"
  },
  "next_actions": [
    {"command": "export GITHUB_TOKEN=$(secrets lease github_token)", "description": "Export to environment"},
    {"command": "secrets revoke lease-123", "description": "Revoke this lease"}
  ]
}
```

Error responses include a concrete `fix` field:
```json
{
  "ok": false,
  "command": "secrets lease",
  "error": {"message": "failed to acquire lease: ... secret not found", "code": "generic_error"},
  "fix": "Check available secrets: secrets status"
}
```

**Important**: Secrets cannot be accessed directly. You must acquire a lease, and leases auto-expire.

### 4. Checking Status

View daemon and lease status:
```bash
secrets status
```

Output shows:
- Daemon running state
- Start time
- Number of stored secrets
- Active lease count

### 5. Audit Trail

View the append-only audit log:
```bash
# Last 50 entries (default)
secrets audit

# Last 100 entries
secrets audit --tail 100
```

Logs include:
- Secret access events
- Lease grants and expirations
- Revocations
- Rotation events
- Killswitch activations

### 6. Revocation

**Revoke specific lease**:
```bash
secrets revoke abc123
```

**KILLSWITCH — Revoke ALL active leases**:
```bash
secrets revoke --all
```

Use the killswitch when:
- Agent is compromised
- Session needs immediate termination
- Emergency security event occurs

## Agent Integration Patterns

### Claude Code / Cline / Aider

In your agent's environment setup script:
```bash
# Session initialization
secrets list
export GITHUB_TOKEN=$(secrets lease github_token)
export ANTHROPIC_API_KEY=$(secrets lease anthropic_key)
export OPENAI_API_KEY=$(secrets lease openai_key)

# Now agent has time-bounded access
gh api /user
curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" https://api.anthropic.com/...
```

### Swarm Worker Pattern

For multi-agent swarm tasks, each worker should:
1. Lease required credentials on startup with unique client ID
2. Use `--ttl` matching expected task duration
3. Let leases auto-expire on completion (no manual cleanup needed)

Example:
```bash
# Worker initialization
WORKER_ID="worker-${EPIC_ID}-${TASK_ID}"
export GH_TOKEN=$(secrets lease github_token --ttl 2h --client-id "$WORKER_ID")
export VERCEL_TOKEN=$(secrets lease vercel_token --ttl 2h --client-id "$WORKER_ID")

# Work proceeds with secured credentials
# Leases auto-expire after 2 hours
```

## Security Considerations

### Encryption
- All secrets encrypted at rest using [age](https://age-encryption.org/) with X25519
- Identity file permissions are `0600` (read/write owner only)
- No plaintext secrets on disk

### Lease Management
- Mandatory TTL on all leases (max 24h by default)
- Expired leases automatically pruned by background process
- Leases cannot be extended—must acquire new lease

### Audit
- Every operation logged with timestamp, client ID, and event type
- Append-only format (JSONL) prevents tampering
- Use audit log for security reviews and incident response

### Killswitch
- `revoke --all` immediately invalidates all active leases
- Optional: rotate all secrets with configured hooks
- Optional: wipe entire store
- Optional: heartbeat monitor (auto-killswitch if remote endpoint fails)

### Rotation Hooks
Auto-rotation commands run on lease expiration or manual trigger:
```bash
# GitHub token refresh
secrets add github_token --rotate-via "gh auth refresh"

# AWS session token
secrets add aws_token --rotate-via "aws sts get-session-token --duration-seconds 3600"

# Custom script
secrets add api_key --rotate-via "/path/to/refresh-token.sh"
```

## Configuration

Edit `~/.agent-secrets/config.json` to customize:

```json
{
  "directory": "/home/user/.agent-secrets",
  "socket_path": "/home/user/.agent-secrets/agent-secrets.sock",
  "default_lease_ttl": "1h",
  "max_lease_ttl": "24h",
  "rotation_timeout": "30s",
  "heartbeat": {
    "enabled": false,
    "url": "https://your-endpoint.com/heartbeat",
    "interval": "1m",
    "timeout": "10s",
    "fail_action": {
      "revoke_all": true,
      "rotate_all": false,
      "wipe_store": false
    }
  }
}
```

### Heartbeat Monitor (Optional)

Enable remote killswitch via heartbeat failure:
- Set `heartbeat.enabled: true`
- Configure endpoint URL
- Set fail actions (revoke_all, rotate_all, wipe_store)

If heartbeat endpoint becomes unreachable for `timeout` duration, configured fail actions execute automatically.

## Common CLI Commands Reference

| Command | Description | Example |
|---------|-------------|---------|
| `secrets` | Show command tree for discovery | `secrets` |
| `init` | Initialize encrypted store | `secrets init` |
| `list` | List stored secret names | `secrets list` |
| `add <name>` | Add secret (interactive or stdin) | `secrets add github_token` |
| `add <name> --rotate-via <cmd>` | Add secret with rotation hook | `secrets add token --rotate-via "gh auth refresh"` |
| `lease <name>` | Get raw secret value (default 1h lease) | `secrets lease github_token` |
| `lease <name> --json` | Get lease envelope + next actions | `secrets lease github_token --json` |
| `lease <name> --ttl <duration>` | Get lease with custom TTL | `secrets lease api_key --ttl 30m` |
| `lease <name> --client-id <id>` | Get lease with audit identifier | `secrets lease token --client-id "worker-123"` |
| `status` | Show daemon and lease status | `secrets status` |
| `audit` | View audit log (last 50 entries) | `secrets audit` |
| `audit --tail <n>` | View last N audit entries | `secrets audit --tail 100` |
| `revoke <lease-id>` | Revoke specific lease | `secrets revoke abc123` |
| `revoke --all` | KILLSWITCH: Revoke all leases | `secrets revoke --all` |

## Troubleshooting

**Daemon not running?**
```bash
# Check status
secrets status

# Daemon auto-starts on first lease/add command
secrets lease github_token
```

**Permission denied on identity file?**
```bash
chmod 600 ~/.agent-secrets/identity.age
```

**Forgot which secrets are stored?**
```bash
secrets list
```

**Need to rotate everything immediately?**
```bash
secrets revoke --all
# Then add secrets again with fresh values
```

## Best Practices for AI Agents

1. **Use descriptive client IDs**: Include agent name, task ID, or session ID for audit trail
2. **Match TTL to task duration**: Don't request 24h lease for 5min task
3. **Let leases expire naturally**: No manual cleanup needed
4. **Enable rotation hooks**: For dynamic credentials (GitHub, AWS, etc.)
5. **Monitor audit log**: Review for unexpected access patterns
6. **Test killswitch**: Verify `revoke --all` works in your environment
7. **Use unique leases per worker**: In swarm mode, each worker gets own lease with unique client ID

## Example: Full Agent Session

```bash
#!/bin/bash
# Agent session initialization with agent-secrets

set -euo pipefail

# Navigate to agent-secrets CLI
SECRETS_CLI="/home/joel/Code/joelhooks/agent-secrets/secrets"

# Lease credentials for 2-hour work session
echo "🔐 Acquiring credentials..."
export GITHUB_TOKEN=$($SECRETS_CLI lease github_token)
export ANTHROPIC_API_KEY=$($SECRETS_CLI lease anthropic_key)
export VERCEL_TOKEN=$($SECRETS_CLI lease vercel_token)

# Verify credentials loaded
echo "✅ Credentials acquired (expire in 2h)"

# Check status
$SECRETS_CLI status

# Agent work proceeds here...
# gh pr create ...
# vercel deploy ...
# etc.

# No cleanup needed - leases auto-expire
echo "🎯 Session complete (leases will auto-expire)"
```

## Repository Location

CLI source: `/home/joel/Code/joelhooks/agent-secrets`

Build the CLI:
```bash
cd /home/joel/Code/joelhooks/agent-secrets
make build
# Binary: secrets
```

Install system-wide:
```bash
cd /home/joel/Code/joelhooks/agent-secrets
make install
# Binary installed to $GOPATH/bin/secrets
```

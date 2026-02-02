# 🛡️ agent-secrets

**Aegis for AI Agents** — Portable credential management with age encryption, session-scoped leases, and a killswitch.

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Why?

AI agents need secrets. API keys, tokens, credentials. But giving an agent raw access to your secrets is asking for trouble:

- **Exfiltration risk** — compromised agent leaks all credentials
- **No audit trail** — who accessed what, when?
- **No revocation** — can't cut off access without rotating everything
- **No rotation** — credentials sit forever, waiting to be compromised

**agent-secrets** fixes this with:

- 🔐 **Age encryption** — secrets never plaintext on disk
- ⏱️ **Session-scoped leases** — TTL-based access, auto-expires
- 🔄 **Auto-rotation hooks** — `gh auth refresh`, custom commands
- 🚨 **Multi-factor killswitch** — revoke all + rotate all + wipe
- 📋 **Append-only audit log** — every access recorded

## Quick Start

```bash
# Build
make build

# Initialize encrypted store (creates ~/.agent-secrets/)
./secrets init

# Add secrets
./secrets add github_token --rotate-via "gh auth refresh"
./secrets add anthropic_key
echo "sk-ant-..." | ./secrets add openai_key

# Get a lease (returns secret value, starts TTL timer)
export GITHUB_TOKEN=$(./secrets lease github_token --ttl 1h)

# View status
./secrets status

# View audit log
./secrets audit --tail 20

# Emergency: revoke all leases
./secrets revoke --all
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (cobra)                         │
│   init | add | lease | revoke | audit | status              │
└─────────────────────────┬───────────────────────────────────┘
                          │ Unix Socket (JSON-RPC)
┌─────────────────────────▼───────────────────────────────────┐
│                    Daemon Process                           │
│         ~/.agent-secrets/agent-secrets.sock                 │
└─────┬─────────┬─────────┬─────────┬─────────┬───────────────┘
      │         │         │         │         │
      ▼         ▼         ▼         ▼         ▼
┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────┐
│  Store  │ │  Lease  │ │  Audit  │ │Rotation │ │ Killswitch  │
│  (age)  │ │ Manager │ │   Log   │ │  Hooks  │ │ +Heartbeat  │
└─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────────┘
```

## Commands

### `secrets init`
Initialize the encrypted store. Creates:
- `~/.agent-secrets/identity.age` — X25519 private key
- `~/.agent-secrets/secrets.age` — encrypted secrets
- `~/.agent-secrets/config.json` — configuration

### `secrets add <name>`
Add a secret to the store.

```bash
# Interactive (prompts for value)
secrets add my_secret

# With rotation hook
secrets add github_token --rotate-via "gh auth refresh"

# Pipe value from stdin
echo "secret-value" | secrets add api_key
cat credentials.txt | secrets add service_account
```

### `secrets lease <name>`
Acquire a time-bounded lease on a secret. Returns **only** the secret value (perfect for shell piping).

```bash
# Default 1 hour TTL
export TOKEN=$(secrets lease github_token)

# Custom TTL
export TOKEN=$(secrets lease github_token --ttl 30m)

# Custom client ID (for audit)
export TOKEN=$(secrets lease github_token --client-id "my-agent")
```

### `secrets revoke [lease-id]`
Revoke access.

```bash
# Revoke specific lease
secrets revoke abc123

# KILLSWITCH: Revoke ALL active leases
secrets revoke --all
```

### `secrets audit`
View the append-only audit log.

```bash
# Last 50 entries (default)
secrets audit

# Last 100 entries
secrets audit --tail 100
```

### `secrets status`
Show daemon status.

```bash
secrets status
# Running: true
# Started: 2024-01-15T10:30:00Z
# Secrets: 5
# Active Leases: 2
```

## Security Model

### Encryption
- All secrets encrypted at rest using [age](https://age-encryption.org/)
- X25519 key pair generated on init
- Identity file permissions: `0600`

### Leases
- Secrets **cannot** be accessed directly — must acquire a lease
- Leases have mandatory TTL (max 24h by default)
- Expired leases automatically cleaned up
- Background goroutine prunes expired leases

### Audit
- Every operation logged with timestamp
- Append-only format (JSONL)
- Logs: secret access, lease grants, revocations, rotations, killswitch events

### Killswitch
- `revoke --all` immediately invalidates all active leases
- Optional: rotate all secrets with hooks
- Optional: wipe entire store
- Optional: heartbeat monitor — auto-killswitch if remote endpoint goes down

## Configuration

Config stored at `~/.agent-secrets/config.json`:

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

## For AI Agents

### Claude Code / Cline / Aider
```bash
# In your agent's environment setup
export GITHUB_TOKEN=$(secrets lease github_token --ttl 1h --client-id "claude-code")
export ANTHROPIC_API_KEY=$(secrets lease anthropic_key --ttl 1h --client-id "claude-code")
```

### MCP Server Integration
Coming soon — expose as an MCP tool for direct agent access with automatic lease management.

## Development

```bash
# Run tests
make test

# Run with coverage
make test-cover

# Build
make build

# Install to $GOPATH/bin
make install

# Lint
make lint
```

## Dependencies

- [filippo.io/age](https://github.com/FiloSottile/age) — Modern encryption
- [github.com/spf13/cobra](https://github.com/spf13/cobra) — CLI framework
- [github.com/google/uuid](https://github.com/google/uuid) — Lease IDs

## License

MIT — Use it, fork it, ship it.

---

*Built for agents that need secrets but shouldn't keep them.*

# 🛡️ agent-secrets

**Aegis for AI Agents** — Portable credential management with age encryption, session-scoped leases, and a killswitch.

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Why?

AI agents need secrets: API keys, tokens, credentials. But giving an agent raw access to your password manager (and therefore all your passwords) is a terrible idea:

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

## Installation

**One-liner (macOS, Linux, WSL):**
```bash
curl -fsSL https://raw.githubusercontent.com/joelhooks/agent-secrets/main/install.sh | bash
```

**Or clone and install manually:**
```bash
git clone https://github.com/joelhooks/agent-secrets
cd agent-secrets
make build
sudo mv secrets /usr/local/bin/
```

**Or with Go:**
```bash
go install github.com/joelhooks/agent-secrets/cmd/secrets@latest
```

**Add the OpenClaw skill (teaches your agent how to use it):**
```bash
npx openclaw skills add https://github.com/joelhooks/agent-secrets
```

**Verify (self-documenting root command):**
```bash
secrets
```

## Quick Start

```bash
# 1) Initialize store and start daemon (one-time setup)
secrets init
secrets serve &

# 2) Add secrets
secrets add github_token --rotate-via "gh auth refresh"
secrets add anthropic_key
echo "sk-ant-..." | secrets add openai_key

# 3) Discover commands and available secrets
secrets
secrets list

# 4) Lease a secret (default output is raw value, ideal for exports)
export GITHUB_TOKEN=$(secrets lease github_token)

# 5) Request JSON envelope when you need metadata + next actions
secrets lease github_token --json

# 6) Inspect state and logs
secrets status
secrets audit --tail 20

# 7) Emergency killswitch
secrets revoke --all
```

> **Note:** The daemon must be running for most commands to work. The install script auto-starts it, but if you see "daemon not running" errors, run `secrets serve &`.

## Migration Guide: v0.4.x -> v0.5.x

`v0.5.x` keeps compatibility with older scripts while moving to JSON-first behavior.

- `secrets lease <name>` now defaults to raw value output. `--raw` still works as a hidden deprecated no-op and prints a warning to `stderr`. Remove it from scripts before `v0.6.0`.
- `--human` and `--output` are restored as hidden deprecated global flags. They are no-ops and print warnings to `stderr`. Remove them before `v0.6.0`.
- JSON envelopes now include both `ok` and `success` for one version cycle. They carry the same boolean value.

## JSON Envelope Pattern

All commands return a JSON response envelope with `ok`, `success`, `command`, `result`, and `next_actions`, except `secrets lease <name>` which returns only the raw secret value by default.

```bash
# Root command returns command tree
secrets
```

```json
{
  "ok": true,
  "command": "secrets",
  "result": {
    "description": "Portable credential management for AI agents",
    "version": "dev",
    "commands": [
      {"name": "init", "description": "Initialize the secrets store", "usage": "secrets init"},
      {"name": "list", "description": "List stored secret names", "usage": "secrets list"},
      {"name": "lease", "description": "Get a secret value (raw by default)", "usage": "secrets lease <name> [--ttl 1h] [--client-id agent-x] [--json]"}
    ]
  },
  "next_actions": [
    {"command": "secrets status", "description": "Check daemon status"}
  ]
}
```

```bash
# Lease envelope (opt in)
secrets lease github_token --json
```

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
    "client_id": "my-agent"
  },
  "next_actions": [
    {"command": "export GITHUB_TOKEN=$(secrets lease github_token)", "description": "Export to environment"},
    {"command": "secrets revoke lease-123", "description": "Revoke this lease"}
  ]
}
```

```json
{
  "ok": false,
  "command": "secrets lease",
  "error": {
    "message": "failed to acquire lease: ... secret not found",
    "code": "generic_error"
  },
  "fix": "Check available secrets: secrets status"
}
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

### `secrets`
Show a self-documenting command tree for agent discovery.

```bash
secrets
```

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

### `secrets list`
List stored secret names and lease-related metadata for discovery.

```bash
secrets list
```

### `secrets lease <name>`
Acquire a time-bounded lease on a secret.

- Default output: **raw secret value only** (best for shell exports)
- `--json`: full envelope with lease metadata and `next_actions`

```bash
# Primary pattern: raw value for shell export
export TOKEN=$(secrets lease github_token)

# Custom TTL
export TOKEN=$(secrets lease github_token --ttl 30m)

# Custom client ID (for audit)
export TOKEN=$(secrets lease github_token --client-id "my-agent")

# JSON envelope for agents
secrets lease github_token --json
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
```

```json
{
  "ok": true,
  "command": "secrets status",
  "result": {
    "running": true,
    "secrets_count": 5,
    "active_leases": 2,
    "started_at": "2026-02-19T10:30:00Z",
    "uptime": "1h 15m"
  },
  "next_actions": [
    {"command": "secrets lease <name>", "description": "Get a secret value"}
  ]
}
```

### `secrets env`
Generate `.env` file from `.secrets.json` config. Perfect for agentic workflows where secrets need to be loaded into a project environment.

```bash
# Generate .env from .secrets.json in current directory
secrets env

# Force overwrite existing .env
secrets env --force
```

**How it works:**
1. Reads `.secrets.json` from current directory
2. Acquires leases for each secret listed
3. Writes `KEY=value` pairs to `.env` file
4. Sets restrictive permissions (0600)

**Example `.secrets.json`:**
```json
{
  "secrets": [
    {
      "name": "github_token",
      "env_var": "GITHUB_TOKEN"
    },
    {
      "name": "anthropic_key",
      "env_var": "ANTHROPIC_API_KEY"
    },
    {
      "name": "openai_key",
      "env_var": "OPENAI_API_KEY",
      "ttl": "30m"
    }
  ],
  "client_id": "my-project"
}
```

**Schema:**
- `secrets` (required): Array of secret mappings
  - `name` (required): Secret name in agent-secrets store
  - `env_var` (required): Environment variable name for .env file
  - `ttl` (optional): Custom TTL for this secret (default: 1h)
- `client_id` (optional): Custom client ID for audit trail (default: auto-generated)

### `secrets exec`
Run a command with secrets loaded as environment variables. Combines `secrets env` + command execution + automatic cleanup.

```bash
# Run command with secrets loaded
secrets exec -- npm run dev

# Run tests with credentials
secrets exec -- pytest tests/

# Execute shell script
secrets exec -- ./deploy.sh

# Chain multiple commands
secrets exec -- sh -c "npm install && npm test"
```

**What it does:**
1. Generates temporary `.env` file from `.secrets.json`
2. Executes command with environment loaded
3. Cleans up `.env` file when command exits (even on error)

### `secrets cleanup`
Remove expired lease environment files. Run this to clean up stale `.env` files when leases have expired.

```bash
# Remove all expired .env files
secrets cleanup

# Check what would be cleaned (dry-run)
secrets cleanup --dry-run
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

## Agent Integration

Once the CLI is installed globally (`secrets` in PATH), any AI agent with shell access can use it directly. For richer integration, install the skill documentation or platform plugins.

### Any Agent (Direct CLI)

Works out of the box with any agent that can run shell commands.

**Option 1: Direct lease (single secret)**
```bash
# Lease credentials for a task
export GITHUB_TOKEN=$(secrets lease github_token --ttl 1h --client-id "claude-refactor-123")
export ANTHROPIC_API_KEY=$(secrets lease anthropic_key --ttl 1h --client-id "claude-refactor-123")

# Check status
secrets status

# Revoke when done
secrets revoke --all
```

**Option 2: Project-based workflow (.secrets.json)**
```bash
# 1. Create .secrets.json in project root
cat > .secrets.json <<'EOF'
{
  "secrets": [
    {"name": "github_token", "env_var": "GITHUB_TOKEN"},
    {"name": "anthropic_key", "env_var": "ANTHROPIC_API_KEY"},
    {"name": "vercel_token", "env_var": "VERCEL_TOKEN", "ttl": "30m"}
  ],
  "client_id": "project-deploy-task"
}
EOF

# 2. Generate .env with all secrets
secrets env

# 3. Work with credentials loaded
source .env
npm run deploy

# 4. Cleanup when done
secrets cleanup
```

**Option 3: One-shot execution**
```bash
# Run command with secrets, auto-cleanup
secrets exec -- npm run deploy
secrets exec -- pytest tests/integration
secrets exec -- ./scripts/sync-prod.sh
```

**Best practices:**
- Use descriptive `--client-id` values (task name, agent ID)
- Match TTL to expected task duration
- Revoke leases when task completes or errors
- Use `secrets exec` for one-shot commands (auto-cleanup)
- Use `.secrets.json` for multi-secret workflows

---

### Claude Code / OpenCode (Agent Skills)

Install the skill documentation so agents understand capabilities and usage patterns.

**Option 1: Global skills (recommended)**
```bash
# Install skill globally - available to all projects
mkdir -p ~/.claude/skills
cp -r agent-secrets/skills/secret-management ~/.claude/skills/

# For OpenCode
mkdir -p ~/.opencode/skills
cp -r agent-secrets/skills/secret-management ~/.opencode/skills/
```

**Option 2: Per-project skills**
```bash
# Add to a specific project
mkdir -p your-project/.claude/skills
cp -r agent-secrets/skills/secret-management your-project/.claude/skills/
```

Once installed, agents will discover the skill and know how to use the CLI:
```bash
secrets status
secrets lease github_token --ttl 1h --client-id "claude-session-123"
```

---

### OpenClaw Plugin

The repo includes a full OpenClaw plugin with registered tools.

**Installation**

Add to your OpenClaw config (`~/.openclaw/config.json`):

```json
{
  "plugins": {
    "load": {
      "paths": ["~/path/to/agent-secrets"]
    },
    "entries": {
      "agent-secrets": {
        "enabled": true,
        "config": {
          "default_ttl": "1h",
          "client_id_prefix": "openclaw"
        }
      }
    }
  }
}
```

The plugin assumes `secrets` is in your PATH. Override with `"cli_path": "/custom/path/secrets"` if needed.

**Registered Tools**

| Tool | Description | Optional |
|------|-------------|----------|
| `secrets_lease` | Acquire time-bounded credential | No |
| `secrets_status` | Check daemon and lease status | No |
| `secrets_revoke` | Revoke specific lease | No |
| `secrets_audit` | View audit log | No |
| `secrets_add` | Add new secret | Yes (allowlist) |
| `secrets_killswitch` | Emergency revoke all | Yes (allowlist) |

**Enabling optional tools** (dangerous operations require explicit allowlist):

```json
{
  "agents": {
    "list": [{
      "id": "main",
      "tools": {
        "allow": ["secrets_add", "secrets_killswitch"]
      }
    }]
  }
}
```

**Usage in OpenClaw:**
```
Agent: I need to access the GitHub token for this task.

[Tool: secrets_lease]
{
  "name": "github_token",
  "ttl": "30m",
  "client_id": "openclaw-task-123"
}

→ Returns: ghp_xxxxxxxxxxxx
```

---

### Direct CLI Usage (Any Agent)

Any agent with shell access can use the CLI directly:

```bash
# In your agent's environment setup or task preamble
export GITHUB_TOKEN=$(secrets lease github_token --ttl 1h --client-id "my-agent")
export ANTHROPIC_API_KEY=$(secrets lease anthropic_key --ttl 1h --client-id "my-agent")

# Check what's available
secrets status

# When done or on error, revoke the lease
secrets revoke $LEASE_ID
```

**Best practices for agents:**
1. Use descriptive `--client-id` values (e.g., `"claude-refactor-auth-module"`)
2. Match TTL to expected task duration
3. Revoke leases when task completes
4. Use `secrets audit` to review access patterns

---

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

## Inspiration

This project was inspired by [Alex Hillman's approach](https://x.com/alexhillman/status/2005334574973296911) to agent credential management — the insight that agents shouldn't be anywhere near ALL your passwords. Scoped, time-bounded, audited access with a killswitch.

## License

MIT — Use it, fork it, ship it.

---

*Built for agents that need secrets but shouldn't keep them.*

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

**Verify:**
```bash
secrets --help
```

## Quick Start

```bash
# Initialize encrypted store (creates ~/.agent-secrets/)
secrets init

# Add secrets
secrets add github_token --rotate-via "gh auth refresh"
secrets add anthropic_key
echo "sk-ant-..." | secrets add openai_key

# Get a lease (returns secret value, starts TTL timer)
export GITHUB_TOKEN=$(secrets lease github_token --ttl 1h)

# View status
secrets status

# View audit log
secrets audit --tail 20

# Emergency: revoke all leases
secrets revoke --all
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

### MCP Server Integration

Coming soon — expose as an MCP tool server for direct agent access with automatic lease management.

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

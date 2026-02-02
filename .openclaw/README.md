# OpenClaw Plugin for Agent Secrets

This directory contains the OpenClaw plugin integration for `agent-secrets`, providing AI agents with secure credential management capabilities.

## Plugin Structure

```
.openclaw/
├── extensions/
│   └── secrets.ts          # TypeScript plugin entry point
└── README.md               # This file
```

The plugin manifest is at the repository root: `openclaw.plugin.json`

## Usage in OpenClaw

Once OpenClaw discovers this plugin, agents can use the secrets management API:

```typescript
import { activate } from './agent-secrets/.openclaw/extensions/secrets';

const plugin = activate({
  secrets_cli_path: '/home/joel/Code/joelhooks/agent-secrets/secrets',
  default_ttl: '1h',
  client_id_prefix: 'openclaw',
});

// Lease a credential for 2 hours
const githubToken = await plugin.secrets.lease('github_token', { ttl: '2h' });

// Initialize an agent session with multiple credentials
const creds = await plugin.initSession(['github_token', 'anthropic_key'], '2h');
console.log(creds.github_token);
console.log(creds.anthropic_key);

// Emergency revocation
await plugin.emergencyKillswitch();
```

## Configuration

The plugin accepts the following config options (via `openclaw.plugin.json`):

- `secrets_cli_path`: Path to the agent-secrets CLI binary (default: `/home/joel/Code/joelhooks/agent-secrets/secrets`)
- `default_ttl`: Default lease TTL (default: `1h`)
- `max_ttl`: Maximum allowed lease TTL (default: `24h`)
- `auto_init`: Automatically initialize secrets store if not present (default: `false`)
- `client_id_prefix`: Prefix for client IDs in audit logs (default: `openclaw`)

## Available Tools

The plugin exposes these tools to OpenClaw agents:

- `init()` - Initialize encrypted secrets store
- `add(name, options)` - Add a new secret (with optional rotation hook)
- `lease(name, options)` - Acquire time-bounded lease for a secret
- `revoke(leaseId)` - Revoke specific lease
- `revokeAll()` - KILLSWITCH: Revoke all active leases
- `status()` - Get daemon and lease status
- `audit(tailCount)` - View audit log entries

## Integration Patterns

### Session Initialization

```typescript
const creds = await plugin.initSession(
  ['github_token', 'vercel_token', 'anthropic_key'],
  '2h'
);

// Use credentials
process.env.GITHUB_TOKEN = creds.github_token;
process.env.VERCEL_TOKEN = creds.vercel_token;
process.env.ANTHROPIC_API_KEY = creds.anthropic_key;
```

### Swarm Worker Pattern

```typescript
// Each worker gets unique client ID for audit trail
const workerId = `worker-${epicId}-${taskId}`;
const apiKey = await plugin.secrets.lease('openai_key', {
  ttl: '2h',
  clientId: workerId,
});
```

### Emergency Revocation

```typescript
// If agent is compromised or session needs immediate termination
await plugin.emergencyKillswitch();
```

## CLI Reference

For direct CLI usage, see `skills/secret-management/SKILL.md`.

## Security Model

- All secrets encrypted at rest using age (X25519)
- Mandatory TTL on all leases (max 24h)
- Expired leases auto-pruned by background daemon
- Append-only audit log for security reviews
- Multi-factor killswitch for emergency revocation
- Optional auto-rotation hooks for dynamic credentials

## Repository

Source: `/home/joel/Code/joelhooks/agent-secrets`

Build the CLI:
```bash
cd /home/joel/Code/joelhooks/agent-secrets
make build
```

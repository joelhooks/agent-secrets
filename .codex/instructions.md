# Agent Secrets - Codex Instructions

You have access to the `secrets` CLI for secure credential management.

## Quick Reference

```bash
# Get credentials (returns JSON with value and actions)
secrets lease <name> --ttl 1h --client-id codex-task

# Get raw value for export
export TOKEN=$(secrets lease github_token --raw)

# Check status
secrets status

# Revoke when done
secrets revoke <lease_id>

# Emergency: revoke all
secrets revoke --all
```

## JSON Response Format

All commands return JSON by default:

```json
{
  "success": true,
  "message": "Lease acquired",
  "data": {
    "lease_id": "abc123",
    "value": "ghp_xxxxx",
    "expires_at": "2024-01-15T12:00:00Z"
  },
  "actions": [
    {"name": "revoke", "command": "secrets revoke abc123"},
    {"name": "status", "command": "secrets status"}
  ]
}
```

## Best Practices

1. Use `--client-id` with descriptive task names for audit
2. Match TTL to expected task duration
3. Use `--raw` flag when piping to environment variables
4. Always revoke leases when task completes
5. Check `actions` array for suggested next steps

## Human-Readable Mode

Add `--human` flag for readable output (not recommended for agents).

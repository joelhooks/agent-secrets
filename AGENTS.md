# Agent Instructions for agent-secrets

This file provides context for AI agents working on this codebase.

## Project Overview

**agent-secrets** is a Go CLI for portable credential management for AI agents. It provides secure, time-bounded access to API keys and tokens without exposing plaintext secrets.

**Core features:**
- Age encryption for secrets at rest
- Session-scoped leases with TTL (auto-expiration)
- Auto-rotation hooks for dynamic credentials
- Multi-factor killswitch for emergency revocation
- Append-only audit logging

## Repository Structure

```
agent-secrets/
├── cmd/secrets/          # CLI entry point (Cobra commands)
│   ├── main.go
│   ├── root.go
│   ├── init.go
│   ├── add.go
│   ├── lease.go
│   ├── revoke.go
│   ├── audit.go
│   └── status.go
├── internal/
│   ├── types/            # Shared types and errors
│   ├── config/           # Configuration management
│   ├── store/            # Age-encrypted secret storage
│   ├── audit/            # Append-only audit log
│   ├── lease/            # TTL-based lease manager
│   ├── rotation/         # Auto-rotation hook executor
│   ├── killswitch/       # Emergency revocation + heartbeat
│   └── daemon/           # Unix socket daemon (JSON-RPC)
├── skills/               # Agent Skills (Claude Code, OpenCode)
│   └── secret-management/
│       └── SKILL.md
├── .openclaw/            # OpenClaw plugin
│   └── extensions/
│       └── secrets.ts
├── .github/workflows/    # CI/CD
│   ├── ci.yml            # Tests, lint, goreleaser check
│   └── release.yml       # Automated releases on v* tags
├── .goreleaser.yml       # Multi-platform binary builds
└── install.sh            # Cross-platform installer
```

## Tech Stack

- **Language:** Go 1.22+
- **Encryption:** [filippo.io/age](https://github.com/FiloSottile/age) (X25519)
- **CLI:** [Cobra](https://github.com/spf13/cobra)
- **IPC:** Unix socket with JSON-RPC
- **CI:** GitHub Actions + GoReleaser

## CLI Commands

| Command | Description |
|---------|-------------|
| `secrets init` | Initialize encrypted store (~/.agent-secrets/) |
| `secrets add <name>` | Add a secret (interactive, stdin, or with rotation hook) |
| `secrets lease <name>` | Get time-bounded lease (returns secret value) |
| `secrets revoke <id>` | Revoke specific lease |
| `secrets revoke --all` | KILLSWITCH: revoke all leases |
| `secrets status` | Show daemon status and active leases |
| `secrets audit` | View append-only audit log |

## Development

```bash
# Build
make build

# Test
make test

# Lint
make lint

# Run locally
./secrets --help
```

## Release Process

Releases are automated via GitHub Actions. To publish a new version:

```bash
# 1. Ensure all changes are committed and pushed
git status  # Should be clean

# 2. Create and push a version tag
git tag -a v0.1.1 -m "v0.1.1 - Description of changes"
git push origin v0.1.1

# 3. GitHub Actions will automatically:
#    - Build binaries for linux/darwin (amd64/arm64)
#    - Create GitHub Release with assets
#    - Generate checksums
```

**Version format:** Semantic versioning (vMAJOR.MINOR.PATCH)

**Pre-release:** Use `-alpha`, `-beta`, `-rc1` suffixes (e.g., `v0.2.0-alpha`)

## Testing Changes

Before creating a release:

```bash
# Run full test suite
make test

# Check goreleaser config
goreleaser check

# Build locally to verify
goreleaser build --snapshot --clean
```

## Agent Integration Points

### For agents using this tool:

1. **Check if installed:** `which secrets || echo "Not installed"`
2. **Initialize if needed:** `secrets init`
3. **Lease credentials:** `export TOKEN=$(secrets lease github_token --ttl 1h --client-id "agent-task-123")`
4. **Revoke when done:** `secrets revoke --all`

### For agents modifying this repo:

1. **Run tests after changes:** `make test`
2. **Check types:** `go build ./...`
3. **Lint before commit:** `make lint`
4. **Don't modify release tags** — create new versions instead

## Key Files for Common Tasks

| Task | Files |
|------|-------|
| Add CLI command | `cmd/secrets/` |
| Modify encryption | `internal/store/` |
| Change lease logic | `internal/lease/` |
| Update audit format | `internal/audit/` |
| Fix daemon IPC | `internal/daemon/` |
| Update install script | `install.sh` |
| Modify release process | `.goreleaser.yml`, `.github/workflows/release.yml` |

## Security Considerations

- **Never log secret values** — only log metadata (name, lease ID, timestamps)
- **Secrets are encrypted at rest** — identity.age file has 0600 permissions
- **Leases have mandatory TTL** — max 24h by default
- **Killswitch exists** — `revoke --all` for emergencies
- **Audit log is append-only** — tampering is detectable

## Contact

Repository: https://github.com/joelhooks/agent-secrets

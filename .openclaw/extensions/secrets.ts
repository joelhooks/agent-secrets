import { exec } from 'child_process';
import { promisify } from 'util';
import { Type } from '@sinclair/typebox';

const execAsync = promisify(exec);

interface PluginConfig {
  cli_path?: string;
  default_ttl?: string;
  client_id_prefix?: string;
}

/**
 * Agent Secrets OpenClaw Plugin
 *
 * Provides secure, time-bounded credential access for AI agents using:
 * - Age encryption for secrets at rest
 * - Session-scoped leases with auto-expiration
 * - Auto-rotation hooks for dynamic credentials
 * - Multi-factor killswitch for emergency revocation
 * - Append-only audit logging
 */
export default function(api: any) {
  const config: PluginConfig = api.config || {};
  const cliPath = config.cli_path || 'secrets';
  const defaultTTL = config.default_ttl || '1h';
  const clientPrefix = config.client_id_prefix || 'openclaw';

  // Helper to run CLI commands
  async function runCli(args: string): Promise<string> {
    const { stdout, stderr } = await execAsync(`${cliPath} ${args}`);
    if (stderr && !stderr.includes('Success')) {
      throw new Error(stderr);
    }
    return stdout.trim();
  }

  // Register: secrets_lease - Get time-bounded credential access
  api.registerTool({
    name: 'secrets_lease',
    description: 'Acquire a time-bounded lease for a secret. Returns the decrypted secret value. The lease automatically expires after the TTL.',
    parameters: Type.Object({
      name: Type.String({ description: 'Name of the secret to lease' }),
      ttl: Type.Optional(Type.String({ description: 'Lease duration (e.g., "1h", "30m", "2h"). Defaults to 1h.' })),
      client_id: Type.Optional(Type.String({ description: 'Client identifier for audit logging' }))
    }),
    async execute(_id: string, params: { name: string; ttl?: string; client_id?: string }) {
      const ttl = params.ttl || defaultTTL;
      const clientId = params.client_id || `${clientPrefix}-${Date.now()}`;
      const result = await runCli(`lease ${params.name} --ttl ${ttl} --client-id "${clientId}"`);
      return { content: [{ type: 'text', text: result }] };
    }
  });

  // Register: secrets_status - Check daemon and lease status
  api.registerTool({
    name: 'secrets_status',
    description: 'Get the status of the secrets daemon, including active leases and secret count.',
    parameters: Type.Object({}),
    async execute() {
      const result = await runCli('status');
      return { content: [{ type: 'text', text: result }] };
    }
  });

  // Register: secrets_revoke - Revoke a specific lease
  api.registerTool({
    name: 'secrets_revoke',
    description: 'Revoke a specific lease by ID, immediately invalidating access to that secret.',
    parameters: Type.Object({
      lease_id: Type.String({ description: 'The lease ID to revoke' })
    }),
    async execute(_id: string, params: { lease_id: string }) {
      const result = await runCli(`revoke ${params.lease_id}`);
      return { content: [{ type: 'text', text: result || 'Lease revoked successfully' }] };
    }
  });

  // Register: secrets_killswitch - Emergency revoke all (optional, requires allowlist)
  api.registerTool({
    name: 'secrets_killswitch',
    description: 'EMERGENCY: Revoke ALL active leases immediately. Use only in emergencies.',
    parameters: Type.Object({
      confirm: Type.Boolean({ description: 'Must be true to confirm killswitch activation' })
    }),
    async execute(_id: string, params: { confirm: boolean }) {
      if (!params.confirm) {
        return { content: [{ type: 'text', text: 'Killswitch not activated. Set confirm: true to proceed.' }] };
      }
      const result = await runCli('revoke --all');
      return { content: [{ type: 'text', text: result || 'All leases revoked' }] };
    }
  }, { optional: true }); // Requires explicit allowlist

  // Register: secrets_audit - View audit log
  api.registerTool({
    name: 'secrets_audit',
    description: 'View the append-only audit log of all secret access and lease operations.',
    parameters: Type.Object({
      tail: Type.Optional(Type.Number({ description: 'Number of recent entries to show', default: 50 }))
    }),
    async execute(_id: string, params: { tail?: number }) {
      const tail = params.tail || 50;
      const result = await runCli(`audit --tail ${tail}`);
      return { content: [{ type: 'text', text: result }] };
    }
  });

  // Register: secrets_add - Add a new secret (optional, requires allowlist)
  api.registerTool({
    name: 'secrets_add',
    description: 'Add a new secret to the encrypted store. Optionally specify a rotation command.',
    parameters: Type.Object({
      name: Type.String({ description: 'Name for the secret' }),
      value: Type.String({ description: 'The secret value to store' }),
      rotate_via: Type.Optional(Type.String({ description: 'Command to run for auto-rotation' }))
    }),
    async execute(_id: string, params: { name: string; value: string; rotate_via?: string }) {
      let cmd = `add ${params.name}`;
      if (params.rotate_via) {
        cmd += ` --rotate-via "${params.rotate_via}"`;
      }
      // Pipe value to stdin
      const { stdout, stderr } = await execAsync(`echo "${params.value}" | ${cliPath} ${cmd}`);
      if (stderr && !stderr.includes('added')) {
        throw new Error(stderr);
      }
      return { content: [{ type: 'text', text: 'Secret added successfully' }] };
    }
  }, { optional: true }); // Requires explicit allowlist
}

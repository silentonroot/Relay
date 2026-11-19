import { connect } from 'node:net';
import { VAULT_OPERATION_SCHEMAS } from '@aab/contracts';
import type { VaultOperation, VaultParams, VaultResult } from '@aab/contracts';

/*
 * A minimal client for the vault's admin socket (the `vault` command). One request, one response
 * line, a timeout. It returns the result or throws an `AdminCallError` carrying the vault's error
 * code and nothing else.
 */

export class AdminCallError extends Error {
  override readonly name = 'AdminCallError';
  constructor(readonly code: string) {
    super(code);
  }
}

export function adminSocketPath(socketDir: string): string {
  return `${socketDir}/admin/vault.sock`;
}

export function callVault<Op extends VaultOperation>(
  socketPath: string,
  operation: Op,
  params: VaultParams<Op>,
  timeoutMs = 120_000,
): Promise<VaultResult<Op>> {
  return new Promise((resolve, reject) => {
    const socket = connect(socketPath);
    let data = '';
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new AdminCallError('timeout'));
    }, timeoutMs);
    const done = (finish: () => void) => {
      clearTimeout(timer);
      socket.destroy();
      finish();
    };
    socket.on('connect', () =>
      socket.write(`${JSON.stringify({ id: 'cli', operation, params })}\n`),
    );
    socket.on('data', (chunk) => {
      data += chunk.toString('utf8');
      const end = data.indexOf('\n');
      if (end === -1) return;
      done(() => {
        try {
          const response = JSON.parse(data.slice(0, end)) as {
            ok?: boolean;
            result?: unknown;
            error?: { code?: string };
          };
          if (response.ok === true) {
            const checked = VAULT_OPERATION_SCHEMAS[operation].result.safeParse(response.result);
            if (checked.success) resolve(checked.data as VaultResult<Op>);
            else reject(new AdminCallError('bad_response'));
          } else {
            reject(new AdminCallError(response.error?.code ?? 'bad_response'));
          }
        } catch {
          reject(new AdminCallError('bad_response'));
        }
      });
    });
    socket.on('error', () => done(() => reject(new AdminCallError('unreachable'))));
    socket.on('close', () => done(() => reject(new AdminCallError('closed'))));
  });
}

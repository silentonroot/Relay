import { VaultCallError } from '@aab/vault-client';
import type { VaultGateway } from './gateway.js';

export type VaultStartOutcome =
  | { state: 'ready' }
  /** The vault did not answer. The API starts degraded (ADR-014 sections 7 and 9). */
  | { state: 'unreachable'; code: string };

/**
 * The start-up `hello` check (ADR-014 section 3). Throws `VaultStartupRefusal` when the vault
 * answered and is wrong for this API (another role, another isolation mode, a readable key
 * directory in `separate-uid` mode): the caller must not start. Returns `unreachable` when the
 * vault gave no usable answer; every later authorization repeats the check before it uses the vault.
 */
export async function verifyVaultAtStart(gateway: VaultGateway): Promise<VaultStartOutcome> {
  try {
    await gateway.verify();
    return { state: 'ready' };
  } catch (error) {
    if (error instanceof VaultCallError) return { state: 'unreachable', code: error.code };
    throw error;
  }
}

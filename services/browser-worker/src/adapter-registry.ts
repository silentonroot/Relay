import { AdapterRegistry } from '@aab/adapter-sdk';
import type { ApplicationAdapter } from '@aab/adapter-sdk';
import { pathToFileURL } from 'node:url';

/**
 * Loads a registry module (exporting `adapters: readonly ApplicationAdapter[]`) into an
 * `AdapterRegistry`, which accepts only adapters produced by `defineAdapter`. Shared by the
 * supervisor and the runner.
 */
export async function loadAdapterRegistry(modulePath: string): Promise<AdapterRegistry> {
  const loaded: unknown = await import(pathToFileURL(modulePath).href);
  const list = (loaded as { adapters?: unknown }).adapters;
  if (!Array.isArray(list)) {
    throw new Error('the adapter registry module must export an `adapters` array');
  }
  const registry = new AdapterRegistry();
  for (const adapter of list as ApplicationAdapter[]) registry.register(adapter);
  return registry;
}

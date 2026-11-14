import { isDefinedAdapter } from './define.js';
import { AdapterContractError } from './errors.js';
import type { ApplicationAdapter } from './types.js';

const keyOf = (id: string, version: string): string => `${id}@${version}`;

/** The set of adapters a process is willing to run, keyed by id and exact version. */
export class AdapterRegistry {
  readonly #adapters = new Map<string, ApplicationAdapter>();

  /** Throws AdapterContractError for unvalidated adapters and duplicate id+version pairs. */
  register(adapter: ApplicationAdapter): void {
    if (!isDefinedAdapter(adapter)) {
      throw new AdapterContractError('only adapters created with defineAdapter can be registered');
    }
    const key = keyOf(adapter.id, adapter.version);
    if (this.#adapters.has(key)) {
      throw new AdapterContractError(`adapter ${key} is already registered`);
    }
    this.#adapters.set(key, adapter);
  }

  get(id: string, version: string): ApplicationAdapter | undefined {
    return this.#adapters.get(keyOf(id, version));
  }

  list(): ApplicationAdapter[] {
    return [...this.#adapters.values()];
  }
}

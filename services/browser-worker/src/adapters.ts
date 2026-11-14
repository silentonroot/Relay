import { northstarAdapter } from '@aab/adapter-northstar';
import type { ApplicationAdapter } from '@aab/adapter-sdk';

/**
 * The static adapter registry: every adapter the browser worker will run. The supervisor and
 * the runner both load this module (the runner inside the sandbox, from the read-only code
 * mount). Supervisor configuration may point at a different module, for tests; a job message
 * never can.
 */
export const adapters: readonly ApplicationAdapter[] = [northstarAdapter];

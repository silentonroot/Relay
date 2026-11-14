import type { ApplicationAdapter } from '@aab/adapter-sdk';
import { fixtureAdapter } from './fixture-adapter.js';

/** Test registry, selected through supervisor configuration (`adapterRegistryModule`). */
export const adapters: readonly ApplicationAdapter[] = [fixtureAdapter];

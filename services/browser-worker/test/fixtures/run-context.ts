import { inject } from 'vitest';

/** Values chosen once per test run by test/global-setup.ts. */

export const fixturePort = (): number => inject('fixturePort');
export const fixtureOrigin = (): string => `http://127.0.0.1:${fixturePort()}`;
export const runtimeBaseDir = (): string => inject('runtimeBaseDir');
export const registryModule = (): string => inject('registryModule');

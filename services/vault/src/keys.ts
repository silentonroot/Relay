import { createSecretKey } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import { inspect } from 'node:util';
import { KekStoreError, LocalFileKekProvider } from '@aab/crypto';

/*
 * The vault's key material, loaded once at start (ADR-014 section 3). The KEK stays inside
 * the `LocalFileKekProvider`; the capability MAC keys are derived from each KEK version with
 * HKDF (label `aab.vault.capability-mac.v1`) and kept here, in memory only, as KeyObjects that
 * do not print their bytes. Nothing here is ever logged or returned by an operation.
 */

export class VaultKeys {
  readonly #macKeys = new Map<number, KeyObject>();
  readonly kekProvider: LocalFileKekProvider;
  readonly keyDirectory: string;

  private constructor(provider: LocalFileKekProvider) {
    this.kekProvider = provider;
    this.keyDirectory = provider.directory;
  }

  /**
   * Loads every KEK version from `directory` (the ADR-003 checks, unchanged) and requires the
   * directory to belong to the vault's own user: the vault narrows the provider's "this user
   * or root". Refuses to start when no KEK is present or the directory is unsafe.
   */
  static async load(directory: string): Promise<VaultKeys> {
    const stat = await lstat(directory).catch(() => null);
    const uid = process.geteuid?.();
    if (stat !== null && uid !== undefined && stat.isDirectory() && stat.uid !== uid) {
      throw new KekStoreError(`KEK directory must be owned by the vault's user: ${directory}`);
    }
    const provider = await LocalFileKekProvider.load(directory);
    const keys = new VaultKeys(provider);
    for (const version of provider.versions) {
      const derived = provider.deriveKeyFor(version, 'vaultCapabilityMac');
      try {
        keys.#macKeys.set(derived.kekVersion, createSecretKey(derived.key));
      } finally {
        derived.key.fill(0);
      }
    }
    return keys;
  }

  get currentKekVersion(): number {
    return this.kekProvider.currentVersion;
  }

  get kekVersions(): number[] {
    return this.kekProvider.versions;
  }

  /** The MAC key for a KEK version, or undefined when that version is not loaded. */
  macKey(kekVersion: number): KeyObject | undefined {
    return this.#macKeys.get(kekVersion);
  }

  /** The MAC key of the current KEK version, with the version to record beside the MAC. */
  currentMacKey(): { kekVersion: number; key: KeyObject } {
    const kekVersion = this.currentKekVersion;
    const key = this.#macKeys.get(kekVersion);
    if (key === undefined) throw new KekStoreError('no capability MAC key for the current KEK');
    return { kekVersion, key };
  }

  [inspect.custom](): string {
    return `VaultKeys ${inspect({ kekVersions: this.kekVersions })}`;
  }

  toJSON(): Record<string, unknown> {
    return { kekVersions: this.kekVersions };
  }
}

import { createSecretKey } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { lstat, realpath } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { inspect } from 'node:util';
import { KekStoreError, LocalFileKekProvider } from '@aab/crypto';
import { ancestorProblem } from './socket-safety.js';

/*
 * The vault's key material, loaded once at start (ADR-014 section 3). The KEK stays inside
 * the `LocalFileKekProvider`; the capability MAC keys are derived from each KEK version with
 * HKDF (label `aab.vault.capability-mac.v1`) and kept here, in memory only, as KeyObjects that
 * do not print their bytes. Nothing here is ever logged or returned by an operation.
 */

/**
 * The key directory's path must be a real one (no symbolic link in it) and every directory above
 * it must pass the socket directory's rule (`ancestorProblem`): owned by root or the vault's user
 * and not writable by group or other, a sticky directory being exempt only when root owns it.
 * Whoever can rename an ancestor, or replace a link, can swap the key directory after it was
 * checked (ADR-014 section 3; the B2 residual closed in B4 and tightened in its review). A
 * directory that does not exist yet (`init-kek`) is checked through its nearest existing
 * ancestor. Runs before any key file is read.
 */
export async function requireSafeKeyPath(directory: string): Promise<void> {
  const uid = process.geteuid?.() ?? -1;
  const target = resolve(directory);
  let existing = target;
  for (;;) {
    if (
      await lstat(existing).then(
        () => true,
        () => false,
      )
    )
      break;
    const parent = dirname(existing);
    if (parent === existing) break;
    existing = parent;
  }
  if ((await realpath(existing)) !== existing) {
    throw new KekStoreError(`the KEK directory path must not contain a symbolic link: ${target}`);
  }
  // The nearest existing path is itself an ancestor when the key directory is yet to be created.
  let current = existing === target ? dirname(target) : existing;
  for (;;) {
    const problem = ancestorProblem(await lstat(current), uid);
    if (problem !== null) {
      throw new KekStoreError(`a parent of the KEK directory ${problem}: ${current}`);
    }
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

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
    // Every path check happens before a key file is opened, and the keys load from that path.
    await requireSafeKeyPath(directory);
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

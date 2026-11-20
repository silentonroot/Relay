import { describe, expect, it } from 'vitest';
import {
  encodeSnapshot,
  filterStorageState,
  MAX_SNAPSHOT_BYTES,
  parseSnapshot,
  sessionExpiry,
  SnapshotOpenError,
  SnapshotTooLargeError,
} from '../../src/session-store/index.js';
import type { StorageState } from '../../src/types.js';
import { APP_ORIGIN, CDN_ORIGIN, cookie, OTHER_ORIGIN, stateWith } from '../supervisor/helpers.js';

const CANARY = 'canary-cookie-value-7f3a9c';

/*
 * The store no longer seals or opens anything (ADR-014): it validates and serializes a state for
 * the vault and parses what the vault returns. Sealing is tested in services/vault.
 */
describe('session store: encode and parse', () => {
  it('round-trips a state through the base64url form the vault carries', () => {
    const state = stateWith(CANARY);
    const encoded = encodeSnapshot(state);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    const opened = parseSnapshot(encoded, { version: 3, kekVersion: 2 });
    expect(opened.storageState).toEqual(state);
    expect(opened.version).toBe(3);
    expect(opened.kekVersion).toBe(2);
    opened.dispose();
    expect(opened.storageState.cookies).toHaveLength(0);
    expect(opened.storageState.origins).toHaveLength(0);
    opened.dispose();
  });

  it('refuses a state over the size cap before anything is sent', () => {
    const big: StorageState = {
      cookies: [],
      origins: Array.from({ length: 10 }, (_, index) => ({
        origin: `https://o${index}.example.test`,
        localStorage: [{ name: 'blob', value: 'x'.repeat(250_000) }],
      })),
    };
    expect(() => encodeSnapshot(big)).toThrow(SnapshotTooLargeError);
    expect(MAX_SNAPSHOT_BYTES).toBe(2 * 1024 * 1024);
  });

  it('rejects an invalid storage state on both sides', () => {
    const invalid = { cookies: [{ name: 'x' }], origins: [] } as unknown as StorageState;
    expect(() => encodeSnapshot(invalid)).toThrow(SnapshotOpenError);
    const meta = { version: 1, kekVersion: 1 };
    const b64 = (value: string) => Buffer.from(value, 'utf8').toString('base64url');
    expect(() => parseSnapshot(b64('not json'), meta)).toThrow(SnapshotOpenError);
    expect(() => parseSnapshot(b64('{"cookies":[{"name":"x"}],"origins":[]}'), meta)).toThrow(
      SnapshotOpenError,
    );
    expect(() => parseSnapshot(b64('{"cookies":[],"origins":[],"extra":1}'), meta)).toThrow(
      SnapshotOpenError,
    );
    const error = (() => {
      try {
        parseSnapshot(b64(`{"cookies":[{"name":"${CANARY}"}],"origins":[]}`), meta);
      } catch (e) {
        return e as Error;
      }
      return null;
    })();
    expect(error?.message ?? '').not.toContain(CANARY);
    expect(error).not.toHaveProperty('cause');
  });
});

describe('filterStorageState', () => {
  it('keeps cookies whose domain is an allowed host and origin storage that is exactly allowed', () => {
    const state: StorageState = {
      cookies: [
        cookie('a', '1', 'app.example.test'),
        cookie('b', '2', '.app.example.test'),
        cookie('c', '3', 'cdn.example.test'),
        cookie('d', '4', 'example.test'),
        cookie('e', '5', '.example.test'),
        cookie('f', '6', 'tracker.other.test'),
        cookie('g', '7', 'evil-app.example.test'),
        cookie('h', '8', '..app.example.test'),
        cookie('i', '9', 'APP.example.test'),
      ],
      origins: [
        { origin: APP_ORIGIN, localStorage: [{ name: 'k', value: 'v' }] },
        { origin: OTHER_ORIGIN, localStorage: [{ name: 'k', value: 'v' }] },
        { origin: 'http://app.example.test', localStorage: [] },
        { origin: `${APP_ORIGIN}:8443`, localStorage: [] },
      ],
    };
    const filtered = filterStorageState(state, [APP_ORIGIN, CDN_ORIGIN]);
    expect(filtered.cookies.map((c) => c.name)).toEqual(['a', 'b', 'c', 'i']);
    expect(filtered.origins.map((o) => o.origin)).toEqual([APP_ORIGIN]);
    // The input is not modified.
    expect(state.cookies).toHaveLength(9);
  });

  it('returns an empty state for no allowed origins', () => {
    expect(filterStorageState(stateWith('x'), [])).toEqual({ cookies: [], origins: [] });
  });
});

describe('sessionExpiry', () => {
  it('returns the earliest positive expiry', () => {
    const state: StorageState = {
      cookies: [
        cookie('a', '1', 'app.example.test', -1),
        cookie('b', '1', 'app.example.test', 2_000_000_000),
        cookie('c', '1', 'app.example.test', 1_900_000_000.5),
        cookie('d', '1', 'app.example.test', 0),
      ],
      origins: [],
    };
    expect(sessionExpiry(state)).toEqual(new Date(1_900_000_000_500));
  });

  it('ignores expiries within the margin of now (L6)', () => {
    const now = new Date(1_800_000_000_000);
    const at = (seconds: number) => cookie('c', '1', 'app.example.test', 1_800_000_000 + seconds);
    // 60 s away: ignored; 10 minutes away: counts.
    expect(sessionExpiry({ cookies: [at(60)], origins: [] }, now)).toBeNull();
    expect(sessionExpiry({ cookies: [at(60), at(600), at(900)], origins: [] }, now)).toEqual(
      new Date(1_800_000_600_000),
    );
    // Already past: ignored too.
    expect(sessionExpiry({ cookies: [at(-100), at(900)], origins: [] }, now)).toEqual(
      new Date(1_800_000_900_000),
    );
  });

  it('returns null for session cookies only', () => {
    expect(
      sessionExpiry({ cookies: [cookie('a', '1', 'app.example.test', -1)], origins: [] }),
    ).toBeNull();
    expect(sessionExpiry({ cookies: [], origins: [] })).toBeNull();
  });
});

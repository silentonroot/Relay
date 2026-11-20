import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/*
 * Key handling is the vault's alone (ADR-014, P3-1, P3-20): no module of the API seals, opens or
 * rewraps a secret or loads a KEK. The API does use @aab/crypto for password hashing, session
 * tokens and constant-time comparison, so the package itself is allowed; the key-handling names
 * are not, and every name taken from the package must be on the list below. The worker half of
 * this check is services/browser-worker/test/session-store/import-boundary.test.ts.
 */

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

/** What the API may take from @aab/crypto: hashing and token helpers, never key handling. */
const ALLOWED_CRYPTO_NAMES = new Set([
  'constantTimeEqual',
  'generateToken',
  'hashPassword',
  'hashToken',
  'needsRehash',
  'verifyPassword',
  'MAX_PASSWORD_BYTES',
  'ScryptParams',
  'HashPasswordOptions',
]);

const FORBIDDEN_NAMES =
  /\b(?:sealSecret|openSecret|rewrapSecret|KekProvider|KeyringKekProvider|LocalFileKekProvider|InMemoryKekProvider|loadLocalKek|generateLocalKek|deriveKeyFor)\b/;

function sourceFiles(directory: string): string[] {
  const files: string[] = [];
  for (const name of readdirSync(directory)) {
    const full = path.join(directory, name);
    if (statSync(full).isDirectory()) files.push(...sourceFiles(full));
    else if (/\.(?:ts|js|mts|cts)$/.test(name)) files.push(full);
  }
  return files;
}

/** Removes block and line comments, so prose that mentions a name is not a use of it. */
function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** True when `text` imports, re-exports or requires `pkg` (or a sub-path of it) in any form. */
function importsPackage(text: string, pkg: string): boolean {
  const escaped = pkg.replace(/[/.]/g, '\\$&');
  const specifier = `['"\`]${escaped}(?:/[^'"\`]*)?['"\`]`;
  return new RegExp(
    `(?:from\\s*${specifier}|import\\s*\\(?\\s*${specifier}|require\\s*\\(\\s*${specifier})`,
  ).test(text);
}

/** The names named in `import { a, type B as C } from '@aab/crypto'` (the imported side). */
function cryptoNamedImports(text: string): string[] {
  const names: string[] = [];
  const pattern =
    /(?:import|export)\s+(?:type\s+)?\{([^}]*)\}\s*from\s*['"`]@aab\/crypto(?:\/[^'"`]*)?['"`]/g;
  for (const match of text.matchAll(pattern)) {
    for (const part of (match[1] ?? '').split(',')) {
      const name = part
        .trim()
        .replace(/^type\s+/, '')
        .split(/\s+as\s+/)[0]
        ?.trim();
      if (name) names.push(name);
    }
  }
  return names;
}

const files = sourceFiles(SRC).map((file) => ({
  rel: path.relative(SRC, file).split(path.sep).join('/'),
  text: stripComments(readFileSync(file, 'utf8')),
}));

describe('import boundary of the API (P3-20)', () => {
  it('finds the source tree', () => {
    expect(files.some((file) => file.rel === 'app.ts')).toBe(true);
    expect(files.some((file) => file.rel.startsWith('vault/'))).toBe(true);
  });

  it('the matchers recognize the forms they guard against', () => {
    expect(importsPackage("import { x } from '@aab/crypto';", '@aab/crypto')).toBe(true);
    expect(importsPackage("export * from '@aab/crypto/kek';", '@aab/crypto')).toBe(true);
    expect(importsPackage("await import('@aab/crypto')", '@aab/crypto')).toBe(true);
    expect(importsPackage("import { x } from '@aab/cryptography';", '@aab/crypto')).toBe(false);
    expect(
      cryptoNamedImports("import { a, type B, c as d } from '@aab/crypto';\nimport z from 'y';"),
    ).toEqual(['a', 'B', 'c']);
    expect(cryptoNamedImports("export { sealSecret } from '@aab/crypto/envelope';")).toEqual([
      'sealSecret',
    ]);
    expect(FORBIDDEN_NAMES.test('const f = sealSecret;')).toBe(true);
    expect(FORBIDDEN_NAMES.test('const f = sealSecretary;')).toBe(false);
    expect(stripComments('// sealSecret\n/* openSecret */ const a = 1;')).not.toContain('Secret');
  });

  it('no API module imports sealSecret, openSecret, rewrapSecret or a KEK provider', () => {
    // Nothing may name them, so a local re-implementation, an alias or a re-export fails too.
    const named = files.filter((file) => FORBIDDEN_NAMES.test(file.text)).map((file) => file.rel);
    expect(named).toEqual([]);
    // What the API does take from @aab/crypto is on the allow list (deny by default).
    const unexpected = files.flatMap((file) =>
      cryptoNamedImports(file.text)
        .filter((name) => !ALLOWED_CRYPTO_NAMES.has(name))
        .map((name) => `${file.rel}: ${name}`),
    );
    expect(unexpected).toEqual([]);
    // No namespace or default import hides the names from the check above.
    const namespaced = files
      .filter((file) =>
        /import\s+(?:type\s+)?(?:\*\s+as\s+\w+|\w+)\s*(?:,\s*\{[^}]*\}\s*)?from\s*['"`]@aab\/crypto/.test(
          file.text,
        ),
      )
      .map((file) => file.rel);
    expect(namespaced).toEqual([]);
  });

  it('no API module loads @aab/crypto dynamically or reaches into packages/crypto by a relative path', () => {
    // Dynamic and require forms cannot be checked name by name, so they are refused outright.
    const DYNAMIC = /\b(?:import|require)\s*\(\s*['"`]@aab\/crypto/;
    const RELATIVE = /['"`](?:\.{1,2}\/)+(?:[^'"`]*\/)?(?:packages\/)?crypto\/(?:src|dist)\b/;
    expect(DYNAMIC.test("const c = await import('@aab/crypto');")).toBe(true);
    expect(DYNAMIC.test("const c = require('@aab/crypto/kek');")).toBe(true);
    expect(RELATIVE.test("import { x } from '../../../packages/crypto/src/kek.js';")).toBe(true);
    expect(RELATIVE.test("import { x } from './crypto-helpers.js';")).toBe(false);
    expect(files.filter((file) => DYNAMIC.test(file.text)).map((file) => file.rel)).toEqual([]);
    expect(files.filter((file) => RELATIVE.test(file.text)).map((file) => file.rel)).toEqual([]);
  });

  it('no API module imports the vault service or reads a key file', () => {
    const offenders = files
      .filter(
        (file) =>
          importsPackage(file.text, '@aab/vault') ||
          /\bkek-v|\.key['"`]/.test(file.text) ||
          /\breadFile(?:Sync)?\b[^;]*\bkek\b/i.test(file.text),
      )
      .map((file) => file.rel);
    expect(offenders).toEqual([]);
    const manifest = JSON.parse(readFileSync(path.join(SRC, '..', 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    expect(Object.keys({ ...manifest.dependencies, ...manifest.devDependencies })).not.toContain(
      '@aab/vault',
    );
  });
});

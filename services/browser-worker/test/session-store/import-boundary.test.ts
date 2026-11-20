import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/*
 * Key handling is the vault's alone (ADR-014, P3-1): no module of the worker, the session store
 * included, imports the crypto package or names a seal, open, rewrap or key-provider function.
 * The untrusted half of the worker also never sees the database (ADR-013).
 */

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'src');

function sourceFiles(directory: string): string[] {
  const files: string[] = [];
  for (const name of readdirSync(directory)) {
    const full = path.join(directory, name);
    if (statSync(full).isDirectory()) files.push(...sourceFiles(full));
    else if (/\.(?:ts|js|mts|cts)$/.test(name)) files.push(full);
  }
  return files;
}

/** Static imports, re-exports, dynamic imports and require calls of a package. */
function importsPackage(text: string, pkg: string): boolean {
  const escaped = pkg.replace(/[/.]/g, '\\$&');
  const specifier = `['"\`]${escaped}(?:/[^'"\`]*)?['"\`]`;
  return new RegExp(
    `(?:from\\s*${specifier}|import\\s*\\(?\\s*${specifier}|require\\s*\\(\\s*${specifier})`,
  ).test(text);
}

/** Removes block and line comments, so prose that mentions a name is not a use of it. */
function stripComments(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
}

const files = sourceFiles(SRC).map((file) => ({
  rel: path.relative(SRC, file).split(path.sep).join('/'),
  text: readFileSync(file, 'utf8'),
}));

describe('import boundaries', () => {
  it('finds the source tree', () => {
    expect(files.some((file) => file.rel === 'session-store/index.ts')).toBe(true);
    expect(files.some((file) => file.rel === 'vault/gateway.ts')).toBe(true);
    expect(files.some((file) => file.rel.startsWith('runner/'))).toBe(true);
  });

  it('the matcher recognizes the import forms it guards against', () => {
    expect(importsPackage("import { x } from '@aab/crypto';", '@aab/crypto')).toBe(true);
    expect(importsPackage("export * from '@aab/crypto/kek';", '@aab/crypto')).toBe(true);
    expect(importsPackage("await import('@aab/crypto')", '@aab/crypto')).toBe(true);
    expect(importsPackage("import '@aab/crypto';", '@aab/crypto')).toBe(true);
    expect(importsPackage("import { x } from '@aab/cryptography';", '@aab/crypto')).toBe(false);
    expect(stripComments('// sealSecret\n/* openSecret */ const a = 1;')).not.toContain('Secret');
  });

  it('no worker module imports sealSecret, openSecret, rewrapSecret or a KEK provider', () => {
    const offenders = files
      .filter((file) => importsPackage(file.text, '@aab/crypto'))
      .map((file) => file.rel);
    expect(offenders).toEqual([]);
    // Nothing may name them either, so a local re-implementation or a re-export fails too.
    const names =
      /\b(?:sealSecret|openSecret|rewrapSecret|KekProvider|LocalFileKekProvider|InMemoryKekProvider|loadLocalKek|generateLocalKek)\b/;
    const named = files
      .filter((file) => names.test(stripComments(file.text)))
      .map((file) => file.rel);
    expect(named).toEqual([]);
    // And the package does not depend on it.
    const manifest = JSON.parse(readFileSync(path.join(SRC, '..', 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    expect(Object.keys({ ...manifest.dependencies, ...manifest.devDependencies })).not.toContain(
      '@aab/crypto',
    );
  });

  it('the runner, sandbox and egress code import neither the database nor crypto', () => {
    const offenders = files
      .filter((file) => /^(?:runner|sandbox|egress)\//.test(file.rel))
      .filter(
        (file) =>
          importsPackage(file.text, '@aab/database') || importsPackage(file.text, '@aab/crypto'),
      )
      .map((file) => file.rel);
    expect(offenders).toEqual([]);
  });
});

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/*
 * Key handling stays in the session store (and the key initialization script); the
 * untrusted half of the worker never sees the database or the crypto package (ADR-013).
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

const files = sourceFiles(SRC).map((file) => ({
  rel: path.relative(SRC, file).split(path.sep).join('/'),
  text: readFileSync(file, 'utf8'),
}));

describe('import boundaries', () => {
  it('finds the source tree', () => {
    expect(files.some((file) => file.rel === 'session-store/index.ts')).toBe(true);
    expect(files.some((file) => file.rel.startsWith('runner/'))).toBe(true);
  });

  it('the matcher recognizes the import forms it guards against', () => {
    expect(importsPackage("import { x } from '@aab/crypto';", '@aab/crypto')).toBe(true);
    expect(importsPackage("export * from '@aab/crypto/kek';", '@aab/crypto')).toBe(true);
    expect(importsPackage("await import('@aab/crypto')", '@aab/crypto')).toBe(true);
    expect(importsPackage("import '@aab/crypto';", '@aab/crypto')).toBe(true);
    expect(importsPackage("import { x } from '@aab/cryptography';", '@aab/crypto')).toBe(false);
  });

  it('only the session store and scripts import @aab/crypto', () => {
    const offenders = files
      .filter((file) => !file.rel.startsWith('session-store/') && !file.rel.startsWith('scripts/'))
      .filter((file) => importsPackage(file.text, '@aab/crypto'))
      .map((file) => file.rel);
    expect(offenders).toEqual([]);
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

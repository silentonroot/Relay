import { spawn } from 'node:child_process';
import { join } from 'node:path';

/*
 * The KEK is created by the vault now (ADR-014 section 3): the script moved to
 * `services/vault/src/scripts/init-kek.ts`. This wrapper keeps the old entry point working by
 * running that script with the same arguments and passing its output and exit code through. It
 * imports no key handling code (the worker must not, ADR-014 section 3).
 */

const script = join(
  import.meta.dirname,
  '..',
  '..',
  '..',
  'vault',
  'src',
  'scripts',
  'init-kek.ts',
);
const child = spawn(process.execPath, ['--import', 'tsx', script, ...process.argv.slice(2)], {
  stdio: 'inherit',
  cwd: join(import.meta.dirname, '..', '..', '..', 'vault'),
});
child.once('error', () => {
  console.error(
    'init-kek moved to services/vault (run it from there: pnpm --filter @aab/vault run init-kek)',
  );
  process.exit(1);
});
child.once('exit', (code, signal) => process.exit(code ?? (signal === null ? 1 : 1)));

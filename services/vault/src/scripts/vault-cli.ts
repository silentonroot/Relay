import { isAbsolute } from 'node:path';
import { adminSocketPath, AdminCallError, callVault } from '../admin-client.js';

/*
 * The `vault` admin command (ADR-014 section 8). It talks to the vault's admin socket only and
 * never reads a key file or the database:
 *   AAB_VAULT_SOCKET_DIR=/abs/dir vault status
 *   AAB_VAULT_SOCKET_DIR=/abs/dir vault rewrap [--batch-size N] [--max-batches N]
 *   AAB_VAULT_SOCKET_DIR=/abs/dir vault kek-retirement-check <kekVersion>
 * Output is one JSON object on stdout. Exit 0 on success; `rewrap` calls the vault, each call after
 * the previous one's `nextAfterId`, until the list ends, and exits 3 when rows remain or failed.
 * Exit 1: the vault refused or is unreachable; 2: bad usage.
 */

/** A safety stop for the loop below (500 rows per call by default). */
const MAX_REWRAP_CALLS = 100_000;

function usage(): never {
  console.error(
    'usage: vault <status | rewrap [--batch-size N] [--max-batches N] | kek-retirement-check <version>>\n' +
      '       (AAB_VAULT_SOCKET_DIR must be the absolute socket directory)',
  );
  process.exit(2);
}

function intOption(args: string[], name: string, fallback: number): number {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const raw = args[index + 1];
  if (raw === undefined || !/^[1-9]\d{0,5}$/.test(raw)) usage();
  return Number(raw);
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  const socketDir = process.env['AAB_VAULT_SOCKET_DIR'];
  if (command === undefined || socketDir === undefined || !isAbsolute(socketDir)) usage();
  const socket = adminSocketPath(socketDir);
  try {
    if (command === 'status' && rest.length === 0) {
      console.log(JSON.stringify(await callVault(socket, 'status', {})));
    } else if (command === 'rewrap') {
      const known = ['--batch-size', '--max-batches'];
      if (rest.some((arg, i) => (i % 2 === 0 ? !known.includes(arg) : false))) usage();
      const params = {
        batchSize: Math.min(intOption(rest, '--batch-size', 100), 1_000),
        maxBatches: Math.min(intOption(rest, '--max-batches', 1_000), 10_000),
      };
      // One call does a bounded amount of work and returns `nextAfterId` when it stopped with
      // more candidates behind it. Passing that back moves past rows that cannot be rewrapped (a
      // missing KEK, a failed unwrap), so they never starve the rows after them; the loop ends when
      // the vault reports the end of the list. Each call starts after the previous one, so it ends.
      const total = { rewrapped: 0, skipped: 0, failed: 0, remaining: 0 };
      let afterId: string | undefined;
      for (let call = 0; call < MAX_REWRAP_CALLS; call += 1) {
        const result = await callVault(
          socket,
          'rewrap',
          afterId === undefined ? params : { ...params, afterId },
        );
        total.rewrapped += result.rewrapped;
        total.skipped += result.skipped;
        total.failed += result.failed;
        total.remaining = result.remaining;
        if (result.nextAfterId === undefined || result.nextAfterId === afterId) break;
        afterId = result.nextAfterId;
      }
      console.log(JSON.stringify(total));
      if (total.remaining > 0 || total.failed > 0) process.exit(3);
    } else if (
      command === 'kek-retirement-check' &&
      rest.length === 1 &&
      /^[1-9]\d{0,8}$/.test(rest[0]!)
    ) {
      console.log(
        JSON.stringify(
          await callVault(socket, 'kekRetirementCheck', { kekVersion: Number(rest[0]) }),
        ),
      );
    } else {
      usage();
    }
  } catch (error) {
    console.error(`vault: ${error instanceof AdminCallError ? error.code : 'failed'}`);
    process.exit(1);
  }
}

void main();

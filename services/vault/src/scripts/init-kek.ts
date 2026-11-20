import { readdir } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { generateLocalKek, KekStoreError } from '@aab/crypto';
import { requireSafeKeyPath } from '../keys.js';

/*
 * Creates a local key-encryption key (ADR-003, ADR-014 section 8). Run it as the vault's user:
 *   AAB_KEK_DIR=/abs/path node --import tsx src/scripts/init-kek.ts            # first key, v1
 *   node --import tsx src/scripts/init-kek.ts /abs/path --next                # the next version
 * The directory is created with mode 0700 and each key file with mode 0600. An existing key is
 * never overwritten, and without `--next` an existing key refuses the run. Prints only the path
 * of the new file. The vault never deletes a key file; neither does this script.
 */

const KEY_FILE = /^kek-v([1-9]\d{0,8})\.key$/;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const next = args.includes('--next');
  const positional = args.filter((arg) => arg !== '--next');
  const unknown = args.filter((arg) => arg.startsWith('--') && arg !== '--next');
  const directory = positional[0] ?? process.env['AAB_KEK_DIR'];
  if (
    unknown.length > 0 ||
    positional.length > 1 ||
    directory === undefined ||
    directory.trim() === '' ||
    !isAbsolute(directory)
  ) {
    console.error('usage: init-kek [--next] <absolute key directory>   (or set AAB_KEK_DIR)');
    process.exit(2);
  }
  const existing = (await readdir(directory).catch(() => [] as string[]))
    .map((name) => KEY_FILE.exec(name))
    .filter((match): match is RegExpExecArray => match !== null)
    .map((match) => Number(match[1]));
  if (existing.length > 0 && !next) {
    console.error(`a KEK already exists in ${directory}; refusing to overwrite or add one`);
    process.exit(1);
  }
  if (existing.length === 0 && next) {
    console.error(`no KEK exists in ${directory}; create the first key without --next`);
    process.exit(1);
  }
  try {
    // The vault refuses such a directory at start; do not create a key it would then refuse.
    await requireSafeKeyPath(directory);
    const path = await generateLocalKek(
      directory,
      existing.length === 0 ? 1 : Math.max(...existing) + 1,
    );
    console.log(path);
  } catch (error) {
    console.error(error instanceof KekStoreError ? error.message : 'the KEK could not be created');
    process.exit(1);
  }
}

void main();

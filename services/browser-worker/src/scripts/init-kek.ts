import { readdir } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { generateLocalKek, KekStoreError } from '@aab/crypto';

/*
 * Creates the local key-encryption key (ADR-003):
 *   AAB_KEK_DIR=/abs/path node --import tsx src/scripts/init-kek.ts
 * The directory is created with mode 0700 and `kek-v1.key` with mode 0600. An existing key is
 * never overwritten. Prints only the path of the new file.
 */

async function main(): Promise<void> {
  const directory = process.argv[2] ?? process.env['AAB_KEK_DIR'];
  if (directory === undefined || directory.trim() === '' || !isAbsolute(directory)) {
    console.error('usage: init-kek <absolute key directory>   (or set AAB_KEK_DIR)');
    process.exit(2);
  }
  const existing = await readdir(directory).catch(() => [] as string[]);
  if (existing.some((name) => /^kek-v\d+\.key$/.test(name))) {
    console.error(`a KEK already exists in ${directory}; refusing to overwrite or add one`);
    process.exit(1);
  }
  try {
    const path = await generateLocalKek(directory, 1);
    console.log(path);
  } catch (error) {
    console.error(error instanceof KekStoreError ? error.message : 'the KEK could not be created');
    process.exit(1);
  }
}

void main();

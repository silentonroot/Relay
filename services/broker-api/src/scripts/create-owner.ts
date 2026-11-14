/*
 * Creates the first owner account: `npm run create-owner -- [--email you@example.test]
 * [--organization "Name"]`.
 *
 * On a terminal it prompts for anything not given on the command line and reads the password
 * twice without echo. When stdin is not a terminal (automation), --email is required and the
 * password is the first line of stdin. There is deliberately no environment variable or
 * command-line flag for the password: both end up in shell history and process listings.
 */
import process from 'node:process';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { createDatabase } from '@aab/database';
import { DatabaseUrl } from '../config.js';
import {
  createOwner,
  DEFAULT_ORGANIZATION_NAME,
  MIN_OWNER_PASSWORD_LENGTH,
  OwnerInputError,
  passwordProblem,
} from '../owner.js';

class Cancelled extends Error {}

async function promptVisible(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

/** Reads one line in raw mode, echoing nothing. */
function promptHidden(question: string): Promise<string> {
  const stdin = process.stdin;
  process.stdout.write(question);
  return new Promise((resolve, reject) => {
    let value: string[] = [];
    const finish = (error: Error | null) => {
      stdin.off('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
      process.stdout.write('\n');
      if (error === null) resolve(value.join(''));
      else reject(error);
      value = [];
    };
    const onData = (chunk: string) => {
      for (const char of chunk) {
        if (char === '\r' || char === '\n') return finish(null);
        if (char === '\u0003' || (char === '\u0004' && value.length === 0)) {
          return finish(new Cancelled('cancelled'));
        }
        if (char === '\u007f' || char === '\b') {
          value.pop();
          continue;
        }
        if (char < ' ') continue;
        value.push(char);
      }
    };
    stdin.setEncoding('utf8');
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on('data', onData);
  });
}

async function readFirstLineOfStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : (chunk as Buffer));
  }
  const text = Buffer.concat(chunks).toString('utf8');
  return text.split(/\r?\n/, 1)[0] ?? '';
}

async function main(): Promise<number> {
  const url = DatabaseUrl.safeParse(process.env.DATABASE_URL?.trim() || undefined);
  if (!url.success) {
    console.error(`create-owner: DATABASE_URL ${url.error.issues[0]?.message ?? 'is invalid'}`);
    return 1;
  }

  const { values } = parseArgs({
    options: { email: { type: 'string' }, organization: { type: 'string' } },
    strict: true,
  });
  const interactive = process.stdin.isTTY === true;

  let email = values.email?.trim() ?? '';
  let organizationName = values.organization?.trim() ?? '';
  let password: string;

  if (interactive) {
    if (email === '') email = await promptVisible('Owner email: ');
    if (organizationName === '') {
      organizationName =
        (await promptVisible(`Organization name [${DEFAULT_ORGANIZATION_NAME}]: `)) ||
        DEFAULT_ORGANIZATION_NAME;
    }
    password = await promptHidden(`Password (at least ${MIN_OWNER_PASSWORD_LENGTH} characters): `);
    const problem = passwordProblem(password);
    if (problem !== null) {
      console.error(`create-owner: ${problem}`);
      return 1;
    }
    const confirmation = await promptHidden('Repeat password: ');
    if (confirmation !== password) {
      console.error('create-owner: passwords do not match');
      return 1;
    }
  } else {
    if (email === '') {
      console.error('create-owner: --email is required when stdin is not a terminal');
      return 1;
    }
    password = await readFirstLineOfStdin();
  }

  const database = createDatabase({ connectionString: url.data, maxConnections: 1 });
  try {
    const result = await createOwner(database.db, {
      email,
      password,
      organizationName: organizationName || DEFAULT_ORGANIZATION_NAME,
    });
    console.log(
      `create-owner: created owner ${result.user.email} (user ${result.user.id}) ` +
        `in organization "${result.organization.name}" (${result.organization.id})`,
    );
    return 0;
  } catch (error) {
    if (error instanceof OwnerInputError) {
      console.error(`create-owner: ${error.message}`);
      return 1;
    }
    console.error(
      `create-owner: failed: ${error instanceof Error ? error.message : 'unknown error'}`,
    );
    return 1;
  } finally {
    await database.close();
  }
}

try {
  process.exitCode = await main();
} catch (error) {
  if (error instanceof Cancelled) {
    console.error('create-owner: cancelled');
    process.exitCode = 130;
  } else {
    throw error;
  }
}

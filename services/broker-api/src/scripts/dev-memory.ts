/*
 * Development only: runs the API on an in-memory PGlite database with a throwaway owner, so
 * the dashboard can be tried without PostgreSQL. Everything is lost on exit.
 *
 *   npm run dev:memory
 *
 * The owner's password is random and printed once on this terminal. Never use this mode for
 * anything but synthetic data.
 */
import process from 'node:process';
import { generateToken } from '@aab/crypto';
import { createTestDatabase } from '@aab/database/testing';
import { buildApp } from '../app.js';
import { loadConfig } from '../config.js';
import { createOwner } from '../owner.js';

const config = loadConfig({
  ...process.env,
  // Unused by the in-memory database, but the config schema requires one.
  DATABASE_URL: 'postgres://in-memory.invalid/aab',
  AAB_COOKIE_SECURE: process.env.AAB_COOKIE_SECURE ?? 'false',
});

const database = await createTestDatabase();
const email = 'owner@example.test';
const password = generateToken(18);
await createOwner(database.db, { email, password, organizationName: 'Demo organization' });

const app = await buildApp({ database, config });
const stop = async () => {
  await app.close();
  await database.close();
  process.exit(0);
};
process.once('SIGINT', () => void stop());
process.once('SIGTERM', () => void stop());

await app.listen({ host: config.host, port: config.port });
console.log(`dev-memory: in-memory API on http://${config.host}:${config.port}`);
console.log(`dev-memory: sign in as ${email} with password ${password}`);

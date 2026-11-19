import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { hashToken } from '@aab/crypto';
import { rowsOf } from '../../../packages/database/src/client.js';
import {
  b64url,
  completeParams,
  dumpAllTables,
  execSql,
  ok,
  prepare,
  readParams,
  seedLoginJob,
  seedSealedOperation,
  seedTenant,
  sql,
  startService,
  storageStateJson,
} from './service-helpers.js';
import type { Prepared, Service } from './service-helpers.js';

const READ_CANARY = 'CANARY-READ-SESSION-0b8e41d2';
const LOGIN_CANARY = 'CANARY-LOGIN-SESSION-77c1aa90';

let service: Service;
const tokens: string[] = [];
const hashes: string[] = [];
const macs: string[] = [];
let readResponse = '';

async function collectCapability(prepared: Prepared): Promise<void> {
  tokens.push(prepared.token);
  hashes.push(hashToken(prepared.token));
  const row = rowsOf(
    await service.db.execute(
      sql`select authorization_mac, token_mac from vault_access_capabilities where id = ${prepared.capabilityId}::uuid`,
    ),
  )[0]!;
  macs.push(String(row['authorization_mac']), String(row['token_mac']));
}

beforeAll(async () => {
  service = await startService();
  const tenant = await seedTenant(service.repos, 'scan');

  // A read, a replayed read, a forged one and a login: every kind of call.
  const op = await seedSealedOperation(service, tenant, storageStateJson(READ_CANARY));
  const p1 = await prepare(service, op);
  const read = await service.rpc('supervisor', 'readForWorker', readParams(p1));
  readResponse = JSON.stringify(read);
  ok(read);
  await service.rpc('supervisor', 'readForWorker', readParams(p1)); // used
  await collectCapability(p1);

  const op2 = await seedSealedOperation(service, await seedTenant(service.repos, 'scan2'), 'x');
  const p2 = await prepare(service, op2);
  await execSql(
    service,
    sql`update vault_access_capabilities set token_mac = ${'e'.repeat(64)} where id = ${p2.capabilityId}::uuid`,
  );
  await service.rpc('supervisor', 'readForWorker', readParams(p2)); // forged
  tokens.push(p2.token);
  hashes.push(hashToken(p2.token));
  macs.push('e'.repeat(64));

  const login = await seedLoginJob(service, tenant);
  const p3 = await prepare(service, login);
  ok(
    await service.rpc(
      'supervisor',
      'completeLogin',
      completeParams(p3, storageStateJson(LOGIN_CANARY)),
    ),
  );
  await collectCapability(p3);
  await service.rpc('admin', 'status', {});
  await service.rpc('api', 'status', {});
});
afterAll(async () => {
  await service.cleanup();
});

const plaintexts = () => [
  READ_CANARY,
  LOGIN_CANARY,
  b64url(storageStateJson(READ_CANARY)),
  b64url(storageStateJson(LOGIN_CANARY)),
  Buffer.from(READ_CANARY).toString('base64'),
  Buffer.from(READ_CANARY).toString('hex'),
  Buffer.from(LOGIN_CANARY).toString('hex'),
];

function expectNone(text: string, needles: string[], where: string): void {
  for (const needle of needles) {
    expect(text.includes(needle), `${where} must not contain ${needle.slice(0, 12)}...`).toBe(
      false,
    );
  }
}

describe('P3-15: no plaintext, token or MAC outside the vault’s transient memory', () => {
  it('has real values to look for (positive control)', () => {
    expect(readResponse).toContain(b64url(storageStateJson(READ_CANARY)));
    expect(tokens).toHaveLength(3);
    expect(macs.length).toBeGreaterThan(3);
  });

  it('no log line holds plaintext, a token, a token hash or a MAC', () => {
    expectNone(service.log.text(), [...plaintexts(), ...tokens, ...hashes, ...macs], 'the logs');
  });

  it('no response other than the plaintext read holds plaintext, a token hash or a MAC; the token is only in issue responses', () => {
    const others = service.responses.filter(
      (line) => line !== readResponse && !line.includes('"token"'),
    );
    expect(others.length).toBeGreaterThan(5);
    expectNone(others.join('\n'), [...plaintexts(), ...tokens, ...hashes, ...macs], 'responses');
    // Issue responses carry the token (their purpose) and nothing else of the above.
    const issued = service.responses.filter((line) => line.includes('"token"'));
    expectNone(issued.join('\n'), [...plaintexts(), ...hashes, ...macs], 'issue responses');
  });

  it('no audit record holds plaintext, a token, a token hash or a MAC', async () => {
    const rows = rowsOf(
      await service.db.execute(sql`select row_to_json(a)::text as j from audit_events as a`),
    );
    expect(rows.length).toBeGreaterThan(10);
    expectNone(
      rows.map((row) => String(row['j'])).join('\n'),
      [...plaintexts(), ...tokens, ...hashes, ...macs],
      'audit_events',
    );
  });
});

describe('P3-16: database-only theft yields ciphertext', () => {
  it('a dump of every table holds no plaintext and no raw token', async () => {
    const dump = await dumpAllTables(service);
    expect(dump.size).toBeGreaterThan(10);
    for (const [table, rows] of dump) {
      expectNone(rows.join('\n'), [...plaintexts(), ...tokens], `table ${table}`);
    }
  });

  it('token hashes and MACs live only in the capability table', async () => {
    const dump = await dumpAllTables(service);
    for (const [table, rows] of dump) {
      const text = rows.join('\n');
      if (table === 'vault_access_capabilities') {
        // Sanity: the scan can see them where they belong.
        expect(hashes.some((hash) => text.includes(hash))).toBe(true);
        continue;
      }
      expectNone(text, [...hashes, ...macs], `table ${table}`);
    }
  });

  it('the stored session is ciphertext: the version row is not the plaintext in any encoding', async () => {
    const rows = rowsOf(
      await service.db.execute(
        sql`select encode(ciphertext, 'escape') as e, encode(ciphertext, 'hex') as h from vault_secret_versions`,
      ),
    );
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expectNone(String(row['e']) + String(row['h']), plaintexts(), 'ciphertext columns');
    }
  });
});

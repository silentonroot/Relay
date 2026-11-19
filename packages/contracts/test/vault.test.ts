import { describe, expect, it } from 'vitest';
import {
  AUTHORIZATION_TTL_MAX_SECONDS,
  AuthorizeJobAccessParams,
  CompleteLoginParams,
  ErrorCode,
  HelloParams,
  IssueAccessCapabilityParams,
  isOperationAllowedForRole,
  isVaultOperation,
  KekRetirementCheckParams,
  ReadForWorkerParams,
  RewrapParams,
  StatusParams,
  VAULT_ERROR_CODES,
  VAULT_ERROR_TO_ERROR_CODE,
  VAULT_MAX_PLAINTEXT_CHARS,
  VAULT_OPERATION_ROLES,
  VAULT_OPERATION_SCHEMAS,
  VAULT_OPERATIONS,
  VAULT_ROLES,
  VaultRequestEnvelope,
  VaultResponse,
} from '../src/index.js';

const UUID = '3f1c2b0e-8a54-4a52-9d57-0e1c2d3e4f50';
const TOKEN = 'A'.repeat(43);

describe('vault operation table', () => {
  it('lists every operation once, with at least one allowed role, and only known roles', () => {
    expect(Object.keys(VAULT_OPERATION_ROLES).sort()).toEqual([...VAULT_OPERATIONS].sort());
    expect(Object.keys(VAULT_OPERATION_SCHEMAS).sort()).toEqual([...VAULT_OPERATIONS].sort());
    for (const operation of VAULT_OPERATIONS) {
      const roles = VAULT_OPERATION_ROLES[operation];
      expect(roles.length).toBeGreaterThan(0);
      for (const role of roles) expect(VAULT_ROLES).toContain(role);
    }
  });

  it('matches ADR-014 section 4', () => {
    expect(VAULT_OPERATION_ROLES).toEqual({
      hello: ['api', 'supervisor', 'admin'],
      authorizeJobAccess: ['api'],
      issueAccessCapability: ['supervisor'],
      readForWorker: ['supervisor'],
      completeLogin: ['supervisor'],
      status: ['api', 'admin'],
      rewrap: ['admin'],
      kekRetirementCheck: ['admin'],
    });
    expect(isOperationAllowedForRole('readForWorker', 'api')).toBe(false);
    expect(isOperationAllowedForRole('readForWorker', 'supervisor')).toBe(true);
  });

  it('never lets api or admin read a session', () => {
    for (const operation of ['readForWorker', 'completeLogin', 'issueAccessCapability'] as const) {
      expect(VAULT_OPERATION_ROLES[operation]).toEqual(['supervisor']);
    }
  });

  it('recognises only own operation names (no prototype keys)', () => {
    expect(isVaultOperation('hello')).toBe(true);
    for (const name of ['toString', '__proto__', 'constructor', 'Hello', '', 5, null]) {
      expect(isVaultOperation(name)).toBe(false);
    }
  });
});

describe('vault parameter schemas', () => {
  it('are strict: every one refuses an unknown field, including role', () => {
    const valid = [
      [HelloParams, { protocolVersion: 1 }],
      [AuthorizeJobAccessParams, { jobId: UUID, ttlSeconds: 600 }],
      [
        IssueAccessCapabilityParams,
        { capabilityId: UUID, jobId: UUID, workerId: 'w1', attempt: 1, ttlSeconds: 30 },
      ],
      [
        ReadForWorkerParams,
        { token: TOKEN, jobId: UUID, connectionId: UUID, operation: 'orders.list' },
      ],
      [
        CompleteLoginParams,
        {
          token: TOKEN,
          jobId: UUID,
          connectionId: UUID,
          plaintext: 'e30',
          externalAccountHint: null,
          sessionExpiresAt: null,
        },
      ],
      [StatusParams, {}],
      [RewrapParams, { batchSize: 10, maxBatches: 2 }],
      [KekRetirementCheckParams, { kekVersion: 1 }],
    ] as const;
    for (const [schema, params] of valid) {
      expect(schema.safeParse(params).success).toBe(true);
      expect(schema.safeParse({ ...params, role: 'admin' }).success).toBe(false);
      expect(schema.safeParse({ ...params, extra: 1 }).success).toBe(false);
    }
  });

  it('bounds lifetimes: safe integers inside 10..3600 and 1..120 only', () => {
    for (const ttlSeconds of [
      undefined,
      0,
      9,
      3601,
      10.5,
      Number.NaN,
      Infinity,
      '600',
      null,
      Number.MAX_SAFE_INTEGER + 2,
    ]) {
      expect(AuthorizeJobAccessParams.safeParse({ jobId: UUID, ttlSeconds }).success).toBe(false);
    }
    expect(AuthorizeJobAccessParams.safeParse({ jobId: UUID, ttlSeconds: 10 }).success).toBe(true);
    expect(
      AuthorizeJobAccessParams.safeParse({ jobId: UUID, ttlSeconds: AUTHORIZATION_TTL_MAX_SECONDS })
        .success,
    ).toBe(true);
    const base = { capabilityId: UUID, jobId: UUID, workerId: 'w', attempt: 1 };
    for (const ttlSeconds of [undefined, 0, 121, 1.5, -1]) {
      expect(IssueAccessCapabilityParams.safeParse({ ...base, ttlSeconds }).success).toBe(false);
    }
    expect(IssueAccessCapabilityParams.safeParse({ ...base, ttlSeconds: 1 }).success).toBe(true);
    expect(IssueAccessCapabilityParams.safeParse({ ...base, ttlSeconds: 120 }).success).toBe(true);
  });

  it('caps and shapes the plaintext and the token', () => {
    const base = {
      token: TOKEN,
      jobId: UUID,
      connectionId: UUID,
      externalAccountHint: null,
      sessionExpiresAt: null,
    };
    const ok = (plaintext: string) => CompleteLoginParams.safeParse({ ...base, plaintext }).success;
    expect(ok('A'.repeat(VAULT_MAX_PLAINTEXT_CHARS))).toBe(true);
    expect(ok('A'.repeat(VAULT_MAX_PLAINTEXT_CHARS + 1))).toBe(false);
    expect(ok('')).toBe(false);
    expect(ok('e30=')).toBe(false);
    expect(ok('a b')).toBe(false);
    expect(
      CompleteLoginParams.safeParse({ ...base, token: 'short', plaintext: 'e30' }).success,
    ).toBe(false);
  });

  it('rejects a hello for another protocol version', () => {
    expect(HelloParams.safeParse({ protocolVersion: 2 }).success).toBe(false);
  });
});

describe('vault envelopes', () => {
  it('requires id, operation and params and refuses anything else, including role', () => {
    const ok = { id: 'r1', operation: 'hello', params: { protocolVersion: 1 } };
    expect(VaultRequestEnvelope.safeParse(ok).success).toBe(true);
    expect(VaultRequestEnvelope.safeParse({ ...ok, role: 'admin' }).success).toBe(false);
    expect(VaultRequestEnvelope.safeParse({ id: 'r1', operation: 'hello' }).success).toBe(false);
    expect(VaultRequestEnvelope.safeParse({ ...ok, params: [] }).success).toBe(false);
    expect(VaultRequestEnvelope.safeParse({ ...ok, id: 'has space' }).success).toBe(false);
    expect(VaultRequestEnvelope.safeParse({ ...ok, id: 'x'.repeat(65) }).success).toBe(false);
  });

  it('accepts a success and an error response and nothing with extra fields', () => {
    expect(VaultResponse.safeParse({ id: 'a', ok: true, result: {} }).success).toBe(true);
    expect(
      VaultResponse.safeParse({ id: null, ok: false, error: { code: 'malformed' } }).success,
    ).toBe(true);
    expect(
      VaultResponse.safeParse({ id: 'a', ok: false, error: { code: 'malformed', message: 'x' } })
        .success,
    ).toBe(false);
    expect(VaultResponse.safeParse({ id: 'a', ok: false, error: { code: 'nope' } }).success).toBe(
      false,
    );
  });

  it('maps every vault error code onto the existing error contract', () => {
    for (const code of VAULT_ERROR_CODES) {
      expect(ErrorCode.safeParse(VAULT_ERROR_TO_ERROR_CODE[code]).success).toBe(true);
    }
    expect(VAULT_ERROR_TO_ERROR_CODE.malformed).toBe('validation_failed');
    expect(VAULT_ERROR_TO_ERROR_CODE.not_implemented).toBe('service_unavailable');
  });
});

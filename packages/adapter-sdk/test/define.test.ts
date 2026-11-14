import { OperationDescriptor } from '@aab/contracts';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  AdapterContractError,
  AdapterRegistry,
  defineAdapter,
  defineOperation,
  isDefinedAdapter,
  toOperationDescriptors,
} from '../src/index.js';
import type { ApplicationAdapter, OperationDefinition } from '../src/index.js';
import { adapterDefinition, helpdesk, readOperation, writeOperation } from './fixtures.js';

describe('defineOperation', () => {
  it('accepts a valid read and a valid write', () => {
    expect(defineOperation(readOperation()).name).toBe('tickets.list');
    expect(defineOperation(writeOperation()).name).toBe('tickets.close');
  });

  it.each<[string, Partial<OperationDefinition>, RegExp]>([
    ['a name that is not dotted', { name: 'tickets' }, /dotted name/],
    ['a wildcard name', { name: 'tickets.*' }, /dotted name/],
    ['an empty description', { description: '  ' }, /description/],
    ['a timeout below one second', { timeoutMs: 999 }, /timeout/],
    ['a timeout above two minutes', { timeoutMs: 120_001 }, /timeout/],
    ['a fractional timeout', { timeoutMs: 1500.5 }, /timeout/],
    ['an unknown sensitivity', { sensitivity: 'admin' as never }, /sensitivity/],
    ['no allowed paths', { allowedPaths: [] }, /at least one allowed path/],
    ['an allowed path given as a regular expression', { allowedPaths: ['/tickets/.*'] }, /pattern/],
    [
      'an allowed path with a traversal segment',
      { allowedPaths: ['/tickets/../admin'] },
      /pattern/,
    ],
    ['an allowed path that is a full URL', { allowedPaths: ['https://evil.test/'] }, /pattern/],
    [
      'a limitArgument missing from the input schema',
      { limitArgument: 'pageSize' },
      /limitArgument/,
    ],
    [
      'a resourceArgument missing from the input schema',
      { resourceArgument: 'ticketId' },
      /resourceArgument/,
    ],
    ['a read that lists side effects', { sideEffects: ['Deletes things.'] }, /read/],
    ['an input that is not an object schema', { input: z.string() as never }, /object schemas/],
    [
      'an output schema that passes unknown fields through',
      { output: z.looseObject({ tickets: z.array(z.string()) }) },
      /undeclared fields/,
    ],
    [
      'a nested output object that passes unknown fields through',
      { output: z.object({ tickets: z.array(z.object({ id: z.string() }).loose()) }) },
      /output\.tickets\[\]/,
    ],
  ])('rejects a read operation with %s', (_label, overrides, message) => {
    expect(() => defineOperation(readOperation(overrides))).toThrow(AdapterContractError);
    expect(() => defineOperation(readOperation(overrides))).toThrow(message);
  });

  it.each<[string, Partial<OperationDefinition>, RegExp]>([
    [
      'a write declared idempotent without side effects listed',
      { idempotent: true, sideEffects: [] },
      /idempotent but lists no side effects/,
    ],
    ['a non-idempotent write without side effects listed', { sideEffects: [] }, /side effects/],
    [
      'a destructive operation that does not require approval',
      { sensitivity: 'destructive', requiresApproval: false },
      /destructive and must require approval/,
    ],
  ])('rejects %s', (_label, overrides, message) => {
    expect(() => defineOperation(writeOperation(overrides))).toThrow(AdapterContractError);
    expect(() => defineOperation(writeOperation(overrides))).toThrow(message);
  });

  it('returns a frozen definition', () => {
    const operation = defineOperation(readOperation());
    expect(Object.isFrozen(operation)).toBe(true);
    expect(Object.isFrozen(operation.allowedPaths)).toBe(true);
    expect(() => (operation.allowedPaths as string[]).push('/admin')).toThrow(TypeError);
  });
});

describe('defineAdapter', () => {
  it.each<[string, Partial<ApplicationAdapter>, RegExp]>([
    ['an id with uppercase letters', { id: 'HelpDesk' }, /id/],
    ['a version that is not semantic', { version: 'latest' }, /semantic version/],
    ['an empty display name', { displayName: '' }, /display name/],
    ['an unknown auth mode', { authMode: 'password' as never }, /authMode/],
    ['no allowed origins', { allowedOrigins: [] }, /at least one allowed origin/],
    ['a plain-http remote origin', { allowedOrigins: ['http://app.example.test'] }, /origin/],
    ['a wildcard origin', { allowedOrigins: ['https://*.example.test'] }, /origin/],
    ['an origin with a path', { allowedOrigins: ['https://app.example.test/app'] }, /origin/],
    [
      'a repeated origin',
      { allowedOrigins: ['https://app.example.test', 'https://app.example.test'] },
      /twice/,
    ],
    ['no operations', { operations: {} }, /at least one operation/],
    [
      'an operation registered under a key different from its name',
      { operations: { 'tickets.search': readOperation() } },
      /different key/,
    ],
    [
      'an operation that is itself invalid',
      { operations: { 'tickets.list': readOperation({ timeoutMs: 5 }) } },
      /timeout/,
    ],
  ])('rejects an adapter with %s', (_label, overrides, message) => {
    expect(() => defineAdapter(adapterDefinition(overrides))).toThrow(AdapterContractError);
    expect(() => defineAdapter(adapterDefinition(overrides))).toThrow(message);
  });

  it('returns a deeply frozen adapter', () => {
    expect(Object.isFrozen(helpdesk)).toBe(true);
    expect(Object.isFrozen(helpdesk.operations)).toBe(true);
    expect(Object.isFrozen(helpdesk.allowedOrigins)).toBe(true);
    expect(Object.isFrozen(helpdesk.operations['tickets.list'])).toBe(true);
    expect(() => (helpdesk.allowedOrigins as string[]).push('https://evil.test')).toThrow(
      TypeError,
    );
  });

  it('does not let later changes to the source definition leak in', () => {
    const origins = ['https://app.example.test'];
    const adapter = defineAdapter(adapterDefinition({ allowedOrigins: origins }));
    origins.push('https://evil.test');
    expect(adapter.allowedOrigins).toEqual(['https://app.example.test']);
  });

  it('accepts a loopback http origin for local demo applications', () => {
    const adapter = defineAdapter(adapterDefinition({ allowedOrigins: ['http://localhost:4100'] }));
    expect(adapter.allowedOrigins).toEqual(['http://localhost:4100']);
  });
});

describe('toOperationDescriptors', () => {
  it('produces contract descriptors for the policy engine', () => {
    const descriptors = toOperationDescriptors(helpdesk);
    expect(descriptors).toEqual([
      {
        name: 'tickets.list',
        sensitivity: 'read',
        requiresApproval: false,
        limitArgument: 'limit',
      },
      {
        name: 'tickets.close',
        sensitivity: 'write',
        requiresApproval: true,
        resourceArgument: 'ticketId',
      },
    ]);
    for (const descriptor of descriptors) {
      expect(OperationDescriptor.safeParse(descriptor).success).toBe(true);
    }
  });
});

describe('AdapterRegistry', () => {
  it('registers, finds and lists adapters by id and version', () => {
    const registry = new AdapterRegistry();
    const next = defineAdapter(adapterDefinition({ version: '1.1.0' }));
    registry.register(helpdesk);
    registry.register(next);

    expect(registry.get('helpdesk', '1.0.0')).toBe(helpdesk);
    expect(registry.get('helpdesk', '1.1.0')).toBe(next);
    expect(registry.get('helpdesk', '2.0.0')).toBeUndefined();
    expect(registry.get('other', '1.0.0')).toBeUndefined();
    expect(registry.list()).toEqual([helpdesk, next]);
  });

  it('rejects a duplicate id and version', () => {
    const registry = new AdapterRegistry();
    registry.register(helpdesk);
    expect(() => registry.register(defineAdapter(adapterDefinition()))).toThrow(
      /already registered/,
    );
  });

  it('rejects an adapter that did not go through defineAdapter', () => {
    const raw = adapterDefinition();
    expect(isDefinedAdapter(raw)).toBe(false);
    expect(isDefinedAdapter(helpdesk)).toBe(true);
    expect(() => new AdapterRegistry().register(raw)).toThrow(AdapterContractError);
  });
});

describe('operation schema allowlist (F-1, F-3)', () => {
  /** Stands in for a schema kind a future Zod version might add. */
  const futureKind = { def: { type: 'future_kind' } } as unknown as z.ZodString;

  it.each<[string, z.ZodType]>([
    ['record', z.record(z.string(), z.string())],
    ['unknown', z.unknown()],
    ['any', z.any()],
    ['lazy', z.json()],
    ['pipe', z.object({ id: z.string() }).transform((value) => value)],
    ['pipe', z.string().pipe(z.string())],
    ['lazy', z.lazy(() => z.object({ id: z.string() }))],
    ['intersection', z.intersection(z.object({ id: z.string() }), z.object({ n: z.number() }))],
    ['default', z.string().default('x')],
    ['catch', z.string().catch('x')],
    ['custom check', z.string().refine(() => true)],
    ['overwrite check', z.string().trim()],
    ['future_kind', futureKind],
  ])('rejects an output schema containing a %s node and names its path', (kind, node) => {
    const output = z.object({ order: z.object({ id: z.string(), meta: node }) });
    const define = () => defineOperation(readOperation({ output }));
    expect(define).toThrow(AdapterContractError);
    expect(define).toThrow(`disallowed node at output.order.meta: ${kind}`);
  });

  it('rejects a disallowed node inside a union, tuple or nullable', () => {
    for (const node of [
      z.union([z.string(), z.record(z.string(), z.string())]),
      z.tuple([z.string(), z.any()]),
      z.tuple([z.string()], z.unknown()),
      z.array(z.unknown()).nullable(),
    ]) {
      expect(() => defineOperation(readOperation({ output: z.object({ meta: node }) }))).toThrow(
        /disallowed node at output\.meta/,
      );
    }
  });

  it('accepts output schemas built only from allowlisted kinds', () => {
    const output = z.object({
      id: z
        .string()
        .min(1)
        .max(32)
        .regex(/^T-\d+$/),
      count: z.number().int().nonnegative(),
      flag: z.boolean(),
      nothing: z.null(),
      kind: z.literal('ticket'),
      status: z.enum(['open', 'closed']),
      note: z.string().optional(),
      closedAt: z.string().nullable(),
      pair: z.tuple([z.string(), z.number()]),
      tags: z.array(z.string()).max(10),
      owner: z.strictObject({ name: z.string() }),
      either: z.discriminatedUnion('type', [
        z.object({ type: z.literal('a'), a: z.string() }),
        z.object({ type: z.literal('b'), b: z.number() }),
      ]),
    });
    expect(() => defineOperation(readOperation({ output }))).not.toThrow();
  });

  it.each<[string, z.ZodType, RegExp]>([
    ['a trimming string', z.string().trim(), /input\.status: overwrite check/],
    ['a lowercasing string', z.string().toLowerCase(), /input\.status: overwrite check/],
    ['a default', z.enum(['open', 'closed']).default('open'), /input\.status: default/],
    ['a coerced number', z.coerce.number(), /input\.status: coerced number/],
    ['a transform', z.string().transform((value) => value), /input\.status: pipe/],
    ['a preprocess', z.preprocess((value) => value, z.string()), /input\.status: pipe/],
    ['a loose nested object', z.looseObject({ a: z.string() }), /passes undeclared fields/],
  ])('rejects an input schema with %s', (_label, node, message) => {
    const input = z.object({ status: node });
    const define = () => defineOperation(readOperation({ input, limitArgument: undefined }));
    expect(define).toThrow(AdapterContractError);
    expect(define).toThrow(message);
  });
});

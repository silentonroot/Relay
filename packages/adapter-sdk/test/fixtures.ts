import { z } from 'zod';
import { defineAdapter, defineOperation } from '../src/index.js';
import type { ApplicationAdapter, OperationDefinition } from '../src/index.js';

/** A valid read operation; tests override single fields to break one rule at a time. */
export function readOperation(overrides: Partial<OperationDefinition> = {}): OperationDefinition {
  return {
    name: 'tickets.list',
    description: 'Lists synthetic tickets.',
    input: z.object({
      status: z.enum(['open', 'closed']).optional(),
      limit: z.number().int().min(1).max(50).optional(),
    }),
    output: z.object({
      tickets: z.array(z.object({ id: z.string(), title: z.string() })),
    }),
    sensitivity: 'read',
    requiresApproval: false,
    idempotent: true,
    sideEffects: [],
    timeoutMs: 10_000,
    allowedPaths: ['/tickets'],
    limitArgument: 'limit',
    ...overrides,
  };
}

export function writeOperation(overrides: Partial<OperationDefinition> = {}): OperationDefinition {
  return {
    name: 'tickets.close',
    description: 'Closes one synthetic ticket.',
    input: z.object({ ticketId: z.string().regex(/^T-\d+$/) }),
    output: z.object({ id: z.string(), status: z.literal('closed') }),
    sensitivity: 'write',
    requiresApproval: true,
    idempotent: false,
    sideEffects: ['Sets the ticket status to closed.'],
    timeoutMs: 20_000,
    allowedPaths: ['/tickets/:ticketId', '/tickets/:ticketId/close'],
    resourceArgument: 'ticketId',
    ...overrides,
  };
}

export function adapterDefinition(overrides: Partial<ApplicationAdapter> = {}): ApplicationAdapter {
  return {
    id: 'helpdesk',
    version: '1.0.0',
    displayName: 'Synthetic Helpdesk',
    allowedOrigins: ['https://app.example.test'],
    authMode: 'browser_session',
    operations: {
      'tickets.list': readOperation(),
      'tickets.close': writeOperation(),
    },
    ...overrides,
  };
}

export const helpdesk = defineAdapter({
  ...adapterDefinition(),
  operations: {
    'tickets.list': defineOperation(readOperation()),
    'tickets.close': defineOperation(writeOperation()),
  },
});

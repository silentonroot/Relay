import { describe, expect, it } from 'vitest';
import {
  ActionHash,
  ApprovalDecision,
  ApprovalDetail,
  ApprovalRefusalReason,
  ApprovalRequest,
  ApprovalRequiredResponse,
  ApprovalStatus,
  ApproveApprovalRequest,
  AuditEventType,
  DenyApprovalRequest,
  JobArgumentsHashLayout,
  JobErrorCode,
  OperationDescriptor,
} from '../src/index.js';

const UUID = '3f1c2b0e-8a54-4a52-9d57-0e1c2d3e4f50';
const HASH = 'ab'.repeat(32);
const NOW = '2026-11-26T10:00:00.000Z';

describe('approval decide bodies (P4-7)', () => {
  it.each([
    ['approve', ApproveApprovalRequest],
    ['deny', DenyApprovalRequest],
  ] as const)('%s accepts only the presented action hash (positive control)', (_name, schema) => {
    expect(schema.safeParse({ actionHash: HASH }).success).toBe(true);
  });

  it.each([
    ['approve', ApproveApprovalRequest],
    ['deny', DenyApprovalRequest],
  ] as const)('%s rejects approver and agent fields and any unknown field', (_name, schema) => {
    for (const extra of [
      { approverUserId: UUID },
      { agentId: UUID },
      { userId: UUID },
      { ownerUserId: UUID },
      { status: 'approved' },
      { extra: 1 },
    ]) {
      expect(schema.safeParse({ actionHash: HASH, ...extra }).success).toBe(false);
    }
    expect(schema.safeParse({}).success).toBe(false);
    expect(schema.safeParse({ actionHash: HASH.toUpperCase() }).success).toBe(false);
    expect(schema.safeParse({ actionHash: HASH.slice(1) }).success).toBe(false);
  });

  it('ActionHash is 64 lowercase hex digits', () => {
    expect(ActionHash.safeParse(HASH).success).toBe(true);
    expect(ActionHash.safeParse('g'.repeat(64)).success).toBe(false);
  });
});

const view = () => ({
  id: UUID,
  status: 'pending',
  agentId: UUID,
  connectionId: UUID,
  operation: 'orders.applyApprovedUpdate',
  runId: null,
  targetResourceId: 'ORD-1001',
  expectedResourceVersion: 3,
  proposal: { orderId: 'ORD-1001', expectedVersion: 3, changes: { status: 'held' } },
  before: null,
  policyDecisionId: UUID,
  approverUserId: null,
  decidedAt: null,
  expiresAt: NOW,
  consumedAt: null,
  consumedByJobId: null,
  createdAt: NOW,
});

describe('ApprovalRequest view (P4-14)', () => {
  it('parses a pending approval (positive control)', () => {
    expect(ApprovalRequest.safeParse(view()).success).toBe(true);
  });

  it('has no mac, mac key version or action hash in its shape', () => {
    const keys = Object.keys(ApprovalRequest.shape);
    for (const forbidden of [
      'mac',
      'macKekVersion',
      'mac_kek_version',
      'actionHash',
      'action_hash',
    ]) {
      expect(keys).not.toContain(forbidden);
    }
    expect(keys.some((key) => /mac|hash/i.test(key))).toBe(false);
  });

  it('drops a mac or an action hash that a caller tries to pass through', () => {
    const parsed = ApprovalRequest.parse({ ...view(), mac: 'x', actionHash: HASH });
    expect(Object.keys(parsed)).not.toContain('mac');
    expect(Object.keys(parsed)).not.toContain('actionHash');
  });

  it('only the owner detail adds the action hash, and never a mac', () => {
    expect(Object.keys(ApprovalDetail.shape)).toContain('actionHash');
    expect(Object.keys(ApprovalDetail.shape).some((key) => /mac/i.test(key))).toBe(false);
    expect(ApprovalDetail.safeParse({ ...view(), actionHash: HASH }).success).toBe(true);
    expect(ApprovalDetail.safeParse(view()).success).toBe(false);
  });

  it('knows exactly the six statuses', () => {
    expect(ApprovalStatus.options).toEqual([
      'pending',
      'approved',
      'denied',
      'expired',
      'revoked',
      'consumed',
    ]);
    expect(ApprovalRequest.safeParse({ ...view(), status: 'allowed' }).success).toBe(false);
  });
});

describe('ApprovalDecision and the approval_required response', () => {
  it('parses a decision and rejects an unknown kind', () => {
    const decision = {
      id: UUID,
      approvalRequestId: UUID,
      userId: UUID,
      decision: 'approved',
      decidedAt: NOW,
    };
    expect(ApprovalDecision.safeParse(decision).success).toBe(true);
    expect(ApprovalDecision.safeParse({ ...decision, decision: 'consumed' }).success).toBe(false);
  });

  it('is the 202 body of decision D11 and nothing more', () => {
    const body = { status: 'approval_required', approvalId: UUID, expiresAt: NOW };
    expect(ApprovalRequiredResponse.safeParse(body).success).toBe(true);
    expect(ApprovalRequiredResponse.safeParse({ ...body, actionHash: HASH }).success).toBe(false);
    expect(ApprovalRequiredResponse.safeParse({ ...body, status: 'denied' }).success).toBe(false);
    expect(ApprovalRequiredResponse.safeParse({ status: 'approval_required' }).success).toBe(false);
  });
});

describe('closed lists that Phase 4 extends', () => {
  it('lists the approval refusal reasons and the input-check codes', () => {
    for (const reason of [
      'not_found',
      'not_approved',
      'expired',
      'consumed',
      'revoked',
      'binding_mismatch',
      'unsafe_integer',
      'negative_zero',
      'lone_surrogate',
      'non_finite_number',
      'duplicate_key',
      'invalid_json',
    ]) {
      expect(ApprovalRefusalReason.safeParse(reason).success).toBe(true);
    }
    expect(ApprovalRefusalReason.safeParse('allowed').success).toBe(false);
  });

  it('lists the approval audit events, the dispatch event and the vault approval events', () => {
    for (const type of [
      'approval.proposed',
      'approval.approved',
      'approval.denied',
      'approval.expired',
      'approval.revoked',
      'approval.redeemed',
      'approval.refused',
      'operation.write_dispatched',
      'vault.approval_sealed',
      'vault.approval_rejected',
      'policy.evaluated',
    ]) {
      expect(AuditEventType.safeParse(type).success).toBe(true);
    }
    expect(AuditEventType.safeParse('approval.invented').success).toBe(false);
  });

  it('has the stale_version job error code and the two hash layouts', () => {
    expect(JobErrorCode.safeParse('stale_version').success).toBe(true);
    expect(JobArgumentsHashLayout.safeParse(1).success).toBe(true);
    expect(JobArgumentsHashLayout.safeParse(2).success).toBe(true);
    expect(JobArgumentsHashLayout.safeParse(3).success).toBe(false);
  });

  it('lets an operation descriptor carry a versionArgument', () => {
    const descriptor = {
      name: 'orders.applyApprovedUpdate',
      sensitivity: 'write',
      requiresApproval: true,
      resourceArgument: 'orderId',
      versionArgument: 'expectedVersion',
    };
    expect(OperationDescriptor.safeParse(descriptor).success).toBe(true);
    expect(OperationDescriptor.parse(descriptor).versionArgument).toBe('expectedVersion');
  });
});

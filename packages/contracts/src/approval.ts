import { z } from 'zod';
import { ApprovalInputErrorCodes } from './approval-input.js';
import { IsoDateTime, JsonObject, OperationName, Uuid } from './primitives.js';

/*
 * Phase 4: approval of an exact action (specification §8.2, §11; ADR-015).
 *
 * What is deliberately absent from `ApprovalRequest`: the vault MAC, its key version, and the
 * action hash. The owner's detail view alone carries the hash (`ApprovalDetail`), because the
 * owner confirms it when deciding; an agent-facing or list response never does.
 */

export const ApprovalStatus = z.enum([
  'pending',
  'approved',
  'denied',
  'expired',
  'revoked',
  'consumed',
]);
export type ApprovalStatus = z.infer<typeof ApprovalStatus>;

/**
 * Why an approval was refused at redemption or authorization. Only the audit event carries the
 * reason; the caller of the API learns that the request was refused. The input codes are those
 * of the strict approval-input check (`checkApprovalInput`, `findRawJsonIssue`).
 */
export const ApprovalRefusalReason = z.enum([
  'not_found',
  'not_approved',
  'expired',
  'consumed',
  'revoked',
  'binding_mismatch',
  ...ApprovalInputErrorCodes,
]);
export type ApprovalRefusalReason = z.infer<typeof ApprovalRefusalReason>;

/** Lowercase hex SHA-256, as `approval_requests.action_hash` holds it. */
export const ActionHash = z.string().regex(/^[0-9a-f]{64}$/);

/** A resource version as a target application states it: an integer or a short string. */
export const ResourceVersionValue = z.union([
  z.string().min(1).max(200),
  z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
]);

/**
 * An approval as the API shows it (list and detail). No MAC, no MAC key version and no action
 * hash: a test asserts the schema's shape. `proposal` holds the final arguments (the values the
 * owner is asked to approve); responses go to the owner only.
 */
export const ApprovalRequest = z.object({
  id: Uuid,
  status: ApprovalStatus,
  agentId: Uuid,
  connectionId: Uuid,
  operation: OperationName,
  runId: Uuid.nullable(),
  targetResourceId: z.string().min(1).max(200),
  expectedResourceVersion: ResourceVersionValue,
  /** The final arguments, obligations applied. */
  proposal: JsonObject,
  /** Display only, labelled "as read at version N". Not covered by the action hash. */
  before: JsonObject.nullable(),
  policyDecisionId: Uuid,
  approverUserId: Uuid.nullable(),
  decidedAt: IsoDateTime.nullable(),
  expiresAt: IsoDateTime,
  consumedAt: IsoDateTime.nullable(),
  consumedByJobId: Uuid.nullable(),
  createdAt: IsoDateTime,
});
export type ApprovalRequest = z.infer<typeof ApprovalRequest>;

/**
 * `GET /v1/approvals/:id` for the signed-in owner: the view plus the action hash the dashboard
 * displays and sends back when deciding. Never returned by a list or to an agent.
 */
export const ApprovalDetail = ApprovalRequest.extend({ actionHash: ActionHash });
export type ApprovalDetail = z.infer<typeof ApprovalDetail>;

/** One row of `approval_decisions`: append-only. */
export const ApprovalDecisionKind = z.enum(['approved', 'denied']);
export type ApprovalDecisionKind = z.infer<typeof ApprovalDecisionKind>;

export const ApprovalDecision = z.object({
  id: Uuid,
  approvalRequestId: Uuid,
  /** The signed-in owner, taken from the session and never from a request body. */
  userId: Uuid,
  decision: ApprovalDecisionKind,
  decidedAt: IsoDateTime,
});
export type ApprovalDecision = z.infer<typeof ApprovalDecision>;

export const ApprovalParams = z.object({ approvalId: Uuid });

/**
 * `POST /v1/approvals/:id/approve` and `/deny` bodies. The owner presents the action hash the
 * page displayed, so a proposal that changed after it was shown cannot be decided. Strict: an
 * `approverUserId`, `agentId` or any other field is an error, never ignored.
 */
export const ApproveApprovalRequest = z.strictObject({ actionHash: ActionHash });
export type ApproveApprovalRequest = z.infer<typeof ApproveApprovalRequest>;

export const DenyApprovalRequest = z.strictObject({ actionHash: ActionHash });
export type DenyApprovalRequest = z.infer<typeof DenyApprovalRequest>;

/**
 * The answer to an execute request that needs approval (specification §12.2, owner decision
 * D11): HTTP 202, a pending approval exists, and no job does.
 */
export const ApprovalRequiredResponse = z.strictObject({
  status: z.literal('approval_required'),
  approvalId: Uuid,
  expiresAt: IsoDateTime,
});
export type ApprovalRequiredResponse = z.infer<typeof ApprovalRequiredResponse>;

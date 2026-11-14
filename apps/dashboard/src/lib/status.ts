import type {
  ApprovalMode,
  AuditDecision,
  ConnectionStatus,
  EntityStatus,
  GrantEffect,
  JobStatus,
} from '@aab/contracts';

/** Colour family. Status is always also carried by a label and a distinct icon shape. */
export type Tone = 'ok' | 'warn' | 'danger' | 'info' | 'neutral';

export type IconName =
  'check' | 'ring' | 'half' | 'dots' | 'triangle' | 'clock' | 'loop' | 'cross' | 'pause' | 'minus';

export interface StatusPresentation {
  label: string;
  description: string;
  tone: Tone;
  icon: IconName;
}

/**
 * The eight lifecycle states mapped to what the owner needs to know and do. Labels are unique
 * so two states can never read the same to a screen reader or in a monochrome print.
 */
export const CONNECTION_STATUS: Record<ConnectionStatus, StatusPresentation> = {
  created: {
    label: 'Not signed in',
    description: 'Created, never authenticated.',
    tone: 'neutral',
    icon: 'ring',
  },
  authentication_required: {
    label: 'Sign-in required',
    description: 'Waiting for you to sign in to the application.',
    tone: 'info',
    icon: 'half',
  },
  authenticating: {
    label: 'Signing in',
    description: 'A sign-in is in progress in the broker-controlled browser.',
    tone: 'info',
    icon: 'dots',
  },
  active: {
    label: 'Connected',
    description: 'Session is valid. Granted agents can run operations.',
    tone: 'ok',
    icon: 'check',
  },
  degraded: {
    label: 'Connected, degraded',
    description: 'Session works but recent health checks reported problems.',
    tone: 'warn',
    icon: 'triangle',
  },
  expired: {
    label: 'Session expired',
    description: 'The application ended the session. Operations are refused until you sign in.',
    tone: 'warn',
    icon: 'clock',
  },
  reconnect_required: {
    label: 'Reconnect required',
    description: 'The stored session can no longer be used. Sign in again to restore access.',
    tone: 'danger',
    icon: 'loop',
  },
  revoked: {
    label: 'Revoked',
    description: 'Permanently disconnected. Create a new connection to use this account again.',
    tone: 'danger',
    icon: 'cross',
  },
};

export const ENTITY_STATUS: Record<EntityStatus, StatusPresentation> = {
  active: { label: 'Active', description: '', tone: 'ok', icon: 'check' },
  disabled: { label: 'Disabled', description: '', tone: 'neutral', icon: 'pause' },
};

export const GRANT_EFFECT: Record<GrantEffect, StatusPresentation> = {
  allow: { label: 'Allow', description: '', tone: 'ok', icon: 'check' },
  deny: { label: 'Deny', description: 'Overrides any allow grant.', tone: 'danger', icon: 'cross' },
};

export const APPROVAL_MODE: Record<ApprovalMode, string> = {
  none: 'No approval',
  required: 'Approval required',
};

export const AUDIT_DECISION: Record<AuditDecision, StatusPresentation> = {
  allow: { label: 'Allowed', description: '', tone: 'ok', icon: 'check' },
  deny: { label: 'Denied', description: '', tone: 'danger', icon: 'cross' },
  approval_required: { label: 'Approval required', description: '', tone: 'warn', icon: 'half' },
  not_applicable: { label: 'Not a decision', description: '', tone: 'neutral', icon: 'minus' },
};

export const JOB_STATUS: Record<JobStatus, StatusPresentation> = {
  queued: {
    label: 'Queued',
    description: 'Waiting for the browser worker to pick it up.',
    tone: 'info',
    icon: 'ring',
  },
  running: {
    label: 'Running',
    description: 'The browser worker is running it now.',
    tone: 'info',
    icon: 'dots',
  },
  succeeded: {
    label: 'Succeeded',
    description: 'Finished and the result passed the operation’s output check.',
    tone: 'ok',
    icon: 'check',
  },
  failed: {
    label: 'Failed',
    description: 'It did not complete.',
    tone: 'danger',
    icon: 'cross',
  },
  denied: {
    label: 'Denied',
    description: 'Policy no longer allowed it when the worker checked again. Nothing was done.',
    tone: 'danger',
    icon: 'minus',
  },
  reauth_required: {
    label: 'Sign-in needed',
    description: 'The application no longer accepts the stored session.',
    tone: 'warn',
    icon: 'loop',
  },
  outcome_unknown: {
    label: 'Outcome unknown',
    description:
      'It may have changed something in the application, but the result could not be verified. Check the application before trying again.',
    tone: 'warn',
    icon: 'triangle',
  },
  cancelled: {
    label: 'Cancelled',
    description: 'Cancelled before it finished.',
    tone: 'neutral',
    icon: 'pause',
  },
};

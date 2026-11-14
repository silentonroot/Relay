import {
  AdapterContractError,
  NavigationBlockedError,
  OperationInputError,
  ReauthRequiredError,
  sanitizeOperationOutput,
  validateOperationInput,
} from '@aab/adapter-sdk';
import type { AdapterRegistry, SanitizedResult, SessionHealth } from '@aab/adapter-sdk';
import type { JobErrorCode } from '@aab/contracts';
import type { z } from 'zod';
import { jobError, mapAdapterErrorCode } from '../protocol.js';
import type { OperationJobMessage, RunnerOperationOutcome } from '../protocol.js';
import { BrowserActionError, JobStoppedError } from './facade.js';
import type { Violation } from './facade.js';
import { diag } from './io.js';
import { lookupAdapter, openBrowserJob } from './session.js';
import type { BrowserJob, RunnerEnvironment } from './session.js';

type Outcome = z.infer<typeof RunnerOperationOutcome>;

const failed = (code: JobErrorCode): Outcome => ({ status: 'failed', error: jobError(code) });

/** How close to the deadline an unclassified failure still counts as the job timing out. */
const DEADLINE_MARGIN_MS = 100;

class DeadlineError extends Error {
  constructor() {
    super('deadline');
  }
}

/** Maps anything thrown by adapter code to an outcome. Exception text is never used. */
export function outcomeForError(error: unknown): Outcome {
  if (error instanceof ReauthRequiredError) return { status: 'reauth_required' };
  if (error instanceof NavigationBlockedError) return failed('navigation_blocked');
  if (error instanceof AdapterContractError) return failed('output_rejected');
  if (error instanceof OperationInputError) return failed('invalid_arguments');
  if (error instanceof DeadlineError) return failed('timeout');
  if (error instanceof JobStoppedError) return failed('timeout');
  diag('runner_error', {
    code: error instanceof BrowserActionError ? 'browser_action' : 'adapter',
  });
  return failed('worker_failure');
}

function violationOutcome(violation: Violation): Outcome {
  return outcomeForError(violation);
}

export async function runOperation(
  message: OperationJobMessage,
  registry: AdapterRegistry,
  env: RunnerEnvironment,
  stopped: Promise<'cancelled'>,
): Promise<Outcome> {
  const job = message.job;
  const deadline = Date.now() + job.timeoutMs;
  const remainingMs = (): number => Math.max(0, deadline - Date.now());

  const found = lookupAdapter(registry, job.adapterId, job.adapterVersion, job.allowedOrigins);
  if (!found.ok) {
    diag('adapter_unavailable', { code: found.code });
    return failed(found.code);
  }
  const { adapter, origins } = found;
  if (adapter.execute === undefined) return failed('adapter_unavailable');

  const input = validateOperationInput(adapter, job.operation, job.arguments);
  if (!input.ok) {
    return failed(
      input.error.code === 'unknown_operation' ? 'adapter_unavailable' : 'invalid_arguments',
    );
  }
  const operation = input.operation;

  let timer: NodeJS.Timeout | undefined;
  const expired = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new DeadlineError()), remainingMs());
  });
  const cancelled = stopped.then((): Outcome => failed('cancelled'));

  let browserJob: BrowserJob | null = null;
  const work = async (): Promise<Outcome> => {
    browserJob = await openBrowserJob({
      env,
      adapter,
      origins,
      mode: { kind: 'session' },
      headed: false,
      storageState: job.storageState,
    });
    const opened = browserJob;
    const ctx = opened.makeContext(job.connectionId, remainingMs);
    const violation = opened.violation.then(violationOutcome);

    const steps = async (): Promise<Outcome> => {
      if (adapter.checkSession !== undefined) {
        const health: SessionHealth = await adapter.checkSession(ctx);
        if (opened.guard.violation !== null) return violationOutcome(opened.guard.violation);
        if (health.state === 'expired') return { status: 'reauth_required' };
        if (
          job.expectedAccountHint !== null &&
          health.externalAccountHint !== job.expectedAccountHint
        ) {
          return failed('identity_mismatch');
        }
      }
      opened.guard.setMode({ kind: 'operation', operation: operation.name });
      const result: SanitizedResult = await (
        adapter.execute as NonNullable<typeof adapter.execute>
      )(ctx, operation);
      if (opened.guard.violation !== null) return violationOutcome(opened.guard.violation);
      switch (result.status) {
        case 'succeeded':
          return {
            status: 'succeeded',
            data: sanitizeOperationOutput(adapter, operation.name, result.data),
          };
        case 'reauth_required':
          return { status: 'reauth_required' };
        case 'failed':
          return failed(mapAdapterErrorCode(result.error.code));
        case 'outcome_unknown':
          return { status: 'outcome_unknown' };
        default:
          return failed('worker_failure');
      }
    };
    return Promise.race([steps(), violation]);
  };

  const running = work();
  // Whichever loses the race must not become an unhandled rejection.
  running.catch(() => undefined);
  expired.catch(() => undefined);
  try {
    return await Promise.race([running, expired, cancelled]);
  } catch (error) {
    const current = browserJob as BrowserJob | null;
    const violation = current === null ? null : current.guard.violation;
    if (violation !== null && !(error instanceof DeadlineError)) {
      return violationOutcome(violation);
    }
    const outcome = outcomeForError(error);
    // Browser actions are given the job's remaining time as their own timeout, so an action
    // that runs into the deadline can fail a moment before the deadline timer does. That is
    // still the job timing out, not a worker failure.
    if (
      outcome.status === 'failed' &&
      outcome.error.code === 'worker_failure' &&
      deadline - Date.now() <= DEADLINE_MARGIN_MS
    ) {
      return failed('timeout');
    }
    return outcome;
  } finally {
    clearTimeout(timer);
    const current = browserJob as BrowserJob | null;
    await current?.close();
  }
}

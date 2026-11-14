import type { AgentGrant, Connection, OperationJob } from '@aab/contracts';
import { isTerminalJobStatus } from '@aab/contracts';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { toApiError } from '../api/client.js';
import { useExecuteOperation, useOperationJob } from '../api/hooks.js';
import { buildExecuteRequest } from '../lib/forms.js';
import type { FieldErrors } from '../lib/forms.js';
import { JOB_ERROR_TEXT } from '../lib/jobs.js';
import { JOB_STATUS } from '../lib/status.js';
import { ErrorState, Field, StatusBadge } from './ui.js';

/** What the owner is told when `execute` refuses before any job exists. */
const REFUSAL: Record<string, { title: string; text: string }> = {
  denied: {
    title: 'Denied by policy',
    text: 'Policy did not allow this operation, so nothing was run. Check the grant: it may have expired, been revoked, or have constraints these arguments do not meet.',
  },
  approval_required: {
    title: 'Approval required',
    text: 'This grant asks for approval before each action, and approvals are not available yet, so nothing was run.',
  },
  reauth_required: {
    title: 'Sign in again first',
    text: 'The application needs you to sign in again before this connection can be used. Nothing was run.',
  },
  validation_failed: {
    title: 'The request was not accepted',
    text: 'The broker rejected the request as invalid. Nothing was run.',
  },
  conflict: {
    title: 'Conflict',
    text: 'The broker could not accept this request in the connection’s current state. Nothing was run.',
  },
};

function JobView({ job }: { job: OperationJob }) {
  const status = JOB_STATUS[job.status];
  const terminal = isTerminalJobStatus(job.status);
  return (
    <div className="run-result">
      <div className="run-status" role="status" aria-live="polite">
        <StatusBadge status={status} />
        <p>
          {terminal ? status.description : `${status.description} This page updates by itself.`}
        </p>
        {job.error !== null && (
          <p>
            Error <code>{job.error.code}</code>: {JOB_ERROR_TEXT[job.error.code]}
          </p>
        )}
        {job.status === 'reauth_required' && (
          <p>
            <Link to="/connections">Go to Connections to sign in again</Link>
          </p>
        )}
      </div>
      <p className="field-hint">
        Job <code>{job.jobId}</code> · <code>{job.operation}</code>
      </p>
      {job.result !== null && (
        <>
          <h3 className="run-result-heading">Result</h3>
          <p className="field-hint" id={`result-caption-${job.jobId}`}>
            This text comes from the target application and is untrusted. It is shown as plain text
            only: nothing in it is rendered as HTML or opened as a link.
          </p>
          <pre
            className="result"
            tabIndex={0}
            aria-label="Result (untrusted text)"
            aria-describedby={`result-caption-${job.jobId}`}
          >
            {JSON.stringify(job.result, null, 2)}
          </pre>
        </>
      )}
    </div>
  );
}

/**
 * Sends one operation through the same path an agent uses, to test a grant. The result is
 * rendered only as text children of a <pre>: never as HTML, never as a link.
 */
export function RunOperationPanel(props: {
  agentId: string;
  agentActive: boolean;
  grants: AgentGrant[];
  connections: Connection[];
  now: number;
}) {
  const execute = useExecuteOperation();
  const [grantId, setGrantId] = useState('');
  const [argumentsJson, setArgumentsJson] = useState('{}');
  const [errors, setErrors] = useState<FieldErrors>({});
  const [started, setStarted] = useState<OperationJob | null>(null);

  const connectionById = new Map(props.connections.map((c) => [c.id, c]));
  const usable = props.grants.filter((grant) => {
    if (!props.agentActive) return false;
    if (grant.effect !== 'allow' || grant.revokedAt !== null) return false;
    if (grant.expiresAt !== null && new Date(grant.expiresAt).getTime() <= props.now) return false;
    const connection = connectionById.get(grant.connectionId);
    return connection !== undefined && connection.status !== 'revoked';
  });

  const polled = useOperationJob(
    started?.jobId ?? null,
    started !== null && !isTerminalJobStatus(started.status),
  );
  const job = polled.data ?? started;
  const busy = execute.isPending || (job !== null && !isTerminalJobStatus(job.status));

  function submit(event: FormEvent) {
    event.preventDefault();
    const grant = usable.find((candidate) => candidate.id === grantId);
    const result = buildExecuteRequest(
      { grantId, argumentsJson },
      grant,
      // Fresh for every send: a repeat click is a new request, not a replay.
      crypto.randomUUID(),
    );
    if (!result.ok) {
      setErrors(result.errors);
      return;
    }
    setErrors({});
    setStarted(null);
    execute.reset();
    execute.mutate(result.request, { onSuccess: (response) => setStarted(response) });
  }

  const failure = execute.isError ? toApiError(execute.error) : null;
  const refusal = failure === null ? undefined : REFUSAL[failure.code];

  return (
    <section aria-labelledby="run-heading" className="run">
      <div className="section-header">
        <h2 id="run-heading">Run a read operation</h2>
      </div>
      {usable.length === 0 ? (
        <p className="field-hint">
          {props.agentActive
            ? 'To test a grant, this agent needs an allow grant that is in force on a connection that is not revoked.'
            : 'This agent is disabled, so its requests are denied.'}
        </p>
      ) : (
        <form className="panel form" onSubmit={submit} noValidate aria-label="Run a read operation">
          <p className="callout">
            Sends a real request to the application, checked against this agent’s grants exactly
            like a request from the agent. Use it with read operations only.
          </p>
          <Field label="Grant to test" error={errors.grantId}>
            {(control) => (
              <select
                {...control}
                value={grantId}
                onChange={(event) => setGrantId(event.target.value)}
                disabled={busy}
              >
                <option value="">Choose…</option>
                {usable.map((grant) => (
                  <option key={grant.id} value={grant.id}>
                    {grant.operation} on {connectionById.get(grant.connectionId)?.displayName}
                  </option>
                ))}
              </select>
            )}
          </Field>
          <Field
            label="Arguments (JSON object)"
            hint={
              <>
                For example <code>{'{"limit": 5}'}</code>. Use <code>{'{}'}</code> for none.
              </>
            }
            error={errors.arguments ?? errors._form}
          >
            {(control) => (
              <textarea
                {...control}
                rows={4}
                className="mono"
                value={argumentsJson}
                onChange={(event) => setArgumentsJson(event.target.value)}
                spellCheck={false}
                disabled={busy}
              />
            )}
          </Field>
          <div className="button-row">
            <button type="submit" className="button button-primary" disabled={busy}>
              {busy ? 'Running…' : 'Run operation'}
            </button>
          </div>
        </form>
      )}

      {execute.isPending && (
        <p className="field-hint" role="status" aria-live="polite">
          Sending the request…
        </p>
      )}
      {failure !== null && refusal !== undefined && (
        <div className="outcome-box" role="status" aria-live="polite">
          <p className="outcome outcome-warn">
            <strong>{refusal.title}.</strong> {refusal.text}
          </p>
          <p className="field-hint">
            Broker said: {failure.message}
            {failure.requestId !== null && (
              <>
                {' '}
                · Request ID <code>{failure.requestId}</code>
              </>
            )}
          </p>
          {failure.code === 'reauth_required' && (
            <p>
              <Link to="/connections">Go to Connections to sign in again</Link>
            </p>
          )}
        </div>
      )}
      {failure !== null && refusal === undefined && (
        <ErrorState title="The operation could not be sent" error={failure} />
      )}
      {job !== null && <JobView job={job} />}
      {polled.isError && (
        <ErrorState title="The job status could not be refreshed" error={polled.error} />
      )}
    </section>
  );
}

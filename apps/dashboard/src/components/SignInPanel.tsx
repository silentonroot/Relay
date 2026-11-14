import type { Connection, JobError } from '@aab/contracts';
import { useEffect, useId, useRef, useState } from 'react';
import { useCompleteConnectionAuth, useConnectionPoll } from '../api/hooks.js';
import { JOB_ERROR_TEXT, LOGIN_TIMEOUT_MINUTES } from '../lib/jobs.js';
import { useAnnounce } from './Announcer.js';
import { ErrorState } from './ui.js';

type Outcome =
  { kind: 'success' } | { kind: 'failed'; error: JobError | null; reason: string | null };

function outcomeFromConnection(connection: Connection): Outcome | null {
  if (connection.status === 'authenticating') return null;
  if (connection.status === 'active') return { kind: 'success' };
  return { kind: 'failed', error: null, reason: connection.statusReason };
}

function failureText(outcome: Extract<Outcome, { kind: 'failed' }>): string {
  if (outcome.error !== null) return JOB_ERROR_TEXT[outcome.error.code];
  return (
    outcome.reason ??
    'The sign-in did not finish, for example because the window was closed. Nothing was saved.'
  );
}

/**
 * The login handoff for one connection. It renders from the connection's own status, so a page
 * reload while a handoff is open shows the same instructions. The API has no cancel yet: closing
 * the browser window is the cancel, and the polling below notices it.
 */
export function SignInPanel(props: {
  connection: Connection;
  /** Starts a new handoff; only offered while the status allows it. */
  onRetry: (() => void) | null;
  onClose: () => void;
}) {
  const { connection } = props;
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);
  const announce = useAnnounce();
  const complete = useCompleteConnectionAuth();
  const [checking, setChecking] = useState(false);
  const [local, setLocal] = useState<Outcome | null>(null);

  const authenticating = connection.status === 'authenticating';
  useConnectionPoll(connection.id, authenticating);

  const outcome = local ?? outcomeFromConnection(connection);

  useEffect(() => {
    panel.current?.focus();
  }, []);

  // A handoff that ends without the owner pressing the button (window closed, timeout, or a
  // check that took longer than the API waits) is still announced.
  const wasAuthenticating = useRef(authenticating);
  useEffect(() => {
    if (wasAuthenticating.current && !authenticating && local === null) {
      announce(
        connection.status === 'active'
          ? `Signed in to “${connection.displayName}”.`
          : `Sign-in to “${connection.displayName}” ended without a session.`,
        connection.status === 'active' ? 'success' : 'error',
      );
    }
    wasAuthenticating.current = authenticating;
  }, [authenticating, local, connection.status, connection.displayName, announce]);

  function finish() {
    setChecking(false);
    complete.mutate(connection.id, {
      onSuccess: (response) => {
        if (response.connection.status === 'authenticating') {
          // 202: still being checked. The poll takes over.
          setChecking(true);
          return;
        }
        if (response.connection.status === 'active') {
          setLocal({ kind: 'success' });
          announce(`Signed in to “${connection.displayName}”.`);
        } else {
          setLocal({
            kind: 'failed',
            error: response.error,
            reason: response.connection.statusReason,
          });
          announce(`Sign-in to “${connection.displayName}” did not finish.`, 'error');
        }
      },
    });
  }

  return (
    <div className="handoff" role="group" aria-labelledby={titleId} tabIndex={-1} ref={panel}>
      <p className="handoff-title" id={titleId}>
        {authenticating
          ? `Sign in to “${connection.displayName}” in the browser window`
          : `Sign-in to “${connection.displayName}”`}
      </p>

      {authenticating && (
        <div className="handoff-body">
          <ol className="handoff-steps">
            <li>
              A browser window has opened <strong>on this computer</strong>, outside the dashboard.
              Sign in to the application there, including any verification step.
            </li>
            <li>
              The broker never sees what you type. Once you confirm, it checks that a session
              exists, stores that session encrypted, and closes the window.
            </li>
            <li>
              When you have finished, come back here and press <strong>I’ve signed in</strong>.
            </li>
          </ol>
          <p className="field-hint">
            There is no cancel button yet. To cancel, close the sign-in window: the connection
            returns to “Sign-in required” and nothing is stored. A sign-in that is not finished
            within {LOGIN_TIMEOUT_MINUTES} minutes is abandoned.
          </p>
        </div>
      )}

      <div className="handoff-status" role="status" aria-live="polite">
        {authenticating && (checking || complete.isPending) && (
          <p>Checking your sign-in. This page updates when the check finishes.</p>
        )}
        {outcome?.kind === 'success' && (
          <p className="outcome outcome-ok">
            Signed in.{' '}
            {connection.externalAccountHint !== null && (
              <>
                Account: <strong>{connection.externalAccountHint}</strong>.{' '}
              </>
            )}
            Granted agents can run operations on this connection.
          </p>
        )}
        {outcome?.kind === 'failed' && (
          <p className="outcome outcome-warn">Sign-in did not finish. {failureText(outcome)}</p>
        )}
      </div>

      {complete.isError && (
        <ErrorState title="Sign-in could not be checked" error={complete.error} />
      )}

      <div className="button-row">
        {authenticating ? (
          <button
            type="button"
            className="button button-primary"
            onClick={finish}
            disabled={complete.isPending || checking}
          >
            {complete.isPending || checking ? 'Checking…' : 'I’ve signed in'}
          </button>
        ) : (
          <>
            {outcome?.kind === 'failed' && props.onRetry !== null && (
              <button type="button" className="button button-primary" onClick={props.onRetry}>
                Try again
              </button>
            )}
            <button type="button" className="button" onClick={props.onClose}>
              Dismiss
            </button>
          </>
        )}
      </div>
    </div>
  );
}

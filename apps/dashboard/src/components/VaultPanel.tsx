import type { CapabilityRejectionReason, Connection } from '@aab/contracts';
import { ApiError, toApiError } from '../api/client.js';
import { useConnectionVault, useDeleteStoredSession, useRevokeCapabilities } from '../api/hooks.js';
import { useState } from 'react';
import { useAnnounce } from './Announcer.js';
import { ConfirmPanel, ErrorState, Loading, StatusBadge, Timestamp } from './ui.js';
import type { StatusPresentation } from '../lib/status.js';

const SECRET_STATUS: Record<string, StatusPresentation> = {
  active: { label: 'Stored', description: '', tone: 'ok', icon: 'check' },
  pending: { label: 'Pending', description: '', tone: 'info', icon: 'dots' },
  deleted: { label: 'Deleted', description: '', tone: 'neutral', icon: 'minus' },
  revoked: { label: 'Revoked', description: '', tone: 'danger', icon: 'cross' },
};

/**
 * What each rejection reason usually means. Only an expired token is also what an honestly slow
 * worker produces (ADR-014 section 10); the others point at a replayed, forged or stale token
 * or at a state that changed under the request.
 */
const REJECTION_TEXT: Record<CapabilityRejectionReason, string> = {
  unknown_token: 'A token the vault never issued was presented.',
  used: 'A token that was already used was presented again (replay).',
  revoked: 'A token that had been revoked was presented after the revocation.',
  expired: 'A token was presented after it expired. This can also mean a slow worker.',
  binding_mismatch: 'A token was presented for a different job, connection or operation.',
  integrity: 'A stored record failed its integrity check.',
  job_not_running: 'A token was presented for a job that was not running.',
  secret_not_active: 'The stored session was not active when the token was presented.',
  connection_not_active: 'The connection was not active when the token was presented.',
  key_unavailable: 'The key needed to open the session was not available.',
};

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

function conflictTitle(error: unknown): string {
  const apiError = toApiError(error);
  return apiError instanceof ApiError && apiError.status === 409
    ? 'Not possible in the connection’s current state (for example no session is stored, the connection is revoked, or a sign-in is in progress)'
    : 'That did not work';
}

function DeleteSession({ connection, onClose }: { connection: Connection; onClose: () => void }) {
  const remove = useDeleteStoredSession(connection.id);
  const announce = useAnnounce();
  return (
    <ConfirmPanel
      title={`Delete the stored session of “${connection.displayName}”?`}
      confirmLabel="Delete stored session"
      pending={remove.isPending}
      error={remove.error}
      errorTitle={conflictTitle(remove.error)}
      onCancel={onClose}
      onConfirm={() =>
        remove.mutate(undefined, {
          onSuccess: (result) => {
            announce(
              `Stored session of “${connection.displayName}” deleted. The connection now needs ` +
                `to be reconnected. ${plural(result.capabilitiesRevoked, 'capability', 'capabilities')} ` +
                `revoked, ${plural(result.jobsCancelled, 'job', 'jobs')} cancelled or flagged.`,
            );
            onClose();
          },
        })
      }
    >
      <p>
        The stored session is removed and cannot be recovered. The connection goes to “reconnect
        required” and you will need to sign in again. Queued jobs for this connection are cancelled,
        running jobs are flagged for cancellation, and every unused capability is revoked.
      </p>
    </ConfirmPanel>
  );
}

function RevokeCapabilities({
  connection,
  onClose,
}: {
  connection: Connection;
  onClose: () => void;
}) {
  const revoke = useRevokeCapabilities(connection.id);
  const announce = useAnnounce();
  return (
    <ConfirmPanel
      title={`Revoke outstanding capabilities of “${connection.displayName}”?`}
      confirmLabel="Revoke capabilities"
      pending={revoke.isPending}
      error={revoke.error}
      errorTitle={conflictTitle(revoke.error)}
      onCancel={onClose}
      onConfirm={() =>
        revoke.mutate(undefined, {
          onSuccess: (result) => {
            announce(
              `${plural(result.capabilitiesRevoked, 'capability', 'capabilities')} revoked for ` +
                `“${connection.displayName}”, ${plural(result.jobsCancelled, 'queued job', 'queued jobs')} cancelled.`,
            );
            onClose();
          },
        })
      }
    >
      <p>
        Every capability not yet used is revoked, and queued jobs that held one are cancelled. The
        connection and its stored session stay as they are. Jobs already running are not touched.
      </p>
    </ConfirmPanel>
  );
}

/** Vault metadata and the two lifecycle actions of one connection. Metadata only. */
export function VaultPanel({ connection }: { connection: Connection }) {
  const vault = useConnectionVault(connection.id);
  const [action, setAction] = useState<'delete' | 'revoke' | null>(null);

  if (vault.isPending) return <Loading label="Loading vault details…" />;
  if (vault.isError) {
    return (
      <ErrorState
        title="Vault details could not be loaded"
        error={vault.error}
        onRetry={() => void vault.refetch()}
      />
    );
  }

  const { secrets, capabilities } = vault.data;
  const hasStoredSession = secrets.some((secret) => secret.activeVersion !== null);
  const headingId = `vault-${connection.id}`;
  return (
    <section className="vault-panel" aria-labelledby={headingId}>
      <h3 id={headingId}>Vault details for “{connection.displayName}”</h3>

      {secrets.length === 0 ? (
        <p className="muted">No session has been stored for this connection.</p>
      ) : (
        secrets.map((secret) => (
          <dl className="session-facts vault-secret" key={secret.secretType}>
            <div>
              <dt>Secret type</dt>
              <dd>{secret.secretType}</dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>
                <StatusBadge
                  status={
                    SECRET_STATUS[secret.status] ?? {
                      label: secret.status,
                      description: '',
                      tone: 'neutral',
                      icon: 'minus',
                    }
                  }
                />
              </dd>
            </div>
            <div>
              <dt>Active version</dt>
              <dd>{secret.activeVersion ?? <span className="muted">None</span>}</dd>
            </div>
            <div>
              <dt>Key (KEK) version</dt>
              <dd>{secret.kekVersion ?? <span className="muted">None</span>}</dd>
            </div>
            <div>
              <dt>Last access</dt>
              <dd>
                <Timestamp iso={secret.lastAccessedAt} />
              </dd>
            </div>
          </dl>
        ))
      )}

      <h4>Capabilities, last {capabilities.windowHours} hours</h4>
      <dl className="session-facts vault-counts">
        <div>
          <dt>Authorized</dt>
          <dd>{capabilities.authorized}</dd>
          <dd className="field-hint">
            Capabilities authorized in the window, including those issued to store a session at
            sign-in.
          </dd>
        </div>
        <div>
          <dt>Used</dt>
          <dd>{capabilities.used}</dd>
          <dd className="field-hint">
            Capabilities consumed in the window, whenever they were authorized.
          </dd>
        </div>
        <div>
          <dt>Revoked</dt>
          <dd>{capabilities.revoked}</dd>
          <dd className="field-hint">
            Capabilities revoked in the window, whenever they were authorized: your own actions and
            their consequences. Revoking is deliberate and is not counted as a rejection below.
          </dd>
        </div>
      </dl>
      <p className="field-hint">
        Used and revoked count events of the window, so they can exceed authorized.
      </p>

      <h4>Rejected requests, last {capabilities.windowHours} hours</h4>
      {capabilities.rejected.length === 0 ? (
        <p className="muted">No request was rejected.</p>
      ) : (
        <ul className="vault-rejections">
          {capabilities.rejected.map((entry) => (
            <li key={entry.reason}>
              <strong>{entry.reason}</strong>: {entry.count}
              <span className="field-hint"> {REJECTION_TEXT[entry.reason]}</span>
            </li>
          ))}
        </ul>
      )}

      {action === 'delete' && (
        <DeleteSession connection={connection} onClose={() => setAction(null)} />
      )}
      {action === 'revoke' && (
        <RevokeCapabilities connection={connection} onClose={() => setAction(null)} />
      )}
      {action === null && (
        <>
          <div className="button-row">
            <button type="button" className="button" onClick={() => setAction('revoke')}>
              Revoke outstanding capabilities
            </button>
            <button
              type="button"
              className="button button-quiet-danger"
              onClick={() => setAction('delete')}
              disabled={!hasStoredSession}
              aria-describedby={hasStoredSession ? undefined : `${headingId}-nodelete`}
            >
              Delete stored session
            </button>
          </div>
          {!hasStoredSession && (
            <p className="field-hint" id={`${headingId}-nodelete`}>
              There is no stored session to delete.
            </p>
          )}
        </>
      )}
    </section>
  );
}

import { ApiError } from '../api/client.js';
import { useVaultStatus } from '../api/hooks.js';
import { EmptyState, ErrorState, Icon, Loading, PageHeader } from '../components/ui.js';

/**
 * Installation key status (ADR-014 section 12). Owner only; the API answers 403 to anyone else
 * and 503 while the vault is down. Metadata only: key versions and counts, never key material.
 */
export function VaultPage() {
  const status = useVaultStatus();

  return (
    <>
      <PageHeader
        title="Vault"
        description="Key status of the vault that stores connection sessions. Secret values and key material are never shown, here or anywhere."
      />
      {status.isPending && <Loading label="Loading key status…" />}
      {status.isError && (
        <StatusFailure error={status.error} onRetry={() => void status.refetch()} />
      )}
      {status.isSuccess && (
        <>
          <section className="panel" aria-labelledby="key-status-heading">
            <h2 id="key-status-heading">Key status</h2>
            {status.data.missingKekVersions.length > 0 && (
              <div className="state state-error" role="alert">
                <p className="state-title">
                  <Icon name="triangle" /> Key versions are missing
                </p>
                <p>
                  Stored sessions are wrapped under key version
                  {status.data.missingKekVersions.length === 1 ? '' : 's'}{' '}
                  <strong>{status.data.missingKekVersions.join(', ')}</strong>, but the key file
                  {status.data.missingKekVersions.length === 1 ? ' is' : 's are'} not present. Those
                  sessions cannot be opened; restore the key files from your backup or reconnect the
                  affected connections.
                </p>
              </div>
            )}
            <dl className="session-facts">
              <div>
                <dt>Isolation mode</dt>
                <dd>{status.data.isolation}</dd>
              </div>
              <div>
                <dt>Current key (KEK) version</dt>
                <dd>{status.data.currentKekVersion}</dd>
              </div>
              <div>
                <dt>Key versions present</dt>
                <dd>{status.data.kekVersions.join(', ')}</dd>
              </div>
              <div>
                <dt>Missing key versions</dt>
                <dd>
                  {status.data.missingKekVersions.length === 0 ? (
                    <span className="muted">None</span>
                  ) : (
                    <strong>{status.data.missingKekVersions.join(', ')}</strong>
                  )}
                </dd>
              </div>
            </dl>
            {status.data.isolation === 'shared-uid' && (
              <div className="callout" role="note">
                <Icon name="triangle" /> The vault runs as the same operating-system user as the
                broker (shared-uid). That is acceptable for a local trial; it does not protect the
                key files from a compromised broker process. Use separate-uid for anything else.
              </div>
            )}
            <h3>Stored session versions per key version</h3>
            {Object.keys(status.data.versionsByKek).length === 0 ? (
              <p className="muted">No stored session versions.</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Key version</th>
                    <th scope="col">Stored versions</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(status.data.versionsByKek)
                    .sort(([a], [b]) => Number(a) - Number(b))
                    .map(([kek, count]) => (
                      <tr key={kek}>
                        <th scope="row">{kek}</th>
                        <td>{count}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            )}
          </section>
          <section className="panel" aria-labelledby="protection-heading">
            <h2 id="protection-heading">What the key protects</h2>
            <p>{status.data.protectionStatement}</p>
            <p className="field-hint">
              Rewrapping stored sessions to a new key version and retiring an old key version are
              done only with the vault’s admin command on the server. The dashboard has no button
              for either, by design.
            </p>
          </section>
        </>
      )}
    </>
  );
}

function StatusFailure({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  if (error instanceof ApiError && error.status === 403) {
    return (
      <EmptyState title="Key status is shown to owners only">
        Your role cannot see the installation’s key status. Ask an owner of this organization.
      </EmptyState>
    );
  }
  if (error instanceof ApiError && error.status === 503) {
    return (
      <div className="state state-error" role="alert">
        <p className="state-title">Vault not available</p>
        <p>
          The vault service is not running or cannot be reached, so key status cannot be shown.
          Stored sessions cannot be opened or sealed until it is back, so agents cannot run
          operations that need a session. Deleting a stored session and revoking capabilities still
          work, because they need no key.
        </p>
        {error.requestId !== null && (
          <p className="request-id">
            Request ID <code>{error.requestId}</code>
          </p>
        )}
        <button type="button" className="button" onClick={onRetry}>
          Try again
        </button>
      </div>
    );
  }
  return <ErrorState title="Key status could not be loaded" error={error} onRetry={onRetry} />;
}

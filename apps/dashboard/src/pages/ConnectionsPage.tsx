import { canTransitionConnection, CreateConnectionRequest } from '@aab/contracts';
import type { Connection } from '@aab/contracts';
import { useEffect, useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import {
  useApplications,
  useConnections,
  useCreateConnection,
  useRevokeConnection,
  useStartConnectionAuth,
} from '../api/hooks.js';
import { useAnnounce } from '../components/Announcer.js';
import { SessionInfo } from '../components/SessionInfo.js';
import { SignInPanel } from '../components/SignInPanel.js';
import {
  ConfirmPanel,
  EmptyState,
  ErrorState,
  Field,
  Loading,
  PageHeader,
  StatusBadge,
  TableRegion,
} from '../components/ui.js';
import { fieldErrors } from '../lib/forms.js';
import type { FieldErrors } from '../lib/forms.js';
import { CONNECTION_STATUS } from '../lib/status.js';

function CreateConnectionForm({ onDone }: { onDone: () => void }) {
  const applications = useApplications();
  const create = useCreateConnection();
  const announce = useAnnounce();
  const [applicationId, setApplicationId] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [accountHint, setAccountHint] = useState('');
  const [errors, setErrors] = useState<FieldErrors>({});

  const available = (applications.data ?? []).filter((app) => app.status === 'active');

  function submit(event: FormEvent) {
    event.preventDefault();
    if (applicationId === '') {
      setErrors({ applicationId: 'Choose an application.' });
      return;
    }
    const hint = accountHint.trim();
    const parsed = CreateConnectionRequest.safeParse({
      applicationId,
      displayName,
      ...(hint === '' ? {} : { externalAccountHint: hint }),
    });
    if (!parsed.success) {
      setErrors(fieldErrors(parsed.error));
      return;
    }
    setErrors({});
    create.mutate(parsed.data, {
      onSuccess: (connection) => {
        announce(`Connection “${connection.displayName}” created.`);
        onDone();
      },
    });
  }

  if (applications.isPending) return <Loading label="Loading applications…" />;
  if (applications.isError) {
    return (
      <ErrorState
        title="Applications could not be loaded"
        error={applications.error}
        onRetry={() => void applications.refetch()}
      />
    );
  }
  if (available.length === 0) {
    return (
      <EmptyState title="No application to connect to">
        Register an application on the Applications page first.
      </EmptyState>
    );
  }

  return (
    <form className="panel form" onSubmit={submit} noValidate aria-label="New connection">
      <h2>New connection</h2>
      <p className="callout">
        Signing in to the application happens in a broker-controlled browser, which arrives with the
        browser worker. Until then a new connection stays in “Not signed in” and no agent can use
        it.
      </p>
      <Field label="Application" error={errors.applicationId}>
        {(control) => (
          <select
            {...control}
            value={applicationId}
            onChange={(event) => setApplicationId(event.target.value)}
          >
            <option value="">Choose…</option>
            {available.map((app) => (
              <option key={app.id} value={app.id}>
                {app.name} ({app.adapterId} {app.adapterVersion})
              </option>
            ))}
          </select>
        )}
      </Field>
      <Field
        label="Display name"
        hint="How you tell this account apart, for example “Northstar – primary”."
        error={errors.displayName}
      >
        {(control) => (
          <input
            {...control}
            type="text"
            value={displayName}
            onChange={(event) => setDisplayName(event.target.value)}
            maxLength={120}
          />
        )}
      </Field>
      <Field
        label="Account hint (optional)"
        hint="A non-secret label such as a username. Never a password or token."
        error={errors.externalAccountHint}
      >
        {(control) => (
          <input
            {...control}
            type="text"
            value={accountHint}
            onChange={(event) => setAccountHint(event.target.value)}
            maxLength={120}
            autoComplete="off"
          />
        )}
      </Field>
      {create.isError && <ErrorState title="Connection was not created" error={create.error} />}
      <div className="button-row">
        <button type="button" className="button" onClick={onDone} disabled={create.isPending}>
          Cancel
        </button>
        <button type="submit" className="button button-primary" disabled={create.isPending}>
          {create.isPending ? 'Creating…' : 'Create connection'}
        </button>
      </div>
    </form>
  );
}

function RevokeConnection({
  connection,
  onClose,
}: {
  connection: Connection;
  onClose: () => void;
}) {
  const revoke = useRevokeConnection();
  const announce = useAnnounce();
  const [reason, setReason] = useState('');

  return (
    <ConfirmPanel
      title={`Revoke “${connection.displayName}”?`}
      confirmLabel="Revoke connection"
      pending={revoke.isPending}
      error={revoke.error}
      onCancel={onClose}
      onConfirm={() => {
        const trimmed = reason.trim();
        revoke.mutate(
          { id: connection.id, body: trimmed === '' ? {} : { reason: trimmed } },
          {
            onSuccess: () => {
              announce(`Connection “${connection.displayName}” revoked.`);
              onClose();
            },
          },
        );
      }}
    >
      <p>
        This cannot be undone. Every agent loses access through this connection immediately and its
        stored session is discarded. To use the account again you will need to create a new
        connection. Audit history is kept.
      </p>
      <Field label="Reason (optional, recorded in the audit log)">
        {(control) => (
          <input
            {...control}
            type="text"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            maxLength={500}
          />
        )}
      </Field>
    </ConfirmPanel>
  );
}

export function ConnectionsPage() {
  const connections = useConnections();
  const applications = useApplications();
  const [creating, setCreating] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  // Connections whose sign-in panel stays open (to show the outcome), and how many handoffs
  // each has had, so a new handoff starts with a fresh panel.
  const [panels, setPanels] = useState<Record<string, number>>({});
  const [startErrors, setStartErrors] = useState<Record<string, unknown>>({});
  const start = useStartConnectionAuth();
  const announce = useAnnounce();

  function signIn(connection: Connection) {
    setStartErrors(({ [connection.id]: _dropped, ...rest }) => rest);
    start.mutate(connection.id, {
      onSuccess: () => {
        setPanels((previous) => ({
          ...previous,
          [connection.id]: (previous[connection.id] ?? 0) + 1,
        }));
        announce(`Sign-in started for “${connection.displayName}”. A browser window has opened.`);
      },
      onError: (error) => setStartErrors((previous) => ({ ...previous, [connection.id]: error })),
    });
  }

  // A handoff found already in progress (a reload, another tab) keeps its panel open after it
  // ends, so the outcome is shown instead of the panel vanishing.
  const signingInIds = (connections.data ?? [])
    .filter((connection) => connection.status === 'authenticating')
    .map((connection) => connection.id)
    .join(',');
  useEffect(() => {
    const ids = signingInIds === '' ? [] : signingInIds.split(',');
    setPanels((previous) => {
      const missing = ids.filter((id) => previous[id] === undefined);
      return missing.length === 0
        ? previous
        : { ...previous, ...Object.fromEntries(missing.map((id) => [id, 0])) };
    });
  }, [signingInIds]);

  const applicationNames = useMemo(
    () => new Map((applications.data ?? []).map((app) => [app.id, app.name])),
    [applications.data],
  );

  return (
    <>
      <PageHeader
        title="Connections"
        description="Each connection is one account on one application. Agents act through a connection only where you have granted them an operation."
        actions={
          !creating && (
            <button
              type="button"
              className="button button-primary"
              onClick={() => setCreating(true)}
            >
              New connection
            </button>
          )
        }
      />

      {creating && <CreateConnectionForm onDone={() => setCreating(false)} />}

      {connections.isPending && <Loading label="Loading connections…" />}
      {connections.isError && (
        <ErrorState
          title="Connections could not be loaded"
          error={connections.error}
          onRetry={() => void connections.refetch()}
        />
      )}
      {connections.isSuccess && connections.data.length === 0 && (
        <EmptyState title="No connections yet">
          Create a connection to link an account on a registered application.
        </EmptyState>
      )}
      {connections.isSuccess && connections.data.length > 0 && (
        <TableRegion label="Connections">
          <table>
            <thead>
              <tr>
                <th scope="col">Connection</th>
                <th scope="col">Application</th>
                <th scope="col">Account</th>
                <th scope="col">Status</th>
                <th scope="col">Session</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {connections.data.map((connection) => {
                const status = CONNECTION_STATUS[connection.status];
                const panelOpen =
                  connection.status === 'authenticating' || panels[connection.id] !== undefined;
                const canSignIn =
                  !panelOpen &&
                  revokingId !== connection.id &&
                  // The API also accepts a brand-new connection: it moves it through
                  // `authentication_required` itself when the handoff starts.
                  (connection.status === 'created' ||
                    canTransitionConnection(connection.status, 'authenticating'));
                const signInLabel =
                  connection.status === 'expired' || connection.status === 'reconnect_required'
                    ? 'Sign in again'
                    : 'Sign in';
                return [
                  <tr key={connection.id}>
                    <th scope="row">{connection.displayName}</th>
                    <td>
                      {applicationNames.get(connection.applicationId) ?? (
                        <span className="muted">Unknown application</span>
                      )}
                    </td>
                    <td>
                      {connection.externalAccountHint ?? <span className="muted">Not set</span>}
                    </td>
                    <td>
                      <StatusBadge status={status} />
                      <p className="cell-note">{connection.statusReason ?? status.description}</p>
                    </td>
                    <td>
                      <SessionInfo connection={connection} />
                    </td>
                    <td className="cell-actions">
                      {canSignIn && (
                        <button
                          type="button"
                          className="button"
                          aria-label={`${signInLabel} to ${connection.displayName}`}
                          onClick={() => signIn(connection)}
                          disabled={start.isPending}
                        >
                          {signInLabel}
                        </button>
                      )}
                      {connection.status !== 'revoked' && revokingId !== connection.id && (
                        <button
                          type="button"
                          className="button button-quiet-danger"
                          aria-label={`Revoke ${connection.displayName}`}
                          onClick={() => setRevokingId(connection.id)}
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>,
                  startErrors[connection.id] !== undefined && (
                    <tr key={`${connection.id}-start-error`} className="row-confirm">
                      <td colSpan={6}>
                        <ErrorState
                          title={`Sign-in to “${connection.displayName}” could not be started`}
                          error={startErrors[connection.id]}
                        />
                      </td>
                    </tr>
                  ),
                  panelOpen && (
                    <tr key={`${connection.id}-signin`} className="row-confirm">
                      <td colSpan={6}>
                        <SignInPanel
                          key={`${connection.id}:${panels[connection.id] ?? 0}`}
                          connection={connection}
                          onRetry={
                            canTransitionConnection(connection.status, 'authenticating')
                              ? () => signIn(connection)
                              : null
                          }
                          onClose={() => setPanels(({ [connection.id]: _closed, ...rest }) => rest)}
                        />
                      </td>
                    </tr>
                  ),
                  revokingId === connection.id && (
                    <tr key={`${connection.id}-confirm`} className="row-confirm">
                      <td colSpan={6}>
                        <RevokeConnection
                          connection={connection}
                          onClose={() => setRevokingId(null)}
                        />
                      </td>
                    </tr>
                  ),
                ];
              })}
            </tbody>
          </table>
        </TableRegion>
      )}
      {connections.isSuccess && connections.data.length > 0 && (
        <p className="field-hint">
          Session expiry is an estimate taken from the stored session’s cookies. The application can
          end a session earlier, and a session with no reported expiry can still be ended.
        </p>
      )}
    </>
  );
}

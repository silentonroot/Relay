import type { AgentGrant, Connection } from '@aab/contracts';
import { useMemo, useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  useAgent,
  useAgentGrants,
  useConnections,
  useCreateGrant,
  useRevokeGrant,
} from '../api/hooks.js';
import { useAnnounce } from '../components/Announcer.js';
import { RunOperationPanel } from '../components/RunOperationPanel.js';
import {
  ConfirmPanel,
  EmptyState,
  ErrorState,
  Field,
  Loading,
  PageHeader,
  StatusBadge,
  TableRegion,
  Timestamp,
} from '../components/ui.js';
import { buildGrantRequest, EMPTY_GRANT_FORM } from '../lib/forms.js';
import type { FieldErrors, GrantFormValues } from '../lib/forms.js';
import { describeConstraints } from '../lib/format.js';
import { APPROVAL_MODE, ENTITY_STATUS, GRANT_EFFECT } from '../lib/status.js';
import type { StatusPresentation } from '../lib/status.js';
import { DisableAgent } from './AgentsPage.js';

function AddGrantForm(props: { agentId: string; connections: Connection[]; onDone: () => void }) {
  const create = useCreateGrant(props.agentId);
  const announce = useAnnounce();
  const [values, setValues] = useState<GrantFormValues>(EMPTY_GRANT_FORM);
  const [errors, setErrors] = useState<FieldErrors>({});

  const set = <K extends keyof GrantFormValues>(key: K, value: GrantFormValues[K]) =>
    setValues((previous) => ({ ...previous, [key]: value }));

  // A revoked connection can never run anything, so it is not offered.
  const selectable = props.connections.filter((connection) => connection.status !== 'revoked');

  function submit(event: FormEvent) {
    event.preventDefault();
    const result = buildGrantRequest(values);
    if (!result.ok) {
      setErrors(result.errors);
      return;
    }
    setErrors({});
    create.mutate(result.request, {
      onSuccess: (grant) => {
        announce(`${GRANT_EFFECT[grant.effect].label} grant for ${grant.operation} added.`);
        props.onDone();
      },
    });
  }

  if (selectable.length === 0) {
    return (
      <EmptyState title="No connection to grant access to">
        Create a connection first; a grant always names one connection.
      </EmptyState>
    );
  }

  return (
    <form className="panel form" onSubmit={submit} noValidate aria-label="Add grant">
      <h2>Add grant</h2>
      <p className="callout">
        Agents are denied by default. A grant covers exactly one operation on one connection. A deny
        grant overrides every allow grant for the same operation.
      </p>

      <Field label="Connection" error={errors.connectionId}>
        {(control) => (
          <select
            {...control}
            value={values.connectionId}
            onChange={(event) => set('connectionId', event.target.value)}
          >
            <option value="">Choose…</option>
            {selectable.map((connection) => (
              <option key={connection.id} value={connection.id}>
                {connection.displayName}
              </option>
            ))}
          </select>
        )}
      </Field>

      <Field
        label="Operation"
        hint="The adapter operation name, for example orders.list. Wildcards are not supported."
        error={errors.operation}
      >
        {(control) => (
          <input
            {...control}
            type="text"
            value={values.operation}
            onChange={(event) => set('operation', event.target.value)}
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
          />
        )}
      </Field>

      <fieldset className="field">
        <legend>Effect</legend>
        <label className="choice">
          <input
            type="radio"
            name="effect"
            checked={values.effect === 'allow'}
            onChange={() => set('effect', 'allow')}
          />
          Allow
        </label>
        <label className="choice">
          <input
            type="radio"
            name="effect"
            checked={values.effect === 'deny'}
            onChange={() => set('effect', 'deny')}
          />
          Deny (overrides any allow)
        </label>
      </fieldset>

      <label className="choice">
        <input
          type="checkbox"
          checked={values.effect === 'allow' && values.requireApproval}
          disabled={values.effect === 'deny'}
          onChange={(event) => set('requireApproval', event.target.checked)}
        />
        Require my approval for each action
      </label>

      <Field
        label="Result limit (optional)"
        hint="Largest number of results the agent may request per call."
        error={errors.maxResults}
      >
        {(control) => (
          <input
            {...control}
            type="number"
            inputMode="numeric"
            min={1}
            value={values.maxResults}
            onChange={(event) => set('maxResults', event.target.value)}
          />
        )}
      </Field>

      <Field
        label="Resource IDs (optional)"
        hint="Restrict the grant to these resources. Separate with commas or new lines."
        error={errors.resourceIds}
      >
        {(control) => (
          <textarea
            {...control}
            rows={2}
            value={values.resourceIds}
            onChange={(event) => set('resourceIds', event.target.value)}
            spellCheck={false}
          />
        )}
      </Field>

      <Field
        label="Argument rules (optional, JSON)"
        hint={
          <>
            Supported keys: <code>argumentEquals</code> and <code>argumentOneOf</code>, for example{' '}
            <code>{'{"argumentEquals": {"status": "held"}}'}</code>. Unknown keys are rejected.
          </>
        }
        error={errors.extraConstraints}
      >
        {(control) => (
          <textarea
            {...control}
            rows={3}
            className="mono"
            value={values.extraConstraints}
            onChange={(event) => set('extraConstraints', event.target.value)}
            spellCheck={false}
          />
        )}
      </Field>

      <Field
        label="Expires (optional)"
        hint="In your local time. The grant stops applying at this moment."
        error={errors.expiresAt}
      >
        {(control) => (
          <input
            {...control}
            type="datetime-local"
            value={values.expiresAt}
            onChange={(event) => set('expiresAt', event.target.value)}
          />
        )}
      </Field>

      {errors._form !== undefined && <p className="field-error">{errors._form}</p>}
      {create.isError && <ErrorState title="Grant was not added" error={create.error} />}
      <div className="button-row">
        <button type="button" className="button" onClick={props.onDone} disabled={create.isPending}>
          Cancel
        </button>
        <button type="submit" className="button button-primary" disabled={create.isPending}>
          {create.isPending ? 'Adding…' : 'Add grant'}
        </button>
      </div>
    </form>
  );
}

const GRANT_REVOKED: StatusPresentation = {
  label: 'Revoked',
  description: '',
  tone: 'neutral',
  icon: 'cross',
};
const GRANT_EXPIRED: StatusPresentation = {
  label: 'Expired',
  description: '',
  tone: 'neutral',
  icon: 'clock',
};
const GRANT_IN_FORCE: StatusPresentation = {
  label: 'In force',
  description: '',
  tone: 'ok',
  icon: 'check',
};

function grantState(grant: AgentGrant, now: number): StatusPresentation {
  if (grant.revokedAt !== null) return GRANT_REVOKED;
  if (grant.expiresAt !== null && new Date(grant.expiresAt).getTime() <= now) return GRANT_EXPIRED;
  return GRANT_IN_FORCE;
}

function RevokeGrant(props: { agentId: string; grant: AgentGrant; onClose: () => void }) {
  const revoke = useRevokeGrant(props.agentId);
  const announce = useAnnounce();
  return (
    <ConfirmPanel
      title={`Revoke the ${props.grant.effect} grant for ${props.grant.operation}?`}
      confirmLabel="Revoke grant"
      pending={revoke.isPending}
      error={revoke.error}
      onCancel={props.onClose}
      onConfirm={() =>
        revoke.mutate(props.grant.id, {
          onSuccess: () => {
            announce(`Grant for ${props.grant.operation} revoked.`);
            props.onClose();
          },
        })
      }
    >
      <p>
        {props.grant.effect === 'deny'
          ? 'Removing a deny grant can widen what this agent may do if an allow grant exists for the same operation.'
          : 'The agent can no longer rely on this grant. Requests already waiting for approval are re-checked and will be refused.'}{' '}
        A revoked grant cannot be restored; add a new one instead.
      </p>
    </ConfirmPanel>
  );
}

export function AgentDetailPage() {
  const { agentId = '' } = useParams();
  const agent = useAgent(agentId);
  const grants = useAgentGrants(agentId);
  const connections = useConnections();
  const [adding, setAdding] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [disabling, setDisabling] = useState(false);
  const [now] = useState(() => Date.now());

  const connectionNames = useMemo(
    () => new Map((connections.data ?? []).map((c) => [c.id, c.displayName])),
    [connections.data],
  );

  if (agent.isPending) return <Loading label="Loading agent…" />;
  if (agent.isError) {
    return (
      <>
        <PageHeader title="Agent" />
        <ErrorState
          title="This agent could not be loaded"
          error={agent.error}
          onRetry={() => void agent.refetch()}
        />
        <p>
          <Link to="/agents">Back to agents</Link>
        </p>
      </>
    );
  }

  return (
    <>
      <p className="breadcrumb">
        <Link to="/agents">Agents</Link> <span aria-hidden="true">/</span>
      </p>
      <PageHeader
        title={agent.data.name}
        description={
          <>
            Client identity <code>{agent.data.clientIdentity}</code> · registered{' '}
            <Timestamp iso={agent.data.createdAt} />
          </>
        }
        actions={
          <>
            <StatusBadge status={ENTITY_STATUS[agent.data.status]} />
            {agent.data.status === 'active' && !disabling && (
              <button
                type="button"
                className="button button-quiet-danger"
                onClick={() => setDisabling(true)}
              >
                Disable agent
              </button>
            )}
          </>
        }
      />

      {disabling && <DisableAgent agent={agent.data} onClose={() => setDisabling(false)} />}
      {agent.data.status === 'disabled' && (
        <p className="callout">
          This agent is disabled. All of its requests are denied regardless of the grants below.
        </p>
      )}

      <section aria-labelledby="grants-heading">
        <div className="section-header">
          <h2 id="grants-heading">Grants</h2>
          {!adding && (
            <button type="button" className="button button-primary" onClick={() => setAdding(true)}>
              Add grant
            </button>
          )}
        </div>

        {adding &&
          (connections.isPending ? (
            <Loading label="Loading connections…" />
          ) : connections.isError ? (
            <ErrorState
              title="Connections could not be loaded"
              error={connections.error}
              onRetry={() => void connections.refetch()}
            />
          ) : (
            <AddGrantForm
              agentId={agentId}
              connections={connections.data}
              onDone={() => setAdding(false)}
            />
          ))}

        {grants.isPending && <Loading label="Loading grants…" />}
        {grants.isError && (
          <ErrorState
            title="Grants could not be loaded"
            error={grants.error}
            onRetry={() => void grants.refetch()}
          />
        )}
        {grants.isSuccess && grants.data.length === 0 && (
          <EmptyState title="No grants">
            This agent is denied everything. Add a grant to allow one operation on one connection.
          </EmptyState>
        )}
        {grants.isSuccess && grants.data.length > 0 && (
          <TableRegion label="Grants">
            <table>
              <thead>
                <tr>
                  <th scope="col">Operation</th>
                  <th scope="col">Connection</th>
                  <th scope="col">Effect</th>
                  <th scope="col">Approval</th>
                  <th scope="col">Constraints</th>
                  <th scope="col">Expires</th>
                  <th scope="col">State</th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {grants.data.map((grant) => {
                  const constraints = describeConstraints(grant.constraints);
                  const state = grantState(grant, now);
                  return [
                    <tr
                      key={grant.id}
                      className={state === GRANT_IN_FORCE ? undefined : 'row-inactive'}
                    >
                      <th scope="row">
                        <code>{grant.operation}</code>
                      </th>
                      <td>
                        {connectionNames.get(grant.connectionId) ?? (
                          <span className="muted">Unknown connection</span>
                        )}
                      </td>
                      <td>
                        <StatusBadge status={GRANT_EFFECT[grant.effect]} />
                      </td>
                      <td>
                        {grant.effect === 'deny' ? (
                          <span className="muted">Not applicable</span>
                        ) : (
                          APPROVAL_MODE[grant.approvalMode]
                        )}
                      </td>
                      <td>
                        {constraints.length === 0 ? (
                          <span className="muted">None</span>
                        ) : (
                          <ul className="plain-list">
                            {constraints.map((line) => (
                              <li key={line}>{line}</li>
                            ))}
                          </ul>
                        )}
                      </td>
                      <td className="numeric">
                        {grant.expiresAt === null ? (
                          <span className="muted">Never</span>
                        ) : (
                          <Timestamp iso={grant.expiresAt} />
                        )}
                      </td>
                      <td>
                        <StatusBadge status={state} />
                        {grant.revokedAt !== null && (
                          <p className="cell-note">
                            <Timestamp iso={grant.revokedAt} />
                          </p>
                        )}
                      </td>
                      <td className="cell-actions">
                        {grant.revokedAt === null && revokingId !== grant.id && (
                          <button
                            type="button"
                            className="button button-quiet-danger"
                            aria-label={`Revoke grant for ${grant.operation}`}
                            onClick={() => setRevokingId(grant.id)}
                          >
                            Revoke
                          </button>
                        )}
                      </td>
                    </tr>,
                    revokingId === grant.id && (
                      <tr key={`${grant.id}-confirm`} className="row-confirm">
                        <td colSpan={8}>
                          <RevokeGrant
                            agentId={agentId}
                            grant={grant}
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
      </section>

      {grants.isSuccess && connections.isSuccess && (
        <RunOperationPanel
          agentId={agentId}
          agentActive={agent.data.status === 'active'}
          grants={grants.data}
          connections={connections.data}
          now={now}
        />
      )}
    </>
  );
}

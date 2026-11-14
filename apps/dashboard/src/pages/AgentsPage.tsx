import { CreateAgentRequest } from '@aab/contracts';
import type { Agent } from '@aab/contracts';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { useAgents, useCreateAgent, useDisableAgent } from '../api/hooks.js';
import { useAnnounce } from '../components/Announcer.js';
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
import { fieldErrors } from '../lib/forms.js';
import type { FieldErrors } from '../lib/forms.js';
import { ENTITY_STATUS } from '../lib/status.js';

function CreateAgentForm({ onDone }: { onDone: () => void }) {
  const create = useCreateAgent();
  const announce = useAnnounce();
  const [name, setName] = useState('');
  const [clientIdentity, setClientIdentity] = useState('');
  const [errors, setErrors] = useState<FieldErrors>({});

  function submit(event: FormEvent) {
    event.preventDefault();
    const parsed = CreateAgentRequest.safeParse({ name, clientIdentity });
    if (!parsed.success) {
      setErrors(fieldErrors(parsed.error));
      return;
    }
    setErrors({});
    create.mutate(parsed.data, {
      onSuccess: (agent) => {
        announce(`Agent “${agent.name}” registered. It has no grants, so it can do nothing yet.`);
        onDone();
      },
    });
  }

  return (
    <form className="panel form" onSubmit={submit} noValidate aria-label="New agent">
      <h2>New agent</h2>
      <p className="callout">
        A new agent starts with no grants. Add grants on the agent’s page to let it run specific
        operations on specific connections.
      </p>
      <Field label="Name" error={errors.name}>
        {(control) => (
          <input
            {...control}
            type="text"
            value={name}
            onChange={(event) => setName(event.target.value)}
            maxLength={120}
          />
        )}
      </Field>
      <Field
        label="Client identity"
        hint="A stable identifier for the client, independent of model or conversation, for example “order-assistant”."
        error={errors.clientIdentity}
      >
        {(control) => (
          <input
            {...control}
            type="text"
            value={clientIdentity}
            onChange={(event) => setClientIdentity(event.target.value)}
            maxLength={200}
            autoComplete="off"
          />
        )}
      </Field>
      {create.isError && <ErrorState title="Agent was not registered" error={create.error} />}
      <div className="button-row">
        <button type="button" className="button" onClick={onDone} disabled={create.isPending}>
          Cancel
        </button>
        <button type="submit" className="button button-primary" disabled={create.isPending}>
          {create.isPending ? 'Registering…' : 'Register agent'}
        </button>
      </div>
    </form>
  );
}

export function DisableAgent({ agent, onClose }: { agent: Agent; onClose: () => void }) {
  const disable = useDisableAgent();
  const announce = useAnnounce();
  return (
    <ConfirmPanel
      title={`Disable “${agent.name}”?`}
      confirmLabel="Disable agent"
      pending={disable.isPending}
      error={disable.error}
      onCancel={onClose}
      onConfirm={() =>
        disable.mutate(agent.id, {
          onSuccess: () => {
            announce(`Agent “${agent.name}” disabled.`);
            onClose();
          },
        })
      }
    >
      <p>
        Every request from this agent will be denied from now on, whatever grants it holds. Its
        grants and audit history are kept.
      </p>
    </ConfirmPanel>
  );
}

export function AgentsPage() {
  const agents = useAgents();
  const [creating, setCreating] = useState(false);
  const [disablingId, setDisablingId] = useState<string | null>(null);

  return (
    <>
      <PageHeader
        title="Agents"
        description="An agent requests operations; it never holds credentials. What it may do is decided by its grants."
        actions={
          !creating && (
            <button
              type="button"
              className="button button-primary"
              onClick={() => setCreating(true)}
            >
              New agent
            </button>
          )
        }
      />

      {creating && <CreateAgentForm onDone={() => setCreating(false)} />}

      {agents.isPending && <Loading label="Loading agents…" />}
      {agents.isError && (
        <ErrorState
          title="Agents could not be loaded"
          error={agents.error}
          onRetry={() => void agents.refetch()}
        />
      )}
      {agents.isSuccess && agents.data.length === 0 && (
        <EmptyState title="No agents yet">
          Register an agent, then grant it operations on a connection.
        </EmptyState>
      )}
      {agents.isSuccess && agents.data.length > 0 && (
        <TableRegion label="Agents">
          <table>
            <thead>
              <tr>
                <th scope="col">Agent</th>
                <th scope="col">Client identity</th>
                <th scope="col">Status</th>
                <th scope="col">Registered</th>
                <th scope="col">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {agents.data.map((agent) => [
                <tr key={agent.id}>
                  <th scope="row">
                    <Link to={`/agents/${agent.id}`}>{agent.name}</Link>
                  </th>
                  <td>
                    <code>{agent.clientIdentity}</code>
                  </td>
                  <td>
                    <StatusBadge status={ENTITY_STATUS[agent.status]} />
                  </td>
                  <td className="numeric">
                    <Timestamp iso={agent.createdAt} />
                  </td>
                  <td className="cell-actions">
                    <Link className="button button-quiet" to={`/agents/${agent.id}`}>
                      Grants<span className="sr-only"> for {agent.name}</span>
                    </Link>
                    {agent.status === 'active' && disablingId !== agent.id && (
                      <button
                        type="button"
                        className="button button-quiet-danger"
                        aria-label={`Disable ${agent.name}`}
                        onClick={() => setDisablingId(agent.id)}
                      >
                        Disable
                      </button>
                    )}
                  </td>
                </tr>,
                disablingId === agent.id && (
                  <tr key={`${agent.id}-confirm`} className="row-confirm">
                    <td colSpan={5}>
                      <DisableAgent agent={agent} onClose={() => setDisablingId(null)} />
                    </td>
                  </tr>
                ),
              ])}
            </tbody>
          </table>
        </TableRegion>
      )}
    </>
  );
}

import { AuditEventType } from '@aab/contracts';
import type { AuditEvent } from '@aab/contracts';
import { useMemo, useState } from 'react';
import type { AuditFilters } from '../api/endpoints.js';
import { useAgents, useAuditEvents, useConnections } from '../api/hooks.js';
import { useAnnounce } from '../components/Announcer.js';
import {
  EmptyState,
  ErrorState,
  Field,
  Loading,
  PageHeader,
  StatusBadge,
  TableRegion,
  Timestamp,
} from '../components/ui.js';
import { formatEventType, formatJsonValue, shortId, truncateHash } from '../lib/format.js';
import { AUDIT_DECISION } from '../lib/status.js';

const ACTOR_LABEL: Record<AuditEvent['actorType'], string> = {
  user: 'User',
  agent: 'Agent',
  worker: 'Worker',
  system: 'System',
};

export function AuditTable(props: {
  events: AuditEvent[];
  agentNames: Map<string, string>;
  connectionNames: Map<string, string>;
}) {
  const name = (names: Map<string, string>, id: string | null) =>
    id === null ? <span className="muted">—</span> : (names.get(id) ?? <code>{shortId(id)}</code>);

  return (
    <TableRegion label="Audit events">
      <table>
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Event</th>
            <th scope="col">Actor</th>
            <th scope="col">Decision</th>
            <th scope="col">Agent</th>
            <th scope="col">Connection</th>
            <th scope="col">Details</th>
          </tr>
        </thead>
        <tbody>
          {props.events.map((event) => {
            const metadata = Object.entries(event.metadata);
            return (
              <tr key={event.id}>
                <td className="numeric">
                  <Timestamp iso={event.timestamp} />
                </td>
                <th scope="row">{formatEventType(event.eventType)}</th>
                <td>{ACTOR_LABEL[event.actorType]}</td>
                <td>
                  <StatusBadge status={AUDIT_DECISION[event.decision]} />
                </td>
                <td>{name(props.agentNames, event.agentId)}</td>
                <td>{name(props.connectionNames, event.connectionId)}</td>
                <td>
                  <details>
                    <summary>
                      {metadata.length === 0
                        ? 'Record'
                        : `${metadata.length} ${metadata.length === 1 ? 'field' : 'fields'}`}
                      <span className="sr-only"> for event {event.sequence}</span>
                    </summary>
                    <dl className="meta">
                      {metadata.map(([key, value]) => (
                        <div key={key}>
                          <dt>{key}</dt>
                          <dd>{formatJsonValue(value)}</dd>
                        </div>
                      ))}
                      <div>
                        <dt>Sequence</dt>
                        <dd>{event.sequence}</dd>
                      </div>
                      <div>
                        <dt>Chain hash</dt>
                        <dd>
                          <code>{truncateHash(event.eventHash)}</code>
                        </dd>
                      </div>
                    </dl>
                  </details>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </TableRegion>
  );
}

export function useEntityNames() {
  const agents = useAgents();
  const connections = useConnections();
  const agentNames = useMemo(
    () => new Map((agents.data ?? []).map((agent) => [agent.id, agent.name])),
    [agents.data],
  );
  const connectionNames = useMemo(
    () => new Map((connections.data ?? []).map((c) => [c.id, c.displayName])),
    [connections.data],
  );
  return { agents, connections, agentNames, connectionNames };
}

export function ActivityPage() {
  const [filters, setFilters] = useState<AuditFilters>({});
  const audit = useAuditEvents(filters);
  const { agents, connections, agentNames, connectionNames } = useEntityNames();
  const announce = useAnnounce();

  const events = audit.data?.pages.flatMap((page) => page.items) ?? [];
  const filtered = Object.values(filters).some((value) => value !== undefined);

  async function loadMore() {
    const result = await audit.fetchNextPage();
    const added = result.data?.pages.at(-1)?.items.length;
    if (added !== undefined) announce(`Loaded ${added} more events.`);
  }

  return (
    <>
      <PageHeader
        title="Activity & Audit"
        description="Every sign-in, change and authorization decision, newest first. Entries are summaries: they never contain credentials or page content."
      />

      <form
        className="filters"
        aria-label="Filter events"
        onSubmit={(event) => event.preventDefault()}
      >
        <Field label="Agent">
          {(control) => (
            <select
              {...control}
              value={filters.agentId ?? ''}
              onChange={(event) =>
                setFilters((f) => ({ ...f, agentId: event.target.value || undefined }))
              }
            >
              <option value="">All agents</option>
              {(agents.data ?? []).map((agent) => (
                <option key={agent.id} value={agent.id}>
                  {agent.name}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label="Connection">
          {(control) => (
            <select
              {...control}
              value={filters.connectionId ?? ''}
              onChange={(event) =>
                setFilters((f) => ({ ...f, connectionId: event.target.value || undefined }))
              }
            >
              <option value="">All connections</option>
              {(connections.data ?? []).map((connection) => (
                <option key={connection.id} value={connection.id}>
                  {connection.displayName}
                </option>
              ))}
            </select>
          )}
        </Field>
        <Field label="Event type">
          {(control) => (
            <select
              {...control}
              value={filters.eventType ?? ''}
              onChange={(event) => {
                const parsed = AuditEventType.safeParse(event.target.value);
                setFilters((f) => ({ ...f, eventType: parsed.success ? parsed.data : undefined }));
              }}
            >
              <option value="">All events</option>
              {AuditEventType.options.map((type) => (
                <option key={type} value={type}>
                  {formatEventType(type)}
                </option>
              ))}
            </select>
          )}
        </Field>
        {filtered && (
          <button type="button" className="button" onClick={() => setFilters({})}>
            Clear filters
          </button>
        )}
      </form>

      {audit.isPending && <Loading label="Loading events…" />}
      {audit.isError && events.length === 0 && (
        <ErrorState
          title="Events could not be loaded"
          error={audit.error}
          onRetry={() => void audit.refetch()}
        />
      )}
      {audit.isSuccess && events.length === 0 && (
        <EmptyState title={filtered ? 'No events match these filters' : 'No events recorded yet'}>
          {filtered
            ? 'Clear a filter to widen the search.'
            : 'Activity appears here as it happens.'}
        </EmptyState>
      )}
      {events.length > 0 && (
        <>
          <AuditTable events={events} agentNames={agentNames} connectionNames={connectionNames} />
          {audit.isFetchNextPageError && (
            <ErrorState title="More events could not be loaded" error={audit.error} />
          )}
          <div className="list-footer">
            <p className="muted">
              Showing {events.length} {events.length === 1 ? 'event' : 'events'}
              {audit.hasNextPage ? '' : ' · end of log'}
            </p>
            {audit.hasNextPage && (
              <button
                type="button"
                className="button"
                disabled={audit.isFetchingNextPage}
                onClick={() => void loadMore()}
              >
                {audit.isFetchingNextPage ? 'Loading…' : 'Load more'}
              </button>
            )}
          </div>
        </>
      )}
    </>
  );
}

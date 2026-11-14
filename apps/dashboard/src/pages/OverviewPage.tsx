import { ConnectionStatus } from '@aab/contracts';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import {
  useAgents,
  useApplications,
  useConnections,
  useHealth,
  useRecentAuditEvents,
} from '../api/hooks.js';
import {
  EmptyState,
  ErrorState,
  Icon,
  Loading,
  PageHeader,
  StatusBadge,
} from '../components/ui.js';
import { CONNECTION_STATUS } from '../lib/status.js';
import type { StatusPresentation } from '../lib/status.js';
import { AuditTable, useEntityNames } from './ActivityPage.js';

const RECENT_EVENTS = 8;

function Stat(props: {
  title: string;
  to: string;
  pending: boolean;
  error: unknown;
  value: number | undefined;
  children?: ReactNode;
}) {
  return (
    <section className="stat">
      <h2>
        <Link to={props.to}>{props.title}</Link>
      </h2>
      {props.pending ? (
        <Loading label="Loading…" />
      ) : props.error !== null ? (
        <ErrorState title="Could not be loaded" error={props.error} />
      ) : (
        <>
          <p className="stat-value">{props.value}</p>
          {props.children}
        </>
      )}
    </section>
  );
}

const HEALTH_OK: StatusPresentation = {
  label: 'Operational',
  description: '',
  tone: 'ok',
  icon: 'check',
};
const HEALTH_DEGRADED: StatusPresentation = {
  label: 'Degraded',
  description: '',
  tone: 'warn',
  icon: 'triangle',
};
const HEALTH_DOWN: StatusPresentation = {
  label: 'Unavailable',
  description: '',
  tone: 'danger',
  icon: 'cross',
};

export function OverviewPage() {
  const applications = useApplications();
  const connections = useConnections();
  const agents = useAgents();
  const health = useHealth();
  const recent = useRecentAuditEvents(RECENT_EVENTS);
  const { agentNames, connectionNames } = useEntityNames();

  const byStatus = ConnectionStatus.options
    .map((status) => ({
      status,
      count: (connections.data ?? []).filter((c) => c.status === status).length,
    }))
    .filter((entry) => entry.count > 0);
  const activeAgents = (agents.data ?? []).filter((agent) => agent.status === 'active').length;

  return (
    <>
      <PageHeader
        title="Overview"
        description="What is connected, who may act, and what happened most recently."
      />

      <div className="stat-grid">
        <Stat
          title="Applications"
          to="/applications"
          pending={applications.isPending}
          error={applications.error}
          value={applications.data?.length}
        />
        <Stat
          title="Connections"
          to="/connections"
          pending={connections.isPending}
          error={connections.error}
          value={connections.data?.length}
        >
          {byStatus.length > 0 && (
            <ul className="status-breakdown">
              {byStatus.map(({ status, count }) => (
                <li key={status} className={`tone-${CONNECTION_STATUS[status].tone}`}>
                  <Icon name={CONNECTION_STATUS[status].icon} />
                  <span>{CONNECTION_STATUS[status].label}</span>
                  <span className="numeric">{count}</span>
                </li>
              ))}
            </ul>
          )}
        </Stat>
        <Stat
          title="Agents"
          to="/agents"
          pending={agents.isPending}
          error={agents.error}
          value={agents.data?.length}
        >
          {agents.data !== undefined && agents.data.length > 0 && (
            <p className="muted">
              {activeAgents} active · {agents.data.length - activeAgents} disabled
            </p>
          )}
        </Stat>
        <section className="stat">
          <h2>Broker API</h2>
          {health.isPending ? (
            <Loading label="Checking…" />
          ) : health.isError ? (
            <>
              <p className="stat-badge">
                <StatusBadge status={HEALTH_DOWN} />
              </p>
              <p className="muted">The health check did not answer.</p>
            </>
          ) : (
            <>
              <p className="stat-badge">
                <StatusBadge status={health.data.status === 'ok' ? HEALTH_OK : HEALTH_DEGRADED} />
              </p>
              <p className="muted">
                Version {health.data.version} · database{' '}
                {health.data.checks.database === 'ok' ? 'reachable' : 'unavailable'}
              </p>
            </>
          )}
        </section>
      </div>

      <section aria-labelledby="recent-heading">
        <div className="section-header">
          <h2 id="recent-heading">Recent activity</h2>
          <Link to="/activity">View all activity</Link>
        </div>
        {recent.isPending && <Loading label="Loading recent activity…" />}
        {recent.isError && (
          <ErrorState
            title="Recent activity could not be loaded"
            error={recent.error}
            onRetry={() => void recent.refetch()}
          />
        )}
        {recent.isSuccess && recent.data.items.length === 0 && (
          <EmptyState title="Nothing has happened yet">
            Sign-ins, changes and authorization decisions will be listed here.
          </EmptyState>
        )}
        {recent.isSuccess && recent.data.items.length > 0 && (
          <AuditTable
            events={recent.data.items}
            agentNames={agentNames}
            connectionNames={connectionNames}
          />
        )}
      </section>
    </>
  );
}

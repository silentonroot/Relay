import { Link } from 'react-router-dom';
import { PageHeader, StatusBadge } from '../components/ui.js';
import type { StatusPresentation } from '../lib/status.js';

const NOT_AVAILABLE: StatusPresentation = {
  label: 'Not available yet',
  description: '',
  tone: 'neutral',
  icon: 'minus',
};

interface PlannedContent {
  title: string;
  summary: string;
  items: readonly string[];
  /** What the owner can do today instead, only where something real exists. */
  today?: { text: string; to: string; linkLabel: string };
}

/** A route that is real but has no backend yet. It states what will live here, nothing more. */
function PlannedPage({ content }: { content: PlannedContent }) {
  return (
    <>
      <PageHeader title={content.title} description={content.summary} />
      <section className="panel planned" aria-labelledby="planned-heading">
        <p>
          <StatusBadge status={NOT_AVAILABLE} />
        </p>
        <h2 id="planned-heading">What will live here</h2>
        <ul className="planned-list">
          {content.items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        {content.today !== undefined && (
          <p className="muted">
            {content.today.text} <Link to={content.today.to}>{content.today.linkLabel}</Link>
          </p>
        )}
      </section>
    </>
  );
}

export function VaultPage() {
  return (
    <PlannedPage
      content={{
        title: 'Vault',
        summary: 'Secret metadata and rotation. Secret values are never shown, here or anywhere.',
        items: [
          'Which secrets exist, which connection each belongs to, and when it was created.',
          'When each secret was last rotated and when it is due for rotation.',
          'Rotation and revocation actions. Values stay inside the broker and are never displayed or exported.',
        ],
      }}
    />
  );
}

export function PoliciesPage() {
  return (
    <PlannedPage
      content={{
        title: 'Policies',
        summary: 'Grant rules and a policy simulator.',
        items: [
          'Every grant rule across all agents in one place, with what each allows or denies.',
          'A simulator: pick an agent, connection and operation and see the decision the broker would make, and why, without running anything.',
        ],
        today: {
          text: 'Grants are managed per agent for now.',
          to: '/agents',
          linkLabel: 'Go to Agents',
        },
      }}
    />
  );
}

export function WorkflowsPage() {
  return (
    <PlannedPage
      content={{
        title: 'Workflows',
        summary: 'Multi-step runs.',
        items: [
          'Runs that chain several operations, with the status of each step.',
          'Where a run paused, what it is waiting for, and what it changed.',
        ],
      }}
    />
  );
}

export function ApprovalsPage() {
  return (
    <PlannedPage
      content={{
        title: 'Approvals',
        summary: 'The exact proposed actions awaiting a decision.',
        items: [
          'Each action an agent has proposed that needs your approval, shown exactly as it would run.',
          'Approve or reject, with the decision recorded in the audit log.',
        ],
      }}
    />
  );
}

export function SettingsPage() {
  return (
    <PlannedPage
      content={{
        title: 'Settings',
        summary: 'Local identity, key status, worker health and retention.',
        items: [
          'Local identity: the owner account and organization of this instance.',
          'Key status: whether encryption keys are present, and when they were last rotated.',
          'Worker health: whether the browser workers are running and responding.',
          'Retention: how long audit and run records are kept.',
        ],
      }}
    />
  );
}

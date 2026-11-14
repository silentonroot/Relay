import { useEffect, useId, useRef } from 'react';
import type { ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { toApiError } from '../api/client.js';
import { formatDateTime } from '../lib/format.js';
import type { IconName, StatusPresentation } from '../lib/status.js';

const ICONS: Record<IconName, ReactNode> = {
  check: <path d="M3 8.6l3.1 3.1L13 4.6" />,
  ring: <circle cx="8" cy="8" r="5.2" />,
  half: (
    <>
      <circle cx="8" cy="8" r="5.2" />
      <path d="M8 2.8a5.2 5.2 0 0 1 0 10.4z" fill="currentColor" stroke="none" />
    </>
  ),
  dots: (
    <g fill="currentColor" stroke="none">
      <circle cx="3.5" cy="8" r="1.4" />
      <circle cx="8" cy="8" r="1.4" />
      <circle cx="12.5" cy="8" r="1.4" />
    </g>
  ),
  triangle: <path d="M8 2.6l5.8 10.2H2.2zM8 6.6v3M8 11.3v.2" />,
  clock: (
    <>
      <circle cx="8" cy="8" r="5.6" />
      <path d="M8 4.8V8l2.2 1.5" />
    </>
  ),
  loop: <path d="M13 8a5 5 0 1 1-1.5-3.6M13 2.4v2.9h-2.9" />,
  cross: <path d="M4 4l8 8M12 4l-8 8" />,
  pause: <path d="M5.5 3.5v9M10.5 3.5v9" />,
  minus: <path d="M3.5 8h9" />,
};

export function Icon({ name }: { name: IconName }) {
  return (
    <svg
      className="icon"
      viewBox="0 0 16 16"
      width="14"
      height="14"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {ICONS[name]}
    </svg>
  );
}

/** Status as icon shape plus text. Colour only reinforces what the label already says. */
export function StatusBadge({ status }: { status: StatusPresentation }) {
  return (
    <span className={`badge badge-${status.tone}`}>
      <Icon name={status.icon} />
      {status.label}
    </span>
  );
}

export function Timestamp({ iso }: { iso: string | null }) {
  if (iso === null) return <span className="muted">Never</span>;
  return (
    <time dateTime={iso} title={iso}>
      {formatDateTime(iso)}
    </time>
  );
}

/** Page title. Sets the document title and takes focus after in-app navigation. */
export function PageHeader(props: { title: string; description?: ReactNode; actions?: ReactNode }) {
  const heading = useRef<HTMLHeadingElement>(null);
  const location = useLocation();

  useEffect(() => {
    document.title = `${props.title} · Agent Access Broker`;
  }, [props.title]);

  useEffect(() => {
    // The first entry of a visit keeps the browser's own focus position.
    if (location.key !== 'default') heading.current?.focus();
  }, [location.key]);

  return (
    <header className="page-header">
      <div>
        <h1 ref={heading} tabIndex={-1}>
          {props.title}
        </h1>
        {props.description !== undefined && <p className="page-description">{props.description}</p>}
      </div>
      {props.actions !== undefined && <div className="page-actions">{props.actions}</div>}
    </header>
  );
}

export function Loading({ label }: { label: string }) {
  return (
    <p className="state" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </p>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="state state-empty">
      <p className="state-title">{title}</p>
      {children !== undefined && <p>{children}</p>}
    </div>
  );
}

/** Shows what failed and the request id, so the failure can be quoted and traced. */
export function ErrorState(props: { title: string; error: unknown; onRetry?: () => void }) {
  const error = toApiError(props.error);
  return (
    <div className="state state-error" role="alert">
      <p className="state-title">{props.title}</p>
      <p>{error.message}</p>
      {error.details.length > 0 && (
        <ul>
          {error.details.map((detail) => (
            <li key={`${detail.path}:${detail.message}`}>
              <strong>{detail.path}</strong>: {detail.message}
            </li>
          ))}
        </ul>
      )}
      {error.requestId !== null && (
        <p className="request-id">
          Request ID <code>{error.requestId}</code>
        </p>
      )}
      {props.onRetry !== undefined && (
        <button type="button" className="button" onClick={props.onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

interface FieldControlProps {
  id: string;
  'aria-describedby'?: string;
  'aria-invalid'?: true;
}

/** Label, hint and error wired to one control by id. */
export function Field(props: {
  label: string;
  hint?: ReactNode;
  error?: string | undefined;
  children: (control: FieldControlProps) => ReactNode;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [
    props.hint !== undefined ? hintId : null,
    props.error !== undefined ? errorId : null,
  ]
    .filter((value) => value !== null)
    .join(' ');

  const control: FieldControlProps = { id };
  if (describedBy !== '') control['aria-describedby'] = describedBy;
  if (props.error !== undefined) control['aria-invalid'] = true;

  return (
    <div className="field">
      <label htmlFor={id}>{props.label}</label>
      {props.children(control)}
      {props.hint !== undefined && (
        <p className="field-hint" id={hintId}>
          {props.hint}
        </p>
      )}
      {props.error !== undefined && (
        <p className="field-error" id={errorId}>
          {props.error}
        </p>
      )}
    </div>
  );
}

/** Horizontally scrollable, keyboard-reachable wrapper so wide tables never break the page. */
export function TableRegion({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="table-region" role="region" aria-label={label} tabIndex={0}>
      {children}
    </div>
  );
}

/**
 * Inline confirmation for an action that removes access. Focus moves here when it opens and
 * the safe choice (cancel) comes first.
 */
export function ConfirmPanel(props: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  pending: boolean;
  error?: unknown;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    panel.current?.focus();
  }, []);

  return (
    <div className="confirm" role="group" aria-labelledby={titleId} tabIndex={-1} ref={panel}>
      <p className="confirm-title" id={titleId}>
        {props.title}
      </p>
      <div className="confirm-body">{props.children}</div>
      {props.error !== undefined && props.error !== null && (
        <ErrorState title="That did not work" error={props.error} />
      )}
      <div className="button-row">
        <button type="button" className="button" onClick={props.onCancel} disabled={props.pending}>
          Cancel
        </button>
        <button
          type="button"
          className="button button-danger"
          onClick={props.onConfirm}
          disabled={props.pending}
        >
          {props.pending ? 'Working…' : props.confirmLabel}
        </button>
      </div>
    </div>
  );
}

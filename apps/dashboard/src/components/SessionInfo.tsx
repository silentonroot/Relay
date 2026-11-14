import type { Connection } from '@aab/contracts';
import { useEffect, useState } from 'react';
import { describeSessionExpiry, hasStoredSession } from '../lib/session.js';
import { Icon, Timestamp } from './ui.js';

/** The current time, refreshed so "expires in 3 hours" does not go stale on an open page. */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs]);
  return now;
}

/** Last verified time and estimated session expiry for one connection. */
export function SessionInfo({ connection }: { connection: Connection }) {
  const now = useNow();
  const expiry = describeSessionExpiry(connection.sessionExpiresAt, now);

  let expiryView;
  if (!hasStoredSession(connection.status)) {
    expiryView = <span className="muted">no session stored</span>;
  } else if (expiry.level === 'warn') {
    expiryView = (
      <span className="badge badge-warn">
        <Icon name="triangle" />
        {expiry.text}
      </span>
    );
  } else if (expiry.level === 'expired') {
    expiryView = (
      <span className="badge badge-danger">
        <Icon name="clock" />
        {expiry.text}
      </span>
    );
  } else if (expiry.level === 'none') {
    expiryView = <span className="muted">{expiry.text}</span>;
  } else {
    expiryView = <span>{expiry.text}</span>;
  }

  return (
    <dl className="session-facts">
      <div>
        <dt>Last verified</dt>
        <dd>
          <Timestamp iso={connection.lastVerifiedAt} />
        </dd>
      </div>
      <div>
        <dt>Session expiry (estimate)</dt>
        <dd title={connection.sessionExpiresAt ?? undefined}>{expiryView}</dd>
      </div>
    </dl>
  );
}

import { screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { describeSessionExpiry } from '../src/lib/session.js';
import { json, makeApplication, makeConnection, mockApi, page, renderApp } from './helpers.js';

const NOW = new Date('2026-03-02T10:00:00.000Z').getTime();
const at = (offsetMs: number) => new Date(NOW + offsetMs).toISOString();
const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;

describe('describeSessionExpiry', () => {
  it.each([
    [null, 'none', 'no expiry reported'],
    ['not a date', 'none', 'no expiry reported'],
    [at(-1), 'expired', 'expired'],
    [at(0), 'expired', 'expired'],
    [at(1), 'warn', 'expires in less than a minute'],
    [at(MINUTE - 1), 'warn', 'expires in less than a minute'],
    [at(MINUTE), 'warn', 'expires in 1 minute'],
    [at(2 * MINUTE + 30 * SECOND), 'warn', 'expires in 2 minutes'],
    [at(HOUR - 1), 'warn', 'expires in 59 minutes'],
    [at(HOUR), 'ok', 'expires in 1 hour'],
    [at(3 * HOUR + 20 * MINUTE), 'ok', 'expires in 3 hours'],
    [at(24 * HOUR - 1), 'ok', 'expires in 23 hours'],
    [at(24 * HOUR), 'ok', 'expires in 1 day'],
    [at(5 * 24 * HOUR), 'ok', 'expires in 5 days'],
  ] as const)('%s -> %s, %s', (iso, level, text) => {
    expect(describeSessionExpiry(iso, NOW)).toEqual({ level, text });
  });
});

describe('Session status on the connections page', () => {
  beforeEach(() => {
    // Only the clock is faked, so timers and network still run normally.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  function show(...overrides: Parameters<typeof makeConnection>[1][]) {
    const connections = overrides.map((o, index) => makeConnection(index + 1, o));
    mockApi({
      'GET /v1/connections': () => json(page(connections)),
      'GET /v1/applications': () => json(page([makeApplication(1)])),
    });
    renderApp('/connections');
  }

  it('shows account, last verified, expiry, and says the expiry is an estimate', async () => {
    show({
      displayName: 'Healthy',
      externalAccountHint: 'o***@example.test',
      lastVerifiedAt: at(-2 * HOUR),
      sessionExpiresAt: at(3 * HOUR + 5 * MINUTE),
    });
    const row = await screen.findByRole('row', { name: /Healthy/ });
    expect(within(row).getByText('o***@example.test')).toBeInTheDocument();
    expect(within(row).getByText('Last verified')).toBeInTheDocument();
    expect(within(row).getByText('expires in 3 hours')).toBeInTheDocument();
    expect(within(row).getByText('expires in 3 hours').closest('.badge')).toBeNull();
    expect(screen.getByText(/Session expiry is an estimate/)).toBeInTheDocument();
    expect(within(row).getByText('Session expiry (estimate)')).toBeInTheDocument();
  });

  it('warns with a badge when less than an hour remains, but not at exactly one hour', async () => {
    show(
      { displayName: 'Soon', sessionExpiresAt: at(HOUR - 1) },
      { displayName: 'Hour', sessionExpiresAt: at(HOUR) },
    );
    const soon = await screen.findByRole('row', { name: /Soon/ });
    const warning = within(soon).getByText('expires in 59 minutes');
    expect(warning.closest('.badge-warn')).not.toBeNull();
    expect(warning.closest('.badge')?.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');

    const hour = screen.getByRole('row', { name: /Hour/ });
    expect(within(hour).getByText('expires in 1 hour').closest('.badge')).toBeNull();
  });

  it('shows expired as a badge, and no expiry reported when the application gave none', async () => {
    show(
      { displayName: 'Gone', sessionExpiresAt: at(-MINUTE) },
      { displayName: 'Unknown', sessionExpiresAt: null },
    );
    const gone = await screen.findByRole('row', { name: /Gone/ });
    expect(within(gone).getByText('expired').closest('.badge-danger')).not.toBeNull();
    const unknown = screen.getByRole('row', { name: /Unknown/ });
    expect(within(unknown).getByText('no expiry reported')).toBeInTheDocument();
    expect(within(unknown).getByText('Never')).toBeInTheDocument();
  });

  it('shows no expiry for a connection that holds no session', async () => {
    show({
      displayName: 'Fresh',
      status: 'authentication_required',
      sessionExpiresAt: at(HOUR * 5),
    });
    const row = await screen.findByRole('row', { name: /Fresh/ });
    expect(within(row).getByText('no session stored')).toBeInTheDocument();
    expect(within(row).queryByText(/expires in/)).not.toBeInTheDocument();
  });
});

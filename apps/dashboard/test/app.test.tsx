import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { apiError, json, makeConnection, mockApi, page, renderApp, requestsTo } from './helpers.js';

const NAV_ORDER = [
  'Overview',
  'Applications',
  'Connections',
  'Vault',
  'Agents',
  'Policies',
  'Workflows',
  'Approvals',
  'Activity & Audit',
  'Settings',
];

describe('Navigation', () => {
  it('lists the ten sections in order, each with its own route', async () => {
    mockApi();
    const user = userEvent.setup();
    renderApp('/');
    const nav = await screen.findByRole('navigation', { name: 'Primary' });
    const links = within(nav).getAllByRole('link');
    expect(links.map((link) => link.querySelector('span')?.textContent)).toEqual(NAV_ORDER);
    expect(new Set(links.map((link) => link.getAttribute('href'))).size).toBe(10);

    await user.click(within(nav).getByRole('link', { name: /^Agents/ }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Agents' })).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: /^Agents/ })).toHaveAttribute(
      'aria-current',
      'page',
    );
  });

  it('marks the sections that have no backend yet', async () => {
    mockApi();
    renderApp('/');
    const nav = await screen.findByRole('navigation', { name: 'Primary' });
    const planned = within(nav)
      .getAllByText('Planned')
      .map((tag) => tag.previousElementSibling?.textContent);
    expect(planned).toEqual(['Vault', 'Policies', 'Workflows', 'Approvals', 'Settings']);
  });

  it('shows a not-found page for an unknown address inside the shell', async () => {
    mockApi();
    renderApp('/nowhere');
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Primary' })).toBeInTheDocument();
  });
});

describe('Not-yet-available sections', () => {
  const cases: [string, string, RegExp][] = [
    ['/vault', 'Vault', /Secret metadata and rotation.*never shown/],
    ['/policies', 'Policies', /Grant rules and a policy simulator/],
    ['/workflows', 'Workflows', /Multi-step runs/],
    ['/approvals', 'Approvals', /exact proposed actions awaiting a decision/],
    ['/settings', 'Settings', /Local identity, key status, worker health and retention/],
  ];

  it.each(cases)('%s says plainly that it is not available yet', async (path, title, summary) => {
    const log = mockApi();
    renderApp(path);
    expect(await screen.findByRole('heading', { level: 1, name: title })).toBeInTheDocument();
    expect(screen.getByText(summary)).toBeInTheDocument();
    expect(screen.getByText('Not available yet')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'What will live here' })).toBeInTheDocument();
    // No data is fetched or invented for these pages.
    expect(log.map((request) => request.path)).toEqual(['/v1/auth/session']);
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });
});

describe('Overview', () => {
  it('summarises counts and connection statuses', async () => {
    mockApi({
      'GET /v1/connections': () =>
        json(
          page([makeConnection(1, { status: 'active' }), makeConnection(2, { status: 'revoked' })]),
        ),
    });
    renderApp('/');
    const stat = (await screen.findByRole('heading', { name: 'Connections' })).closest('section');
    expect(stat).not.toBeNull();
    expect(await within(stat as HTMLElement).findByText('Connected')).toBeInTheDocument();
    expect(within(stat as HTMLElement).getByText('Revoked')).toBeInTheDocument();
    expect(await screen.findByText('Operational')).toBeInTheDocument();
  });
});

describe('Session expiry', () => {
  it('returns to sign-in and clears cached data when any call answers 401', async () => {
    let expired = false;
    const log = mockApi({
      'GET /v1/connections': () =>
        expired
          ? apiError(401, 'unauthenticated', 'Session ended.')
          : json(page([makeConnection(1, { displayName: 'Secret-ish name' })])),
    });
    const user = userEvent.setup();
    const { queryClient } = renderApp('/connections');
    expect(await screen.findByText('Secret-ish name')).toBeInTheDocument();
    expect(queryClient.getQueryCache().getAll().length).toBeGreaterThan(0);

    // The session dies server-side; the next request the dashboard makes is refused.
    expired = true;
    await user.click(screen.getByRole('link', { name: /^Agents/ }));
    await user.click(screen.getByRole('link', { name: /^Connections/ }));
    await queryClient.invalidateQueries({ queryKey: ['connections'] });

    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.getByText('Your session ended. Sign in again to continue.')).toBeInTheDocument();
    expect(screen.queryByText('Secret-ish name')).not.toBeInTheDocument();
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(requestsTo(log, 'GET', '/v1/connections').length).toBeGreaterThan(1);
  });

  it('signs out through the API and shows the sign-in page', async () => {
    const log = mockApi({
      'POST /v1/auth/logout': () => new Response(null, { status: 204 }),
    });
    const user = userEvent.setup();
    renderApp('/');
    await user.click(await screen.findByRole('button', { name: 'Sign out' }));
    expect(await screen.findByText('You have signed out.')).toBeInTheDocument();
    const [logout] = requestsTo(log, 'POST', '/v1/auth/logout');
    expect(logout?.headers.get('x-csrf-token')).toBe('csrf-test-token');
  });
});

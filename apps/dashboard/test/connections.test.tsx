import type { Connection } from '@aab/contracts';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { CONNECTION_STATUS } from '../src/lib/status.js';
import {
  ALL_CONNECTION_STATUSES,
  CSRF_TOKEN,
  json,
  makeApplication,
  makeConnection,
  mockApi,
  page,
  renderApp,
  requestsTo,
  uuid,
} from './helpers.js';

describe('Connections list', () => {
  it('shows each of the eight statuses with its own text and its own icon shape', async () => {
    const connections = ALL_CONNECTION_STATUSES.map((status, index) =>
      makeConnection(index + 1, { status, displayName: `Account ${status}` }),
    );
    mockApi({
      'GET /v1/connections': () => json(page(connections)),
      'GET /v1/applications': () => json(page([makeApplication(1)])),
      [`GET /v1/connections/${connections[2]?.id}`]: () => json(connections[2]),
    });
    renderApp('/connections');

    const table = await screen.findByRole('table');
    const labels = ALL_CONNECTION_STATUSES.map((status) => CONNECTION_STATUS[status].label);
    expect(new Set(labels).size).toBe(8);

    const shapes = new Set<string>();
    for (const status of ALL_CONNECTION_STATUSES) {
      const label = CONNECTION_STATUS[status].label;
      // The sign-in panel of the one connection that is signing in sits in its own row.
      const [row = table] = within(table).getAllByRole('row', {
        name: new RegExp(`Account ${status}`),
      });
      // Exact match: "Connected" must not also match "Connected, degraded".
      const badge = within(row).getByText(label, { exact: true, selector: '.badge' });
      expect(badge).toBeVisible();
      const icon = badge.querySelector('svg');
      expect(icon).not.toBeNull();
      // The icon is decoration; the label is what assistive technology reads.
      expect(icon).toHaveAttribute('aria-hidden', 'true');
      shapes.add(icon?.innerHTML ?? '');
    }
    expect(shapes.size).toBe(8);
  });

  it('shows the server status reason, or a plain description when there is none', async () => {
    mockApi({
      'GET /v1/connections': () =>
        json(
          page([
            makeConnection(1, {
              status: 'degraded',
              statusReason: 'Three health checks failed.',
              displayName: 'With reason',
            }),
            makeConnection(2, { status: 'expired', displayName: 'No reason' }),
          ]),
        ),
      'GET /v1/applications': () => json(page([makeApplication(1)])),
    });
    renderApp('/connections');
    expect(await screen.findByText('Three health checks failed.')).toBeInTheDocument();
    expect(screen.getByText(CONNECTION_STATUS.expired.description)).toBeInTheDocument();
  });
});

describe('Create connection', () => {
  it('posts the chosen application, name and hint with the CSRF header', async () => {
    const app = makeApplication(1, { name: 'Northstar' });
    const created = makeConnection(7, {
      displayName: 'Northstar primary',
      status: 'created',
      applicationId: app.id,
    });
    let connections: Connection[] = [];
    const log = mockApi({
      'GET /v1/connections': () => json(page(connections)),
      'GET /v1/applications': () => json(page([app])),
      'POST /v1/connections': () => {
        connections = [created];
        return json(created, 201);
      },
    });
    const user = userEvent.setup();
    renderApp('/connections');

    await user.click(await screen.findByRole('button', { name: 'New connection' }));
    await user.selectOptions(await screen.findByLabelText('Application'), app.id);
    await user.type(screen.getByLabelText('Display name'), 'Northstar primary');
    await user.type(screen.getByLabelText('Account hint (optional)'), 'o***@example.test');
    await user.click(screen.getByRole('button', { name: 'Create connection' }));

    expect(await screen.findByText('Connection “Northstar primary” created.')).toBeInTheDocument();
    const [post] = requestsTo(log, 'POST', '/v1/connections');
    expect(post?.body).toEqual({
      applicationId: app.id,
      displayName: 'Northstar primary',
      externalAccountHint: 'o***@example.test',
    });
    expect(post?.headers.get('x-csrf-token')).toBe(CSRF_TOKEN);
    // The list reloads and the new connection appears, with its "never signed in" status.
    expect(await screen.findByRole('row', { name: /Northstar primary/ })).toBeInTheDocument();
    expect(screen.getByText('Not signed in', { selector: '.badge' })).toBeInTheDocument();
  });

  it('omits the hint when left empty and refuses a missing application client-side', async () => {
    const app = makeApplication(1);
    const log = mockApi({
      'GET /v1/applications': () => json(page([app])),
      'POST /v1/connections': () => json(makeConnection(8, { status: 'created' }), 201),
    });
    const user = userEvent.setup();
    renderApp('/connections');
    await user.click(await screen.findByRole('button', { name: 'New connection' }));
    await user.type(await screen.findByLabelText('Display name'), 'Plain');

    await user.click(screen.getByRole('button', { name: 'Create connection' }));
    expect(screen.getByText('Choose an application.')).toBeInTheDocument();
    expect(requestsTo(log, 'POST', '/v1/connections')).toHaveLength(0);

    await user.selectOptions(screen.getByLabelText('Application'), app.id);
    await user.click(screen.getByRole('button', { name: 'Create connection' }));
    await waitFor(() => expect(requestsTo(log, 'POST', '/v1/connections')).toHaveLength(1));
    expect(requestsTo(log, 'POST', '/v1/connections')[0]?.body).toEqual({
      applicationId: app.id,
      displayName: 'Plain',
    });
  });
});

describe('Revoke connection', () => {
  const target = makeConnection(3, { displayName: 'Northstar primary', status: 'active' });

  it('asks for confirmation first, and cancelling sends nothing', async () => {
    const log = mockApi({
      'GET /v1/connections': () => json(page([target])),
      'GET /v1/applications': () => json(page([makeApplication(1)])),
    });
    const user = userEvent.setup();
    renderApp('/connections');

    await user.click(await screen.findByRole('button', { name: 'Revoke Northstar primary' }));
    const confirm = await screen.findByRole('group', { name: /Revoke “Northstar primary”\?/ });
    expect(confirm).toHaveTextContent('This cannot be undone');
    expect(requestsTo(log, 'POST', `/v1/connections/${target.id}/revoke`)).toHaveLength(0);

    await user.click(within(confirm).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('group', { name: /Revoke/ })).not.toBeInTheDocument();
    expect(log.some((request) => request.method === 'POST')).toBe(false);
  });

  it('posts the reason to the revoke endpoint only after confirmation', async () => {
    let current = target;
    const log = mockApi({
      'GET /v1/connections': () => json(page([current])),
      'GET /v1/applications': () => json(page([makeApplication(1)])),
      [`POST /v1/connections/${target.id}/revoke`]: () => {
        current = { ...target, status: 'revoked' };
        return json(current);
      },
    });
    const user = userEvent.setup();
    renderApp('/connections');

    await user.click(await screen.findByRole('button', { name: 'Revoke Northstar primary' }));
    const confirm = await screen.findByRole('group', { name: /Revoke/ });
    await user.type(within(confirm).getByLabelText(/Reason/), 'Left the company');
    await user.click(within(confirm).getByRole('button', { name: 'Revoke connection' }));

    expect(await screen.findByText('Connection “Northstar primary” revoked.')).toBeInTheDocument();
    const posts = requestsTo(log, 'POST', `/v1/connections/${target.id}/revoke`);
    expect(posts).toHaveLength(1);
    expect(posts[0]?.body).toEqual({ reason: 'Left the company' });
    expect(posts[0]?.headers.get('x-csrf-token')).toBe(CSRF_TOKEN);

    // The list reloads; a revoked connection shows its status and offers no further revoke.
    expect(await screen.findByText('Revoked', { selector: '.badge' })).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Revoke Northstar primary' }),
    ).not.toBeInTheDocument();
  });

  it('sends an empty body when no reason is given', async () => {
    const log = mockApi({
      'GET /v1/connections': () => json(page([target])),
      'GET /v1/applications': () => json(page([makeApplication(1)])),
      [`POST /v1/connections/${target.id}/revoke`]: () => json({ ...target, status: 'revoked' }),
    });
    const user = userEvent.setup();
    renderApp('/connections');
    await user.click(await screen.findByRole('button', { name: 'Revoke Northstar primary' }));
    await user.click(await screen.findByRole('button', { name: 'Revoke connection' }));
    await waitFor(() =>
      expect(requestsTo(log, 'POST', `/v1/connections/${target.id}/revoke`)).toHaveLength(1),
    );
    expect(requestsTo(log, 'POST', `/v1/connections/${target.id}/revoke`)[0]?.body).toEqual({});
    expect(uuid(3)).toBeTruthy();
  });
});

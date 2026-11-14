import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { buildGrantRequest, EMPTY_GRANT_FORM } from '../src/lib/forms.js';
import {
  apiError,
  CSRF_TOKEN,
  json,
  makeAgent,
  makeConnection,
  makeGrant,
  mockApi,
  page,
  renderApp,
  requestsTo,
} from './helpers.js';
import type { Handlers } from './helpers.js';

const agent = makeAgent(1, { name: 'Order assistant' });
const connection = makeConnection(1, { displayName: 'Northstar primary' });

function agentHandlers(grants = [makeGrant(1)]): Handlers {
  return {
    [`GET /v1/agents/${agent.id}`]: () => json(agent),
    [`GET /v1/agents/${agent.id}/grants`]: () => json(page(grants)),
    'GET /v1/connections': () => json(page([connection])),
  };
}

async function openForm() {
  const user = userEvent.setup();
  await user.click(await screen.findByRole('button', { name: 'Add grant' }));
  const form = await screen.findByRole('form', { name: 'Add grant' });
  await user.selectOptions(within(form).getByLabelText('Connection'), connection.id);
  return { user, form };
}

describe('Agent grant form', () => {
  it('lists existing grants with their constraints in plain language', async () => {
    mockApi(
      agentHandlers([makeGrant(1, { constraints: { maxResults: 25, resourceIds: ['a1', 'b2'] } })]),
    );
    renderApp(`/agents/${agent.id}`);
    const table = await screen.findByRole('table');
    expect(within(table).getByText('orders.list')).toBeInTheDocument();
    expect(within(table).getByText('At most 25 results per call')).toBeInTheDocument();
    expect(within(table).getByText('Only resources a1, b2')).toBeInTheDocument();
    expect(within(table).getByText('In force')).toBeInTheDocument();
  });

  it('rejects an invalid operation name client-side', async () => {
    const log = mockApi(agentHandlers());
    renderApp(`/agents/${agent.id}`);
    const { user, form } = await openForm();

    await user.type(within(form).getByLabelText('Operation'), 'Orders List');
    await user.click(within(form).getByRole('button', { name: 'Add grant' }));

    expect(within(form).getByText(/expected a dotted name such as "orders\.list"/)).toBeVisible();
    expect(within(form).getByLabelText('Operation')).toBeInvalid();
    expect(requestsTo(log, 'POST', `/v1/agents/${agent.id}/grants`)).toHaveLength(0);
  });

  it('rejects a wildcard operation', async () => {
    const log = mockApi(agentHandlers());
    renderApp(`/agents/${agent.id}`);
    const { user, form } = await openForm();
    await user.type(within(form).getByLabelText('Operation'), 'orders.*');
    await user.click(within(form).getByRole('button', { name: 'Add grant' }));
    expect(within(form).getByLabelText('Operation')).toBeInvalid();
    expect(requestsTo(log, 'POST', `/v1/agents/${agent.id}/grants`)).toHaveLength(0);
  });

  it('rejects an unknown constraint key client-side', async () => {
    const log = mockApi(agentHandlers());
    renderApp(`/agents/${agent.id}`);
    const { user, form } = await openForm();

    await user.type(within(form).getByLabelText('Operation'), 'orders.list');
    const rules = within(form).getByLabelText(/Argument rules/);
    await user.click(rules);
    await user.paste('{"maxRows": 5}');
    await user.click(within(form).getByRole('button', { name: 'Add grant' }));

    expect(within(form).getByText(/Unrecognized key/i)).toBeVisible();
    expect(rules).toBeInvalid();
    expect(requestsTo(log, 'POST', `/v1/agents/${agent.id}/grants`)).toHaveLength(0);
  });

  it('rejects argument rules that are not a JSON object', async () => {
    const log = mockApi(agentHandlers());
    renderApp(`/agents/${agent.id}`);
    const { user, form } = await openForm();
    await user.type(within(form).getByLabelText('Operation'), 'orders.list');
    await user.click(within(form).getByLabelText(/Argument rules/));
    await user.paste('not json');
    await user.click(within(form).getByRole('button', { name: 'Add grant' }));
    expect(within(form).getByText(/Enter a JSON object/)).toBeVisible();
    expect(requestsTo(log, 'POST', `/v1/agents/${agent.id}/grants`)).toHaveLength(0);
  });

  it('posts a valid grant to the agent grants endpoint', async () => {
    const created = makeGrant(2, {
      operation: 'orders.list',
      approvalMode: 'required',
      constraints: { maxResults: 25, resourceIds: ['a1', 'b2'] },
    });
    const log = mockApi({
      ...agentHandlers(),
      [`POST /v1/agents/${agent.id}/grants`]: () => json(created, 201),
    });
    renderApp(`/agents/${agent.id}`);
    const { user, form } = await openForm();

    await user.type(within(form).getByLabelText('Operation'), ' orders.list ');
    await user.click(within(form).getByLabelText('Require my approval for each action'));
    await user.type(within(form).getByLabelText(/Result limit/), '25');
    await user.type(within(form).getByLabelText(/Resource IDs/), 'a1, b2');
    await user.click(within(form).getByLabelText(/Argument rules/));
    await user.paste('{"argumentEquals": {"status": "held"}}');
    await user.click(within(form).getByRole('button', { name: 'Add grant' }));

    expect(await screen.findByText('Allow grant for orders.list added.')).toBeInTheDocument();
    const [post] = requestsTo(log, 'POST', `/v1/agents/${agent.id}/grants`);
    expect(post?.body).toEqual({
      connectionId: connection.id,
      operation: 'orders.list',
      effect: 'allow',
      approvalMode: 'required',
      constraints: {
        argumentEquals: { status: 'held' },
        maxResults: 25,
        resourceIds: ['a1', 'b2'],
      },
    });
    expect(post?.headers.get('x-csrf-token')).toBe(CSRF_TOKEN);
  });

  it('surfaces a server-side validation failure with its request id', async () => {
    mockApi({
      ...agentHandlers(),
      [`POST /v1/agents/${agent.id}/grants`]: () =>
        apiError(409, 'conflict', 'A grant for this operation already exists.', 'req_conflict'),
    });
    renderApp(`/agents/${agent.id}`);
    const { user, form } = await openForm();
    await user.type(within(form).getByLabelText('Operation'), 'orders.list');
    await user.click(within(form).getByRole('button', { name: 'Add grant' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('A grant for this operation already exists.');
    expect(alert).toHaveTextContent('req_conflict');
    await waitFor(() => expect(form).toBeInTheDocument());
  });

  it('revokes a grant with DELETE only after confirmation', async () => {
    const grant = makeGrant(1);
    const log = mockApi({
      ...agentHandlers([grant]),
      [`DELETE /v1/agents/${agent.id}/grants/${grant.id}`]: () =>
        new Response(null, { status: 204 }),
    });
    const user = userEvent.setup();
    renderApp(`/agents/${agent.id}`);
    await user.click(await screen.findByRole('button', { name: 'Revoke grant for orders.list' }));
    expect(log.some((request) => request.method === 'DELETE')).toBe(false);
    await user.click(await screen.findByRole('button', { name: 'Revoke grant' }));
    await screen.findByText('Grant for orders.list revoked.');
    const [del] = requestsTo(log, 'DELETE', `/v1/agents/${agent.id}/grants/${grant.id}`);
    expect(del?.headers.get('x-csrf-token')).toBe(CSRF_TOKEN);
    expect(del?.body).toBeUndefined();
  });
});

describe('buildGrantRequest', () => {
  const base = { ...EMPTY_GRANT_FORM, connectionId: connection.id, operation: 'orders.list' };
  const now = new Date('2026-03-02T10:00:00Z');

  it('forces approval off for deny grants', () => {
    const result = buildGrantRequest({ ...base, effect: 'deny', requireApproval: true }, now);
    expect(result).toMatchObject({
      ok: true,
      request: { effect: 'deny', approvalMode: 'none' },
    });
  });

  it('refuses an expiry in the past and a limit set twice', () => {
    const past = buildGrantRequest({ ...base, expiresAt: '2020-01-01T00:00' }, now);
    expect(past).toMatchObject({
      ok: false,
      errors: { expiresAt: 'Choose a time in the future.' },
    });
    const twice = buildGrantRequest(
      { ...base, maxResults: '5', extraConstraints: '{"maxResults": 3}' },
      now,
    );
    expect(twice.ok).toBe(false);
  });

  it('refuses a limit that is not a whole positive number', () => {
    for (const maxResults of ['0', '-1', '2.5', 'abc']) {
      expect(buildGrantRequest({ ...base, maxResults }, now).ok).toBe(false);
    }
  });
});

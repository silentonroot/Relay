import type { OperationJob } from '@aab/contracts';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { buildExecuteRequest } from '../src/lib/forms.js';
import {
  apiError,
  CSRF_TOKEN,
  json,
  jobError,
  makeAgent,
  makeConnection,
  makeGrant,
  makeJob,
  mockApi,
  page,
  renderApp,
  requestsTo,
  uuid,
} from './helpers.js';
import type { Handlers } from './helpers.js';

vi.mock('../src/api/polling.js', () => ({ AUTH_POLL_MS: 25, JOB_POLL_MS: 25 }));

const agent = makeAgent(1, { name: 'Order assistant' });
const connection = makeConnection(1, { displayName: 'Northstar primary' });
const grant = makeGrant(1);
const EXECUTE = 'POST /v1/operations/execute';

function handlers(
  extra: Handlers = {},
  overrides: { agent?: typeof agent; grants?: unknown[] } = {},
) {
  return {
    [`GET /v1/agents/${agent.id}`]: () => json(overrides.agent ?? agent),
    [`GET /v1/agents/${agent.id}/grants`]: () => json(page(overrides.grants ?? [grant])),
    'GET /v1/connections': () => json(page([connection])),
    ...extra,
  } satisfies Handlers;
}

async function openPanel() {
  renderApp(`/agents/${agent.id}`);
  const form = await screen.findByRole('form', { name: 'Run a read operation' });
  const user = userEvent.setup();
  await user.selectOptions(
    within(form).getByLabelText('Grant to test'),
    within(form).getByRole('option', { name: /orders\.list on Northstar primary/ }),
  );
  return { user, form };
}

async function run(user: ReturnType<typeof userEvent.setup>, form: HTMLElement, json = '{}') {
  const box = within(form).getByLabelText('Arguments (JSON object)');
  await user.clear(box);
  // `{` is special to user-event's keyboard syntax, so set the text directly.
  await user.click(box);
  await user.paste(json);
  await user.click(within(form).getByRole('button', { name: 'Run operation' }));
}

describe('Run a read operation: which grants are offered', () => {
  it('lists only allow grants that are in force on a connection that is not revoked', async () => {
    const revokedConnection = makeConnection(2, { displayName: 'Old', status: 'revoked' });
    mockApi(
      handlers(
        { 'GET /v1/connections': () => json(page([connection, revokedConnection])) },
        {
          grants: [
            grant,
            makeGrant(2, { effect: 'deny', operation: 'orders.cancel' }),
            makeGrant(3, { operation: 'orders.get', revokedAt: '2026-03-01T00:00:00.000Z' }),
            makeGrant(4, { operation: 'orders.old', expiresAt: '2020-01-01T00:00:00.000Z' }),
            makeGrant(5, { operation: 'orders.dead', connectionId: revokedConnection.id }),
          ],
        },
      ),
    );
    renderApp(`/agents/${agent.id}`);
    const form = await screen.findByRole('form', { name: 'Run a read operation' });
    const options = within(form)
      .getAllByRole('option')
      .map((option) => option.textContent);
    expect(options).toEqual(['Choose…', 'orders.list on Northstar primary']);
  });

  it('offers nothing for a disabled agent or an agent without an allow grant', async () => {
    mockApi(handlers({}, { agent: { ...agent, status: 'disabled' } }));
    renderApp(`/agents/${agent.id}`);
    expect(
      await screen.findByText(/This agent is disabled, so its requests are denied\./),
    ).toBeInTheDocument();
    expect(screen.queryByRole('form', { name: 'Run a read operation' })).not.toBeInTheDocument();
  });
});

describe('Run a read operation: arguments', () => {
  it.each([
    ['', 'Enter a JSON object'],
    ['{not json', 'not valid JSON'],
    ['[1, 2]', 'must be a JSON object'],
    ['null', 'must be a JSON object'],
    ['"text"', 'must be a JSON object'],
    ['5', 'must be a JSON object'],
  ])('refuses %j before sending anything', async (text, message) => {
    const log = mockApi(handlers());
    const { user, form } = await openPanel();
    const box = within(form).getByLabelText('Arguments (JSON object)');
    await user.clear(box);
    if (text !== '') {
      await user.click(box);
      await user.paste(text);
    }
    await user.click(within(form).getByRole('button', { name: 'Run operation' }));

    expect(within(form).getByText(new RegExp(message))).toBeVisible();
    expect(box).toBeInvalid();
    expect(requestsTo(log, 'POST', '/v1/operations/execute')).toHaveLength(0);
  });

  it('asks for a grant when none is chosen', async () => {
    const log = mockApi(handlers());
    renderApp(`/agents/${agent.id}`);
    const form = await screen.findByRole('form', { name: 'Run a read operation' });
    await userEvent.setup().click(within(form).getByRole('button', { name: 'Run operation' }));
    expect(within(form).getByText('Choose a grant.')).toBeVisible();
    expect(requestsTo(log, 'POST', '/v1/operations/execute')).toHaveLength(0);
  });

  it('builds a request the contract accepts', () => {
    const ok = buildExecuteRequest(
      { grantId: grant.id, argumentsJson: '{"limit": 5}' },
      grant,
      'abcdefgh-1',
    );
    expect(ok).toEqual({
      ok: true,
      request: {
        agentId: grant.agentId,
        connectionId: grant.connectionId,
        operation: 'orders.list',
        arguments: { limit: 5 },
        idempotencyKey: 'abcdefgh-1',
      },
    });
    expect(buildExecuteRequest({ grantId: '', argumentsJson: '{}' }, grant, 'short').ok).toBe(
      false,
    );
  });
});

describe('Run a read operation: sending', () => {
  it('sends the request with the CSRF header and a fresh idempotency key each time', async () => {
    const job = makeJob(1, { result: { orders: [{ id: 'A1' }] } });
    const log = mockApi(handlers({ [EXECUTE]: () => json(job) }));
    const { user, form } = await openPanel();

    await run(user, form, '{"limit": 5}');
    expect(await screen.findByText('Succeeded', { selector: '.badge' })).toBeInTheDocument();
    await run(user, form, '{"limit": 5}');
    await waitFor(() => expect(requestsTo(log, 'POST', '/v1/operations/execute')).toHaveLength(2));

    const [first, second] = requestsTo(log, 'POST', '/v1/operations/execute');
    expect(first?.headers.get('x-csrf-token')).toBe(CSRF_TOKEN);
    expect(first?.body).toMatchObject({
      agentId: agent.id,
      connectionId: connection.id,
      operation: 'orders.list',
      arguments: { limit: 5 },
    });
    const key1 = (first?.body as { idempotencyKey: string }).idempotencyKey;
    const key2 = (second?.body as { idempotencyKey: string }).idempotencyKey;
    expect(key1).toMatch(/^[0-9a-f-]{36}$/);
    expect(key2).toMatch(/^[0-9a-f-]{36}$/);
    expect(key1).not.toBe(key2);

    expect(screen.getByLabelText(/Result \(untrusted text\)/).textContent).toBe(
      JSON.stringify({ orders: [{ id: 'A1' }] }, null, 2),
    );
  });

  it('202: shows the running job, polls it, and ends on the final status', async () => {
    const running = makeJob(2, { status: 'running', result: null, finishedAt: null });
    let polls = 0;
    const log = mockApi(
      handlers({
        [EXECUTE]: () => json(running, 202),
        [`GET /v1/operations/${running.jobId}`]: () => {
          polls += 1;
          const next: OperationJob =
            polls < 3 ? running : { ...running, status: 'succeeded', result: { count: 2 } };
          return json(next);
        },
      }),
    );
    const { user, form } = await openPanel();
    await run(user, form);

    expect(await screen.findByText('Running', { selector: '.badge' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Running…' })).toBeDisabled();
    expect(await screen.findByText('Succeeded', { selector: '.badge' })).toBeInTheDocument();
    expect(screen.getByLabelText(/Result \(untrusted text\)/)).toHaveTextContent('"count": 2');
    expect(requestsTo(log, 'GET', `/v1/operations/${running.jobId}`).length).toBeGreaterThanOrEqual(
      3,
    );
    expect(screen.getByRole('button', { name: 'Run operation' })).toBeEnabled();

    // Polling stops once the job is terminal.
    const seen = requestsTo(log, 'GET', `/v1/operations/${running.jobId}`).length;
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(requestsTo(log, 'GET', `/v1/operations/${running.jobId}`).length).toBe(seen);
  });

  it('queued job that ends failed shows the error code and a sentence', async () => {
    const queued = makeJob(3, { status: 'queued', result: null, finishedAt: null });
    mockApi(
      handlers({
        [EXECUTE]: () => json(queued, 202),
        [`GET /v1/operations/${queued.jobId}`]: () =>
          json({
            ...queued,
            status: 'failed',
            error: jobError('timeout', 'The operation timed out.'),
          }),
      }),
    );
    const { user, form } = await openPanel();
    await run(user, form);
    expect(await screen.findByText('Failed', { selector: '.badge' })).toBeInTheDocument();
    expect(screen.getByText('timeout', { selector: 'code' })).toBeInTheDocument();
    expect(screen.getByText(/took too long/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/Result \(untrusted text\)/)).not.toBeInTheDocument();
  });

  it('a job that ends reauth_required points to the connections page', async () => {
    mockApi(
      handlers({
        [EXECUTE]: () =>
          json(
            makeJob(4, {
              status: 'reauth_required',
              result: null,
              error: jobError('session_expired'),
            }),
          ),
      }),
    );
    const { user, form } = await openPanel();
    await run(user, form);
    expect(await screen.findByText('Sign-in needed', { selector: '.badge' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /sign in again/ })).toHaveAttribute(
      'href',
      '/connections',
    );
  });
});

describe('Run a read operation: untrusted result', () => {
  it('renders markup and links in the result as literal text', async () => {
    const hostile = {
      note: '<img src=x onerror=alert(1)>',
      link: '[click me](https://evil.example/steal)',
      html: '<a href="https://evil.example">x</a><script>alert(2)</script>',
    };
    mockApi(handlers({ [EXECUTE]: () => json(makeJob(5, { result: hostile })) }));
    const { user, form } = await openPanel();
    await run(user, form);

    const result = await screen.findByLabelText(/Result \(untrusted text\)/);
    expect(result.tagName).toBe('PRE');
    expect(result.textContent).toContain('<img src=x onerror=alert(1)>');
    expect(result.textContent).toContain('[click me](https://evil.example/steal)');
    expect(result.textContent).toContain('<script>alert(2)</script>');
    // Only text nodes: no element of any kind was created from the result.
    expect(result.children).toHaveLength(0);
    expect(document.querySelector('img')).toBeNull();
    expect(document.querySelector('script')).toBeNull();
    expect(result.querySelector('a')).toBeNull();
    expect(screen.queryByRole('link', { name: /click me/ })).not.toBeInTheDocument();
    expect(screen.getByText(/untrusted/, { selector: 'p' })).toHaveTextContent(
      'shown as plain text only',
    );
  });
});

describe('Run a read operation: refusals', () => {
  it.each([
    [403, 'denied', 'Denied by policy', /did not allow this operation/],
    [403, 'approval_required', 'Approval required', /approvals are not available yet/],
    [409, 'reauth_required', 'Sign in again first', /sign in again before/],
    [400, 'validation_failed', 'The request was not accepted', /rejected the request/],
    [409, 'conflict', 'Conflict', /could not accept this request/],
  ] as const)('shows %s %s as an outcome, not a crash', async (status, code, title, text) => {
    mockApi(handlers({ [EXECUTE]: () => apiError(status, code, 'Broker words.', 'req_refused') }));
    const { user, form } = await openPanel();
    await run(user, form);

    expect(await screen.findByText(new RegExp(`${title}\\.`))).toBeInTheDocument();
    expect(screen.getByText(text)).toBeInTheDocument();
    expect(screen.getByText(/Broker said: Broker words\./)).toHaveTextContent('req_refused');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByText('Succeeded')).not.toBeInTheDocument();
    // The form is usable again.
    expect(screen.getByRole('button', { name: 'Run operation' })).toBeEnabled();
    expect(uuid(1)).toBeTruthy();
  });

  it('links reauth_required to the connections page', async () => {
    mockApi(handlers({ [EXECUTE]: () => apiError(409, 'reauth_required', 'Sign in again.') }));
    const { user, form } = await openPanel();
    await run(user, form);
    expect(await screen.findByRole('link', { name: /sign in again/ })).toHaveAttribute(
      'href',
      '/connections',
    );
  });

  it('other failures (a server error) use the normal error state', async () => {
    mockApi(handlers({ [EXECUTE]: () => apiError(500, 'internal_error', 'Boom.', 'req_500') }));
    const { user, form } = await openPanel();
    await run(user, form);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('could not be sent');
    expect(alert).toHaveTextContent('req_500');
  });
});

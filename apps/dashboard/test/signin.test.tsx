import type { Connection } from '@aab/contracts';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { JOB_ERROR_TEXT } from '../src/lib/jobs.js';
import {
  apiError,
  ALL_CONNECTION_STATUSES,
  CSRF_TOKEN,
  json,
  jobError,
  makeApplication,
  makeAuthResponse,
  makeConnection,
  mockApi,
  page,
  renderApp,
  requestsTo,
} from './helpers.js';
import type { Handlers } from './helpers.js';

// Poll quickly so the tests do not wait for the real two-second interval.
vi.mock('../src/api/polling.js', () => ({ AUTH_POLL_MS: 25, JOB_POLL_MS: 25 }));

const base = makeConnection(1, {
  displayName: 'Northstar primary',
  status: 'authentication_required',
  externalAccountHint: null,
});
const startPath = `/v1/connections/${base.id}/auth/start`;
const completePath = `/v1/connections/${base.id}/auth/complete`;
const onePath = `/v1/connections/${base.id}`;

/** A fake broker whose one connection moves when the auth routes are called. */
function broker(initial: Connection, extra: Handlers = {}) {
  const state = { current: initial };
  const handlers: Handlers = {
    'GET /v1/applications': () => json(page([makeApplication(1)])),
    'GET /v1/connections': () => json(page([state.current])),
    [`GET ${onePath}`]: () => json(state.current),
    ...extra,
  };
  return { state, handlers };
}

const authenticating = { ...base, status: 'authenticating' as const };

describe('Sign in action', () => {
  it('is offered for a new connection and where the lifecycle allows authenticating', async () => {
    const connections = ALL_CONNECTION_STATUSES.map((status, index) =>
      makeConnection(index + 1, { status, displayName: `Account ${status}` }),
    );
    mockApi({
      'GET /v1/connections': () => json(page(connections)),
      'GET /v1/applications': () => json(page([makeApplication(1)])),
      [`GET /v1/connections/${connections[2]?.id}`]: () => json(connections[2]),
    });
    renderApp('/connections');
    await screen.findByRole('table');

    const offered = ALL_CONNECTION_STATUSES.filter(
      (status) =>
        screen.queryByRole('button', {
          name: new RegExp(`^Sign in( again)? to Account ${status}$`),
        }) !== null,
    );
    expect(offered).toEqual([
      'created',
      'authentication_required',
      'expired',
      'reconnect_required',
    ]);
    expect(
      screen.getByRole('button', { name: 'Sign in to Account authentication_required' }),
    ).toHaveTextContent(/^Sign in$/);
    expect(
      screen.getByRole('button', { name: 'Sign in again to Account expired' }),
    ).toHaveTextContent(/^Sign in again$/);
    expect(
      screen.getByRole('button', { name: 'Sign in again to Account reconnect_required' }),
    ).toHaveTextContent(/^Sign in again$/);
  });
});

describe('Login handoff', () => {
  it('starts, explains the window, and offers no cancel button', async () => {
    const { state, handlers } = broker(base, {
      [`POST ${startPath}`]: () => {
        state.current = authenticating;
        return json(makeAuthResponse(authenticating));
      },
    });
    const log = mockApi(handlers);
    const user = userEvent.setup();
    renderApp('/connections');

    await user.click(await screen.findByRole('button', { name: 'Sign in to Northstar primary' }));

    const panel = await screen.findByRole('group', { name: /Sign in to “Northstar primary”/ });
    expect(panel).toHaveTextContent('on this computer');
    expect(panel).toHaveTextContent('The broker never sees what you type');
    expect(panel).toHaveTextContent('There is no cancel button yet');
    expect(panel).toHaveTextContent('close the sign-in window');
    expect(within(panel).queryByRole('button', { name: /cancel/i })).not.toBeInTheDocument();
    expect(within(panel).getByRole('button', { name: 'I’ve signed in' })).toBeEnabled();

    const [post] = requestsTo(log, 'POST', startPath);
    expect(post?.headers.get('x-csrf-token')).toBe(CSRF_TOKEN);
    expect(post?.body).toBeUndefined();
    // The row shows the new status, and the sign-in button is replaced by the panel.
    expect(screen.getAllByText('Signing in', { selector: '.badge' })).toHaveLength(1);
    expect(screen.queryByRole('button', { name: /^Sign in to/ })).not.toBeInTheDocument();
    // While authenticating, the connection is polled.
    await waitFor(() => expect(requestsTo(log, 'GET', onePath).length).toBeGreaterThan(0));
  });

  it('completes with success: connected, account shown, nothing else to press', async () => {
    const connected = {
      ...base,
      status: 'active' as const,
      externalAccountHint: 'o***@example.test',
    };
    const { state, handlers } = broker(base, {
      [`POST ${startPath}`]: () => {
        state.current = authenticating;
        return json(makeAuthResponse(authenticating));
      },
      [`POST ${completePath}`]: () => {
        state.current = connected;
        return json(makeAuthResponse(connected));
      },
    });
    const log = mockApi(handlers);
    const user = userEvent.setup();
    renderApp('/connections');

    await user.click(await screen.findByRole('button', { name: 'Sign in to Northstar primary' }));
    await user.click(await screen.findByRole('button', { name: 'I’ve signed in' }));

    const panel = await screen.findByRole('group', { name: /Sign-in to “Northstar primary”/ });
    expect(panel).toHaveTextContent('Signed in.');
    expect(panel).toHaveTextContent('o***@example.test');
    expect(within(panel).queryByRole('button', { name: 'I’ve signed in' })).not.toBeInTheDocument();
    expect(requestsTo(log, 'POST', completePath)[0]?.headers.get('x-csrf-token')).toBe(CSRF_TOKEN);
    expect(await screen.findByText('Signed in to “Northstar primary”.')).toBeInTheDocument();
    expect(screen.getByText('Connected', { selector: '.badge' })).toBeInTheDocument();

    await user.click(within(panel).getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByRole('group', { name: /Sign-in to/ })).not.toBeInTheDocument();
  });

  it.each([['login_not_completed'], ['login_window_closed'], ['identity_mismatch']] as const)(
    'explains the failure %s in plain words and offers another try',
    async (code) => {
      const back = { ...base, status: 'authentication_required' as const };
      const { state, handlers } = broker(base, {
        [`POST ${startPath}`]: () => {
          state.current = authenticating;
          return json(makeAuthResponse(authenticating));
        },
        [`POST ${completePath}`]: () => {
          state.current = back;
          return json(
            makeAuthResponse(back, { jobStatus: 'failed', error: jobError(code, 'Fixed text.') }),
          );
        },
      });
      mockApi(handlers);
      const user = userEvent.setup();
      renderApp('/connections');

      await user.click(await screen.findByRole('button', { name: 'Sign in to Northstar primary' }));
      await user.click(await screen.findByRole('button', { name: 'I’ve signed in' }));

      const panel = await screen.findByRole('group', { name: /Sign-in to “Northstar primary”/ });
      expect(panel).toHaveTextContent('Sign-in did not finish.');
      expect(panel).toHaveTextContent(JOB_ERROR_TEXT[code]);
      expect(within(panel).getByRole('button', { name: 'Try again' })).toBeEnabled();
      expect(screen.getByText('Sign-in required', { selector: '.badge' })).toBeInTheDocument();
    },
  );

  it('can try again after a failure, with a fresh panel', async () => {
    let starts = 0;
    const back = { ...base };
    const { state, handlers } = broker(base, {
      [`POST ${startPath}`]: () => {
        starts += 1;
        state.current = authenticating;
        return json(makeAuthResponse(authenticating));
      },
      [`POST ${completePath}`]: () => {
        state.current = back;
        return json(
          makeAuthResponse(back, { jobStatus: 'failed', error: jobError('login_window_closed') }),
        );
      },
    });
    mockApi(handlers);
    const user = userEvent.setup();
    renderApp('/connections');
    await user.click(await screen.findByRole('button', { name: 'Sign in to Northstar primary' }));
    await user.click(await screen.findByRole('button', { name: 'I’ve signed in' }));
    await user.click(await screen.findByRole('button', { name: 'Try again' }));

    const panel = await screen.findByRole('group', {
      name: /Sign in to “Northstar primary” in the/,
    });
    expect(starts).toBe(2);
    expect(panel).not.toHaveTextContent('Sign-in did not finish');
    expect(within(panel).getByRole('button', { name: 'I’ve signed in' })).toBeEnabled();
  });

  it('answered 202: keeps checking, polls the connection, and then shows the outcome', async () => {
    const connected = { ...base, status: 'active' as const };
    let polls = 0;
    const { state, handlers } = broker(base, {
      [`POST ${startPath}`]: () => {
        state.current = authenticating;
        return json(makeAuthResponse(authenticating));
      },
      [`POST ${completePath}`]: () => json(makeAuthResponse(authenticating), 202),
      [`GET ${onePath}`]: () => {
        polls += 1;
        if (polls >= 3) state.current = connected;
        return json(state.current);
      },
    });
    const log = mockApi(handlers);
    const user = userEvent.setup();
    renderApp('/connections');

    await user.click(await screen.findByRole('button', { name: 'Sign in to Northstar primary' }));
    await user.click(await screen.findByRole('button', { name: 'I’ve signed in' }));

    expect(await screen.findByText(/Checking your sign-in/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Checking…' })).toBeDisabled();

    const panel = await screen.findByRole('group', { name: /Sign-in to “Northstar primary”/ });
    expect(panel).toHaveTextContent('Signed in.');
    expect(screen.getByText('Connected', { selector: '.badge' })).toBeInTheDocument();
    expect(requestsTo(log, 'GET', onePath).length).toBeGreaterThanOrEqual(3);
    // Complete was pressed once; the polling did not repeat it.
    expect(requestsTo(log, 'POST', completePath)).toHaveLength(1);
  });

  it('after a reload into authenticating shows the same panel without starting again', async () => {
    const closed = {
      ...base,
      status: 'authentication_required' as const,
      statusReason: 'The sign-in window was closed.',
    };
    let polls = 0;
    const { state, handlers } = broker(authenticating, {
      [`GET ${onePath}`]: () => {
        polls += 1;
        if (polls >= 2) state.current = closed;
        return json(state.current);
      },
    });
    const log = mockApi(handlers);
    renderApp('/connections');

    const panel = await screen.findByRole('group', {
      name: /Sign in to “Northstar primary” in the/,
    });
    expect(panel).toHaveTextContent('on this computer');
    expect(within(panel).getByRole('button', { name: 'I’ve signed in' })).toBeEnabled();
    expect(requestsTo(log, 'POST', startPath)).toHaveLength(0);

    // The window is closed without pressing anything: the poll notices and says so.
    const ended = await screen.findByRole('group', { name: /Sign-in to “Northstar primary”/ });
    expect(ended).toHaveTextContent('Sign-in did not finish.');
    expect(ended).toHaveTextContent('The sign-in window was closed.');
    expect(await screen.findByText(/ended without a session/)).toBeInTheDocument();
  });

  it('shows a refused start (409) as an error and leaves the connection alone', async () => {
    const { handlers } = broker(base, {
      [`POST ${startPath}`]: () =>
        apiError(409, 'conflict', 'A sign-in is already in progress.', 'req_conflict'),
    });
    mockApi(handlers);
    const user = userEvent.setup();
    renderApp('/connections');
    await user.click(await screen.findByRole('button', { name: 'Sign in to Northstar primary' }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('could not be started');
    expect(alert).toHaveTextContent('A sign-in is already in progress.');
    expect(alert).toHaveTextContent('req_conflict');
    expect(screen.getByRole('button', { name: 'Sign in to Northstar primary' })).toBeEnabled();
  });

  it('shows an error from the completion check and lets the owner press again', async () => {
    let attempts = 0;
    const connected = { ...base, status: 'active' as const };
    const { state, handlers } = broker(authenticating, {
      [`POST ${completePath}`]: () => {
        attempts += 1;
        if (attempts === 1) return apiError(409, 'conflict', 'Nothing to complete.');
        state.current = connected;
        return json(makeAuthResponse(connected));
      },
    });
    mockApi(handlers);
    const user = userEvent.setup();
    renderApp('/connections');

    await user.click(await screen.findByRole('button', { name: 'I’ve signed in' }));
    expect(await screen.findByText('Nothing to complete.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'I’ve signed in' }));
    expect(await screen.findByText(/Signed in\./)).toBeInTheDocument();
  });
});

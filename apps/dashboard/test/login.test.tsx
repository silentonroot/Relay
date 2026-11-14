import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import {
  apiError,
  CSRF_TOKEN,
  json,
  makeSession,
  mockApi,
  renderApp,
  requestsTo,
} from './helpers.js';

const UNAUTHENTICATED = () => apiError(401, 'unauthenticated', 'Not signed in.');

describe('Login', () => {
  it('signs in, posts the credentials, and shows the overview', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    const log = mockApi({
      'GET /v1/auth/session': UNAUTHENTICATED,
      'POST /v1/auth/login': () => json(makeSession()),
    });
    const user = userEvent.setup();
    renderApp('/connections');

    // The guard: a deep link while signed out shows the sign-in page, not the page asked for.
    expect(await screen.findByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Connections' })).not.toBeInTheDocument();

    await user.type(screen.getByLabelText('Email'), 'owner@example.test');
    await user.type(screen.getByLabelText('Password'), 'correct horse battery');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    // Signing in lands on the address that was asked for.
    expect(await screen.findByRole('heading', { name: 'Connections' })).toBeInTheDocument();
    expect(screen.getByText('Test Organization')).toBeInTheDocument();

    const [login] = requestsTo(log, 'POST', '/v1/auth/login');
    expect(login?.body).toEqual({
      email: 'owner@example.test',
      password: 'correct horse battery',
    });

    // Nothing auth-related is persisted by the page: the cookie is HttpOnly and the CSRF token
    // lives in memory only.
    expect(setItem).not.toHaveBeenCalled();
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
    expect(document.cookie).toBe('');
    expect(window.location.href).not.toContain(CSRF_TOKEN);
  });

  it('shows the server message on failure, clears the password and stays on the form', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    mockApi({
      'GET /v1/auth/session': UNAUTHENTICATED,
      'POST /v1/auth/login': () =>
        apiError(401, 'unauthenticated', 'Invalid email or password.', 'req_login_fail'),
    });
    const user = userEvent.setup();
    renderApp('/');

    await user.type(await screen.findByLabelText('Email'), 'owner@example.test');
    await user.type(screen.getByLabelText('Password'), 'wrong-password');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Sign-in failed');
    expect(alert).toHaveTextContent('Invalid email or password.');
    expect(alert).toHaveTextContent('req_login_fail');
    // A failed login is not "your session ended".
    expect(screen.queryByText(/session ended/i)).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue(''));
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled();
    expect(setItem).not.toHaveBeenCalled();
    expect(window.localStorage).toHaveLength(0);
    expect(window.sessionStorage).toHaveLength(0);
  });

  it('refuses an empty form client-side without calling the API', async () => {
    const log = mockApi({ 'GET /v1/auth/session': UNAUTHENTICATED });
    const user = userEvent.setup();
    renderApp('/');
    await user.click(await screen.findByRole('button', { name: 'Sign in' }));
    expect(requestsTo(log, 'POST', '/v1/auth/login')).toHaveLength(0);
    expect(screen.getAllByText(/./, { selector: '.field-error' }).length).toBeGreaterThan(0);
  });

  it('offers a retry when the broker cannot be reached', async () => {
    mockApi({ 'GET /v1/auth/session': () => apiError(503, 'service_unavailable', 'Down.') });
    renderApp('/');
    expect(await screen.findByText('The broker API is not reachable')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });
});

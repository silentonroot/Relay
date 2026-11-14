# ADR-002: Browser login handoff and session snapshots

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

Before an agent can do anything on a connection, the owner has to sign in to the target
application once, and AAB has to keep enough of the resulting session to act later without asking
again. The sign-in may involve a password, a second factor, a CAPTCHA or a single-sign-on redirect.
None of that may pass through the language model, and AAB must not automate or bypass any of it.

The product is local-first: the broker, the worker and the owner's desktop are the same machine.
That makes one simple mechanism available that would not exist in a hosted product.

## Decision

### Handoff

1. The owner clicks "Connect" or "Reconnect" for a connection in the dashboard. The API moves the
   connection to `authenticating` and asks the worker to start a login session for it.
2. The worker launches a **headed Chromium window on the owner's own desktop**, with a fresh
   browser profile that belongs to this connection only, and navigates it to the login page that
   the application's adapter declares. The page must be on one of the application's allowlisted
   origins.
3. The owner signs in directly in that window, completing whatever the application asks for,
   including MFA. **The worker does not type, fill, read or record credentials.** It does not
   attach input listeners, and it does not capture screenshots, video or traces during login.
4. The language model is not involved. No agent tool can start a login, observe one, or receive
   its result beyond the connection's status.
5. When the owner confirms in the dashboard that sign-in is complete, the worker calls the
   adapter's `checkSession`. This is a read-only check that the browser is signed in and that
   reports which account it is signed in as.
6. If the check passes, the worker captures the session snapshot described below, encrypts it, and
   stores it. The connection moves to `active`. If the check fails, the window is closed or the
   handoff times out, nothing is stored and the connection returns to `authentication_required`.
7. The login window and its profile directory are closed and deleted when the handoff ends, whether
   it succeeded or not.

### Snapshot contents

A snapshot is the browser storage state for the application's allowlisted origins and nothing
else: the cookies whose domain matches an allowlisted origin's host, and the origin-scoped web
storage for those origins. Cookies and storage that belong to any other origin visited during
login (an identity provider, an analytics host) are discarded before encryption.

A snapshot does not contain browsing history, cached pages, form autofill data, saved passwords,
screenshots, or the profile directory itself.

**A snapshot is equivalent to a password.** Anyone who can read the plaintext can act as the user
on that application until the session expires or is revoked there. It is treated accordingly: it
is encrypted before it touches disk ([ADR-003](ADR-003-local-vault-root-key.md)), it is bound by
associated data to its organization, owner and connection, it is never written to logs, audit
metadata, job payloads or API responses, and it is decrypted only inside a worker for the duration
of one job.

### Retention

- One current snapshot per connection. A successful reconnect replaces it; the previous version is
  deleted, not archived.
- When an operation finishes, the worker may write back a refreshed snapshot if the application
  rotated its session cookie. This is a replacement, with the same rules.
- Revoking or deleting a connection deletes its snapshot ciphertext and wrapped key. Revocation in
  AAB does not sign the user out of the target application; where an adapter supports it, the
  worker performs the application's own logout first, and the dashboard says so when it cannot.
- When `checkSession` finds the session no longer valid, the connection moves to `expired` and
  then `reconnect_required`. AAB does not attempt to re-authenticate on its own and never asks an
  agent for a password.

### What is out of scope

There is no remote browser streaming. A hosted AAB, where the worker is not on the owner's
machine, needs a different handoff (a streamed remote browser, or OAuth where the application
supports it). That is Phase 10 at the earliest, and it is a new decision record, not an extension
of this one.

## Alternatives considered

- **Collect the password in the dashboard and replay it.** Rejected. It puts the password in AAB
  for the lifetime of the connection, cannot satisfy interactive MFA, and trains the user to type
  an application's password into something that is not that application.
- **Import cookies from the owner's everyday browser.** Rejected. It requires reading another
  application's credential store, pulls in unrelated cookies, and shares a session with the
  owner's own browsing so that a logout in one ends the other.
- **Stream a remote browser into the dashboard.** This is the mechanism a hosted product needs. It
  is rejected for the local product because it adds a video and input relay, which is a large
  attack surface, to solve a problem a local install does not have.
- **Keep the whole profile directory.** Simpler than extracting storage state and survives more
  kinds of session. Rejected: a profile directory holds history, cache and unrelated origins, is
  large, and cannot be filtered to an allowlist with confidence.
- **OAuth instead of browser sessions.** Preferred wherever the application offers it, because
  tokens can be scoped and revoked. It is Phase 8. Most ordinary web applications, including the
  demo, offer only a login form.

## Consequences

- The Phase 2 worker must run on the owner's desktop session so that it can open a window. It
  cannot be a container in the Compose stack without display forwarding. This conflicts with the
  specification's local baseline (§19: Compose with one browser worker) and with the Phase 3 move
  to a containerized worker in [ADR-001](ADR-001-trust-boundaries-worker-isolation.md). The likely
  resolution is to split the worker into a small host-side login helper and a containerized
  executor. That split is **not decided** and must be settled before Phase 3 starts.
- The adapter contract needs two things the specification's §7 interface does not have: a declared
  login URL, and a way to list origins that may be visited during sign-in but must not be captured
  or used for operations (an external identity provider). Until the second exists, only
  applications whose login stays on their own origins can be connected. Northstar is one.
- Filtering by exact origin loses cookies set on a parent domain that the application relies on
  (for example a cookie for `.example.com` used by `app.example.com`). The rule above keeps a
  cookie when its domain matches an allowlisted host; whether "matches" includes parent-domain
  cookies is an adapter-level declaration that still has to be designed and tested against a
  non-demo application.
- Session storage (as opposed to local storage) is not part of a storage-state snapshot.
  Applications that keep their token only there cannot be restored and will need a different
  adapter strategy.
- The owner states an account label when creating a connection, and `checkSession` reports the
  account actually signed in. The worker must record what it observed, and a mismatch on reconnect
  (the owner signs in as a different account) must fail the handoff. The specification does not say
  which value wins; this record decides that the observed one does.
- The "sign-in complete" signal comes from the owner, so a handoff can be left open. It needs a
  timeout, after which the window is closed and nothing is stored.

## Revisit when

- The worker moves into a container (Phase 3).
- An application is to be connected whose login leaves its own origins, or which uses passkeys or
  device-bound credentials that do not survive a storage-state export.
- OAuth connections arrive (Phase 8); for applications that support both, the default changes.
- Any hosted or multi-user deployment is planned.

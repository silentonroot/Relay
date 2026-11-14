# Writing an adapter

This guide explains how to write an application adapter against `@aab/adapter-sdk`. It uses the
Northstar adapter (`packages/adapters/northstar`) as the worked example.

**Status: tracks adapter SDK version 0.x.** The SDK package is at `0.0.0` and has one adapter. Its
interfaces will change, and when they do this document changes with them. The packaging, trust and
upgrade rules for adapters are still a proposal ([ADR-006](adr/ADR-006-adapter-packaging-trust.md)).
Where this guide describes something that does not exist yet, it says so.

**What exists today.** The SDK validates adapter definitions, validates operation input, sanitizes
operation output, decides whether a navigation is allowed, and registers adapters. It defines the
interfaces the browser worker implements. Since Phase 2 the worker (`services/browser-worker`) runs an
adapter's `checkSession` and `execute` inside a per-job sandbox, and the Northstar adapter implements
both for its two read operations. The sections on `execute` and on the browser facade describe the
contract the SDK defines and what the worker's facade (`services/browser-worker/src/runner/facade.ts`)
allows and forbids. Only reads exist: nothing in the worker runs a write operation, so the rules for
writes in this guide are the specification's and have no code behind them.

## 1. What an adapter is, and why it is trusted

An adapter is the code that knows how to perform named operations on one web application. When a worker
runs it, the worker holds a signed-in browser session for the owner's account. A careless or malicious
adapter can do whatever the owner could do on that application, so adapters are part of the trusted
computing base. They live in this repository under `packages/adapters/<id>`, are reviewed like the rest
of the code, and are imported statically. There is no dynamic loading and nobody installs an adapter at
run time.

Three ideas run through the whole SDK.

1. **The agent chooses from a fixed list.** An agent never supplies a URL, a selector, a script or a
   path. It names an operation and gives arguments that your input schema accepts.
2. **The adapter touches the page only through a small facade.** There is no raw browser object.
3. **Whatever the page says is data.** It never decides what the broker does next.

Since Phase 2 an adapter's code runs inside a sandbox that has no network, no key and no database
credentials, and whose only way out is an egress proxy that allows the job's origins
([ADR-013](adr/ADR-013-per-job-sandbox-egress-proxy.md)). That limits what a flawed adapter or a
hostile page can reach. It does not limit what the adapter can do on the allowed origins with the
session: path restrictions are enforced by the facade inside the sandbox, and the proxy cannot see
paths.

## 2. Package layout

An adapter is a workspace package named `@aab/adapter-<id>`. Use the Northstar package as the template:

```text
packages/adapters/<id>/
├── package.json      # "exports": { ".": "./src/index.ts" }, no build step
├── tsconfig.json     # extends ../../../tsconfig.base.json
├── src/
│   ├── index.ts      # defineAdapter(...) and re-exports
│   ├── operations.ts # one defineOperation(...) per operation, plus their schemas
│   └── selectors.ts  # every path, selector and data attribute the adapter reads
└── test/
```

Its dependencies are `@aab/contracts`, `@aab/adapter-sdk` and `zod`. It must not depend on the target
application's source code, on the database, or on other adapters. Dependency additions go through the
review in [ADR-012](adr/ADR-012-synthetic-only-dependency-review.md).

Keep every path, form selector and `data-field` name in one file. Northstar does this in `selectors.ts`
(`NORTHSTAR_UI`), so a change to the target's markup is a one-file diff.

## 3. Defining operations

An operation is one named action. Define it with `defineOperation` and put it in the adapter's
`operations` map under its own name. `defineOperation` checks the definition and returns a frozen copy,
and throws `AdapterContractError` if a rule is broken.

This is Northstar's `orders.get`:

```ts
export const ordersGet = defineOperation({
  name: 'orders.get',
  description: 'Reads one order of the connected Northstar account, including its line items.',
  input: z.object({ orderId: NorthstarOrderId }),
  output: z.object({ order: NorthstarOrderDetail }),
  sensitivity: 'read',
  requiresApproval: false,
  idempotent: true,
  sideEffects: [],
  timeoutMs: 15_000,
  allowedPaths: ['/orders/:orderId'],
  resourceArgument: 'orderId',
});
```

### Fields

| Field              | What it is                                                                  | Rule enforced by the SDK                                                                                                                     |
| ------------------ | --------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`             | Dotted name, for example `orders.list`.                                     | Matches `^[a-z][a-zA-Z0-9]*(\.[a-z][a-zA-Z0-9]*)+$` and the key it is registered under. Names appear in grants, audit events and tool names. |
| `description`      | What the operation does, in a sentence.                                     | Not empty.                                                                                                                                   |
| `input`            | Zod object schema of the arguments an agent may submit.                     | Must be a Zod object. Parsed strictly (see below).                                                                                           |
| `output`           | Zod object schema of the only fields that may reach an agent.               | Must be a Zod object and must not let undeclared fields through.                                                                             |
| `sensitivity`      | `read`, `write` or `destructive`.                                           | One of the three.                                                                                                                            |
| `requiresApproval` | Whether a human must approve the exact action whatever the grant says.      | Must be `true` when sensitivity is `destructive`.                                                                                            |
| `idempotent`       | Whether repeating the call with the same arguments is safe.                 | Must be a boolean. Be honest: the orchestrator's retry rules will depend on it.                                                              |
| `sideEffects`      | What the operation changes in the target application, as sentences.         | Empty for a `read`. Not empty for a `write` or `destructive` operation, each entry non-empty.                                                |
| `timeoutMs`        | The longest the operation may run.                                          | An integer from 1000 to 120000.                                                                                                              |
| `allowedPaths`     | Path patterns the operation may visit. See section 5.                       | At least one, each a valid pattern.                                                                                                          |
| `resourceArgument` | Name of the input key that identifies the target resource, if there is one. | Must be a key of `input`.                                                                                                                    |
| `limitArgument`    | Name of the input key that bounds result size, if there is one.             | Must be a key of `input`.                                                                                                                    |

### Input schemas

The SDK parses arguments with `input.strict()`, so an unknown key is rejected and not dropped. Write the
schema so that nothing dangerous can be expressed in it.

- Use enums, bounded numbers and anchored regular expressions. Northstar's order identifier is
  `^NS-\d{4,}$`, anchored at both ends, so a value such as `NS-1001/../admin`, `NS-1001?x=1` or an
  identifier followed by a newline cannot pass.
- Bound every string and every array.
- Never accept a URL, a path, a selector, a script, a file name or a shell fragment from the agent.
  Identifiers go into a path or query only after your own schema has constrained them.
- Make the limit argument optional. A grant with `maxResults` and a request with no limit leads the
  policy engine to impose the limit as an obligation, so the adapter must accept an argument that the
  broker added.

### Output schemas

The output schema is the **only** thing that decides what an agent can see.

- Declare every field an agent may receive, and nothing else.
- Bound every string. Northstar's notes field is capped at 2,000 characters, and its comment says why:
  everything in the result comes from the page, so the cap bounds how much page text one result can
  carry.
- Do not use `z.looseObject`, `.passthrough()` or `.catchall(...)` anywhere in the output schema,
  including inside arrays, unions and optional wrappers. `defineOperation` walks the schema and rejects
  the definition if it finds one, because such a schema would let undeclared fields through.
- Output must be plain JSON. A value that is not (a date object, a class instance) fails sanitization.

### What the rules mean for write operations

Writes arrive in Phase 4 and the Northstar adapter does not have any yet. The SDK already enforces the
shape: a write must list its side effects, and a destructive operation must require approval. The
specification adds rules that no code enforces yet and that authors must follow: validate the target
resource and its version immediately before writing (a stale approval must fail), verify the
postcondition afterwards, and report `outcome_unknown` when the outcome cannot be confirmed
(`OutcomeUnknownError`, `SanitizedResult` status `outcome_unknown`). Never report success because the
browser call returned without throwing.

## 4. Resource and limit arguments, and grants

The policy engine never reads adapter code. It reads a descriptor derived from each definition
(`toOperationDescriptors` produces them): the name, the sensitivity, `requiresApproval`, the resource
argument and the limit argument. Grants refer to those two names.

- `resourceIds` in a grant constrains the operation's **resource argument**. The engine requires the
  argument's value to be a string in the grant's list. An operation without a resource argument cannot
  satisfy a grant that sets `resourceIds`.
- `maxResults` in a grant bounds the operation's **limit argument**. The value must be an integer from 1
  to the maximum, and when it is absent the engine returns an obligation setting it to the maximum. An
  operation without a limit argument cannot satisfy a grant that sets `maxResults`.
- `argumentEquals` and `argumentOneOf` compare named arguments to JSON primitives.

If you do not name a resource or limit argument, grants cannot constrain on them, and the grant
fails closed. Name them whenever the operation has them. Northstar's `orders.list` names `limit`, and
`orders.get` names `orderId`.

## 5. Allowed paths

`allowedPaths` is the list of URL paths an operation may visit within the adapter's allowed origins. The
navigation guard checks each navigation against the list of the operation being run.

A path pattern is `/` or a series of `/segment` parts. A segment is either a literal made only of URL
unreserved characters (`A-Z a-z 0-9 . _ ~ -`) or a placeholder such as `:orderId`, which matches
exactly one such segment. Patterns are data, not regular expressions.

- Matching is exact. There is no prefix matching, no tolerance for a trailing slash, and a
  percent-encoded segment never matches.
- A pattern does not include the query string. The guard does not inspect query strings or fragments, so
  **your code must build query strings only from validated arguments**. If the page offers a link with a
  query string, do not follow it from page data.
- List only what the operation needs. Northstar's `orders.list` may visit `/orders`, and `orders.get` may
  visit `/orders/:orderId`. `orders.list` cannot load an order page and `orders.get` cannot load the list.
  Neither can load `/login`, which only adapter-level flows with no operation name may.

## 6. Defining the adapter

`defineAdapter` validates the whole adapter and returns a deeply frozen copy. Only an adapter returned
from it can be put in an `AdapterRegistry`.

```ts
export const northstarAdapter = defineAdapter({
  id: 'northstar',
  version: '0.1.0',
  displayName: 'Northstar (synthetic demo)',
  allowedOrigins: [NORTHSTAR_UI.defaultOrigin],
  authMode: 'browser_session',
  operations: {
    'orders.list': ordersList,
    'orders.get': ordersGet,
  },
});
```

The SDK checks the following.

- `id` is lowercase letters, digits and dashes. `version` is a semantic version. The registry keys
  adapters by both and refuses a duplicate pair. The worker will run an operation only with the exact
  version an application definition names ([ADR-006](adr/ADR-006-adapter-packaging-trust.md)).
- `allowedOrigins` is a non-empty list of exact origins with no duplicates: one scheme, host and port,
  no path, no wildcard, no user information. HTTPS is required, except plain HTTP on a loopback host. A
  value with a different default port spelling, an uppercase host or a trailing path is not an origin.
- `authMode` is one of `browser_session`, `oauth` and `api_key`. It is a single value in the SDK, while the
  specification's interface has a list.
- Each operation's key equals its `name`.
- `loginPath` is the application's sign-in page as a literal path with no placeholders, and it is
  required for a `browser_session` adapter that implements `checkSession` or `execute`. The login
  handoff opens it, and a navigation that lands on it during a job means the session expired (see
  "Expiry" below). The worker refuses to start a login for an adapter without it
  (`adapter_unavailable`), and so does the API (409).
- `sessionCheckPaths` lists the path patterns `checkSession` may visit, in the same syntax as an
  operation's `allowedPaths`. While `checkSession` runs, the facade allows those paths and the login path
  only.
- `checkSession` and `execute` are optional in the SDK so that a manifest-only adapter can be registered,
  granted and policy-checked without a worker. The worker refuses to run an operation for an adapter
  without `execute` (`adapter_unavailable`), and refuses a login for one without `checkSession`.

A job may reach only the origins that appear in **both** the adapter's `allowedOrigins` and the
application definition's `allowed_origins`; if the lists share nothing the job fails with
`origin_not_allowed` before a sandbox starts. This is a provisional decision awaiting the owner
(spec changelog 0.3, item 36). The facade resolves every `goto` path against the first origin of that
intersection, in the adapter's order. Keep the adapter's list as small as the application needs.

## 7. The execute contract and the browser facade

`execute(ctx, operation)` receives a `WorkerContext` and a `ValidatedOperation` and returns a
`SanitizedResult`.

```ts
interface WorkerContext {
  readonly connectionId: string;
  readonly signal: AbortSignal; // aborted on cancellation, timeout or revocation of the connection
  readonly logger: AdapterLogger;
  readonly browser: BrowserSession;
}
```

`ValidatedOperation` is a branded type produced only by `validateOperationInput`. It carries the adapter
id and version, the operation name and the parsed arguments, and you cannot construct one by hand.
Because the arguments are a generic JSON object, `execute` should parse them again with the operation's
own input schema to get typed values, for example `ordersList.input.parse(operation.arguments)`.

### BrowserSession is the only page access

The facade has these members and no others:

| Member                               | What it does                                                                                      |
| ------------------------------------ | ------------------------------------------------------------------------------------------------- |
| `goto(path)`                         | Navigates to a path, with an optional query, on the job's primary allowed origin.                 |
| `currentUrl()`                       | The current URL.                                                                                  |
| `text(selector)` / `texts(selector)` | Text of the first matching element, or of all of them.                                            |
| `attribute(selector, name)`          | An attribute of the first matching element.                                                       |
| `rows(rowSelector, fieldAttribute)`  | For each matching row, the text of the descendants carrying `fieldAttribute`, keyed by its value. |
| `fill(selector, value)`              | Fills a field.                                                                                    |
| `click(selector)`                    | Clicks an element.                                                                                |
| `waitFor(selector, options)`         | Waits for an element.                                                                             |

It deliberately has no script evaluation, no navigation to an arbitrary URL, no access to cookies or
storage, no network interception and no underlying page object. A requirement that cannot be written with
these members is a reason to discuss the SDK, not to find a way around it. Do not cast the session to a
broader type, and do not import a browser automation library into an adapter.

What the worker's facade allows and forbids, in addition to the member list:

- **`goto`** takes a path that starts with a single `/`, is at most 2048 characters, and is joined to the
  primary allowed origin by the facade. The resulting URL is judged before it is sent. A path that is
  not allowed for the operation throws `NavigationBlockedError` and ends the job as
  `navigation_blocked`.
- **Every main-frame request and redirect hop is judged before it is sent**, whatever started it: `goto`,
  a click, a form, a meta refresh or script. A blocked one is failed and recorded as the job's
  violation, which ends the job even if the adapter caught the error. Sub-frames may load any path on an
  allowed origin; the facade does not apply an operation's paths to them.
- **The browser can reach only the job's allowed origins.** Every request, subresources included, goes
  through the egress proxy, which refuses anything else, and refuses an allowed host that resolves to a
  non-public address. An adapter cannot widen this.
- **Reads are bounded.** One `text` or `attribute` result is cut at 65,536 characters; `texts` and `rows` share a
  524,288-character budget and fail beyond 1000 elements (`rows`: 100 fields per row); selectors are at most 1000
  characters; attribute names must look like attribute names; `fill` values are at most 65,536 characters. A row's
  keys `__proto__`, `constructor` and `prototype` are skipped.
- **A failed browser action** (a timeout, a missing element for `click` or `fill`, a closed page) throws
  `BrowserActionError`, whose message is fixed and never carries Playwright's or the page's text. The job
  then ends as `worker_failure`.
- **Not available:** downloads are off, service workers are blocked, no browser permission is granted,
  and any popup the page opens is closed at once.
- **Logging** through `ctx.logger` does not leave the sandbox with its text: the runner forwards only a
  fixed event name and the level. Log scalar values anyway, in case that changes.

Rules for `execute`:

1. **Build every path from constants and validated arguments.** Use the constants in `selectors.ts`.
   Encode values you place in a query string, or, as Northstar does, put only enum values and digits there.
2. **Never navigate to something read from the page.** A link, a redirect target or a URL in a note is
   data. Page content does not choose where the adapter goes.
3. **Check `ctx.signal`** between steps and stop when it is aborted.
4. **Log through `ctx.logger` with scalar fields only,** and never page content, cookies or argument
   values.
5. **Return one of the four result shapes:** `succeeded` with `data`, `failed` with a code and a message,
   `reauth_required`, or `outcome_unknown`. How the worker maps results and thrown errors is in "Failure
   codes" below.
6. **Honor the arguments as the broker finalized them.** If a grant imposed a limit, `operation.arguments`
   contains it.

Northstar's `execute` (`packages/adapters/northstar/src/execute.ts`) is the worked example. It
dispatches on the operation name, parses the arguments again with the operation's own input schema, builds
each path from constants and validated values, reads pages with `rows`, `text` and `attribute`, and
returns `sanitizeOperationOutput(...)` of what it read. It never branches on free text, never builds a
path or selector from page content and never logs it. A page that does not have the expected shape ends
in a fixed failure code (`unexpected_page`), and an order that is not found in the application's 404 page
ends in `not_found`.

### checkSession

`checkSession` reports whether the session still works: `active`, `degraded` or `expired`, and, if the
application shows it, a non-secret label for the signed-in account (`externalAccountHint`). It must be
free of side effects in the target application. The specification requires session checks never to
perform a destructive action (§5.2). Northstar's loads `/orders` (a GET) and reads the current user.

The worker uses it in two places. At the end of a **login handoff** it must report `active`, and the
label is stored with the connection (the worker trims it and keeps at most 120 characters). Before every
**operation** it runs first: `expired` ends the job as `reauth_required`, and a label that differs from
the stored one ends it as `identity_mismatch` before `execute` runs. The check may use only
`sessionCheckPaths` and the login path. A connection first verified with no label cannot be re-verified
once the application starts showing one.

### Expiry

Signal an expired session by letting the facade do it. When a main-frame navigation lands on `loginPath`
and the adapter did not itself ask for the login path, the facade throws `ReauthRequiredError` and the
job ends as `reauth_required`. In `checkSession`, catch it and return `expired`, as Northstar does; in
`execute`, let it propagate. The worker then moves the connection to `expired` and deletes the stored
ciphertext. An adapter whose application shows an expired session without redirecting to a login page
cannot use this and must detect it from the page and return `reauth_required` itself.

### Failure codes

An adapter's `execute` can end a job in these ways. The job's error message is always fixed text chosen
by the worker for the code; text from the adapter or the page is dropped.

| What the adapter does                                                            | Job result                                                                                                                            |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Returns `succeeded` with `data`                                                  | `succeeded`, after `sanitizeOperationOutput` in the runner and again in the supervisor; a mismatch is `failed` with `output_rejected` |
| Returns `failed` with code `not_found`, `unexpected_page` or `invalid_arguments` | `failed` with the same code                                                                                                           |
| Returns `failed` with code `aborted`                                             | `cancelled`                                                                                                                           |
| Returns `failed` with any other code (including `unknown_operation`)             | `failed` with `worker_failure`                                                                                                        |
| Returns `reauth_required` or throws `ReauthRequiredError`                        | `reauth_required`; the connection becomes `expired`                                                                                   |
| Returns `outcome_unknown`                                                        | `outcome_unknown`                                                                                                                     |
| Lets `NavigationBlockedError` propagate, or the facade records a blocked hop     | `failed` with `navigation_blocked`                                                                                                    |
| Throws `AdapterContractError` (for example from `sanitizeOperationOutput`)       | `failed` with `output_rejected`                                                                                                       |
| Throws any other error, or a browser action fails                                | `failed` with `worker_failure`                                                                                                        |
| Runs past the operation's `timeoutMs`                                            | `failed` with `timeout`                                                                                                               |

The mapping is `mapAdapterErrorCode` in `services/browser-worker/src/protocol.ts`. Codes the worker
produces without the adapter: `denied`, `adapter_unavailable`, `origin_not_allowed`,
`identity_mismatch`, `session_expired`, `cancelled`, `login_not_completed`, `login_window_closed`.

## 8. Output sanitization is the only gate

`sanitizeOperationOutput(adapter, operationName, raw)` parses `raw` with the operation's output schema.
Fields the schema does not declare are removed, at every level. Output that does not satisfy the schema
is not passed through: it throws `AdapterContractError`, whose message names the failing field paths and
never echoes page content. An operation the adapter does not define also throws.

The consequence for your design: **nothing reaches an agent except what the output schema declares and
what the page supplied for those fields.** The rule to follow is to treat the output schema as a
permission list for fields, and to review every addition to it as a disclosure.

Two points about who calls it. The SDK describes the function as the single gate between worker-internal
data and agent-visible results, and the `SanitizedResult` type says its `data` has passed it. The type is
not branded, so nothing enforces that, and the SDK does not say whether the adapter or the worker calls
it. Do both: call it in the adapter so that your tests exercise it, and expect the worker to call it
again on everything that leaves.

## 9. The navigation guard

`isNavigationAllowed(adapter, operationName, url)` returns `{ allowed: true }` or `{ allowed: false,
reason }`. `assertNavigationAllowed` throws `NavigationBlockedError`, which carries the reason and not the
URL. The worker applies it to the first navigation and to every redirect hop, with the same operation
name (see "What the worker's facade allows and forbids"). Pass `null` for the operation only for adapter-level flows, the owner's interactive login being the
case the SDK names. With `null` the guard still checks origin, scheme, credentials and traversal, and it
does not check paths.

A URL is allowed only when all of these hold:

- it is absolute, parses, has no backslash, whitespace or control character, and carries no user
  information;
- its scheme is `https`, or `http` on a loopback host;
- its origin equals one of the adapter's allowed origins exactly (port and scheme included);
- it is **already in canonical form**;
- it contains no dot segments, and no percent-encoded dot, slash or backslash in the path;
- when an operation is named, its path matches one of that operation's `allowedPaths`.

### The normalised-URL requirement

The guard checks the exact string that is going to be loaded. After the parser has resolved the origin,
the guard requires the text itself to start with that canonical origin and to continue with nothing, `/`,
`?` or `#`. That rejects every spelling a parser would quietly normalise into an allowed origin: an
uppercase host or scheme, an explicit default port (`:443`), a missing slash after the scheme, and a
trailing-dot host. Those are blocked as `non_canonical_url` or `origin_not_allowed`.

What this means in practice:

- Build URLs by joining the **adapter's own origin string** with a path from your constants. Do not
  assemble a URL from page content or from a library that re-serialises it.
- Pass the guard the string the browser will actually be told to load. If you check one spelling and load
  another, the check proves nothing.
- A redirect target is checked as the URL the server sent, before the browser follows it, not after it has
  been normalised by something else.

What the guard does not do: it does not resolve DNS or inspect IP addresses (the egress proxy does that,
outside the sandbox), it does not look at query strings or fragments, and it covers navigations, not the
other requests a page makes while loading. Those other requests are limited to the job's allowed origins
by the egress proxy, and not by path.

In the worker the guard runs inside the sandbox, through a browser-protocol interception that pauses each
main-frame request, redirect hops included, before it is sent (`src/runner/facade.ts`). The facade adds
rules the SDK guard does not know: a main-frame URL must be on one of the job's allowed origins, the
login path means `ReauthRequiredError` unless the adapter asked for it, and during `checkSession` only
`sessionCheckPaths` are allowed. Because it runs in the sandbox it does not survive a compromised runner;
the origin limit in the egress proxy does.

## 10. Treat page content as untrusted

Everything that comes back from the target application is untrusted data: element text, attributes, links,
titles, error messages, order notes. It may contain text written to look like an instruction to an AI
agent. Northstar's seed data contains such a note on purpose.

- Do not branch on free text to decide what the adapter does next, which pages it visits or which
  operation runs. Branch on structure you expect (an element exists, a status is one of an enum).
- Do not follow links or redirects that the page supplies.
- Do not copy page text into log fields, error messages, tool names or descriptions. Tool names and
  descriptions come from the static operation definitions only.
- Bound and shape the fields you return. A note is returned as a bounded string in a declared field. It is
  never merged into a message that looks like it is from the system.
- The broker's own decisions never depend on page content ([ADR-001](adr/ADR-001-trust-boundaries-worker-isolation.md),
  INV-14). The adapter's part is to keep it that way: return the text as a field and do nothing else
  with it.

Returning an injection string to the agent as a field is expected. What matters is that returning it
changes nothing about what the broker permits. The end-to-end test reads Northstar's injection note and a
benign order and checks that the job status, the audit event type, the job, grant and audit counts and the
requests the demo received are the same for both (`services/browser-worker/test/e2e/phase2.e2e.test.ts`,
step E); no model takes part in that test.

## 11. Tests every adapter needs

The Northstar tests are the model: `packages/adapters/northstar/test/northstar.test.ts` for the manifest
and `packages/adapters/northstar/test/execute.test.ts` for `execute` and `checkSession`. The SDK has no
fake `BrowserSession`, so tests of `execute` need one written in the adapter's own test directory that
implements the interface and records every call (`FakeBrowser` in `execute.test.ts`). A phase that adds
an operation is not complete until these exist for it.

There are two levels of test. **Unit tests against a fake facade** check what the adapter does with the
pages it is shown. **The sandbox integration fixtures** in `services/browser-worker/test/` check the
worker's real facade, proxy and sandbox with a small fixture application: an adapter with operations such
as `nav.redirectPath`, `page.exfil` and `op.hang` (`test/fixtures/registry/fixture-adapter.ts`), a fixture
server with scripted sessions (`test/fixtures/app-server.ts`), and a harness that runs jobs through the
real launcher (`test/integration/helpers.ts`). They run only where bubblewrap and Chromium are installed
and skip otherwise. An adapter's own behaviour belongs in the first level; a new worker rule belongs in
the second.

**Manifest**

- The adapter passes `defineAdapter` and can be put in an `AdapterRegistry` (`isDefinedAdapter`).
- The operation list, sensitivities and empty or non-empty side effects match what is intended. A read
  has none, and a write or destructive operation lists its effects.
- `toOperationDescriptors` yields what you expect, and each descriptor parses with the contracts
  `OperationDescriptor` schema. In particular the resource and limit argument names are present.

**Input: refuse what should not pass**

- Accepts the documented valid arguments, including omitted optional ones.
- Rejects values out of bounds, of the wrong type, unknown keys, and unknown operation names.
- Rejects arguments shaped like attacks on the identifier: a path traversal suffix, a query suffix, a
  newline, a wrong case, a too-short identifier and a number where a string is expected.
- Rejects prototype names (`constructor`, `__proto__`) as operation names.
- Never echoes submitted values or unknown key names in the error.

**Output: nothing extra gets out**

- Plant fields the schema does not declare, at the top and in nested objects and array items, including
  a cookie-shaped canary string, and assert they are absent from the result.
- A missing required field, an out-of-enum value and an over-length string each fail with
  `AdapterContractError`, and the message contains no page content.
- A prompt-injection string in a declared free-text field passes through unchanged, as data.

**Navigation: stay inside the lines**

- Every operation's allowed paths are allowed, and every other operation's paths are blocked for it.
- Blocked: another origin, a different port, a lookalike host, a userinfo trick, a scheme downgrade, a
  non-canonical spelling, a traversal, a path outside the list, a trailing slash.
- For loopback origins, other spellings of loopback (`127.0.0.1` for `localhost`) are blocked.
- The adapter builds each URL from its constants, and a test asserts that every URL it asks the facade to
  load passes the guard for its operation.

**Execution (against the fake facade)**

- Against the fake session: the adapter calls only the facade, visits only expected paths, and builds
  query strings only from validated arguments.
- A page containing a canary session value, a hostile link and an instruction in a note produces a result
  with none of the canary, no navigation to the link, and the expected fields.
- A grant-imposed limit appears in the arguments and is honored.
- `checkSession` returns `expired` for a login page, reports the account label, and performs no write.
- Aborting `ctx.signal` stops the operation promptly.
- Nothing is logged except scalar fields without page content.

**Writes (Phase 4 onward)**

- A stale resource version is refused.
- An unverifiable postcondition returns `outcome_unknown` and is not retried.
- A destructive operation without `requiresApproval` fails definition.
- A write is never reported as succeeded without verification.

**Worker-level tests** (a redirect to another origin aborts the operation, two accounts stay isolated, a
page's request to another origin is refused by the proxy) belong to the worker's integration fixtures and
the end-to-end suite, not to the adapter. `services/browser-worker/test/integration/operations.test.ts`
has them today.

## 12. Checklist for a new adapter or operation

- [ ] The package follows the layout in section 2 and has no dependency outside the three allowed.
- [ ] Every operation has a strict, bounded input schema and an output schema without loose objects.
- [ ] Sensitivity, side effects, idempotency, timeout and approval are set honestly.
- [ ] Resource and limit arguments are named wherever the operation has them.
- [ ] `allowedPaths` is the smallest set that works, and no query string is built from unvalidated data.
- [ ] Every URL is built from the adapter's origin and constants.
- [ ] No page content reaches a log, an error, a tool name or a decision.
- [ ] The negative tests of section 11 exist and pass, including `execute` against a fake facade.
- [ ] The phase's security checklist ([security.md](security.md)) has the adapter's disclosures and tests
      listed.
- [ ] Any gap in the SDK that you worked around is recorded in an issue, not hidden in the adapter.

## 13. Gaps in the SDK that adapter authors will meet

These are visible in the SDK as written and are not settled.

- The adapter declares `loginPath`, but there is no list of origins that may be visited during sign-in but
  never captured ([ADR-002](adr/ADR-002-login-handoff-session-snapshots.md) requires one). Until there is,
  only applications whose login stays on their own origin can be connected, and cookies scoped to a parent
  domain are dropped from the stored session.
- The adapter's `allowedOrigins` and the application definition's `allowed_origins` combine as an
  intersection, a provisional rule awaiting the owner.
- `authMode` is a single value, and the specification shows a list.
- `SanitizedResult` is not branded, so passing the output gate is not enforced by the type.
- No fake `BrowserSession` in the SDK (each adapter writes its own), and no helper that checks that an
  adapter's URLs pass its own guard.
- No tool that compares two versions of an adapter and flags breaking changes
  ([ADR-006](adr/ADR-006-adapter-packaging-trust.md) proposes one).

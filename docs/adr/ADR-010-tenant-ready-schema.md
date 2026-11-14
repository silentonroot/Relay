# ADR-010: Tenant-ready schema, single local organization

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

The first release is a local installation with one owner. The specification does not want it to be
a dead end: "No multi-tenant SaaS launch in the first milestone, though tenancy boundaries are
represented in the schema" (§1.2), and the identity hierarchy starts at `Organization (future
tenant)` (§5.1). Hosted, multi-user operation is Phase 10 and is optional.

Retrofitting isolation into a schema and a code base that were written without it is a known way to
ship cross-tenant leaks. The usual failure is a query that someone forgot to filter. So the
isolation rules are built into the first tables and tested from the first repository function,
even though only one organization will exist in practice.

Isolation is not authorization. This record decides which rows a caller can see at all. Which
operations an agent may run is the policy engine's job ([ADR-005](ADR-005-policy-representation.md)).

## Decision

### What the schema carries

- Every table that holds tenant-owned data carries `organization_id`, and every table whose rows belong
  to one person carries that person as `owner_user_id`. `connections` and `agents` have both.
  `application_definitions` has the organization only, because an application definition is shared by
  the organization's members. `user_sessions` and `memberships` have the organization and the user.
  `audit_events` has the organization, with the chain scoped to it
  ([ADR-009](ADR-009-audit-integrity.md)).
- Two child tables carry neither column: `agent_grants` (reached through its agent and its
  connection) and `connection_status_events` (reached through its connection). They carry no organization or owner column. Their rows inherit
  scope through their agent or connection, and every scoped repository function that touches them first resolves the
  parent within the caller's scope. This is a deviation from "every owned row carries both columns" and is
  deliberate, but it has a cost that is stated under Consequences.
- Foreign keys tie rows to their organization and owner where a column exists. A unique index scopes
  names: an owner cannot have two connections with the same display name for one application, and
  agent client identities are unique per owner (the unique index is on `owner_user_id` and
  `client_identity`; it was per organization in the first draft).
- There is one organization in practice. `bootstrapLocalOwner` creates the organization, the owner
  and the membership in one transaction, takes an advisory lock, and refuses to run again once any
  user exists, so it cannot be replayed to create a second owner.

### Every scoped repository function takes an explicit scope

`Scope` is `{ organizationId, userId }`. It must come from a validated dashboard session and never
from request parameters or bodies. Every repository function that reads or changes tenant-owned
data takes a `Scope` as an argument and puts it into the SQL `WHERE` clause. There is no ambient
"current tenant" in a global, a thread-local or an async context, so a function that forgets the
filter has an argument it does not use, and review can see it.

An invalid scope (a value that is not a UUID) matches nothing. Lists return empty pages, lookups
return null, and changes throw the not-found error.

Composition is by transaction: `repositories.transaction` binds the same repositories to one
database transaction, and each call inside still takes its own scope.

### Out of scope is the same as missing

A row outside the caller's scope is **indistinguishable from a row that does not exist**. Lookups
return `null` and changes throw `NotFoundError`, whether the ID is unknown or belongs to someone else.
The message names the kind of row and nothing else. Malformed IDs are also "not found", so probing
with garbage does not produce a database error that differs from probing with a valid foreign ID.
The API maps `NotFoundError` to the `not_found` response (§12.1), with the same body in both cases.

Creating a grant checks that both the agent and the connection are owned by the caller, inside the
transaction that inserts the grant, and takes share locks on both rows. A grant can therefore never
join an agent and a connection that belong to different owners. The policy engine checks the same
thing again at evaluation time and denies on a mismatch, so a row written some other way still
grants nothing.

### Functions that are not scoped, by name

Not every repository function takes a `Scope`, because some run before a scope exists or serve the
broker itself. They are listed here so that the list can be reviewed and so that it does not grow
silently.

| Function                                                              | Why it has no scope                                                                                                                  |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `users.create`, `users.findForLogin`                                  | Run before sign-in. `findForLogin` returns the password hash and must never reach a response.                                        |
| `organizations.create`, `addMember`, `bootstrapLocalOwner`            | Create the scope itself.                                                                                                             |
| `sessions.create`, `findValid`, `touch`, `revoke`, `revokeAllForUser` | Resolve a session token hash into a scope, or act on a session by its ID. `create` checks active membership.                         |
| `grants.listForEvaluation`                                            | Called by the broker after it has resolved and authorized the agent and connection. Never to be exposed through a user-facing route. |
| `audit.append`                                                        | Takes an organization ID, because events are written by system actors (workers, policy evaluation) as well as by users.              |

`grants.listForEvaluation` and `audit.append` take no scope because they are broker-internal. They
must never be exposed through a user-facing route: a route that passed a caller-supplied agent,
connection or organization identifier to either would bypass scoping.

Everything else is scoped. The audit **list** and **verify** functions take a `Scope` and filter by
organization only, since the audit table has no owner column: any member of the organization can read
all of the organization's events. That is acceptable for a single local owner and must be revisited
before multi-user use.

## Alternatives considered

- **Add tenancy when hosting arrives.** Cheaper now and the usual source of leaks later. Migrating
  populated tables and finding every query is the expensive way to learn what the schema should have
  said.
- **PostgreSQL row-level security from the start.** The database would enforce scope even when
  application code forgets. It is the right defence in depth for hosting. Deferred: it needs the scope
  set on every connection the pool hands out, it complicates tests that run on a single in-process
  connection, and it would give the local product a mechanism with no second tenant to protect. It is
  on the list for Phase 10.
- **A schema or a database per tenant.** Stronger isolation, and a reasonable answer for hosting.
  Deferred for the same reason; it changes migration and operations, not just the schema.
- **An implicit tenant from request context.** Convenient, and a missing filter then becomes a
  silent leak, not a visible unused argument.
- **Return `forbidden` for rows that exist but belong to others.** Honest, and it tells an attacker
  which identifiers exist. The specification rules it out (§12.1).
- **Give every table both columns, including grants and status events.** Uniform, and it makes
  row-level security and per-table export simple. Not done in Phase 1 because the parent already
  fixes the scope and a second copy can disagree with it. This may be reversed in Phase 10.

## Consequences

- Every new repository function must take a scope or be added to the list above with a reason. A
  function that takes an ID and nothing else is a defect unless it is on that list.
- Isolation is enforced by application code and tested, not by the database. The tests in
  `packages/database` create two organizations and two users in one organization, and try every read
  and write across both boundaries. They also check that a foreign row and a missing row produce the
  same outcome, and that the owner's own access still works, so the refusals are not trivially true.
  A repository function added later is protected only if someone adds the same tests for it.
- `agent_grants` and `connection_status_events` have no scope columns of their own. A future
  function that selects from them without joining the parent would have nothing to filter on. This is
  the weak spot of the schema and the reason the repository functions for them resolve the parent
  first.
- The audit trail is organization-wide. With one owner this is correct. With several members it
  would show each member the others' agent and connection identifiers and event types. Phase 10
  needs an owner-level filter or an administrator role for it.
- Role names (`owner`, `admin`, `member`) are stored on memberships, and no repository function
  checks them. Role checks, such as "only an admin may register an application", belong to the API
  layer and are not yet written.
- All of this is untested against more than a handful of synthetic users and one database
  connection. The tests prove the intended rules for the functions they cover. They are not an
  independent verification of tenant isolation, and they must not be described as one.
- Having the structure does not make the product multi-tenant. Single-organization operation means
  nobody has attacked the boundary, that no tenant-specific encryption keys exist, and that no
  per-tenant limits, billing or retention exist.

## What real hosting needs

Hosted operation with several organizations is **Phase 10**, and the specification's exit criterion
for it is "independently verified tenant isolation and operational readiness". That verification is
a precondition. It is carried out by someone who did not write the code, covers every route and
every repository function, and includes attempts to cross the boundary through the API, not only
through the repositories. In addition, Phase 10 needs at least:

- sign-in through an identity provider and a real role model;
- row-level security or an equivalent second line of defence in the database;
- scope columns on the child tables, or another way to enforce scope there;
- tenant-scoped encryption keys through a managed KMS (the AAD already includes the organization);
- per-tenant quotas, retention and an owner-level audit filter;
- a review of the places where a global resource could be shared, such as caches, queues and logs.

## Revisit when

- A second organization is to be created in any installation.
- A second member is added to an organization, even without hosting.
- Phase 10 is scheduled.
- A repository function is added that cannot take a scope, or a table is added that carries no
  tenant column.

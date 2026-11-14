# ADR-005: Policy representation

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

Every operation an agent requests must be authorized on the server before anything executes. The
specification describes authority as grants binding an agent, a connection and an operation with
conditions, an expiry and an approval policy (§5.1, §8.1), and it also lists a `policies` table
holding a "policy document" and leaves open whether to use a declarative policy engine (§21,
ADR-005 in the queue).

The decision has to be small enough to verify exhaustively, and it has to be explainable: the
dashboard must show which grant caused an allow or a deny (§10.2).

## Decision

### Grants are rows

A grant is one database row. Its API shape is `AgentGrant` in `packages/contracts`:

| Field                    | Meaning                                                               |
| ------------------------ | --------------------------------------------------------------------- |
| `agentId`                | The agent the grant applies to.                                       |
| `connectionId`           | The one connection it applies to.                                     |
| `operation`              | One exact operation name, such as `orders.list`.                      |
| `effect`                 | `allow` or `deny`.                                                    |
| `constraints`            | A strict JSON object that narrows the grant (below).                  |
| `approvalMode`           | `none` or `required`.                                                 |
| `expiresAt`, `revokedAt` | When the grant stops applying. A revoked grant is kept for the audit. |

The specification's `agent_grants` table had no `effect` column although §8.1 requires explicit
denies. This record adds it.

### Constraints are a closed set

`GrantConstraints` is a strict schema with four keys: `maxResults`, `argumentEquals`,
`argumentOneOf` and `resourceIds`. An object with any other key is rejected when the grant is
written. A constraint the engine does not understand must never be stored and silently ignored,
because the owner would believe the grant was narrower than it is.

The same rule holds at evaluation time, in case a row was written by an older version or edited
directly. A damaged allow grant is ignored: it cannot allow anything. A damaged deny grant stays in
force: if its constraints do not parse it denies everything it targets, and a revocation or expiry
timestamp that cannot be read does not lift it (only a readable one that has already taken effect
does). A grant whose `effect` is unreadable is treated as an unconditional deny. Both fail closed.

A constraint that cannot be enforced for an operation also fails closed. If a grant sets
`maxResults` and the operation declares no limit argument, or sets `resourceIds` and the operation
declares no resource argument, the grant does not satisfy the request.

### Evaluation

The policy engine is a pure function in `packages/policy-engine`. It takes the request, the
operation's descriptor, the candidate grants, the agent and connection records and the current
time. It performs no I/O and has no clock of its own, so the same inputs always give the same
decision and the dashboard's policy simulator is the same function.

1. The request must be well-formed, the operation must be known to the connection's adapter, the
   agent must be active, the connection must be in an executable status (`active` or `degraded`),
   and the agent and connection must belong to the same owner and organization. Any failure is a
   deny with its own reason code.
2. Only grants whose agent, connection and operation match **exactly** are considered. There are
   no wildcards and no prefix matches. Revoked and expired grants are ignored.
3. If any applicable deny grant matches, the decision is deny. **Explicit deny wins**, whatever
   allow grants exist and in whatever order they are stored.
4. Otherwise at least one allow grant must have all its constraints satisfied. If none exists the
   decision is deny: `no_matching_grant` when there were no allow grants, `constraint_violation`
   when there were but none was satisfied.
5. An allowed request becomes `approval_required` when the operation's sensitivity is
   `destructive`, when the adapter marks the operation `requiresApproval`, or when no satisfied
   grant has `approvalMode: none`. The first two hold **whatever the grant says**: no grant, however
   it is written, can make a destructive or approval-marked operation run without approval.

There is no default allow anywhere. An empty grant list is a deny.

Deny grants narrow themselves differently from allow grants. A constrained deny applies unless the
request clearly falls outside its predicates. The rules the implementation settled:

- **An absent argument does not lift a deny.** If a deny grant constrains an argument that the
  request does not supply, the deny still applies, because the engine cannot know what the adapter
  would default that argument to. A deny is lifted only by an argument that is present and
  different. (An allow grant is the opposite: an absent constrained argument leaves it unsatisfied.)
- **`maxResults` never narrows a deny.** It is a limit on what an allow permits, not a predicate on
  the request, so a deny grant that sets it applies as if it did not.
- **A damaged allow grant is ignored, and a damaged deny grant stays in force** (see above).

### The decision

`PolicyDecision` in `packages/contracts` carries:

- `outcome`: `allow`, `deny` or `approval_required`.
- `reasonCode`: one of a fixed list (`allowed`, `approval_required`, `no_matching_grant`,
  `explicit_deny`, `constraint_violation`, `agent_not_active`, `connection_not_active`,
  `ownership_mismatch`, `operation_unknown`, `invalid_request`).
- `reason`: a sentence for the dashboard and the audit log. It never contains argument values,
  because arguments can hold business data.
- `matchedGrantIds`: the grant that allowed the request, or the grants that denied it.
- `obligations`: argument overrides the broker must apply before execution. The example today is a
  result limit: when a grant sets `maxResults` and the request omits the limit, the obligation sets
  the limit to that maximum. A request that asks for more than the maximum is denied, not clamped.

### No external policy language, and no `policies` table yet

OPA/Rego, Cedar and similar engines are not used. The specification's `policies` table is not
created in Phases 1 to 4, because grants and constraints are the whole policy and a second,
free-form source of authority would have to be reconciled with them.

## Alternatives considered

- **Cedar or OPA/Rego.** Both are capable and would allow richer conditions. Rejected for now: the
  rules above fit in one reviewable function with a table-driven test for every branch, while a
  general policy language adds an interpreter, a second place where authority is defined and a
  syntax owners would need to learn. Nothing AAB needs today is inexpressible as grants.
- **Wildcard operations (`orders.*`).** Convenient. Rejected: a wildcard silently extends to
  operations added by a later adapter version, including writes.
- **Free-form constraint JSON interpreted by adapters.** Rejected: the policy engine could no
  longer say whether a request is allowed, and each adapter would become its own policy engine.
- **Clamp over-limit requests instead of denying.** Rejected: the agent would receive fewer results
  than it asked for with no signal, and the audit would record an allow for a request that was not
  honoured as made.
- **A role model (agents hold roles, roles hold permissions).** Deferred: with a handful of agents
  per owner it adds indirection without removing work.

## Consequences

- Granting an agent ten operations takes ten rows. The dashboard must make that easy, for example
  by creating several grants from one form. It must not do so by introducing wildcards.
- A new kind of constraint is a change to the contracts schema and the engine together, with tests,
  and it is deployed before any grant can use it.
- A constrained deny grant applies only when its constraints match the request; an unconstrained
  deny grant applies always. This is the reading the engine implements. It deserves a sentence in
  the grant editor, because "deny when the status is held" and "deny unless the status is held"
  are easy to confuse.
- `approvalMode` has no meaning on a deny grant, yet the request schema accepts the combination.
  The API should reject it or the dashboard should hide it; today nothing does.
- A deny grant can name an operation the adapter does not define (the specification's own example
  denies `orders.delete`). That is harmless, since the operation is denied by default, but the
  grant will never match and the dashboard should say so.
- The reason codes do not distinguish "you had a grant and it expired" from "you never had one";
  both are `no_matching_grant`. That is safe, but less helpful to the owner than §10.2 intends. The
  simulator can report ignored grants separately without changing the decision.
- The engine itself forces approval for `destructive` operations and for operations the adapter
  marks `requiresApproval`, so a mistake in an owner's grant (`approvalMode: none`) or in an
  adapter's descriptor cannot let a destructive operation run unapproved. The reason text says
  which of the two forced it. The adapter SDK should still keep the two flags consistent so that
  the descriptor tells the truth in the dashboard.

## Revisit when

- An owner needs a rule that cannot be written as grants with these constraints, such as a
  time-of-day window, a rate limit, or a condition on a second argument's relationship to the
  first. One such need is a new constraint key. Three unrelated ones are the signal to evaluate a
  policy language.
- Organization-wide rules that override individual owners' grants are required (Phase 10). That is
  when a `policies` table earns its place.

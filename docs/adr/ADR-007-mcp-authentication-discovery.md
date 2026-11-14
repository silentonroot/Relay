# ADR-007: MCP authentication and tool-discovery scoping

- **Status:** Proposed
- **Date:** 2026-11-11

## Context

In Phase 6 external agents call AAB through an HTTP tool gateway and through a Model Context
Protocol (MCP) server. The specification is firm on two points: MCP is not a privileged bypass
(§12.4), and tool discovery shows only what the requesting agent has been granted (§9.2).

Two things have to be decided: how an agent proves which agent it is, and what the list of tools
looks like for a given agent. Neither is needed before Phase 6. The MCP specification's
authorization model has been changing, so its current state must be checked when the work starts.

## Decision (proposed)

### One path

The MCP server is a thin client of the same gateway endpoint that HTTP agents call. It holds no
database connection, no vault access and no policy logic. Every `tools/call` becomes one operation
request that goes through authentication, schema validation, policy evaluation, approval, job
creation and audit exactly as an HTTP request does. If the gateway would refuse a request, there is
no MCP route around the refusal.

### Agent authentication

- Each agent has its own credential. The first form is a random opaque token of at least 256 bits,
  shown once at creation, stored only as a hash, revocable, and optionally expiring. It identifies
  the agent; it carries no authority. Authority comes only from grants.
- The token is configuration of the agent's runtime (the MCP client's server settings or an
  environment variable of the process that runs the agent). It must not be placed in a prompt, a
  tool description or a tool result. It is a broker credential, not a credential for any target
  application, so INV-1 in [ADR-001](ADR-001-trust-boundaries-worker-isolation.md) still holds if
  it leaks; the damage is bounded by that agent's grants and ended by revoking the token.
- A local MCP server over standard input and output receives the token from its launch
  configuration and forwards it to the gateway. A remote MCP server over HTTP should use the
  authorization flow the MCP specification defines at that time, mapped to the same agent
  identities.
- Every request also carries a run identifier, so that permissions and approvals cannot leak from
  one task to another (§5.1).

### Tool discovery

- `tools/list` is computed per request from the agent's current grants. A tool appears only if the
  agent has an unexpired, unrevoked allow grant for that operation on that connection, no
  unconstrained deny grant covers it, and the connection is in an executable status.
- A tool corresponds to one operation on one connection. The agent sees an opaque connection handle
  and the owner's display name for it. It does not see connections it has no grant on, the list of
  operations an adapter supports beyond its grants, or other agents.
- Tool names, descriptions and input schemas come from the adapter's static operation definitions.
  **Nothing read from a target application is ever placed in a tool name or description.** That
  closes the route by which page content could rewrite the agent's instructions.
- Operations that need approval are listed. Calling one returns `approval_required` with a
  reference the agent can poll; it does not block and it does not prompt the model for anything.
- Discovery is a convenience, not a control. A call to a tool that was not listed is evaluated by
  the policy engine like any other and denied.
- There is no general-purpose tool: nothing that takes a URL, a selector, JavaScript or a shell
  command.

## Alternatives considered

- **One shared key for all agents.** Rejected: grants are per agent, so the gateway must know which
  agent is calling, and one leaked key could not be revoked without stopping everything.
- **Signed self-contained tokens (JWT) carrying the grant list.** Rejected: grants must be
  revocable immediately, so the server has to consult the database on every call anyway, and a
  token that states authority invites trusting it.
- **Mutual TLS client certificates.** Strong for service-to-service use. Deferred: heavy for local
  agent runtimes, and most MCP clients cannot be configured for it.
- **A static tool list with per-call denial.** Simpler. Rejected: it tells every agent the full
  shape of every connected application and encourages it to try.
- **One generic `execute(operation, connection, arguments)` tool.** Fewer tools to list. Rejected
  as the primary interface: the model loses per-operation schemas and makes more malformed calls,
  and per-tool approval settings in MCP clients stop being meaningful.

## Consequences

- The tool list changes when grants change or a connection expires. Clients that cache the list
  will show stale tools until they refresh; the server should send the protocol's list-changed
  notification if clients honour it, and calls to removed tools are denied regardless.
- With many connections and operations the tool list grows as their product. A limit and a naming
  scheme that stays readable need testing with real clients.
- Token storage adds a table that the specification's schema does not list (hashed agent
  credentials, with creation, last use, expiry and revocation).
- The display name of a connection is written by the owner and reaches the model. It is owner
  input, not target-application input, but it should still be length-limited and treated as a label.

## Evidence still missing

- Which MCP clients AAB must work with first, and which transports and authorization flows they
  support at that time.
- The current MCP authorization specification. Its state at the time of writing was not verified.
- Whether clients act on list-changed notifications.
- How large a tool list those clients handle well.

## The spike that settles it

At the start of Phase 6: stand up the gateway with opaque tokens, put a minimal MCP server in front
of it, and connect two real clients as two agents with different grants on the same Northstar
connection. Confirm that each sees only its own tools, that revoking a grant mid-session removes
the capability on the next call, that an unlisted tool call is denied and audited, and that no
token appears in any transcript.

## Revisit when

- Phase 6 begins.
- The MCP authorization specification changes in a way that affects remote servers.
- Agents need to act for more than one owner (Phase 10), which changes what an agent identity is.

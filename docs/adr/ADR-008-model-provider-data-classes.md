# ADR-008: Model providers and data classes

- **Status:** Proposed
- **Date:** 2026-11-11

## Context

AAB moves business data from web applications toward language models. An operation such as
`orders.get` returns customer names, order contents and free-text notes. Whoever receives that
result, the agent's model provider included, has received that data. The specification says that
company use "requires organizational authorization and review of data handling, model provider,
automation policies, and audit requirements" (§13.4), asks for a "model-provider abstraction with
budget, token, and cost limits" (§9.2), and requires the model provider to be disabled by default
(§19). It leaves open which providers may receive which data (§21, ADR-008).

Two different things are called "the model" in this project, and the decision has to treat them
separately.

1. **An external agent** (an MCP client, a script, a hosted assistant) calls AAB's tool gateway
   from Phase 6. It brings its own model and its own provider. AAB sees only the agent's requests
   and sends back sanitized results. Once a result has been delivered, AAB has no control over where
   it goes next. It cannot verify which provider the agent uses, whether the agent logs prompts, or
   whether the provider retains them.
2. **A model that AAB itself calls.** Phase 6 lists "integrate a configurable hosted/local LLM
   provider through an adapter", and the orchestrator of Phase 7 may use one to choose workflow
   steps. Here AAB builds the request, so it can decide what goes into it and can count what comes
   back.

Nothing in Phase 1 contacts a model, and the repository contains no provider code. This record is a
recommendation, the evidence that is missing, and a spike. The three constraints below are already
fixed by the specification and by [ADR-001](ADR-001-trust-boundaries-worker-isolation.md), and the
proposal does not reopen them.

- Authentication material (passwords, cookies, tokens, session snapshots, ciphertext, wrapped keys,
  KEKs) never reaches a model, whichever provider it is (INV-1).
- The provider is off unless the owner turns it on (§19).
- Deterministic tests need no model, no network and no provider key (§19). The CI workflow has no
  secrets and the test command runs on in-process PGlite, so this holds today.

## Decision (proposed)

### Data classes

Every piece of data that AAB could place in front of a model belongs to one of these classes. The
list is ordered by how much damage disclosure does.

| Class | Name                | What it contains                                                                                                                                                                                                          |
| ----- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D0    | Authentication      | Passwords, cookies, bearer and refresh tokens, browser storage state, vault ciphertext, wrapped keys, KEKs, agent and session tokens.                                                                                     |
| D1    | Business data       | Whatever a target application shows about real people and real transactions: customer names, addresses, order contents, amounts, free-text notes. Treated as personal data.                                               |
| D2    | Control metadata    | What the owner wrote or the broker generated about its own configuration: operation names, connection display names, grant shapes, policy reason codes, error codes, run status.                                          |
| D3    | Audit and telemetry | Redacted audit summaries, structured log lines, metrics.                                                                                                                                                                  |
| D4    | Synthetic data      | Fixtures and seed data that were generated for development and testing, including the Northstar demo's records. Contains no real person or company data by rule ([ADR-012](ADR-012-synthetic-only-dependency-review.md)). |

D0 is not part of the matrix below because no provider may receive it. A code path that would put
D0 into a prompt is a defect, and the existing canary test design (INV-1) is the check.

### Provider classes

| Class | Name               | Meaning                                                                                                                                                                          |
| ----- | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P0    | None               | No model is configured. The default.                                                                                                                                             |
| P1    | Local              | A model that runs on the owner's own machine or network and sends nothing to a third party. AAB's configuration records the endpoint, and it must be a loopback address.         |
| P2    | Hosted, authorized | A hosted provider that the organization has reviewed and approved in writing for the data classes below, under terms covering retention, training use, region and subprocessors. |
| P3    | Hosted, unreviewed | Any other hosted provider, including a personal account on a hosted service, and any provider whose terms nobody has read.                                                       |

### Recommended matrix

"Yes" means the class may appear in a request to that provider. "Owner decision" means the owner
may allow it for a specific agent after reading the provider's terms, and the allowance is
recorded. "No" is a rule the broker enforces where it can and documents where it cannot.

| Data class          | P0 none | P1 local | P2 hosted, authorized | P3 hosted, unreviewed |
| ------------------- | ------- | -------- | --------------------- | --------------------- |
| D1 business data    | n/a     | Yes      | Owner decision        | No                    |
| D2 control metadata | n/a     | Yes      | Yes                   | Yes                   |
| D3 audit, telemetry | n/a     | Yes      | Owner decision        | No                    |
| D4 synthetic data   | n/a     | Yes      | Yes                   | Yes                   |

Three rules sit under the matrix.

1. **Real business data needs a reviewed provider.** D1 goes only to P1, or to P2 after the owner
   has recorded the review. Until the project has a way to record that review, the effective rule
   is that D1 goes only to P1, and development uses D4 with any provider.
2. **Provider prompts and responses are not logged by default.** This restates §18. Enabling prompt
   logging is a separate setting, it applies only to D4 data, and it is off in every shipped
   configuration.
3. **Page content stays data.** Whatever class a result belongs to, text read from a target
   application is untrusted ([ADR-001](ADR-001-trust-boundaries-worker-isolation.md), INV-14). It is
   never placed in a system prompt, a tool description or a tool name.

### Where the matrix can be enforced

The two kinds of model need different mechanisms, and only one of them is a control.

- **A model that AAB calls (P1, P2, P3 configured in AAB).** AAB builds every request, so a
  provider adapter can refuse to send a payload whose declared class exceeds the provider's class.
  The orchestrator tags what it assembles with a class, and the adapter checks the tag. This is
  enforcement, with the limit that the tag is only as good as the code that sets it.
- **An external agent.** AAB cannot see the agent's provider. The proposed mechanism is a
  **declared ceiling**: when the owner registers an agent they state the highest data class that
  agent's provider may receive, and the broker refuses to return a result of a higher class to
  that agent. Each adapter operation would declare the class of its output, defaulting to D1 when
  the author says nothing. The refusal happens during policy evaluation, before any job exists.
  This is an **attestation by the owner, not a verification**. The broker cannot know whether the
  declaration is true, and the documentation must say that.

Neither mechanism exists. Both need schema work: a `dataClass` on the operation descriptor and on
the operation definition in `packages/adapter-sdk`, and a ceiling attribute on agents. The policy
constraint set is closed ([ADR-005](ADR-005-policy-representation.md)), so a ceiling is better
modelled as an attribute of the agent that the engine checks, not as a new grant constraint. That
choice belongs to the spike.

### Run ceilings

When AAB calls a model, every run carries two ceilings, set by the owner and checked by AAB.

- A **token ceiling**: the sum of input and output tokens across all model calls in the run. This is
  the hard control, because token counts come from the provider's usage report and from AAB's own
  count of what it sent.
- A **cost ceiling** in a stated currency, computed from token usage and a price table that the
  owner maintains in configuration. It is an estimate. Prices change, and AAB does not fetch them.

A call that would take the run past either ceiling is not made. The run ends in `failed` with a
reason recorded in the audit trail, and no further model call is attempted. There is no
silent truncation and no automatic retry that spends more. The normalized error codes
(`packages/contracts`, `ErrorCode`) have no budget code today. Whether to add one or to report the
condition under an existing code is settled in the spike, because adding a code changes the
contracts first.

For an external agent AAB sets no ceiling, because AAB does not see the agent's model usage. What AAB
can bound for such an agent is the number and rate of operations, which the specification already
plans for Phase 6.

### Defaults and tests

- The configuration default is `provider: none` (P0). No provider adapter is constructed unless
  the owner configures one, and no network call to a model host is possible in that state.
- The test suite uses a scripted deterministic agent client and a fake provider that returns
  canned responses and reports fabricated token usage. These cover the policy path, the
  ceilings and the matrix without a model.
- A test that calls a real model is opt-in, lives outside the default `pnpm test` command, reads its
  key from the environment of the person running it, uses D4 data only, and is never run in CI.

## Alternatives considered

- **Send everything to any provider the owner picks.** The simplest design, and it ignores what
  §13.4 says about company use. It makes AAB's "no credentials" claim true and leaves business
  data exposure to chance.
- **Refuse all hosted providers.** The safest position, and it makes AAB useless to people whose
  agents run on hosted models, which is most of them. The matrix keeps the safe default and lets an
  informed owner relax it.
- **Redact or tokenize D1 fields before sending them to P2 or P3.** Attractive because the model
  could still reason over placeholders. Rejected for now: reliable detection of personal data in free
  text is an unsolved problem, an operation that returns a name needs the name, and a false sense of
  safety is worse than a clear rule. It stays open as a later refinement for named, structured
  fields only.
- **A cost ceiling only.** Owners think in money. Rejected as the sole control, because it depends on
  a price table that can be wrong or stale. Tokens are counted by the provider and by AAB, so they
  are the hard limit and cost is derived.
- **Provider allowlist inside the agent gateway.** Would require the gateway to know the agent's
  provider, which it cannot observe. The declared ceiling states the same thing honestly.

## Consequences

- AAB cannot stop an external agent from sending a result to a provider the owner mis-declared, or
  from forwarding a result anywhere. The security documentation must say that the matrix is enforced
  for models AAB calls and is a declared policy for external agents.
- Operation authors must classify output. The default of D1 is the safe one and will annoy people
  whose operations return only counts. Classifying a field as lower than it is would break the
  matrix silently, so a review rule is needed: a class below D1 needs a stated reason in the
  adapter's pull request.
- A provider adapter, a fake provider and the ceiling accounting are new code on the path of every
  model-backed run. They need negative tests: a run stopped at the ceiling, a payload refused for its
  class, a provider that reports no usage.
- The price table is configuration that can be wrong. A wrong table makes the cost ceiling
  misleading, never the token ceiling.
- Recording "the owner reviewed provider X for class D1" needs a place in the data model. That is
  a table or a setting that the schema does not have.

## Evidence still missing

- What each candidate provider's written terms say about retention, training use, regions,
  subprocessors and deletion. **None has been read for this record**, and it names no provider on
  purpose. A person with authority to accept those terms has to read them.
- Whether providers report token usage for interrupted or streamed responses, and whether cached
  or reasoning tokens are counted in the figures they report. Ceiling accounting depends on both.
- Whether adapter authors can classify output reliably, and how often the default D1 is too
  strict to be useful.
- How the MCP clients that AAB must serve behave: whether they expose their provider to the server
  at all.
- Which organizations, if any, will run AAB against real data, and what review they require. This
  decides how much of "Owner decision" is needed.

## The spike that settles it

At the start of Phase 6, in a throwaway branch:

1. Define the provider adapter interface and write three implementations: a scripted fake, a local
   model behind a loopback endpoint, and one hosted provider used with D4 data only.
2. Run a deliberately looping agent against each. Confirm that the token ceiling stops the run within
   a stated margin of the limit, that the reported usage and AAB's own count agree within a stated
   tolerance, and that the run ends in the recorded state.
3. Plant canary strings of each data class in fixtures. Capture the outbound request body of each
   provider with a recording proxy and confirm that no class above the provider's ceiling and no D0
   canary appears in it.
4. Add the `dataClass` field to one adapter operation and a ceiling to one agent, and confirm that
   an agent with a lower ceiling is refused before a job is created, and that the refusal is audited.
5. Have the person who owns the data-handling decision read the terms of the hosted candidate and
   fill in the matrix for it.

When the spike is done, replace this record with an Accepted one that states the matrix, where the
ceiling lives, how a budget stop is reported, and what remains an attestation.

## Revisit when

- Phase 6 begins (run the spike).
- Any real business data is about to pass through AAB.
- A hosted provider is proposed as the default for any shipped configuration.
- An external agent needs results of a class above its declared ceiling for a legitimate reason.
- The set of providers or their terms change in a way that moves a provider between classes.

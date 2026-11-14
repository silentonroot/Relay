# ADR-006: Adapter packaging, trust and upgrades

- **Status:** Proposed
- **Date:** 2026-11-11

## Context

An adapter is the code that knows how to perform named operations on one web application. It runs
inside the worker with a signed-in browser session in its hands. A malicious or careless adapter
can do anything the user can do on that application. Adapters are therefore part of the trusted
computing base, and how they are packaged, reviewed and upgraded is a security decision.

Only one adapter exists (Northstar, for the synthetic demo), and it has not yet executed against a
browser. The parts of this record that depend on that experience are proposals.

## Decision (proposed)

1. **Adapters are workspace packages in this repository**, under `packages/adapters/<id>`, written
   against `packages/adapter-sdk`. They are reviewed, tested and released exactly like the rest of
   the code. The demo adapter lives here; the demo application's source does not
   ([ADR-012](ADR-012-synthetic-only-dependency-review.md)).
2. **No dynamic loading.** The worker imports its adapters statically and registers them at start.
   There is no plugin directory, no installation of adapters from a registry at run time, and no
   adapter code supplied through the API or by an agent.
3. **An adapter is identified by `id` and `version`.** An application definition records both
   (`adapterId`, `adapterVersion` in `packages/contracts`). The worker executes a job only with the
   exact adapter version the application definition names, and refuses if that version is not
   registered.
4. **Signing is not introduced** while every adapter is in this repository. Their integrity is the
   repository's integrity: review, the lockfile and the release process.
5. **Upgrades are explicit.** A new adapter version does not silently replace the one an
   application definition uses. The owner (later, an administrator) moves the application
   definition to the new version, and that change is audited.
6. **An operation's meaning is stable within a major version.** Changing an operation's
   sensitivity, side effects, resource argument or approval requirement, or widening its input, is
   a breaking change. It needs either a new operation name or a new major version. On a major
   upgrade, existing grants for that application are suspended until the owner confirms them
   against the new operation list.

## Alternatives considered

- **Third-party adapters loaded at run time.** This is how AAB would grow an ecosystem. Rejected
  for the foreseeable future: it turns "install an adapter" into "run arbitrary code with my
  sessions", and containing that needs per-adapter sandboxing that does not exist.
- **Declarative adapters (a data file of selectors and steps interpreted by the worker).** Reduces
  the code that must be trusted and is worth exploring for read operations. Not chosen as the
  contract: real applications need logic for pagination, state checks before writes and
  postcondition verification that a step list expresses poorly.
- **Signed adapter packages.** Deferred until adapters are distributed separately from the worker.
  Signing an artifact built from the same repository in the same pipeline adds ceremony and no
  independent check.
- **Always use the newest adapter version.** Rejected: an upgrade that adds a write operation or
  changes a selector could alter what existing grants permit without anyone deciding it.

## Consequences

- Supporting a new application means a code change and a release. That is slow by design.
- Old adapter versions must stay registered while any application definition still names them,
  which means carrying their code and tests until the migration is complete.
- The rule in point 6 needs tooling to be more than a convention: a check that compares the
  operation descriptors of two adapter versions and fails when a breaking change is not accompanied
  by a major version bump. That check does not exist yet.
- Grant suspension on major upgrade is not in the data model yet. It needs either a status on
  grants or a version stamp that the policy engine compares.

## Evidence still missing

- How often a real application's interface changes force adapter updates, and whether those updates
  are usually selector-only (patch) or behavioural.
- Whether two versions of one adapter can be loaded side by side in one worker without sharing
  state.
- Whether selector-only changes can be safely auto-adopted.

## The spike that settles it

During Phase 2, change the Northstar demo's markup in a way that breaks the adapter, release a
patch adapter version, and walk the upgrade end to end with a connection and grants in place.
During Phase 4, add a write operation in a minor version and confirm that no existing grant gains
authority. Record what the process needed that this proposal does not provide.

## Revisit when

- The first adapter for an application we do not control is proposed.
- Someone outside the core contributors wants to supply an adapter.
- The Phase 2 and Phase 4 spikes above are complete.

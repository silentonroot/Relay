# ADR-012: Synthetic-only development and dependency review

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

AAB's purpose is to hold real credentials and sessions for real web applications. While it is being
built it must not hold any. A development setup that quietly accumulates a real cookie in a test
fixture, a customer name in a seed file or a personal API key in a prompt has already failed, because
repositories are copied, pushed, indexed and shared, and prompts and logs leave the machine.

Two kinds of risk meet here. The first is data: anything real that enters the repository, the
fixtures, the prompts, the logs or the commit history. The second is code: every dependency is
third-party code that runs on developer machines at install time and inside the broker at run time,
sometimes next to session material. The specification's own rules cover both (§1.2, §13.3, §22 rule
4), and its Phase 0 task list asks for "a synthetic-only development policy and license/dependency
review checklist". This record is that policy and that checklist.

## Decision

### Synthetic data only

Nothing real goes into any of the following, at any time, by anyone, including the maintainers:

- **Source code and tests.** No real credential, token, cookie, key, private URL, company name,
  customer, employee or personal data.
- **Fixtures and seed data.** Generated for development, labelled as synthetic where a human might
  read them, and free of anything derived from a real system by copying and editing.
- **Prompts.** Prompts, tool descriptions and conversations used to build or test AAB, whether typed by a
  person or assembled by a program, contain no real data ([ADR-008](ADR-008-model-provider-data-classes.md)
  holds the same line for data that AAB sends to models).
- **Logs, traces, screenshots and recordings,** in the repository or attached to an issue or a pull
  request.
- **Commit messages, branch names, issues and pull request text.**
- **Accounts.** No development or test activity uses a real third-party account. That includes a
  personal account on a hosted service, an account at a company, and a model-provider account whose
  data terms nobody has reviewed. The only accounts used are the local demo's synthetic ones.

Rules that make this practical:

1. **Reserved names only.** Hosts in fixtures and tests are drawn from names that can never belong to
   anyone: the domains `example.com`, `example.net`, `example.org`, and the top-level names `.example`,
   `.test`, `.invalid` and `.localhost` (RFC 2606 and RFC 6761); loopback addresses (`localhost`,
   `127.0.0.1`, `[::1]`); and the documentation address blocks `192.0.2.0/24`, `198.51.100.0/24` and
   `203.0.113.0/24` (RFC 5737). Email addresses use the same domains. The adapter SDK's own tests
   use `app.example.test`, and the demo is reached at `http://localhost:4100`. The shared `Origin`
   schema allows plain HTTP only for loopback hosts, so a real hostname without TLS cannot be
   registered.
2. **No credential has a default, and none is committed.** `.env.example` holds blank values and
   comments, and says that a blank required value must be set before the API will start (the API
   was being written when this record was made, so that behaviour is not yet verified). Passwords for demo accounts are
   generated randomly each time the demo database is reset and printed once. The owner account is
   created by an interactive command and no environment variable carries its password. Key files are
   outside the repository ([ADR-003](ADR-003-local-vault-root-key.md)). Tests generate throwaway keys
   in memory or in a temporary directory.
3. **Canaries are obviously fake.** Planted secrets used in leak tests are random strings with a
   recognizable prefix and no resemblance to a real secret format that a scanner would be trained to
   find, so that finding one is a test result and not an incident.
4. **A secret scan covers history.** The CI workflow runs a secret scanner over the full commit
   history, with no network and with findings redacted in the log. A finding is handled as an incident
   (rotate or revoke first, then remove from history if needed), not as a lint failure.
5. **CI has no secrets.** No job in the workflow references one.

Nothing in the repository checks mechanically that a fixture's hostnames are reserved or that a
fixture contains no personal data. The secret scan looks for credentials, not for customer names.
Rules 1 and 3 are therefore enforced by review today. A test that scans fixtures for hostnames
outside the reserved list would be a cheap addition.

### When real data may enter

Not before the conditions of [ADR-001](ADR-001-trust-boundaries-worker-isolation.md) and
[ADR-003](ADR-003-local-vault-root-key.md) are met: container isolation for the worker, the vault
service, an external review of the cryptography and the vault boundary, and a decision about model
providers ([ADR-008](ADR-008-model-provider-data-classes.md)). Using AAB with a real third-party
account is a separate decision that needs its own record. It is not a matter of a developer pointing
a connection at a real site.

### The Northstar demo is a separate repository and an external trust domain

Northstar is the synthetic target application. Its source lives in its own repository, with its own
database, build and Compose file. This repository contains only the adapter
(`packages/adapters/northstar`), which depends on the demo's documented `data-testid` contract and on
nothing else in it.

- The broker never imports demo code, never reads the demo's database, and never links to its
  internals. The broker's Compose file does not build or start the demo.
- The broker treats the demo exactly as it would treat any web application it does not control: it
  is an external trust domain, its pages are untrusted input, and one seeded order note contains a
  prompt-injection string for that reason (§2).
- Demo-specific names (orders, SKUs, statuses) stay in the adapter. The broker core must not learn
  them. A change that leaks them into `contracts`, the policy engine or the database is a defect.
- A change in the demo's interface shows up as a change to the adapter's selector constants and
  nowhere else.

### Dependency review checklist

Before any dependency is added, or upgraded to a new major version, the person proposing it fills in
the checklist below in the pull request, and the dependency owner (§22.1) installs it. A dependency
that fails an item is not added unless the pull request says why and a second person agrees.
Anything that affects what the broker does with secrets or page content gets items 8 and 9 in full.

```text
Dependency:          name, version, the registry page or repository
Purpose:             what it does for us, in one sentence
Needed:              why a Node built-in or code we already have is not enough

1. Licence            SPDX identifier of the package and of its production dependencies.
                      Compatible with the licence this repository is published under?
2. Maintenance        Date of the latest release. Releases in the past year. Number of people who can
                      publish it. Open security advisories. Archived or deprecated? A single
                      maintainer is acceptable only for small, readable packages.
3. Install scripts    Does it, or anything it pulls in, declare preinstall, install or postinstall
                      scripts, or build native code? If yes, name the script, read it, and justify
                      an entry in the install-script allowlist. Prefer an alternative with none.
4. Transitive count   Number of packages the change adds to the lockfile (compare the lockfile
                      before and after). Anything with a large tree for a small job is replaced or
                      written by hand.
5. Release age        The release is at least as old as the package manager's minimum release age.
                      The guard is never bypassed to take a newer one. A security fix that cannot
                      wait is a recorded exception in the pull request.
6. Where it runs      Development only, build time, the dashboard, the API, or the worker and vault
                      path. The closer to secrets, the stricter the bar.
7. Runtime behaviour  Makes network calls? Sends telemetry? Reads files outside its own use, or the
                      process environment? Starts processes? Uses eval or dynamic code loading?
8. Touches secrets    Does it handle credentials, keys, session material, tokens, page content or
                      audit data? If yes: read the relevant source, not only the documentation;
                      prefer Node built-ins; and say how a compromise of it is contained.
9. Types and format   Ships its own types, supports ESM and Node 24, and works under the repository's
                      TypeScript and lint configuration.
10. Alternatives      The best alternative considered and why it lost, or "none exists".
11. Evidence          Where each statement above was checked (registry listing, the package's own
                      repository, the lockfile diff) and on what date.
```

An architectural dependency, one that shapes a package's design (a queue library, a policy language, an
orchestration engine), also gets its own decision record, as [ADR-004](ADR-004-job-queue.md) does,
including the registry facts it was chosen on. Statements about behaviour that have not been tested
are marked as unverified.

Review is repeated when a dependency's maintainer changes, when it publishes an install script it did
not have, and at each phase's security checklist ([security.md](../security.md)).

## Alternatives considered

- **Test against a real account "just once".** The most common way real credentials enter a project.
  Rejected without exceptions until the conditions above are met. The demo exists so that this is never
  needed.
- **Real data with masking applied before it enters fixtures.** Masking is a transformation that can
  fail silently, and the unmasked original has to exist somewhere on a development machine first.
  Synthetic data has no original to leak.
- **Put the demo application in this repository.** Convenient, and it would let broker code depend on
  demo internals without anyone deciding to. A separate repository makes the boundary a real one and
  proves that the adapter works against an application the broker does not control.
- **Rely on the secret scanner alone.** Scanners find patterns, not meaning. They do not catch a
  customer's name, an internal URL or a credential in an unusual format. They are one layer.
- **A larger approved-dependency list.** Maintaining an allowlist of packages is the same work as the
  checklist, with less context. The checklist is applied to each addition, and the lockfile is the list.
- **No review for development-only dependencies.** Development tools run on every contributor's machine
  and read the whole repository, so install scripts and network behaviour matter for them too. The
  checklist applies; its items weigh less for tools that never ship.

## Consequences

- Development is slower in some places: demo data has to be built, a second repository has to be run,
  and some bugs that only appear against a real application will be found late.
- Every dependency costs someone fifteen minutes of reading. This is the intended price.
- The reserved-name rule limits some tests. A test of internationalized domain handling, for example,
  has to use `.test` names with the unusual characters and not a real look-alike domain.
- Enforcement is partly human. The secret scan and the install-script allowlist are mechanical. Reserved
  names in fixtures, absence of personal data and the quality of the checklist answers depend on review.
- The repository has no `LICENSE` file at the time of writing, so item 1 of the checklist cannot yet be
  answered fully. The licence has to be chosen before the first public release.
- Prompts are the weakest point. They are written by people and by coding agents under time pressure, and
  nothing inspects them. The rule works only if contributors and the tools they use are told it, and the
  contributor guidance has to say so.

## Revisit when

- A real third-party account or any real business data is proposed for any purpose.
- The first adapter for an application we do not control is proposed ([ADR-006](ADR-006-adapter-packaging-trust.md)).
- A leak is found, by the scanner or by a person. The record should then be reviewed for what failed.
- Someone proposes moving the demo into this repository, or having the broker depend on its internals.
- The repository's licence is chosen, or the dependency owner role changes.

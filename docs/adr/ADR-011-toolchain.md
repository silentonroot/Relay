# ADR-011: Toolchain

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

The toolchain is a security decision as well as a convenience. Dependencies run with the permissions
of the person installing them, install scripts execute code on the developer's machine, and the
test setup decides whether the security tests get run at all. The project is also developed by
several people and coding agents in parallel (specification §22.1), so a shared, small set of
conventions matters.

The versions below were checked against the package registry on 2026-11-11 and are the ones in
`package.json`, `pnpm-lock.yaml` and the package manifests at that date. Where this record explains
why a version is held back, the reason is the state of the ecosystem on that day.

## Decision

### Runtime and language

- **Node.js 24.** `engines.node` is `>=24`, the CI workflow and the container image use Node 24, and
  the code relies on `node:crypto` for every cryptographic primitive. The demo application uses
  `node:sqlite`, which Node 24 provides (§2).
- **TypeScript pinned to 6.0.x** (`~6.0.3`; the lockfile resolves 6.0.3). TypeScript 7 was current on
  2026-11-11, but `typescript-eslint` did not yet support it: its supported range stopped below 6.1
  (§4). Running the linter against an unsupported compiler produces wrong or missing diagnostics, and
  the linter is how rules such as `no-console` and `no-explicit-any` are enforced. The pin is a
  tilde range so patch releases of 6.0 are accepted and 6.1 or 7 are not.
- **Strict compiler settings** in `tsconfig.base.json`: `strict`, `noUncheckedIndexedAccess`,
  `noImplicitOverride`, `noImplicitReturns`, `noFallthroughCasesInSwitch`, `verbatimModuleSyntax`,
  `isolatedModules`, `NodeNext` modules, `noEmit`. Relative imports carry a `.js` suffix, as
  NodeNext requires. Each package extends the base file.

### Package manager and installation

- **pnpm 12**, activated through Corepack and pinned in the `packageManager` field
  (`pnpm@12.18.0`). The workspace has four globs: `apps/*`, `services/*`, `packages/*` and
  `packages/adapters/*`.
- **The minimum-release-age guard stays on.** `pnpm-workspace.yaml` does not override it, and nobody
  may disable it to get a release through. During setup the guard refused a Vite release that had been
  published a few hours earlier, and the previous release was installed instead. That is the guard
  working as intended: a newly published version is the one most likely to be a compromised or
  mistaken upload, and the waiting period is the cheapest defence against it. The specification lists it
  as a control against malicious dependencies (§13.3).
- **Dependency install scripts are allowlisted.** `pnpm-workspace.yaml` has an `allowBuilds` entry for
  `esbuild` and nothing else. A package that wants to run a script at install time is blocked until
  someone adds it to that list in a reviewed change, with a reason ([ADR-012](ADR-012-synthetic-only-dependency-review.md)).
- The lockfile is committed. CI installs with `--frozen-lockfile`, so the lockfile and the manifests
  cannot drift, and CI runs `pnpm audit` for shipped dependencies, with a blocking threshold of high
  severity.
- Dependencies are added by one owner, who installs once (§22.1). A parallel worker that needs a new
  dependency reports it.

### Schemas, database and tests

- **Zod 4 is the single schema language.** Request and response shapes, entity shapes, the policy
  request and decision, operation definitions, configuration and the audit event are Zod schemas in
  `packages/contracts` or are built from them. TypeScript types are inferred from the schemas, so a
  type and its validator cannot disagree. The dashboard, the API, the policy engine and the adapter
  SDK all validate with the same objects.
- **Drizzle ORM with committed SQL migrations.** The schema is `packages/database/src/schema.ts`.
  `drizzle-kit generate` produces SQL files in `packages/database/drizzle`, which are reviewed and
  committed, and the generated snapshot sits beside them. The migration runner in
  `packages/database/src/migrate.ts` applies those files itself, in one transaction behind an
  advisory lock, and keeps Drizzle's bookkeeping table so the two stay interchangeable. The
  `schema.ts` file repeats the enum value lists of the contracts package because drizzle-kit's
  bundler does not follow the workspace's `.js` import suffixes, and a test fails if the two lists
  differ.
- **PostgreSQL in deployment, PGlite in tests.** The deployed database is PostgreSQL (the Compose file
  uses the 18 image) through `pg`. Tests use PGlite, PostgreSQL compiled to WebAssembly and run in the
  test process, through `createTestDatabase`. The whole suite therefore needs Node.js and the
  installed dependencies, and no Docker. Repository code is written against a driver-independent
  `Db` type so the same code runs on both.
- **Vitest** runs every package's tests, with `jsdom` and Testing Library for the dashboard.
  Tests live beside the package they test.
- **ESLint with a flat configuration**, on ESLint 10 and `typescript-eslint`. `no-console` is an
  error across the repository, so output goes through the structured logger, which redacts. The
  exceptions are command-line entry points under `scripts` and `seed` directories and configuration
  files. `no-explicit-any`, `eqeqeq`, consistent type imports and unused-variable checks are errors,
  and the React hooks rules apply to the dashboard. Prettier formats all files.

### Packages and services

- **Internal packages export TypeScript source, with no build step.** A package's `exports` field
  points at `./src/index.ts`, and its consumers import that file through the workspace. `tsc --noEmit`
  is the typecheck and nothing emits JavaScript. The services run with **tsx**, which strips the types
  at start-up: `tsx watch src/main.ts` in development, and the container's start command loads tsx.
  The dashboard is the exception, since a browser needs a bundle: Vite builds it.
- **Docker Compose is deployment packaging.** It is not how development or testing works.
  `infra/compose.yaml` is checked by `docker compose config`, and building the images and running the
  stack are verified separately from the test suite. CI does not run Compose.

## Alternatives considered

- **TypeScript 7 now.** The newest compiler, and `typescript-eslint` does not support it. Rejected until it
  does. Dropping the linter's type-aware rules to use it would trade a real control for speed.
- **Disable the minimum-release-age guard, or set it to zero, to take the newest release.** Rejected. It
  is a deliberate control and its refusal is a signal, not an obstacle.
- **Allow all install scripts.** Standard behaviour of other package managers. Rejected: install scripts
  are a primary route for supply-chain attacks, and only esbuild needs one.
- **npm or Yarn.** Workable. pnpm's strict `node_modules` layout means a package can only import what it
  declares, which keeps the package dependency graph honest, and its install-script and release-age
  controls are the ones we want.
- **Another schema language (JSON Schema, io-ts, TypeBox, ArkType).** Each is capable. A single language
  was the requirement, Zod 4 is widely understood, and it validates in the browser and on the server
  from one definition.
- **Prisma, or a query builder such as Kysely.** Prisma is also viable (§4). Drizzle keeps the schema as
  TypeScript, produces plain SQL migrations that can be read in review, and runs on both drivers. Its
  cost is a younger ecosystem and a migration runner that we wrote partly ourselves.
- **SQLite or a mock in tests.** Rejected: SQL dialects differ, and the security behaviours under test
  (advisory locks, check constraints, `jsonb`, row locks) are PostgreSQL features. PGlite runs the same
  SQL.
- **Testcontainers or a Docker PostgreSQL for tests.** The faithful option, and it would make Docker a
  prerequisite for running any test, including on machines without it. Kept as a candidate for a
  separate integration suite.
- **Jest.** Established. Vitest runs TypeScript and ESM natively with no configuration, and Vite is
  already needed for the dashboard.
- **A build step for every package (tsup, tsc to `dist`).** The conventional choice for publishing.
  Nothing here is published, and a build step adds an output directory that can go stale and be
  tested instead of the source.
- **Compose as the development environment.** Rejected: it makes the tests depend on Docker and hides
  failures behind image builds.

## Consequences

- Holding TypeScript at 6.0 means missing features and fixes from newer compilers. It also means a
  deliberate upgrade later, when the linter supports a newer version.
- The release-age guard slows the adoption of security fixes as well as of bad releases. A fix that
  must be taken at once needs a recorded exception in the change that makes it, with the reason. No
  such exception exists today.
- Because the install-script allowlist exists, a new dependency that needs a script fails to install
  and someone must decide. That is the intended cost.
- Running TypeScript through tsx in production means no type checking at run time (CI's
  `typecheck` is the only check), a transform at every start-up, no build artefact to scan or sign,
  and a development dependency (`tsx`) that has to be present in the image. The Dockerfile already
  notes that `tsx` is a root development dependency and should become a dependency of the API. If
  packages are ever consumed outside this repository, or start-up time or image size matters, this
  decision needs revisiting.
- PGlite is not PostgreSQL. It runs one connection, so transactions execute one after another and
  lock contention is not exercised (the audit chain's concurrency test shows the sequence is correct,
  not that the lock holds under load). Its server version is not the one in the Compose file, and
  differences were not audited. The risk is a defect that appears only on a real server. A smoke run of
  the migrations and the repository tests against the real PostgreSQL image before a release would
  reduce it, and it does not exist yet.
- `schema.ts` duplicates enum lists from the contracts package. The drift test is the only thing
  keeping them aligned.
- Every package that imports TypeScript source relies on the workspace to resolve it. A package cannot be
  used from outside the workspace without a build.
- The logger that `no-console` points to is part of the API service, which was being written when this
  record was made. The lint rule is in place and the logger itself was not reviewed for this record.
- Compose passing `docker compose config` shows that the file is well formed, not that the stack works.

## Revisit when

- `typescript-eslint` supports a newer TypeScript, which is when the pin moves.
- A package is to be published or used outside the workspace, or the container image size or start-up
  time becomes a problem (add a build step).
- A security fix cannot wait for the release-age window.
- A defect is found that only a real PostgreSQL server shows (add a real-database suite).
- Another dependency needs an install script.
- Node 24 leaves long-term support, or the demo or the packages need a newer runtime feature.

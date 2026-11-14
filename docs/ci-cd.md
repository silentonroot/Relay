# CI/CD and maintenance

How changes are checked, how a release is published, and what runs on a schedule. The pipelines
are GitHub Actions workflows in `.github/workflows/`, written for the repository
`silentonroot/Relay`.

**Status on 2026-11-14: `ci.yml` has run on GitHub and passed all five jobs; `nightly.yml` ran once
(run 43585891090, 2026-11-14 10:34 UTC, commit 640bd27) and failed; `release.yml` has not run.**
In that run "Sandbox isolation tests", "Advisories and secret scan" and "Report a failed
scheduled run" worked, "End-to-end test" skipped itself (the `NORTHSTAR_DEMO_REPOSITORY`
variable is not set), and "Rebuild and scan images" failed because the scanner found HIGH and
CRITICAL vulnerabilities with fixes available, not because the script is broken (see
[The first nightly failure](#the-first-nightly-failure)). The failure opened issue #4. Dependabot
has run for all four configured ecosystems. The table in
[What has and has not been run](#what-has-and-has-not-been-run) says, for each job, where it has
run.

## Overview

| Workflow                          | Runs on                                        | Purpose                                                                  |
| --------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------ |
| `ci.yml`                          | Every pull request, every push to `main`       | The gate for a change                                                    |
| `nightly.yml`                     | Every day at 03:17 UTC, and on demand          | Slow isolation tests, and checks for things that change without a commit |
| `release.yml`                     | A pushed version tag (`v1.2.3`, `v1.2.3-rc.1`) | Publish container images and a GitHub release                            |
| `dependabot.yml` (not a workflow) | Mondays at 06:00 UTC                           | Propose dependency, action and base-image updates as pull requests       |

There is no deployment workflow. AAB is installed and run by its owner on their own machine, so
"CD" here means continuous delivery: a release produces verifiable artifacts that an owner
pulls. Nothing is pushed to anyone's running system.

## CI: the gate for a change

Five jobs, all with read-only access to the repository and no secrets.

| Job                | What it does                                                                                                                                                                                                                        |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `verify`           | Installs with the frozen lockfile, then ESLint, Prettier check, type checking, every package's unit tests, and the dashboard's production build.                                                                                    |
| `database`         | Runs the database suite again on a real PostgreSQL 18 service, which adds the concurrent job-claim test that the in-process database cannot run.                                                                                    |
| `containers`       | Runs `infra/ci/compose-smoke.sh` (build the API and dashboard images, start the Compose stack, check it, remove it), builds the browser-runner image, and runs a job through the Docker launcher with skipping turned into failure. |
| `secret-scan`      | gitleaks over the full history, from an image pinned by digest, with no network and a read-only mount.                                                                                                                              |
| `dependency-audit` | Fails on a high or critical advisory in anything that ships; reports lower-severity and development-only advisories without failing.                                                                                                |

What the Compose smoke test checks: health through nginx; the dashboard's security headers; a
request with an unexpected `Host` is refused; an unauthenticated API call is refused; the
migrations created the tables; the API container is not root, has a read-only filesystem, has no
key directory configured and cannot reach the internet; `create-owner`, login and resource
creation work; an operation without a grant is denied and creates no job; exactly one port is
published and it is bound to loopback.

The sandbox integration tests and the Docker launcher tests **skip** in `verify`, because that
job has neither a sandbox-capable browser nor the runner image. The Docker ones run in
`containers`; the bubblewrap ones run nightly.

## Nightly: scheduled maintenance

| Job          | What it does                                                                                                                                                                               |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sandbox`    | Prepares the runner (`infra/ci/sandbox-prereqs.sh`) and runs the whole browser-worker suite with `AAB_REQUIRE_INTEGRATION=1`, so a missing prerequisite fails the run instead of skipping. |
| `e2e`        | Checks out the Northstar demo next to the broker and runs the 15-step end-to-end test. Needs the repository variable `NORTHSTAR_DEMO_REPOSITORY`; without it the job passes with a notice. |
| `image-scan` | Rebuilds the three images with fresh base layers and scans each for HIGH and CRITICAL vulnerabilities that have a fix (`infra/ci/scan-image.sh`).                                          |
| `audit`      | The dependency audit and the secret scan again, because advisories appear without a commit.                                                                                                |
| `report`     | When a scheduled run fails, opens an issue titled "Nightly run failed", or comments on the open one. It writes job results and a link, never log content.                                  |

Why these are not in the pull-request gate: the sandbox and end-to-end tests start a real browser
for every job and need a kernel setting changed on the runner; the image scan and the audit fail
for reasons unrelated to the change under review. Once `sandbox` has been green for a while, move
it into `ci.yml` as a required check.

`sandbox-prereqs.sh` uses `sudo` to install bubblewrap, Xvfb, xdotool and xauth, installs the
Chromium build that matches the installed Playwright driver, copies the Node binary to
`/usr/bin/node` (the sandbox launcher runs Node from there, and setup-node installs it
elsewhere), and turns off Ubuntu 24.04's restriction on unprivileged user namespaces. That last step is acceptable on a disposable runner and wrong on a
long-lived machine; the script refuses to run outside CI.

## Release: publishing a version

```sh
git tag -s v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

1. The whole CI workflow runs on the tagged commit.
2. Each image is built to an archive and scanned. A fixable HIGH or CRITICAL vulnerability stops
   the release here, before anything has been pushed.
3. The images are pushed to `ghcr.io/silentonroot/relay/{broker-api,dashboard,browser-runner}`
   with the version tag, and `latest` unless the tag is a release candidate. Each carries a
   software bill of materials and a provenance record, built from the same cached layers that
   were scanned.
4. A signed build-provenance attestation is created for each image digest.
5. A GitHub release is created with generated notes and the image digests.

An owner verifies an image before running it:

```sh
gh attestation verify oci://ghcr.io/silentonroot/relay/broker-api@sha256:<digest> --repo silentonroot/Relay
```

Only the `publish` job has write access (releases, packages, attestations and their storage
records, an identity token for signing). It uses the workflow's own token; no long-lived secret is stored in the repository.

Things a release does not do yet: it does not set the version in `package.json` (all packages
are `0.0.0`), it does not publish npm packages, and it does not publish the Northstar demo.

## Dependency and base-image updates

Dependabot proposes updates every Monday as pull requests, which go through CI like any other
change. Nothing merges automatically.

- **npm packages.** Development tooling is grouped into one pull request; runtime dependencies
  come one at a time. A five-day cooldown keeps brand-new releases from being proposed, and pnpm
  separately refuses to install anything younger than one day (`pnpm-workspace.yaml`).
- **GitHub Actions.** Actions are pinned to commit SHAs; Dependabot updates the SHA and the
  version comment together.
- **Base images.** Every `FROM` line and the PostgreSQL image in `infra/compose.yaml` are pinned
  by tag and digest. Dependabot proposes new digests. The nightly scan rebuilds with `--pull`
  and reports vulnerabilities in between.

**The first three proposals (2026-11-13).** Dependabot opened #1 (`node` base image 24 to 25,
in `infra/docker`), #2 (`nginxinc/nginx-unprivileged` 1.30 to 1.31) and #3 (`@types/node` 24 to
26). #2 and #3 passed CI. #1 failed in the `containers` job, at the step that builds the images
and starts the Compose stack, so the Node 25 base image breaks the image build. The project
targets Node 24 (`engines`, CI and the Dockerfiles), so `.github/dependabot.yml` now ignores
major-version updates of the `node` image and of `@types/node`; minor, patch and digest updates
are still proposed. Moving to a new Node line is a deliberate change: update `engines`, the CI
Node version, the Dockerfiles and `@types/node` together, and remove the ignore rules. Close a
major-version proposal for any other dependency unless it is wanted; CI passing does not make it
wanted.

Three pins are outside Dependabot's reach and are updated by hand: the gitleaks image in
`ci.yml` and `nightly.yml`, the Trivy image in `infra/ci/scan-image.sh`, and the PostgreSQL
service image in `ci.yml` (keep it in step with `infra/compose.yaml`).

## Repository settings to apply once

These cannot be set from files in the repository.

1. **Branch protection on `main`:** require a pull request, block force pushes, and require
   these checks, which are named by each job's display name, not its id: "Lint, typecheck,
   test, build" (`verify`), "Database suite on PostgreSQL" (`database`), "Images, Compose stack,
   Docker launcher" (`containers`), "Secret scan" (`secret-scan`) and "Dependency audit"
   (`dependency-audit`).
2. **Actions permissions:** default workflow token permissions "Read repository contents";
   allow actions created by GitHub only (no other action is used).
3. **Security features:** Dependabot alerts, secret scanning with push protection, and private
   vulnerability reporting.
4. **Variable `NORTHSTAR_DEMO_REPOSITORY`:** the `owner/name` of the Northstar demo repository,
   to enable the nightly end-to-end test. The demo repository must be public, or the checkout
   step needs a token that can read it.
5. **Tag ruleset:** restrict who can create `v*` tags (a repository ruleset that targets
   tags; GitHub has replaced the older tag protection rules with rulesets), since a tag
   publishes images.
6. **Package visibility:** the first release creates the three packages on GitHub's registry as
   private; make them public if anyone else should pull them.

### The first nightly failure

The "Rebuild and scan images" job failed on 2026-11-14 at "Build and scan each image". GitHub
shows only "Process completed with exit code 1" without a signed-in session, so the cause was
reproduced locally: the three images were built as the job builds them (`docker build --pull`,
all succeeded) and `infra/ci/scan-image.sh` was run on each. The script works with its
read-only root filesystem, tmpfs mounts and dropped capabilities: it downloads the database,
reads the archive and prints a report. It exits 1 because the report is not empty.

Findings with a fix available (Trivy 0.76.2, database of 2026-11-14):

- `dashboard` (Alpine 3.24.2 base): 13 findings in `brotli-libs`, `curl`/`libcurl`, `libexpat`,
  `libxslt`, `musl`/`musl-utils` and `zlib`. The pinned base image was already the current digest
  of its tag, but Alpine had published fixed packages. `apk upgrade --no-cache` in the Dockerfile
  clears all of them (the rescan reports 0).
- `broker-api` and `browser-runner` (Debian 12.15 base): no operating-system findings, including
  the Chromium packages. The remaining findings are the same in both images and are not cleared by
  a newer digest (the pinned digest is the current one for `node:24-bookworm-slim`):
  - `brace-expansion` 5.0.9 (2 HIGH) and `undici` 6.28.0 (4 HIGH) inside the `npm` that ships with
    the Node.js base image, under `/usr/local/lib/node_modules/npm`. The images do not run `npm`.
  - Go standard library CVEs (2 CRITICAL, many HIGH) in the `esbuild` binaries, built with Go
    1.20.7 (`esbuild@0.18.20`) and Go 1.23.12 (`esbuild@0.25.12`). These come from the root
    development dependency chain `drizzle-kit@0.31.11` (a devDependency of `packages/database`) which
    depends on `esbuild@0.25.12` and, through `@esbuild-kit/esm-loader`, on `esbuild@0.18.20`. They
    are installed because the images install with `--include-workspace-root` and without `--prod`.
    `esbuild@0.28.2` (used by `tsx`) is not flagged. No released `drizzle-kit` avoids the old
    esbuild versions (0.31.11 is the latest; the 1.0 beta still depends on `esbuild@^0.25`).
    Clearing this needs a decision on the lockfile (a `pnpm` override of `esbuild`, or keeping
    development dependencies out of the images), which is not made here.

The gate is unchanged (`--exit-code 1`, HIGH and CRITICAL, fixed only), so the nightly job keeps
failing until the Node-based images are clean.

## What has and has not been run

"Run locally" means the job's commands were executed on a developer machine (Docker 28.5,
2026-11-13), not that the workflow ran on GitHub. The first `ci` run on GitHub was on the push to
`main` at commit 640bd27 (2026-11-13 23:18 UTC): <https://github.com/silentonroot/Relay/actions/runs/43526169259>.

| Workflow and job          | State                                                                                                                                                                                                          |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ci` / `verify`           | Ran on GitHub and passed. Commands also run locally (`pnpm run check`, dashboard build).                                                                                                                       |
| `ci` / `database`         | Ran on GitHub and passed. Also run locally against the same pinned PostgreSQL image over TCP: 119 tests passed.                                                                                                |
| `ci` / `containers`       | Ran on GitHub and passed. `compose-smoke.sh`, the runner image build and the Docker launcher tests also passed locally.                                                                                        |
| `ci` / `secret-scan`      | Ran on GitHub and passed.                                                                                                                                                                                      |
| `ci` / `dependency-audit` | Ran on GitHub and passed.                                                                                                                                                                                      |
| `nightly` / `sandbox`     | Ran on GitHub on 2026-11-14 and passed, so `sandbox-prereqs.sh` (without `--postgres`) has run on a runner. The `--postgres` path has not run. Also passes locally on Debian with the distribution's Chromium. |
| `nightly` / `e2e`         | Ran on 2026-11-14 but skipped itself: the `NORTHSTAR_DEMO_REPOSITORY` variable is not set, so the test has not run on a runner. It passes locally.                                                             |
| `nightly` / `image-scan`  | Ran on 2026-11-14 and failed. The scanner works (it also ran locally with the same hardening flags); it found fixed HIGH and CRITICAL vulnerabilities in all three images. See the section below.              |
| `nightly` / `audit`       | Ran on GitHub on 2026-11-14 ("Advisories and secret scan") and passed.                                                                                                                                         |
| `nightly` / `report`      | Ran on 2026-11-14 and worked: it opened issue #4 "Nightly run failed".                                                                                                                                         |
| `release`                 | Not run. The two-step build with a `docker-container` builder, the registry push and the attestations are untested.                                                                                            |
| Dependabot                | Ran for all four ecosystems on 2026-11-13 and opened three pull requests (see below). It finds the `*.Dockerfile` names and updates the pnpm lockfile (the npm pull request passed a frozen-lockfile install). |
| Workflow syntax           | Parsed as YAML and reviewed by hand. Not checked with `actionlint`.                                                                                                                                            |

## Northstar demo

The demo is a separate repository with its own small `ci.yml` (lint, format, typecheck, tests,
and a container build that must come up healthy and answer on its three known routes) and its
own Dependabot configuration. Its container job's commands were run locally and passed. Where
that repository will be hosted is not decided.

## Cost and limits

- A pull request runs five jobs, roughly 10 to 15 runner-minutes in total; the `containers` job
  dominates because it builds three images, one of which installs Chromium.
- The nightly run adds about 30 runner-minutes a day.
- GitHub disables scheduled workflows in a repository with no activity for 60 days.

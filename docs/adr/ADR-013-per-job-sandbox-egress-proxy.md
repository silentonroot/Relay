# ADR-013: Per-job sandbox and egress proxy for the browser worker

- **Status:** Accepted
- **Date:** 2026-11-12
- **Supersedes:** the "Isolation level by phase" table in
  [ADR-001](ADR-001-trust-boundaries-worker-isolation.md) for Phase 2 and Phase 3

## Context

ADR-001 gave the Phase 2 browser worker process isolation only, and noted the weakness: the
navigation allowlist would be enforced inside the same process that runs the browser and the
adapter code, so a compromised worker could ignore it, and that process would also hold the
key-encryption key (KEK) and a database connection. Container isolation was deferred to Phase 3.

The owner decided on 2026-11-12 to bring worker isolation forward into Phase 2. The goal is a
bounded claim in place of "out of scope": **a compromised browser or adapter reaches only the one
session it was running, for the length of that job, and can talk only to that application's
allowed origins.**

## Decision

### Two roles inside the worker service

| Role           | Lifetime    | Holds                                                                                                     | Does not hold                                                               |
| -------------- | ----------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| **Supervisor** | Long-lived  | Database connection, KEK (Phase 2 only), the session store module, the egress proxy, the sandbox launcher | A browser. It never parses a web page.                                      |
| **Runner**     | One per job | One decrypted session snapshot, one validated operation, a browser, the adapter code                      | KEK, database credentials, any other connection's data, a network interface |

The supervisor treats the runner as untrusted. Everything a runner returns is parsed as hostile
input: size-capped, checked with `checkPlainJson`, validated against a schema, and an operation
result is passed through `sanitizeOperationOutput` again outside the sandbox.

### The sandbox

Each job gets a new sandbox that is destroyed when the job ends. Inside it:

- **No network interface** other than its own loopback. There is no route to the host, to the
  local network or to the internet.
- **A read-only filesystem** holding the runtime, the browser and the runner code. The only
  writable paths are memory-backed temporary directories that vanish with the sandbox. The
  repository's `.env` files, the KEK directory, the user's home directory and the database are not
  mounted.
- **An empty environment** apart from `HOME`, `PATH` and the variables the runner needs.
- **No capabilities** and no way to gain privileges.
- Under the bubblewrap launcher the browser's own sandbox stays enabled inside it. Under the
  Docker launcher's default mode it is off (see Consequences).

The job is delivered on standard input and the outcome is returned on standard output. The
session snapshot is never written to disk, to an environment variable or to a command line.

Two launchers implement this, behind one interface:

| Launcher                         | Used for                                                          | Notes                                                                                                                                                                                                                                                                                                                                                |
| -------------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bubblewrap`                     | Local installs on Linux. The default.                             | Unprivileged user namespaces; no daemon and no root. Supports the headed login window by binding the display socket into the sandbox. No memory or process-count limit: only a wall-clock timeout.                                                                                                                                                   |
| `docker`                         | Deployments that run the worker with access to a container engine | `--network none`, read-only root, all capabilities dropped, `no-new-privileges`, memory and process limits, Docker's default seccomp and AppArmor profiles, and the browser's own sandbox off. Headed login is not supported in a container in Phase 2. Access to the engine's socket is root-equivalent on the host, so only the supervisor has it. |
| `unsafe-process` (explicit only) | Development on platforms with neither, and continuous checks      | No isolation at all. Refused unless `AAB_WORKER_SANDBOX=unsafe-process` is set; the worker logs a warning at start and on every job. No security claim in this document applies to it.                                                                                                                                                               |

### The egress proxy

Because the sandbox has no network, the only way out is a Unix-domain socket that the supervisor
creates for that job and binds into the sandbox. A small relay in the runner listens on the
sandbox's loopback and forwards to that socket; the browser is configured to use the relay as its
proxy for every request, loopback destinations included.

The proxy runs in the supervisor, outside the sandbox, and it:

1. Accepts a request only when its origin (scheme, host and port) is exactly one of the job's
   allowed origins. Everything else gets `403`, including the browser's own background traffic.
2. Resolves the host itself and applies the rules of specification §3.2: a loopback origin must
   resolve only to loopback addresses; any other origin must not resolve to a loopback, private,
   link-local, unique-local, multicast or unspecified address.
3. Connects to the address it checked, never to the name, so a DNS answer that changes after the
   check (DNS rebinding) cannot redirect the connection.
4. Logs the origin and the decision only. Headers and bodies pass through it and are never logged,
   because they carry the session cookie.

Origin restriction therefore survives a compromised runner. **Path restriction does not**: the
per-operation path allowlist and the redirect checks are enforced by the browser facade inside
the sandbox, because the proxy cannot see paths inside TLS and cannot tell a page from a
stylesheet.

### Which origins a job may reach

A job's allowed origins are the **intersection** of the adapter's `allowedOrigins` and the
registered application definition's `allowed_origins`. An empty intersection fails the job with
`origin_not_allowed`. This is the conservative reading of an open question in the specification
changelog (which list is authoritative); the owner can relax it later without weakening anything
already granted.

### Session snapshots

- Written once, by the login handoff. An operation job does **not** write a refreshed snapshot
  back in Phase 2: accepting session state from a runner after it has loaded pages would let a
  compromised runner replace the stored session.
- The supervisor filters a captured snapshot to the job's allowed origins, caps its size, seals it
  with `packages/crypto` in the session store module, and stores only ciphertext.
- After login the supervisor records the account label the adapter reports. Every later job
  reports the label again, and a mismatch ends the job with `identity_mismatch` before the adapter
  runs the operation.

### The login handoff

The login window is a headed browser in the same kind of sandbox, with one addition: the display
socket. Its network still goes only through the egress proxy. With X11 this addition is
significant, because any X11 client can observe input to other windows on the same display; a
Wayland session does not have that weakness. The handoff is short-lived and shows only an
allow-listed login page, and the limitation is stated in the threat model.

## What this does and does not give

| Property                                                                     | Holds when the runner is compromised?                           |
| ---------------------------------------------------------------------------- | --------------------------------------------------------------- |
| The runner cannot read the KEK, the database or another connection's session | Yes                                                             |
| The runner cannot send data anywhere except the job's allowed origins        | Yes                                                             |
| The runner's reach ends when the job ends                                    | Yes, bounded by the job timeout                                 |
| The runner stays on the operation's allowed paths                            | No. It can make any request the session allows on those origins |
| The session it was given stays secret                                        | No. It can use it, and send it to the allowed origins only      |
| The result it returns is truthful                                            | No. It is schema-valid and size-capped, nothing more            |

Still out of scope: a compromised supervisor, a compromised host, and a kernel or sandbox escape.
The supervisor holds the KEK until Phase 3 moves it behind the vault service.

## Alternatives considered

- **Process isolation only (ADR-001 as written).** Rejected by the owner's decision: every control
  would sit inside the process it protects.
- **Container with a filtered network instead of no network.** Needs firewall rules or a second
  proxy container per job, and a container still sees the engine's DNS and gateway. A sandbox with
  no interface at all is simpler to reason about and behaves the same under both launchers.
- **A long-lived sandboxed worker per connection.** Fewer process starts, but state from one job
  could influence the next and a compromise would persist. One sandbox per job costs roughly one
  browser start per operation, which is acceptable for Phase 2 volumes.
- **MicroVMs.** Stronger than namespaces, but they need KVM access and an image pipeline. Revisit
  for a hosted deployment (Phase 10).

## Consequences

- Linux local installs need `bubblewrap` and a Chromium build; the worker checks for both at start
  and refuses to run if a sandbox cannot be created.
- Every operation pays a browser start. Throughput is bounded by `AAB_WORKER_CONCURRENCY`.
- The `docker` launcher needs an image. Run on 2026-11-13 it showed that Chromium's own sandbox
  cannot be kept on under Docker's defaults: the default seccomp profile blocks the system calls
  that create user namespaces, and on kernels where AppArmor mediates user namespaces the default
  AppArmor profile denies them as well. The launcher therefore defaults to Docker's own profiles
  with Chromium's sandbox off, so the container is the only boundary around the browser, and it
  is Docker's standard one. Keeping Chromium's sandbox on is an opt-in that needs both a seccomp
  and an AppArmor profile permitting user namespaces; neither has been reviewed, so that mode is
  not yet usable (backlog AAB-017).
- Phase 3 removes the KEK from the supervisor; the sandbox design does not change.

## Revisit when

- A target application needs an identity provider on a different origin during login.
- An application rotates its session cookie on every request, which makes write-back necessary.
- AAB is deployed for more than one person on one machine.

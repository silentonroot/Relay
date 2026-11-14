# ADR-003: Vault root key for local installs

- **Status:** Accepted
- **Date:** 2026-11-11

## Context

Session snapshots and, later, tokens and API keys are stored with envelope encryption
(specification §6.2). Each secret version is encrypted with its own random 256-bit data-encryption
key (DEK) using AES-256-GCM. The DEK is itself encrypted ("wrapped") with a key-encryption key
(KEK). The database holds ciphertext and wrapped DEKs. Whoever holds the KEK can decrypt
everything, so the question is where the KEK lives on a single-user local install that has no cloud
key-management service.

The requirement is that a copy of the database alone, such as a stolen backup or a dump attached to
a bug report, yields only ciphertext.

## Decision

- Each KEK version is **32 random bytes in its own file**, named `kek-v<N>.key`, where `<N>` is a
  positive integer version. The bytes come from the operating system's cryptographic random
  source.
- The files live in one directory given by the `AAB_KEK_DIR` setting. The directory is **outside
  the repository and outside the database's data directory**. The setting holds a path, never key
  bytes.
- The directory has mode `0700` and each key file has mode `0600`, owned by the account that runs
  the service. **The service refuses to start** if the directory or any key file is readable or
  writable by group or others, if a key file is not exactly 32 bytes, or if no key is present. It
  reports which path failed the check and does not print the contents.
- A KEK is never placed in an environment variable, a container image, a configuration file in the
  repository, a log line, a test fixture or the database. Tests generate throwaway keys in memory
  or in a temporary directory.
- Every stored secret version records the KEK version that wrapped its DEK. New secrets use the
  highest version present. Rotation adds a new file and re-wraps the existing DEKs; the old file is
  removed by the owner only after every record reports the new version.
- **Recovery story, stated plainly:** if the KEK files are lost, every stored session is
  unrecoverable. Nothing else is lost. The owner generates a new key and reconnects each
  connection. There is no back door and no key escrow.
- **Backup is the owner's responsibility.** The operations guide tells the owner to back up the key
  directory separately from the database, and warns that a backup that contains both in the clear
  gives up the protection this record exists to provide.

Deferred, deliberately:

- Wrapping the key file with a passphrase.
- Storing the KEK in an operating-system keyring.
- Any hosted or multi-user deployment, which must use a managed KMS or HSM where the KEK never
  leaves the service and unwrap calls are authenticated and logged.

## Alternatives considered

- **Environment variable.** The common default. Rejected: environment variables appear in process
  listings, crash reports, container inspection output and shell history, and child processes
  inherit them, including a browser.
- **A key stored in the database.** Rejected: it defeats the requirement outright.
- **Derive the KEK from the owner's dashboard password.** Attractive because nothing is on disk.
  Rejected for now: the service could not decrypt anything until someone logs in after each
  restart, so background health checks and queued jobs would stall; a password change would require
  re-wrapping under the user's hands; and the key would only be as strong as the password.
- **Operating-system keyring.** Good on a desktop with an unlocked session. Deferred: behaviour
  differs across Linux desktops, it is absent on headless machines and in containers, and it adds a
  native dependency to the most sensitive code path.
- **Run a local secrets manager (for example HashiCorp Vault in dev mode).** Rejected for the local
  product: another service to operate, and its own unseal key then has the same problem.

## Consequences

- The protection is against disclosure of the database on its own. It is **not** protection
  against anyone who can read files as the service's user, against root, or against a backup tool
  that copies the whole home directory. The dashboard's key-status panel and the documentation must
  say this rather than imply more.
- The permission check relies on POSIX file modes. It is meaningful on Linux and macOS. On Windows
  the mode bits do not express access control, so the check cannot be relied on there; native
  Windows is unsupported for anything that stores secrets until an ACL-based check exists.
- Running in a container requires mounting the key directory with the right ownership and mode, as
  a read-only mount into the vault service only. The worker container must not receive it.
- In Phase 2 there is no separate vault service, so the process that executes browser jobs must be
  able to read the key. That is a known weakness of the first slice, recorded in
  [ADR-001](ADR-001-trust-boundaries-worker-isolation.md), and Phase 3 removes it.
- Phase 1 stores no secrets and does not need a KEK. The start-up check applies to the first
  process that uses the vault code, not to the Phase 1 API.
- Key files are easy to delete by accident. The service never deletes or overwrites one; key
  generation fails if the target file exists.

## Revisit when

- A credential that is not synthetic is to be stored.
- AAB is run on Windows, in a container orchestrator, or for more than one user.
- An owner loses a key in practice and the reconnect-everything recovery proves unacceptable, which
  would be the evidence for passphrase wrapping or keyring storage.

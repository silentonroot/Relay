# @aab/crypto

Envelope encryption for vault secrets, key-encryption-key (KEK) providers, password hashing
for the local owner login, and token helpers. Everything is built on `node:crypto`; this
package implements no cipher, KDF, MAC or random generator of its own and has no third-party
cryptographic dependency.

> **Review status: not externally reviewed.** This code must be reviewed by someone qualified
> before it protects real third-party credentials. Until then it is for synthetic data only.

## Construction (spec §6.2)

**Sealing a secret version** (`sealSecret`)

1. A fresh random 256-bit data-encryption key (DEK) is generated for every call.
2. The plaintext is encrypted with AES-256-GCM under the DEK, with a fresh random 96-bit nonce
   and a full 128-bit tag. Each DEK encrypts exactly one message, so a nonce can never repeat
   under a DEK.
3. The associated data is the canonical JSON (`canonicalJson` from `@aab/contracts`, UTF-8) of
   `{ aadVersion, organizationId, userId, connectionId, secretId, secretType, secretVersion }`.
   UUIDs are lowercased first. A sealed secret only opens under the identical context.
4. The DEK is wrapped by a `KekProvider`. The local providers wrap with AES-256-GCM under the
   KEK with a fresh random nonce; the associated data is a fixed label, the KEK version and the
   secret's AAD bytes, so a wrapped DEK cannot be moved to another secret or KEK version.

`SealedSecret` maps onto `vault_secret_versions`:

| Field        | Column        | Notes                                                       |
| ------------ | ------------- | ----------------------------------------------------------- |
| `ciphertext` | `ciphertext`  | same length as the plaintext                                |
| `nonce`      | `nonce`       | 12 bytes                                                    |
| `authTag`    | `auth_tag`    | 16 bytes                                                    |
| `wrappedDek` | `wrapped_dek` | opaque; local format `nonce(12) ‖ ciphertext(32) ‖ tag(16)` |
| `kekVersion` | `kek_version` | positive integer                                            |
| `aadVersion` | `aad_version` | currently `1`                                               |
| `algorithm`  | (new column)  | `aab-envelope-v1/aes-256-gcm`                               |

**Opening** (`openSecret`) rejects with one generic `SecretOpenError` whatever the cause:
wrong context, altered bytes, unknown KEK version, malformed record. Nonce and tag lengths are
checked before the decipher is created, and `authTagLength: 16` is always passed, because
without it Node accepts truncated GCM tags. Plaintext is released only after the tag verifies.

**KEK rotation** (`rewrapSecret`) unwraps the DEK and wraps it under the new KEK. The
ciphertext is not decrypted or changed. DEK rotation is a plain `openSecret` + `sealSecret`
under a new `secretVersion`.

## KEK providers

- `InMemoryKekProvider`: keys held in memory only. For tests.
- `LocalFileKekProvider.load(directory)`: reads raw 32-byte keys named `kek-v<N>.key`. The
  highest version is used for new wraps; older versions remain available for unwrap. Loading
  fails closed if any key file is a symbolic link, is not a regular file, is not exactly 32
  bytes, is accessible by group or other (mode must be `0600` or stricter), or is not owned by
  the current user (or root); and if the directory is a symbolic link, is not owned by the
  current user (or root), or has any group or other permission bit (mode must be `0700` or
  stricter). POSIX only.
- `generateLocalKek(directory, version)`: creates the directory `0700` if missing and writes a
  new random key `0600` with an exclusive create. It refuses an existing directory with looser
  permissions instead of using or silently tightening it, and never overwrites an existing key.

Keep the key directory outside the repository and outside anything backed up alongside the
database. Back the key files up separately: a lost KEK makes every secret wrapped under it
unrecoverable, and every connection must then be re-authenticated.

The library cannot verify that the directory is outside the repository or the database
directory: it does not know where either lives, and a guess (looking for `.git`, for example)
would be unreliable in containers and bind mounts. Placement is the deployment's
responsibility; the start-up scripts or the operator must ensure it.

Keys are held as `KeyObject`s in private class fields. They do not appear in `util.inspect`,
`JSON.stringify`, enumeration or error messages.

## Passwords and tokens

- `hashPassword` / `verifyPassword` / `needsRehash`: scrypt with N = 2^17, r = 8, p = 1, a
  16-byte random salt and a 32-byte output (about 128 MiB and a few hundred milliseconds per
  hash). Encoded as `$scrypt$ln=17,r=8,p=1$<salt>$<hash>` (unpadded base64). Passwords are
  limited to 1024 UTF-8 bytes. `verifyPassword` returns `false` for malformed input instead of
  throwing, bounds the parameters it will accept from a stored hash, and compares with
  `timingSafeEqual`. No Unicode normalization is applied. Passwords containing a NUL character
  are refused: scrypt begins with PBKDF2-HMAC-SHA256, and HMAC zero-pads short keys, so a
  trailing NUL would otherwise not change the hash.
- `generateToken`: random bytes from the OS CSPRNG as base64url (default 32 bytes).
- `hashToken`: hex SHA-256, for storing session and CSRF tokens hashed. Suitable only for
  high-entropy random tokens, never for passwords.
- `constantTimeEqual`: timing-safe string comparison that tolerates unequal lengths.

## Threat boundary

Encryption at rest protects secrets against theft of the database alone: without the KEK,
`vault_secret_versions` rows are ciphertext, and rows cannot be swapped between tenants,
users, connections, secrets or versions.

It does **not** protect against:

- **A compromised worker or host.** A trusted worker must hold plaintext session material in
  memory to use it, and a process that can read the KEK directory can decrypt everything.
  Process isolation, short plaintext lifetimes and restricted debugging access are separate
  controls, and deployments beyond local development should move the KEK into a managed
  KMS/HSM behind the `KekProvider` interface.
- **Memory disclosure.** Buffers holding DEKs are zeroed with `fill(0)` after use, but this is
  best effort: JavaScript cannot guarantee that the runtime, OpenSSL, the garbage collector or
  swap has not kept another copy. Callers own the plaintext buffers they pass in and receive.
- **Rollback.** An attacker who can write to the database can restore an older, valid sealed
  version of the same secret. Detecting that is the vault service's job (active-version
  tracking and audit), not this package's.
- **Loss of the KEK.** There is no recovery path without a backup of the key files.

Random 96-bit nonces under a long-lived KEK stay within accepted limits for up to roughly
2^32 wraps per KEK version; rotate the KEK long before that.

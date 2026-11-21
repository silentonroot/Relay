# Test fixtures: a Phase 2 snapshot (synthetic)

**Everything here is synthetic test material. None of it protects, or ever protected, real data.**

- `phase2-kek-v1.key` is a 32-byte key-encryption key generated for this fixture only, with the
  Phase 2 `generateLocalKek`. It is published in the repository on purpose: it exists so that a
  test can open one synthetic ciphertext. It must never be used as, copied to, or derived into a
  real KEK. The secret scan (`.gitleaks.toml`) allowlists this directory for that reason and
  for no other.
- `phase2-snapshot.json` holds one `vault_secret_versions` row (hex bytes), the identifiers the
  associated data is built from, and the plaintext. The row was sealed by the real Phase 2 code
  at git commit `640bd277dfad1d7c104b0f5f39638393da8b9f41` (`packages/crypto` `sealSecret` with
  `LocalFileKekProvider`), checked out into a temporary worktree and run from a throwaway script
  outside the repository. The code in this repository did not produce these bytes.

Used by `services/vault/test/phase2-snapshot.test.ts` (P3-19). To regenerate, repeat that
procedure with a freshly generated KEK; never edit the bytes by hand.

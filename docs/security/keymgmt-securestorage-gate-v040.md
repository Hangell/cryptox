# v0.4.0 key management & secure storage gate (P3.14)

This record closes the Phase 3 gate for key management and secure storage. It
consolidates the P3.01–P3.13 evidence; it does **not** publish a release tag or
claim independent audit.

**Status:** ready — no known blockers in the Phase 3 scope.

## Checklist

| Area | Result | Evidence |
|---|---|---|
| Key model and lifecycle metadata | ADR 0005 | `docs/adr/0005-key-model-lifecycle.md` |
| One-way lifecycle state machine | implemented + tested | `keys/lifecycle` |
| Versioned, purpose-bound derivation | implemented + tested | `keys.DeriveVersioned` |
| Keyring with controlled KeyID resolution | implemented + tested | `keys/keyring` |
| Explicit, versioned key import/export | implemented + tested | `keyring.Export/Import` (`CKKX` v1) |
| Storage contracts | defined | `securestorage/interfaces`, `docs/spec/securestorage.md` |
| Persistence threat model | documented | `docs/security/securestorage-threat-model.md` |
| Encrypted records layer | implemented + tested | `securestorage/encrypted` |
| In-memory adapter + conformance suite | implemented + tested | `securestorage/memory`, `securestorage/conformance` |
| Filesystem adapter (transactional publication) | implemented + tested | `securestorage/file` |
| Resumable migration | implemented + tested | `encrypted.Migrate` |
| Recovery / persistence-failure validation | tested | `securestorage/file/recovery_test.go` |
| End-to-end example in CI | Put/Get/rotation/recovery test | `securestorage/encrypted/integration_test.go` |

## Format review

- The encrypted-record format (`version(8 BE) ‖ AES-256-GCM(plaintext,
  AAD = namespace ‖ recordID ‖ version)`) implements the P3.08 binding rule and
  is covered by negative tests (tampering, substitution, wrong key/namespace).
- The key export format (`CKKX` v1) is versioned and strictly validated on
  import.
- Both are design-reviewed through this phase; neither has received an
  independent specialist audit yet.

## Dependencies

| Dependency | Status |
|---|---|
| #82–#94 (P3.01–P3.13) | review — merged (PRs #63–#75) |

## Residual limitations

- No validated **per-key** usage bound (carried from P0/P1).
- Deletion is logical, not physical erasure (SSDs/snapshots/remote stores).
- Rollback resistance requires a trusted external anchor; the storage layer
  does not provide it.
- Protected key export (wrapping under a KEK) is deferred.
- The filesystem adapter does not fsync its directory, so crash durability of
  the rename is not guaranteed (atomicity yes, durability best-effort).
- Key material remains in Go memory subject to GC; zeroization is not promised.

## Readiness

Phase 3 provides the key-management and secure-storage foundation for higher
modules. No release tag is published by this record.

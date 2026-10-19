# ADR 0005 — Key model and lifecycle metadata

Status: accepted. Defines the key-management domain model for Phase 3; the
implementations follow in P3.02 onward.

## Context

Phase 3 introduces key management and secure storage. CryptoX already has
one-shot key primitives (`aead.Key`, `keys.GenerateKey`, `keys.DeriveKey`) and a
purpose-separated KDF (`keys.Purpose`). Key management needs a model for
identifying, versioning, and transitioning keys over time without conflating
cryptographic identity with secret material.

## Decision

### KeyID

- A `KeyID` is an opaque, **random** 16-byte identifier generated from
  `crypto/rand`. It is **never derived from the key material** (no hashes or
  fingerprints of the secret), so it can be logged, indexed, and stored in
  envelope `keyID` fields without leaking information about the key.
- `KeyID` is a value type with a `String()` method returning hex; it contains
  no secret.

### Version and purpose

- Each key has a monotonically increasing `KeyVersion uint32` (1-based),
  distinguishing generations produced by rotation.
- Each key records a `keys.Purpose` domain-separation label. A key is usable
  only for its declared purpose; cross-purpose use is rejected.

### Lifecycle state

```text
active ──retire──▶ retired ──revoke──▶ revoked
   │                                    ▲
   └────────────── revoke ──────────────┘
```

- `active`: usable for encrypt and (when applicable) decrypt/sign.
- `retired`: no longer used for new encryption, still used for decryption or
  signature verification of historical data.
- `revoked`: **terminal**; must not be used for any new operation. Historical
  ciphertext/signatures may still be processed only through explicit
  revocation-aware paths.

Transitions are one-way: `active→retired`, `active→revoked`,
`retired→revoked`. Any other transition is an invalid state and is rejected.
The state machine is enforced by the P3.02 implementation, not by convention.

### Public/private separation

- Symmetric keys use the existing opaque `aead.Key` (or `[]byte` only at the
  point of construction). Public/private material for future asymmetric use
  (P4) will be distinct types; the private type is never serializable by
  standard encoding and redacts on `String()`.

### Metadata privacy

- `KeyID`, `KeyVersion`, `Purpose`, and `State` are **not secret**, but the
  envelope carries only the opaque `KeyID` (plus authenticated metadata the
  caller chooses). Lifecycle metadata is not written into envelopes by
  default; it lives in the keyring/secure-storage layer.

### Ownership and copies

- The keyring is the owner of key material. Accessors return keys only for
  explicit operations; no public API returns the raw key except the explicit
  import/export path (P3.06), which is gated and documented.
- Copies are minimized; Go's GC means zeroization is not promised (already
  documented in `SECURITY.md`).

## Consequences

- Envelope `keyID` semantics are fixed: an opaque random identifier, not a
  secret-derived fingerprint.
- Rotation produces a new `KeyVersion` with a fresh `KeyID`; historical reads
  resolve by `(KeyID, KeyVersion)` (P3.04, P3.05).
- Revocation is terminal and enforced in code (P3.02).
- No secret material is exposed through `String()`, JSON, or logging.

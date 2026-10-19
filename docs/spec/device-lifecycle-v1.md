# Device Lifecycle v1

Status: experimental (Phase 4). The identity track does not block the stable
core and must not be promoted to production without specialized validation
(ADR 0006).

## Scope

This document specifies the client-side state machine for device enrollment,
key replacement, and revocation. It is intentionally **server-optional**: the
cryptographic authorization rules are enforced locally, and the consuming
application is responsible for persistence and for propagating state changes
to peers.

## Trust model

All authorization derives from one of two sources:

1. a **trust anchor** — an explicitly configured public key (ADR 0006); or
2. the **device key itself**, for self-revocation only.

The state machine never establishes trust on its own; it only validates that a
transition was authorized by one of these parties.

## States

```text
active ──replace──► retired
   │
   └──revoke──► revoked
```

- **active** — the key is the current device identity key.
- **retired** — the key was replaced by a newer key.
- **revoked** — the key must no longer be accepted.

Transitions are one-way. A retired or revoked key can never become active again.

## Enrollment

Enrollment accepts a device-identity credential ([identity-credential-v1.md](identity-credential-v1.md))
and requires, in order:

1. `credential.purpose == device_identity`;
2. `credential.issuer == trust_anchor`;
3. the credential signature verifies and the current time is within the
   validity window.

An enrollment record stores the credential itself (not just the key), so a
recovered record can be re-validated against the anchor instead of trusting
bare key material. **Recovery therefore cannot bypass authorization.**

## Key replacement

Replacement is authorized by the trust anchor issuing a new device-identity
credential for a different key. Applying it:

1. requires the current record to be active;
2. validates the new credential exactly like enrollment;
3. rejects the new key if it equals the current key;
4. marks the current record retired and produces a new active record with
   `seq = current.seq + 1`.

An adversary cannot rotate a key without the anchor's private key.

## Revocation

A revocation is a signed statement `(key, authorizer, seq, signature)`. It is
valid only when:

1. the signature verifies under `authorizer`;
2. `authorizer` is the trust anchor or the revoked key itself (self-revocation).

A third party therefore cannot revoke a device. Applying a revocation:

1. requires the current record to be active;
2. requires the revocation to target the record's key;
3. requires `revocation.seq > current.seq` (anti-replay/rollback).

## Encodings

- **Record:** enrollment credential (146 bytes, see
  [identity-credential-v1.md](identity-credential-v1.md)) followed by
  `state` (1 byte) and `seq` (8 bytes, big-endian). Total 155 bytes.
- **Revocation:** `key` (32) || `authorizer` (32) || `seq` (8) ||
  `signature` (64). Total 136 bytes.

Both encodings are fixed-width and validated strictly on decode; decoding never
panics on attacker-controlled input (enforced by `FuzzDecodeRecord` and
`FuzzDecodeRevocation`).

## Synchronization threats

This component has no server and no global source of truth. Consumers that
replicate device state must account for:

- **Rollback / replay:** an attacker who controls one replica may present an
  older record (lower `seq`) to undo a revocation or replacement. Consumers
  must keep the highest-seen `seq` per key lineage and reject stale records
  (`ErrStaleSequence`).
- **Re-enrollment of a revoked key:** the state machine has no memory of past
  revocations outside the records it is given. A consumer must not enroll a
  key it knows to be revoked; revocation lists are a transport/application
  concern, not something this package maintains.
- **Split-brain replacement:** without a server, two anchors or replicas can
  issue conflicting replacements. This format detects unauthorized
  replacement but cannot arbitrate between two authorized-but-conflicting
  histories; consumers must define their own conflict-resolution rule.
- **Propagation delay:** a revocation only takes effect where it has been
  delivered and applied. This is an availability property, not a cryptographic
  one.

## Residual limitations

- Revocation is not globally visible; there is no embedded transparency or
  directory (see P4.06).
- The `seq` counter is application state, not a cryptographic commitment; it
  mitigates, but does not eliminate, rollback by a Byzantine replica.
- Memory holding private keys is managed by Go's garbage collector; clearing
  is not guaranteed.

# Identity Credential v1

Status: experimental (Phase 4). The identity track does not block the stable
core and must not be promoted to production without specialized validation
(ADR 0006).

## Purpose

A **credential** is a signed, versioned binding of a subject public key to an
issuer public key, for an explicit purpose and validity window. It is the
cryptographic primitive a device uses to present an identity key in a way that
can be verified by another device, while carrying minimal correlatable
metadata.

## Fields

| Field | Size (bytes) | Encoding | Meaning |
| --- | --- | --- | --- |
| version | 1 | uint8 | `0x01` |
| issuer | 32 | raw | Ed25519 public key of the signing authority |
| subject | 32 | raw | Ed25519 public key being bound |
| purpose | 1 | uint8 | `0x01` device identity, `0x02` agent identity |
| not_before | 8 | big-endian uint64 | Unix seconds, validity start (inclusive) |
| not_after | 8 | big-endian uint64 | Unix seconds, validity end (exclusive) |
| signature | 64 | raw | Ed25519ctx signature over the preceding 82 bytes |

Total encoded size is fixed at **146 bytes** (82-byte payload + 64-byte
signature). There are no length-prefixed variable fields in v1, which keeps the
encoding canonical and trivially parseable with strict bounds.

## Canonical signed payload

The signature covers the exact 82-byte concatenation, in order:

```text
version || issuer || subject || purpose || not_before || not_after
```

The signature is computed as **Ed25519ctx** with the domain-separation context
string:

```text
cryptox/identity/credential/v1
```

so a credential signature cannot be replayed against any other message domain.

## Validity

A credential is valid at time `now` when:

1. the issuer signature verifies over the canonical payload;
2. `not_after > not_before`;
3. `not_before <= now.Unix() < not_after`.

Verification of these properties does **not** establish trust in the issuer.
The consuming application must separately check that `issuer` matches an
explicitly configured trust anchor (ADR 0006). Unanchored keys are unverified.

## Fingerprints and out-of-band verification

A **fingerprint** is the domain-separated SHA-256 of a public key:

```text
SHA-256("cryptox/identity/fingerprint/v1" || 0x00 || public_key)
```

rendered as sixteen uppercase groups of four hex digits (e.g.
`D75A 9801 82B1 0AB7 …`) for human comparison. Fingerprints let two parties
verify that they hold the same key over a trusted out-of-band channel; the
library never implies that fingerprint comparison alone is sufficient in
adversarial settings.

## Limits and failure behavior

- Encoded input must be exactly 146 bytes; anything else is `ErrMalformed`.
- Unknown version → `ErrUnsupportedVersion`; unknown purpose →
  `ErrInvalidPurpose`; `not_after <= not_before` → `ErrInvalidValidity`.
- A failed signature check → `ErrInvalidSignature`; an out-of-window time →
  `ErrExpired`.
- Decoding never panics on attacker-controlled input; this is enforced by the
  `FuzzDecode` target.

## Security properties

- **Tamper detection:** any bit flip in issuer, subject, purpose, validity, or
  signature invalidates the signature.
- **Key replacement detection:** substituting a different subject key without
  re-signing invalidates the signature.
- **Purpose binding:** the purpose is signed, so a credential cannot be
  replayed for a different purpose.
- **Metadata minimization:** no names, no device identifiers, no relationships
  beyond issuer/subject, and no timestamps beyond the validity window.

## Residual limitations

- Ed25519 credentials do not provide forward secrecy or revocation; revocation
  and enrollment flows are specified separately (P4.04).
- This format is versioned, but v1 is fixed-width; structural evolution
  requires a new version byte and an explicit migration story.
- Memory holding private keys is managed by Go's garbage collector; clearing is
  not guaranteed.

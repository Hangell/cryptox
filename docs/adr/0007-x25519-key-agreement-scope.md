# ADR 0007 — X25519 key agreement scope

Status: accepted (experimental track). Key agreement is part of the optional,
experimental identity track (v0.5.0) and does not block the stable core; it
must not be promoted to production without specialized validation.

## Context

ADR 0006 requires an agreement key pair for device identity, separate from
signing material. Phase 4 (P4.05) evaluates X25519 for this role. The master
specification forbids inventing cryptographic protocols: complete handshakes
(PQXDH, MLS, Double Ratchet) must use established, reviewed implementations
rather than a proprietary construction.

## Decision

1. **Expose X25519 (RFC 7748) only as an unauthenticated building block**, in
   `keys/exchange`, implemented with the Go standard library `crypto/ecdh`.
2. **Enforce RFC 7748 requirements**: private keys are clamped by the standard
   library, and a peer public key that yields the all-zero shared secret (a
   low-order point) is rejected with `ErrInvalidPeerKey`.
3. **Do not implement a handshake.** X25519 output is never presented as an
   authenticated session. Authenticated key agreement is deferred to
   established protocols (e.g., PQXDH, MLS) evaluated in a later phase.
4. **Require identity binding and derivation in callers.** The raw shared
   secret must be authenticated with signature-based identities
   (`keys/signatures`, `identity/credentials`) and expanded with HKDF
   (`keys`) before use.

## Evaluation

- **Identity binding:** X25519 provides none by itself. It is unauthenticated
  Diffie-Hellman; both endpoints' public keys must be bound to identities by
  signatures before a shared secret can be trusted.
- **Input validation:** private keys are 32 bytes and clamped; public keys are
  32-byte u-coordinates; the low-order all-zero output is rejected. Decoding
  and key construction never panic on malformed input.
- **Derivation:** the 32-byte shared secret is not a key. It is KDF input,
  expanded with domain-separated HKDF (the existing `keys` derivation
  functions).
- **Attacks considered:**
  - *Man-in-the-middle:* possible whenever public keys are not authenticated;
    this is why the package is labeled unauthenticated.
  - *Key compromise impersonation:* mitigated only by authenticating identities
    and by a protocol with the appropriate security proof; not addressed by
    bare X25519.
  - *Replay:* agreement is non-interactive and stateless; replay resistance is
    a protocol property and out of scope for the primitive.
  - *Small-subgroup / low-order:* addressed by the all-zero shared secret check.
  - *Bad randomness:* key generation draws from `crypto/rand`.

## Consequences

- `keys/exchange` is a minimal, misuse-resistant primitive with an explicit
  warning in its package documentation.
- No proprietary key-agreement handshake is introduced; session establishment
  remains a later, protocol-level decision.
- Callers who ignore the authentication requirement do so outside any guarantee
  this package provides; the limitation is documented, not silently hidden.

## Residual limitations

- X25519 does not provide forward secrecy on its own; that is a property of the
  surrounding protocol.
- The all-zero check addresses low-order inputs but is not a substitute for
  ephemeral keys and authentication in interactive protocols.
- Memory holding private keys is managed by Go's garbage collector; clearing is
  not guaranteed.

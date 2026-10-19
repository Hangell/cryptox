# ADR 0006 — Identity model and trust boundaries

Status: accepted (experimental track). The identity layer is an optional,
experimental track for v0.5.0 and does not block the stable core; it must not
be promoted to production without specialized validation.

## Context

Phase 4 introduces cryptographic identity for devices and agents. The library
must not conflate cryptographic identity with a person's legal identity
(ARCHITECTURE.md §6.5).

## Decision

### Identifiers

- **DeviceID** — an opaque random identifier for a device instance, never
  derived from key material and never linked to a civil identity.
- **AgentID** — an optional opaque identifier for a software agent acting on
  behalf of a device; it is a distinct namespace from DeviceID.

Neither is a claim about a person, an account, or legal identity.

### Key material

- **Signing key pair:** Ed25519. The private key is a distinct, non-serializable
  type that redacts on `String()`; the public key is an explicit type.
- **Agreement key pair:** X25519 (P4.05), evaluated separately; agreement
  material is not reused as signing material.
- Key replacement is explicit: a device may publish a new key only through an
  enrollment/replacement flow (P4.04) that records the transition and its
  authorization. There is no silent key rollover.

### Trust anchors

- A **trust anchor** is an explicitly configured public key (or a root manifest
  signed by one) chosen by the consuming application. CryptoX provides the
  cryptographic building blocks (verification, fingerprinting) but does not
  ship a default trust anchor or a global key directory.
- Verification of a device identity requires an explicit chain back to a trust
  anchor; unanchored keys are treated as unverified.

### Verification and privacy

- Out-of-band verification is supported through public-key fingerprints
  (P4.03). The library never implies that fingerprint comparison alone is
  sufficient in adversarial settings.
- Identity metadata is minimized: identifiers are random and carry no
  timestamps, names, or relationships by default.

### Experimental isolation

- Identity packages live under `identity/` and are not imported by the stable
  core (`aead`, `keys`, `stream`, `envelope`, `securestorage`).
- Nothing in the core depends on identity; promotion to production requires a
  specialized review.

## Consequences

- No legal-identity claims are made.
- Trust is explicit and caller-configured; no global registry or default trust
  is assumed.
- Key replacement is auditable through enrollment/revocation flows, not silent.

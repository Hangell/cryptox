# ADR 0008 — Key transparency boundary

Status: accepted (experimental track). Key transparency is an optional future
concern for the identity track and does not block the stable core.

## Context

ADR 0006 lists key transparency as a future integration point for device
identity. P4.06 evaluates whether to build key transparency now. The master
specification forbids inventing protocols or proprietary constructions whose
security requires specialized analysis.

## Decision

1. **Defer key transparency.** No `identity/transparency` package and no key
   directory interfaces are introduced in this increment: there is no concrete
   consumer or use case yet, and the spec requires interfaces to be created
   only with a demonstrated need.
2. **Keep cryptographic verification in the library.** Signatures
   (`keys/signatures`), credentials (`identity/credentials`), fingerprints
   (`identity/verification`), and the device state machine
   (`identity/devices`) let a verifier check *what is claimed about a key*.
3. **Keep trust in a directory out of the library.** Whether a key was
   published to, and is still valid in, a directory is an operational
   decision made by the consuming application. The library does not ship a
   default directory or a trust anchor (ADR 0006).
4. **If transparency is introduced later**, prefer an established, audited
   append-only log construction (e.g., a Certificate Transparency-style or
   CONIKS-style verifiable log) over a proprietary log. Any such integration
   must expose verification of inclusion proofs, consistency proofs, and the
   split-view/gossip assumptions, and must be documented in its own ADR.

## Evaluation

- **Inclusion:** a verifiable log lets a client prove a key is present at a
  given index. This is a cryptographic property but says nothing about whether
  the key is the *right* one; that decision remains with the trust anchor and
  the application.
- **Consistency:** consistency proofs detect a log that forks or rewrites
  history. Without them, a malicious or compromised log can present different
  histories to different clients.
- **Split-view:** even a correct log cannot prevent a client from being shown a
  stale or partial view. Mitigation requires gossip, monitors, or multiple
  independent sources — operational concerns outside the SDK.
- **Trust distinction:** transparency increases *auditability*, not *trust*.
  A key in a transparent log can still belong to an attacker. Transparency
  complements, and never replaces, out-of-band verification and anchor-based
  authorization.

## Consequences

- No key transparency code or interfaces are added now, avoiding speculative
  abstractions.
- The boundary between what the library verifies (cryptographic claims) and
  what the application trusts (directory state) is explicit.
- Any future transparency work is scoped to an established mechanism with a
  dedicated ADR and a concrete consumer.

## Residual limitations

- Until transparency is adopted, users cannot detect a directory that omits or
  withholds keys; the limitations of directory trust are documented here but
  not mitigated.

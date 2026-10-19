# ADR 0003 — ChaCha20-Poly1305: defer to a future optional suite

Status: accepted (deferral). Inclusion is a valid outcome but is **not** chosen
for the v0.2.0 foundation.

## Context

Phase 1 (cryptographic foundation) must decide whether ChaCha20-Poly1305 joins
AES-256-GCM as a supported AEAD for the v2 streaming format and Envelope v1, or
whether it is explicitly deferred to a future, separately reviewed suite.

The construction is standardized and widely deployed:

- [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439), *ChaCha20 and
  Poly1305 for IETF Protocols*, June 2018. (Accessed 2026-10-19.)
- TLS 1.3 (RFC 8446) assigns ChaCha20-Poly1305 cipher suites, so the
  construction has broad interoperability and implementation coverage.
- [golang.org/x/crypto/chacha20poly1305](https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305)
  is the recognized Go implementation, BSD-3-Clause licensed, maintained by the
  Go project, and used internally by `crypto/tls`. The public package lives in
  `golang.org/x/crypto`, **not** in the Go standard library (the standard
  library only vendors it for `crypto/tls`). (Checked 2026-10-19.)
- [Wycheproof](https://github.com/google/wycheproof) publishes
  `chacha20_poly1305_test.json` vectors for conformance testing.

## Options

### Option A — Adopt now as a second suite

- Add `golang.org/x/crypto` as the project's **first external dependency**.
- Define new suite identifiers: a v2 stream suite byte (e.g. `0x02`) and an
  Envelope v1 suite (`0x0002`).
- Add ChaCha20-Poly1305 to the Wycheproof conformance tests and the CI matrix.

**Costs:** the v2 wire format is pinned (not frozen; ADR 0002) and Envelope v1 is
specified;
introducing a second suite is a format change requiring its own ADR, updated
specifications, golden vectors, and a fresh specialist review. It also breaks
the "standard library only" property of the core.

### Option B — Defer to a future optional suite

- Keep the foundation AES-256-GCM-only, with zero external dependencies.
- Record that ChaCha20-Poly1305 is a planned future suite, gated on a dedicated
  ADR, suite identifier allocation, format revision review, and specialist
  review.

**Costs:** callers that need ChaCha20-Poly1305 (typically for high throughput
without AES-NI, or hardware with only a ChaCha accelerator) must wait.

### Option C — Hand-roll ChaCha20-Poly1305

Rejected. CryptoX must not reinvent cryptographic primitives; a hand-rolled
ChaCha20-Poly1305 would duplicate an audited implementation with no security
benefit.

## Decision

**Option B — defer.** ChaCha20-Poly1305 is reserved as a future optional suite.
The decision is not arbitrary per-message negotiation: a received stream or
envelope that advertises an unknown suite is rejected (never downgraded or
reinterpreted), and a future suite will be identified by a new, explicit
suite/version with its own review.

This matches the already-recorded posture in ADR 0002 and the v2 design review
("ChaCha20-Poly1305 is reserved as a future optional suite").

## Consequences

- `go.mod` keeps zero dependencies; the core remains standard-library-only.
- The v2 stream format and Envelope v1 continue to support exactly one suite
  (`0x01` AES-256-GCM-HKDF-SHA-256 and `0x0001` AES-256-GCM, respectively).
- Unknown suites are rejected at parse time (`stream.ErrUnsupported`,
  `envelope.ErrUnsupportedSuite`).
- Inclusion later requires: a dedicated ADR, suite identifier allocation,
  implementation over `golang.org/x/crypto/chacha20poly1305` (or another
  reviewed implementation), Wycheproof vectors, updated format specifications,
  and a specialist review before the suite is production-ready.

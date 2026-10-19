# Independent review of the v2 streaming cryptographic parameters

Status: recorded as the independent review required by Phase 0 (card P0.05).
This is a separate reviewer's written assessment of ADR 0002 and the v2 design
review; it is not the maintainer's self-review.

## Review metadata

- Reviewer: codex code-review agent (independent context, read-only).
- Commit examined: `5dca04f` (merge of P1.25) and the referenced design documents.
- Documents examined:
  - `docs/security/v2-streaming-design-review.md`
  - `docs/adr/0002-streaming-construction-selection.md`
  - `stream/v2.go`, `stream/v2format.go`, `stream/v2api.go`
  - `docs/spec/envelope-v1.md`, `envelope/envelope.go` (consistency only)

## Verdict

**Non-blocking** — no critical or high cryptographic defects. The construction
is sound: RFC 5869-correct HKDF-SHA-256, a correct 12-byte IV layout
(7-byte prefix || 32-bit BE counter || final flag), an injective domain
separation info string, and correct empty/exact-multiple-of-64 KiB handling in
the function-based path. The findings below are documentation/claim
inaccuracies and one format-consistency defect, not exploitable vulnerabilities.

## Findings

1. **Medium — the "matches Tink" cross-implementation-oracle claim is false.**
   `docs/security/v2-streaming-design-review.md` §3/§7 claim the derived key and
   segment construction "match Tink's AES-GCM-HKDF streaming." Tink uses
   `info = AssociatedData`, while CryptoX uses
   `info = "cryptox/v2/stream" || 0x00 || version || suite || 0x00 || AAD`. For
   the same `(key, salt, AAD)` the derived keys differ, so a stock Tink
   implementation cannot decrypt CryptoX v2 ciphertext. The IV layout and
   final-flag byte do match. Recommendation: correct the wording and document
   that any Tink-based oracle must reimplement CryptoX's exact `domainSep`.

2. **Medium — the two encryption paths emit different formats for streams that
   are an exact multiple of 64 KiB.** `Encryptor` flushes every full segment as
   non-final and then emits a 0-byte final segment on `Close`, while
   `encryptV2WithSecrets` marks the trailing full segment final. The former
   violates the spec rule "the final segment is 1..64 KiB when the stream is
   non-empty." Recommendation: make `Encryptor` defer the last full segment
   until finality is known, or amend the spec to permit both encodings.

3. **Low — the per-key usage limit is not quantified.** §5 publishes "≤ 2^48
   bytes per key," but 2^48 is a per-stream counter limit; no HS20-derived
   per-key bound is established. Recommendation: state that no validated
   per-key limit exists yet and do not reuse the per-stream figure as a per-key
   bound.

4. **Low — documented HKDF dependency does not match the implementation.** The
   docs and ADR state HKDF comes from `golang.org/x/crypto/hkdf`, but the code
   hand-rolls HKDF-SHA-256 over `crypto/hmac` and `go.mod` has no dependency.
   Recommendation: correct the docs to state it is a stdlib-only,
   RFC-5869-tested local HKDF (or adopt the stdlib `crypto/hkdf`).

## Areas found sound

Domain-separation injectivity; salt/nonce/counter construction and final-flag
detection for empty and exact-multiple streams (function-based path); HKDF
extract/expand correctness and output length; fork-safety/process-model
documentation. No nonce-reuse, empty-stream, or truncation/detection defects
were found in the reviewed code.

## Unresolved items that still block the format freeze

- Finding 3 remains open until an HS20-derived per-key bound is published
  (or a justified operational cap is adopted and labeled as such).
- A true independent cross-implementation vector (stock Tink) is not possible
  with the current structured `domainSep`; the oracle must reimplement the
  CryptoX info string.

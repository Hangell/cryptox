# ADR 0002 — Streaming construction selection (v2 replacement format)

Status: **Accepted (maintainer design review recorded)** — the STREAM/AES-GCM-HKDF
construction is selected and its parameters are recorded in
[`docs/security/v2-streaming-design-review.md`](../security/v2-streaming-design-review.md).
Independent specialist review remains a prerequisite before the v2 format is
frozen or shipped as production-ready; this ADR does **not** substitute for that
audit. Architecture approval and Phase 1 entry remain open in
[ROADMAP.md](../../ROADMAP.md#current-progress). No cryptographic code or
dependency was changed by this ADR.

Date: 2026-10-18. Scope: construction selection and parameter recording.
Evidence dates are capture dates; verify against primary sources before any
implementation decision.

---

## Context

The legacy v1 stream format (`SYM1`, AES-GCM chunks, 64-bit random nonce prefix,
nil AAD, no authenticated final record) cannot detect removal of complete
trailing records, does not bind headers, and gives no key proof for empty files.
The [v1 risk register](../../ARCHITECTURE.md#146-legacy-v1-risk-register) records
these as CX-V1-001 through CX-V1-009.

[ARCHITECTURE.md §14.7](../../ARCHITECTURE.md#147-replacement-format-evaluation-gate)
requires an ADR that compares maintained, reviewed streaming constructions and
implementations before any replacement format is implemented or frozen. This ADR
is that record. It must not be read as the specialist review itself.

---

## Decision

Recommend the **STREAM construction (HRRV15)** — nonce-based online
authenticated encryption with nonce-reuse misuse resistance — instantiated the
way [Tink's AES-GCM-HKDF streaming format](https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming)
instantiates it, as the primary candidate for the CryptoX v2 streaming format,
implemented in **pure Go** (standard library `crypto/aes`, `crypto/cipher`,
plus a locally implemented RFC 5869 HKDF-SHA-256 over `crypto/hmac`). The IV
and final-flag layout mirrors Tink, while the HKDF `info` and file header are
CryptoX-specific, so the format is not wire-compatible with Tink; independent
implementations can still serve as reference implementations for the
construction.

Supporting decisions:

- **Do not** put a CGO dependency in the core. The libsodium
  `crypto_secretstream_*` API is recorded as a viable optional adapter, not a
  core path (spec: avoid CGO in the core whenever possible).
- **Do not** adopt a full file-encryption tool as the core primitive. The age
  format is recorded as a reference construction and as an alternative; its
  final-chunk rule is recommended as a hardening requirement for any format.
- **No** new magic bytes, version identifier, or wire format is frozen by this
  ADR. Format freezing requires the specialist review below.

---

## Alternatives considered

### Alternative A — STREAM / AES-GCM-HKDF (Tink), reimplemented in pure Go

- Construction: HRRV15 STREAM, OAE2/nOAE-secure; multi-user analysis in HS20.
- Format: `Header = len(Header)[1] || Salt[16|32] || NoncePrefix[7]`;
  `DerivedKey = HKDF(Hash, ikm=KeyValue, salt=Salt, info=AssociatedData)`.
  Segment `i` is AES-GCM under `DerivedKey` with
  `IV = NoncePrefix[7] || i[4, big-endian] || b`, where `b = 0x01` only for the
  final segment. Segment count `n ≤ 2^32`. Ciphertext is
  `Header || C_0 || ... || C_{n-1}`.
- Per-stream random `Salt` and `NoncePrefix` make accidental nonce reuse across
  streams fail by deriving a different per-stream key (HS20: random nonce +
  nonce-based KDF improves the concrete multi-user bound).
- The final-segment bit `b = 0x01` provides authenticated termination: a
  ciphertext that ends on a non-final segment is rejected as truncated.
- Associated data binds the whole stream through the HKDF `info` input, not
  per-segment AAD (per-segment AAD is empty in Tink).
- Pure Go, no CGO. Standard library only: AES-GCM via `crypto/aes` +
  `crypto/cipher`, HKDF-SHA-256 implemented locally over `crypto/hmac`
  (RFC 5869, verified against official vectors); no adoption of
  tink-go or age as dependencies. (Historical note: this ADR was written while
  `go.mod` declared `go 1.19`; the module now declares `go 1.26`.)
- Tink documents a fork-safety limitation that must be respected.

### Alternative B — libsodium `crypto_secretstream` (XChaCha20-Poly1305), CGO binding

- Mature C library, ISC license, widely deployed; `secretstream` since 1.0.14.
- Per-message XChaCha20-Poly1305 with internal rekeying (ratcheting); a 24-byte
  header; message tags are encrypted; `TAG_FINAL` marks the end and erases the
  in-memory key; no practical limits on stream length or message count.
- Detects truncation, removal, reordering, duplication, and modification.
- Cost: C toolchain and CGO, assembly-optimized builds complicate cross-compiling
  (Windows/macOS/Android/iOS) and conflict with the "no CGO in core" principle.
- Retained as a possible optional adapter for platforms that already ship
  libsodium, not as the core path.

### Alternative C — adopt the age format directly (pure Go)

- age v1 payload is itself a STREAM variant: 16-byte per-file random nonce;
  `payload key = HKDF-SHA-256(file key, salt=nonce, info="payload")`; 64 KiB
  chunks under ChaCha20-Poly1305 with a 12-byte nonce = 11-byte big-endian
  counter plus final byte `0x01` (final) / `0x00` (non-final). Empty final chunk
  is forbidden unless the whole payload is empty.
- Streaming decryption must error on EOF before a valid final chunk.
- Extremely well maintained (BSD-3-Clause, Go, no CGO), specified in the C2SP
  age document, with independent implementations and test vectors
  (`c2sp.org/CCTV/age` is an age test dependency).
- Cost: age is a complete file-encryption format with recipient stanzas
  (X25519, scrypt) — a larger trust surface than CryptoX's streaming primitive
  needs. Using it wholesale couples CryptoX to a file format, not a primitive.
- The payload construction, including its final-chunk rule, is a strong
  reference and an interoperability target if ChaCha20-Poly1305 is preferred
  over AES-GCM-HKDF.

---

## Evaluation against the eight gates

| # | Gate (ARCHITECTURE.md §14.7) | A — STREAM/AES-GCM-HKDF (Tink) | B — libsodium secretstream | C — age payload |
| --- | --- | --- | --- | --- |
| 1 | Authenticated headers, suite/version, ordering, termination, empty streams, suffix removal (CX-V1-001, CX-V1-003, CX-V1-004) | Header carried but authenticated only indirectly via per-stream derived key; segment order bound by counter in IV; termination bound by final bit `b=0x01`; empty stream is one final segment; suffix removal rejected at EOF. | Header authenticated at `init_pull`; ordering/truncation/replay bound per message; `TAG_FINAL` authenticates termination; empty stream needs an explicit final (possibly empty) message. | Final-byte nonce authenticates termination and order; empty payload encoded as one empty final chunk; EOF before final chunk is an error. |
| 2 | Nonce/key lifecycle, domain separation, randomness failures, quantitative limits (CX-V1-002, CX-V1-007) | Random `Salt` + `NoncePrefix` per stream; HKDF derives per-stream key (domain separation via `info`=AAD); `n ≤ 2^32` segments; Tink states 2^64 files × 2^64 bytes per file; HS20 analyzes randomness-failure robustness and notes stronger alternatives. | Internal rekeying per message; 24-byte random header nonce; no practical length/count limits; strong misuse resistance. | 16-byte random nonce per file; HKDF with fixed `info="payload"`; 11-byte counter (2^88 chunks); no per-key bound stated in spec. |
| 3 | Bounded framing, malformed input, unknown versions, no downgrade/reinterpretation (CX-V1-004, CX-V1-005) | Single-byte header length in {24,40}; segment sizes bounded; `n ≤ 2^32`; unknown versions rejected; v2 never parsed as v1 (distinct identifiers). | Fixed-size header and per-message framing; corrupted/unknown data rejected at `pull`; no v1 reinterpretation by construction. | Header stanza format versioned; fixed 64 KiB chunk; unknown recipients/versions rejected; v2 never parsed as v1. |
| 4 | Plaintext-release semantics, short I/O, cleanup, crash behavior, platforms (CX-V1-006, CX-V1-008) | Primitive releases plaintext per segment; the CryptoX file adapter must retain the v1 pattern: unique temp file, `0600`, publish-by-rename on success, cleanup on failure. | Caller controls release per message; adapter obligations identical. | `io.Reader`-based chunk release; adapter obligations identical. |
| 5 | Independent vectors, cross-implementation tests, mutation/property, fuzzing, review plan | Wycheproof vectors are a tink-go test dependency; Tink has C++, Java, Python, Go implementations; OSS-Fuzz coverage exists. | Mature C project with its own test suite; cross-binding interoperability, but fewer external wire-format vectors than Tink. | C2SP spec plus independent Go/Rust implementations and CCTV test vectors. |
| 6 | Maintenance, licensing, dependency cost, platforms, adopting existing format | Apache-2.0; active (tink-go v2.9.0, 2026-10-16); pure Go; deps: protobuf, `x/crypto`, `x/sys`; adopting tink-go forces Go ≥ 1.25. | ISC; active (libsodium 1.0.22, 2026-04-09); C + assembly; CGO; cross-compile burden. | BSD-3-Clause; active (age v1.3.2, 2026-08-29); pure Go; deps: edwards25519, hpke, nistec, `x/crypto`, `x/sys`, `x/term`; forces Go ≥ 1.25 if adopted as dependency. |
| 7 | v1 migration / no-migration policy | See dedicated section below. | Same. | Same. |
| 8 | Scope exclusions (replay, rollback, metadata privacy, compromised endpoints; CX-V1-009) | None of the three supplies replay/rollback protection, metadata privacy, or endpoint isolation; each requires a separately reviewed layer. | Same. | Same. |

---

## Evidence register

Capture date 2026-10-18. Sources are primary: the STREAM paper, the HS20
analysis, the Tink AES-GCM-HKDF streaming specification, the C2SP age
specification, the libsodium secretstream documentation, and the respective
repositories' release and license metadata.

| Subject | Evidence | Date captured |
| --- | --- | --- |
| STREAM construction | Hoang, Reyhanitabar, Rogaway, Vizár, "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance", CRYPTO 2015, [eprint 2015/189](https://eprint.iacr.org/2015/189) | 2026-10-18 |
| Tink multi-user analysis | Hoang, Shen, "Security of Streaming Encryption in Google's Tink Library", [eprint 2020/1019](https://eprint.iacr.org/2020/1019) | 2026-10-18 |
| Tink streaming format | [AES-GCM-HKDF streaming specification](https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming) | 2026-10-18 |
| Tink maintenance / license | tink-go v2.9.0 published 2026-10-16; Apache-2.0; not archived | 2026-10-18 |
| age format | [C2SP age specification](https://c2sp.org/age), payload section | 2026-10-18 |
| age maintenance / license | age v1.3.2 published 2026-08-29; BSD-3-Clause; not archived | 2026-10-18 |
| libsodium secretstream | [libsodium secretstream documentation](https://doc.libsodium.org/secret-key_cryptography/secretstream) | 2026-10-18 |
| libsodium maintenance / license | libsodium 1.0.22 published 2026-04-09; ISC (GitHub API reports NOASSERTION; LICENSE file is ISC) | 2026-10-18 |

Dependencies and platform constraints (capture date 2026-10-18):

- **tink-go** (`github.com/tink-crypto/tink-go/v2`, `go 1.25.0`): pure Go;
  requires `google.golang.org/protobuf`, `golang.org/x/crypto`, `golang.org/x/sys`.
- **age** (`filippo.io/age`, `go 1.25.0`): pure Go; requires
  `filippo.io/edwards25519`, `filippo.io/hpke`, `filippo.io/nistec`,
  `golang.org/x/crypto`, `golang.org/x/sys`, `golang.org/x/term`.
- **libsodium**: C99 + optional assembly; ISC; needs a C toolchain and a CGO
  wrapper for Go; cross-compilation to Windows/macOS/Android/iOS is the caller's
  burden.
- At the time this ADR was written the repository declared `go 1.19`; it now
  declares `go 1.26` (2026-10-18). A pure-Go reimplementation using the
  standard library only adds no dependency and no toolchain bump beyond the
  declared floor.

---

## v1 migration / no-migration

- v1 ciphertexts contain per-chunk tags only; they contain **no** whole-file
  integrity evidence. No migration path can recover a guarantee v1 never had.
- Policy: **no silent migration**. v1 must never be reinterpreted as v2. A v2
  format must use distinct magic bytes and a distinct version/suite identifier.
- A future isolated legacy reader may decrypt v1 for recovery, explicitly
  documented as lacking whole-file integrity (consistent with
  [ADR 0001](0001-legacy-validation.md)). It is not a migration and does not
  extend v1 guarantees.

---

## Plaintext-release limits

- Any streaming primitive releases plaintext before the final segment is
  authenticated; truncation is therefore only detectable at the end of the
  stream. This is inherent to online processing and must be documented.
- The CryptoX file adapter must preserve the existing transactional pattern:
  write decrypted chunks to a unique temporary file with restrictive
  permissions (`0600` on Unix), and publish via rename only after the final
  segment authenticates. Failure must not replace the destination.
- Reader/writer streaming APIs must not be documented as having verified
  whole-stream integrity until the final segment has been read and authenticated.
- Short writes, disk-full, and crash behavior remain platform-dependent and are
  not strengthened by choosing a construction alone (CX-V1-006, CX-V1-008).

---

## Recommendation (accepted)

Recommend **Alternative A**: implement a v2 streaming format that instantiates
the STREAM construction (HRRV15) as specified for Tink's AES-GCM-HKDF streaming
(AES-256-GCM), in pure Go using standard library primitives plus a locally
implemented RFC 5869 HKDF-SHA-256, and treat Tink's Go implementation and the
HS20 analysis as the primary cross-implementation and security references.

The open parameters were recorded in
[`docs/security/v2-streaming-design-review.md`](../security/v2-streaming-design-review.md):
header layout (`CXS2`), suite `0x01` = AES-256-GCM-HKDF-SHA-256, HKDF domain
separation, segment/final-flag semantics, mechanical limits (`n <= 2^32`,
`<= 2^48` bytes/stream), fork-safety, and the CryptoX-specific-header +
CryptoX-specific-`info` compatibility decision.

### Freeze decision (P0.06)

The v2 wire format is **frozen** at the state examined by the independent
review (commit `5dca04f`). The corrections applied while resolving the review
findings do not change the wire format:

- The `Encryptor` bug fix makes the public streaming API emit exactly the
  format already produced by `encryptV2WithSecrets` (no 0-byte final segment
  for exact-multiple-of-64 KiB streams).
- The documentation corrections remove the inaccurate Tink wire-compatibility
  and `x/crypto/hkdf` dependency claims.

The format is frozen for the phase; any change to the algorithm, nonce,
derivation, serialization, or state machine after this point requires a new
ADR and a fresh specialist review. The residual items listed in §8 of the
design review (concrete multi-key bounds and the optional ChaCha20-Poly1305
suite) remain open and do not block Phase 1, but must be resolved before any
production-readiness claim.

---

## Specialist review checklist (recorded)

1. Concrete multi-user / multi-key bounds for the chosen parameters (HS20) —
   **recorded as a residual item** for the independent review; mechanical limits
   are recorded in the design review §5.
2. Header layout, magic, version, suite, and AAD binding — **recorded** in the
   design review §2–§3.
3. Final-segment semantics for empty, one-chunk, and `n = 2^32` streams —
   **recorded** in the design review §4.
4. Fork-safety posture and process model — **recorded** in the design review §6.
5. No-migration policy and legacy-reader scope — **unchanged** from ADR 0001 and
   the v1 migration section below.
6. Test plan (vectors, Tink cross-check, mutation, property, fuzz) — **retained**
   as the acceptance baseline for issues #21 and #27.
7. Dependency and toolchain decision (standard library only) — **recorded**;
   HKDF-SHA-256 is implemented locally over `crypto/hmac` (RFC 5869-verified);
   `go.mod` currently declares `go 1.26`.

---

## Resolved questions

- Default suite: **AES-256-GCM-HKDF-SHA-256** (standard library only; HKDF
  implemented locally, RFC 5869-verified). ChaCha20-Poly1305 is reserved as a
  future optional suite requiring its own review.
- Compatibility: **CryptoX-specific header and HKDF `info`**; the IV and
  final-flag layout mirrors Tink but the format is not wire-compatible with
  Tink. v2 is unambiguously distinct from v1.
- Maximum segment count and byte count: `n <= 2^32`, `<= 2^48` bytes per stream
  at 64 KiB segments (design review §5).
- Toolchain: reimplementation with the standard library only; no adoption of
  tink-go or age as dependencies.

## Remaining open item

- Independent specialist review of the concrete HS20 multi-user / multi-key
  bounds and the resulting per-key usage limit before any production freeze
  (design review §8).

---

## Consequences

- Establishes a recorded, evidence-backed construction choice for the v2
  streaming format.
- Keeps the core CGO-free, dependency-free, and transport-independent.
- Preserves the explicit v1 no-migration policy; legacy ciphertext is never
  promoted to v2 guarantees.
- The v2 wire format is frozen at the independently reviewed state
  (`5dca04f`), with the P0.06 corrections applied; the concrete HS20
  multi-key bounds and the optional ChaCha20-Poly1305 suite remain open items
  that must be resolved before any production-readiness claim.

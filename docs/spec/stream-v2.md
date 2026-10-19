# CryptoX Streaming v2 — implementation-independent specification

- **Format identifier:** `CXS2` (magic bytes `0x43 0x58 0x53 0x32`)
- **Version:** `0x02`
- **Suite:** `0x01` = AES-256-GCM-HKDF-SHA-256
- **Status:** specified and pinned, but **not frozen**. The independent
  specialist review (#71) was administratively closed by owner waiver without a
  review taking place, so the format has **not** been independently validated;
  treat it as experimental. Changes to the algorithm, nonce, derivation,
  serialization, or state machine require a new ADR and a fresh specialist
  review. The internal review (#3) records maintainer judgment only and does
  not substitute for the independent review.

This document is normative: a reader should be able to produce a compatible
implementation without consulting the Go source. All integers are unsigned and
big-endian unless stated otherwise. `‖` denotes byte concatenation.

## 1. Primitives

- AES-256-GCM with a 96-bit (12-byte) nonce and a 128-bit (16-byte) tag.
- HKDF-SHA-256 (RFC 5869): `HKDF-Extract(salt, ikm)` then
  `HKDF-Expand(prk, info, L)`.

The 256-bit key is caller-supplied. A single stream derives its own per-stream
key, so accidental nonce reuse across streams does not reuse an AES-GCM nonce
under the same key.

## 2. Header

The stream begins with a fixed 46-byte header:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `CXS2` = `43 58 53 32` |
| 4 | 1 | version | `02` |
| 5 | 1 | suite | `01` |
| 6 | 1 | salt length | `20` (32) |
| 7 | 32 | salt | 256-bit fresh random value |
| 39 | 7 | nonce prefix | 56-bit fresh random value |

A header whose magic, version, suite, or salt length differs is rejected. A
version or suite other than the supported value is **unsupported** and is never
downgraded or reinterpreted. The legacy `SYM1` format is never reinterpreted as
`CXS2`.

## 3. Key derivation

Let `AAD` be the caller-supplied associated data (possibly empty and at most
65,536 bytes). The v2 APIs reject larger values with `ErrAADTooLarge` before
processing the stream. This is an operational input-size limit that bounds the
HKDF `info` buffer; it is not a cryptographic per-key usage bound. The
per-stream 256-bit key is:

```text
info   = "cryptox/v2/stream" ‖ 0x00 ‖ version ‖ suite ‖ 0x00 ‖ AAD
        = 63 72 79 70 74 6f 78 2f 76 32 2f 73 74 72 65 61 6d
          00
          version (1 byte)
          suite   (1 byte)
          00
          AAD

derivedKey = HKDF-SHA-256(ikm = key, salt = header.salt, info = info, L = 32)
```

This `info` layout is CryptoX-specific. It is **not** Tink's `info = AAD`
construction, so for the same `(key, salt, AAD)` the derived key differs from
Tink's and the ciphertext is not Tink wire-compatible. The AAD bytes are part
of HKDF `info`; they are not passed as GCM AAD to each segment.

## 4. Segmentation

The plaintext is divided into a sequence of segments:

- All segments except the last contain exactly 65,536 bytes (64 KiB).
- The last segment contains between 1 and 65,536 bytes.
- An **empty** stream has one empty final segment (0 plaintext bytes).

Segment `i` (0-based) is encrypted as:

```text
IV        = noncePrefix(7 bytes) ‖ counter(4 bytes, big-endian) ‖ finalFlag(1 byte)
finalFlag = 0x01 if this is the final segment, 0x00 otherwise
segmentCt = AES-256-GCM.Seal(derivedKey, IV, plaintextSegment, aad = empty)
```

`counter` is the 32-bit segment index. The final-flag byte is bound into the IV,
so the final flag is authenticated: decrypting a final segment as non-final (or
vice versa) fails authentication.

The ciphertext is:

```text
header ‖ segmentCt[0] ‖ segmentCt[1] ‖ ... ‖ segmentCt[n-1]
```

where each `segmentCt` is `plaintextSegment ‖ 16-byte tag`.

### Finalization semantics

- A full-size segment (65,552 bytes of ciphertext) is final only when no bytes
  follow it in the input.
- A short segment (fewer than 65,552 bytes) is always final.
- A stream that ends without a final segment, or whose final segment is shorter
  than a 16-byte tag, is **truncated** and must be rejected.
- Data after the final segment is rejected: it either fails short (truncation)
  or fails AES-GCM authentication (the final flag is bound into the IV).

## 5. Limits

| Quantity | Limit | Enforcement |
|---|---|---|
| Segments per stream | `n ≤ 2^32` (32-bit counter) | rejected when exceeded |
| Bytes per stream | `n × 65536 ≤ 2^48` (256 TiB) | consequence of the counter limit |
| Randomizer per stream | 312 bits (`salt ‖ noncePrefix`) | fresh from the system CSPRNG |

The collision probability across `q` streams under one key is approximately
`q² / 2³¹³`.

No validated **per-key** usage bound is published. The `2^48` byte limit is a
per-stream mechanical limit, not a per-key cryptographic bound; a concrete
multi-user/multi-key bound remains an open specialist item (see the design
review §8).

## 6. Decryption

1. Read and validate the 46-byte header (reject unknown magic/version/suite).
2. Derive `derivedKey` per §3.
3. For `counter = 0, 1, 2, …`:
   - Read one full segment (65,552 bytes). If fewer remain, that short read is
     the final segment; it must be at least 16 bytes (the tag).
   - A full segment is final only when no more bytes follow. If bytes follow,
     `finalFlag = 0x00`; otherwise `finalFlag = 0x01`.
   - Reject if the stream ends before a final segment exists.
   - Decrypt with `IV = noncePrefix ‖ counter ‖ finalFlag`; any authentication
     failure aborts with an error and no further plaintext is returned.
4. After the final segment, reject any trailing bytes (§4).
5. Only when the final segment has been authenticated may the consumer treat
   the plaintext as complete. Plaintext yielded before finalization is
   segment-authenticated only.

## 7. Distinctions

- **vs. Tink AES-GCM-HKDF streaming:** the IV/final-flag layout mirrors Tink,
  but the HKDF `info` and the file header are CryptoX-specific, so the format is
  not Tink wire-compatible.
- **vs. the legacy `SYM1` format:** `CXS2` has a distinct magic, authenticated
  termination, and per-stream key derivation. `SYM1` ciphertext is never
  promoted to `CXS2` guarantees.

## 8. Evolution

New versions or suites use new explicit version/suite identifiers and their own
specification and review. Unknown values are rejected; there is no negotiation
and no insecure fallback. A future ChaCha20-Poly1305 suite is reserved (ADR 0003)
and would be a new suite identifier.

Freezing a version or suite identifier remains reserved to an approval
decision (#72). Because the independent specialist review (#71) was
administratively waived without a review, **no freeze is in effect for `CXS2`**
and its parameters are not validated.

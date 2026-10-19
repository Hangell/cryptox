# V2 streaming format — maintainer design review

Date: 2026-10-18. Scope: design review of the construction selected in
[ADR 0002](../adr/0002-streaming-construction-selection.md), resolving the
open parameters before any v2 implementation.

> **Status of this review.** This is a maintainer-level design review, not an
> independent cryptographic audit. It records the engineering decisions and the
> analysis they rely on. Independent specialist review remains a prerequisite
> before the v2 format is frozen or shipped as production-ready. No claim of
> independent audit is made by this document.

## 1. Construction and threat assumptions

The v2 stream format uses the **STREAM** construction of Hoang, Reyhanitabar,
Rogaway, and Vizár (CRYPTO 2015, "Online Authenticated-Encryption and its
Nonce-Reuse Misuse-Resistance", [eprint 2015/189](https://eprint.iacr.org/2015/189)),
instantiated as AES-GCM with a nonce-based key derivation, the same shape as
Tink's AES-GCM-HKDF streaming format. Its multi-user security was analyzed by
Hoang and Shen in [eprint 2020/1019](https://eprint.iacr.org/2020/1019).

Assumed threat model:

- The caller generates and protects the root key material; key compromise is
  outside the format's guarantees.
- The associated data (AAD) is authenticated but not confidential.
- The format provides confidentiality and integrity of the plaintext against
  adaptive chosen-ciphertext attackers within the HS20 concrete bounds.
- The format does **not** provide replay/rollback protection, metadata privacy,
  or protection from a compromised process or operating system.

## 2. Suite and header

Default suite `0x01` = **AES-256-GCM-HKDF-SHA-256**. AES-GCM comes from the Go
standard library (`crypto/aes` + `crypto/cipher.NewGCM`); HKDF from
`golang.org/x/crypto/hkdf`. ChaCha20-Poly1305 is reserved as a future optional
suite and requires its own review before introduction.

Header layout (46 bytes, all fixed size):

| Field | Size (bytes) | Value |
| --- | --- | --- |
| magic | 4 | ASCII `CXS2` |
| version | 1 | `0x02` |
| suite | 1 | `0x01` (AES-256-GCM-HKDF-SHA-256) |
| saltLen | 1 | `32` |
| salt | 32 | fresh CSPRNG bytes per stream |
| noncePrefix | 7 | fresh CSPRNG bytes per stream |

`magic`/`version`/`suite`/`saltLen` are fixed-size structural fields.
`version` and `suite` are additionally bound into the key derivation (§3), so a
modified identifier yields a different derived key and fails authentication.

## 3. Key derivation and domain separation

```
derivedKey = HKDF-SHA-256(ikm = keyValue, salt = salt, info = domainSep)
length(derivedKey) = 32
domainSep   = "cryptox/v2/stream" || 0x00 || version || suite || 0x00 || AAD
```

- `version` and `suite` are the single header bytes, included in `info` to
  domain-separate format revisions and suites.
- `AAD` is the caller-supplied associated data, authenticated via the key
  derivation (`info`), exactly as Tink binds AAD through the HKDF `info` input.
  Per-segment AEAD AAD is empty.
- `salt` (256-bit) and `noncePrefix` (56-bit) are fresh per stream, so
  accidental reuse of a caller-supplied raw key across streams derives a
  different per-stream key with overwhelming probability.

## 4. Segment construction

Plaintext is split into segments of at most `segmentSize = 65536` (64 KiB)
plaintext bytes.

- Non-final segments are exactly 64 KiB.
- The final segment is 1..64 KiB when the stream is non-empty.
- An empty stream is encoded as exactly one final segment of 0 bytes, so even an
  empty stream carries a GCM tag and proves key possession.

For segment index `i` (0-based, 32-bit big-endian):

```
finalByte = 0x01 if i == n-1 else 0x00
IV_i      = noncePrefix[7] || i_be[4] || finalByte
C_i       = AES-256-GCM(key = derivedKey, nonce = IV_i, plaintext = M_i, aad = "")
```

Ciphertext = `header || C_0 || ... || C_{n-1}`.

Decryption must reject:

- a final segment followed by any further segment;
- end-of-stream before a final segment (truncation);
- a missing, duplicated, or reordered segment index (counter continuity);
- a segment index `>= 2^32`.

## 5. Quantitative limits

- Segments per stream: `n <= 2^32` (32-bit counter); encryption fails above it.
- Bytes per stream: `n * 64 KiB <= 2^48` bytes (256 TiB) by the counter limit.
- Per-stream randomizer: `salt || noncePrefix` = 312 bits. The collision
  probability across `q` streams under one key is approximately `q^2 / 2^313`.

Per-key usage guidance (operational, to be confirmed against HS20 concrete
bounds by the independent review): keep total bytes per key conservative
(<= 2^48 bytes) and stream count well below 2^32. The exact concrete multi-user
bounds remain an item for the independent specialist review; the format exposes
the mechanical limits above regardless of that review.

## 6. Fork-safety and process model

AES-GCM-HKDF streaming is documented by Tink as **not fork-safe**: a forked
process that continues from the same in-memory state would reuse segment nonces.
CryptoX v2 inherits this property. The process model is:

- one logical writer per stream state;
- do not fork after stream state is initialized and then continue both copies;
- the high-level file API re-creates fresh state per operation, so normal
  sequential use is unaffected.

## 7. Compatibility decision

The segment construction (derived key, IV layout, final-flag byte) matches
Tink's AES-GCM-HKDF streaming, while the file header is CryptoX-specific
(`CXS2`). This keeps v2 unambiguously distinct from v1 (`SYM1`) and lets a
Tink-based implementation serve as an independent cross-implementation oracle
for the segment ciphertext once `domainSep` is fixed.

## 8. Residual items for the independent specialist review

This review records decisions but does not replace the required independent
audit. The following must be confirmed by a specialist before any production
freeze:

1. Concrete multi-user / multi-key bounds for the chosen parameters (HS20).
2. The exact `domainSep` string and its interaction with AAD length encoding.
3. Per-key and per-stream usage limits to publish.
4. The ChaCha20-Poly1305 optional suite, if and when introduced.

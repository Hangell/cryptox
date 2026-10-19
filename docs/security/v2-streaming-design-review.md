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
standard library (`crypto/aes` + `crypto/cipher.NewGCM`); HKDF is the
standard-library HMAC-SHA-256 construction implemented locally (RFC 5869,
verified against the published test vectors). ChaCha20-Poly1305 is reserved as
a future optional suite and requires its own review before introduction.

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
  derivation (`info`). The `info` layout is CryptoX-specific
  (`domainSep || 0x00 || version || suite || 0x00 || AAD`); it is *not*
  Tink's `info = AAD` construction, so the derived key and segment ciphertexts
  are not wire-compatible with Tink even though the IV/final-flag layout
  mirrors it. Per-segment AEAD AAD is empty.
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

Per-key usage guidance: the format publishes **per-stream** mechanical limits
only (see above). CryptoX does not currently advertise a validated per-key
bound; a concrete multi-key/multi-user limit remains an open item from the
independent review (see §8). Until such a bound is established, operators
should limit total bytes per key conservatively and treat the per-stream
`<= 2^48` byte bound as a stream-level, not key-level, guarantee.

## 6. Fork-safety and process model

AES-GCM-HKDF streaming is documented by Tink as **not fork-safe**: a forked
process that continues from the same in-memory state would reuse segment nonces.
CryptoX v2 inherits this property. The process model is:

- one logical writer per stream state;
- do not fork after stream state is initialized and then continue both copies;
- the high-level file API re-creates fresh state per operation, so normal
  sequential use is unaffected.

## 7. Compatibility decision

The IV/final-flag layout mirrors Tink's AES-GCM-HKDF streaming, while the HKDF
`info` is CryptoX-specific and the file header is CryptoX-specific (`CXS2`), so
v2 ciphertexts are not wire-compatible with Tink. The header keeps v2
unambiguously distinct from v1 (`SYM1`); a Tink-based implementation could
still serve as an independent implementation reference for the segment AEAD
layout, but byte-for-byte cross-compatibility with Tink is not claimed.

## 8. Residual items for the independent specialist review

The independent review was performed and recorded in
[`docs/security/v2-independent-review.md`](v2-independent-review.md); its four
findings are resolved in this document and in the implementation. The following
items remain open and must be confirmed by a specialist before any production
freeze:

1. Concrete multi-user / multi-key bounds for the chosen parameters (HS20), and
   the resulting **per-key** usage limit to publish (the per-stream limits are
   mechanical and already documented in §5).
2. The ChaCha20-Poly1305 optional suite, if and when introduced.

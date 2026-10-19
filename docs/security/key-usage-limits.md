# Key and nonce usage limits

Status: experimental. The package enforces the v2 per-stream counter limit and
a 64 KiB operational limit on v2 caller-supplied AAD. The per-key figures below
remain **unvalidated candidates**, not security guarantees. Card #71 was closed
by owner waiver for project tracking; no independent specialist confirmed the
figures or derived a concrete multi-user/multi-key bound.

## Limit types

- **Structural** — follows from the format and is enforced by the SDK. It does
  not establish a cryptographic advantage bound across keys or streams.
- **Operational** — bounds input size or resource use at an API boundary. It is
  not a cryptographic usage limit.
- **Cryptographic** — a bound on the adversary's total advantage over all
  encryption queries, data blocks, associated data, and failed verification
  attempts. Stateless APIs do not count usage; callers must enforce approved
  limits.
- **Candidate** — a proposed number whose complete proof and applicability to
  this exact CryptoX construction have not been reviewed.

## Enforced and unresolved limits

| Component | Scope | Unit | Bound | Type | Enforcement | Evidence or limitation |
| --- | --- | --- | --- | --- | --- | --- |
| v2 stream | per stream | segments | `n ≤ 2^32` | Structural | `checkCounter` | 32-bit counter; boundary tests exercise the helper without large files. |
| v2 stream | per stream | plaintext bytes | `n × 65,536 ≤ 2^48` | Structural | Counter limit | Maximum implied by the segment size and counter width; not a per-key bound. |
| v2 stream | per call | AAD bytes | `≤ 65,536` | Operational | `MaxV2AADSize`; oversized input returns `ErrAADTooLarge` | AAD is included in HKDF `info`, copied into a bounded buffer, and is not GCM/GHASH AAD. The cap bounds the additional `info` allocation to a fixed prefix plus 64 KiB. |
| one-shot `aead.Seal`/`Open` | per key | invocations, data blocks, failed verification work | No approved bound | Cryptographic | Caller | The previous `2^32`/`2^48` proposal is incomplete: failed `Open` work must include the sizes of submitted ciphertext and AAD, not only attempt count. |
| v2 streams | per root/master key | stream count and aggregate bytes | No approved bound | Cryptographic | Caller | The `2^32` streams and `2^48` aggregate-byte figures remain candidates pending an exact multi-user/multi-key analysis. |
| `keys` derivation | per root | derived-key count | No approved bound | Cryptographic | Caller | The proposed `2^32` count has no derivation in the current package. |

## Accounting requirements

For one-shot AES-GCM, GHASH processes the ciphertext payload (excluding nonce
and tag), GCM AAD, and the encoded length block for each invocation. A useful
accounting unit for an invocation is therefore:

```text
ghashBlocks = ceil(ciphertextBytes / 16)
            + ceil(aadBytes / 16)
            + 1 // encoded lengths
```

Track the sum across successful encryption calls and all decryption attempts.
For failed `Open` attempts, track both attempt count and submitted ciphertext
and AAD lengths. An attempt count by itself is not a complete verification-work
budget when message lengths are unbounded. The SDK's stateless `aead.Seal` and
`aead.Open` APIs do not enforce per-key call, byte, block, or verification
limits, and this document does not publish validated numeric limits for them.

For v2 streams, caller AAD is bound through HKDF `info`; each segment uses GCM
with empty GCM AAD. For GCM accounting, sum `ceil(segmentPlaintextBytes / 16) +
1` for each segment (the tag is excluded from ciphertext payload; the extra
block is the GCM length block). Consequently, v2 AAD length belongs in the
HKDF input and resource accounting, not in the GCM GHASH AAD block total.
`MaxV2AADSize` bounds that single-call input. It does not establish a
multi-user security bound.

Within one v2 stream, distinct 32-bit counters and the final flag produce
distinct IVs. Across streams, the pair `salt ‖ noncePrefix` is 312 bits. Under
uniform independent random draws, the approximate probability of a repeated
pair after `q` streams is `q(q−1)/2^313`. This is only the pair-collision term;
it is not the full construction bound. In particular, a repeated salt can
repeat the derived key even when the nonce prefixes differ. The analysis must
include HKDF security, AES-GCM usage, root-key assumptions, and aggregation
across users/keys.

## Candidate figures retained for review

These numbers are retained as a starting point from the earlier proposal, not
as recommendations or guarantees:

- One-shot: `2^32` `Seal` invocations per key, `2^48` aggregate plaintext plus
  GCM-AAD bytes, and `2^32` failed verification attempts. This is incomplete
  until the proof and caller budget also bound the aggregate blocks submitted
  to `Open`, including ciphertext and AAD lengths.
- v2: `2^32` streams and `2^48` aggregate plaintext bytes per root/master key.
- `keys` derivation: `2^32` derived keys per root.

The one-shot random-nonce birthday estimate at `q = 2^32` is approximately
`q(q−1)/2^97 ≈ 2^-33`. For v2, the 312-bit `(salt, noncePrefix)` pair estimate
at the same `q` is approximately `2^-249`. Neither estimate bounds the complete
AEAD construction or the multi-user use of a root key. The earlier combined
advantage claim based on a simplified GCM expression is withdrawn: the
available evidence does not instantiate a theorem for CryptoX's exact
construction and all of its query/data limits.

## Caller responsibilities

The SDK currently has no shared key-usage counter. Until a numeric budget is
validated, applications must not treat the candidate figures above as
approved safe rotation thresholds. Applications that expose these APIs to
untrusted inputs should impose their own per-call size caps and track aggregate
usage by key/root, including failed-decryption work. v2 callers must also keep
each AAD value at or below `stream.MaxV2AADSize`; the SDK rejects larger values.

## Tests and enforcement

- `stream.TestCounterBoundary` checks the accepted maximum counter and rejects
  the next value without creating a huge stream.
- v2 IV tests check distinct counter encodings within one stream; they do not
  establish a probabilistic collision bound.
- `stream.TestV2AADSizeLimit` accepts 64 KiB and rejects 64 KiB plus one byte
  in the streaming and internal file-format entry points.

These tests verify mechanical/API limits only. They do not prove a per-key
cryptographic bound.

## Evidence still required

The owner waiver closed #71's tracking status but did not supply independent
cryptographic review. A complete per-key budget still requires:

1. A concrete HS20 multi-user/multi-key analysis mapped to CryptoX's exact
   HKDF `info`, random salt, nonce prefix, GCM segment layout, root-key
   assumptions, and proposed query limits.
2. An AES-GCM bound that accounts for encryption blocks, AAD, message-length
   blocks, and aggregate failed-verification work with bounded input lengths.
3. A justified root-level bound for streams and derived keys, with the caller's
   enforcement responsibility stated explicitly.
4. Propagation of confirmed or reduced values to the design review, format
   specification, ADR, and public documentation.

Until that analysis exists, the per-key budget is not final, v2 remains
experimental and pinned rather than frozen, and #31 must not be marked done on
the basis of the owner waiver or passing tests alone.

## References

- [NIST SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D), GCM and GMAC.
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), HKDF.
- [Hoang and Shen, Security of Streaming Encryption in Google's Tink Library
  (ePrint 2020/1019)](https://eprint.iacr.org/2020/1019), multi-user analysis for
  Tink's construction; CryptoX's exact instantiation still requires mapping.

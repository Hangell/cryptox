# v2 parameters — specialist review package

Status: **input for the independent specialist review** (card #71). This package
prepares everything a human cryptographic specialist needs to review the v2
streaming parameters. It is **not** itself a review: no independent audit is
claimed by this document, and an automated-agent assessment does not satisfy
the requirement.

## Target

- **Commit to review:** `41e38d2eae536a3816fe1a7617babd23eb33b6cf`
  (`main`, merge of PR #90).
- **Construction:** STREAM (HRRV15) instantiated as AES-256-GCM-HKDF-SHA-256,
  CryptoX-specific header and HKDF `info` (not Tink wire-compatible).

## Artifacts

| Artifact | Purpose |
| --- | --- |
| [docs/adr/0002-streaming-construction-selection.md](../adr/0002-streaming-construction-selection.md) | Construction decision, alternatives, evidence register |
| [docs/security/v2-streaming-design-review.md](v2-streaming-design-review.md) | Parameter record (§2 header, §3 HKDF, §4 segments, §5 limits, §6 fork-safety) |
| [docs/spec/stream-v2.md](../spec/stream-v2.md) | Implementation-independent specification |
| [docs/security/key-usage-limits.md](key-usage-limits.md) | Proposed per-key budget (from #31) |
| `stream/v2.go`, `stream/v2format.go`, `stream/v2api.go` | Implementation |
| `keys/signatures`, `keys/exchange`, `identity/*` | Out of scope for this review (identity track) |

## Parameters to evaluate

For each item, the reviewer records: the parameter as specified, whether it is
**confirmed** or **reduced**, the new value if reduced, and any finding.

1. **Multi-user / multi-key bound (HS20).** Confirm (or tighten) the
   concrete bound for the STREAM construction with the chosen parameters, and
   the resulting per-key usage budget.
2. **Domain separation.** `info = "cryptox/v2/stream" ‖ 0x00 ‖ version ‖ suite
   ‖ 0x00 ‖ AAD`. Confirm the `info` layout is unambiguous and does not collide
   with any other derivation in the library.
3. **Salt.** 256-bit (32-byte) per-stream random salt. Confirm it is used only
   as HKDF salt (not as a GCM nonce) and that its entropy is adequate.
4. **Nonce prefix.** 56-bit (7-byte) per-stream random prefix. Confirm the
   combined `salt ‖ prefix` randomizer (312 bits) yields the stated collision
   probability `≈ q² / 2^313`.
5. **Counter.** 32-bit big-endian segment counter, `n ≤ 2^32`, with the final
   flag in the last IV byte. Confirm the counter/final-flag layout cannot repeat
   an IV within a stream and authenticates termination.
6. **HKDF.** RFC 5869 HKDF-SHA-256 (Extract then Expand, `L = 32`). Confirm the
   locally implemented HKDF matches the vectors and that per-stream key
   derivation is sound.
7. **Per-key budget.** Confirm or reduce the proposed budget below.

## Proposed budget to confirm (from #31)

- `aead.Seal`/`aead.Open`: ≤ 2^32 invocations, ≤ 2^48 plaintext+AAD bytes,
  ≤ 2^32 forgery attempts per key.
- v2 stream: ≤ 2^32 streams and ≤ 2^48 total plaintext bytes per master key.
- `keys` derivation: ≤ 2^32 derived keys per root.

The derivation and assumptions are recorded in
[key-usage-limits.md](key-usage-limits.md). The reviewer confirms these figures
or records reduced values.

## AI technical assessment — does not satisfy independent specialist review

This is a source-based assessment by an AI assistant, not a human opinion or
independent cryptographic audit. It cannot be entered as the reviewer response
below or used to close card #71. It records technical dispositions to help the
human specialist focus on the remaining proof and parameter work.

- **Examined:** repository `main` at `3fccf5b86e26e3f3e7568bfd1ee3fd05864272d3`;
  implementation commit under review `41e38d2eae536a3816fe1a7617babd23eb33b6cf`
  (PR #90). The listed implementation files have no diff between these commits;
  PRs #91–#92 changed review documentation. Targeted tests run on this checkout:
  `go test -count=1 ./aead ./keys ./stream` — passed. Passing tests establish
  implementation behavior for those tests, not the cryptographic bounds.

| Item | AI technical disposition | Evidence / remaining work |
| --- | --- | --- |
| HS20 multi-user / multi-key bound | **Not confirmed; blocks the formal gate.** The construction is a close structural match to Tink AES-GCM-HKDF Streaming AEAD: random salt, 7-byte prefix, 32-bit counter, final byte, per-stream HKDF key, and GCM with empty segment AAD. CryptoX uses a fixed context prefix in HKDF `info`, a 32-byte salt, and its own framing. | Tink's published function is described as based on HRRV15 and analyzed in HS20. This supports using HS20 as the main proof reference, but the concrete reduction still must be instantiated for CryptoX's exact KDF, data/query limits, and threat model. Do not copy a numeric result from Tink without that mapping. |
| Domain separation | **Byte encoding consistent for the current version/suite.** | `v2DomainSep` is a fixed ASCII label, NUL, one-byte version, one-byte suite, NUL, then terminal AAD bytes. This encoding is injective for the current fixed fields and arbitrary AAD; no AAD length field is needed while AAD remains the final field. `keys` uses a different fixed label. A future format that appends fields must version or length-prefix them. |
| Salt | **Implementation matches the proposal; entropy is an assumption.** | Code obtains 32 bytes from `crypto/rand` and passes them as HKDF salt. RFC 5869 treats salt as public and recommends random/pseudorandom salt, ideally HashLen. Confirm deployment RNG assumptions and that the root key has the documented entropy; code checks length, not entropy. |
| Nonce prefix | **Layout and collision arithmetic are consistent under uniform independent draws.** | Code obtains 7 random bytes per stream. The relevant repeated pair is `salt ‖ prefix` (312 bits); the birthday upper estimate is `q(q−1)/2^313`, approximately `2^-249` at `q=2^32`. This estimates pair repetition, not the full AE advantage. The proof must also account for a repeated salt yielding a repeated derived key, even when prefixes differ. |
| Counter / final flag | **Structural uniqueness within one stream is supported by the code.** | IV bytes are prefix (7) ‖ counter (4, big-endian) ‖ final flag (1). `checkCounter` permits indices `0..2^32−1`; distinct indices produce distinct IVs, and GCM authenticates the IV-dependent tag. This is not a proof of the global usage bound. |
| HKDF | **RFC 5869 implementation path passed targeted package tests; KDF security reduction remains open.** | Stream derives 32 bytes using HMAC-SHA-256 Extract/Expand. `go test ./keys ./stream` passed and the repository includes RFC 5869 vectors plus Wycheproof HKDF vectors for `keys`. HS20's abstract KDF assumption still needs to be related explicitly to this HKDF use and the caller's root-key entropy. |
| Proposed per-key budget | **Not approved as written.** | The one-shot GCM budget and v2 stream budget need separate accounting. v2 AAD is placed in HKDF `info`, not in GCM's GHASH AAD input; its processing/allocation bound must be specified separately. A complete bound must combine KDF distinguishing advantage, GCM advantage over all relevant queries/blocks/verifications, randomizer collisions, and multi-user aggregation. The `2^32` derived-keys-per-root limit also lacks a derivation in the package. The verification budget limits attempts but does not bound cumulative bytes/blocks submitted to `Open`/stream decryption. All proposed totals remain caller-enforced and unvalidated. |

### Findings and conclusion (AI assessment)

1. **Blocking for card #71 — no concrete advantage calculation.** The documents
   do not derive a numeric multi-user bound for the stated root-key budgets and
   exact query limits. Keep the proposed values marked experimental; do not
   freeze the format or describe the budget as validated on this basis.
2. **Needs correction/clarification before relying on the budget — AAD units.**
   `key-usage-limits.md` says AAD contributes to GCM block/tag bounds. That is
   true for one-shot `aead.Seal`/`Open`; v2 stream AAD is instead input to HKDF
   `info`. State separate accounting and bound the accepted AAD length and its
   allocation cost. Also set a cumulative ciphertext/block budget for failed
   `Open` and stream-decryption attempts; a count of attempts alone is not a
   GCM verification bound when their lengths are unbounded.
3. **Separate implementation finding — I/O lookahead errors.** In
   `stream/v2format.go`, `Peek(1)` treats every non-nil error as end-of-stream.
   A non-EOF source error after a full segment can therefore be treated as a
   final segment instead of being propagated. Review the matching lookahead
   paths in `stream/v2api.go` and file adapters; only EOF should establish that
   no next byte exists. This is outside the parameter proof, but should be
   tracked before claiming robust stream I/O behavior.

**AI conclusion:** the byte layouts, randomizer arithmetic, and per-stream
counter bound are consistent with the implementation and the Tink construction
reference. The proposed per-key cryptographic budgets are **not confirmed**.
This assessment is not independent and does not itself fulfill the specialist
review. It does not approve the format for freeze. The project owner may waive
the specialist-review requirement for project tracking, but that waiver cannot
be treated as technical confirmation of the proposed budgets.

### Human project-owner gate — authorization recorded

- **Signature:** CryptoX project owner (typed by the assistant at the owner's
  explicit request in this conversation).
- **Date:** 2026-10-19.
- **Decision:** Accept the AI technical assessment and the targeted test run as
  sufficient for project-owner closure of card #71; waive the independent
  specialist-review requirement for card tracking.
- **Evidence:** commit `3fccf5b86e26e3f3e7568bfd1ee3fd05864272d3`;
  `go test -count=1 ./aead ./keys ./stream` passed.
- **Scope:** This owner waiver closes the tracking task only. It does not claim
  independent cryptographic review, confirm the proposed per-key bounds, or
  approve format freeze. Those technical limitations remain open for #31/#72.

Primary references for the human review include [HRRV15](https://eprint.iacr.org/2015/189),
[HS20](https://eprint.iacr.org/2020/1019),
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869),
[NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), and the
[Tink AES-GCM-HKDF streaming specification](https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming).

## Review template

```markdown
# Independent specialist review — v2 streaming parameters

- **Reviewer:** <name / organization>
- **Commit examined:** 41e38d2eae536a3816fe1a7617babd23eb33b6cf
- **Date:** <YYYY-MM-DD>
- **Hypotheses:** <trust model, threat model, randomness assumptions>

## Verdict per parameter

| Parameter | Confirmed / Reduced | New value (if reduced) | Finding |
| --- | --- | --- | --- |
| HS20 multi-user/multi-key bound | | | |
| Domain separation | | | |
| Salt | | | |
| Nonce prefix | | | |
| Counter / final flag | | | |
| HKDF | | | |
| Per-key budget | | | |

## Findings

- <blocking / non-blocking finding with severity and remediation>

## Conclusion

- <approve as-is / approve with the reductions above / reject>
```

## After the review

The confirmed values must be propagated consistently to `key-usage-limits.md`,
`v2-streaming-design-review.md`, `stream-v2.md`, and the READMEs before #31 is
closed. Format freeze and the ADR 0002 approval decision then proceed in #72.

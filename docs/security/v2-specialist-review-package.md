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

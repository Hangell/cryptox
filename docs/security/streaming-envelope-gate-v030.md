# v0.3.0 streaming & envelope gate (P2.36)

This record closes the Phase 2 gate ("um arquivo produzido por CryptoX deve
poder ser especificado, validado e implementado por outra equipe sem consultar
o código Go"). It consolidates the results of cards #41–#69 and the P2.30–P2.35
complements. It does **not** publish a release tag.

**Status:** ready — no known blockers in the Phase 2 scope.

## Checklist

| Area | Result | Evidence |
|---|---|---|
| Implementation-independent v2 spec | published | `docs/spec/stream-v2.md` (P2.32) |
| Implementation-independent Envelope spec | published | `docs/spec/envelope-v1.md` |
| Independent reference implementation | Python, spec-only, both directions | `testdata/interop/ref.py` (P2.33) |
| Official pinned corpus | empty / 1 B / exact 1–2 segments / +1 / AAD / keyID | `testdata/interop/*-corpus.json` + Go tests (P2.34) |
| Final-segment authentication (truncation/reorder/duplication) | implemented + tested | `stream` v2 tests, `TestV2ReorderDuplicateMissingDetected` |
| I/O failures and partial reads/writes | tested | `TestFragmentedIO`, `TestV2FileDestinationPreservedOnTruncation` |
| Envelope limits + no-panic | tested | `TestOpenRejectsMalformedWithoutPanic` (P2.30) |
| Envelope fuzzing in CI | scheduled + smoke | `.github/workflows/fuzz.yml`, `ci.yml` (P2.31) |
| Legacy v1 retirement decision | recorded | ADR 0004 + `docs/security/v1-migration.md` (P2.35) |
| Independent review of v2 parameters | **pending** | internal agent review recorded in `docs/security/v2-independent-review.md`; independent specialist review and format freeze remain open |

## Dependencies

| Dependency | Status |
|---|---|
| #72 (P0.06) v2 review findings | review — merged |
| #74 (P1.26) foundation gate | review — merged |
| #75 (P2.30) envelope limits/errors | review — merged (PR #58) |
| #76 (P2.31) envelope fuzz CI | review — merged (PR #57) |
| #77 (P2.32) v2 spec | review — merged (PR #56) |
| #78 (P2.33) independent interop | review — merged (PR #60) |
| #79 (P2.34) official corpus | review — merged (PR #61) |
| #80 (P2.35) legacy retirement | review — merged (PR #59) |

## Format stability

- The `CXS2` stream format is **specified and pinned**, but **not frozen**: its
  parameters have not yet received an independent specialist review, which
  remains an open item (ADR 0002 freeze decision is pending that review).
- Envelope v1 (`CXE1`) is **specified and pinned**; it has not yet received an
  independent specialist review, which remains an open item before any
  production-readiness claim.

## Published limitations

- **Incremental plaintext:** a `Decryptor` yields plaintext that is
  segment-authenticated only until `io.EOF`; whole-stream integrity is
  established solely by reading to the end (documented in the API contract).
- **Atomicity:** file adapters publish via temp file + atomic rename, but the
  destination directory is not fsynced and crash durability is
  platform-dependent (documented in `EncryptFileV2`/`DecryptFileV2`).
- **Per-key bounds:** no validated per-key usage bound is published; `2^48`
  bytes is a per-stream mechanical limit.

## Readiness

Phase 2 is sufficiently specified, implemented, tested, and cross-checked to
serve as the streaming and envelope foundation for higher modules. No release
tag is published by this record.

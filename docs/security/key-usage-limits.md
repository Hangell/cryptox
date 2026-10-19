# Key and nonce usage limits

Status: experimental. This document records the **structural** limits that the
implementation enforces or assumes, and a **proposed** per-key cryptographic
budget. Every proposed figure remains a **proposal** until the independent
specialist review (#71) confirms or reduces it; nothing here is a proof or a
production guarantee.

## Definitions

- **Structural limit** — a bound derived from the encoding (counter width,
  nonce length, segment layout) that the code enforces mechanically.
- **Cryptographic limit** — a bound on the total adversarial advantage across
  messages, bytes/blocks, AAD, and failed authentication attempts. In stateless
  APIs the code cannot count these, so enforcement is the caller's
  responsibility.
- **Scope** — whether the limit is per **key** (a single AES/GCM master key),
  per **root** (a `keys` derivation root), or per **stream** (one `CXS2`
  stream).

## Usage limits

Each row records scope, unit, bound, type, enforcement, and the
assumptions/formula/source behind the bound.

| Component | Scope | Unit | Bound | Type | Enforcement | Assumptions / formula / source |
| --- | --- | --- | --- | --- | --- | --- |
| `aead.Seal` | per key | invocations | ≤ 2^32 | Cryptographic | Caller (stateless) | 96-bit random nonce; collision ≈ q²/2^97 ≤ 2^-33 at q=2^32 (birthday bound) |
| `aead.Seal` | per key | total plaintext bytes | ≤ 2^48 (256 TiB) | Cryptographic | Caller (stateless) | GCM block bound: σ ≤ 2^44 blocks ⇒ (σ+q)²/2^129 ≤ 2^-41 (improved GCM bounds) |
| `aead.Open` | per key | forgery attempts | ≤ 2^32 | Cryptographic | Caller (stateless) | 128-bit tag; polynomial auth term stays below 2^-40 at q_v=2^32 |
| `aead.Seal`/`Open` | per key | AAD bytes | ≤ 2^48 total | Cryptographic | Caller (stateless) | AAD is authenticated and contributes to the same block/tag bounds as plaintext |
| v2 stream | per stream | segments | `n ≤ 2^32` | Structural | Enforced (`checkCounter`) | 32-bit big-endian segment counter |
| v2 stream | per stream | plaintext bytes | `n × 64 KiB ≤ 2^48` | Structural | Enforced (counter limit) | 64 KiB segments |
| v2 stream | per master key | streams | ≤ 2^32 | Cryptographic | Caller (stateless) | 312-bit `salt ‖ noncePrefix`; collision ≈ q²/2^313 (negligible) |
| v2 stream | per master key | total plaintext bytes | ≤ 2^48 | Cryptographic (proposed) | Caller (stateless) | HS20 multi-key bound not yet confirmed (#71) |
| `keys.DeriveKey` / `DeriveVersioned` | per root | derived keys | ≤ 2^32 | Cryptographic | Caller (stateless) | HKDF output independence; domain-separated `info` |

## Proposed per-key cryptographic budget

The proposal is built from two standard terms and then applied to the v2
construction. All figures are **proposals** pending #71.

1. **Nonce/randomizer collision.** With `q` fresh random values of bit length
   `n`, the collision probability is approximately `q² / 2^(n+1)`.
   - One-shot `aead.Seal` uses a 96-bit nonce (`n = 96`): at `q = 2^32` the
     collision probability is `2^64 / 2^97 = 2^-33`.
   - A v2 stream uses a 312-bit `salt ‖ noncePrefix` (`n = 312`): at
     `q = 2^32` streams the collision probability is `2^64 / 2^313 = 2^-249`.
     Each stream derives a fresh per-stream GCM key, so accidental nonce reuse
     across streams does not reuse a nonce under one GCM key.

2. **GCM block/tag bound.** For AES-GCM the adversarial advantage grows
   polynomially in the total number of 16-byte blocks processed (`σ`), the
   number of encryption queries (`q`), and the number of forgery attempts
   (`q_v`), all over the 128-bit block/tag size (the leading term is of order
   `(σ + q)² / 2^129`). AAD participates in the same polynomial terms as
   plaintext, so it is folded into the byte/block budget rather than tracked
   separately. Capping `σ ≤ 2^44` blocks (`= 2^48` bytes, plaintext + AAD),
   `q ≤ 2^32`, and `q_v ≤ 2^32` keeps every polynomial term below `2^-40`; the
   combined advantage is dominated by the `2^-33` nonce-collision term and stays
   below roughly `2^-32`.

**Proposed budget (subject to #71):**

- `aead.Seal`/`aead.Open`: ≤ **2^32 invocations**, ≤ **2^48 plaintext + AAD
  bytes**, and ≤ **2^32 forgery attempts** per key, whichever is reached first.
- v2 stream: ≤ **2^32 streams** and ≤ **2^48 plaintext bytes in total** across
  all streams per master key. The `2^48` byte figure is therefore adopted as a
  key-level cap, not only a per-stream cap.
- `keys` derivation: ≤ **2^32 derived keys** per root key.

These figures are **proposals** computed from conservative single-user bounds.
The HS20 multi-user/multi-key analysis for the STREAM construction must confirm
(or reduce) them before they are treated as final (#71).

## Caller responsibilities for stateless APIs

`aead.Seal`/`aead.Open` and the `keys` derivation functions hold no mutable
state and cannot count invocations. Callers must therefore:

- rotate keys before 2^32 `Seal` calls, 2^48 total plaintext+AAD bytes, or 2^32
  forgery attempts under a single key;
- keep the total plaintext across all v2 streams under a master key at or
  below 2^48 bytes;
- rotate master keys before 2^32 streams or 2^32 derived keys.

These are assumptions, not enforced policies; violating them voids the
guarantees the implementation otherwise provides.

## Tests

Counter limits are tested without creating giant files:

- `stream.TestCounterBoundary` — `checkCounter(math.MaxUint32)` passes and
  `checkCounter(math.MaxUint32 + 1)` is rejected; `checkCounter` is the shared
  guard used by the v1 writer, the v2 `Encryptor`/`Decryptor`, and the v2 file
  adapters.
- `stream.TestV2...` IV-uniqueness checks — the per-segment IV is unique across
  counters and does not repeat within a stream.

These tests verify the **mechanical** counter guard only; they do not prove the
cryptographic bounds above.

## Handoff to the independent review (#71)

The independent specialist review must record, at minimum:

- the identity of the independent reviewer, the commit and the artifacts
  examined, and the hypotheses used;
- the concrete HS20 multi-user/multi-key bound for the chosen parameters;
- which proposed figures above were **confirmed**, and which were **reduced**
  (with the new value);
- any remaining findings or open items.

Until #71 produces that record and the final values are propagated consistently
across this document, the v2 design review, the spec, and the READMEs, the
per-key budget is **not final**, and card #31 must not be closed as `done`.

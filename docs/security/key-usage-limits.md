# Key and nonce usage limits

Status: experimental. This document records the **structural** limits that the
implementation enforces or assumes, and a **proposed** concrete per-key
cryptographic budget. The proposal is derived below from standard GCM and
random-nonce bounds; it is subject to confirmation by the independent
specialist review (#71) and is not a proof.

## Definitions

- **Structural limit** — a bound derived from the encoding (counter width,
  nonce length, segment layout) that the implementation enforces mechanically.
- **Cryptographic limit** — a bound on the total adversarial advantage across
  many keys/messages. The proposal below uses conservative single-user GCM
  bounds and is marked for specialist (HS20 multi-user/multi-key) validation.
- **Enforcement** — where the bound is checked in code, or where the caller is
  responsible because the API is stateless.

## Usage limits

| Component | Unit | Bound | Type | Enforcement |
| --- | --- | --- | --- | --- |
| `aead.Seal` (AES-256-GCM, one-shot) | invocations per key | ≤ 2^32 calls | Cryptographic (96-bit random nonce collision ≈ q²/2^97 ≤ 2^-33 at q=2^32) | Not enforced (stateless API) — caller responsibility |
| `aead.Seal` | total plaintext bytes per key | ≤ 2^48 bytes (256 TiB) | Cryptographic (GCM block bound, see below) | Not enforced — caller responsibility |
| `aead.Open` | forgery attempts per key | ≤ 2^32 | Cryptographic (tag verification bound) | Not enforced — caller responsibility |
| v2 stream (`CXS2`) | segments per stream | `n ≤ 2^32` | Structural (32-bit counter) | Enforced: `checkCounter` rejects `> MaxUint32` |
| v2 stream | bytes per stream | `n × 64 KiB ≤ 2^48` bytes | Structural (counter × segment size) | Enforced via the segment counter limit |
| v2 stream | streams per master key | ≤ 2^32 streams | Cryptographic (312-bit randomizer collision ≈ q²/2^313) | Not enforced — caller responsibility |
| v2 stream | total plaintext bytes per master key | ≤ 2^48 bytes | Cryptographic (proposed; HS20 validation #71) | Not enforced — caller responsibility |
| `keys.DeriveKey` / `keys.DeriveVersioned` | derived keys per root | ≤ 2^32 | Cryptographic (HKDF output independence) | Not enforced — caller responsibility |

## Proposed per-key cryptographic budget

The proposal is built from two standard terms and then applied to the v2
construction.

1. **Nonce/randomizer collision.** With `q` fresh random values of bit length
   `n`, the collision probability is approximately `q² / 2^(n+1)`.
   - One-shot `aead.Seal` uses a 96-bit nonce (`n = 96`): at `q = 2^32` the
     collision probability is `2^64 / 2^97 = 2^-33`.
   - A v2 stream uses a 312-bit `salt ‖ noncePrefix` (`n = 312`): at
     `q = 2^32` streams the collision probability is `2^64 / 2^313 = 2^-249`,
     negligible. Each stream then derives a fresh per-stream GCM key, so
     accidental nonce reuse across streams does not reuse a nonce under one
     GCM key.

2. **GCM block bound.** For AES-GCM the adversarial advantage grows
   polynomially in the total number of 16-byte blocks processed (`σ`), the
   number of encryption queries (`q`), and the number of forgery attempts
   (`q_v`), all over the 128-bit tag/block size (the leading term is of order
   `(σ + q)² / 2^129`). Capping `σ ≤ 2^44` blocks (`= 2^48` bytes), `q ≤ 2^32`,
   and `q_v ≤ 2^32` keeps every polynomial term below `2^-40`; the combined
   advantage is then dominated by the `2^-33` nonce-collision term and stays
   below roughly `2^-32`.

**Proposed budget (subject to #71):**

- `aead.Seal`/`aead.Open`: ≤ **2^32 invocations**, ≤ **2^48 plaintext bytes**,
  and ≤ **2^32 forgery attempts** per key, whichever is reached first.
- v2 stream: ≤ **2^32 streams** and ≤ **2^48 plaintext bytes in total** across
  all streams per master key. The `2^48` byte figure is therefore adopted as a
  key-level cap, not only a per-stream cap.
- `keys` derivation: ≤ **2^32 derived keys** per root key.

These figures are **proposals** computed from conservative single-user bounds.
The HS20 multi-user/multi-key analysis for the STREAM construction must confirm
(or tighten) them before they are treated as final (#71); until then they are
experimental guidance, not a production guarantee.

## Caller responsibilities for stateless APIs

`aead.Seal`/`aead.Open` and the `keys` derivation functions hold no mutable
state and cannot count invocations. Callers must therefore:

- rotate keys before 2^32 `Seal` calls, 2^48 total plaintext bytes, or 2^32
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

These tests verify the mechanical counter guard, not the cryptographic bound.

## Residual item

The concrete HS20 multi-user/multi-key bound and any resulting refinement of the
per-key budget above remain **open** and are reserved to the independent
specialist review (#71). Until #71 confirms or replaces these figures, this
document must not be read as a production key budget.

# Key and nonce usage limits

Status: experimental. This document records the **structural** usage limits that
the current implementation enforces or assumes, and separates them from the
**cryptographic** per-key bounds that still require an independent specialist
review (card #71). It does not establish a production per-key budget.

## Definitions

- **Structural limit** — a bound derived from the encoding (counter width,
  nonce length, segment layout) that the implementation enforces mechanically.
- **Cryptographic limit** — a bound on the total adversarial advantage across
  many keys/messages (multi-user / multi-key analysis, e.g. HS20) that requires
  a specialist to compute for the chosen parameters.
- **Enforcement** — where the bound is checked in code, or where the caller is
  responsible because the API is stateless.

## Usage limits

| Component | Unit | Bound | Type | Enforcement |
| --- | --- | --- | --- | --- |
| `aead.Seal` (AES-256-GCM, one-shot) | Seal calls per key | ≤ 2^32 calls | Structural (96-bit random nonce collision ≈ q²/2^97) | Not enforced (stateless API) — caller responsibility; documented in the `aead` package doc |
| `aead.Seal` | bytes per call | bounded by RAM/caller input | Structural | Not enforced |
| v2 stream (`CXS2`) | segments per stream | `n ≤ 2^32` | Structural (32-bit counter) | Enforced: `checkCounter` rejects `> MaxUint32` in `Encryptor`/`Decryptor` and the file adapters |
| v2 stream | bytes per stream | `n × 64 KiB ≤ 2^48` bytes (256 TiB) | Structural (counter × segment size) | Enforced via the segment counter limit |
| v2 stream | streams per key (per-stream randomizer collisions) | approximately `q² / 2^313` for `q` streams under one key | Structural (312-bit salt+prefix) | Not enforced — caller responsibility |
| v2 stream | total bytes per key (multi-key bound) | **not yet established** | Cryptographic | Pending independent review (#71) |
| `keys.DeriveKey` / `keys.DeriveVersioned` | derived keys per root | none established | Cryptographic | Pending independent review (#71) |

## Caller responsibilities for stateless APIs

`aead.Seal`/`aead.Open` and the `keys` derivation functions hold no mutable
state and cannot count invocations. Callers must therefore:

- rotate keys before 2^32 `Seal` calls under a single key;
- treat the v2 per-stream 2^48-byte bound as stream-level, not key-level;
- keep total encrypted bytes per key conservative until the independent review
  (#71) establishes a concrete multi-user/multi-key bound;
- never reuse a key for v2 streams beyond the documented guidance.

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

The concrete per-key (multi-user/multi-key, HS20) bound and any resulting
per-key usage budget are **open** and reserved to the independent specialist
review (#71). Until then this document must not be read as a production key
budget.

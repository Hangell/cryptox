# ADR 0004 — Retire the legacy v1 writer; keep an opt-in migration reader

Status: accepted. Defines the v1 retirement and migration plan; the actual
removal is executed as a breaking change before the stable API.

## Context

The repository still contains the legacy `SYM1` streaming format and the
`utils` compatibility facade:

- `stream.EncryptLargeFiles` / `stream.DecryptLargeFiles` implement the v1
  format (`SYM1`, magic `SYM1\x01AESG`), which authenticates each chunk
  independently and has **no authenticated termination**: it cannot detect
  truncation, reordering, or removal at whole-file scope.
- `utils` re-exports the legacy file functions as a facade.

The v2 format (`CXS2`) and Envelope v1 (`CXE1`) are the supported formats. v2
is frozen and independently reviewed (ADR 0002).

## Decision

1. **Remove the legacy v1 writer before the stable API.** No code path may
   produce new `SYM1` ciphertext. Producing data with no whole-file integrity
   guarantee is a misuse hazard, not a compatibility feature.
2. **Keep the legacy v1 reader only as an explicit, opt-in migration tool.**
   `stream.DecryptLargeFiles` (and the `utils` facade) remain available and
   deprecated solely to decrypt old files so they can be re-encrypted into v2
   or Envelope v1. Nothing in the new APIs auto-detects or auto-selects v1.
3. **Document the boundary explicitly.** Re-encrypting a v1 file does **not**
   recover historical integrity: the v1 format never guaranteed whole-file
   integrity, so a tampered v1 file may already have been silently damaged
   before migration. Migration transfers confidentiality, not retroactive
   integrity.

## Consequences

- **Breaking change:** removing `stream.EncryptLargeFiles` and the `utils`
  facade's write path is an API break, documented in the changelog and the
  migration guide. It lands before `v1.0.0`.
- The deprecated reader stays until the stable API, then is removed in the
  following major; removal is announced at least one minor release in advance.
- New flows use v2 / Envelope v1 exclusively; unknown formats are rejected, so
  a v1 file is never silently reinterpreted.
- Tests keep covering the deprecated reader for the duration of its deprecation
  window, and the migration guide is a permanent record of the no-integrity
  caveat.

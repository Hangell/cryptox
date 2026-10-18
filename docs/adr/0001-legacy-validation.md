# ADR 0001 — Validate the legacy baseline

Status: retained as a record of the initial testing increment. Compatibility is
not a requirement for future modernization; the policy in
[ARCHITECTURE.md](../../ARCHITECTURE.md#20-versioning-and-compatibility) governs it.

For the initial increment, keep `utils` as a facade and extract only an internal
reader-based parser to test fragmented input and I/O errors. File operations
publish output after success; partially decrypted data must not replace the
destination on failure.

Do not add authenticated termination or AAD to the same v1 format identifier.
Such changes require a separately identified format and specific security review.
Tests document current behavior and known limitations, not new guarantees.

Later increments may remove the facade or legacy format with documented impact.
No migration implementation or permanent compatibility commitment is implied.
Configured push/PR checks include tests, race detection, and vet, with bounded
fuzzing. Remote success is established only by the actual workflow run.

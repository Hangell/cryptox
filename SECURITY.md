# Security Policy

## Current security status

CryptoX is under development. No independently audited, production-ready release
or supported security-maintenance window is declared by this policy.

The current `stream` implementation uses the legacy v1 file format. It must not be
used where whole-file integrity is required. Planned guarantees in
[ARCHITECTURE.md](ARCHITECTURE.md) are not guarantees of the current implementation.

## Supported guarantees (current implementation)

The guarantees below apply to the current `stream` v1 implementation and the
`keys` package, and only under the listed assumptions. They are the maximum that
the implementation provides; everything in
[Known limitations](#known-limitations) is explicitly not guaranteed.

- Per-chunk confidentiality and integrity: each chunk is encrypted and
  authenticated with AES-GCM under the supplied key.
- Wrong-key rejection for non-empty files: a chunk decrypted with the wrong key
  fails its authentication tag. Empty files are the exception documented below.
- Safe rejection of malformed input: truncated or oversized chunk lengths and
  invalid nonce bytes are rejected before unbounded allocation.
- Transactional publication: output is written to a unique temporary file and
  renamed over the destination only on success, so a failed operation does not
  replace the destination.
- Secure key generation: `keys.GenerateKey` draws from `crypto/rand` and accepts
  only 16, 24, or 32 byte keys.

Assumptions: the caller supplies a suitable key, keeps it secret, uses a fresh
key per v1 file, and writes to a trusted destination directory. The library does
not enforce these policies; violating them voids the guarantees above.

Planned v2 guarantees (not yet implemented): the replacement format selected in
[ADR 0002](docs/adr/0002-streaming-construction-selection.md) and specified in
[docs/security/v2-streaming-design-review.md](docs/security/v2-streaming-design-review.md)
derives an independent per-stream key from a 312-bit randomizer (32-byte salt +
7-byte nonce prefix) via HKDF. It therefore does not rely on a 64-bit nonce
prefix under a caller-reused key, as v1 does. These guarantees apply only once
the v2 format is implemented and independently reviewed; the v1 risks below
remain for legacy ciphertext.

## Known limitations

- Each chunk is authenticated independently. Removing complete trailing chunks
  can go undetected because the format has no authenticated termination record.
- Headers are structurally validated but not fully authenticated as associated data.
- Empty files have no authentication tag and cannot authenticate the supplied key.
- The random nonce prefix is 64 bits. Reusing a key across files risks prefix
  collisions; use a fresh key per file. The API does not enforce this policy.
- Counter exhaustion is checked within each file, but this does not prevent
  collisions between files encrypted under the same key.
- `ValidateEncryptedFile` checks the header only, not ciphertext integrity.
- Temporary plaintext files use Unix mode `0600`. Windows requires appropriate
  directory ACLs. Use a trusted destination directory; process crashes may leave
  temporary files. Cleanup is attempted on returned errors.
- Rename atomicity depends on the operating system and filesystem. The destination
  directory is not synced, so crash durability is not guaranteed.
- Go does not guarantee immediate or complete erasure of secrets from memory.
- The library does not provide replay protection, storage rollback protection,
  protection from a compromised process/OS, or an E2EE protocol.

The [v1 risk register](ARCHITECTURE.md#146-legacy-v1-risk-register) maps these
findings to source evidence, tests, mitigations, and residual work.

Tests document these limits; passing tests do not resolve them. A new reviewed
format is required for complete stream authentication.

## Reporting a new vulnerability

Do not publish keys, plaintext, credentials, customer data, or sensitive exploit
details in public issues, pull requests, logs, or test fixtures.

1. Check the repository's [Security page](https://github.com/Hangell/cryptox/security).
   If **Report a vulnerability** is available, use that private reporting feature.
2. If private reporting is unavailable, open an issue requesting a confidential
   reporting channel without disclosing vulnerability details. Wait for the
   maintainer to establish a private channel before sharing sensitive information.
3. In the private report, include the affected revision, Go version, operating
   system, relevant API, impact, assumptions, and a minimal reproduction using
   synthetic data. Explain whether the issue differs from the limitations above.

This policy does not assert that GitHub private reporting is enabled. No response
SLA, bounty, or guaranteed remediation date is established. Disclosure timing
should be coordinated privately with the maintainer.

## Changes and releases

Changes to algorithms, nonces, derivation, serialization, state machines, or
cryptographic formats require a specific security review. Do not silently assign
new guarantees to legacy ciphertext or introduce insecure fallback paths.

Document findings, affected scope, mitigations, residual risks, and verification
before declaring a security fix complete. Release gates, independent review,
SBOM, signing, and provenance requirements are tracked in [ROADMAP.md](ROADMAP.md);
their presence in the plan does not mean they have been implemented.

The [CI configuration](.github/workflows/ci.yml) includes tests, race detection,
static analysis, fuzzing, and vulnerability scanning. A successful scan only
addresses its database and analysis scope, not every cryptographic design flaw.
Check the actual run for the relevant commit before claiming remote validation.

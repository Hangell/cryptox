# Security Policy

## Current security status

CryptoX is under development. No independently audited, production-ready release
or supported security-maintenance window is declared by this policy.

The current `stream` implementation uses the legacy v1 file format. It must not be
used where whole-file integrity is required. Planned guarantees in
[ARCHITECTURE.md](ARCHITECTURE.md) are not guarantees of the current implementation.

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

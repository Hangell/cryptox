# Security Policy

## Current security status

CryptoX is under development. No independently audited, production-ready release
or supported security-maintenance window is declared by this policy.

The `stream` package provides the legacy v1 file format (reader and writer,
retained only for migration) and the v2 stream format (implemented, but
experimental and not yet independently reviewed). The v1 format must not be used
where whole-file integrity is required. Planned guarantees in
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

V2 format (implemented and publicly exposed, experimental): the replacement
format selected in
[ADR 0002](docs/adr/0002-streaming-construction-selection.md) and specified in
[docs/security/v2-streaming-design-review.md](docs/security/v2-streaming-design-review.md)
derives an independent per-stream key from a 312-bit randomizer (32-byte salt +
7-byte nonce prefix) via HKDF. It therefore does not rely on a 64-bit nonce
prefix under a caller-reused key, as v1 does. The v2 streaming encrypt/decrypt
core is implemented and tested against truncation, reordering, duplication, and
modification. Its parameters have not yet received an independent specialist
review and the format is not frozen; treat v2 as experimental and do not
attribute to it guarantees beyond those demonstrated by tests. The v1 risks
below remain for legacy ciphertext.

## Known limitations

- Each chunk is authenticated independently. Removing complete trailing chunks
  can go undetected because the format has no authenticated termination record.
- Headers are structurally validated but not fully authenticated as associated data.
- Empty files have no authentication tag and cannot authenticate the supplied key.
- The random nonce prefix is 64 bits. Reusing a key across files risks prefix
  collisions; use a fresh key per file. The API does not enforce this policy.
- Counter exhaustion is checked within each file, but this does not prevent
  collisions between files encrypted under the same key.
- `ValidateHeader` checks the header only, not ciphertext integrity (the
  `ValidateEncryptedFile` name is a deprecated alias).
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
details in public issues, pull requests, logs, or test fixtures. Never post a
proof-of-concept publicly.

Use a confidential channel, in this order:

1. GitHub Security Advisory / Private Vulnerability Reporting at
   <https://github.com/Hangell/cryptox/security/advisories/new>. If the
   **Report a vulnerability** button is not visible, the maintainer enables it
   in Settings → Code security and analysis → Private vulnerability reporting.
2. Email the maintainer at **rodrigo@hangell.org** with the subject
   `[CryptoX security]`. This channel is always available and is the documented
   fallback, not conditional on GitHub settings.

In the report include the affected revision, Go version, operating system,
relevant API, impact, assumptions, and a minimal reproduction using synthetic
data. State whether the issue differs from the limitations above.

Triage and remediation (best-effort, no SLA, no bounty):

1. Acknowledge the report privately within 7 days.
2. Assess severity (CVSS) and confirm scope with the reporter.
3. Prepare the fix in a private branch or GitHub security advisory.
4. Publish the advisory and credit the reporter after the fix is released.

Supported versions: no releases are published yet. Once releases exist, only the
latest stable release line is supported.

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

## Release procedure

A release is published only from an annotated `v*` tag whose commit is on
`main`. The [release workflow](.github/workflows/release.yml) then, in order:

1. Verifies the tag points at a commit on `main`.
2. Builds with `-trimpath` and runs `go test -race ./...`; artifacts are not
   produced if tests fail.
3. Creates a source archive with `git archive` and a `sha256` checksum file.
4. Generates an SPDX SBOM for the repository.
5. Attaches a SLSA build-provenance attestation to the archive and checksums.
6. Publishes the archive, checksums, and SBOM to the GitHub Release.

Verification:

- Checksums: `sha256sum -c checksums.txt` inside the release assets directory.
- Provenance: `gh attestation verify --repo Hangell/cryptox dist/cryptox-*.tar.gz`.
- Dependency inventory: the published `cryptox.spdx.json`.

Release actions are pinned to immutable commit SHAs and the workflow runs with
least-privilege permissions (`contents: write`, `attestations: write`,
`id-token: write`). The source archive is the canonical release artifact; Go
module resolution uses the repository at the tag directly. No release is a
claim of production readiness or independent review.


# Changelog

All notable changes to CryptoX are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) per
[docs/versioning.md](docs/versioning.md).

## Unreleased

### Added

- `aead`: AES-256-GCM one-shot API with opaque `Key`, internal nonce generation,
  and Wycheproof conformance vectors.
- `keys`: validated AES key generation and HKDF-SHA-256 derivation with
  `Purpose` domain separation.
- `stream`: v2 authenticated streaming format (`CXS2`) with `io.Reader` /
  `io.WriteCloser` APIs and file adapters.
- `envelope`: Envelope v1 (`CXE1`) versioned encrypted-object container.
- Error sentinels per package (`errors.Is`-classifiable) in `aead`, `keys`,
  `envelope`, and `stream`.
- CI: multi-platform build/test, race detector, golangci-lint, fuzzing, release
  workflow with SBOM and provenance.

### Changed

- Replaced the legacy `SYM1` streaming implementation with the v2 format;
  `ValidateEncryptedFile` is deprecated in favor of `ValidateHeader`.

### Deprecated

- Legacy `SYM1` stream format: no migration; decrypt with an old build and
  re-encrypt.

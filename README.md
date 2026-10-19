# CryptoX

**A modular cryptographic SDK for Go — under development.**

[English](README.md) · [Português (Brasil)](README.pt-BR.md) · [简体中文](README.zh-CN.md) · [हिन्दी](README.hi.md) · [Русский](README.ru.md)

CryptoX is evolving from a file-encryption utility into a general-purpose cryptographic toolkit. The goal is reusable, auditable components for encryption, key management, encrypted storage, identity, and integrations with established E2EE protocols, independent of cloud vendors, transports, databases, and application frameworks.

> **Current status:** the code implements random AES key generation and legacy v1 file encryption. The v1 format authenticates individual chunks, **not the complete file**. It cannot detect removal of trailing chunks. Do not use this implementation where whole-file integrity is required. No independent security audit or production-readiness claim is made.

## Why explore CryptoX?

- **Focused packages:** import `keys` and `stream` directly; applications do not need a generic utilities package.
- **Bounded memory:** file processing uses chunks of up to 64 KiB rather than loading the whole file into RAM.
- **Small dependency footprint:** the current library uses only Go's standard library, without CGO, mandatory services, or telemetry.
- **Explicit failure behavior:** malformed inputs and failed authentication return errors; file destinations are published only after the operation succeeds.
- **Verifiable engineering:** adversarial tests, fuzzing, race detection, static analysis, and a CI configuration are included.

Today, CryptoX is useful for evaluating the architecture, studying the existing format, and contributing to its modernization. Future targets include secure attachments, backups, offline storage, service communication, device identity, and E2EE integrations. These are intended use cases, not delivered end-to-end solutions. There are no verified performance comparisons or guarantees of superiority over other libraries.

## What exists today?

| Package | Available API | Behavior |
| --- | --- | --- |
| `keys` | `GenerateKey(size int) ([]byte, error)` | Generates 16-, 24-, or 32-byte AES keys using `crypto/rand`. |
| `keys` | `DeriveKey(root []byte, purpose Purpose, length int) ([]byte, error)` | HKDF-SHA-256 derivation with mandatory purpose-based domain separation. |
| `aead` | `Seal` / `Open`, `GenerateKey`, `NewKey` | AES-256-GCM authenticated encryption; fresh nonce per `Seal`; `ErrAuthentication` with no plaintext on failure. |
| `stream` | `EncryptLargeFiles` / `DecryptLargeFiles` | Legacy v1 file format: per-chunk authentication only, no whole-file integrity. |
| `stream` | `NewEncryptor` / `NewDecryptor`, `EncryptFileV2` / `DecryptFileV2` | v2 stream format with authenticated termination; rejects truncation, reordering, and duplication. |
| `stream` | `ValidateHeader(filename string) error` | Checks the header only. It does **not** verify ciphertext or tags. `ValidateEncryptedFile` is a deprecated alias. |
| `envelope` | `Seal` / `Open` | Envelope v1 versioned encrypted-object container (see `docs/spec/envelope-v1.md`). |
| `utils` | The same legacy functions | Deprecated compatibility facade delegating to `keys` and `stream`. |

The public APIs now cover AEAD, HKDF derivation, the v2 streaming format (via `io.Reader`/`io.Writer` and file adapters), and Envelope v1. The v2 stream format and Envelope v1 are specified and tested, but their parameters await independent cryptographic review and a format freeze, so treat them as experimental. Still **not implemented**: secure storage, identities, E2EE session/ratchet adapters, replay protection, mobile bindings, and post-quantum support.

The source declares Go 1.26 as its minimum compatibility level. Use a maintained Go toolchain for development and deployment; minimum source compatibility is not a security recommendation. The library core does not require CGO, but `go test -race` requires a supported platform and C toolchain.

## Installation

### Use the local checkout

To try exactly the implementation described here, point a separate demo module at your CryptoX checkout. Replace `/absolute/path/to/cryptox` with its actual absolute path:

```sh
mkdir cryptox-demo
cd cryptox-demo
go mod init example.com/cryptox-demo
go mod edit -require=github.com/Hangell/cryptox@v0.0.0
go mod edit -replace=github.com/Hangell/cryptox=/absolute/path/to/cryptox
```

Here, `v0.0.0` is only a local module requirement placeholder; it is not a published release claim. The `replace` directive makes Go use your local files.

### Use the remote module

Inside an existing Go module:

```sh
go get github.com/Hangell/cryptox
```

This downloads the repository version available remotely, **not unpublished local changes**. Confirm that your selected revision contains `keys` and `stream`; package layout and formats may change during modernization. No stable release or current remote CI result is asserted here.

## Example: generate a key, encrypt, validate the header, and decrypt

Save the following as `main.go` in `cryptox-demo`, then run `go run .`:

```go
package main

import (
    "bytes"
    "fmt"
    "log"
    "os"
    "path/filepath"

    "github.com/Hangell/cryptox/keys"
    "github.com/Hangell/cryptox/stream"
)

func main() {
    if err := run(); err != nil {
        log.Fatal(err)
    }
}

func run() error {
    // Use disposable data: the v1 format lacks whole-file integrity.
    dir, err := os.MkdirTemp("", "cryptox-demo-*")
    if err != nil {
        return err
    }
    defer os.RemoveAll(dir)

    input := filepath.Join(dir, "message.txt")
    encrypted := filepath.Join(dir, "message.enc")
    restored := filepath.Join(dir, "restored.txt")
    original := []byte("Hello from CryptoX!\n")
    if err := os.WriteFile(input, original, 0o600); err != nil {
        return err
    }

    // Generate a fresh AES-256 key for this file. Never log it.
    key, err := keys.GenerateKey(32)
    if err != nil {
        return err
    }
    if err := stream.EncryptLargeFiles(input, encrypted, key); err != nil {
        return err
    }
    // This checks the header only, not ciphertext integrity.
    if err := stream.ValidateHeader(encrypted); err != nil {
        return err
    }
    if err := stream.DecryptLargeFiles(encrypted, restored, key); err != nil {
        return err
    }
    recovered, err := os.ReadFile(restored)
    if err != nil {
        return err
    }
    // This comparison checks the demo, not the v1 format's security.
    if !bytes.Equal(original, recovered) {
        return fmt.Errorf("round-trip mismatch")
    }
    fmt.Println("Round trip OK")
    return nil
}
```

Expected output: `Round trip OK`. The example uses disposable files and removes them afterward. Only the demonstration reads the complete small plaintext to compare it; the library processes files incrementally.

The key remains in memory for this single run. For persistent data, the application must securely retain and recover the key separately; CryptoX currently provides no key store. Losing the key loses access to the data. Never print or commit keys, and do not use passwords directly as AES keys. Password derivation is not implemented. Use a fresh key per v1 file; the API does not enforce this policy.

Existing consumers can still import `github.com/Hangell/cryptox/utils` and call the same function names. New code should use the focused packages. This describes current compatibility, not a promise that legacy APIs will survive future modernization.

## Security boundaries and the legacy format

```text
Header (21 bytes): "SYM1" | version=1 | "AESG" | base nonce (12 bytes)
Record: ciphertext length (uint32 LE) | ciphertext | GCM tag (16 bytes)
Nonce: random prefix (8 bytes) | chunk counter (uint32 LE)
```

The length field includes the GCM tag. The last four nonce bytes in the header must be zero; each record uses its sequential counter. Counters are rejected before exceeding `uint32`, preventing wraparound within a file.

- **Incomplete-file acceptance:** removing complete trailing records can succeed silently. An empty file has no authentication tag and cannot authenticate the key.
- **Incomplete metadata authentication:** the header is structurally checked but is not fully authenticated as associated data.
- **Nonce collisions across files:** the random prefix is only 64 bits. Reusing a key across files can lead to prefix collisions. A counter check does not eliminate this risk.
- **File publication:** unique temporary files are created in the destination directory with Unix mode `0600`; data is synced and the file closed before rename. On failure, cleanup is attempted and the destination is not intentionally replaced. Successful operations can replace an existing output; create the parent directory first and choose paths carefully.
- **Operating-system limits:** use a trusted destination directory. Windows requires appropriate ACLs; rename atomicity depends on the OS/filesystem. The directory is not synced, so crash durability is not guaranteed. A process crash can leave temporary files behind.
- **Secret and threat limits:** Go does not guarantee immediate memory erasure. This code does not protect against a compromised process/OS, storage rollback, replay, or metadata analysis, and is not an E2EE protocol.

AES-GCM alone does not make a file format secure. The replacement format must explicitly authenticate metadata and termination and receive appropriate review; these properties cannot be retroactively attributed to v1.

## Architecture and direction

The design follows modular and hexagonal principles: consumers use focused packages; optional adapters depend on core contracts; the core remains independent of infrastructure. Interfaces are introduced at real boundaries, not for every function.

| Planned component | Responsibility |
| --- | --- |
| `aead` | ✅ Implemented — authenticated encryption and managed nonces (AES-256-GCM). |
| `keys` expansion | Partially implemented — derivation and purpose separation exist; lifecycle and storage integration remain. |
| `stream` replacement | ✅ v2 implemented — authenticated framing, metadata, ordering, and termination; v1 retained only as a legacy reader. |
| `envelope` | ✅ Implemented — Envelope v1 versioned encrypted-object container. |
| `securestorage` | Encrypted state and optional persistence adapters. |
| `identity` / `pki` | Device identity, signatures, credentials, certificates, and trust validation. |
| `e2ee` | Adapters for established session/group protocols, selected through review. |

Candidate technologies in the architecture include ChaCha20-Poly1305, HKDF, X25519, Ed25519, Argon2id, MLS, and reviewed post-quantum mechanisms. They are evaluation candidates, not installed capabilities or a custom protocol recipe. CryptoX will not implement messaging servers, user registration, queues, push delivery, or cloud orchestration.

## Roadmap

The detailed [ROADMAP.md](ROADMAP.md) defines acceptance gates and these planning targets:

| Phase | Target | Goal |
| --- | --- | --- |
| 0 | v0.1.0 | Security diagnosis and architecture baseline. |
| 1 | v0.2.0 | Cryptographic foundation and engineering controls. |
| 2 | v0.3.0 | Secure streaming and envelopes. |
| 3 | v0.4.0 | Key management and secure storage. |
| 4 | v0.5.0 | Identity and device security. |
| 5 | v0.6.0 | Established E2EE protocol integration. |
| 6 | v0.7.0 | Cross-platform and mobile integration. |
| 7 | v0.9.0 | Hardening and independent review. |
| 8 | v1.0.0 | Validated stable cryptographic core. |
| 9 | v1.x / v2.x | Advanced cryptography and ecosystem. |

These are neither published releases nor delivery dates. Existing code and tests do not establish completion of any phase. Encrypted format **v1** is separate from Go module/release **v1.0.0**. The current modernization policy permits documented breaking changes; E2EE and mobile capabilities may remain experimental even after a stable core release.

## Tests and CI

Run from the CryptoX repository. The first block uses Make; the second provides direct commands, including vulnerability analysis:

```sh
make check
make fuzz
```

```sh
go vet ./...
go test -race -count=1 -coverpkg=./... -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
go test ./stream -run='^$' -fuzz=FuzzDecryptV1 -fuzztime=30s -parallel=2
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

Tests cover the four `utils` functions, AES key lengths, chunk boundaries, wrong keys, malformed headers/lengths, modified/reordered chunks, fragmented reads, short writes, error propagation, temporary-file cleanup, and destination preservation. Parallel cases use independent files. Tests also explicitly record the v1 truncation limitation. Fuzzing checks failure invariants, not just absence of panics.

The [CI workflow](.github/workflows/ci.yml) is configured for pushes, pull requests, manual runs, and weekly runs. It defines Linux/Windows/macOS jobs with Go `stable`, an additional Linux job with `oldstable`, coverage and JSON artifacts, fuzzing, and `govulncheck`. Configuration is not proof of remote success: inspect the run for your commit. Coverage and passing tests do not replace independent cryptographic review.

## Project documentation and contribution

The three primary engineering documents are:

- [AGENTS.md](AGENTS.md): mission, mandatory engineering rules, and acceptance criteria.
- [ARCHITECTURE.md](ARCHITECTURE.md): target modules, contracts, trust boundaries, and threat model.
- [ROADMAP.md](ROADMAP.md): priorities, dependencies, milestones, and release gates.

[CONTRIBUTING.md](CONTRIBUTING.md) describes contribution checks. [THREAT_MODEL.md](THREAT_MODEL.md) links to the maintained threat model in the architecture document. [SECURITY.md](SECURITY.md) documents current limitations and the vulnerability reporting procedure. Use the GitHub security advisory path (`security/advisories/new`) when private reporting is enabled; the documented fallback is emailing the maintainer at `rodrigo@hangell.org` with subject `[CryptoX security]`. The policy does not establish a response SLA. Never post secrets or sensitive exploit details publicly.

Contribute small, reviewable changes: inspect the implementation, add regression/adversarial tests before critical fixes, run the checks, and document security assumptions and API/format changes. Use English identifiers and code comments, and Conventional Commits explaining why. Keep all five README translations aligned when behavior changes.

## License

[MIT](LICENSE) — Copyright (c) 2025 Rodrigo Rangel.

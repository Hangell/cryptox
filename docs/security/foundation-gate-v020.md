# v0.2.0 foundation gate (P1.26)

This record closes the Phase 1 gate ("fundação criptográfica revisada, testada
e suficientemente estável para receber módulos superiores"). It consolidates the
evidence of the Phase 1 cards; it does **not** publish a release tag.

**Status:** ready — no known blockers in the Phase 1 scope.

## Requirement → test → review matrix

| Requirement | Implementation | Tests / evidence | Review |
|---|---|---|---|
| AES-256-GCM wrapper over a reviewed implementation | `aead/aead.go` (stdlib `crypto/aes` + `crypto/cipher`) | `aead/aead_test.go`, `aead/wycheproof_test.go` (curated AES-256-GCM), `aead/fuzz_test.go` | Issue #19; P1.25 cross-validation |
| No caller-managed nonces | `aead.Seal` generates 96-bit nonce internally; `stream` generates salt+prefix | `aead_test.go`, `stream/v2api_test.go` | P1.09 contracts doc |
| Validated key generation | `keys/keys.go`, `aead.GenerateKey` | `keys/keys_test.go`, `aead_test.go` | P1.03 |
| HKDF-SHA-256 derivation | `keys/derivation.go` (local RFC 5869 over `crypto/hmac`) | `keys/derivation_test.go` (RFC 5869 A.1–A.3), `keys/wycheproof_hkdf_test.go` | P1.04, P1.25 |
| Key-purpose separation | `keys.Purpose` domain separation | `keys/derivation_test.go` `TestDeriveKeyDomainSeparation` | P1.05 |
| Key/nonce usage limits | `aead` 2^32 Seal bound; `stream` 2^32 segment counter (`checkCounter`) | `stream/v2_test.go`, `aead` package doc | P1.08; per-key bound remains open (see below) |
| Reject invalid key sizes | `aead.NewKey`, `keys.GenerateKey`, `stream.NewEncryptor`, `envelope.Seal` | per-module rejection tests | P1.11 |
| Prevent insecure algorithm configuration | `stream.parseV2Header`, `envelope.parse` reject unknown version/suite; no mutable registry | `TestV2ErrorClassification`, `TestV2HeaderTamperDetected`, `TestOpenRejectsStructuralTampering` | P1.10 |
| Safe error types | `errors.Is`-classifiable sentinels in `aead`, `keys`, `envelope`, `stream` | per-module classification tests | P1.13; contracts doc |
| Minimal explicit APIs | one-shot / stream / file adapters; no generic cipher interface | `docs/security/public-api-contracts.md` | P1.09 |
| Document concurrency guarantees | `aead` concurrent-safe; `stream` not concurrent | package docs | P1.14 |
| No global mutable state | none present | grep audit during P1.15 | P1.15 |
| Formatting / vet / lint / race | CI matrix + race detector + golangci-lint + `go vet` | `.github/workflows/ci.yml` | P1.17–P1.19 |
| Unit tests and coverage | full `go test` suite; coverage in CI | CI artifact | P1.20 |
| Cryptographic test vectors | Wycheproof AES-256-GCM, HKDF-SHA-256; RFC 5869 vectors; golden files | `*_test.go` + `testdata/` | P1.21, P1.25 |
| Fuzzing | in-process fuzz tests + scheduled CI campaign | `*_fuzz_test.go`, `.github/workflows/fuzz.yml` | P1.22 |
| Dependency checks | `govulncheck` in CI; zero external deps | `.github/workflows/ci.yml` | P1.23 |
| Release/versioning conventions | `docs/versioning.md`, `CHANGELOG.md` | — | P1.24 |
| ChaCha20-Poly1305 decision | deferred to future suite | ADR 0003 | P1.02 |

## Dependencies

| Dependency | Status |
|---|---|
| #18 (P1.02 ChaCha decision) | review — ADR 0003 merged (PR #52) |
| #22 (P1.09 minimal APIs) | review — contracts doc merged (PR #50) |
| #24 (P1.13 error types) | review — sentinels merged (PR #51) |
| #15 (P1.24 versioning) | review — policy merged (PR #53) |
| #73 (P1.25 AEAD+HKDF validation) | review — Wycheproof/RFC 5869 validation merged (PR #46) |

All implemented Phase 1 components are reused as-is; none were reworked for this
gate.

## Residual limitations (documented, non-blocking)

- **No validated per-key usage bound.** The 2^48-byte limit is per-stream; a
  concrete HS20 multi-user/multi-key bound remains an open specialist item
  (design review §8, ADR 0002).
- **ChaCha20-Poly1305 is deferred** (ADR 0003), so the foundation exposes one
  AEAD suite.
- **Envelope is not yet in the scheduled fuzz matrix** (tracked as P2.31 / #76).
- **Legacy `SYM1` has no migration reader**: decrypt with an old build and
  re-encrypt (versioning policy §8).

## Readiness

The Phase 1 foundation is sufficiently reviewed and tested to receive the
Phase 2 modules. No release tag is published by this record; tagging happens
only through the release workflow once the maintainer chooses a version.

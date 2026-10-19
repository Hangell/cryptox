# Versioning and release policy

This policy governs how CryptoX versions its Go module, its wire formats, and
its releases. It implements the compatibility principles in
[ARCHITECTURE.md §20](../ARCHITECTURE.md#20-versioning-and-compatibility).

## 1. Two independent version axes

CryptoX versions **two things separately**, and they must not be conflated:

| Axis | What it versions | Examples |
|---|---|---|
| Go module (SemVer) | The public Go API and release artifacts | `v0.2.0`, `v0.3.0`, `v1.0.0` |
| Wire/format identifiers | The binary layout of encrypted data | `SYM1` (legacy), `CXS2` (stream v2), `CXE1` (Envelope v1) |

A module release does **not** imply a change to the wire formats, and a wire
format change does **not** by itself imply a module major bump. In particular:

- The legacy **v1 stream format `SYM1`** is unrelated to a hypothetical
  **module release `v1.0.0`**. Do not confuse them: `SYM1` is deprecated and
  will never be promoted to the guarantees of `CXS2`.

## 2. Module versioning (SemVer)

- Before `v1.0.0`, the module is `v0` and **does not** promise API stability:
  breaking changes may land in any `v0.x` release. `v0.x.y` bumps `x` for
  features and `y` for fixes; `x` bumps do not imply compatibility.
- From `v1.0.0` onward:
  - **Major** (`vN`): breaking public API or persisted-format changes.
  - **Minor** (`vN.M`): additive, backward-compatible changes.
  - **Patch** (`vN.M.P`): backward-compatible fixes (including security fixes).
- A change that breaks callers or persisted data **requires** a major bump
  after `v1.0.0`, with a documented migration path or an explicit statement
  that no migration exists.

## 3. Wire-format versioning

Wire formats carry their own explicit identifiers (`SYM1`, `CXS2`, `CXE1`),
including version and suite fields. Rules:

- A format change is a new identifier or a new version/suite, never a silent
  change to an existing identifier.
- Unknown versions and suites are **rejected**, never downgraded or
  reinterpreted (see ADR 0002, ADR 0003).
- Legacy formats with known flaws are documented as such and are never
  promoted to new guarantees.

## 4. Minimum Go and supported platforms

- The minimum Go version is the `go` directive in [go.mod](../go.mod)
  (currently `go 1.26`).
- Supported platforms are those covered by CI: Linux, macOS, and Windows on
  `amd64`/`arm64` as exercised by the matrix in
  [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).
- The core is CGO-free and has zero external dependencies.

## 5. Support window

- The two most recent minor releases receive security and critical bug fixes.
- Older minor releases require an upgrade; no backports are promised beyond the
  window.
- Pre-release (`v0`) minor versions are supported only until the next minor.

## 6. Release tags

- Release tags use the form `vX.Y.Z` (SemVer, no leading `v` is ever omitted).
- The release workflow
  ([`.github/workflows/release.yml`](../.github/workflows/release.yml))
  **only publishes from a tag that is an ancestor of `main`**, and it builds,
  runs the full test suite with the race detector, and emits a source archive,
  checksums, an SPDX SBOM, and build-provenance attestations.
- Tag creation is restricted to maintainers (enable tag protection in the
  repository settings); CI refuses any `v*` tag not on `main`.

## 7. Changelog

- Every release has an entry in [CHANGELOG.md](../CHANGELOG.md).
- Commits use Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`), so the
  changelog can be generated per release and breaking changes are flagged.
- Security fixes are listed with the advisory reference when one exists.

## 8. Deprecation and migration

- Deprecated public APIs are marked `Deprecated:` in GoDoc and kept for at
  least one minor release after deprecation; removal happens only in the next
  major.
- Persisted-format changes after `v1.0.0` require either a documented migration
  path or an explicit, user-visible statement that migration is unavailable.
- The legacy `SYM1` format is deprecated with **no migration implementation**:
  callers must decrypt with an old build and re-encrypt. This is intentional
  and will not change silently. See ADR 0004 and
  [docs/security/v1-migration.md](../docs/security/v1-migration.md) for the
  explicit migration path and its integrity caveats.

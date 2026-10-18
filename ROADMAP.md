# CryptoX — Development Roadmap

> **Project:** CryptoX
> **Repository:** https://github.com/Hangell/cryptox
> **Primary Language:** Go
> **Architecture:** Modular, Hexagonal, Security-First
> **Status:** Phase 0 in progress
> **Current Target:** v1.0.0 — Stable Cryptographic Core

---

## 1. Purpose

This document defines the development strategy, milestones, priorities, dependencies, acceptance criteria, and release goals for CryptoX.

CryptoX aims to evolve from a file encryption utility into a modular, general-purpose, security-first cryptographic SDK.

The library must support secure cryptographic integration across multiple application domains, including:

- File encryption and secure streaming.
- Encrypted storage and backups.
- Key generation and management.
- Cryptographic identity.
- Secure communication between systems.
- End-to-end encrypted messaging.
- Multi-device security.
- Future integration with post-quantum cryptographic protocols.

CryptoX must remain independent of application frameworks, database engines, network transports, and cloud providers.

The roadmap follows the architecture defined in `ARCHITECTURE.md` and the engineering rules established in `AGENTS.md`.

**Security and correctness take precedence over delivery speed, feature quantity, and performance optimization.**

---

## 2. Project Constraints

### 2.1 No production consumers

CryptoX currently has no known production consumers.

Therefore, the project may:

- Replace its existing architecture.
- Remove obsolete APIs.
- Rename public packages.
- Replace serialization formats.
- Remove legacy cryptographic implementations.
- Change internal contracts.
- Reorganize its module structure.
- Introduce breaking changes.

Backward compatibility is not required during the initial modernization.

However, all significant changes must be documented.

### 2.2 Primary language

Go is the primary development language.

Rust is not required.

Native libraries written in other languages may be evaluated when they provide established, reviewed cryptographic protocols that would be inappropriate to implement from scratch.

### 2.3 Scope boundaries

CryptoX is a cryptographic SDK.

It must not become a messaging server, authentication platform, database framework, or cloud infrastructure solution.

Its responsibilities end at clearly defined cryptographic and integration boundaries.

---

## 3. Roadmap Overview

| Phase | Milestone | Priority | Target |
|---|---|---|---|
| 0 | Security Audit & Architecture Baseline | Critical | v0.1.0 |
| 1 | Cryptographic Foundation | Critical | v0.2.0 |
| 2 | Secure Streaming & Envelope | Critical | v0.3.0 |
| 3 | Key Management & Secure Storage | High | v0.4.0 |
| 4 | Identity & Device Security | High | v0.5.0 |
| 5 | E2EE Protocol Integration | High | v0.6.0 |
| 6 | Cross-Platform Integration | Medium | v0.7.0 |
| 7 | Security Hardening & External Review | Critical | v0.9.0 |
| 8 | Stable Cryptographic Core Release | Critical | v1.0.0 |
| 9 | Advanced Cryptography & Ecosystem | Future | v1.x / v2.x |

Version targets are planning milestones, not promised release dates.

No milestone may advance merely because its planned development tasks are complete.

Each phase requires validation against its security acceptance criteria.

---

# Phase 0 — Security Audit & Architecture Baseline

**Target:** v0.1.0
**Priority:** Critical
**Status:** In progress

## Objective

Understand the existing CryptoX implementation, identify security weaknesses, and establish a validated architectural baseline.

This phase must be completed before broad refactoring.

## Tasks

- [x] Inventory existing packages, exported functions, and dependencies.
- [ ] Review the current AES-GCM implementation.
- [ ] Analyze nonce generation and counter management.
- [ ] Evaluate encrypted file framing.
- [ ] Verify chunk authentication and ordering.
- [ ] Investigate truncation and replay risks.
- [ ] Review file creation permissions and temporary file handling.
- [ ] Inspect error handling and malformed-input behavior.
- [x] Review existing tests and benchmarks.
- [x] Verify README claims against actual implementation.
- [ ] Identify reusable code and components requiring replacement.
- [ ] Establish the initial threat model.
- [ ] Identify trust boundaries.
- [ ] Define supported and unsupported security guarantees.
- [ ] Confirm the target package structure.
- [x] Document significant architecture decisions.

## Deliverables

- Verified implementation inventory.
- Prioritized security findings.
- Initial threat model in `ARCHITECTURE.md`.
- Validated architecture baseline.
- Initial Architecture Decision Records.
- Updated development backlog.

## Acceptance criteria

- [ ] Critical implementation risks are documented.
- [ ] Existing security assumptions are understood.
- [ ] No unsupported security claims remain in public documentation.
- [ ] The target architecture is approved.
- [ ] Phase 1 requirements are clearly defined.

**Exit gate:** Security and architecture review completed.

---

# Phase 1 — Cryptographic Foundation

**Target:** v0.2.0
**Priority:** Critical
**Status:** Not started

## Objective

Establish a reliable cryptographic foundation with secure public APIs, validated primitives, and strong automated testing.

## Tasks

### Cryptographic primitives

- [ ] Implement or wrap AES-256-GCM using a reviewed implementation.
- [ ] Evaluate ChaCha20-Poly1305 support.
- [ ] Implement validated key generation.
- [ ] Implement HKDF-based key derivation.
- [ ] Establish explicit key-purpose separation.
- [ ] Define authenticated metadata handling.
- [ ] Define safe nonce management.
- [ ] Define limits for key and nonce usage.

### Public APIs

- [ ] Design minimal, explicit APIs.
- [ ] Prevent insecure algorithm configuration.
- [ ] Reject invalid key sizes.
- [ ] Avoid caller-managed nonces in high-level APIs.
- [ ] Define safe error types.
- [ ] Document concurrency guarantees.
- [ ] Eliminate unnecessary global mutable state.

### Engineering foundation

- [ ] Establish Go package conventions.
- [ ] Configure formatting and linting.
- [ ] Configure `go vet`.
- [ ] Configure race testing.
- [ ] Add unit tests.
- [ ] Add cryptographic test vectors.
- [ ] Add fuzz tests for untrusted inputs.
- [ ] Add automated dependency checks.
- [ ] Establish release and versioning conventions.

## Deliverables

- AEAD module.
- Key generation utilities.
- HKDF integration.
- Public API conventions.
- Automated CI security checks.
- Initial test vector suite.
- Documented cryptographic policies.

## Acceptance criteria

- [ ] Implementations use recognized cryptographic primitives.
- [ ] Invalid inputs fail safely.
- [ ] Authentication failures never return plaintext.
- [ ] Key-and-nonce reuse is prevented by high-level APIs under documented assumptions.
- [ ] Cryptographic test vectors pass.
- [ ] Fuzzing infrastructure is functional.
- [ ] Security assumptions are documented.
- [ ] API design has undergone security review.

**Exit gate:** Cryptographic foundation verified.

---

# Phase 2 — Secure Streaming & Envelope

**Target:** v0.3.0
**Priority:** Critical
**Status:** Not started

## Objective

Deliver secure, authenticated, memory-efficient encryption for files and streams.

This phase replaces the legacy file encryption format with a newly specified, versioned format.

## Tasks

### Streaming

- [ ] Define a new authenticated streaming specification.
- [ ] Implement streaming encryption.
- [ ] Implement streaming decryption.
- [ ] Support bounded-memory processing.
- [ ] Authenticate stream headers.
- [ ] Authenticate security-relevant metadata.
- [ ] Bind chunk ordering cryptographically.
- [ ] Detect missing chunks.
- [ ] Detect reordered chunks.
- [ ] Detect truncated streams.
- [ ] Authenticate stream termination.
- [ ] Reject oversized length fields.
- [ ] Prevent counter overflow.
- [ ] Define maximum stream size.
- [ ] Handle partial reads and writes correctly.
- [ ] Ensure safe behavior under interrupted operations.

### File handling

- [ ] Use restrictive temporary file permissions.
- [ ] Avoid exposing partially decrypted output.
- [ ] Ensure safe cleanup after failures.
- [ ] Document atomicity guarantees and filesystem assumptions.
- [ ] Test disk-full and interrupted-write scenarios.
- [ ] Validate file destination and overwrite policies.

### Envelope

- [ ] Define versioned envelope structures.
- [ ] Define canonical serialization.
- [ ] Bind algorithm identifiers cryptographically.
- [ ] Reject unsupported versions.
- [ ] Reject malformed headers.
- [ ] Enforce explicit size limits.
- [ ] Document the binary format.

## Deliverables

- Secure streaming module.
- Secure envelope module.
- Versioned cryptographic file format.
- Streaming interoperability test vectors.
- File encryption examples.
- Updated documentation.

## Acceptance criteria

- [ ] Truncation is detected.
- [ ] Chunk reordering is detected.
- [ ] Unauthorized modification is detected.
- [ ] Missing finalization is detected.
- [ ] Counter overflow is rejected.
- [ ] Malformed files fail safely.
- [ ] Temporary file behavior is secure under documented filesystem assumptions.
- [ ] Memory consumption remains bounded for large files.
- [ ] All adversarial streaming tests pass.

**Exit gate:** Authenticated streaming implementation validated.

---

# Phase 3 — Key Management & Secure Storage

**Target:** v0.4.0
**Priority:** High
**Status:** Not started

## Objective

Provide secure abstractions for cryptographic key lifecycle and encrypted persistence.

## Tasks

### Key management

- [ ] Define cryptographic key representations.
- [ ] Implement key generation policies.
- [ ] Implement key identification.
- [ ] Implement key derivation contexts.
- [ ] Implement key-purpose separation.
- [ ] Define key lifecycle states.
- [ ] Define rotation mechanisms.
- [ ] Define controlled import/export.
- [ ] Document revocation limitations.
- [ ] Prevent accidental secret logging and serialization.

### Secure storage

- [ ] Define secure storage contracts.
- [ ] Implement encrypted record storage.
- [ ] Authenticate persistent state.
- [ ] Support versioned records.
- [ ] Define atomic write assumptions.
- [ ] Implement corruption detection.
- [ ] Document rollback limitations.
- [ ] Define storage migration mechanisms.
- [ ] Add integration tests for persistence failures.

### Platform integration contracts

- [ ] Define optional platform secure-storage interfaces.
- [ ] Evaluate Android Keystore integration.
- [ ] Evaluate Apple Keychain integration.
- [ ] Evaluate OS credential-store integration.
- [ ] Evaluate HSM integration requirements.

## Deliverables

- Key management module.
- Secure storage abstraction.
- Secure persistence implementation.
- Storage test suite.
- Key lifecycle documentation.
- Platform integration contracts.

## Acceptance criteria

- [ ] Keys are separated by purpose.
- [ ] Sensitive material is not exposed through normal diagnostics.
- [ ] Corrupted records are rejected.
- [ ] Persistent state is authenticated.
- [ ] Recovery expectations are documented.
- [ ] Rollback protection limitations are explicit.
- [ ] Platform dependencies remain optional.

**Exit gate:** Key and storage lifecycle validated.

---

# Phase 4 — Identity & Device Security

**Target:** v0.5.0
**Priority:** High
**Status:** Not started

## Objective

Provide reusable cryptographic identity components suitable for secure communication and multi-device systems.

## Tasks

### Identity

- [ ] Define cryptographic identity models.
- [ ] Support device-specific identity keys.
- [ ] Implement public-key verification.
- [ ] Integrate reviewed digital signature implementations.
- [ ] Define key identifiers.
- [ ] Define credential representation.
- [ ] Validate identity-related serialization.

### Device lifecycle

- [ ] Define device authorization contracts.
- [ ] Define device revocation semantics.
- [ ] Define identity change handling.
- [ ] Support cryptographic verification workflows.
- [ ] Document key replacement security assumptions.

### Transparency

- [ ] Define interfaces for key transparency.
- [ ] Evaluate suitable append-only log constructions.
- [ ] Define verification requirements.
- [ ] Document consistency and split-view threats.

## Deliverables

- Identity module.
- Device identity abstractions.
- Verification APIs.
- Transparency integration contracts.
- Identity test vectors.
- Device lifecycle documentation.

## Acceptance criteria

- [ ] Identity verification uses recognized cryptographic mechanisms.
- [ ] Key substitution risks are explicitly addressed.
- [ ] Device authorization assumptions are documented.
- [ ] Identity formats are versioned.
- [ ] Invalid credentials are rejected.
- [ ] No unsupported identity trust claims are made.

**Exit gate:** Identity components validated.

---

# Phase 5 — E2EE Protocol Integration

**Target:** v0.6.0
**Priority:** High
**Status:** Not started

## Objective

Enable consuming applications to integrate established end-to-end encryption protocols through consistent CryptoX interfaces.

CryptoX must not invent a new messaging cryptographic protocol.

## Tasks

### Protocol selection

- [ ] Evaluate established individual-session protocols.
- [ ] Evaluate maintained protocol libraries.
- [ ] Review licensing compatibility.
- [ ] Review audit history.
- [ ] Evaluate mobile compatibility.
- [ ] Evaluate persistent state requirements.
- [ ] Produce protocol selection ADR.

### Session integration

- [ ] Define session interface contracts.
- [ ] Implement the selected protocol adapter.
- [ ] Support authenticated session establishment.
- [ ] Integrate secure session state storage.
- [ ] Define recovery from interrupted state updates.
- [ ] Handle out-of-order messages according to protocol guarantees.
- [ ] Handle replay attempts according to protocol guarantees.
- [ ] Document key change behavior.

### Multi-device integration

- [ ] Define device identity integration.
- [ ] Define per-device session behavior.
- [ ] Define state synchronization boundaries.
- [ ] Define device revocation behavior.
- [ ] Validate cross-device interoperability.

### Group E2EE

- [ ] Evaluate MLS integration.
- [ ] Review group-state persistence requirements.
- [ ] Define membership-change behavior.
- [ ] Define protocol version compatibility.
- [ ] Evaluate security implications of group recovery.

## Deliverables

- E2EE protocol selection ADR.
- Session integration APIs.
- Reviewed protocol adapter.
- E2EE interoperability tests.
- Multi-device integration contracts.
- Group protocol integration specification.

## Acceptance criteria

- [ ] No custom unreviewed messaging protocol is introduced.
- [ ] Protocol security assumptions are documented.
- [ ] Session interoperability tests pass.
- [ ] Invalid session states fail safely.
- [ ] Replay and ordering behavior matches the selected protocol.
- [ ] Persistence requirements are verified.
- [ ] Multi-device assumptions are explicit.
- [ ] Independent security review requirements are identified.

**Exit gate:** E2EE integration technically validated.

**Release restriction:** E2EE functionality remains experimental until the required independent security review and interoperability validation are completed.

---

# Phase 6 — Cross-Platform Integration

**Target:** v0.7.0
**Priority:** Medium
**Status:** Not started

## Objective

Validate CryptoX across supported systems and prepare secure integration mechanisms for mobile and desktop applications.

## Tasks

### Go platforms

- [ ] Validate Linux AMD64.
- [ ] Validate Linux ARM64.
- [ ] Validate Windows AMD64.
- [ ] Validate macOS ARM64.
- [ ] Validate macOS AMD64 where supported.

### Android

- [ ] Evaluate Go mobile bindings.
- [ ] Define Android integration contracts.
- [ ] Evaluate Android Keystore.
- [ ] Test device lifecycle behavior.
- [ ] Validate cryptographic state persistence.
- [ ] Test interruption and process termination scenarios.

### iOS

- [ ] Evaluate supported Go integration mechanisms.
- [ ] Define Swift-facing interfaces.
- [ ] Evaluate Keychain and Secure Enclave.
- [ ] Validate secret handling across language boundaries.
- [ ] Test process termination and state recovery.
- [ ] Validate interoperability with other platforms.

### Interoperability

- [ ] Share cryptographic test vectors across platforms.
- [ ] Verify deterministic format compatibility.
- [ ] Test malformed input handling across platforms.
- [ ] Compare behavior between implementations.
- [ ] Document supported integration models.

## Deliverables

- Cross-platform test matrix.
- Mobile integration prototypes.
- Platform security documentation.
- Shared interoperability vectors.
- Mobile integration decision ADR.

## Acceptance criteria

- [ ] Core functionality passes tests on supported targets.
- [ ] Cross-platform ciphertext interoperability is verified.
- [ ] Platform-specific limitations are documented.
- [ ] Secret handling across FFI boundaries is reviewed.
- [ ] No unsupported platform security guarantees are made.

**Exit gate:** Cross-platform compatibility validated.

---

# Phase 7 — Security Hardening & External Review

**Target:** v0.9.0
**Priority:** Critical
**Status:** Not started

## Objective

Prepare the intended stable release scope for independent security assessment.

## Tasks

### Security testing

- [ ] Run comprehensive unit and integration tests.
- [ ] Run fuzzing campaigns.
- [ ] Run race-condition detection.
- [ ] Run static analysis.
- [ ] Run dependency vulnerability analysis.
- [ ] Review public API misuse risks.
- [ ] Validate malformed-input resistance.
- [ ] Test key lifecycle edge cases.
- [ ] Test encrypted storage failures.
- [ ] Test streaming corruption scenarios.
- [ ] Validate protocol interoperability.

### Security governance

- [ ] Update the threat model.
- [ ] Review architectural decisions.
- [ ] Document residual risks.
- [ ] Prepare an external audit scope.
- [ ] Obtain independent security review for the intended stable components.
- [ ] Track findings and remediation.
- [ ] Reassess critical changes after remediation.
- [ ] Establish vulnerability disclosure procedures.

### Supply-chain security

- [ ] Review all dependencies.
- [ ] Generate an SBOM.
- [ ] Pin release dependencies appropriately.
- [ ] Establish release artifact integrity verification.
- [ ] Configure release provenance where practical.
- [ ] Protect release workflows.
- [ ] Review repository branch protection and permissions.

## Deliverables

- Security testing reports.
- Updated threat model.
- Security audit report or equivalent independent assessment.
- Remediation backlog.
- Release security checklist.
- Dependency inventory and SBOM.

## Acceptance criteria

- [ ] No known unresolved critical or high-severity vulnerability is accepted in the stable release scope without documented risk disposition and explicit release decision.
- [ ] Independent review findings have been addressed or appropriately scoped.
- [ ] Security claims correspond to tested capabilities.
- [ ] Release artifacts have integrity verification.
- [ ] Known limitations are documented.
- [ ] Relevant tests pass after remediation.

**Exit gate:** Stable release security review completed.

---

# Phase 8 — Stable Cryptographic Core Release

**Target:** v1.0.0
**Priority:** Critical
**Status:** Not started

## Objective

Publish a stable, documented, independently reviewed cryptographic core suitable for integration into security-sensitive applications within its documented threat model.

## Scope

The stable release must include validated components for:

- Authenticated encryption.
- Secure key generation.
- Key derivation.
- Secure streaming.
- Versioned encrypted envelopes.
- Core documentation.
- Test vectors.
- Security policy.
- Supported-platform matrix.

Additional modules may be included only if their security and compatibility criteria are satisfied.

**E2EE, identity, mobile bindings, and other advanced modules may remain experimental or be distributed separately.**

A stable core release must not be delayed merely to include every planned advanced feature.

## Tasks

- [ ] Freeze the intended stable API scope.
- [ ] Complete public API documentation.
- [ ] Publish format specifications.
- [ ] Finalize migration guidance.
- [ ] Publish supported platform information.
- [ ] Complete required security assessments.
- [ ] Validate release artifacts.
- [ ] Publish benchmark methodology.
- [ ] Update examples.
- [ ] Finalize `SECURITY.md`.
- [ ] Finalize `CONTRIBUTING.md`.
- [ ] Publish release notes.
- [ ] Tag the stable release.

## Acceptance criteria

- [ ] Stable API scope is explicitly defined.
- [ ] Public APIs are documented.
- [ ] Cryptographic formats are specified.
- [ ] Security properties and limitations are documented.
- [ ] All release-blocking findings are resolved.
- [ ] Required independent assessment is complete.
- [ ] Release builds pass the supported test matrix.
- [ ] Examples are functional.
- [ ] Versioning and release policies are established.

**Exit gate:** v1.0.0 approved for publication.

---

# Phase 9 — Advanced Cryptography & Ecosystem

**Target:** v1.x / v2.x
**Priority:** Future
**Status:** Not started

## Objective

Expand CryptoX beyond its stable core without weakening established security properties.

Potential initiatives:

### Post-quantum integration

- [ ] Evaluate standardized post-quantum mechanisms.
- [ ] Review maintained implementations.
- [ ] Evaluate hybrid key establishment protocols.
- [ ] Document interoperability and migration strategies.
- [ ] Avoid experimental protocol compositions in production.

### Advanced identity

- [ ] Extend key transparency integrations.
- [ ] Evaluate anonymous credentials.
- [ ] Evaluate privacy-preserving verification systems.
- [ ] Explore suitable credential revocation mechanisms.

### Enterprise integration

- [ ] Evaluate HSM adapters.
- [ ] Evaluate PKCS#11 integration.
- [ ] Evaluate enterprise key lifecycle requirements.
- [ ] Add optional compliance-oriented integrations.

### Developer ecosystem

- [ ] Create additional examples.
- [ ] Publish integration guides.
- [ ] Improve mobile bindings.
- [ ] Publish interoperability test suites.
- [ ] Establish long-term maintenance policies.
- [ ] Encourage independent implementations and external review.

Each advanced capability requires a separate security assessment and architecture decision.

---

# 4. Implementation Priority Rules

Development agents must prioritize work according to risk and dependency order.

## P0 — Security blockers

Examples:

- Cryptographic vulnerabilities.
- Authentication bypass.
- Nonce reuse.
- Unsafe plaintext exposure.
- Broken integrity verification.
- Secret leakage.
- Malformed-input vulnerabilities.
- Unsafe protocol downgrade.

P0 issues block affected releases.

## P1 — Core correctness

Examples:

- Incorrect serialization.
- Incomplete error handling.
- State corruption.
- Missing protocol validation.
- Unsafe concurrency.
- Broken test vectors.
- Incorrect key lifecycle behavior.

## P2 — Architecture and maintainability

Examples:

- Module decoupling.
- API consistency.
- Documentation.
- Testability.
- Dependency simplification.
- Developer experience.

## P3 — Performance and enhancements

Examples:

- Allocation optimization.
- Parallel processing.
- Additional adapters.
- Optional algorithms.
- Developer tooling.

Performance work must not precede unresolved security or correctness blockers.

---

# 5. Definition of Done

A task is complete only when:

- [ ] Implementation satisfies its documented requirements.
- [ ] Security assumptions are explicit.
- [ ] Relevant unit tests exist.
- [ ] Relevant negative tests exist.
- [ ] Cryptographic test vectors pass where applicable.
- [ ] Failure behavior is tested.
- [ ] Input validation is complete.
- [ ] Public APIs are documented.
- [ ] No unintended secret logging exists.
- [ ] No unsafe default is introduced.
- [ ] Relevant race tests pass.
- [ ] Relevant fuzz tests pass.
- [ ] Dependency changes are justified.
- [ ] Architecture documentation is updated when necessary.
- [ ] Known limitations are documented.

Do not equate successful compilation with task completion.

---

# 6. Release Policy

CryptoX releases must be evidence-based.

A release may be published only when:

1. Its scope is defined.
2. Its security properties are documented.
3. Its compatibility expectations are stated.
4. Its automated tests pass.
5. Its relevant security reviews are complete.
6. Its known limitations are recorded.
7. Its release artifacts can be verified.

Cryptographic format versions and Go module versions must be managed separately when necessary.

A new Go module version does not automatically require a new encrypted format version.

Similarly, a new encrypted format version does not necessarily require a major Go module release unless public API compatibility is affected.

---

# 7. Risk Management

The project must maintain an active security and engineering risk backlog.

Each significant risk should include:

- Identifier.
- Description.
- Affected component.
- Impact.
- Likelihood.
- Severity.
- Mitigation.
- Responsible owner.
- Status.
- Evidence or reference.

Security risks should be tracked through issues or security advisories according to disclosure sensitivity.

Avoid publishing exploitable details of unresolved vulnerabilities when doing so would unnecessarily expose users.

---

# 8. Development Agent Workflow

All agents contributing to CryptoX must follow this workflow:

1. Read `AGENTS.md`.
2. Read `ARCHITECTURE.md`.
3. Read `ROADMAP.md`.
4. Inspect the actual relevant source code.
5. Identify the current milestone.
6. Determine applicable security requirements.
7. Design the smallest safe implementation increment.
8. Implement or update tests.
9. Implement the change.
10. Run relevant quality and security checks.
11. Update documentation when required.
12. Report results, limitations, and remaining risks.

Agents must not:

- Skip security analysis.
- Invent cryptographic algorithms.
- Introduce unsafe fallback behavior.
- Claim formal security without appropriate evidence.
- Implement unrelated roadmap phases prematurely.
- Create unnecessary abstractions.
- Weaken validation to make tests pass.
- Ignore failed security checks.
- Modify cryptographic formats without documentation.

When uncertainty involves cryptographic composition, protocol correctness, or security guarantees, the agent must stop that sensitive implementation decision and document the unresolved issue for specialist review.

---

# 9. Progress Tracking

Every phase uses one of these statuses:

- **Not started**
- **In progress**
- **Blocked**
- **Security review**
- **Completed**

The project must maintain accurate progress information.

A phase must not be marked completed until its acceptance criteria have been satisfied.

The agent must update phase status only when supported by actual implementation and test evidence.

## Current progress

| Phase | Status |
|---|---|
| 0 — Security Audit | In progress |
| 1 — Cryptographic Foundation | Not started |
| 2 — Secure Streaming | Not started |
| 3 — Key Management | Not started |
| 4 — Identity | Not started |
| 5 — E2EE | Not started |
| 6 — Cross-Platform | Not started |
| 7 — Security Review | Not started |
| 8 — Stable Release | Not started |
| 9 — Advanced Capabilities | Not started |

### Baseline evidence and remaining work

This is a local-checkout assessment dated 2026-10-18, not a release or remote CI
certification. Preparatory work does not satisfy the Phase 0 exit gate by itself.

| Evidence | What it establishes | What remains open |
| --- | --- | --- |
| `go.mod`, `keys/keys.go`, `stream/files.go`, `utils/aes-utils.go` | Inventory: one module, standard-library dependencies, key generation, legacy file operations, compatibility facade. | Reviewed replacement format and public core contracts. |
| `keys/keys_test.go`, `stream/files_test.go`, `stream/parser_test.go`, `utils/aes-utils_test.go` | Executable tests for the implemented baseline, malformed input, I/O failures, facade behavior, known truncation limits, and concurrent round trips. | Complete security assessment, broader external vectors, and independent review. |
| `Makefile`, `.github/workflows/ci.yml`, `.golangci.yml` | Local checks and configured multiplatform CI, fuzzing, linting, and vulnerability analysis. | Remote results for the published commit and release controls; configuration is not execution evidence. |
| `keys/keys_bench_test.go`, `stream/files_bench_test.go` | Reproducible microbenchmarks for key generation and v1 file operations via `make bench`. | Published performance comparisons and AMD64/ARM64 results with recorded methodology. |
| `README*.md`, `SECURITY.md` | Implemented features are distinguished from targets; current v1 limits and disclosure procedure are documented. | Resolution of the underlying cryptographic risks. |
| `ARCHITECTURE.md`, `docs/adr/0001-legacy-validation.md` | Proposed boundaries and a recorded decision for baseline compatibility tests. | Architecture approval, specialist review, and Phase 1 entry requirements. |

A reproducible benchmark suite exists (`make bench`), but no performance
comparison or benchmark results are published yet. Test coverage is measured by
`make check`; do not treat an old percentage as the current status. The minimum
Go version was raised to 1.26, the oldest release still receiving security
patches at the time of this change, so the CI no longer builds an end-of-life
toolchain. Phases 1–9 remain not started as milestones, even though some
preparatory testing, linting, and CI work already exists.

The [v1 risk register](ARCHITECTURE.md#146-legacy-v1-risk-register) now assigns
CX-V1-001 through CX-V1-009 to findings, evidence, conditions, and residual work.
The [replacement evaluation gate](ARCHITECTURE.md#147-replacement-format-evaluation-gate)
defines criteria for construction selection; no replacement format is approved.

The next increment is to compare established streaming constructions and maintained
implementations in an ADR, then obtain the required review of the chosen assumptions.
Architecture approval and Phase 1 entry criteria remain open. Do not implement or
freeze a new cryptographic composition before that review.

---

# 10. Immediate Next Actions

The first development iteration must focus exclusively on Phase 0.

Required actions:

1. Review the current repository.
2. Inspect cryptographic implementations.
3. Verify existing documentation claims.
4. Identify unsafe behavior.
5. Confirm architecture and trust boundaries.
6. Define the first secure foundation milestone.
7. Create a prioritized implementation backlog.
8. Begin Phase 1 only after completing the Phase 0 exit gate.

Do not attempt to implement all roadmap phases in a single iteration.

Prefer small, independently testable and reviewable changes.

---

# 11. Long-Term Success Criteria

CryptoX will be considered successful when it provides:

- A stable, well-documented Go cryptographic API.
- Verified authenticated encryption.
- Secure and efficient streaming.
- Reliable key management abstractions.
- Clearly defined security guarantees.
- Cross-platform interoperability.
- Reusable identity components.
- Integrations with established E2EE protocols.
- Independent security assessments.
- A sustainable open source development process.

The long-term objective is not to maximize the number of cryptographic algorithms supported.

**The objective is to provide dependable cryptographic building blocks that developers can integrate correctly, maintain confidently, and evaluate independently.**

---

## Final Principle

> **CryptoX must evolve through verified security properties, not assumptions.**

Every milestone must increase reliability, clarity, auditability, or meaningful functionality without weakening the guarantees established by previous releases.

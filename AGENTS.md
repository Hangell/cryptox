# CryptoX — Master Engineering Specification

## 1. Project Mission

Evolve **github.com/Hangell/cryptox** into an open-source, modular, extensible, high-performance, security-focused cryptographic SDK.

CryptoX must become cryptographic infrastructure independent of applications, operating systems, cloud providers, and transport protocols.

The project must support everything from simple cryptographic operations to complex distributed applications, such as:

- End-to-end encrypted (E2EE) messaging applications.
- Large-file encryption and streaming.
- Encrypted local and remote storage.
- Secure file sharing.
- Communication between services and devices.
- Cryptographic identity systems.
- Encrypted backup and recovery.
- Offline-first applications.
- IoT systems and device-to-device communication.
- Enterprise applications with strict confidentiality requirements.
- Systems requiring cryptographic agility and post-quantum resistance.

**Objective:** turn CryptoX into a reliable, reusable cryptographic SDK without reinventing cryptographic primitives or protocols whose security requires specialized analysis.

CryptoX must provide secure abstractions over recognized implementations, rather than develop novel proprietary ciphers.

---

## 2. Architectural Principles

Every engineering decision must respect the following principles.

### 2.1 Security by Design

Security must be an architectural property, not an optional feature.

- Secure by default.
- Fail closed.
- Least privilege.
- Defense in depth.
- Explicit trust boundaries.
- Controlled cryptographic agility.
- Minimized key exposure.
- Data and metadata authentication.
- Strict input validation.
- Rejection of invalid states.
- No insecure cryptographic fallback.

No operation may be considered secure solely because it uses an established cryptographic algorithm.

### 2.2 API Misuse Resistance

Develop APIs that are difficult to misuse.

Requirements:

- Generate nonces automatically whenever possible.
- Prevent accidental key and nonce reuse.
- Do not expose dangerous cryptographic settings by default.
- Clearly distinguish public and private material.
- Use types that represent security properties.
- Require authentication in applicable encryption modes.
- Reject obsolete or insecure algorithms.
- Return clear errors without revealing sensitive data.
- Avoid generic abstractions that conceal incompatible guarantees.

Prefer small, explicit APIs that are difficult to misuse.

### 2.3 Infrastructure Independence

The SDK must not require dependencies on:

- AWS.
- Azure.
- Google Cloud.
- Firebase.
- Apple.
- External authentication services.
- Specific databases.
- Kubernetes.
- Proprietary storage systems.

External integrations must exist exclusively as optional adapters.

### 2.4 Evolution Without Compromising Security

Use explicit versioning for:

- Cryptographic formats.
- Envelopes.
- Protocols.
- Algorithms.
- Cryptographic suite identifiers.
- Persisted states.
- Key structures.

Do not allow silent downgrades or negotiation of insecure algorithms.

When migration is provided, its compatibility and recovery boundaries must be explicit. Never retroactively attribute guarantees that earlier formats did not provide.

---

## 3. Language and Portability

The project's primary language will be **Go**.

Requirements:

- Prioritize the Go standard library.
- Use recognized cryptographic dependencies when necessary.
- Minimize external dependencies.
- Avoid CGO in the core whenever possible.
- Ensure operation on Linux, Windows, and macOS.
- Design optional integrations for Android and iOS.
- Do not require Rust to maintain the core architecture.
- Do not rely on experimental cryptographic implementations in production.

For complete protocols such as Double Ratchet, PQXDH, or MLS, evaluate established implementations, licenses, maintenance, interoperability, and audits.

Do not reimplement these protocols solely to keep all code in Go.

A maintained and audited native integration in another language is acceptable when it provides a demonstrable security benefit.

---

## 4. Hexagonal and Modular Architecture

Adopt concepts from:

- Hexagonal Architecture (Ports and Adapters).
- Clean Architecture where it improves clarity.
- Separation of Concerns.
- Dependency Inversion.
- Composition over Inheritance.
- Interface Segregation.
- Immutability where applicable.
- Explicit Dependencies.
- Secure State Machines.

Avoid applying these patterns mechanically when they increase complexity without demonstrable benefit.

The cryptographic domain must have no knowledge of:

- HTTP.
- WebSocket.
- gRPC.
- PostgreSQL.
- Redis.
- Specific filesystems.
- Frontend frameworks.
- Authentication providers.

Dependencies must point from integrations toward cryptographic contracts and implementations.

Do not create interfaces indiscriminately for every structure. Introduce interfaces at genuine abstraction boundaries.

---

## 5. Proposed Organization

```text
cryptox/
├── aead/
│   ├── aesgcm/
│   └── chacha20poly1305/
│
├── keys/
│   ├── generation/
│   ├── derivation/
│   ├── exchange/
│   ├── signatures/
│   └── lifecycle/
│
├── identity/
│   ├── devices/
│   ├── credentials/
│   ├── verification/
│   └── transparency/
│
├── stream/
│   ├── encrypt/
│   ├── decrypt/
│   ├── framing/
│   └── integrity/
│
├── envelope/
│   ├── format/
│   ├── encoding/
│   ├── versioning/
│   └── validation/
│
├── securestorage/
│   ├── interfaces/
│   ├── encrypted/
│   └── adapters/
│
├── e2ee/
│   ├── interfaces/
│   ├── sessions/
│   ├── devices/
│   ├── groups/
│   └── adapters/
│
├── pki/
│   ├── certificates/
│   ├── trust/
│   └── validation/
│
├── internal/
│   ├── validation/
│   ├── encoding/
│   └── errors/
│
├── compat/
│   └── legacy/
│
├── examples/
│   ├── files/
│   ├── messaging/
│   ├── backups/
│   └── storage/
│
├── testdata/
│   ├── vectors/
│   └── malformed/
│
├── docs/
│   ├── architecture/
│   ├── security/
│   ├── protocols/
│   ├── adr/
│   └── threat-model/
│
├── .github/
│   └── workflows/
│
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
├── README.md
└── go.mod
```

This structure represents the target architecture.

Do not create all packages as empty placeholders in advance.

Introduce each module only when it has a clear contract, implementation, tests, and use case.

Split Go modules only when there is a demonstrated need for independent versioning or distribution.

---

## 6. Modules and Responsibilities

### 6.1 AEAD Engine

Responsible for authenticated symmetric encryption.

Capabilities:

- AES-256-GCM.
- ChaCha20-Poly1305.
- Secure nonce generation.
- Associated Authenticated Data.
- Size validation.
- Integrity and authenticity.
- Cryptographic suite identification.
- Secure error handling.

Do not allow applications to reuse the same key and nonce combination.

Treat single-message APIs and streaming protocols as distinct contexts.

### 6.2 Key Management

Management of cryptographic material.

Capabilities:

- Secure key generation.
- Derivation with HKDF.
- Integration with secure storage mechanisms.
- Key identification and versioning.
- Controlled rotation.
- Credential and device revocation.
- Key separation by purpose.
- Support for explicitly defined recovery mechanisms.

Never log secret material.

Document the limitations of memory clearing in garbage-collected environments.

### 6.3 Stream Encryption

Authenticated encryption of files and data streams of arbitrary size.

Requirements:

- Incremental processing.
- Explicit chunk limits.
- Resistance to malformed input.
- Header and metadata authentication.
- Truncation detection.
- Detection of chunk modification, removal, and reordering.
- End-of-stream authentication.
- Limits on counters and message lengths.
- Transactional file writes.
- Restrictive permissions for temporary files.

Design the streaming format using recognized constructions and review it before freezing the specification.

Do not directly reuse the legacy format to provide new security guarantees.

### 6.4 Secure Envelope

Define a versioned representation for transporting encrypted objects.

The envelope may contain:

- Format version.
- Cryptographic suite identifier.
- Opaque key identifier when necessary.
- Public algorithm parameters.
- Ciphertext.
- Authentication material.
- Authenticated metadata.

Avoid unnecessary fields that could expose identities, timestamps, filenames, and relationships between users.

The envelope must not assume a specific transport.

### 6.5 Identity Engine

Provide cryptographic identity components.

Capabilities:

- Device identities.
- Verifiable public keys.
- Digital signatures.
- Versioned credentials.
- Identity verification between devices.
- Integration with key directories.
- Interfaces for key transparency.

The library must not conflate cryptographic identity with a person's legal identity.

### 6.6 E2EE Integration

Create an independent layer for using established E2EE protocols.

Expected capabilities:

- Authenticated session establishment.
- Session state management.
- Replay protection.
- Forward secrecy, according to the protocol's guarantees.
- Post-compromise recovery, according to the protocol.
- Device authorization and revocation.
- Integration with reviewed group protocols.
- Interoperability tests.

Do not develop a proprietary cryptographic messaging protocol without formal analysis and external review.

### 6.7 Secure Storage

Enable encrypted data persistence without coupling it to a specific technology.

Define contracts for:

- Reading.
- Writing.
- Logical deletion.
- Record identification.
- Versioning.
- Migration.
- Transactions, when available.

Adapters may integrate filesystems, local databases, and operating system secure storage mechanisms.

Do not promise guaranteed physical erasure on SSDs, systems with snapshots, or remote storage.

### 6.8 PKI and Trust

Add tools for validating certificates, trust chains, and identities when needed.

Do not create a custom certificate authority by default.

Clearly distinguish PKI, E2EE identity, and user authentication: they are related but distinct domains.

---

## 7. Design Patterns

Use patterns only when they meaningfully contribute to security, testability, and maintenance.

| Pattern | Application |
|---|---|
| Strategy | Controlled selection of cryptographic implementations |
| Adapter | Integrations with external platforms and libraries |
| Factory | Component construction with parameter validation |
| Facade | Simple public APIs over complex subsystems |
| State Machine | Cryptographic sessions and device lifecycles |
| Dependency Injection | Dependency substitution in tests and integrations |
| Repository | Persistence through contracts |
| Builder | Validated configuration of complex objects |
| Null Object | Only when the absence of behavior does not weaken controls |
| Functional Options | Optional settings with secure defaults |

Do not allow arbitrary algorithm selection in incoming messages.

The cryptographic policy must explicitly validate which suites are supported in each protocol version.

Avoid mutable global registries, implicit initialization, and singletons that store session keys.

---

## 8. Development Security

Implement a Secure SDLC.

Requirements:

- Threat modeling with STRIDE.
- Privacy analysis with LINDDUN.
- Documentation of security properties and limitations.
- Conformance tests using official vectors.
- Unit and integration tests.
- Fuzzing of parsers and binary formats.
- Property-based testing.
- Concurrency tests.
- Race condition detection.
- Static analysis.
- Dependency analysis.
- SBOM.
- Release signing and provenance.
- Auditing of sensitive changes.
- A responsible vulnerability disclosure policy.

Every change to an algorithm, nonce, derivation, serialization, state machine, or cryptographic format must receive a specific security review.

Test coverage does not equal proven security.

---

## 9. Memory and Key Security

Because Go uses garbage collection, do not promise immediate or guaranteed removal of secret material from memory.

Reduce:

- Unnecessary key copies.
- The time secrets remain in memory.
- Accidental serialization of private material.
- Exposure in dumps and error messages.
- Unsafe sharing between goroutines.

Integrate hardware-protected storage mechanisms when available and appropriate.

On mobile platforms, evaluate Android Keystore and Apple Keychain/Secure Enclave while respecting their actual capabilities and limitations.

Do not treat encryption at rest, hardware protection, and isolation from a compromised operating system as equivalent guarantees.

---

## 10. Messaging and Distributed Applications

CryptoX must provide reusable components for E2EE messaging without taking on the role of a messaging server.

CryptoX will NOT be responsible for:

- WebSocket gateways.
- Delivery queues.
- Push notifications.
- Application user management.
- Presence management.
- Message databases.
- Network routing.

These responsibilities remain with consuming systems.

CryptoX must provide the cryptographic components these systems need to offer secure communication.

Design interoperable APIs and persistent session states with explicit handling of reconnections, out-of-order messages, and multiple devices.

---

## 11. Performance Engineering

Prioritize security and correctness before optimization.

Required measurements:

- Encryption throughput.
- Latency per operation.
- Allocations.
- Memory usage.
- Garbage collector impact.
- ARM64 and AMD64 performance.
- Small and large files.
- Concurrent operations.
- Serialization cost.
- Component initialization time.

Compare results with reference implementations.

Do not introduce parallelism that compromises ordering, authentication, or nonce uniqueness.

All published benchmarks must be reproducible and identify the platform, version, parameters, and methodology.

---

## 12. Documentation and Developer Experience

Provide:

- Complete GoDoc documentation.
- A concise README.
- Working examples.
- An architecture guide.
- An integration guide.
- Threat models.
- Examples of unsafe usage and their alternatives.
- A migration guide between versions.
- A compatibility matrix.
- A versioning policy.
- A security policy.
- A binary format reference.
- Implementation-independent specifications.

Clearly document what the library guarantees and what it does not.

Developers who are not cryptography specialists must be able to understand and integrate the project without gaining a false sense of security.

---

## 13. Compatibility and Governance

Adopt semantic versioning for public APIs, accounting for the constraints of cryptographic changes.

Create Architecture Decision Records (ADRs) for significant decisions.

Use public specifications for interoperable formats.

During initial modernization, legacy API and format compatibility is not required. Preserve compatibility only when useful and safe; never retain an unsafe capability solely because it already exists.

Document intentional breaking changes and their impact on callers and persisted data. Provide an isolated migration reader where justified, or explicitly state that migration is unavailable.

Do not promote legacy formats with known flaws as secure.

Ensure format changes have documented migration and recovery procedures.

The source code must remain auditable and have a clearly defined open-source license.

---

## 14. Roadmap

### Phase 0 — Diagnosis

Inspect the existing repository.

Deliverables:

- Feature inventory.
- Dependency map.
- Architectural diagnosis.
- Vulnerability identification.
- Risk matrix.
- Compatibility assessment.
- Proposed target architecture.

Do not perform extensive refactoring before the diagnosis.

### Phase 1 — Secure Foundation

Fix existing vulnerabilities.

Create:

- Comprehensive tests.
- Fuzzing.
- Security pipelines.
- Public contracts.
- A versioning policy.
- Format documentation.
- A secure v2 streaming format.

### Phase 2 — Cryptographic Core

Develop the following modules:

- AEAD.
- Key Management.
- Secure Envelope.
- Secure Streaming.
- Secure Storage.

The implementation must be modular, transport-independent, and usable by different applications.

### Phase 3 — Identity and E2EE Integration

Add:

- Device identity.
- Key verification.
- Session interfaces.
- Integrations with established protocols.
- Interoperability tests.

Do not offer E2EE as a production-ready feature before specialized validation.

### Phase 4 — Cross-Platform Support

Validate:

- Native Go.
- Linux.
- Windows.
- macOS.
- Android.
- iOS.

Create bindings or adapters only when their security and maintenance limitations are understood.

### Phase 5 — Maturity and Auditing

Consolidate:

- Independent cryptographic auditing.
- Public API auditing.
- Continuous fuzzing.
- A vulnerability response policy.
- Reproducible releases.
- Formal documentation of guarantees.
- External compatibility tests.

---

## 15. Acceptance Criteria

No phase may be considered complete solely because the code compiles or existing tests pass.

Each delivery must demonstrate:

1. Fulfillment of functional requirements.
2. Explicitly defined security properties.
3. Absence of known critical vulnerabilities within the delivery's scope.
4. Negative and adversarial tests.
5. Correct handling of invalid input.
6. APIs that are secure by default.
7. Test coverage appropriate to the risks.
8. Verified compatibility where applicable.
9. Updated technical documentation.
10. Documented residual limitations.

Approval of an internal phase does not replace an independent audit.

---

## 16. Agent Execution Guidelines

Act as a senior software architect specializing in Go, application security, distributed systems, and cryptographic engineering.

Your responsibilities are:

1. Understand the repository's actual state.
2. Challenge requirements that could compromise security.
3. Propose solutions grounded in recognized standards and protocols.
4. Identify the boundaries between architecture, implementation, and cryptographic guarantees.
5. Preserve compatibility when useful and safe; document intentional breaks under the modernization policy.
6. Avoid cosmetic refactoring without clear benefit.
7. Introduce tests before critical changes.
8. Document architectural decisions.
9. Justify external dependencies.
10. Explicitly flag anything requiring a specialized audit.

Do not invent cryptographic algorithms.

Do not claim an implementation is secure without sufficient evidence.

Do not create fallback mechanisms for insecure operations.

Do not implement experimental features as though they were suitable for production.

Do not modify public APIs or persisted formats without documenting the impact.

**First mission:** produce a complete diagnosis of the current CryptoX implementation, a well-founded target architecture, and a backlog prioritized by risk, dependencies, and value. Only then begin incremental implementation.

**Long-term vision:** turn CryptoX into a leading open-source cryptographic library for Go developers, focused on verifiable security, performance, interoperability, privacy, and technological independence.

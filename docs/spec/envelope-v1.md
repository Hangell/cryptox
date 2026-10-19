# CryptoX Envelope v1 — specification

Status: proposed implementation-independent specification. This document defines
the format so another team can validate and implement it without consulting the
Go source code.

## 1. Purpose

The envelope is a versioned, transport-independent container for one encrypted
object. It carries:

- a format version;
- a cryptographic suite identifier;
- an optional opaque key identifier;
- authenticated associated metadata;
- public algorithm parameters (the AEAD nonce);
- ciphertext and its authentication tag.

The envelope does **not** provide replay/rollback protection, metadata privacy,
or a messaging protocol. It is a single encrypted object container.

## 2. Conventions

- All integers are big-endian.
- `u8` and `u16` are unsigned 8-bit and 16-bit integers.
- Lengths precede their byte strings; no implicit terminators are used.
- Every field appears exactly once in a fixed order, so no duplicate or
  ambiguous encodings exist.

## 3. Layout

```text
Envelope = Header || Ciphertext || Tag
Header   = magic || version || suite || keyIDLen || keyID
           || aadLen || aad || nonceLen || nonce
```

| Field | Size (bytes) | Value / constraint |
| --- | --- | --- |
| magic | 4 | ASCII `CXE1` |
| version | 1 | `0x01` |
| suite | 2 | `0x0001` = AES-256-GCM |
| keyIDLen | 1 | 0..64 |
| keyID | keyIDLen | opaque key identifier (may be empty) |
| aadLen | 2 | 0..65535 |
| aad | aadLen | authenticated associated metadata |
| nonceLen | 1 | must be `12` for suite `0x0001` |
| nonce | nonceLen | the AEAD nonce, fresh per envelope |
| Ciphertext | variable | AES-256-GCM ciphertext (excludes the tag) |
| Tag | 16 | AES-256-GCM authentication tag |

`Header` is everything from `magic` through `nonce`. The payload length is
`len(Ciphertext)` (GCM preserves length); the plaintext is empty when
`len(Ciphertext) = 0`.

## 4. Encryption (suite 0x0001)

```
nonce = 12 random bytes from a CSPRNG (fresh per envelope)
AAD   = Header                       // all header fields are authenticated
Ciphertext || Tag = AES-256-GCM(key = 32-byte key, nonce = nonce,
                                plaintext = payload, aad = AAD)
```

The header is the complete associated data, so version, suite, key identifier,
metadata, and nonce are all cryptographically bound to the ciphertext.

## 5. Decryption

1. Parse and validate the header exactly, enforcing the constraints in §3.
2. Reject unknown `version` and any `suite` other than `0x0001`.
3. Require at least one tag byte after the header (`len(Ciphertext)+16 >= 16`).
4. Recompute `AAD = Header` and run AES-256-GCM `Open`. Any authentication
   failure is an error; no plaintext is returned.

## 6. Limits

- `keyIDLen <= 64`.
- `aadLen <= 65535`.
- `nonceLen == 12` (suite 0x0001).
- Payload size is bounded by the GCM message limit and by the caller's input;
  no implicit maximum payload is enforced beyond what the input provides.

## 7. Security properties

- Confidentiality and integrity of the payload, and integrity of the header and
  metadata, under a 32-byte key within GCM's security bounds.
- Wrong key, tampered header/metadata/nonce/ciphertext/tag, unsupported
  version/suite, and malformed lengths all fail closed.

Not provided: replay/rollback protection, metadata privacy (lengths and key
identifier are visible), and protection from a compromised process or OS.

## 8. Interoperability gate

> A file produced by CryptoX must be specifiable, validatable, and implementable
> by another team without consulting the Go code.

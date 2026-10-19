# Public API contracts (P1.09)

This document records the misuse-resistance contract of every public CryptoX
surface as of `v0.2.0` development. It is the reference for reviewers and for
future changes: any change to a signature, return value, error, or state
transition below is a public change and must be recorded here and in the
release notes.

## 1. Design rules

1. **No caller-managed nonces.** No high-level API accepts a nonce, IV, or
   counter. Nonces are generated from `crypto/rand` internally.
2. **Explicit shapes.** One-shot, streaming, and file adapters are distinct
   types. There is no generic `Cipher` interface that would let a caller mix
   an AEAD seal with a streaming session and hide incompatible guarantees.
3. **Mandatory finalization.** Streaming output is only complete after an
   explicit `Close`; streaming input only reports success at `io.EOF`. A
   consumer that skips either step must not mistake partial data for a
   complete, authenticated stream.
4. **Fail closed.** Authentication failures return an error and never return
   plaintext.
5. **Key material is typed and redacted.** `aead.Key` is an opaque value type
   whose `String()` method redacts the bytes.

## 2. Public surfaces

### 2.1 `aead` — one-shot AEAD

| Symbol | Contract |
|---|---|
| `type Key [32]byte` | Opaque AES-256 key. `String()` redacts. Zero value is valid raw material (32 zero bytes), **not** a sentinel; use `GenerateKey`. |
| `NewKey([]byte) (Key, error)` | Rejects any length other than 32 with `ErrInvalidKeySize`. |
| `GenerateKey() (Key, error)` | Fresh 256-bit key from `crypto/rand`. |
| `Seal(Key, plaintext, aad []byte) ([]byte, error)` | Returns `nonce ‖ ciphertext ‖ tag`; nonce is fresh per call. |
| `Open(Key, ciphertext, aad []byte) ([]byte, error)` | Returns plaintext or `ErrAuthentication`/`ErrCiphertextTooShort`; never returns plaintext on failure. |

- Concurrency: `Seal`/`Open` are safe for concurrent use (no shared mutable
  state).
- Bound: random-nonce GCM is documented safe for at most 2^32 `Seal` calls
  under one key.

### 2.2 `keys` — key derivation

| Symbol | Contract |
|---|---|
| `type Purpose string` | Domain-separation context; validated as non-empty printable ASCII without NUL, ≤ 255 bytes (`ErrInvalidPurpose`). |
| `DeriveKey(root []byte, purpose Purpose, length int) ([]byte, error)` | HKDF-SHA-256 (RFC 5869) with empty salt and `info = "cryptox/v1/kdf" ‖ 0x00 ‖ purpose`. Requires `len(root) ≥ 32` (`ErrInvalidKeyMaterial`); length ∈ [16, 255·32] (`ErrInvalidLength`). |
| `GenerateKey(size int) ([]byte, error)` | Random AES key of 16, 24, or 32 bytes; any other size returns `ErrInvalidKeySize`. |

- `root` must be high-entropy keying material. This is not a password KDF.

### 2.3 `envelope` — one-shot versioned container

| Symbol | Contract |
|---|---|
| `Seal(key, payload, keyID, aad []byte) ([]byte, error)` | AES-256-GCM with a fresh 12-byte nonce; header (version, suite, keyID, aad, nonce) is GCM AAD. Rejects `len(key) != 32`, `len(keyID) > 64`, `len(aad) > 65535`. |
| `Open(key, data []byte) (*Opened, error)` | Parses with strict bounds, then authenticates; returns `ErrInvalidKey`, `ErrMalformed`, `ErrUnsupportedVersion`, `ErrUnsupportedSuite`, or `ErrAuthentication`. Never returns a payload on failure. |

- `Opened.Suite`, `KeyID`, `AAD`, `Payload` are copies owned by the caller.

### 2.4 `stream` — v2 streaming

| Symbol | Contract |
|---|---|
| `NewEncryptor(w io.Writer, key, aad []byte) (*Encryptor, error)` | Writes the header immediately. Requires a 32-byte key (`ErrInvalidKey`). `Encryptor` is an `io.WriteCloser`; `Close` is mandatory and idempotent. |
| `NewDecryptor(r io.Reader, key, aad []byte) (*Decryptor, error)` | `Decryptor` is an `io.Reader`; `Read` returns `io.EOF` only after the final segment is authenticated. Any error before `io.EOF` means the stream was truncated, modified, or reordered, and the plaintext must not be treated as complete. |
| `EncryptFileV2(infile, outfile string, key, aad []byte) error` | Publishes via a temp file + atomic rename on success only. |
| `DecryptFileV2(infile, outfile string, key, aad []byte) error` | Authenticates the entire stream before publishing; on error the destination is untouched. |

Errors are classifiable with `errors.Is` via the exported sentinels
`ErrInvalidKey`, `ErrMalformed`, `ErrUnsupported`, `ErrAuthentication`, and
`ErrTruncated`. No error carries key material, nonce material, or plaintext.

- `Encryptor`/`Decryptor` are not safe for concurrent use.
- Neither type has a usable zero value; both are constructor-only.

## 3. Mandatory `Close` / `EOF`

```go
// Correct: Close makes the final authenticated segment.
e, _ := stream.NewEncryptor(&out, key, aad)
e.Write(plaintext)
if err := e.Close(); err != nil { /* discard out */ }
```

```go
// Correct: read to io.EOF to establish whole-stream authentication.
d, _ := stream.NewDecryptor(bytes.NewReader(ct), key, aad)
if _, err := io.ReadAll(d); err != nil { /* do not use the plaintext */ }
```

Writing without `Close` (or reading without reaching `io.EOF`) yields
segment-authenticated data only; it is not whole-stream authenticated and must
not be published.

## 4. Unsafe usage and the alternative

| Unsafe | Why it is unsafe | Safe alternative |
|---|---|---|
| Reusing a nonce/IV manually | Reuse breaks GCM confidentiality/integrity | Not possible: no API accepts a nonce. |
| Using a low-entropy password as `root` | HKDF does not stretch low-entropy secrets | Use a dedicated password KDF. |
| Treating pre-`Close` output as complete | No authenticated termination | Require `Close` success. |
| Stopping a `Decryptor` before `io.EOF` | Only segment-authenticated so far | Read to `io.EOF`. |
| Logging a key | Exposes secret material | `aead.Key.String()` redacts; never log raw bytes. |
| Using the zero `aead.Key` | Predictable key | Use `GenerateKey`. |

## 5. Change policy

This document is part of the public contract. Changes to any surface above are
recorded in the changelog and reviewed as a public-API change. The v2 wire
format is pinned separately (see ADR 0002); its freeze awaits the specialist
review (#71) and the approval decision (#72). API changes do not imply format
changes and vice versa.

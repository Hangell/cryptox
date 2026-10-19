# Migrating from the legacy `SYM1` format

The legacy v1 streaming format (`SYM1`) authenticates each chunk independently
and has **no authenticated termination**. It cannot detect truncation,
reordering, or removal of chunks at whole-file scope.

CryptoX **does not produce new `SYM1` files** (ADR 0004). The only supported
migration is decrypt-then-re-encrypt:

```text
old file (SYM1)  --DecryptLargeFiles (deprecated)-->  plaintext
plaintext        --EncryptFileV2 / envelope.Seal-->   new file (CXS2 / CXE1)
```

## What migration does and does not give you

| Property | After migration |
|---|---|
| Confidentiality of the plaintext | preserved, under the new key |
| Integrity from now on | guaranteed by v2 authenticated termination or Envelope v1 |
| Retroactive integrity of the old file | **not recovered** — v1 never guaranteed it |

Re-encrypting a v1 file cannot detect whether that file was already tampered
before migration. Treat any v1-sourced plaintext as untrusted with respect to
its history.

## Rules

- New code must not call the legacy writer. It will be removed before `v1.0.0`.
- `stream.DecryptLargeFiles` and the `utils` facade are deprecated and
  exist only for migration; they are removed in the major release after the
  stable API, with at least one minor release of advance notice.
- There is no automatic v1 detection or fallback: a v1 file is never
  reinterpreted as v2 or Envelope v1.

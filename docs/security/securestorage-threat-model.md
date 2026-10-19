# Secure storage threat model (P3.08)

This document models the persistence, substitution, and rollback threats for the
Phase 3 secure-storage layer, and specifies the binding rule the encrypted
records format must satisfy. It is a design review input, not a proof of
security.

## Assets

- Record ciphertext and its binding metadata (namespace, record ID, version).
- Key material in the keyring (never persisted by this layer unencrypted).

## Adversary model

The storage backend is untrusted for integrity and confidentiality: an attacker
who can read, write, reorder, delete, or restore (rollback) stored bytes is in
scope. The process memory and the keyring are out of scope (a compromised
process or OS is documented as a non-guarantee elsewhere).

## Threats

| Threat | Description | Mitigation |
|---|---|---|
| T1 Replay / rollback | An old version of a record is restored. | Version is bound into the authenticated record; without a trusted monotonic anchor, rollback to an **authentic** older version cannot be detected — the consumer must supply an external anchor (e.g., a signed manifest or a trusted counter) if rollback resistance is required. |
| T2 Cross-record substitution | Bytes of record A are presented as record B. | The authenticated payload binds `namespace ‖ recordID ‖ version`; substitution fails authentication. |
| T3 Tampering | Ciphertext or metadata is modified. | AES-GCM over the bound metadata fails closed. |
| T4 Deletion | A record is removed and not detected. | `List` reflects the store; deletion detection needs an external manifest/checkpoint. |
| T5 Snapshot restore | A whole-store snapshot is rolled back. | Same residual as T1: detection requires a trusted anchor outside the store. |
| T6 Metadata inference | Record IDs and sizes leak. | Record IDs are caller-chosen; no confidentiality of metadata is promised here. |

## Binding rule

The encrypted-records layer (P3.09) MUST authenticate the tuple
`namespace ‖ recordID ‖ version` together with the ciphertext. The recommended
construction is:

```text
AAD     = namespace (UTF-8, length-prefixed) ‖ recordID (length-prefixed)
          ‖ version (8 bytes, big-endian)
ciphertext = AEAD(plaintext, aad = AAD)
```

`namespace` is a caller-supplied domain label separating independent stores;
`recordID` and `version` are the `interfaces.RecordID` and
`interfaces.Version`.

## Residual risks (consumer controls)

- **Rollback resistance is not provided by the storage layer alone.** Consumers
  needing it must keep a trusted monotonic anchor (for example a signed root
  manifest) and check record versions against it.
- **Logical deletion is not physical erasure.** Backups, snapshots, SSDs, and
  remote stores can retain copies.
- **Metadata (IDs, sizes, timing) is not hidden.** Confidentiality applies to
  the record payload.

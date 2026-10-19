# CryptoX secure storage — contract specification

This document specifies the storage contract that every CryptoX secure-storage
adapter implements. It is transport- and backend-independent; the Go interfaces
live in `securestorage/interfaces`.

## 1. Model

A store holds records identified by a non-empty `RecordID`. Each record has:

- an opaque identifier;
- a monotonically increasing `Version`;
- opaque `Data` bytes (typically ciphertext; the store does not interpret them).

## 2. Operations and semantics

| Operation | Contract |
|---|---|
| `Get(id)` | Returns the latest record or `ErrNotFound`. |
| `Put(id, data, expected)` | Writes `data`. `expected == nil` is an unconditional write; `*expected == 0` is insert-if-absent (fails with `ErrConflict` if the record exists); a non-zero `*expected` is a compare-and-swap against the stored version. Returns the new version. |
| `Delete(id, expected)` | Logical deletion with the same CAS rules. Deleted records are omitted from `List`. |
| `List()` | Returns the identifiers of all non-deleted records. |

- Empty identifiers are rejected with `ErrInvalidID`.
- A closed store rejects all operations with `ErrClosed`.

## 3. Concurrency and atomicity

- A `Store` must be safe for concurrent use.
- `Put`/`Delete` are atomic per record; a CAS conflict never partially writes.
- `Transactional` (optional capability) runs `View` against a consistent
  read-only snapshot and commits an `Update` only when the function returns
  nil, otherwise rolling it back.

## 4. Non-promises

- **Deletion is logical**, not physical erasure. SSDs, snapshots, and remote
  storage make guaranteed physical erasure impossible; adapters must not claim
  it.
- The store does not encrypt data; encryption is the responsibility of the
  encrypted-records layer above it (P3.09).
- The store does not provide replay/rollback protection or version history
  beyond the latest version; migration and history are explicit adapter
  capabilities.

## 5. Conformance suite

Every adapter must pass the same reusable conformance suite, which asserts:

1. Put then Get round-trips data and version.
2. Get on a missing ID returns `ErrNotFound`.
3. CAS Put with a stale expected version returns `ErrConflict` and leaves the
   record unchanged.
4. CAS Put with the correct expected version succeeds.
5. Delete removes the record from `List`; Get then returns `ErrNotFound`.
6. Empty IDs are rejected with `ErrInvalidID`.
7. Concurrent Puts with the same expected version yield exactly one success.
8. `Transactional.Update` rolls back on error (when the capability exists).

The Go conformance helper is provided alongside the in-memory adapter
(P3.10) and is reused by the file adapter (P3.11).

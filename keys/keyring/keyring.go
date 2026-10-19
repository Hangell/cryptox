// Package keyring provides a minimal in-memory key registry that resolves key
// material by opaque KeyID, version, and purpose. It follows ADR 0005: there
// is no global registry, key material is never exposed through serialization,
// and unauthenticated metadata never authorizes an operation by itself.
package keyring

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/Hangell/cryptox/keys"
	"github.com/Hangell/cryptox/keys/lifecycle"
)

// KeyIDLen is the length of an opaque key identifier in bytes.
const KeyIDLen = 16

// KeyID is an opaque key identifier. It is random and never derived from key
// material (ADR 0005), so it can be logged and stored without leaking anything
// about the key.
type KeyID [KeyIDLen]byte

// String returns the hex encoding of the KeyID. It contains no secret.
func (id KeyID) String() string { return hex.EncodeToString(id[:]) }

// NewKeyID returns a fresh random KeyID.
func NewKeyID() (KeyID, error) {
	var id KeyID
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, fmt.Errorf("keyring: generate key id: %w", err)
	}
	return id, nil
}

// Secret is key material held by the keyring. It is a distinct type so a
// keyring record cannot be accidentally printed or serialized; String redacts.
type Secret []byte

// String always returns a redaction marker.
func (Secret) String() string { return "[redacted keyring secret]" }

// Bytes returns a copy of the secret material for explicit use by callers.
func (s Secret) Bytes() []byte { return append([]byte(nil), s...) }

// Record is a keyring entry: an opaque identifier, a rotation version, the
// declared purpose, the lifecycle state, and the secret material.
type Record struct {
	ID      KeyID
	Version uint32
	Purpose keys.Purpose
	State   lifecycle.State
	Secret  Secret
}

// Errors returned by the package. Callers can classify failures with errors.Is.
var (
	// ErrNotFound indicates no record exists for the given KeyID.
	ErrNotFound = errors.New("keyring: key not found")
	// ErrDuplicateID indicates a record with the same KeyID already exists.
	ErrDuplicateID = errors.New("keyring: duplicate key id")
	// ErrInvalidRecord indicates a record failed validation (version, purpose,
	// state, or secret).
	ErrInvalidRecord = errors.New("keyring: invalid record")
	// ErrVersionNotFound indicates the KeyID exists but not the requested version.
	ErrVersionNotFound = errors.New("keyring: version not found")
	// ErrPurposeMismatch indicates the KeyID exists but its purpose does not
	// match the requested purpose.
	ErrPurposeMismatch = errors.New("keyring: purpose mismatch")
)

// Keyring is a concurrency-safe in-memory key registry. Construct one per
// security domain; never share a package-level singleton.
type Keyring struct {
	mu      sync.RWMutex
	records map[KeyID]*Record
}

// New returns an empty Keyring.
func New() *Keyring {
	return &Keyring{records: make(map[KeyID]*Record)}
}

// Add stores a record. It rejects duplicate KeyIDs and invalid records. The
// keyring copies the secret, so the caller still owns its slice.
func (k *Keyring) Add(r Record) error {
	if err := validateRecord(r); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.records[r.ID]; ok {
		return ErrDuplicateID
	}
	cp := r
	cp.Secret = append(Secret(nil), r.Secret...)
	k.records[r.ID] = &cp
	return nil
}

// Get returns the record for an exact KeyID, or ErrNotFound.
func (k *Keyring) Get(id KeyID) (Record, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	r, ok := k.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return *r, nil
}

// Resolve returns key material only for an exact (KeyID, version, purpose)
// match. Unknown IDs, unknown versions, and incompatible purposes fail; no
// metadata alone can authorize resolution.
func (k *Keyring) Resolve(id KeyID, version uint32, purpose keys.Purpose) (Record, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	r, ok := k.records[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if r.Version != version {
		return Record{}, ErrVersionNotFound
	}
	if r.Purpose != purpose {
		return Record{}, ErrPurposeMismatch
	}
	return *r, nil
}

// Rotate retires the current active version of id and adds a new version with a
// fresh KeyID and the same purpose. It returns the old and new records.
// Rotation requires the current record to be active.
func (k *Keyring) Rotate(id KeyID, newSecret Secret) (old, new Record, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	r, ok := k.records[id]
	if !ok {
		return Record{}, Record{}, ErrNotFound
	}
	if r.State != lifecycle.StateActive {
		return Record{}, Record{}, fmt.Errorf("%w: cannot rotate %s key", lifecycle.ErrInvalidTransition, r.State)
	}
	newID, err := NewKeyID()
	if err != nil {
		return Record{}, Record{}, err
	}
	if len(newSecret) == 0 {
		return Record{}, Record{}, fmt.Errorf("%w: empty secret", ErrInvalidRecord)
	}
	r.State = lifecycle.StateRetired
	old = *r

	added := Record{
		ID:      newID,
		Version: old.Version + 1,
		Purpose: old.Purpose,
		State:   lifecycle.StateActive,
		Secret:  append(Secret(nil), newSecret...),
	}
	k.records[newID] = &added
	return old, added, nil
}

// Revoke moves a record to the terminal revoked state. Revoking an active or
// retired key succeeds; revoking an already-revoked key is an error.
func (k *Keyring) Revoke(id KeyID) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	r, ok := k.records[id]
	if !ok {
		return ErrNotFound
	}
	if !r.State.CanTransitionTo(lifecycle.StateRevoked) {
		return fmt.Errorf("%w: cannot revoke %s key", lifecycle.ErrInvalidTransition, r.State)
	}
	r.State = lifecycle.StateRevoked
	return nil
}

// List returns a snapshot of all records ordered by KeyID.
func (k *Keyring) List() []Record {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]Record, 0, len(k.records))
	for _, r := range k.records {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].ID, out[j].ID
		for n := 0; n < KeyIDLen; n++ {
			if a[n] != b[n] {
				return a[n] < b[n]
			}
		}
		return false
	})
	return out
}

func validateRecord(r Record) error {
	if r.ID == (KeyID{}) {
		return fmt.Errorf("%w: zero key id", ErrInvalidRecord)
	}
	if r.Version == 0 {
		return fmt.Errorf("%w: zero version", ErrInvalidRecord)
	}
	if r.Purpose == "" {
		return fmt.Errorf("%w: empty purpose", ErrInvalidRecord)
	}
	if r.State != lifecycle.StateActive && r.State != lifecycle.StateRetired && r.State != lifecycle.StateRevoked {
		return fmt.Errorf("%w: invalid state", ErrInvalidRecord)
	}
	if len(r.Secret) == 0 {
		return fmt.Errorf("%w: empty secret", ErrInvalidRecord)
	}
	return nil
}

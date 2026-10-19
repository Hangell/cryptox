// Package encrypted implements the encrypted-records layer over a
// securestorage/interfaces.Store. It encrypts record payloads with AES-256-GCM
// and authenticates the record context (namespace || recordID || version) as
// associated data, per docs/security/securestorage-threat-model.md.
//
// The backend never sees plaintext: it stores an 8-byte big-endian logical
// version followed by the AEAD ciphertext. The logical version is metadata; it
// is authenticated through the AAD, so tampering with it fails closed.
package encrypted

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Hangell/cryptox/aead"
	"github.com/Hangell/cryptox/securestorage/interfaces"
)

const (
	// versionLen is the encoded logical version length.
	versionLen = 8
	// maxPutAttempts bounds the read-modify-write retry on CAS contention.
	maxPutAttempts = 8
)

// Store is an encrypted-records store wrapping an underlying interfaces.Store.
// It is safe for concurrent use as long as the underlying store is.
type Store struct {
	inner     interfaces.Store
	key       aead.Key
	namespace string
}

// New returns an encrypted Store. key must be 32 bytes; namespace must be
// non-empty and is bound into every record's authentication context, so records
// from different namespaces are never interchangeable.
func New(inner interfaces.Store, key []byte, namespace string) (*Store, error) {
	if len(key) != aead.KeySize {
		return nil, fmt.Errorf("encrypted: key must be %d bytes", aead.KeySize)
	}
	if namespace == "" {
		return nil, errors.New("encrypted: namespace must not be empty")
	}
	k, err := aead.NewKey(key)
	if err != nil {
		return nil, err
	}
	return &Store{inner: inner, key: k, namespace: namespace}, nil
}

// Get decrypts the record for id, returning the plaintext and its logical
// version.
func (s *Store) Get(id interfaces.RecordID) (interfaces.Record, error) {
	if id == "" {
		return interfaces.Record{}, interfaces.ErrInvalidID
	}
	raw, err := s.inner.Get(id)
	if err != nil {
		return interfaces.Record{}, err
	}
	version, ct, err := decode(raw.Data)
	if err != nil {
		return interfaces.Record{}, err
	}
	plaintext, err := aead.Open(s.key, ct, buildAAD(s.namespace, id, version))
	if err != nil {
		return interfaces.Record{}, fmt.Errorf("encrypted: %w", err)
	}
	return interfaces.Record{ID: id, Version: version, Data: plaintext}, nil
}

// Put encrypts data and stores it under id with compare-and-swap semantics on
// the logical version. If expected is non-nil and does not equal the stored
// logical version, it fails with interfaces.ErrConflict and writes nothing.
func (s *Store) Put(id interfaces.RecordID, data []byte, expected *interfaces.Version) (interfaces.Record, error) {
	if id == "" {
		return interfaces.Record{}, interfaces.ErrInvalidID
	}
	for attempt := 0; attempt < maxPutAttempts; attempt++ {
		cur, err := s.inner.Get(id)
		var currentVersion interfaces.Version
		var underlyingVersion *interfaces.Version
		switch {
		case errors.Is(err, interfaces.ErrNotFound):
			currentVersion = 0
			zero := interfaces.Version(0)
			underlyingVersion = &zero // insert-if-absent
		case err != nil:
			return interfaces.Record{}, err
		default:
			currentVersion, _, err = decode(cur.Data)
			if err != nil {
				return interfaces.Record{}, err
			}
			v := cur.Version
			underlyingVersion = &v
		}

		if expected != nil && *expected != currentVersion {
			return interfaces.Record{}, interfaces.ErrConflict
		}

		next := currentVersion + 1
		ct, err := aead.Seal(s.key, data, buildAAD(s.namespace, id, next))
		if err != nil {
			return interfaces.Record{}, err
		}
		stored := append(encodeVersion(next), ct...)
		if _, err := s.inner.Put(id, stored, underlyingVersion); err != nil {
			if errors.Is(err, interfaces.ErrConflict) {
				continue // retry: another writer changed the record
			}
			return interfaces.Record{}, err
		}
		return interfaces.Record{ID: id, Version: next, Data: append([]byte(nil), data...)}, nil
	}
	return interfaces.Record{}, interfaces.ErrConflict
}

// Delete logically deletes id with the same CAS semantics on the logical
// version as Put.
func (s *Store) Delete(id interfaces.RecordID, expected *interfaces.Version) error {
	if id == "" {
		return interfaces.ErrInvalidID
	}
	cur, err := s.inner.Get(id)
	if err != nil {
		return err
	}
	curVersion, _, err := decode(cur.Data)
	if err != nil {
		return err
	}
	if expected != nil && *expected != curVersion {
		return interfaces.ErrConflict
	}
	v := cur.Version
	return s.inner.Delete(id, &v)
}

// List returns the identifiers of all non-deleted records.
func (s *Store) List() ([]interfaces.RecordID, error) {
	return s.inner.List()
}

// encodeVersion encodes v as 8 big-endian bytes.
func encodeVersion(v interfaces.Version) []byte {
	b := make([]byte, versionLen)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

// decode splits raw into its logical version and AEAD ciphertext.
func decode(raw []byte) (interfaces.Version, []byte, error) {
	if len(raw) < versionLen {
		return 0, nil, errors.New("encrypted: malformed stored record")
	}
	return interfaces.Version(binary.BigEndian.Uint64(raw[:versionLen])), raw[versionLen:], nil
}

// buildAAD builds the authentication context: length-prefixed namespace and
// record ID, followed by the big-endian version. The layout is injective.
func buildAAD(namespace string, id interfaces.RecordID, version interfaces.Version) []byte {
	aad := make([]byte, 0, 4+len(namespace)+4+len(id)+versionLen)
	aad = binary.BigEndian.AppendUint32(aad, uint32(len(namespace)))
	aad = append(aad, namespace...)
	aad = binary.BigEndian.AppendUint32(aad, uint32(len(id)))
	aad = append(aad, id...)
	aad = binary.BigEndian.AppendUint64(aad, uint64(version))
	return aad
}

// Package file implements securestorage/interfaces.Store over a directory of
// files. Each record is a file named by the base64url encoding of its
// RecordID (preventing path traversal) containing version(8 BE) || data.
//
// Publication is transactional: data is written to a restrictive temporary
// file, fsynced, and atomically renamed over the destination on success. The
// destination directory is not fsynced, so crash durability is not guaranteed;
// see the atomicity note in Put and the storage spec.
package file

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Hangell/cryptox/securestorage/interfaces"
)

const versionLen = 8

// Store is a filesystem-backed Store. It serializes writes with a mutex; reads
// are also serialized for simplicity.
type Store struct {
	mu  sync.Mutex
	dir string
}

// New returns a Store rooted at dir, which must already exist and be a
// directory.
func New(dir string) (*Store, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("file store: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("file store: path is not a directory")
	}
	return &Store{dir: dir}, nil
}

// Get returns the record for id, or ErrNotFound.
func (s *Store) Get(id interfaces.RecordID) (interfaces.Record, error) {
	if id == "" {
		return interfaces.Record{}, interfaces.ErrInvalidID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return interfaces.Record{}, interfaces.ErrNotFound
		}
		return interfaces.Record{}, err
	}
	version, payload, err := decode(data)
	if err != nil {
		return interfaces.Record{}, err
	}
	return interfaces.Record{ID: id, Version: version, Data: payload}, nil
}

// Put writes data for id transactionally. With expected != nil it is a
// compare-and-swap on the stored version. A failed write leaves the
// destination untouched.
//
// Atomicity: the data reaches the destination only via an atomic rename after
// the temporary file is fsynced. Durability: the directory is not fsynced, so
// a crash or power loss may lose the rename; this is documented, not promised.
func (s *Store) Put(id interfaces.RecordID, data []byte, expected *interfaces.Version) (interfaces.Record, error) {
	if id == "" {
		return interfaces.Record{}, interfaces.ErrInvalidID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, err := s.get(id)
	var current interfaces.Version
	switch {
	case errors.Is(err, interfaces.ErrNotFound):
		current = 0
	case err != nil:
		return interfaces.Record{}, err
	default:
		current = cur.Version
	}
	if current == 0 {
		// Insert-if-absent: expected==0 creates, any other non-zero expected
		// conflicts with absence.
		if expected != nil && *expected != 0 {
			return interfaces.Record{}, interfaces.ErrConflict
		}
	} else if expected != nil && *expected != current {
		return interfaces.Record{}, interfaces.ErrConflict
	}

	next := current + 1
	encoded := encode(next, data)

	tmp, err := os.CreateTemp(s.dir, ".cryptox-store-*")
	if err != nil {
		return interfaces.Record{}, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := writeAll(tmp, encoded); err != nil {
		_ = tmp.Close()
		return interfaces.Record{}, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return interfaces.Record{}, err
	}
	if err := tmp.Close(); err != nil {
		return interfaces.Record{}, err
	}
	if err := os.Rename(tmpName, s.path(id)); err != nil {
		return interfaces.Record{}, err
	}
	return interfaces.Record{ID: id, Version: next, Data: append([]byte(nil), data...)}, nil
}

// Delete removes id with compare-and-swap semantics. Removal is best-effort and
// is not secure erasure.
func (s *Store) Delete(id interfaces.RecordID, expected *interfaces.Version) error {
	if id == "" {
		return interfaces.ErrInvalidID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.get(id)
	if err != nil {
		return err
	}
	if expected != nil && *expected != cur.Version {
		return interfaces.ErrConflict
	}
	if err := os.Remove(s.path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// List returns the identifiers of all records in the directory.
func (s *Store) List() ([]interfaces.RecordID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []interfaces.RecordID
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		id, err := decodeName(e.Name())
		if err != nil {
			continue // not a record file
		}
		out = append(out, interfaces.RecordID(id))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (s *Store) get(id interfaces.RecordID) (interfaces.Record, error) {
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return interfaces.Record{}, interfaces.ErrNotFound
		}
		return interfaces.Record{}, err
	}
	version, payload, err := decode(data)
	if err != nil {
		return interfaces.Record{}, err
	}
	return interfaces.Record{ID: id, Version: version, Data: payload}, nil
}

// path maps a RecordID to a safe filename inside the store directory.
func (s *Store) path(id interfaces.RecordID) string {
	name := base64.RawURLEncoding.EncodeToString([]byte(id))
	return filepath.Join(s.dir, name)
}

func decodeName(name string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(name)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func encode(version interfaces.Version, data []byte) []byte {
	b := make([]byte, 0, versionLen+len(data))
	b = binary.BigEndian.AppendUint64(b, uint64(version))
	b = append(b, data...)
	return b
}

func decode(data []byte) (interfaces.Version, []byte, error) {
	if len(data) < versionLen {
		return 0, nil, errors.New("file store: malformed record file")
	}
	return interfaces.Version(binary.BigEndian.Uint64(data[:versionLen])), data[versionLen:], nil
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

var _ interfaces.Store = (*Store)(nil)

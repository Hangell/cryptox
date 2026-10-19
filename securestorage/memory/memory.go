// Package memory provides an in-memory reference implementation of
// securestorage/interfaces.Store. It is intended for tests and ephemeral use;
// it is not persistent and makes no durability or erasure promises.
package memory

import (
	"sort"
	"sync"

	"github.com/Hangell/cryptox/securestorage/interfaces"
)

// Store is a concurrency-safe in-memory Store.
type Store struct {
	mu      sync.RWMutex
	records map[interfaces.RecordID]interfaces.Record
	next    interfaces.Version
	closed  bool
}

// New returns an empty in-memory Store.
func New() *Store {
	return &Store{records: make(map[interfaces.RecordID]interfaces.Record), next: 1}
}

// Get returns the record for id, or ErrNotFound. The returned Data is a copy.
func (s *Store) Get(id interfaces.RecordID) (interfaces.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return interfaces.Record{}, interfaces.ErrClosed
	}
	if id == "" {
		return interfaces.Record{}, interfaces.ErrInvalidID
	}
	r, ok := s.records[id]
	if !ok {
		return interfaces.Record{}, interfaces.ErrNotFound
	}
	return copyRecord(r), nil
}

// Put writes data for id with compare-and-swap semantics. The store copies
// data, so later mutation of the caller's slice does not alias the record.
func (s *Store) Put(id interfaces.RecordID, data []byte, expected *interfaces.Version) (interfaces.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return interfaces.Record{}, interfaces.ErrClosed
	}
	if id == "" {
		return interfaces.Record{}, interfaces.ErrInvalidID
	}
	if cur, ok := s.records[id]; ok {
		if expected != nil && *expected != cur.Version {
			return interfaces.Record{}, interfaces.ErrConflict
		}
		s.next++
		r := interfaces.Record{ID: id, Version: s.next, Data: append([]byte(nil), data...)}
		s.records[id] = r
		return copyRecord(r), nil
	}
	// Absent record: nil expected or expected==0 (insert-if-absent) creates;
	// any other non-zero expected is a conflict.
	if expected != nil && *expected != 0 {
		return interfaces.Record{}, interfaces.ErrConflict
	}
	r := interfaces.Record{ID: id, Version: s.next, Data: append([]byte(nil), data...)}
	s.records[id] = r
	return copyRecord(r), nil
}

// Delete logically deletes id with compare-and-swap semantics.
func (s *Store) Delete(id interfaces.RecordID, expected *interfaces.Version) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return interfaces.ErrClosed
	}
	if id == "" {
		return interfaces.ErrInvalidID
	}
	r, ok := s.records[id]
	if !ok {
		return interfaces.ErrNotFound
	}
	if expected != nil && *expected != r.Version {
		return interfaces.ErrConflict
	}
	delete(s.records, id)
	return nil
}

// List returns the identifiers of all non-deleted records, ordered by ID.
func (s *Store) List() ([]interfaces.RecordID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, interfaces.ErrClosed
	}
	out := make([]interfaces.RecordID, 0, len(s.records))
	for id := range s.records {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// View runs fn against a consistent read-only snapshot.
func (s *Store) View(fn func(interfaces.Store) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return interfaces.ErrClosed
	}
	snap := s.snapshot()
	return fn(snap)
}

// Update runs fn against a copy of the store and commits the copy only if fn
// returns nil. Concurrent writes are detected through a version counter.
func (s *Store) Update(fn func(interfaces.Store) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return interfaces.ErrClosed
	}
	work := s.snapshot()
	if err := fn(work); err != nil {
		return err
	}
	// Commit: copy work's records and version counter back.
	s.records = make(map[interfaces.RecordID]interfaces.Record, len(work.records))
	for id, r := range work.records {
		s.records[id] = copyRecord(r)
	}
	s.next = work.next
	return nil
}

// Close marks the store closed; subsequent operations return ErrClosed.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// snapshot returns a Store whose records map is a copy of s, sharing no slices.
func (s *Store) snapshot() *Store {
	cp := &Store{records: make(map[interfaces.RecordID]interfaces.Record, len(s.records)), next: s.next}
	for id, r := range s.records {
		cp.records[id] = copyRecord(r)
	}
	return cp
}

func copyRecord(r interfaces.Record) interfaces.Record {
	return interfaces.Record{ID: r.ID, Version: r.Version, Data: append([]byte(nil), r.Data...)}
}

// Compile-time assertions.
var (
	_ interfaces.Store         = (*Store)(nil)
	_ interfaces.Transactional = (*Store)(nil)
	_ interfaces.Closer        = (*Store)(nil)
)

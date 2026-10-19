package encrypted

import (
	"bytes"
	"errors"
	"sort"
	"sync"
	"testing"

	"github.com/Hangell/cryptox/securestorage/interfaces"
)

// fakeStore is a minimal in-memory interfaces.Store used only by these tests.
// The official in-memory adapter lives in securestorage/memory (P3.10).
type fakeStore struct {
	mu      sync.Mutex
	records map[interfaces.RecordID]interfaces.Record
	next    interfaces.Version
}

func newFakeStore() *fakeStore {
	return &fakeStore{records: make(map[interfaces.RecordID]interfaces.Record), next: 1}
}

func (f *fakeStore) Get(id interfaces.RecordID) (interfaces.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.records[id]
	if !ok {
		return interfaces.Record{}, interfaces.ErrNotFound
	}
	return r, nil
}

func (f *fakeStore) Put(id interfaces.RecordID, data []byte, expected *interfaces.Version) (interfaces.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id == "" {
		return interfaces.Record{}, interfaces.ErrInvalidID
	}
	if cur, ok := f.records[id]; ok {
		if expected != nil && *expected != cur.Version {
			return interfaces.Record{}, interfaces.ErrConflict
		}
		f.next++
		r := interfaces.Record{ID: id, Version: f.next, Data: append([]byte(nil), data...)}
		f.records[id] = r
		return r, nil
	}
	if expected != nil {
		return interfaces.Record{}, interfaces.ErrConflict
	}
	r := interfaces.Record{ID: id, Version: f.next, Data: append([]byte(nil), data...)}
	f.records[id] = r
	return r, nil
}

func (f *fakeStore) Delete(id interfaces.RecordID, expected *interfaces.Version) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.records[id]
	if !ok {
		return interfaces.ErrNotFound
	}
	if expected != nil && *expected != r.Version {
		return interfaces.ErrConflict
	}
	delete(f.records, id)
	return nil
}

func (f *fakeStore) List() ([]interfaces.RecordID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]interfaces.RecordID, 0, len(f.records))
	for id := range f.records {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func newTestStore(t *testing.T) (*Store, *fakeStore) {
	t.Helper()
	inner := newFakeStore()
	s, err := New(inner, bytes.Repeat([]byte{0x42}, 32), "test-ns")
	if err != nil {
		t.Fatal(err)
	}
	return s, inner
}

func TestEncryptedRoundTripAndVersions(t *testing.T) {
	s, _ := newTestStore(t)
	id := interfaces.RecordID("rec-1")

	r1, err := s.Put(id, []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Version != 1 {
		t.Fatalf("version = %d, want 1", r1.Version)
	}

	got, err := s.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Data, []byte("hello")) || got.Version != 1 {
		t.Fatalf("got %+v", got)
	}

	// CAS with correct expected version succeeds.
	v1 := interfaces.Version(1)
	r2, err := s.Put(id, []byte("world"), &v1)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Version != 2 {
		t.Fatalf("version = %d, want 2", r2.Version)
	}

	// CAS with stale version fails.
	if _, err := s.Put(id, []byte("stale"), &v1); !errors.Is(err, interfaces.ErrConflict) {
		t.Fatalf("stale CAS: got %v, want ErrConflict", err)
	}
}

func TestEncryptedRejectsEmptyID(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.Get(""); !errors.Is(err, interfaces.ErrInvalidID) {
		t.Fatalf("Get: got %v", err)
	}
	if _, err := s.Put("", []byte("x"), nil); !errors.Is(err, interfaces.ErrInvalidID) {
		t.Fatalf("Put: got %v", err)
	}
	if err := s.Delete("", nil); !errors.Is(err, interfaces.ErrInvalidID) {
		t.Fatalf("Delete: got %v", err)
	}
}

func TestEncryptedWrongKeyAndNamespace(t *testing.T) {
	inner := newFakeStore()
	s, err := New(inner, bytes.Repeat([]byte{0x42}, 32), "ns-a")
	if err != nil {
		t.Fatal(err)
	}
	id := interfaces.RecordID("rec")
	if _, err := s.Put(id, []byte("secret"), nil); err != nil {
		t.Fatal(err)
	}

	// Wrong key.
	s2, err := New(inner, bytes.Repeat([]byte{0x43}, 32), "ns-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Get(id); err == nil {
		t.Fatal("wrong key accepted")
	}

	// Wrong namespace.
	s3, err := New(inner, bytes.Repeat([]byte{0x42}, 32), "ns-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s3.Get(id); err == nil {
		t.Fatal("wrong namespace accepted")
	}
}

func TestEncryptedNeverWritesPlaintext(t *testing.T) {
	s, inner := newTestStore(t)
	plaintext := []byte("sensitive data that must never appear in the backend")
	if _, err := s.Put("rec", plaintext, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := inner.Get("rec")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw.Data, plaintext) {
		t.Fatal("plaintext leaked into the backend")
	}
}

func TestEncryptedRejectsTamperingAndSubstitution(t *testing.T) {
	s, inner := newTestStore(t)

	if _, err := s.Put("a", []byte("data-a"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("b", []byte("data-b"), nil); err != nil {
		t.Fatal(err)
	}

	// Corrupt a ciphertext byte.
	rawA, _ := inner.Get("a")
	bad := append([]byte(nil), rawA.Data...)
	bad[len(bad)-1] ^= 0x01
	if _, err := inner.Put("a", bad, &rawA.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a"); err == nil {
		t.Fatal("corrupted record accepted")
	}

	// Cross-record substitution: put record b's bytes under a.
	rawB, _ := inner.Get("b")
	if _, err := inner.Put("a", rawB.Data, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a"); err == nil {
		t.Fatal("substituted record accepted")
	}
}

func TestEncryptedDelete(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.Put("rec", []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	v1 := interfaces.Version(1)
	if err := s.Delete("rec", &v1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("rec"); !errors.Is(err, interfaces.ErrNotFound) {
		t.Fatalf("Get after delete: got %v", err)
	}
}

// Package conformance provides the reusable secure-storage conformance suite
// from docs/spec/securestorage.md. Any adapter should run
// conformance.Test(t, newStore) in its own tests.
package conformance

import (
	"errors"
	"sync"
	"testing"

	"github.com/Hangell/cryptox/securestorage/interfaces"
)

// Test runs the conformance suite against stores produced by newStore.
func Test(t *testing.T, newStore func() interfaces.Store) {
	t.Helper()
	t.Run("PutGetRoundTrip", func(t *testing.T) {
		s := newStore()
		put, err := s.Put("a", []byte("hello"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if put.Version == 0 {
			t.Fatal("version must be non-zero after first put")
		}
		got, err := s.Get("a")
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != put.Version || string(got.Data) != "hello" {
			t.Fatalf("round trip mismatch: %+v", got)
		}
	})

	t.Run("GetMissing", func(t *testing.T) {
		if _, err := newStore().Get("missing"); !errors.Is(err, interfaces.ErrNotFound) {
			t.Fatalf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("CASStaleFails", func(t *testing.T) {
		s := newStore()
		if _, err := s.Put("a", []byte("v1"), nil); err != nil {
			t.Fatal(err)
		}
		stale := interfaces.Version(0)
		if _, err := s.Put("a", []byte("v2"), &stale); !errors.Is(err, interfaces.ErrConflict) {
			t.Fatalf("stale CAS: got %v, want ErrConflict", err)
		}
		got, _ := s.Get("a")
		if string(got.Data) != "v1" {
			t.Fatalf("record changed after stale CAS: %q", got.Data)
		}
	})

	t.Run("CASCorrectSucceeds", func(t *testing.T) {
		s := newStore()
		put, err := s.Put("a", []byte("v1"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Put("a", []byte("v2"), &put.Version); err != nil {
			t.Fatalf("correct CAS: %v", err)
		}
	})

	t.Run("DeleteRemovesFromList", func(t *testing.T) {
		s := newStore()
		put, _ := s.Put("a", []byte("x"), nil)
		if err := s.Delete("a", &put.Version); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get("a"); !errors.Is(err, interfaces.ErrNotFound) {
			t.Fatalf("Get after delete: %v", err)
		}
		ids, err := s.List()
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			if id == "a" {
				t.Fatal("deleted record still listed")
			}
		}
	})

	t.Run("EmptyIDRejected", func(t *testing.T) {
		s := newStore()
		if _, err := s.Put("", []byte("x"), nil); !errors.Is(err, interfaces.ErrInvalidID) {
			t.Fatalf("Put empty id: got %v", err)
		}
	})

	t.Run("ConcurrentCASOneWinner", func(t *testing.T) {
		s := newStore()
		put, _ := s.Put("a", []byte("initial"), nil)
		const n = 32
		var wg sync.WaitGroup
		var successes int
		var mu sync.Mutex
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if _, err := s.Put("a", []byte{byte(i)}, &put.Version); err == nil {
					mu.Lock()
					successes++
					mu.Unlock()
				}
			}(i)
		}
		wg.Wait()
		if successes != 1 {
			t.Fatalf("concurrent CAS successes = %d, want 1", successes)
		}
	})

	t.Run("TransactionalUpdateRollsBack", func(t *testing.T) {
		s := newStore()
		if _, err := s.Put("a", []byte("before"), nil); err != nil {
			t.Fatal(err)
		}
		tx, ok := s.(interfaces.Transactional)
		if !ok {
			t.Skip("store is not transactional")
		}
		sentinel := errors.New("rollback")
		if err := tx.Update(func(work interfaces.Store) error {
			if _, err := work.Put("a", []byte("changed"), nil); err != nil {
				return err
			}
			return sentinel
		}); !errors.Is(err, sentinel) {
			t.Fatalf("Update: got %v, want sentinel", err)
		}
		got, _ := s.Get("a")
		if string(got.Data) != "before" {
			t.Fatalf("rollback failed: %q", got.Data)
		}
	})
}

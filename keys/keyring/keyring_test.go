package keyring

import (
	"errors"
	"sync"
	"testing"

	"github.com/Hangell/cryptox/keys/lifecycle"
)

func newTestID(t *testing.T) KeyID {
	t.Helper()
	id, err := NewKeyID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestKeyringAddGetResolve(t *testing.T) {
	k := New()
	id := newTestID(t)
	rec := Record{ID: id, Version: 1, Purpose: "storage", State: lifecycle.StateActive, Secret: Secret{1, 2, 3}}

	if err := k.Add(rec); err != nil {
		t.Fatal(err)
	}
	// Duplicate ID is rejected.
	if err := k.Add(rec); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("duplicate add: got %v", err)
	}

	got, err := k.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.Purpose != "storage" {
		t.Fatalf("unexpected record: %+v", got)
	}

	// Exact resolve succeeds.
	if _, err := k.Resolve(id, 1, "storage"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Unknown version.
	if _, err := k.Resolve(id, 2, "storage"); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("wrong version: got %v", err)
	}
	// Incompatible purpose.
	if _, err := k.Resolve(id, 1, "envelope"); !errors.Is(err, ErrPurposeMismatch) {
		t.Fatalf("wrong purpose: got %v", err)
	}
	// Unknown ID.
	if _, err := k.Resolve(newTestID(t), 1, "storage"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: got %v", err)
	}
}

func TestKeyringRejectsInvalidRecords(t *testing.T) {
	k := New()
	cases := []Record{
		{}, // zero id
		{ID: newTestID(t), Version: 0, Purpose: "p", State: lifecycle.StateActive, Secret: Secret{1}},
		{ID: newTestID(t), Version: 1, Purpose: "", State: lifecycle.StateActive, Secret: Secret{1}},
		{ID: newTestID(t), Version: 1, Purpose: "p", State: lifecycle.State(99), Secret: Secret{1}},
		{ID: newTestID(t), Version: 1, Purpose: "p", State: lifecycle.StateActive, Secret: Secret{}},
	}
	for i, r := range cases {
		if err := k.Add(r); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("case %d: got %v, want ErrInvalidRecord", i, err)
		}
	}
}

func TestKeyringRotate(t *testing.T) {
	k := New()
	id := newTestID(t)
	if err := k.Add(Record{ID: id, Version: 1, Purpose: "storage", State: lifecycle.StateActive, Secret: Secret{1}}); err != nil {
		t.Fatal(err)
	}

	old, next, err := k.Rotate(id, Secret{2})
	if err != nil {
		t.Fatal(err)
	}
	if old.State != lifecycle.StateRetired {
		t.Fatalf("old state = %s, want retired", old.State)
	}
	if next.Version != 2 || next.State != lifecycle.StateActive || next.Purpose != "storage" {
		t.Fatalf("unexpected next record: %+v", next)
	}
	if next.ID == old.ID {
		t.Fatal("rotated key must have a fresh KeyID")
	}
	// Rotating a retired key fails.
	if _, _, err := k.Rotate(id, Secret{3}); !errors.Is(err, lifecycle.ErrInvalidTransition) {
		t.Fatalf("rotate retired: got %v", err)
	}
}

func TestKeyringRevoke(t *testing.T) {
	k := New()
	id := newTestID(t)
	if err := k.Add(Record{ID: id, Version: 1, Purpose: "storage", State: lifecycle.StateActive, Secret: Secret{1}}); err != nil {
		t.Fatal(err)
	}
	if err := k.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if r, _ := k.Get(id); r.State != lifecycle.StateRevoked {
		t.Fatalf("state = %s, want revoked", r.State)
	}
	if err := k.Revoke(id); !errors.Is(err, lifecycle.ErrInvalidTransition) {
		t.Fatalf("revoke again: got %v", err)
	}
}

func TestKeyringConcurrentAccess(t *testing.T) {
	k := New()
	id := newTestID(t)
	if err := k.Add(Record{ID: id, Version: 1, Purpose: "storage", State: lifecycle.StateActive, Secret: Secret{1}}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := k.Get(id); err != nil {
				t.Errorf("Get: %v", err)
			}
		}()
	}
	wg.Wait()
}

func TestSecretRedacts(t *testing.T) {
	s := Secret{0xde, 0xad, 0xbe, 0xef}
	if got := s.String(); got != "[redacted keyring secret]" {
		t.Fatalf("String() = %q, want redaction", got)
	}
	b := s.Bytes()
	b[0] = 0x00
	if s[0] == b[0] {
		t.Fatal("Bytes must return a copy")
	}
}

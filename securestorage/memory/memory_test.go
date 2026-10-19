package memory

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Hangell/cryptox/securestorage/conformance"
	"github.com/Hangell/cryptox/securestorage/interfaces"
)

func TestMemoryStoreConformance(t *testing.T) {
	conformance.Test(t, func() interfaces.Store { return New() })
}

func TestMemoryStoreCopiesBuffers(t *testing.T) {
	s := New()
	data := []byte("original")
	if _, err := s.Put("a", data, nil); err != nil {
		t.Fatal(err)
	}
	data[0] = 'X'
	got, err := s.Get("a")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got.Data, []byte("Xriginal")) {
		t.Fatal("store aliases the caller's input buffer")
	}
	if got.Data[0] == 'X' {
		t.Fatal("Get aliases the stored buffer")
	}
}

func TestMemoryStoreEmptyID(t *testing.T) {
	s := New()
	if _, err := s.Get(""); !errors.Is(err, interfaces.ErrInvalidID) {
		t.Fatalf("Get empty id: got %v", err)
	}
	if err := s.Delete("", nil); !errors.Is(err, interfaces.ErrInvalidID) {
		t.Fatalf("Delete empty id: got %v", err)
	}
}

func TestMemoryStoreClosed(t *testing.T) {
	s := New()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a"); !errors.Is(err, interfaces.ErrClosed) {
		t.Fatalf("Get after close: got %v", err)
	}
	if _, err := s.Put("a", nil, nil); !errors.Is(err, interfaces.ErrClosed) {
		t.Fatalf("Put after close: got %v", err)
	}
}

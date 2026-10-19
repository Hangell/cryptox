package file

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Hangell/cryptox/securestorage/conformance"
	"github.com/Hangell/cryptox/securestorage/interfaces"
)

func TestFileStoreConformance(t *testing.T) {
	conformance.Test(t, func() interfaces.Store {
		dir := t.TempDir()
		s, err := New(dir)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestFileStoreRejectsTraversal(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Record IDs are base64url-encoded, so a path-separator ID cannot escape the
	// directory; it just maps to a safe filename.
	id := interfaces.RecordID("../escape")
	if _, err := s.Put(id, []byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(id); err != nil {
		t.Fatal(err)
	}
	// No file was created outside the store directory.
	if _, err := os.Stat(filepath.Join(filepath.Dir(s.dir), "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("path traversal escaped the store directory")
	}
}

func TestFileStoreDestinationPreservedOnFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("a", []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	// Stale CAS must not modify the file.
	stale := interfaces.Version(0)
	if _, err := s.Put("a", []byte("v2"), &stale); !errors.Is(err, interfaces.ErrConflict) {
		t.Fatalf("stale CAS: got %v", err)
	}
	got, err := s.Get("a")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "v1" {
		t.Fatalf("destination changed after failed write: %q", got.Data)
	}
}

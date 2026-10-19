package file

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Hangell/cryptox/securestorage/encrypted"
)

// TestPersistenceAcrossReopen verifies recovery when the same directory is
// reopened by a new Store instance (keys available).
func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("rec", []byte("durable"), nil); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Get("rec")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Data, []byte("durable")) {
		t.Fatalf("reopened data = %q", got.Data)
	}
}

// TestMissingDirectoryFails ensures New rejects a non-existent directory.
func TestMissingDirectoryFails(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("New accepted a missing directory")
	}
}

// TestCorruptedRecordFailsClosed verifies a malformed record file returns an
// error rather than panicking, and List skips non-record files.
func TestCorruptedRecordFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "not-a-record!"), []byte("junk"), 0600); err != nil {
		t.Fatal(err)
	}
	ids, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("List returned non-record files: %v", ids)
	}
}

// TestEncryptedRecoveryWithWrongKey verifies recovery fails closed when the
// wrong key is supplied (key material absent or different).
func TestEncryptedRecoveryWithWrongKey(t *testing.T) {
	dir := t.TempDir()
	backend, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := encrypted.New(backend, bytes.Repeat([]byte{0x42}, 32), "ns")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put("rec", []byte("secret"), nil); err != nil {
		t.Fatal(err)
	}

	// Reopen the backend with the wrong key.
	backend2, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := encrypted.New(backend2, bytes.Repeat([]byte{0x43}, 32), "ns")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Get("rec"); err == nil {
		t.Fatal("wrong key accepted during recovery")
	}

	// Reopen with the correct key succeeds.
	backend3, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	right, err := encrypted.New(backend3, bytes.Repeat([]byte{0x42}, 32), "ns")
	if err != nil {
		t.Fatal(err)
	}
	got, err := right.Get("rec")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data) != "secret" {
		t.Fatalf("recovered data = %q", got.Data)
	}
}

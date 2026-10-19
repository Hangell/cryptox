package stream

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestOverwriteOnSuccess verifies that a successful operation atomically
// replaces an existing destination (overwrite is part of the contract).
func TestOverwriteOnSuccess(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output")
	key := bytes.Repeat([]byte{0x11}, 32)
	data := []byte("fresh content")

	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	// Pre-existing destination with a sentinel value.
	if err := os.WriteFile(output, []byte("old sentinel"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := EncryptLargeFiles(input, output, key); err != nil {
		t.Fatal(err)
	}

	// The destination must now decrypt to the new content, not the sentinel.
	decrypted := filepath.Join(dir, "decrypted")
	if err := DecryptLargeFiles(output, decrypted, key); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("destination was not replaced: got %q", got)
	}
}

// TestDestinationPreservedOnAuthFailure verifies a failed decryption leaves a
// pre-existing destination byte-for-byte intact.
func TestDestinationPreservedOnAuthFailure(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	encrypted := filepath.Join(dir, "encrypted")
	output := filepath.Join(dir, "output")
	key := bytes.Repeat([]byte{0x22}, 32)

	if err := os.WriteFile(input, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptLargeFiles(input, encrypted, key); err != nil {
		t.Fatal(err)
	}
	// Corrupt the last byte (the authentication tag of the only chunk).
	ct, err := os.ReadFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0x01
	if err := os.WriteFile(encrypted, ct, 0600); err != nil {
		t.Fatal(err)
	}

	sentinel := []byte("destination must survive failure")
	if err := os.WriteFile(output, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	if err := DecryptLargeFiles(encrypted, output, key); err == nil {
		t.Fatal("corrupted ciphertext accepted")
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, sentinel) {
		t.Fatalf("destination changed on failure: got %q", got)
	}
}

// TestRenameFailureCleansUp verifies that when publication (rename) fails, the
// temporary file is removed and no partial output is left.
func TestRenameFailureCleansUp(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output") // made into a directory so rename fails
	key := bytes.Repeat([]byte{0x33}, 32)

	if err := os.WriteFile(input, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}

	if err := EncryptLargeFiles(input, output, key); err == nil {
		t.Fatal("rename over a directory succeeded")
	}

	leftovers, err := filepath.Glob(filepath.Join(dir, ".cryptox-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temporary file leaked: %v", leftovers)
	}
}

// TestInputOpenFailurePreservesDestination verifies that failing to open the
// input leaves the destination untouched.
func TestInputOpenFailurePreservesDestination(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "output")
	key := bytes.Repeat([]byte{0x44}, 32)

	sentinel := []byte("untouched")
	if err := os.WriteFile(output, sentinel, 0600); err != nil {
		t.Fatal(err)
	}

	if err := EncryptLargeFiles(filepath.Join(dir, "does-not-exist"), output, key); err == nil {
		t.Fatal("missing input accepted")
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, sentinel) {
		t.Fatalf("destination changed on input failure: got %q", got)
	}
}

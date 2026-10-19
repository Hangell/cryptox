package stream

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestV2FileRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	aad := []byte("file aad")
	for _, size := range []int{0, 1, v2SegmentSize, v2SegmentSize + 1, 3*v2SegmentSize + 100} {
		dir := t.TempDir()
		input := filepath.Join(dir, "input")
		encrypted := filepath.Join(dir, "encrypted")
		output := filepath.Join(dir, "output")
		data := bytes.Repeat([]byte{0x7a}, size)
		if err := os.WriteFile(input, data, 0600); err != nil {
			t.Fatal(err)
		}

		if err := EncryptFileV2(input, encrypted, key, aad); err != nil {
			t.Fatalf("size %d encrypt: %v", size, err)
		}
		if err := DecryptFileV2(encrypted, output, key, aad); err != nil {
			t.Fatalf("size %d decrypt: %v", size, err)
		}
		got, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
	}
}

func TestV2FileOverwriteOnSuccess(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output")
	key := bytes.Repeat([]byte{0x22}, 32)

	if err := os.WriteFile(input, []byte("new content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("old sentinel"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := EncryptFileV2(input, output, key, nil); err != nil {
		t.Fatal(err)
	}

	decrypted := filepath.Join(dir, "decrypted")
	if err := DecryptFileV2(output, decrypted, key, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(decrypted)
	if !bytes.Equal(got, []byte("new content")) {
		t.Fatalf("destination not replaced: got %q", got)
	}
}

func TestV2FileDestinationPreservedOnTruncation(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	encrypted := filepath.Join(dir, "encrypted")
	output := filepath.Join(dir, "output")
	key := bytes.Repeat([]byte{0x33}, 32)

	// A stream larger than one segment so truncation removes the final record.
	if err := os.WriteFile(input, bytes.Repeat([]byte{0x44}, 2*v2SegmentSize+10), 0600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFileV2(input, encrypted, key, nil); err != nil {
		t.Fatal(err)
	}
	ct, _ := os.ReadFile(encrypted)
	// Remove the final record (10 bytes + 16-byte tag).
	if err := os.WriteFile(encrypted, ct[:len(ct)-(10+16)], 0600); err != nil {
		t.Fatal(err)
	}

	sentinel := []byte("destination must survive")
	if err := os.WriteFile(output, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFileV2(encrypted, output, key, nil); err == nil {
		t.Fatal("truncated v2 file accepted")
	}
	got, _ := os.ReadFile(output)
	if !bytes.Equal(got, sentinel) {
		t.Fatalf("destination changed on truncation: got %q", got)
	}

	leftovers, _ := filepath.Glob(filepath.Join(dir, ".cryptox-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary file leaked: %v", leftovers)
	}
}

func TestV2FileDestinationPreservedOnWrongKey(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	encrypted := filepath.Join(dir, "encrypted")
	output := filepath.Join(dir, "output")
	key := bytes.Repeat([]byte{0x55}, 32)

	if err := os.WriteFile(input, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFileV2(input, encrypted, key, nil); err != nil {
		t.Fatal(err)
	}

	sentinel := []byte("untouched")
	if err := os.WriteFile(output, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFileV2(encrypted, output, bytes.Repeat([]byte{0x66}, 32), nil); err == nil {
		t.Fatal("wrong key accepted")
	}
	got, _ := os.ReadFile(output)
	if !bytes.Equal(got, sentinel) {
		t.Fatalf("destination changed on wrong key: got %q", got)
	}
}

func TestV2FileRejectsShortKey(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(input, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFileV2(input, output, make([]byte, 16), nil); err == nil {
		t.Fatal("EncryptFileV2 accepted a 16-byte key")
	}
	if err := DecryptFileV2(input, output, make([]byte, 16), nil); err == nil {
		t.Fatal("DecryptFileV2 accepted a 16-byte key")
	}
}

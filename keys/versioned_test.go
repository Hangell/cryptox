package keys

import (
	"bytes"
	"errors"
	"testing"
)

func TestDeriveVersionedDomainSeparation(t *testing.T) {
	root := bytes.Repeat([]byte{0x42}, 64)

	stream, err := DeriveVersioned(root, "stream", CurrentKDFVersion, 32)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := DeriveVersioned(root, "envelope", CurrentKDFVersion, 32)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := DeriveVersioned(root, "storage", CurrentKDFVersion, 32)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(stream, envelope) || bytes.Equal(stream, storage) || bytes.Equal(envelope, storage) {
		t.Fatal("derived keys for different purposes must differ")
	}

	// Deterministic for the same (root, purpose, version).
	again, err := DeriveVersioned(root, "stream", CurrentKDFVersion, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stream, again) {
		t.Fatal("DeriveVersioned is not deterministic")
	}
}

func TestDeriveVersionedSchemeSeparationFromV1(t *testing.T) {
	root := bytes.Repeat([]byte{0x43}, 64)
	legacy, err := DeriveKey(root, "stream", 32)
	if err != nil {
		t.Fatal(err)
	}
	versioned, err := DeriveVersioned(root, "stream", CurrentKDFVersion, 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(legacy, versioned) {
		t.Fatal("v1 DeriveKey and versioned DeriveVersioned must be distinct schemes")
	}
}

func TestDeriveVersionedRejectsInvalidInput(t *testing.T) {
	root := bytes.Repeat([]byte{0x44}, 64)

	if _, err := DeriveVersioned(bytes.Repeat([]byte{0x44}, 31), "p", CurrentKDFVersion, 32); !errors.Is(err, ErrInvalidKeyMaterial) {
		t.Fatalf("short root: got %v", err)
	}
	if _, err := DeriveVersioned(root, "", CurrentKDFVersion, 32); !errors.Is(err, ErrInvalidPurpose) {
		t.Fatalf("empty purpose: got %v", err)
	}
	if _, err := DeriveVersioned(root, "p", 0, 32); !errors.Is(err, ErrUnsupportedKDFVersion) {
		t.Fatalf("version 0: got %v", err)
	}
	if _, err := DeriveVersioned(root, "p", 2, 32); !errors.Is(err, ErrUnsupportedKDFVersion) {
		t.Fatalf("version 2: got %v", err)
	}
	if _, err := DeriveVersioned(root, "p", CurrentKDFVersion, 15); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("short length: got %v", err)
	}
	if _, err := DeriveVersioned(root, "p", CurrentKDFVersion, maxDerivedKeyLen+1); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("long length: got %v", err)
	}
}

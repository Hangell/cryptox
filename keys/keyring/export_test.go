package keyring

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/Hangell/cryptox/keys"
	"github.com/Hangell/cryptox/keys/lifecycle"
)

func TestExportImportRoundTrip(t *testing.T) {
	id := newTestID(t)
	r := Record{
		ID:      id,
		Version: 3,
		Purpose: "storage",
		State:   lifecycle.StateRetired,
		Secret:  Secret{0xde, 0xad, 0xbe, 0xef},
	}

	data, err := Export(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Import(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != r.ID || got.Version != r.Version || got.Purpose != r.Purpose ||
		got.State != r.State || !bytes.Equal(got.Secret, r.Secret) {
		t.Fatalf("round trip mismatch:\n got: %+v\nwant: %+v", got, r)
	}
}

func TestExportIndependentOfRecordSecret(t *testing.T) {
	id := newTestID(t)
	r := Record{ID: id, Version: 1, Purpose: "p", State: lifecycle.StateActive, Secret: Secret{1, 2, 3}}
	data, err := Export(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Secret[0] = 0xff
	if data[len(data)-3] != 1 {
		t.Fatal("export must not alias the record secret")
	}
}

func TestImportRejectsMalformed(t *testing.T) {
	id := newTestID(t)
	r := Record{ID: id, Version: 1, Purpose: "p", State: lifecycle.StateActive, Secret: Secret{1, 2, 3}}
	valid, err := Export(r)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":            {},
		"magic only":       []byte("CKKX"),
		"bad magic":        append([]byte("XXXX"), valid[4:]...),
		"truncated":        valid[:len(valid)-1],
		"trailing garbage": append(append([]byte(nil), valid...), 0x00),
	}
	for name, data := range cases {
		if _, err := Import(data); !errors.Is(err, ErrMalformedExport) {
			t.Fatalf("%s: got %v, want ErrMalformedExport", name, err)
		}
	}

	// Unknown version.
	badVersion := append([]byte(nil), valid...)
	badVersion[4] = 0x7f
	if _, err := Import(badVersion); !errors.Is(err, ErrUnsupportedExportVersion) {
		t.Fatalf("bad version: got %v", err)
	}
}

func TestExportRejectsUnrepresentableLengths(t *testing.T) {
	id := newTestID(t)
	longPurpose := Record{ID: id, Version: 1, Purpose: keys.Purpose(strings.Repeat("a", 256)), State: lifecycle.StateActive, Secret: Secret{1}}
	if _, err := Export(longPurpose); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("long purpose: got %v", err)
	}
	longSecret := Record{ID: id, Version: 1, Purpose: "p", State: lifecycle.StateActive, Secret: make(Secret, 65536)}
	if _, err := Export(longSecret); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("long secret: got %v", err)
	}
}

func TestRecordFormatRedactsSecret(t *testing.T) {
	id := newTestID(t)
	r := Record{ID: id, Version: 1, Purpose: "p", State: lifecycle.StateActive, Secret: Secret{0xaa, 0xbb}}
	// Common %v formatting must not leak material.
	if got := r.Secret.String(); got != "[redacted keyring secret]" {
		t.Fatalf("Secret.String() = %q", got)
	}
}

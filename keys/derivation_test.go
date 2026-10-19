package keys

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// TestHKDFSHA256RFC5869 verifies the HKDF-SHA-256 primitive against RFC 5869
// Appendix A test cases 1-3.
func TestHKDFSHA256RFC5869(t *testing.T) {
	cases := []struct {
		name   string
		ikm    string
		salt   string
		info   string
		length int
		okm    string
	}{
		{
			name:   "A.1 basic",
			ikm:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:   "000102030405060708090a0b0c",
			info:   "f0f1f2f3f4f5f6f7f8f9",
			length: 42,
			okm:    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name: "A.2 longer inputs/outputs",
			ikm: "000102030405060708090a0b0c0d0e0f" +
				"101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f" +
				"303132333435363738393a3b3c3d3e3f" +
				"404142434445464748494a4b4c4d4e4f",
			salt: "606162636465666768696a6b6c6d6e6f" +
				"707172737475767778797a7b7c7d7e7f" +
				"808182838485868788898a8b8c8d8e8f" +
				"909192939495969798999a9b9c9d9e9f" +
				"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
				"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
				"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
				"e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
				"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			length: 82,
			okm: "b11e398dc80327a1c8e7f78c596a4934" +
				"4f012eda2d4efad8a050cc4c19afa97c" +
				"59045a99cac7827271cb41c65e590e09" +
				"da3275600c2f09b8367793a9aca3db71" +
				"cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		{
			name:   "A.3 zero-length salt/info",
			ikm:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:   "",
			info:   "",
			length: 42,
			okm:    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var salt []byte
			if tc.salt != "" {
				salt = mustHex(t, tc.salt)
			}
			got := hkdfSHA256(mustHex(t, tc.ikm), salt, mustHex(t, tc.info), tc.length)
			want := mustHex(t, tc.okm)
			if !bytes.Equal(got, want) {
				t.Fatalf("OKM mismatch\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

func TestDeriveKeyDomainSeparation(t *testing.T) {
	root := bytes.Repeat([]byte{0x42}, 64)

	a, err := DeriveKey(root, "envelope", 32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKey(root, "storage", 32)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := DeriveKey(root, "envelope", 32)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(a, b) {
		t.Fatal("different purposes produced identical keys")
	}
	if !bytes.Equal(a, a2) {
		t.Fatal("same purpose is not deterministic")
	}

	other, err := DeriveKey(bytes.Repeat([]byte{0x43}, 64), "envelope", 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, other) {
		t.Fatal("different roots produced identical keys")
	}
}

func TestDeriveKeyMatchesHKDF(t *testing.T) {
	root := bytes.Repeat([]byte{0x11}, 32)
	got, err := DeriveKey(root, "test", 32)
	if err != nil {
		t.Fatal(err)
	}
	want := hkdfSHA256(root, nil, []byte("cryptox/v1/kdf\x00test"), 32)
	if !bytes.Equal(got, want) {
		t.Fatalf("DeriveKey diverged from HKDF\n got: %x\nwant: %x", got, want)
	}
}

func TestDeriveKeyRejectsInvalidInput(t *testing.T) {
	root := bytes.Repeat([]byte{0x42}, 64)

	cases := []struct {
		name    string
		root    []byte
		purpose Purpose
		length  int
	}{
		{"short root", bytes.Repeat([]byte{0x42}, 31), "p", 32},
		{"empty purpose", root, "", 32},
		{"nul purpose", root, "a\x00b", 32},
		{"non-ascii purpose", root, "café", 32},
		{"too-long purpose", root, Purpose(bytes.Repeat([]byte("x"), 256)), 32},
		{"length too small", root, "p", 15},
		{"length too large", root, "p", maxDerivedKeyLen + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := DeriveKey(tc.root, tc.purpose, tc.length); err == nil || got != nil {
				t.Fatalf("expected error, got key %x", got)
			}
		})
	}
}

func TestDeriveKeyLengthBounds(t *testing.T) {
	root := bytes.Repeat([]byte{0x42}, 64)
	for _, length := range []int{16, 32, 64, maxDerivedKeyLen} {
		got, err := DeriveKey(root, "bounds", length)
		if err != nil {
			t.Fatalf("length %d: %v", length, err)
		}
		if len(got) != length {
			t.Fatalf("length %d: got %d bytes", length, len(got))
		}
	}
}

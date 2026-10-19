package stream

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestV2HeaderRoundTrip(t *testing.T) {
	var salt [v2SaltLen]byte
	var prefix [v2NoncePrefixLen]byte
	for i := range salt {
		salt[i] = byte(i)
	}
	for i := range prefix {
		prefix[i] = byte(0x80 + i)
	}

	h := buildV2Header(salt, prefix)
	gotSalt, gotPrefix, err := parseV2Header(h[:])
	if err != nil {
		t.Fatalf("parseV2Header: %v", err)
	}
	if gotSalt != salt {
		t.Errorf("salt mismatch: got %x, want %x", gotSalt, salt)
	}
	if gotPrefix != prefix {
		t.Errorf("nonce prefix mismatch: got %x, want %x", gotPrefix, prefix)
	}
}

func TestV2HeaderRejectsV1Magic(t *testing.T) {
	// A v1-style header must never be accepted as v2.
	h := make([]byte, v2HeaderLen)
	copy(h[0:4], "SYM1")
	h[4] = v2Version
	h[5] = v2SuiteAES256GCMHKDFSHA256
	h[6] = v2SaltLen
	if _, _, err := parseV2Header(h); err == nil {
		t.Fatal("v1 magic accepted as v2 header")
	}
}

func TestV2HeaderRejectsUnknownVersionAndSuite(t *testing.T) {
	var salt [v2SaltLen]byte
	var prefix [v2NoncePrefixLen]byte
	good := buildV2Header(salt, prefix)

	for _, name := range []string{"version", "suite", "saltLen"} {
		bad := good
		switch name {
		case "version":
			bad[4] = 0x03
		case "suite":
			bad[5] = 0x7f
		case "saltLen":
			bad[6] = 0x10
		}
		if _, _, err := parseV2Header(bad[:]); err == nil {
			t.Errorf("accepted invalid %s", name)
		}
	}
}

func TestV2HeaderRejectsBadLength(t *testing.T) {
	if _, _, err := parseV2Header(make([]byte, v2HeaderLen-1)); err == nil {
		t.Fatal("accepted short v2 header")
	}
}

func TestV2SegmentIVLayout(t *testing.T) {
	var prefix [v2NoncePrefixLen]byte
	for i := range prefix {
		prefix[i] = byte(0x10 + i)
	}

	iv := v2SegmentIV(prefix, 0x01020304, true)
	if !bytes.Equal(iv[:v2NoncePrefixLen], prefix[:]) {
		t.Errorf("prefix mismatch: got %x", iv[:v2NoncePrefixLen])
	}
	if got := binary.BigEndian.Uint32(iv[7:11]); got != 0x01020304 {
		t.Errorf("counter mismatch: got %#x", got)
	}
	if iv[11] != 0x01 {
		t.Errorf("final flag = %#x, want 0x01", iv[11])
	}

	nonFinal := v2SegmentIV(prefix, 0x01020304, false)
	if nonFinal[11] != 0x00 {
		t.Errorf("non-final flag = %#x, want 0x00", nonFinal[11])
	}
}

func TestV2SegmentIVUniqueness(t *testing.T) {
	var prefix [v2NoncePrefixLen]byte
	seen := map[[12]byte]bool{}
	for i := uint32(0); i < 1000; i++ {
		iv := v2SegmentIV(prefix, i, false)
		if seen[iv] {
			t.Fatalf("duplicate IV for counter %d", i)
		}
		seen[iv] = true
	}
	// The final flag keeps the final segment distinct from a non-final one with
	// the same counter.
	if v2SegmentIV(prefix, 42, false) == v2SegmentIV(prefix, 42, true) {
		t.Fatal("final flag does not differentiate the final segment")
	}
}

func TestV2DomainSepBindsContext(t *testing.T) {
	base := v2DomainSep(v2Version, v2SuiteAES256GCMHKDFSHA256, []byte("aad"))
	if !bytes.Contains(base, []byte(v2DomainSepLabel)) {
		t.Errorf("domainSep missing label %q", v2DomainSepLabel)
	}

	different := []struct {
		name string
		got  []byte
	}{
		{"version", v2DomainSep(0x03, v2SuiteAES256GCMHKDFSHA256, []byte("aad"))},
		{"suite", v2DomainSep(v2Version, 0x02, []byte("aad"))},
		{"aad", v2DomainSep(v2Version, v2SuiteAES256GCMHKDFSHA256, []byte("other"))},
	}
	for _, d := range different {
		if bytes.Equal(base, d.got) {
			t.Errorf("domainSep not bound to %s", d.name)
		}
	}
}

func TestV2RandomizerSize(t *testing.T) {
	// The v2 design derives a per-stream key from a 312-bit randomizer
	// (32-byte salt + 7-byte nonce prefix), not the v1 64-bit prefix.
	if v2RandomizerBytes != v2SaltLen+v2NoncePrefixLen {
		t.Fatalf("v2RandomizerBytes = %d, want %d", v2RandomizerBytes, v2SaltLen+v2NoncePrefixLen)
	}
	if v2SaltLen != 32 {
		t.Errorf("salt length = %d, want 32", v2SaltLen)
	}
	if v2NoncePrefixLen != 7 {
		t.Errorf("nonce prefix length = %d, want 7", v2NoncePrefixLen)
	}
}

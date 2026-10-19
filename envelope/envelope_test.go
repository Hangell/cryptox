package envelope

import (
	"bytes"
	"errors"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	cases := []struct {
		name    string
		payload []byte
		keyID   []byte
		aad     []byte
	}{
		{"empty", nil, nil, nil},
		{"with key id and aad", []byte("payload"), []byte("kid-1"), []byte("meta")},
		{"binary", bytes.Repeat([]byte{0x00, 0xff}, 4096), nil, []byte{0x01, 0x02}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := Seal(key, tc.payload, tc.keyID, tc.aad)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := Open(key, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(opened.Payload, tc.payload) {
				t.Fatalf("payload mismatch: got %x, want %x", opened.Payload, tc.payload)
			}
			if !bytes.Equal(opened.KeyID, tc.keyID) {
				t.Fatalf("keyID mismatch: got %x, want %x", opened.KeyID, tc.keyID)
			}
			if !bytes.Equal(opened.AAD, tc.aad) {
				t.Fatalf("aad mismatch: got %x, want %x", opened.AAD, tc.aad)
			}
			if opened.Suite != SuiteAES256GCM {
				t.Fatalf("suite = %#x, want %#x", opened.Suite, SuiteAES256GCM)
			}
		})
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	ct, _ := Seal(bytes.Repeat([]byte{0x01}, 32), []byte("secret"), nil, nil)
	if _, err := Open(bytes.Repeat([]byte{0x02}, 32), ct); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key: got err=%v, want ErrAuthentication", err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x03}, 32)
	ct, err := Seal(key, []byte("secret"), []byte("kid"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range ct {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		if opened, err := Open(key, bad); err == nil && opened != nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
}

func TestOpenRejectsStructuralTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x04}, 32)
	ct, _ := Seal(key, []byte("secret"), []byte("kid"), []byte("aad"))

	for i := 0; i < 4; i++ { // magic
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		if _, err := Open(key, bad); err == nil {
			t.Fatalf("tampered magic byte %d accepted", i)
		}
	}
	// Unknown version.
	bad := append([]byte(nil), ct...)
	bad[4] = 0x02
	if _, err := Open(key, bad); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("unknown version: got err=%v", err)
	}
	// Unknown suite.
	bad = append([]byte(nil), ct...)
	bad[5] = 0x7f
	if _, err := Open(key, bad); !errors.Is(err, ErrUnsupportedSuite) {
		t.Fatalf("unknown suite: got err=%v", err)
	}
}

func TestOpenRejectsMalformed(t *testing.T) {
	key := bytes.Repeat([]byte{0x05}, 32)
	ct, _ := Seal(key, []byte("payload"), nil, nil)

	for _, n := range []int{0, 1, 4, len(ct) - 1} {
		if _, err := Open(key, ct[:n]); err == nil {
			t.Fatalf("truncated to %d bytes accepted", n)
		}
	}
}

func TestSealRejectsInvalidInput(t *testing.T) {
	if _, err := Seal(make([]byte, 16), nil, nil, nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short key: got err=%v", err)
	}
	if _, err := Seal(bytes.Repeat([]byte{1}, 32), nil, make([]byte, MaxKeyIDLen+1), nil); err == nil {
		t.Fatal("oversized key id accepted")
	}
	if _, err := Seal(bytes.Repeat([]byte{1}, 32), nil, nil, make([]byte, MaxAADLen+1)); err == nil {
		t.Fatal("oversized aad accepted")
	}
	if _, err := Open(make([]byte, 16), nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short key on Open: got err=%v", err)
	}
}

func TestSealNonceRandomized(t *testing.T) {
	key := bytes.Repeat([]byte{0x06}, 32)
	a, _ := Seal(key, []byte("same"), nil, nil)
	b, _ := Seal(key, []byte("same"), nil, nil)
	if bytes.Equal(a, b) {
		t.Fatal("two Seal calls produced identical envelopes")
	}
}

func TestEnvelopeDeterministicHeaderAfterNonce(t *testing.T) {
	// The header layout must be fixed so another implementation can parse it.
	key := bytes.Repeat([]byte{0x07}, 32)
	ct, _ := Seal(key, []byte("p"), []byte("kid"), []byte("aad"))

	if string(ct[:4]) != Magic {
		t.Fatalf("magic = %q", ct[:4])
	}
	if ct[4] != Version {
		t.Fatalf("version = %d", ct[4])
	}
	// suite is big-endian 0x0001 at bytes 5-6.
	if ct[5] != 0x00 || ct[6] != 0x01 {
		t.Fatalf("suite = %#x%#x", ct[5], ct[6])
	}
	// keyIDLen at byte 7, then "kid".
	if ct[7] != 3 || string(ct[8:11]) != "kid" {
		t.Fatalf("key id field malformed: %x", ct[7:11])
	}
}

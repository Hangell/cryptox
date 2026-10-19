package aead

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sync"
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

// TestKnownAnswerNIST checks AES-256-GCM against NIST GCM specification,
// Test Case 15 (empty AAD, 12-byte IV).
func TestKnownAnswerNIST(t *testing.T) {
	keyBytes := mustHex(t, "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
	nonce := mustHex(t, "cafebabefacedbaddecaf888")
	plaintext := mustHex(t, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
	expected := mustHex(t, "cafebabefacedbaddecaf888522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015adb094dac5d93471bdec1a502270e3cc6c")

	key, err := NewKey(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	g, err := newGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	got := sealWithNonce(g, nonce, plaintext, nil)
	if !bytes.Equal(got, expected) {
		t.Fatalf("AES-256-GCM known answer mismatch\n got: %x\nwant: %x", got, expected)
	}
}

func TestRoundTrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		plaintext []byte
		aad       []byte
	}{
		{"empty", nil, nil},
		{"with aad", []byte("hello, world"), []byte("header")},
		{"binary", bytes.Repeat([]byte{0x00, 0xff}, 1000), []byte{0x01, 0x02}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := Seal(key, tc.plaintext, tc.aad)
			if err != nil {
				t.Fatal(err)
			}
			pt, err := Open(key, ct, tc.aad)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pt, tc.plaintext) {
				t.Fatalf("round trip mismatch: got %x, want %x", pt, tc.plaintext)
			}
		})
	}
}

func TestOpenRejectsTamperedCiphertextAndTag(t *testing.T) {
	key, _ := GenerateKey()
	ct, _ := Seal(key, []byte("sensitive data"), []byte("aad"))

	for i := len(ct) - 1; i >= len(ct)-16; i-- {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		if pt, err := Open(key, bad, []byte("aad")); err == nil || pt != nil {
			t.Fatalf("tampered tag at byte %d accepted (pt=%x, err=%v)", i, pt, err)
		}
	}
	// Tamper with the ciphertext body.
	bad := append([]byte(nil), ct...)
	bad[len(ct)-17] ^= 0x80
	if _, err := Open(key, bad, []byte("aad")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered ciphertext: got err=%v, want ErrAuthentication", err)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	ct, _ := Seal(k1, []byte("plaintext"), nil)
	if _, err := Open(k2, ct, nil); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key: got err=%v, want ErrAuthentication", err)
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	key, _ := GenerateKey()
	ct, _ := Seal(key, []byte("plaintext"), []byte("aad"))
	if _, err := Open(key, ct, []byte("different")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong AAD: got err=%v, want ErrAuthentication", err)
	}
}

func TestInvalidKeySize(t *testing.T) {
	for _, n := range []int{0, 16, 24, 31, 33} {
		if _, err := NewKey(make([]byte, n)); !errors.Is(err, ErrInvalidKeySize) {
			t.Fatalf("key size %d: got err=%v, want ErrInvalidKeySize", n, err)
		}
	}
}

func TestCiphertextTooShort(t *testing.T) {
	key, _ := GenerateKey()
	if _, err := Open(key, make([]byte, 0), nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("empty ciphertext: got err=%v, want ErrCiphertextTooShort", err)
	}
	if _, err := Open(key, make([]byte, 27), nil); !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("short ciphertext: got err=%v, want ErrCiphertextTooShort", err)
	}
}

func TestSealNonceRandomized(t *testing.T) {
	key, _ := GenerateKey()
	pt := []byte("same plaintext")
	a, err1 := Seal(key, pt, nil)
	b, err2 := Seal(key, pt, nil)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two Seal calls produced identical ciphertext")
	}
	if !bytes.Equal(a[:12], b[:12]) {
		t.Log("nonces differ as expected")
	}
}

func TestConcurrentSealOpen(t *testing.T) {
	key, _ := GenerateKey()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pt := bytes.Repeat([]byte{byte(i)}, 64)
			ct, err := Seal(key, pt, []byte("aad"))
			if err != nil {
				t.Error(err)
				return
			}
			got, err := Open(key, ct, []byte("aad"))
			if err != nil {
				t.Error(err)
				return
			}
			if !bytes.Equal(got, pt) {
				t.Error("concurrent round trip mismatch")
			}
		}(i)
	}
	wg.Wait()
}

func TestKeyStringRedacted(t *testing.T) {
	key, _ := GenerateKey()
	s := key.String()
	if bytes.Contains([]byte(s), key[:]) || s == "" {
		t.Fatalf("Key.String() leaked material: %q", s)
	}
}

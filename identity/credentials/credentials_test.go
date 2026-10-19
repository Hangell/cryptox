package credentials

import (
	"bytes"
	"testing"
	"time"

	"github.com/Hangell/cryptox/keys/signatures"
)

func testIssuer(t *testing.T) (signatures.PublicKey, signatures.PrivateKey) {
	t.Helper()
	pub, priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func testSubject(t *testing.T) signatures.PublicKey {
	t.Helper()
	pub, _, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestRoundTrip(t *testing.T) {
	issuerPub, issuerPriv := testIssuer(t)
	subject := testSubject(t)
	now := time.Now()
	c, err := New(issuerPriv, subject, PurposeDeviceIdentity, uint64(now.Add(-time.Hour).Unix()), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Issuer != issuerPub {
		t.Fatal("issuer field does not match signing key")
	}
	if c.Subject != subject {
		t.Fatal("subject field mismatch")
	}

	enc, err := c.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(enc) != credentialSize {
		t.Fatalf("encoded length %d, want %d", len(enc), credentialSize)
	}

	dec, err := Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if dec != c {
		t.Fatal("decode/encode round-trip mismatch")
	}
	if err := dec.Verify(now); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestEncodeDeterministic(t *testing.T) {
	_, issuerPriv := testIssuer(t)
	subject := testSubject(t)
	c, err := New(issuerPriv, subject, PurposeAgentIdentity, 1000, 2000)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := c.Encode()
	b, _ := c.Encode()
	if !bytes.Equal(a, b) {
		t.Fatal("Encode is not deterministic")
	}
}

func TestTamperDetection(t *testing.T) {
	_, issuerPriv := testIssuer(t)
	subject := testSubject(t)
	now := time.Now()
	c, err := New(issuerPriv, subject, PurposeDeviceIdentity, uint64(now.Add(-time.Hour).Unix()), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	base, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func([]byte){
		"issuer":    func(b []byte) { b[1] ^= 0x01 },
		"subject":   func(b []byte) { b[1+signatures.PublicKeySize] ^= 0x01 },
		"purpose":   func(b []byte) { b[1+2*signatures.PublicKeySize] ^= 0x01 },
		"notBefore": func(b []byte) { b[1+2*signatures.PublicKeySize+1] ^= 0x01 },
		"notAfter":  func(b []byte) { b[1+2*signatures.PublicKeySize+1+8] ^= 0x01 },
		"signature": func(b []byte) { b[encodedSize] ^= 0x01 },
	} {
		t.Run(name, func(t *testing.T) {
			b := append([]byte(nil), base...)
			mutate(b)
			dec, err := Decode(b)
			if err != nil {
				return // structural tampering rejected at decode
			}
			if err := dec.Verify(now); err == nil {
				t.Fatal("tampering not detected")
			}
		})
	}
}

func TestKeyReplacementDetected(t *testing.T) {
	_, issuerPriv := testIssuer(t)
	subjectA := testSubject(t)
	subjectB := testSubject(t)
	now := time.Now()
	c, err := New(issuerPriv, subjectA, PurposeDeviceIdentity, uint64(now.Add(-time.Hour).Unix()), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	// Swap in a different subject without re-signing: signature must fail.
	c.Subject = subjectB
	if err := c.Verify(now); err == nil {
		t.Fatal("replaced subject key not detected")
	}
}

func TestValidityWindow(t *testing.T) {
	_, issuerPriv := testIssuer(t)
	subject := testSubject(t)
	base := time.Now()

	c, err := New(issuerPriv, subject, PurposeDeviceIdentity, uint64(base.Add(-time.Hour).Unix()), uint64(base.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(base.Add(-2 * time.Hour)); err == nil {
		t.Fatal("accepted credential before NotBefore")
	}
	if err := c.Verify(base.Add(2 * time.Hour)); err == nil {
		t.Fatal("accepted credential after NotAfter")
	}
	if err := c.Verify(base); err != nil {
		t.Fatalf("valid credential rejected: %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	_, issuerPriv := testIssuer(t)
	subject := testSubject(t)

	if _, err := New(issuerPriv, subject, Purpose(0xFF), 1000, 2000); err != ErrInvalidPurpose {
		t.Fatalf("unknown purpose: got %v, want ErrInvalidPurpose", err)
	}
	if _, err := New(issuerPriv, subject, PurposeDeviceIdentity, 2000, 1000); err != ErrInvalidValidity {
		t.Fatalf("inverted window: got %v, want ErrInvalidValidity", err)
	}
	if _, err := New(issuerPriv, subject, PurposeDeviceIdentity, 1000, 1000); err != ErrInvalidValidity {
		t.Fatalf("zero-length window: got %v, want ErrInvalidValidity", err)
	}
	if _, err := New(signatures.PrivateKey{}, subject, PurposeDeviceIdentity, 1000, 2000); err == nil {
		t.Fatal("New accepted an invalid issuer private key")
	}
}

func TestDecodeValidation(t *testing.T) {
	_, issuerPriv := testIssuer(t)
	subject := testSubject(t)
	c, err := New(issuerPriv, subject, PurposeDeviceIdentity, 1000, 2000)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := c.Encode()

	if _, err := Decode(nil); err != ErrMalformed {
		t.Fatalf("nil: got %v, want ErrMalformed", err)
	}
	if _, err := Decode(base[:len(base)-1]); err != ErrMalformed {
		t.Fatalf("truncated: got %v, want ErrMalformed", err)
	}
	if _, err := Decode(append(append([]byte(nil), base...), 0x00)); err != ErrMalformed {
		t.Fatalf("extended: got %v, want ErrMalformed", err)
	}
	badVersion := append([]byte(nil), base...)
	badVersion[0] = 0x02
	if _, err := Decode(badVersion); err != ErrUnsupportedVersion {
		t.Fatalf("bad version: got %v, want ErrUnsupportedVersion", err)
	}
	badPurpose := append([]byte(nil), base...)
	badPurpose[1+2*signatures.PublicKeySize] = 0xFF
	if _, err := Decode(badPurpose); err != ErrInvalidPurpose {
		t.Fatalf("bad purpose: got %v, want ErrInvalidPurpose", err)
	}
	badWindow := append([]byte(nil), base...)
	// Overwrite NotBefore (offset 66) with a value >= NotAfter (offset 74 holds 2000).
	for i := 0; i < 8; i++ {
		badWindow[1+2*signatures.PublicKeySize+1+i] = 0xFF
	}
	if _, err := Decode(badWindow); err != ErrInvalidValidity {
		t.Fatalf("inverted window: got %v, want ErrInvalidValidity", err)
	}
}

func FuzzDecode(f *testing.F) {
	_, issuerPriv, err := signatures.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	subjectPub, _, err := signatures.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	seed, err := New(issuerPriv, subjectPub, PurposeDeviceIdentity, 1000, 2000)
	if err != nil {
		f.Fatal(err)
	}
	seedBytes, _ := seed.Encode()

	f.Add([]byte{})
	f.Add(make([]byte, credentialSize))
	f.Add(seedBytes)
	f.Fuzz(func(t *testing.T, b []byte) {
		dec, err := Decode(b)
		if err != nil {
			return
		}
		// Decode succeeded: Verify and Encode must not panic and must stay consistent.
		_ = dec.Verify(time.Unix(0, 0))
		re, err := dec.Encode()
		if err == nil && !bytes.Equal(re, b) {
			t.Fatalf("re-encode of decoded bytes differs: %x != %x", re, b)
		}
	})
}

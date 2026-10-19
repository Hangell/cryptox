package exchange

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// RFC 7748 Section 6.1 — Diffie-Hellman test vector.
func TestRFC7748Vector(t *testing.T) {
	alicePriv := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePub := mustHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPriv := mustHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPub := mustHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	wantSecret := mustHex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	var aPriv PrivateKey
	var bPriv PrivateKey
	var aPub PublicKey
	var bPub PublicKey
	copy(aPriv[:], alicePriv)
	copy(bPriv[:], bobPriv)
	copy(aPub[:], alicePub)
	copy(bPub[:], bobPub)

	// Public keys derived from private keys match the vector.
	if pub, err := aPriv.Public(); err != nil || pub != aPub {
		t.Fatalf("alice public key mismatch: %x, err=%v", pub, err)
	}
	if pub, err := bPriv.Public(); err != nil || pub != bPub {
		t.Fatalf("bob public key mismatch: %x, err=%v", pub, err)
	}

	// Both directions agree with the expected shared secret.
	ka, err := ECDH(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := ECDH(bPriv, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ka, wantSecret) {
		t.Fatalf("alice shared secret mismatch: %x", ka)
	}
	if !bytes.Equal(ka, kb) {
		t.Fatal("shared secrets differ between directions")
	}
}

func TestECDHAgreement(t *testing.T) {
	_, aPriv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	bPub, bPriv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	aPub, err := aPriv.Public()
	if err != nil {
		t.Fatal(err)
	}
	ka, err := ECDH(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := ECDH(bPriv, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ka, kb) {
		t.Fatal("shared secrets disagree")
	}
	if len(ka) != SharedSecretSize {
		t.Fatalf("shared secret length %d, want %d", len(ka), SharedSecretSize)
	}
}

func TestLowOrderPeerKeyRejected(t *testing.T) {
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// u-coordinate 0 is a low-order point whose X25519 output is all-zero,
	// which RFC 7748 requires implementations to reject.
	if _, err := ECDH(priv, PublicKey{}); err != ErrInvalidPeerKey {
		t.Fatalf("low-order peer key: got %v, want ErrInvalidPeerKey", err)
	}
}

func TestPrivateKeyStringRedacted(t *testing.T) {
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(priv.String(), hex.EncodeToString(priv[:])) {
		t.Fatal("PrivateKey.String leaked material")
	}
}

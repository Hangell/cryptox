package signatures

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

// RFC 8032 Section 7.1 — Ed25519 test vectors, exercised with an empty context
// so the API maps to plain Ed25519.
func TestRFC8032Ed25519Vectors(t *testing.T) {
	tests := []struct {
		name    string
		seed    string
		pub     string
		message string
		sig     string
	}{
		{
			name:    "TEST 1",
			seed:    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			pub:     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			message: "",
			sig:     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
		},
		{
			name:    "TEST 2",
			seed:    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			pub:     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
			message: "72",
			sig:     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
		},
		{
			name:    "TEST 3",
			seed:    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
			pub:     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
			message: "af82",
			sig:     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, priv, err := PrivateKeyFromSeed(mustHex(t, tt.seed))
			if err != nil {
				t.Fatalf("PrivateKeyFromSeed: %v", err)
			}
			if !bytes.Equal(pub[:], mustHex(t, tt.pub)) {
				t.Fatalf("public key mismatch: got %x", pub)
			}
			msg := mustHex(t, tt.message)
			sig, err := Sign(priv, msg, "")
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !bytes.Equal(sig, mustHex(t, tt.sig)) {
				t.Fatalf("signature mismatch: got %x", sig)
			}
			if !Verify(pub, msg, "", sig) {
				t.Fatal("Verify rejected a valid RFC 8032 signature")
			}
		})
	}
}

// RFC 8032 Section 7.2 — Ed25519ctx test vectors.
func TestRFC8032Ed25519ctxVectors(t *testing.T) {
	seed := mustHex(t, "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6")
	wantPub := mustHex(t, "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292")
	msg := mustHex(t, "f726936d19c800494e3fdaff20b276a8")

	tests := []struct {
		name    string
		context string
		wantSig string
	}{
		{
			name:    "foo",
			context: "foo",
			wantSig: "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d",
		},
		{
			name:    "bar",
			context: "bar",
			wantSig: "fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d",
		},
	}

	pub, priv, err := PrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("PrivateKeyFromSeed: %v", err)
	}
	if !bytes.Equal(pub[:], wantPub) {
		t.Fatalf("public key mismatch: got %x", pub)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantSig := mustHex(t, tt.wantSig)
			sig, err := Sign(priv, msg, tt.context)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !bytes.Equal(sig, wantSig) {
				t.Fatalf("signature mismatch: got %x", sig)
			}
			if !Verify(pub, msg, tt.context, sig) {
				t.Fatal("Verify rejected a valid RFC 8032 Ed25519ctx signature")
			}
			// The signature must not verify under plain Ed25519.
			if Verify(pub, msg, "", sig) {
				t.Fatal("Ed25519ctx signature verified under empty context")
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if derived, err := priv.Public(); err != nil || !bytes.Equal(derived[:], pub[:]) {
		t.Fatalf("PrivateKey.Public mismatch: derived=%x err=%v", derived, err)
	}
	msg := []byte("cryptox identity: device binding")
	for _, context := range []string{"", "cryptox/identity/device", strings.Repeat("x", 255)} {
		sig, err := Sign(priv, msg, context)
		if err != nil {
			t.Fatalf("Sign(context=%q): %v", context, err)
		}
		if !Verify(pub, msg, context, sig) {
			t.Fatalf("Verify(context=%q) rejected own signature", context)
		}
	}
}

func TestContextIsolation(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("hello")
	a, err := Sign(priv, msg, "domain-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(priv, msg, "domain-b")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("signatures across distinct contexts must differ")
	}
	if Verify(pub, msg, "domain-b", a) {
		t.Fatal("signature from domain-a verified under domain-b")
	}
	if !Verify(pub, msg, "domain-a", a) {
		t.Fatal("signature failed under its own domain")
	}
}

func TestMalformedInputs(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("data")
	sig, err := Sign(priv, msg, "")
	if err != nil {
		t.Fatal(err)
	}

	// Truncated signature.
	if Verify(pub, msg, "", sig[:len(sig)-1]) {
		t.Fatal("accepted truncated signature")
	}
	// Extended signature.
	if Verify(pub, msg, "", append(append([]byte(nil), sig...), 0x00)) {
		t.Fatal("accepted extended signature")
	}
	// Mutated signature.
	mut := append([]byte(nil), sig...)
	mut[0] ^= 0x01
	if Verify(pub, msg, "", mut) {
		t.Fatal("accepted mutated signature")
	}
	// Mutated message.
	if Verify(pub, append(append([]byte(nil), msg...), 0x00), "", sig) {
		t.Fatal("accepted signature over mutated message")
	}

	// Zero private key must return ErrInvalidKey, not panic or sign.
	if _, err := Sign(PrivateKey{}, msg, ""); err == nil {
		t.Fatal("Sign accepted a zero private key")
	}
	// A private key whose public suffix does not match its seed is malformed.
	var corrupt PrivateKey
	copy(corrupt[:], priv[:])
	corrupt[PrivateKeySize-1] ^= 0x01
	if _, err := Sign(corrupt, msg, ""); err == nil {
		t.Fatal("Sign accepted a private key with a mismatched public suffix")
	}
	if _, err := corrupt.Public(); err == nil {
		t.Fatal("Public accepted a mismatched private key")
	}
	// Oversized context must be rejected.
	if _, err := Sign(priv, msg, strings.Repeat("c", 256)); err == nil {
		t.Fatal("Sign accepted a 256-byte context")
	}
	if Verify(pub, msg, strings.Repeat("c", 256), sig) {
		t.Fatal("Verify accepted a 256-byte context")
	}
	// Seed of wrong length must return ErrInvalidKey, not panic.
	if _, _, err := PrivateKeyFromSeed([]byte{0x01}); err == nil {
		t.Fatal("PrivateKeyFromSeed accepted a short seed")
	}
}

func TestPrivateKeyStringRedacted(t *testing.T) {
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s := priv.String()
	if strings.Contains(s, hex.EncodeToString(priv[:])) || strings.Contains(s, "00") {
		t.Fatalf("PrivateKey.String leaked material: %q", s)
	}
}

package envelope

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type envelopeGolden struct {
	Source     string `json:"source"`
	Key        string `json:"key"`
	Nonce      string `json:"nonce"`
	KeyID      string `json:"keyID"`
	AAD        string `json:"aad"`
	Payload    string `json:"payload"`
	Ciphertext string `json:"ciphertext"`
}

func loadEnvelopeGolden(t *testing.T) envelopeGolden {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "envelope-v1-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g envelopeGolden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// TestEnvelopeGoldenOpen verifies that the pinned golden envelope opens to the
// expected payload, key id, and metadata.
func TestEnvelopeGoldenOpen(t *testing.T) {
	g := loadEnvelopeGolden(t)
	opened, err := Open(hexBytes(t, g.Key), hexBytes(t, g.Ciphertext))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.Payload, hexBytes(t, g.Payload)) {
		t.Fatalf("payload mismatch\n got: %x\nwant: %s", opened.Payload, g.Payload)
	}
	if !bytes.Equal(opened.KeyID, hexBytes(t, g.KeyID)) {
		t.Fatalf("key id mismatch: got %q", opened.KeyID)
	}
	if !bytes.Equal(opened.AAD, hexBytes(t, g.AAD)) {
		t.Fatalf("aad mismatch: got %q", opened.AAD)
	}
}

// TestEnvelopeGoldenSealReproduces verifies that deterministic sealing with the
// pinned nonce reproduces the golden envelope byte-for-byte.
func TestEnvelopeGoldenSealReproduces(t *testing.T) {
	g := loadEnvelopeGolden(t)
	ct, err := sealWithNonce(
		hexBytes(t, g.Key),
		hexBytes(t, g.Nonce),
		hexBytes(t, g.Payload),
		hexBytes(t, g.KeyID),
		hexBytes(t, g.AAD),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ct, hexBytes(t, g.Ciphertext)) {
		t.Fatalf("ciphertext mismatch\n got: %x\nwant: %s", ct, g.Ciphertext)
	}
}

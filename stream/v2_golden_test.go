package stream

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type v2Golden struct {
	Source      string `json:"source"`
	Key         string `json:"key"`
	Salt        string `json:"salt"`
	NoncePrefix string `json:"noncePrefix"`
	AAD         string `json:"aad"`
	Plaintext   string `json:"plaintext"`
	Ciphertext  string `json:"ciphertext"`
}

func loadV2Golden(t *testing.T) v2Golden {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "v2-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g v2Golden
	if err := json.Unmarshal(b, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func (g v2Golden) key(t *testing.T) []byte {
	t.Helper()
	return mustHex(t, g.Key)
}

// TestV2GoldenDecrypt verifies that the pinned golden ciphertext decrypts to
// the expected plaintext across future versions.
func TestV2GoldenDecrypt(t *testing.T) {
	g := loadV2Golden(t)
	d, err := NewDecryptor(bytes.NewReader(mustHex(t, g.Ciphertext)), g.key(t), mustHex(t, g.AAD))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustHex(t, g.Plaintext)) {
		t.Fatalf("golden plaintext mismatch\n got: %x\nwant: %s", got, g.Plaintext)
	}
}

// TestV2GoldenEncryptReproduces verifies that deterministic encryption with the
// pinned secrets reproduces the golden ciphertext byte-for-byte.
func TestV2GoldenEncryptReproduces(t *testing.T) {
	g := loadV2Golden(t)
	var salt [v2SaltLen]byte
	copy(salt[:], mustHex(t, g.Salt))
	var prefix [v2NoncePrefixLen]byte
	copy(prefix[:], mustHex(t, g.NoncePrefix))

	var out bytes.Buffer
	if err := encryptV2WithSecrets(&out, bytes.NewReader(mustHex(t, g.Plaintext)), g.key(t), mustHex(t, g.AAD), salt, prefix); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), mustHex(t, g.Ciphertext)) {
		t.Fatalf("golden ciphertext mismatch\n got: %x\nwant: %s", out.Bytes(), g.Ciphertext)
	}
}

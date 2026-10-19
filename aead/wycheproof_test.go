package aead

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type wycheproofDoc struct {
	Source    string             `json:"source"`
	File      string             `json:"file"`
	Algorithm string             `json:"algorithm"`
	Vectors   []wycheproofVector `json:"vectors"`
}

type wycheproofVector struct {
	TCID    int      `json:"tcId"`
	Flags   []string `json:"flags"`
	Comment string   `json:"comment"`
	Key     string   `json:"key"`
	IV      string   `json:"iv"`
	AAD     string   `json:"aad"`
	Msg     string   `json:"msg"`
	Ct      string   `json:"ct"`
	Tag     string   `json:"tag"`
	Result  string   `json:"result"`
}

// TestWycheproofAES256GCM runs the curated Wycheproof vectors against the
// aead package. Valid vectors must round-trip and match the independently
// generated ciphertext/tag; invalid vectors must be rejected.
func TestWycheproofAES256GCM(t *testing.T) {
	doc := loadWycheproof(t)

	for _, v := range doc.Vectors {
		name := v.Result
		if v.Comment != "" {
			name += ": " + v.Comment
		}
		t.Run(name, func(t *testing.T) {
			key, err := NewKey(mustHex(t, v.Key))
			if err != nil {
				t.Fatal(err)
			}
			iv := mustHex(t, v.IV)
			aad := mustHex(t, v.AAD)
			msg := mustHex(t, v.Msg)

			switch v.Result {
			case "valid":
				if len(iv) != 12 {
					t.Skipf("non-12-byte IV vector not applicable to this API")
				}
				g, err := newGCM(key)
				if err != nil {
					t.Fatal(err)
				}
				got := sealWithNonce(g, iv, msg, aad)
				want := append(append(append([]byte{}, iv...), mustHex(t, v.Ct)...), mustHex(t, v.Tag)...)
				if !bytes.Equal(got, want) {
					t.Fatalf("seal mismatch\n got: %x\nwant: %x", got, want)
				}
				pt, err := Open(key, want, aad)
				if err != nil {
					t.Fatalf("Open rejected valid vector: %v", err)
				}
				if !bytes.Equal(pt, msg) {
					t.Fatalf("decrypt mismatch: got %x, want %x", pt, msg)
				}
			case "invalid":
				ct := append(append(append([]byte{}, iv...), mustHex(t, v.Ct)...), mustHex(t, v.Tag)...)
				if _, err := Open(key, ct, aad); !errors.Is(err, ErrAuthentication) && !errors.Is(err, ErrCiphertextTooShort) {
					t.Fatalf("Open accepted invalid vector: got err=%v", err)
				}
			}
		})
	}
}

func loadWycheproof(t *testing.T) wycheproofDoc {
	t.Helper()
	path := filepath.Join("testdata", "wycheproof_aes256_gcm.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc wycheproofDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Algorithm != "AES-256-GCM" {
		t.Fatalf("unexpected vector algorithm %q", doc.Algorithm)
	}
	return doc
}

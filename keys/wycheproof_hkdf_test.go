package keys

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

type wycheproofHKDFDoc struct {
	Source            string              `json:"source"`
	File              string              `json:"file"`
	Algorithm         string              `json:"algorithm"`
	Valid             []wycheproofHKDFVec `json:"valid"`
	SizeTooLargeBytes []int               `json:"sizeTooLargeBytes"`
}

type wycheproofHKDFVec struct {
	TCID    int      `json:"tcId"`
	Comment string   `json:"comment"`
	Flags   []string `json:"flags"`
	IKM     string   `json:"ikm"`
	Salt    string   `json:"salt"`
	Info    string   `json:"info"`
	Size    int      `json:"size"`
	OKM     string   `json:"okm"`
}

// TestWycheproofHKDFSHA256 runs the curated Wycheproof HKDF-SHA-256 vectors
// through the extract/expand primitive.
func TestWycheproofHKDFSHA256(t *testing.T) {
	doc := loadHKDFWycheproof(t)

	for _, v := range doc.Valid {
		name := v.Comment
		if name == "" {
			name = strconv.Itoa(v.TCID)
		}
		t.Run(name, func(t *testing.T) {
			var salt []byte
			if v.Salt != "" {
				salt = mustHex(t, v.Salt)
			}
			got := hkdfSHA256(mustHex(t, v.IKM), salt, mustHex(t, v.Info), v.Size)
			want := mustHex(t, v.OKM)
			if !bytes.Equal(got, want) {
				t.Fatalf("OKM mismatch\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

// TestWycheproofHKDFSizeLimit verifies the RFC 5869 output-length limit is
// enforced by DeriveKey, matching Wycheproof's SizeTooLarge cases.
func TestWycheproofHKDFSizeLimit(t *testing.T) {
	doc := loadHKDFWycheproof(t)
	if len(doc.SizeTooLargeBytes) == 0 {
		t.Fatal("expected SizeTooLarge entries in the curated vector set")
	}
	for _, size := range doc.SizeTooLargeBytes {
		if size != maxDerivedKeyLen+1 {
			t.Fatalf("unexpected too-large size %d, want %d", size, maxDerivedKeyLen+1)
		}
		if got, err := DeriveKey(bytes.Repeat([]byte{0x42}, 64), "limit", size); err == nil || got != nil {
			t.Fatalf("DeriveKey accepted length %d", size)
		}
	}
}

func loadHKDFWycheproof(t *testing.T) wycheproofHKDFDoc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "wycheproof_hkdf_sha256.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc wycheproofHKDFDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Algorithm != "HKDF-SHA-256" {
		t.Fatalf("unexpected vector algorithm %q", doc.Algorithm)
	}
	return doc
}

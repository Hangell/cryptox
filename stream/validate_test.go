package stream

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

// TestValidateHeader checks that the header-only API validates structure and
// rejects malformed or truncated headers, without claiming integrity.
func TestValidateHeader(t *testing.T) {
	dir := t.TempDir()

	// A structurally valid v1 header with no records is accepted (this is the
	// documented limitation: it proves nothing about ciphertext integrity).
	validHeader := append([]byte("SYM1\x01AESG"), make([]byte, 12)...)
	valid := filepath.Join(dir, "valid")
	writeFile(t, valid, validHeader)
	if err := ValidateHeader(valid); err != nil {
		t.Fatalf("valid header rejected: %v", err)
	}

	cases := []struct {
		name string
		data []byte
	}{
		{"too short", []byte("SYM1")},
		{"bad magic", append([]byte("BAD1\x01AESG"), make([]byte, 12)...)},
		{"bad version", append([]byte("SYM1\x02AESG"), make([]byte, 12)...)},
		{"bad alg", append([]byte("SYM1\x01XXXX"), make([]byte, 12)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			writeFile(t, path, tc.data)
			if err := ValidateHeader(path); err == nil {
				t.Fatalf("%q was accepted", tc.name)
			}
		})
	}
}

// TestValidateEncryptedFileIsAlias confirms the deprecated name delegates to
// ValidateHeader and behaves identically.
func TestValidateEncryptedFileIsAlias(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enc")
	writeFile(t, path, append([]byte("SYM1\x01AESG"), make([]byte, 12)...))

	a := ValidateHeader(path)
	b := ValidateEncryptedFile(path)
	if a != nil || b != nil {
		t.Fatalf("unexpected errors: %v, %v", a, b)
	}

	missing := filepath.Join(dir, "missing")
	if ValidateHeader(missing) == nil || ValidateEncryptedFile(missing) == nil {
		t.Fatal("missing file not rejected")
	}
}

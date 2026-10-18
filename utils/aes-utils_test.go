package utils_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Hangell/cryptox/stream"
	"github.com/Hangell/cryptox/utils"
)

func TestLegacyAPI(t *testing.T) {
	for _, keySize := range []int{16, 24, 32} {
		keySize := keySize
		for _, size := range []int{0, 1, 65535, 65536, 65537, 131073} {
			size := size
			t.Run(fmt.Sprintf("key%d/bytes%d", keySize, size), func(t *testing.T) {
				t.Parallel()
				key, err := utils.GenerateKey(keySize)
				if err != nil {
					t.Fatal(err)
				}
				if len(key) != keySize {
					t.Fatal("incorrect key length")
				}
				originalKey := append([]byte(nil), key...)
				dir := t.TempDir()
				input := filepath.Join(dir, "input")
				encrypted := filepath.Join(dir, "encrypted")
				output := filepath.Join(dir, "output")
				data := bytes.Repeat([]byte{0xa5}, size)
				writeFile(t, input, data)
				if err := utils.EncryptLargeFiles(input, encrypted, key); err != nil {
					t.Fatal(err)
				}
				if err := utils.ValidateEncryptedFile(encrypted); err != nil {
					t.Fatal(err)
				}
				if err := stream.DecryptLargeFiles(encrypted, output, key); err != nil {
					t.Fatal(err)
				}
				assertFile(t, output, data)
				if err := stream.EncryptLargeFiles(input, encrypted, key); err != nil {
					t.Fatal(err)
				}
				if err := utils.DecryptLargeFiles(encrypted, output, key); err != nil {
					t.Fatal(err)
				}
				assertFile(t, output, data)
				if !bytes.Equal(key, originalKey) {
					t.Fatal("key mutated")
				}
			})
		}
	}
}

func TestLegacyAPIErrors(t *testing.T) {
	for _, size := range []int{-1, 0, 15, 17, 23, 25, 31, 33} {
		if key, err := utils.GenerateKey(size); err == nil || key != nil {
			t.Fatalf("accepted key size %d", size)
		}
	}
	for _, operation := range []struct {
		name string
		run  func(string, string, []byte) error
	}{
		{"encrypt", utils.EncryptLargeFiles}, {"decrypt", utils.DecryptLargeFiles},
	} {
		t.Run(operation.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input")
			output := filepath.Join(dir, "output")
			writeFile(t, input, []byte("data"))
			writeFile(t, output, []byte("preserve"))
			for _, size := range []int{0, 15, 17, 33} {
				if err := operation.run(input, output, make([]byte, size)); err == nil {
					t.Fatal("accepted invalid key")
				}
				assertFile(t, output, []byte("preserve"))
			}
			if err := operation.run(filepath.Join(dir, "missing"), output, make([]byte, 32)); err == nil {
				t.Fatal("accepted missing input")
			}
			if err := operation.run(input, filepath.Join(dir, "missing", "output"), make([]byte, 32)); err == nil {
				t.Fatal("accepted missing output directory")
			}
			assertFile(t, output, []byte("preserve"))
		})
	}
	if err := utils.ValidateEncryptedFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("accepted missing file")
	}
}

func TestLegacyAuthenticationFailure(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	encrypted := filepath.Join(dir, "encrypted")
	output := filepath.Join(dir, "output")
	key := bytes.Repeat([]byte{1}, 32)
	writeFile(t, input, bytes.Repeat([]byte{42}, 65537))
	if err := utils.EncryptLargeFiles(input, encrypted, key); err != nil {
		t.Fatal(err)
	}
	writeFile(t, output, []byte("preserve"))
	if err := utils.DecryptLargeFiles(encrypted, output, bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Fatal("accepted wrong key")
	}
	assertFile(t, output, []byte("preserve"))
	data, err := os.ReadFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	writeFile(t, encrypted, data)
	// Header validation deliberately cannot detect ciphertext corruption.
	if err := utils.ValidateEncryptedFile(encrypted); err != nil {
		t.Fatal(err)
	}
	if err := utils.DecryptLargeFiles(encrypted, output, key); err == nil {
		t.Fatal("accepted modified tag")
	}
	assertFile(t, output, []byte("preserve"))
	leftovers, err := filepath.Glob(filepath.Join(dir, ".cryptox-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatal("temporary plaintext leaked")
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func assertFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("unexpected file contents")
	}
}

func TestLegacyHeaderValidation(t *testing.T) {
	header := append([]byte("SYM1\x01AESG"), make([]byte, 12)...)
	for _, offset := range []int{0, 4, 5, 17, 20} {
		data := append([]byte{}, header...)
		data[offset] ^= 1
		path := filepath.Join(t.TempDir(), "input")
		writeFile(t, path, data)
		if err := utils.ValidateEncryptedFile(path); err == nil {
			t.Fatalf("accepted modified header at %d", offset)
		}
	}
	for size := 0; size < len(header); size++ {
		path := filepath.Join(t.TempDir(), "input")
		writeFile(t, path, header[:size])
		if err := utils.ValidateEncryptedFile(path); err == nil {
			t.Fatalf("accepted header size %d", size)
		}
	}
}

// TestLegacyAPIConcurrent exercises the legacy facade from concurrent goroutines.
// It is intended to run under the race detector via `make test`.
func TestLegacyAPIConcurrent(t *testing.T) {
	const goroutines = 12

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()

			dir := t.TempDir()
			input := filepath.Join(dir, "input")
			encrypted := filepath.Join(dir, "encrypted")
			output := filepath.Join(dir, "output")

			key := make([]byte, 32)
			for i := range key {
				key[i] = byte(g) ^ byte(i)
			}
			data := bytes.Repeat([]byte{byte(g), 0x5a}, 4096+g)

			if err := os.WriteFile(input, data, 0600); err != nil {
				t.Error(err)
				return
			}
			if err := utils.EncryptLargeFiles(input, encrypted, key); err != nil {
				t.Error(err)
				return
			}
			if err := utils.DecryptLargeFiles(encrypted, output, key); err != nil {
				t.Error(err)
				return
			}
			got, err := os.ReadFile(output)
			if err != nil {
				t.Error(err)
				return
			}
			if !bytes.Equal(got, data) {
				t.Error("round trip mismatch")
			}
		}(g)
	}
	wg.Wait()
}

package stream

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFiles(t *testing.T) {
	for _, size := range []int{0, 1, chunkSize, chunkSize + 1} {
		dir := t.TempDir()
		input, encrypted, output := filepath.Join(dir, "input"), filepath.Join(dir, "encrypted"), filepath.Join(dir, "output")
		key := bytes.Repeat([]byte{1}, 32)
		data := bytes.Repeat([]byte{42}, size)
		if err := os.WriteFile(input, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := EncryptLargeFiles(input, encrypted, key); err != nil {
			t.Fatal(err)
		}
		if err := DecryptLargeFiles(encrypted, output, key); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, got) {
			t.Fatal("round trip mismatch")
		}
		stat, err := os.Stat(output)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && stat.Mode().Perm() != 0600 {
			t.Fatal("insecure output permissions")
		}
		if size == 0 {
			continue
		}
		original, err := os.ReadFile(encrypted)
		if err != nil {
			t.Fatal(err)
		}
		for _, corrupt := range [][]byte{append([]byte{}, original[:len(original)-1]...), append(append([]byte{}, original...), 1), append([]byte{}, original...)} {
			corrupt[len(corrupt)-1] ^= 1
			if err := os.WriteFile(encrypted, corrupt, 0600); err != nil {
				t.Fatal(err)
			}
			if err := DecryptLargeFiles(encrypted, output, key); err == nil {
				t.Fatal("accepted corruption")
			}
			got, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data) {
				t.Fatal("failure replaced destination")
			}
		}
		leftovers, err := filepath.Glob(filepath.Join(dir, ".cryptox-*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(leftovers) != 0 {
			t.Fatal("temporary files leaked")
		}
	}
}

func TestCounterBoundary(t *testing.T) {
	if err := checkCounter(math.MaxUint32); err != nil {
		t.Fatal(err)
	}
	if checkCounter(uint64(math.MaxUint32)+1) == nil {
		t.Fatal("counter wrap accepted")
	}
}

// TestV1TruncationLimitation records a format limitation that requires v2.
func TestV1TruncationLimitation(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output")
	header := append([]byte("SYM1\x01AESG"), make([]byte, 12)...)
	if err := os.WriteFile(input, header, 0600); err != nil {
		t.Fatal(err)
	}
	if err := DecryptLargeFiles(input, output, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
}

func FuzzDecryptV1(f *testing.F) {
	valid, key := legacyFixture(f)
	f.Add(valid)
	f.Add(valid[:headerLen])
	f.Add([]byte("SYM1"))
	oversized := append(append([]byte{}, valid[:headerLen]...), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(oversized[headerLen:], math.MaxUint32)
	f.Add(oversized)
	dir := f.TempDir()
	input, output := filepath.Join(dir, "input"), filepath.Join(dir, "output")
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2*chunkSize {
			t.Skip()
		}
		sentinel := []byte("destination must survive failure")
		if err := os.WriteFile(input, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, sentinel, 0600); err != nil {
			t.Fatal(err)
		}
		decryptErr := DecryptLargeFiles(input, output, key)
		got, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if decryptErr != nil && !bytes.Equal(got, sentinel) {
			t.Fatal("failure changed destination")
		}
		leftovers, err := filepath.Glob(filepath.Join(dir, ".cryptox-*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(leftovers) != 0 {
			t.Fatal("temporary file leaked")
		}
	})
}

// TestLegacyVector uses the AES-128-GCM zero-key, zero-nonce empty-message vector.
func TestLegacyVector(t *testing.T) {
	data, err := hex.DecodeString("53594d3101414553470000000000000000000000001000000058e2fccefa7e3061367f1d57a4e7455a")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := DecryptLargeFiles(input, output, make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("unexpected plaintext")
	}
}

func TestPublishFailureCleanup(t *testing.T) {
	for _, operation := range []struct {
		name string
		run  func(string, string, []byte) error
	}{
		{"encrypt", EncryptLargeFiles}, {"decrypt", DecryptLargeFiles},
	} {
		t.Run(operation.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input")
			target := filepath.Join(dir, "directory")
			data, key := legacyFixture(t)
			if err := os.WriteFile(input, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			if err := operation.run(input, target, key); err == nil {
				t.Fatal("replaced directory")
			}
			stat, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			if !stat.IsDir() {
				t.Fatal("destination changed")
			}
			leftovers, err := filepath.Glob(filepath.Join(dir, ".cryptox-*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(leftovers) != 0 {
				t.Fatal("failed publication leaked temporary file")
			}
		})
	}
}

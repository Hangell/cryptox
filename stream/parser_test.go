package stream

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

func legacyFixture(t testing.TB) ([]byte, []byte) {
	t.Helper()
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte("SYM1\x01AESG"), make([]byte, 12)...)
	for counter, plain := range []string{"first", "second"} {
		nonce := make([]byte, 12)
		binary.LittleEndian.PutUint32(nonce[8:], uint32(counter))
		encrypted := aead.Seal(nil, nonce, []byte(plain), nil)
		var length [4]byte
		binary.LittleEndian.PutUint32(length[:], uint32(len(encrypted)))
		data = append(data, length[:]...)
		data = append(data, encrypted...)
	}
	return data, key
}

func TestDecryptFragmentedReader(t *testing.T) {
	data, key := legacyFixture(t)
	for _, reader := range []io.Reader{iotest.OneByteReader(bytes.NewReader(data)), iotest.HalfReader(bytes.NewReader(data)), iotest.DataErrReader(bytes.NewReader(data))} {
		var output bytes.Buffer
		if err := decryptV1(reader, &output, key); err != nil {
			t.Fatal(err)
		}
		if output.String() != "firstsecond" {
			t.Fatal("fragmented read lost plaintext")
		}
	}
}

func TestDecryptMalformedRecords(t *testing.T) {
	original, key := legacyFixture(t)
	boundary := headerLen + 4 + 16 + len("first")
	cases := map[string][]byte{
		"missing header":     nil,
		"partial header":     original[:headerLen-1],
		"partial length":     original[:headerLen+3],
		"partial ciphertext": original[:boundary-1],
		"trailing byte":      append(append([]byte{}, original...), 0),
		"reordered":          append(append(append([]byte{}, original[:headerLen]...), original[boundary:]...), original[headerLen:boundary]...),
		"missing first":      append(append([]byte{}, original[:headerLen]...), original[boundary:]...),
		"duplicated":         append(append([]byte{}, original...), original[headerLen:boundary]...),
	}
	for name, offset := range map[string]int{"magic": 0, "version": 4, "algorithm": 5, "nonce": 9, "reserved": 17, "tag": boundary - 1} {
		mutated := append([]byte{}, original...)
		mutated[offset] ^= 1
		cases[name] = mutated
	}
	for name, size := range map[string]uint32{"zero length": 0, "short tag": 15, "oversized": chunkSize + 17} {
		mutated := append([]byte{}, original...)
		binary.LittleEndian.PutUint32(mutated[headerLen:], size)
		cases[name] = mutated
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if err := decryptV1(bytes.NewReader(data), io.Discard, key); err == nil {
				t.Fatal("accepted malformed record")
			}
		})
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

func TestDecryptIOErrors(t *testing.T) {
	data, key := legacyFixture(t)
	sentinel := errors.New("injected I/O failure")
	for _, offset := range []int{0, headerLen, headerLen + 4, len(data)} {
		reader := io.MultiReader(bytes.NewReader(data[:offset]), iotest.ErrReader(sentinel))
		if err := decryptV1(reader, io.Discard, key); !errors.Is(err, sentinel) {
			t.Fatalf("read error lost at %d: %v", offset, err)
		}
	}
	if err := decryptV1(bytes.NewReader(data), failingWriter{sentinel}, key); !errors.Is(err, sentinel) {
		t.Fatalf("write error lost: %v", err)
	}
	if err := decryptV1(bytes.NewReader(data), shortWriter{}, key); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write accepted: %v", err)
	}
}

// TestV1TrailingTruncation documents a residual limitation, not a security guarantee.
func TestV1TrailingTruncation(t *testing.T) {
	data, key := legacyFixture(t)
	boundary := headerLen + 4 + 16 + len("first")
	var output bytes.Buffer
	if err := decryptV1(bytes.NewReader(data[:boundary]), &output, key); err != nil {
		t.Fatal(err)
	}
	if output.String() != "first" {
		t.Fatal("unexpected legacy prefix")
	}
}

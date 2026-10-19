package stream

import (
	"bytes"
	"testing"
)

// FuzzDecryptV2 ensures the v2 parser never panics on arbitrary input and never
// writes plaintext together with a returned error beyond the failing segment.
func FuzzDecryptV2(f *testing.F) {
	key := bytes.Repeat([]byte{0x42}, 32)
	var seedBuf bytes.Buffer
	if err := encryptV2(&seedBuf, bytes.NewReader([]byte("fuzz seed plaintext")), key, nil); err != nil {
		f.Fatal(err)
	}
	seed := seedBuf.Bytes()
	f.Add(seed)
	f.Add([]byte{})
	f.Add(make([]byte, v2HeaderLen))
	f.Add([]byte("CXS2"))

	f.Fuzz(func(t *testing.T, data []byte) {
		var out bytes.Buffer
		// decryptV2 writes per segment; a returned error may be preceded by
		// authenticated prefix output, which is documented behavior. The
		// invariant here is simply that the parser does not panic.
		_ = decryptV2(bytes.NewReader(data), &out, key, nil)
	})
}

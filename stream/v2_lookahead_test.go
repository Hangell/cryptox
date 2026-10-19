package stream

import (
	"bytes"
	"errors"
	"testing"
)

// errSentinel is a non-EOF error used to assert that I/O errors from the
// underlying source are propagated rather than silently treated as
// end-of-stream by the final-segment lookahead.
var errSentinel = errors.New("sentinel source error")

// errorAfterReader returns data byte-for-byte and then err forever.
type errorAfterReader struct {
	data []byte
	err  error
}

func (r *errorAfterReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestEncryptV2PropagatesNonEOFSourceError(t *testing.T) {
	key := make([]byte, 32)
	src := &errorAfterReader{data: make([]byte, v2SegmentSize), err: errSentinel}
	var out bytes.Buffer
	if err := encryptV2(&out, src, key, nil); !errors.Is(err, errSentinel) {
		t.Fatalf("encryptV2 error = %v, want wrapped sentinel", err)
	}
}

func TestDecryptV2PropagatesNonEOFSourceError(t *testing.T) {
	key := make([]byte, 32)
	var salt [v2SaltLen]byte
	var prefix [v2NoncePrefixLen]byte
	hdr := buildV2Header(salt, prefix)

	g, err := newV2GCM(v2DeriveKey(key, salt, nil))
	if err != nil {
		t.Fatal(err)
	}
	var seg bytes.Buffer
	if err := writeV2Segment(&seg, g, prefix, 0, false, make([]byte, v2SegmentSize)); err != nil {
		t.Fatal(err)
	}

	data := append(append([]byte{}, hdr[:]...), seg.Bytes()...)
	src := &errorAfterReader{data: data, err: errSentinel}
	var out bytes.Buffer
	if err := decryptV2(src, &out, key, nil); !errors.Is(err, errSentinel) {
		t.Fatalf("decryptV2 error = %v, want wrapped sentinel", err)
	}
}

func TestDecryptorPropagatesNonEOFSourceError(t *testing.T) {
	key := make([]byte, 32)
	var salt [v2SaltLen]byte
	var prefix [v2NoncePrefixLen]byte
	hdr := buildV2Header(salt, prefix)

	g, err := newV2GCM(v2DeriveKey(key, salt, nil))
	if err != nil {
		t.Fatal(err)
	}
	var seg bytes.Buffer
	if err := writeV2Segment(&seg, g, prefix, 0, false, make([]byte, v2SegmentSize)); err != nil {
		t.Fatal(err)
	}

	data := append(append([]byte{}, hdr[:]...), seg.Bytes()...)
	src := &errorAfterReader{data: data, err: errSentinel}
	d, err := NewDecryptor(src, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	for {
		if _, err := d.Read(buf); err != nil {
			if !errors.Is(err, errSentinel) {
				t.Fatalf("Decryptor.Read error = %v, want wrapped sentinel", err)
			}
			return
		}
	}
}

// Regression: clean EOF after a full non-final segment is still treated as the
// final segment (no error), so the fix does not break normal finalization.
func TestPeekCleanEOFRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	var out bytes.Buffer
	if err := encryptV2(&out, bytes.NewReader(make([]byte, v2SegmentSize)), key, nil); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if err := decryptV2(bytes.NewReader(out.Bytes()), &dec, key, nil); err != nil {
		t.Fatalf("decryptV2: %v", err)
	}
	if !bytes.Equal(dec.Bytes(), make([]byte, v2SegmentSize)) {
		t.Fatal("plaintext mismatch")
	}
}

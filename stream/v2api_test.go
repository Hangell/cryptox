package stream

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func v2Encrypt(t *testing.T, plaintext, key, aad []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	e, err := NewEncryptor(&out, key, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func v2DecryptAll(t *testing.T, ciphertext, key, aad []byte) ([]byte, error) {
	t.Helper()
	d, err := NewDecryptor(bytes.NewReader(ciphertext), key, aad)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(d)
}

func TestV2ErrorClassification(t *testing.T) {
	key := bytes.Repeat([]byte{0x81}, 32)
	aad := []byte("aad")
	pt := bytes.Repeat([]byte{0x82}, v2SegmentSize+7)
	ct := v2Encrypt(t, pt, key, aad)

	// ErrInvalidKey.
	if _, err := NewEncryptor(&bytes.Buffer{}, make([]byte, 16), aad); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewEncryptor short key: got %v", err)
	}
	if _, err := NewDecryptor(bytes.NewReader(ct), make([]byte, 16), aad); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("NewDecryptor short key: got %v", err)
	}

	// ErrUnsupported: unknown version byte.
	badVersion := append([]byte(nil), ct...)
	badVersion[4] ^= 0x01
	if _, err := NewDecryptor(bytes.NewReader(badVersion), key, aad); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown version: got %v", err)
	}

	// ErrMalformed: unknown magic byte.
	badMagic := append([]byte(nil), ct...)
	badMagic[0] ^= 0x01
	if _, err := NewDecryptor(bytes.NewReader(badMagic), key, aad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad magic: got %v", err)
	}

	// ErrTruncated (header): header shorter than the fixed v2 header.
	if _, err := NewDecryptor(bytes.NewReader(ct[:5]), key, aad); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short header: got %v", err)
	}

	// ErrTruncated (segment): final segment shorter than an authentication tag.
	// The stream is header || full non-final segment || 23-byte final segment;
	// removing 13 bytes leaves 10 bytes of the final segment (< 16-byte tag).
	if _, err := v2DecryptAll(t, ct[:len(ct)-13], key, aad); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short final segment: got %v", err)
	}

	// ErrAuthentication: flip a byte inside the first segment ciphertext.
	badSeg := append([]byte(nil), ct...)
	badSeg[v2HeaderLen+5] ^= 0x01
	if _, err := v2DecryptAll(t, badSeg, key, aad); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered segment: got %v", err)
	}
}

func TestV2AADSizeLimit(t *testing.T) {
	key := bytes.Repeat([]byte{0x81}, 32)
	maxAAD := bytes.Repeat([]byte{0x42}, MaxV2AADSize)
	tooLargeAAD := bytes.Repeat([]byte{0x42}, MaxV2AADSize+1)

	var ciphertext bytes.Buffer
	e, err := NewEncryptor(&ciphertext, key, maxAAD)
	if err != nil {
		t.Fatalf("NewEncryptor rejected maximum AAD: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close with maximum AAD: %v", err)
	}
	d, err := NewDecryptor(bytes.NewReader(ciphertext.Bytes()), key, maxAAD)
	if err != nil {
		t.Fatalf("NewDecryptor rejected maximum AAD: %v", err)
	}
	if _, err := io.ReadAll(d); err != nil {
		t.Fatalf("Decryptor with maximum AAD: %v", err)
	}

	var oversizedOutput bytes.Buffer
	if _, err := NewEncryptor(&oversizedOutput, key, tooLargeAAD); !errors.Is(err, ErrAADTooLarge) {
		t.Fatalf("NewEncryptor oversized AAD: got %v, want ErrAADTooLarge", err)
	}
	if oversizedOutput.Len() != 0 {
		t.Fatalf("NewEncryptor wrote %d bytes before rejecting oversized AAD", oversizedOutput.Len())
	}
	if _, err := NewDecryptor(bytes.NewReader(nil), key, tooLargeAAD); !errors.Is(err, ErrAADTooLarge) {
		t.Fatalf("NewDecryptor oversized AAD: got %v, want ErrAADTooLarge", err)
	}
	if err := encryptV2(&bytes.Buffer{}, bytes.NewReader(nil), key, tooLargeAAD); !errors.Is(err, ErrAADTooLarge) {
		t.Fatalf("encryptV2 oversized AAD: got %v, want ErrAADTooLarge", err)
	}
	if err := decryptV2(bytes.NewReader(nil), &bytes.Buffer{}, key, tooLargeAAD); !errors.Is(err, ErrAADTooLarge) {
		t.Fatalf("decryptV2 oversized AAD: got %v, want ErrAADTooLarge", err)
	}
}

func TestEncryptorDecryptorRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	aad := []byte("aad")
	sizes := []int{0, 1, 100, v2SegmentSize - 1, v2SegmentSize, v2SegmentSize + 1, 2*v2SegmentSize + 7}
	for _, size := range sizes {
		pt := bytes.Repeat([]byte{0x6b}, size)
		ct := v2Encrypt(t, pt, key, aad)
		got, err := v2DecryptAll(t, ct, key, aad)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("size %d: mismatch", size)
		}
	}
}

func TestEncryptorExactMultipleOfSegmentSize(t *testing.T) {
	// Regression test for the independent review finding: the public Encryptor
	// used to emit a 0-byte final segment for streams that are an exact
	// multiple of the 64 KiB segment size, diverging from the format produced
	// by encryptV2WithSecrets. Both paths must now yield exactly n segments
	// (the trailing full segment carrying the final flag), i.e. no extra
	// empty final record.
	key := bytes.Repeat([]byte{0x11}, 32)
	aad := []byte("associated data")
	for _, n := range []int{1, 2, 3} {
		pt := bytes.Repeat([]byte{0x22}, n*v2SegmentSize)

		ct := v2Encrypt(t, pt, key, aad)
		wantLen := v2HeaderLen + n*(v2SegmentSize+v2TagSize)
		if len(ct) != wantLen {
			t.Fatalf("Encryptor: %d full segments produced %d bytes, want %d (extra empty final segment)", n, len(ct), wantLen)
		}

		// Cross-check against the core path with fixed randomizer values.
		var salt [v2SaltLen]byte
		var prefix [v2NoncePrefixLen]byte
		var core bytes.Buffer
		if err := encryptV2WithSecrets(&core, bytes.NewReader(pt), key, aad, salt, prefix); err != nil {
			t.Fatal(err)
		}
		if len(core.Bytes()) != wantLen {
			t.Fatalf("encryptV2WithSecrets: %d full segments produced %d bytes, want %d", n, len(core.Bytes()), wantLen)
		}

		got, err := v2DecryptAll(t, ct, key, aad)
		if err != nil {
			t.Fatalf("round trip (n=%d): %v", n, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round trip (n=%d): mismatch", n)
		}
	}
}

func TestDecryptorEOFOnlyAfterFinalSegment(t *testing.T) {
	key := bytes.Repeat([]byte{0x5b}, 32)
	pt := bytes.Repeat([]byte{0x01}, 3*v2SegmentSize+123)
	ct := v2Encrypt(t, pt, key, nil)

	d, err := NewDecryptor(bytes.NewReader(ct), key, nil)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, v2SegmentSize/2)
	var total int
	for {
		n, err := d.Read(buf)
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if total != len(pt) {
		t.Fatalf("decrypted %d bytes, want %d", total, len(pt))
	}
}

func TestDecryptorRejectsTrailingDataAfterFinalSegment(t *testing.T) {
	key := bytes.Repeat([]byte{0x66}, 32)
	for _, size := range []int{0, 1, v2SegmentSize, v2SegmentSize + 7} {
		ct := v2Encrypt(t, bytes.Repeat([]byte{0x77}, size), key, nil)
		tampered := append(append([]byte(nil), ct...), 0xde, 0xad, 0xbe, 0xef)
		got, err := v2DecryptAll(t, tampered, key, nil)
		if err == nil {
			t.Fatalf("size %d: trailing data after final segment was accepted (%d bytes)", size, len(got))
		}
		if errors.Is(err, io.EOF) {
			t.Fatalf("size %d: trailing data reported as io.EOF instead of an integrity error", size)
		}
	}
}

func TestDecryptorTruncationReturnsErrorNotEOF(t *testing.T) {
	key := bytes.Repeat([]byte{0x5c}, 32)
	ct := v2Encrypt(t, bytes.Repeat([]byte{0x02}, v2SegmentSize+10), key, nil)

	// Remove the final record entirely.
	truncated := ct[:len(ct)-(10+v2TagSize)]
	d, err := NewDecryptor(bytes.NewReader(truncated), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(d)
	if err == nil {
		t.Fatalf("truncated stream returned io.EOF (got %d bytes)", len(got))
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("truncated stream reported io.EOF instead of an integrity error")
	}
}

func TestFragmentedIO(t *testing.T) {
	key := bytes.Repeat([]byte{0x5d}, 32)
	pt := bytes.Repeat([]byte{0x03}, 2*v2SegmentSize+37)

	// Encrypt into a writer that accepts one byte per Write call.
	var slow bytes.Buffer
	oneByteWriter := &chunkWriter{w: &slow, n: 1}
	e, err := NewEncryptor(oneByteWriter, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Write(pt); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}

	// Decrypt from a reader that yields one byte per Read call.
	d, err := NewDecryptor(&chunkReader{r: bytes.NewReader(slow.Bytes()), n: 1}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("fragmented round trip mismatch: %d vs %d", len(got), len(pt))
	}
}

func TestEncryptorCloseIsMandatory(t *testing.T) {
	key := bytes.Repeat([]byte{0x5e}, 32)
	var out bytes.Buffer
	e, err := NewEncryptor(&out, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Write([]byte("some plaintext")); err != nil {
		t.Fatal(err)
	}
	// Do NOT call Close: the output has no authenticated final segment.
	d, err := NewDecryptor(bytes.NewReader(out.Bytes()), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(d); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("unfinalized stream was accepted (err=%v)", err)
	}
}

func TestWriteAfterCloseRejected(t *testing.T) {
	key := bytes.Repeat([]byte{0x5f}, 32)
	var out bytes.Buffer
	e, err := NewEncryptor(&out, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Write([]byte("late")); err == nil {
		t.Fatal("Write after Close was accepted")
	}
}

func TestV2APIRejectsShortKey(t *testing.T) {
	if _, err := NewEncryptor(&bytes.Buffer{}, make([]byte, 16), nil); err == nil {
		t.Fatal("NewEncryptor accepted a 16-byte key")
	}
	if _, err := NewDecryptor(bytes.NewReader(nil), make([]byte, 16), nil); err == nil {
		t.Fatal("NewDecryptor accepted a 16-byte key")
	}
}

func TestNewDecryptorRejectsTamperedHeader(t *testing.T) {
	key := bytes.Repeat([]byte{0x60}, 32)
	ct := v2Encrypt(t, []byte("data"), key, nil)

	// Structural fields (magic/version/suite/saltLen) fail at construction.
	for i := 0; i < 7; i++ {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		if _, err := NewDecryptor(bytes.NewReader(bad), key, nil); err == nil {
			t.Fatalf("tampered structural header byte %d accepted at construction", i)
		}
	}

	// Salt and nonce-prefix tampering is bound through key derivation and the
	// segment nonce, so it fails on the first Read rather than construction.
	for i := 7; i < v2HeaderLen; i++ {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		d, err := NewDecryptor(bytes.NewReader(bad), key, nil)
		if err != nil {
			t.Fatalf("tampered header byte %d unexpectedly failed at construction: %v", i, err)
		}
		if _, err := io.ReadAll(d); err == nil {
			t.Fatalf("tampered header byte %d was accepted", i)
		}
	}
}

func TestDecryptorWrongKeyFails(t *testing.T) {
	key := bytes.Repeat([]byte{0x61}, 32)
	ct := v2Encrypt(t, []byte("secret"), key, nil)

	d, err := NewDecryptor(bytes.NewReader(ct), bytes.Repeat([]byte{0x62}, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(d); err == nil {
		t.Fatal("wrong key accepted")
	}
}

// chunkWriter limits each Write to n bytes.
type chunkWriter struct {
	w io.Writer
	n int
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	if len(p) > c.n {
		p = p[:c.n]
	}
	return c.w.Write(p)
}

// chunkReader limits each Read to n bytes.
type chunkReader struct {
	r io.Reader
	n int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(p) > c.n {
		p = p[:c.n]
	}
	return c.r.Read(p)
}

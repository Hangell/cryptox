package stream

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

func roundTripV2(t *testing.T, plaintext, aad []byte) (ciphertext []byte, key []byte) {
	t.Helper()
	key = bytes.Repeat([]byte{0x42}, 32)
	var out bytes.Buffer
	if err := encryptV2(&out, bytes.NewReader(plaintext), key, aad); err != nil {
		t.Fatalf("encryptV2: %v", err)
	}
	ciphertext = out.Bytes()

	var got bytes.Buffer
	if err := decryptV2(bytes.NewReader(ciphertext), &got, key, aad); err != nil {
		t.Fatalf("decryptV2: %v", err)
	}
	if !bytes.Equal(got.Bytes(), plaintext) {
		t.Fatalf("round trip mismatch: got %d bytes, want %d", got.Len(), len(plaintext))
	}
	return ciphertext, key
}

func TestV2RoundTrip(t *testing.T) {
	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"1B", 1},
		{"100B", 100},
		{"segment-1", v2SegmentSize - 1},
		{"segment", v2SegmentSize},
		{"segment+1", v2SegmentSize + 1},
		{"multi", 3*v2SegmentSize + 100},
	}
	for _, tc := range sizes {
		pt := bytes.Repeat([]byte{0xab}, tc.size)
		t.Run(tc.name, func(t *testing.T) {
			roundTripV2(t, pt, []byte("aad"))
		})
	}
}

func TestV2LargeRoundTrip(t *testing.T) {
	pt := bytes.Repeat([]byte{0xcd}, 1024*1024+7)
	roundTripV2(t, pt, nil)
}

func TestV2EmptyStreamAuthenticatesKey(t *testing.T) {
	ct, _ := roundTripV2(t, nil, nil)
	if len(ct) != v2HeaderLen+v2TagSize {
		t.Fatalf("empty stream length = %d, want %d", len(ct), v2HeaderLen+v2TagSize)
	}

	wrong := bytes.Repeat([]byte{0x43}, 32)
	var out bytes.Buffer
	if err := decryptV2(bytes.NewReader(ct), &out, wrong, nil); err == nil {
		t.Fatal("empty stream accepted a wrong key")
	}
}

func TestV2TruncationDetected(t *testing.T) {
	pt := bytes.Repeat([]byte{0x01}, 3*v2SegmentSize+100)
	ct, key := roundTripV2(t, pt, nil)

	// Removing the final complete record (100 + tag) leaves non-final segments.
	truncated := ct[:len(ct)-(100+v2TagSize)]
	var out bytes.Buffer
	if err := decryptV2(bytes.NewReader(truncated), &out, key, nil); err == nil {
		t.Fatal("removing the final record was accepted")
	}

	// Removing just one byte of the final tag must also fail.
	var out2 bytes.Buffer
	if err := decryptV2(bytes.NewReader(ct[:len(ct)-1]), &out2, key, nil); err == nil {
		t.Fatal("removing one tag byte was accepted")
	}

	// Header only is a truncation.
	var out3 bytes.Buffer
	if err := decryptV2(bytes.NewReader(ct[:v2HeaderLen]), &out3, key, nil); err == nil {
		t.Fatal("header-only ciphertext was accepted")
	}
}

func TestV2ReorderDuplicateMissingDetected(t *testing.T) {
	const full = v2SegmentSize + v2TagSize
	pt := bytes.Repeat([]byte{0x02}, 3*v2SegmentSize+100)
	ct, key := roundTripV2(t, pt, nil)

	seg := func(i int) []byte {
		start := v2HeaderLen + i*full
		return append([]byte(nil), ct[start:start+full]...)
	}

	// Reorder: swap segment 0 and 1.
	reordered := append([]byte(nil), ct[:v2HeaderLen]...)
	reordered = append(reordered, seg(1)...)
	reordered = append(reordered, seg(0)...)
	reordered = append(reordered, ct[v2HeaderLen+2*full:]...)
	var out bytes.Buffer
	if err := decryptV2(bytes.NewReader(reordered), &out, key, nil); err == nil {
		t.Fatal("reordered segments were accepted")
	}

	// Duplicate: segment 0 appears twice.
	duplicated := append([]byte(nil), ct[:v2HeaderLen]...)
	duplicated = append(duplicated, seg(0)...)
	duplicated = append(duplicated, seg(0)...)
	duplicated = append(duplicated, ct[v2HeaderLen+2*full:]...)
	var out2 bytes.Buffer
	if err := decryptV2(bytes.NewReader(duplicated), &out2, key, nil); err == nil {
		t.Fatal("duplicated segment was accepted")
	}

	// Missing: drop segment 1.
	missing := append([]byte(nil), ct[:v2HeaderLen]...)
	missing = append(missing, seg(0)...)
	missing = append(missing, ct[v2HeaderLen+2*full:]...)
	var out3 bytes.Buffer
	if err := decryptV2(bytes.NewReader(missing), &out3, key, nil); err == nil {
		t.Fatal("missing segment was accepted")
	}
}

func TestV2RejectsTrailingDataAfterFinalSegment(t *testing.T) {
	// The format contract (design review §4) requires decryption to reject a
	// final segment followed by any further segment. Appended bytes change the
	// final segment's ciphertext boundary or its final-flag IV, so GCM
	// authentication must fail; this locks that fail-closed behavior.
	for _, size := range []int{0, 1, v2SegmentSize - 1, v2SegmentSize, 2*v2SegmentSize + 3} {
		ct, key := roundTripV2(t, bytes.Repeat([]byte{0x09}, size), nil)
		tampered := append(append([]byte(nil), ct...), 0xde, 0xad, 0xbe, 0xef)
		var out bytes.Buffer
		if err := decryptV2(bytes.NewReader(tampered), &out, key, nil); err == nil {
			t.Fatalf("size %d: trailing data after final segment was accepted", size)
		}
	}
}

func TestV2HeaderTamperDetected(t *testing.T) {
	ct, key := roundTripV2(t, []byte("header tamper test"), []byte("aad"))

	for i := 7; i < v2HeaderLen; i++ {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		var out bytes.Buffer
		if err := decryptV2(bytes.NewReader(bad), &out, key, []byte("aad")); err == nil {
			t.Fatalf("tampered header byte %d was accepted", i)
		}
	}
	// Version and suite tampering is rejected at parse time.
	for _, i := range []int{4, 5} {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		var out bytes.Buffer
		if err := decryptV2(bytes.NewReader(bad), &out, key, []byte("aad")); err == nil {
			t.Fatalf("tampered header field %d was accepted", i)
		}
	}
}

func TestV2WrongAADDetected(t *testing.T) {
	ct, key := roundTripV2(t, []byte("aad test"), []byte("right-aad"))
	var out bytes.Buffer
	if err := decryptV2(bytes.NewReader(ct), &out, key, []byte("wrong-aad")); err == nil {
		t.Fatal("wrong AAD was accepted")
	}
}

func TestV2AndV1AreDistinct(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("format separation")

	var v2ct bytes.Buffer
	if err := encryptV2(&v2ct, bytes.NewReader(plaintext), key, nil); err != nil {
		t.Fatal(err)
	}

	// v1 decryption must reject the v2 format.
	var out bytes.Buffer
	if err := decryptV1(bytes.NewReader(v2ct.Bytes()), &out, key); err == nil {
		t.Fatal("v1 decryption accepted a v2 stream")
	}

	// v2 decryption must reject a v1 stream.
	v1ct, _ := legacyFixture(t)
	var out2 bytes.Buffer
	if err := decryptV2(bytes.NewReader(v1ct), &out2, key, nil); err == nil {
		t.Fatal("v2 decryption accepted a v1 stream")
	}
}

func TestV2RejectsShortKey(t *testing.T) {
	var buf bytes.Buffer
	if err := encryptV2(&buf, bytes.NewReader(nil), make([]byte, 16), nil); err == nil {
		t.Fatal("encryptV2 accepted a 16-byte key")
	}
	if err := decryptV2(bytes.NewReader(nil), &buf, make([]byte, 16), nil); err == nil {
		t.Fatal("decryptV2 accepted a 16-byte key")
	}
}

func TestStreamHKDFSHA256RFC5869(t *testing.T) {
	cases := []struct {
		name   string
		ikm    string
		salt   string
		info   string
		length int
		okm    string
	}{
		{
			name:   "A.1",
			ikm:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:   "000102030405060708090a0b0c",
			info:   "f0f1f2f3f4f5f6f7f8f9",
			length: 42,
			okm:    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			name: "A.2",
			ikm: "000102030405060708090a0b0c0d0e0f" +
				"101112131415161718191a1b1c1d1e1f" +
				"202122232425262728292a2b2c2d2e2f" +
				"303132333435363738393a3b3c3d3e3f" +
				"404142434445464748494a4b4c4d4e4f",
			salt: "606162636465666768696a6b6c6d6e6f" +
				"707172737475767778797a7b7c7d7e7f" +
				"808182838485868788898a8b8c8d8e8f" +
				"909192939495969798999a9b9c9d9e9f" +
				"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
				"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
				"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
				"e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
				"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			length: 82,
			okm: "b11e398dc80327a1c8e7f78c596a4934" +
				"4f012eda2d4efad8a050cc4c19afa97c" +
				"59045a99cac7827271cb41c65e590e09" +
				"da3275600c2f09b8367793a9aca3db71" +
				"cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
		{
			name:   "A.3",
			ikm:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			salt:   "",
			info:   "",
			length: 42,
			okm:    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var salt []byte
			if tc.salt != "" {
				salt = mustHex(t, tc.salt)
			}
			got := streamHKDFSHA256(mustHex(t, tc.ikm), salt, mustHex(t, tc.info), tc.length)
			if !bytes.Equal(got, mustHex(t, tc.okm)) {
				t.Fatalf("OKM mismatch\n got: %x\nwant: %x", got, mustHex(t, tc.okm))
			}
		})
	}
}

// TestV2DeriveKeyIndependentVector pins the per-stream derived key for fixed
// inputs, computed independently with Python's hashlib/hmac (HKDF-SHA-256).
func TestV2DeriveKeyIndependentVector(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	saltBytes := mustHex(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	var salt [v2SaltLen]byte
	copy(salt[:], saltBytes)

	got := v2DeriveKey(key, salt, []byte("test-aad"))
	want := mustHex(t, "fce06383351e17088cfbe515b2d27100ac668e98c2945f867dbeb9dfd2b86d4a")
	if !bytes.Equal(got, want) {
		t.Fatalf("derived key mismatch\n got: %x\nwant: %x", got, want)
	}
}

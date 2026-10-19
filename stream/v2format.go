package stream

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// v2TagSize is the AES-GCM authentication tag size.
const v2TagSize = 16

// encryptV2 streams plaintext from src into dst in the v2 format specified in
// docs/security/v2-streaming-design-review.md. It authenticates the complete
// stream: the final segment is marked in its nonce, so removing, reordering,
// duplicating, or truncating records fails decryption.
func encryptV2(dst io.Writer, src io.Reader, key, aad []byte) error {
	if len(key) != 32 {
		return ErrInvalidKey
	}

	var salt [v2SaltLen]byte
	var noncePrefix [v2NoncePrefixLen]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return fmt.Errorf("v2: generate salt: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, noncePrefix[:]); err != nil {
		return fmt.Errorf("v2: generate nonce prefix: %w", err)
	}

	return encryptV2WithSecrets(dst, src, key, aad, salt, noncePrefix)
}

// encryptV2WithSecrets is encryptV2 with explicit salt and nonce prefix. It
// exists so golden tests can produce deterministic ciphertext with fixed
// secrets; production callers go through encryptV2.
func encryptV2WithSecrets(dst io.Writer, src io.Reader, key, aad []byte, salt [v2SaltLen]byte, noncePrefix [v2NoncePrefixLen]byte) error {
	if len(key) != 32 {
		return ErrInvalidKey
	}

	hdr := buildV2Header(salt, noncePrefix)
	derived := v2DeriveKey(key, salt, aad)
	g, err := newV2GCM(derived)
	if err != nil {
		return err
	}

	if _, err := dst.Write(hdr[:]); err != nil {
		return fmt.Errorf("v2: write header: %w", err)
	}

	br := bufio.NewReaderSize(src, v2SegmentSize)
	buf := make([]byte, v2SegmentSize)
	var counter uint64
	for {
		if err := checkCounter(counter); err != nil {
			return err
		}

		n, readErr := io.ReadFull(br, buf)
		var data []byte
		var final bool
		switch readErr {
		case nil:
			data = buf[:n]
			// A full-size segment is final only when no more input follows.
			if _, perr := br.Peek(1); perr != nil {
				final = true
			}
		case io.ErrUnexpectedEOF:
			data = buf[:n]
			final = true
		case io.EOF:
			data = nil
			final = true
		default:
			return fmt.Errorf("v2: read plaintext: %w", readErr)
		}

		if err := writeV2Segment(dst, g, noncePrefix, uint32(counter), final, data); err != nil {
			return err
		}
		if final {
			return nil
		}
		counter++
	}
}

// decryptV2 decrypts a v2 stream from src into dst. It fails closed on any
// truncation, reordering, duplication, modification, header tampering, or
// authentication failure, and never writes plaintext past a failed segment.
func decryptV2(src io.Reader, dst io.Writer, key, aad []byte) error {
	if len(key) != 32 {
		return ErrInvalidKey
	}

	hdr := make([]byte, v2HeaderLen)
	if _, err := io.ReadFull(src, hdr); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: truncated header", ErrTruncated)
		}
		return fmt.Errorf("v2: read header: %w", err)
	}
	salt, noncePrefix, err := parseV2Header(hdr)
	if err != nil {
		return err
	}

	derived := v2DeriveKey(key, salt, aad)
	g, err := newV2GCM(derived)
	if err != nil {
		return err
	}

	br := bufio.NewReaderSize(src, v2SegmentSize+v2TagSize)
	buf := make([]byte, v2SegmentSize+v2TagSize)
	var counter uint64
	for {
		if err := checkCounter(counter); err != nil {
			return err
		}

		n, readErr := io.ReadFull(br, buf)
		var final bool
		switch readErr {
		case nil:
			// A full-size segment is final only when no more data follows.
			// Trailing bytes keep it non-final, so the next read either fails
			// short (truncation) or GCM authentication fails; appended data is
			// never silently accepted after the final segment.
			if _, perr := br.Peek(1); perr != nil {
				final = true
			}
		case io.ErrUnexpectedEOF:
			if n < v2TagSize {
				return fmt.Errorf("%w: final segment shorter than authentication tag", ErrTruncated)
			}
			final = true
		case io.EOF:
			return fmt.Errorf("%w: missing authenticated final segment", ErrTruncated)
		default:
			return fmt.Errorf("v2: read segment: %w", readErr)
		}

		plaintext, err := openV2Segment(g, noncePrefix, uint32(counter), final, buf[:n])
		if err != nil {
			return fmt.Errorf("%w: segment %d: %v", ErrAuthentication, counter, err)
		}
		if _, err := dst.Write(plaintext); err != nil {
			return fmt.Errorf("v2: write plaintext: %w", err)
		}
		if final {
			return nil
		}
		counter++
	}
}

// v2DeriveKey derives the per-stream 32-byte AES key from the root key and the
// header salt, binding the format version, suite, and AAD through HKDF info.
func v2DeriveKey(key []byte, salt [v2SaltLen]byte, aad []byte) []byte {
	info := v2DomainSep(v2Version, v2SuiteAES256GCMHKDFSHA256, aad)
	return streamHKDFSHA256(key, salt[:], info, 32)
}

func newV2GCM(derived []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if g.NonceSize() != 12 {
		return nil, errors.New("v2: unexpected GCM nonce size")
	}
	return g, nil
}

func writeV2Segment(dst io.Writer, g cipher.AEAD, noncePrefix [v2NoncePrefixLen]byte, counter uint32, final bool, data []byte) error {
	iv := v2SegmentIV(noncePrefix, counter, final)
	ct := g.Seal(nil, iv[:], data, nil)
	if _, err := dst.Write(ct); err != nil {
		return fmt.Errorf("v2: write segment: %w", err)
	}
	return nil
}

func openV2Segment(g cipher.AEAD, noncePrefix [v2NoncePrefixLen]byte, counter uint32, final bool, ct []byte) ([]byte, error) {
	iv := v2SegmentIV(noncePrefix, counter, final)
	return g.Open(nil, iv[:], ct, nil)
}

// streamHKDFSHA256 implements HKDF-SHA-256 (RFC 5869) over stdlib HMAC. It is
// kept local to stream to avoid exporting a generic key-derivation API; the
// purpose-separated public API lives in package keys.
//
// Duplication review (P1.25): this mirrors keys.hkdfSHA256 byte-for-byte for
// the same inputs. Both are verified against RFC 5869 (keys A.1–A.3, stream
// A.1–A.3) and against Wycheproof HKDF-SHA-256 (keys). No divergence was found;
// the duplication is intentional and is not refactored cosmetically at this
// stage. The stream variant is only called with a fixed 32-byte output, while
// keys.DeriveKey enforces the RFC 5869 length limits.
func streamHKDFSHA256(ikm, salt, info []byte, length int) []byte {
	hashLen := sha256.Size
	if salt == nil {
		salt = make([]byte, hashLen)
	}
	prk := streamHMACSHA256(salt, ikm)

	out := make([]byte, 0, length)
	var t []byte
	for i := 1; len(out) < length; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{byte(i)})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

func streamHMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

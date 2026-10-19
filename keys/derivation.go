package keys

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Derivation limits for the HKDF-SHA-256 construction (RFC 5869).
const (
	// minDerivedKeyLen enforces at least 128-bit derived key material.
	minDerivedKeyLen = 16
	// maxDerivedKeyLen is RFC 5869's 255 * HashLen for SHA-256.
	maxDerivedKeyLen = 255 * sha256.Size
	// derivationLabel is the fixed domain-separation label prepended to every
	// Purpose in the HKDF info string.
	derivationLabel = "cryptox/v1/kdf"
)

// Errors returned by DeriveKey. Callers can classify failures with errors.Is.
var (
	// ErrInvalidKeyMaterial indicates root has less than 256 bits of entropy.
	ErrInvalidKeyMaterial = errors.New("keys: root keying material must be at least 32 bytes")
	// ErrInvalidPurpose indicates an empty, NUL-containing, non-printable, or
	// over-long purpose.
	ErrInvalidPurpose = errors.New("keys: invalid purpose")
	// ErrInvalidLength indicates the derived length is outside [16, 255*32].
	ErrInvalidLength = errors.New("keys: invalid derived key length")
)

// Purpose identifies a key-derivation context. DeriveKey domain-separates every
// Purpose, so keys derived for different purposes are independent even from the
// same root material.
type Purpose string

// DeriveKey derives length bytes of key material from root using HKDF-SHA-256
// (RFC 5869) with an empty salt and an info string bound to purpose.
//
// root is secret input keying material (IKM) with at least 256 bits of entropy.
// Callers must keep it secret and minimize its lifetime; Go does not guarantee
// memory erasure. This is not a password-based KDF: use a dedicated password
// KDF for low-entropy passphrases.
func DeriveKey(root []byte, purpose Purpose, length int) ([]byte, error) {
	if len(root) < 32 {
		return nil, ErrInvalidKeyMaterial
	}
	if err := validatePurpose(purpose); err != nil {
		return nil, err
	}
	if length < minDerivedKeyLen || length > maxDerivedKeyLen {
		return nil, fmt.Errorf("%w: must be in [%d, %d], got %d",
			ErrInvalidLength, minDerivedKeyLen, maxDerivedKeyLen, length)
	}

	info := make([]byte, 0, len(derivationLabel)+1+len(purpose))
	info = append(info, derivationLabel...)
	info = append(info, 0x00)
	info = append(info, purpose...)

	return hkdfSHA256(root, nil, info, length), nil
}

// validatePurpose rejects purposes that could make the domain-separation label
// ambiguous or unreadable. Every rejection wraps ErrInvalidPurpose.
func validatePurpose(p Purpose) error {
	if len(p) == 0 {
		return fmt.Errorf("%w: must not be empty", ErrInvalidPurpose)
	}
	if len(p) > 255 {
		return fmt.Errorf("%w: must be at most 255 bytes", ErrInvalidPurpose)
	}
	for _, b := range []byte(p) {
		if b == 0x00 {
			return fmt.Errorf("%w: must not contain NUL", ErrInvalidPurpose)
		}
		if b < 0x20 || b > 0x7e {
			return fmt.Errorf("%w: must be printable ASCII", ErrInvalidPurpose)
		}
	}
	return nil
}

// hkdfSHA256 implements HKDF-SHA-256 (RFC 5869): extract then expand.
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	hashLen := sha256.Size
	if salt == nil {
		salt = make([]byte, hashLen)
	}

	// Extract.
	prk := hmacSHA256(salt, ikm)

	// Expand.
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

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

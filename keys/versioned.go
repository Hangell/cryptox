package keys

import (
	"errors"
	"fmt"
)

// Versioned KDF domain separation. The versioned derivation is intentionally a
// distinct scheme from DeriveKey (the v1, purpose-only info layout), so a key
// derived under one scheme is never interchangeable with the other.
const (
	// versionedKDFLabel is the fixed label of the versioned KDF info string.
	versionedKDFLabel = "cryptox/kdf/versioned"
	// CurrentKDFVersion is the only derivation version accepted by
	// DeriveVersioned. A new version implies a new derivation scheme and
	// requires a specific security review (see ADR 0005).
	CurrentKDFVersion uint8 = 1
)

// ErrUnsupportedKDFVersion indicates a derivation version other than
// CurrentKDFVersion.
var ErrUnsupportedKDFVersion = errors.New("keys: unsupported KDF version")

// DeriveVersioned derives length bytes of key material from root using
// HKDF-SHA-256 with an empty salt and a versioned, purpose-bound info string:
//
//	info = "cryptox/kdf/versioned" || 0x00 || version || 0x00 || purpose
//
// The version byte binds the derivation scheme itself, so a future scheme
// change bumps CurrentKDFVersion and cannot collide with keys derived today.
// The purpose binds the domain (stream, envelope, storage, ...), so keys are
// independent across domains even from the same root.
//
// Root-key policy: root is secret input keying material used only to derive
// domain keys; it must not be used directly to encrypt data. This is not a
// password KDF: use a dedicated password KDF for low-entropy passphrases.
func DeriveVersioned(root []byte, purpose Purpose, version uint8, length int) ([]byte, error) {
	if len(root) < 32 {
		return nil, ErrInvalidKeyMaterial
	}
	if err := validatePurpose(purpose); err != nil {
		return nil, err
	}
	if version != CurrentKDFVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedKDFVersion, version, CurrentKDFVersion)
	}
	if length < minDerivedKeyLen || length > maxDerivedKeyLen {
		return nil, fmt.Errorf("%w: must be in [%d, %d], got %d",
			ErrInvalidLength, minDerivedKeyLen, maxDerivedKeyLen, length)
	}

	info := make([]byte, 0, len(versionedKDFLabel)+1+1+1+len(purpose))
	info = append(info, versionedKDFLabel...)
	info = append(info, 0x00, version, 0x00)
	info = append(info, purpose...)

	return hkdfSHA256(root, nil, info, length), nil
}

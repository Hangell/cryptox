// Package verification provides out-of-band verification helpers for identity
// public keys, in particular a stable, domain-separated fingerprint for
// comparing keys between devices.
package verification

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"github.com/Hangell/cryptox/keys/signatures"
)

// fingerprintDomain separates fingerprints of this scheme from any other
// SHA-256 use of the same key bytes.
const fingerprintDomain = "cryptox/identity/fingerprint/v1"

// FingerprintSize is the size of a fingerprint in bytes.
const FingerprintSize = 32

// Fingerprint is a SHA-256 digest of a public key under a fixed domain
// separation. It is a deterministic, one-way representation of the key.
type Fingerprint [FingerprintSize]byte

// FingerprintOf returns the domain-separated SHA-256 fingerprint of pub.
func FingerprintOf(pub signatures.PublicKey) Fingerprint {
	h := sha256.New()
	h.Write([]byte(fingerprintDomain))
	h.Write([]byte{0x00})
	h.Write(pub[:])
	var fp Fingerprint
	copy(fp[:], h.Sum(nil))
	return fp
}

// String renders the fingerprint as 16 uppercase hex groups of 4 digits,
// suitable for out-of-band comparison.
func (f Fingerprint) String() string {
	h := strings.ToUpper(hex.EncodeToString(f[:]))
	groups := make([]string, 0, 8)
	for i := 0; i < len(h); i += 4 {
		groups = append(groups, h[i:i+4])
	}
	return strings.Join(groups, " ")
}

// Equal reports whether two fingerprints are identical, using a constant-time
// comparison.
func (f Fingerprint) Equal(other Fingerprint) bool {
	return subtle.ConstantTimeCompare(f[:], other[:]) == 1
}

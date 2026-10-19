// Package exchange provides the X25519 elliptic-curve Diffie-Hellman function
// (RFC 7748) as an explicitly unauthenticated building block, built on the Go
// standard library crypto/ecdh. It implements no handshake and introduces no
// proprietary protocol.
//
// A raw X25519 shared secret provides no authentication: an active attacker
// can substitute either endpoint's public key (man-in-the-middle). Callers
// MUST authenticate the public keys before or after agreement (for example
// with keys/signatures or identity/credentials) and MUST derive symmetric keys
// from the shared secret with a KDF such as HKDF. This package is not an
// authenticated session establishment protocol (ADR 0007).
package exchange

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
)

// Sizes of X25519 keys and shared secrets.
const (
	PublicKeySize    = 32
	PrivateKeySize   = 32
	SharedSecretSize = 32
)

// PublicKey is an X25519 public key (a u-coordinate).
type PublicKey [PublicKeySize]byte

// PrivateKey is an X25519 private key (a clamped scalar). Its String method
// redacts the material.
type PrivateKey [PrivateKeySize]byte

// String redacts the private key material.
func (PrivateKey) String() string { return "[redacted x25519 private key]" }

// Errors returned by the package. Callers can classify failures with errors.Is.
var (
	// ErrInvalidKey indicates a malformed private key.
	ErrInvalidKey = errors.New("exchange: invalid private key")
	// ErrInvalidPeerKey indicates a malformed or low-order peer public key.
	ErrInvalidPeerKey = errors.New("exchange: invalid peer public key")
)

// GenerateKey returns a fresh X25519 key pair from crypto/rand.
func GenerateKey() (PublicKey, PrivateKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("exchange: generate key: %w", err)
	}
	var p PublicKey
	var s PrivateKey
	copy(p[:], priv.PublicKey().Bytes())
	copy(s[:], priv.Bytes())
	return p, s, nil
}

// Public returns the public key corresponding to priv.
func (priv PrivateKey) Public() (PublicKey, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return PublicKey{}, ErrInvalidKey
	}
	var p PublicKey
	copy(p[:], k.PublicKey().Bytes())
	return p, nil
}

// ECDH returns the raw X25519 shared secret between priv and peer.
//
// The result is unauthenticated and must not be used directly as a key. It
// returns ErrInvalidPeerKey when the peer public key yields the all-zero
// shared secret (a low-order point), as required by RFC 7748.
func ECDH(priv PrivateKey, peer PublicKey) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return nil, ErrInvalidKey
	}
	pub, err := ecdh.X25519().NewPublicKey(peer[:])
	if err != nil {
		return nil, ErrInvalidPeerKey
	}
	secret, err := k.ECDH(pub)
	if err != nil {
		return nil, ErrInvalidPeerKey
	}
	return secret, nil
}

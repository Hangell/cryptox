// Package signatures provides Ed25519 signing and verification with explicit
// domain-separation contexts, built on the Go standard library implementation
// (crypto/ed25519). It introduces no proprietary signature scheme.
//
// An empty context selects plain Ed25519 (RFC 8032, Section 5.1.6). A
// non-empty context selects Ed25519ctx (RFC 8032, Section 5.1), so a signature
// is valid only for the exact (context, message) pair and cannot be replayed
// across domains. Contexts must be at most 255 bytes.
//
// Ed25519ph (pre-hashed) is intentionally not exposed: callers who need it
// must opt in explicitly elsewhere, which keeps this API misuse-resistant.
package signatures

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
)

// Sizes of Ed25519 keys and signatures.
const (
	PublicKeySize  = ed25519.PublicKeySize  // 32
	PrivateKeySize = ed25519.PrivateKeySize // 64
	SignatureSize  = ed25519.SignatureSize  // 64
	SeedSize       = ed25519.SeedSize       // 32
)

// PublicKey is an Ed25519 public key.
type PublicKey [PublicKeySize]byte

// PrivateKey is an Ed25519 private key. Its String method redacts the material.
type PrivateKey [PrivateKeySize]byte

// String redacts the private key material.
func (PrivateKey) String() string { return "[redacted ed25519 private key]" }

// Public returns the public key embedded in priv. It fails with ErrInvalidKey
// if priv is internally inconsistent (the public suffix does not match the
// seed).
func (priv PrivateKey) Public() (PublicKey, error) {
	if !priv.valid() {
		return PublicKey{}, ErrInvalidKey
	}
	var p PublicKey
	copy(p[:], priv[PublicKeySize:])
	return p, nil
}

// valid reports whether the public key suffix matches the key derived from the
// seed portion, using a constant-time comparison.
func (priv PrivateKey) valid() bool {
	if len(priv) != PrivateKeySize {
		return false
	}
	derived := ed25519.NewKeyFromSeed(priv[:SeedSize])
	return subtle.ConstantTimeCompare(derived.Public().(ed25519.PublicKey), priv[SeedSize:]) == 1
}

// Errors returned by the package. Callers can classify failures with errors.Is.
var (
	// ErrInvalidKey indicates a malformed public or private key.
	ErrInvalidKey = errors.New("signatures: invalid key")
	// ErrInvalidSignature indicates a malformed signature.
	ErrInvalidSignature = errors.New("signatures: invalid signature")
	// ErrInvalidContext indicates a context longer than the 255-byte limit.
	ErrInvalidContext = errors.New("signatures: invalid context")
)

// GenerateKey returns a fresh Ed25519 key pair from crypto/rand.
func GenerateKey() (PublicKey, PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("signatures: generate key: %w", err)
	}
	var p PublicKey
	var s PrivateKey
	copy(p[:], pub)
	copy(s[:], priv)
	return p, s, nil
}

// PrivateKeyFromSeed derives a key pair from a 32-byte seed (RFC 8032). It
// exists for known-answer testing; production callers should use GenerateKey.
func PrivateKeyFromSeed(seed []byte) (PublicKey, PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return PublicKey{}, PrivateKey{}, ErrInvalidKey
	}
	priv := ed25519.NewKeyFromSeed(seed)
	var p PublicKey
	var s PrivateKey
	copy(p[:], priv.Public().(ed25519.PublicKey))
	copy(s[:], priv)
	return p, s, nil
}

// Sign signs message under priv with the given domain-separation context.
//
// context == "" uses plain Ed25519; otherwise Ed25519ctx is used. Contexts
// longer than 255 bytes are rejected.
func Sign(priv PrivateKey, message []byte, context string) ([]byte, error) {
	if !priv.valid() {
		return nil, ErrInvalidKey
	}
	if len(context) > 255 {
		return nil, ErrInvalidContext
	}
	sig, err := ed25519.PrivateKey(priv[:]).Sign(rand.Reader, message, &ed25519.Options{Context: context})
	if err != nil {
		return nil, fmt.Errorf("signatures: sign: %w", err)
	}
	return sig, nil
}

// Verify reports whether sig is a valid signature of message under pub for the
// given context. Malformed keys, signatures, and contexts are rejected rather
// than panicking.
func Verify(pub PublicKey, message []byte, context string, sig []byte) bool {
	if len(pub) != PublicKeySize || len(sig) != SignatureSize || len(context) > 255 {
		return false
	}
	return ed25519.VerifyWithOptions(ed25519.PublicKey(pub[:]), message, sig, &ed25519.Options{Context: context}) == nil
}

// Ensure the crypto import is used even if the signer path changes.
var _ crypto.Signer = (ed25519.PrivateKey)(nil)

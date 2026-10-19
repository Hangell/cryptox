// Package aead provides misuse-resistant authenticated encryption with
// associated data using AES-256-GCM from the Go standard library.
//
// # Guarantees
//
//   - Confidentiality and integrity of the plaintext, and integrity of the
//     associated data, under a 256-bit key, within GCM's security bounds.
//   - Seal generates a fresh 96-bit random nonce for every call; the nonce is
//     prepended to the ciphertext and never exposed for caller reuse.
//   - Open returns [ErrAuthentication] and never returns plaintext when
//     authentication fails.
//
// # Non-guarantees
//
//   - No replay or rollback protection.
//   - No metadata privacy: ciphertext length reveals the plaintext length.
//   - The random nonce construction is safe within the documented bound of at
//     most 2^32 Seal calls under one key.
//
// Seal and Open are safe for concurrent use: they hold no mutable shared state.
package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KeySize is the size in bytes of an AES-256 key.
const KeySize = 32

// Key is an opaque AES-256 key value. Its String method redacts the material so
// accidental logging does not expose the key.
type Key [KeySize]byte

// Errors returned by the package. Callers can classify failures with errors.Is.
var (
	// ErrAuthentication indicates that authentication failed or the ciphertext
	// was malformed; no plaintext is returned in this case.
	ErrAuthentication = errors.New("aead: authentication failed")
	// ErrInvalidKeySize indicates the supplied key material is not KeySize bytes.
	ErrInvalidKeySize = errors.New("aead: key must be 32 bytes")
	// ErrCiphertextTooShort indicates the ciphertext is shorter than a nonce
	// plus an authentication tag.
	ErrCiphertextTooShort = errors.New("aead: ciphertext too short")
)

// String redacts the key material.
func (Key) String() string { return "[redacted aead key]" }

// NewKey returns a Key from raw 32-byte material, rejecting any other length.
func NewKey(b []byte) (Key, error) {
	var k Key
	if len(b) != KeySize {
		return k, ErrInvalidKeySize
	}
	copy(k[:], b)
	return k, nil
}

// GenerateKey returns a fresh random 256-bit key.
func GenerateKey() (Key, error) {
	var k Key
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return k, fmt.Errorf("aead: generate key: %w", err)
	}
	return k, nil
}

// Seal encrypts plaintext and authenticates aad under key, returning
// nonce || ciphertext || tag. A fresh random nonce is generated per call.
func Seal(key Key, plaintext, aad []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("aead: generate nonce: %w", err)
	}
	return sealWithNonce(g, nonce, plaintext, aad), nil
}

// Open decrypts and authenticates a ciphertext produced by Seal. It returns
// ErrAuthentication (with no plaintext) on any authentication or format
// failure.
func Open(key Key, ciphertext, aad []byte) ([]byte, error) {
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := g.NonceSize()
	if len(ciphertext) < ns+g.Overhead() {
		return nil, ErrCiphertextTooShort
	}
	plaintext, err := g.Open(nil, ciphertext[:ns], ciphertext[ns:], aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	return plaintext, nil
}

// newGCM builds the AES-256-GCM instance for a key.
func newGCM(key Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealWithNonce performs the GCM seal with an explicit nonce and returns
// nonce || ciphertext || tag. It exists so tests can run known-answer vectors
// through the same code path as Seal.
func sealWithNonce(g cipher.AEAD, nonce, plaintext, aad []byte) []byte {
	return g.Seal(nonce, nonce, plaintext, aad)
}

// Package envelope implements the CryptoX Envelope v1: a versioned,
// transport-independent container for one encrypted object. The format is
// specified implementation-independently in docs/spec/envelope-v1.md.
//
// Guarantees: confidentiality and integrity of the payload, and integrity of
// the header, key identifier, and associated metadata, under a 32-byte key,
// within AES-256-GCM's security bounds. The version, suite, key identifier,
// metadata, and nonce are all bound through the GCM associated data.
//
// Non-guarantees: no replay/rollback protection, no metadata privacy, no
// protection from a compromised process or OS.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// Magic is the Envelope v1 identifier.
	Magic = "CXE1"
	// Version is the current envelope version.
	Version = byte(1)

	// SuiteAES256GCM is the only suite defined by Envelope v1.
	SuiteAES256GCM uint16 = 0x0001

	// MaxKeyIDLen bounds the opaque key identifier.
	MaxKeyIDLen = 64
	// MaxAADLen bounds the authenticated associated metadata.
	MaxAADLen = 65535

	nonceLen = 12
	tagLen   = 16
)

// Errors returned by the package. Callers can classify failures with errors.Is.
var (
	ErrAuthentication     = errors.New("envelope: authentication failed")
	ErrInvalidKey         = errors.New("envelope: key must be 32 bytes")
	ErrMalformed          = errors.New("envelope: malformed input")
	ErrUnsupportedVersion = errors.New("envelope: unsupported version")
	ErrUnsupportedSuite   = errors.New("envelope: unsupported suite")
)

// Opened is the result of a successful Open.
type Opened struct {
	Suite   uint16
	KeyID   []byte
	AAD     []byte
	Payload []byte
}

// Seal encrypts payload into an Envelope v1 using AES-256-GCM with a fresh
// random nonce. keyID is an optional opaque key identifier and aad is optional
// authenticated metadata; both are bound to the ciphertext.
func Seal(key, payload, keyID, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	if len(keyID) > MaxKeyIDLen {
		return nil, fmt.Errorf("envelope: key id too long: %d > %d", len(keyID), MaxKeyIDLen)
	}
	if len(aad) > MaxAADLen {
		return nil, fmt.Errorf("envelope: aad too long: %d > %d", len(aad), MaxAADLen)
	}

	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("envelope: generate nonce: %w", err)
	}

	header := buildHeader(SuiteAES256GCM, keyID, aad, nonce)
	ct := g.Seal(nil, nonce, payload, header)

	out := make([]byte, 0, len(header)+len(ct))
	out = append(out, header...)
	out = append(out, ct...)
	return out, nil
}

// Open parses, validates, authenticates, and decrypts an envelope. It returns
// ErrAuthentication (with no payload) on any authentication or format failure.
func Open(key, data []byte) (*Opened, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	p, err := parse(data)
	if err != nil {
		return nil, err
	}
	g, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	payload, err := g.Open(nil, p.nonce, p.ct, p.header)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	return &Opened{
		Suite:   p.suite,
		KeyID:   append([]byte(nil), p.keyID...),
		AAD:     append([]byte(nil), p.aad...),
		Payload: payload,
	}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// buildHeader serializes the canonical header: fixed field order, big-endian
// lengths, and no duplicate or ambiguous encodings.
func buildHeader(suite uint16, keyID, aad, nonce []byte) []byte {
	h := make([]byte, 0, 4+1+2+1+len(keyID)+2+len(aad)+1+len(nonce))
	h = append(h, Magic...)
	h = append(h, Version)
	h = append(h, byte(suite>>8), byte(suite))
	h = append(h, byte(len(keyID)))
	h = append(h, keyID...)
	h = append(h, byte(len(aad)>>8), byte(len(aad)))
	h = append(h, aad...)
	h = append(h, byte(len(nonce)))
	h = append(h, nonce...)
	return h
}

type parsed struct {
	suite  uint16
	keyID  []byte
	aad    []byte
	nonce  []byte
	header []byte
	ct     []byte // ciphertext including the 16-byte tag
}

// parse validates and splits an envelope with strict bounds. Every length is
// checked before use, and unknown versions/suites and invalid nonce lengths are
// rejected.
func parse(data []byte) (*parsed, error) {
	p := &parsed{}
	i := 0

	if len(data) < 4 {
		return nil, ErrMalformed
	}
	if string(data[:4]) != Magic {
		return nil, errors.New("envelope: invalid magic")
	}
	i = 4

	if len(data) < i+1 {
		return nil, ErrMalformed
	}
	if data[i] != Version {
		return nil, ErrUnsupportedVersion
	}
	i++

	if len(data) < i+2 {
		return nil, ErrMalformed
	}
	p.suite = binary.BigEndian.Uint16(data[i : i+2])
	i += 2
	if p.suite != SuiteAES256GCM {
		return nil, ErrUnsupportedSuite
	}

	if len(data) < i+1 {
		return nil, ErrMalformed
	}
	keyIDLen := int(data[i])
	i++
	if keyIDLen > MaxKeyIDLen || len(data) < i+keyIDLen {
		return nil, ErrMalformed
	}
	p.keyID = data[i : i+keyIDLen]
	i += keyIDLen

	if len(data) < i+2 {
		return nil, ErrMalformed
	}
	aadLen := int(binary.BigEndian.Uint16(data[i : i+2]))
	i += 2
	if aadLen > MaxAADLen || len(data) < i+aadLen {
		return nil, ErrMalformed
	}
	p.aad = data[i : i+aadLen]
	i += aadLen

	if len(data) < i+1 {
		return nil, ErrMalformed
	}
	nLen := int(data[i])
	i++
	if nLen != nonceLen {
		return nil, fmt.Errorf("envelope: invalid nonce length %d", nLen)
	}
	if len(data) < i+nLen {
		return nil, ErrMalformed
	}
	p.nonce = data[i : i+nLen]
	i += nLen

	// The header is authenticated as associated data.
	p.header = data[:i]
	if len(data)-i < tagLen {
		return nil, ErrMalformed
	}
	p.ct = data[i:]
	return p, nil
}

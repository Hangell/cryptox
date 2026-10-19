// Package credentials implements versioned identity credentials: a signed,
// purpose-bound binding of a subject public key to an issuer public key with an
// explicit validity window. It builds on keys/signatures (Ed25519/Ed25519ctx)
// and introduces no proprietary scheme.
//
// Credentials carry no names, timestamps beyond the validity window, or
// relationship metadata beyond issuer/subject, minimizing correlatable data
// (ARCHITECTURE.md §6.5). Trust is never implied: a verifier must separately
// decide whether the issuer is trusted (ADR 0006).
package credentials

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/Hangell/cryptox/keys/signatures"
)

// Version is the current credential format version.
const Version = 1

// Domain separation context for the Ed25519ctx signature.
const signatureContext = "cryptox/identity/credential/v1"

// Sizes of the fixed-width fields of a v1 credential.
const (
	encodedSize    = 1 + 2*signatures.PublicKeySize + 1 + 2*8 // 82
	credentialSize = encodedSize + signatures.SignatureSize   // 146
)

// Purpose describes what a subject key is authorized to do. The value is part
// of the signed payload, so a credential for one purpose cannot be replayed as
// another.
type Purpose uint8

// Valid purposes for v1 credentials. Unknown values are rejected.
const (
	// PurposeDeviceIdentity binds a device identity key.
	PurposeDeviceIdentity Purpose = 0x01
	// PurposeAgentIdentity binds a software-agent identity key.
	PurposeAgentIdentity Purpose = 0x02
)

func (p Purpose) valid() bool {
	return p == PurposeDeviceIdentity || p == PurposeAgentIdentity
}

// Errors returned by the package. Callers can classify failures with errors.Is.
var (
	// ErrMalformed indicates bytes that do not match the canonical encoding.
	ErrMalformed = errors.New("credentials: malformed credential")
	// ErrUnsupportedVersion indicates a credential whose version is not known.
	ErrUnsupportedVersion = errors.New("credentials: unsupported credential version")
	// ErrInvalidPurpose indicates an unknown purpose value.
	ErrInvalidPurpose = errors.New("credentials: invalid purpose")
	// ErrInvalidValidity indicates an invalid validity window.
	ErrInvalidValidity = errors.New("credentials: invalid validity window")
	// ErrInvalidSignature indicates a failed signature verification.
	ErrInvalidSignature = errors.New("credentials: invalid signature")
	// ErrExpired indicates the credential is not valid at the requested time.
	ErrExpired = errors.New("credentials: credential not valid at requested time")
)

// Credential is a v1 identity credential: a signed binding of Subject to Issuer
// for a Purpose within [NotBefore, NotAfter).
type Credential struct {
	Issuer    signatures.PublicKey
	Subject   signatures.PublicKey
	Purpose   Purpose
	NotBefore uint64 // Unix seconds, inclusive.
	NotAfter  uint64 // Unix seconds, exclusive.
	Signature [signatures.SignatureSize]byte
}

// New creates a signed credential binding subject to the issuer's public key
// for the given purpose and validity window. The issuer signs with their
// private key; the returned credential does not contain that key.
func New(issuerPriv signatures.PrivateKey, subject signatures.PublicKey, purpose Purpose, notBefore, notAfter uint64) (Credential, error) {
	if !purpose.valid() {
		return Credential{}, ErrInvalidPurpose
	}
	if notAfter <= notBefore {
		return Credential{}, ErrInvalidValidity
	}
	c := Credential{
		Issuer:    issuerPublicKey(issuerPriv),
		Subject:   subject,
		Purpose:   purpose,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
	payload, err := c.payload()
	if err != nil {
		return Credential{}, err
	}
	sig, err := signatures.Sign(issuerPriv, payload, signatureContext)
	if err != nil {
		return Credential{}, fmt.Errorf("credentials: sign: %w", err)
	}
	copy(c.Signature[:], sig)
	return c, nil
}

// issuerPublicKey extracts the issuer's public key from a private key, returning
// a zero key on error (New reports the error from the subsequent Sign call).
func issuerPublicKey(priv signatures.PrivateKey) signatures.PublicKey {
	pub, err := priv.Public()
	if err != nil {
		return signatures.PublicKey{}
	}
	return pub
}

// payload returns the canonical signed bytes: version, issuer, subject,
// purpose, and the validity window, all fixed-width and big-endian.
func (c Credential) payload() ([]byte, error) {
	if !c.Purpose.valid() {
		return nil, ErrInvalidPurpose
	}
	if c.NotAfter <= c.NotBefore {
		return nil, ErrInvalidValidity
	}
	out := make([]byte, 0, encodedSize)
	out = append(out, Version)
	out = append(out, c.Issuer[:]...)
	out = append(out, c.Subject[:]...)
	out = append(out, byte(c.Purpose))
	out = binary.BigEndian.AppendUint64(out, c.NotBefore)
	out = binary.BigEndian.AppendUint64(out, c.NotAfter)
	return out, nil
}

// Encode returns the canonical credential bytes. It is deterministic: the same
// credential always encodes to the same bytes.
func (c Credential) Encode() ([]byte, error) {
	payload, err := c.payload()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, credentialSize)
	out = append(out, payload...)
	out = append(out, c.Signature[:]...)
	return out, nil
}

// Decode parses a canonical v1 credential. It enforces the exact size, the
// version, and a known purpose; it does not verify the signature or the
// validity window (see VerifyAt).
func Decode(b []byte) (Credential, error) {
	if len(b) != credentialSize {
		return Credential{}, ErrMalformed
	}
	if b[0] != Version {
		return Credential{}, ErrUnsupportedVersion
	}
	c := Credential{
		Purpose:   Purpose(b[1+2*signatures.PublicKeySize]),
		NotBefore: binary.BigEndian.Uint64(b[1+2*signatures.PublicKeySize+1:]),
		NotAfter:  binary.BigEndian.Uint64(b[1+2*signatures.PublicKeySize+1+8:]),
	}
	copy(c.Issuer[:], b[1:1+signatures.PublicKeySize])
	copy(c.Subject[:], b[1+signatures.PublicKeySize:1+2*signatures.PublicKeySize])
	copy(c.Signature[:], b[encodedSize:])
	if !c.Purpose.valid() {
		return Credential{}, ErrInvalidPurpose
	}
	if c.NotAfter <= c.NotBefore {
		return Credential{}, ErrInvalidValidity
	}
	return c, nil
}

// Verify checks the signature at time now. It verifies the issuer's signature
// over the canonical payload and that now lies within the validity window.
//
// Verify does not decide whether the issuer is trusted: the caller must check
// c.Issuer against its own trust anchor.
func (c Credential) Verify(now time.Time) error {
	payload, err := c.payload()
	if err != nil {
		return err
	}
	if !signatures.Verify(c.Issuer, payload, signatureContext, c.Signature[:]) {
		return ErrInvalidSignature
	}
	if !c.validAt(now) {
		return ErrExpired
	}
	return nil
}

// validAt reports whether now lies within [NotBefore, NotAfter).
func (c Credential) validAt(now time.Time) bool {
	u := now.Unix()
	return u >= int64(c.NotBefore) && u < int64(c.NotAfter)
}

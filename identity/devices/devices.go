// Package devices implements a client-side state machine for device
// enrollment, key replacement, and revocation, without requiring a mandatory
// server. All authorization derives from a configured trust anchor or the
// device's own key (ADR 0006); nothing in this package establishes trust on
// its own.
//
// Consumers are responsible for persistence and for propagating state changes
// (in particular revocations) to every peer. See
// docs/spec/device-lifecycle-v1.md for the authorization rules and the
// synchronization threats.
package devices

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/Hangell/cryptox/identity/credentials"
	"github.com/Hangell/cryptox/keys/signatures"
)

// Domain separation contexts for signed operations.
const (
	revocationContext = "cryptox/identity/revoke/v1"
)

// State is a device key's lifecycle state. The machine is one-way: an active
// key can become retired (replaced) or revoked, and neither is reversible.
type State uint8

// Device key states.
const (
	StateActive  State = 1
	StateRetired State = 2
	StateRevoked State = 3
)

func (s State) valid() bool { return s >= StateActive && s <= StateRevoked }

func (s State) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateRetired:
		return "retired"
	case StateRevoked:
		return "revoked"
	default:
		return "unknown"
	}
}

// Errors returned by the package. Callers can classify failures with errors.Is.
var (
	// ErrInvalidCredential indicates an enrollment credential that fails
	// verification or is not a device-identity credential.
	ErrInvalidCredential = errors.New("devices: invalid enrollment credential")
	// ErrUntrustedIssuer indicates the credential issuer is not the anchor.
	ErrUntrustedIssuer = errors.New("devices: credential issuer is not the trust anchor")
	// ErrInvalidState indicates an invalid or disallowed state transition.
	ErrInvalidState = errors.New("devices: invalid state transition")
	// ErrWrongKey indicates a revocation that targets a different key.
	ErrWrongKey = errors.New("devices: revocation targets a different key")
	// ErrStaleSequence indicates an operation whose sequence is not newer than
	// the record, protecting against replay or rollback of older operations.
	ErrStaleSequence = errors.New("devices: stale operation sequence")
	// ErrMalformed indicates a record or revocation that does not match the
	// canonical encoding.
	ErrMalformed = errors.New("devices: malformed encoding")
	// ErrInvalidRevocation indicates a revocation with an invalid signature or
	// authorizer.
	ErrInvalidRevocation = errors.New("devices: invalid revocation")
)

// Record is the persisted state of one device key lineage: the anchor-issued
// enrollment credential, the current state, and a monotonic sequence used for
// anti-rollback. The credential is retained so recovery can re-validate it
// against the trust anchor instead of trusting bare key material.
type Record struct {
	Credential credentials.Credential
	State      State
	Seq        uint64
}

// Key returns the device key bound by the record.
func (r Record) Key() signatures.PublicKey { return r.Credential.Subject }

// Enroll validates an anchor-issued device-identity credential and returns an
// active record. Enrollment requires a trust anchor: the credential's issuer
// must equal anchor and the credential must be currently valid.
func Enroll(anchor signatures.PublicKey, cred credentials.Credential, now time.Time) (Record, error) {
	if err := validateEnrollment(anchor, cred, now); err != nil {
		return Record{}, err
	}
	return Record{Credential: cred, State: StateActive, Seq: 1}, nil
}

// Verify re-validates a record against the trust anchor at now. It is the
// recovery path: a record restored from storage is accepted only when its
// anchor-issued credential still verifies, so recovery cannot bypass
// authorization.
func (r Record) Verify(anchor signatures.PublicKey, now time.Time) error {
	if !r.State.valid() {
		return ErrInvalidState
	}
	return validateEnrollment(anchor, r.Credential, now)
}

// Replace authorizes key rotation: the anchor issues a new device-identity
// credential for a different key. The current record becomes retired and the
// returned record is the new active one with an incremented sequence.
//
// Replacement is authorized by the trust anchor signing the new credential; an
// adversary cannot rotate a key without the anchor's private key.
func Replace(anchor signatures.PublicKey, current Record, newCred credentials.Credential, now time.Time) (Record, Record, error) {
	if current.State != StateActive {
		return Record{}, Record{}, ErrInvalidState
	}
	if err := validateEnrollment(anchor, newCred, now); err != nil {
		return Record{}, Record{}, err
	}
	if newCred.Subject == current.Key() {
		return Record{}, Record{}, ErrInvalidCredential
	}
	old := current
	old.State = StateRetired
	next := Record{Credential: newCred, State: StateActive, Seq: current.Seq + 1}
	return old, next, nil
}

// Revocation is a signed statement that a device key is revoked. It may be
// authorized by the trust anchor or by the device key itself.
type Revocation struct {
	Key        signatures.PublicKey
	Authorizer signatures.PublicKey
	Seq        uint64
	Signature  [signatures.SignatureSize]byte
}

// NewRevocation creates a revocation of key signed by authorizerPriv, which
// must be the trust anchor or the key being revoked. Verify rejects any other
// authorizer, so a third party cannot revoke a device.
func NewRevocation(authorizerPriv signatures.PrivateKey, key signatures.PublicKey, seq uint64) (Revocation, error) {
	authorizer, err := authorizerPriv.Public()
	if err != nil {
		return Revocation{}, ErrInvalidRevocation
	}
	r := Revocation{Key: key, Authorizer: authorizer, Seq: seq}
	payload := r.payload()
	sig, err := signatures.Sign(authorizerPriv, payload, revocationContext)
	if err != nil {
		return Revocation{}, err
	}
	copy(r.Signature[:], sig)
	return r, nil
}

// Verify checks the revocation signature and that the authorizer is either the
// trust anchor or the revoked key itself.
func (r Revocation) Verify(anchor signatures.PublicKey) error {
	if r.Authorizer != anchor && r.Authorizer != r.Key {
		return ErrInvalidRevocation
	}
	if !signatures.Verify(r.Authorizer, r.payload(), revocationContext, r.Signature[:]) {
		return ErrInvalidRevocation
	}
	return nil
}

func (r Revocation) payload() []byte {
	out := make([]byte, 0, 2*signatures.PublicKeySize+8)
	out = append(out, r.Key[:]...)
	out = append(out, r.Authorizer[:]...)
	out = binary.BigEndian.AppendUint64(out, r.Seq)
	return out
}

// Revoke applies a verified revocation to an active record, returning a revoked
// record with the revocation's sequence. The revocation must target the
// record's key, be authorized (anchor or self), and carry a newer sequence.
func Revoke(current Record, rev Revocation, anchor signatures.PublicKey) (Record, error) {
	if current.State != StateActive {
		return Record{}, ErrInvalidState
	}
	if rev.Key != current.Key() {
		return Record{}, ErrWrongKey
	}
	if rev.Seq <= current.Seq {
		return Record{}, ErrStaleSequence
	}
	if err := rev.Verify(anchor); err != nil {
		return Record{}, err
	}
	return Record{Credential: current.Credential, State: StateRevoked, Seq: rev.Seq}, nil
}

// Encode returns the canonical record bytes: the enrollment credential,
// followed by the state and the sequence. It is deterministic.
func (r Record) Encode() ([]byte, error) {
	cred, err := r.Credential.Encode()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(cred)+1+8)
	out = append(out, cred...)
	out = append(out, byte(r.State))
	out = binary.BigEndian.AppendUint64(out, r.Seq)
	return out, nil
}

const (
	recordSize     = 146 + 1 + 8 // credential + state + seq
	revocationSize = 2*signatures.PublicKeySize + 8 + signatures.SignatureSize
)

// DecodeRecord parses a canonical record. It enforces the exact size, a known
// state, and a valid embedded credential; it does not verify the credential
// signature (see Record.Verify).
func DecodeRecord(b []byte) (Record, error) {
	if len(b) != recordSize {
		return Record{}, ErrMalformed
	}
	cred, err := credentials.Decode(b[:146])
	if err != nil {
		return Record{}, err
	}
	state := State(b[146])
	if !state.valid() {
		return Record{}, ErrInvalidState
	}
	return Record{Credential: cred, State: state, Seq: binary.BigEndian.Uint64(b[147:])}, nil
}

// Encode returns the canonical revocation bytes.
func (r Revocation) Encode() ([]byte, error) {
	out := make([]byte, 0, revocationSize)
	out = append(out, r.Key[:]...)
	out = append(out, r.Authorizer[:]...)
	out = binary.BigEndian.AppendUint64(out, r.Seq)
	out = append(out, r.Signature[:]...)
	return out, nil
}

// DecodeRevocation parses a canonical revocation, enforcing the exact size.
func DecodeRevocation(b []byte) (Revocation, error) {
	if len(b) != revocationSize {
		return Revocation{}, ErrMalformed
	}
	var r Revocation
	copy(r.Key[:], b[0:signatures.PublicKeySize])
	copy(r.Authorizer[:], b[signatures.PublicKeySize:2*signatures.PublicKeySize])
	r.Seq = binary.BigEndian.Uint64(b[2*signatures.PublicKeySize : 2*signatures.PublicKeySize+8])
	copy(r.Signature[:], b[2*signatures.PublicKeySize+8:])
	return r, nil
}

func validateEnrollment(anchor signatures.PublicKey, cred credentials.Credential, now time.Time) error {
	if cred.Purpose != credentials.PurposeDeviceIdentity {
		return ErrInvalidCredential
	}
	if cred.Issuer != anchor {
		return ErrUntrustedIssuer
	}
	if err := cred.Verify(now); err != nil {
		return ErrInvalidCredential
	}
	return nil
}

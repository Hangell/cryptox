package keyring

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Hangell/cryptox/keys"
	"github.com/Hangell/cryptox/keys/lifecycle"
)

// Key export format (version 1), documented for deliberate, raw key transfer:
//
//	"CKKX" || version(1) || keyIDLen(1)=16 || keyID(16) || keyVersion(4 BE)
//	       || purposeLen(1) || purpose || state(1) || secretLen(2 BE) || secret
//
// This is RAW key material: it is not wrapped or password-protected. Callers
// must transfer it over a secure channel. Protected export (wrapping under a
// key-encryption key) is a separate, future capability.
const (
	exportMagic   = "CKKX"
	exportVersion = byte(1)
)

// Errors returned by key export/import. Callers can classify with errors.Is.
var (
	// ErrMalformedExport indicates the export bytes are structurally invalid.
	ErrMalformedExport = errors.New("keyring: malformed key export")
	// ErrUnsupportedExportVersion indicates an unknown export format version.
	ErrUnsupportedExportVersion = errors.New("keyring: unsupported key export version")
)

// Export encodes r into the versioned raw key format. It is the only path that
// deliberately serializes key material; common logging and serialization of a
// Record never does. The returned slice is independent of r.Secret. It rejects
// records whose purpose (>255 bytes) or secret (>65535 bytes) cannot be
// represented by the format.
func Export(r Record) ([]byte, error) {
	if err := validateRecord(r); err != nil {
		return nil, err
	}
	if len(r.Purpose) > 255 {
		return nil, fmt.Errorf("%w: purpose too long (%d > 255)", ErrInvalidRecord, len(r.Purpose))
	}
	if len(r.Secret) > 65535 {
		return nil, fmt.Errorf("%w: secret too long (%d > 65535)", ErrInvalidRecord, len(r.Secret))
	}
	buf := make([]byte, 0, 4+1+1+KeyIDLen+4+1+len(r.Purpose)+1+2+len(r.Secret))
	buf = append(buf, exportMagic...)
	buf = append(buf, exportVersion)
	buf = append(buf, byte(KeyIDLen))
	buf = append(buf, r.ID[:]...)

	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, r.Version)
	buf = append(buf, version...)

	buf = append(buf, byte(len(r.Purpose)))
	buf = append(buf, r.Purpose...)
	buf = append(buf, byte(r.State))

	secretLen := make([]byte, 2)
	binary.BigEndian.PutUint16(secretLen, uint16(len(r.Secret)))
	buf = append(buf, secretLen...)
	buf = append(buf, r.Secret...)
	return buf, nil
}

// Import parses and validates a versioned raw key export and returns the
// record. Invalid or unknown-version bytes are rejected; no record is returned
// on failure.
func Import(data []byte) (Record, error) {
	if len(data) < 4 || string(data[:4]) != exportMagic {
		return Record{}, ErrMalformedExport
	}
	i := 4
	if len(data) < i+1 {
		return Record{}, ErrMalformedExport
	}
	if data[i] != exportVersion {
		return Record{}, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedExportVersion, data[i], exportVersion)
	}
	i++

	if len(data) < i+1 || data[i] != KeyIDLen {
		return Record{}, ErrMalformedExport
	}
	i++
	if len(data) < i+KeyIDLen {
		return Record{}, ErrMalformedExport
	}
	var id KeyID
	copy(id[:], data[i:i+KeyIDLen])
	i += KeyIDLen

	if len(data) < i+4 {
		return Record{}, ErrMalformedExport
	}
	version := binary.BigEndian.Uint32(data[i : i+4])
	i += 4

	if len(data) < i+1 {
		return Record{}, ErrMalformedExport
	}
	purposeLen := int(data[i])
	i++
	if purposeLen == 0 || len(data) < i+purposeLen {
		return Record{}, ErrMalformedExport
	}
	purpose := keys.Purpose(data[i : i+purposeLen])
	i += purposeLen

	if len(data) < i+1 {
		return Record{}, ErrMalformedExport
	}
	state := lifecycle.State(data[i])
	i++
	if state != lifecycle.StateActive && state != lifecycle.StateRetired && state != lifecycle.StateRevoked {
		return Record{}, ErrMalformedExport
	}

	if len(data) < i+2 {
		return Record{}, ErrMalformedExport
	}
	secretLen := int(binary.BigEndian.Uint16(data[i : i+2]))
	i += 2
	if secretLen == 0 || len(data) != i+secretLen {
		return Record{}, ErrMalformedExport
	}
	secret := append(Secret(nil), data[i:]...)

	r := Record{
		ID:      id,
		Version: version,
		Purpose: purpose,
		State:   state,
		Secret:  secret,
	}
	if err := validateRecord(r); err != nil {
		return Record{}, err
	}
	return r, nil
}

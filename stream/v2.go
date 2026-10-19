package stream

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// v2 stream layout constants, approved in
// docs/security/v2-streaming-design-review.md. These define the nonce and key
// derivation construction only; they do not implement any cipher.
const (
	v2Magic                    = "CXS2"
	v2Version                  = byte(2)
	v2SuiteAES256GCMHKDFSHA256 = byte(1)
	v2SaltLen                  = 32
	v2NoncePrefixLen           = 7
	v2HeaderLen                = 4 + 1 + 1 + 1 + v2SaltLen + v2NoncePrefixLen // 46
	v2SegmentSize              = 64 * 1024
	v2DomainSepLabel           = "cryptox/v2/stream"
)

// v2RandomizerBytes is the total fresh randomness used per stream. A 32-byte
// salt plus a 7-byte nonce prefix gives 312 bits, avoiding the v1 64-bit prefix
// design that is collision-prone under key reuse.
const v2RandomizerBytes = v2SaltLen + v2NoncePrefixLen

// v2DomainSep builds the HKDF info string for the v2 format. It binds the
// format label, version, suite, and caller associated data so a derived key is
// only valid for one format revision, one suite, and one AAD context.
func v2DomainSep(version, suite byte, aad []byte) []byte {
	out := make([]byte, 0, len(v2DomainSepLabel)+1+1+1+1+len(aad))
	out = append(out, v2DomainSepLabel...)
	out = append(out, 0x00)
	out = append(out, version)
	out = append(out, suite)
	out = append(out, 0x00)
	out = append(out, aad...)
	return out
}

// v2SegmentIV builds the 12-byte AES-GCM nonce for a segment: the 7-byte nonce
// prefix, the big-endian 32-bit segment counter, and a final flag byte (0x01 for
// the final segment, 0x00 otherwise).
func v2SegmentIV(noncePrefix [v2NoncePrefixLen]byte, counter uint32, final bool) [12]byte {
	var iv [12]byte
	copy(iv[:v2NoncePrefixLen], noncePrefix[:])
	binary.BigEndian.PutUint32(iv[v2NoncePrefixLen:11], counter)
	if final {
		iv[11] = 0x01
	}
	return iv
}

// buildV2Header assembles the fixed-size v2 header from a salt and nonce prefix.
func buildV2Header(salt [v2SaltLen]byte, noncePrefix [v2NoncePrefixLen]byte) [v2HeaderLen]byte {
	var h [v2HeaderLen]byte
	copy(h[0:4], v2Magic)
	h[4] = v2Version
	h[5] = v2SuiteAES256GCMHKDFSHA256
	h[6] = v2SaltLen
	copy(h[7:7+v2SaltLen], salt[:])
	copy(h[7+v2SaltLen:], noncePrefix[:])
	return h
}

// parseV2Header validates a v2 header and returns its salt and nonce prefix.
// A v1 header or any unknown version/suite is rejected; v1 is never
// reinterpreted as v2.
func parseV2Header(h []byte) (salt [v2SaltLen]byte, noncePrefix [v2NoncePrefixLen]byte, err error) {
	if len(h) != v2HeaderLen {
		return salt, noncePrefix, fmt.Errorf("invalid v2 header length: got %d, want %d", len(h), v2HeaderLen)
	}
	if string(h[0:4]) != v2Magic {
		return salt, noncePrefix, fmt.Errorf("invalid v2 magic: got %q, want %q", string(h[0:4]), v2Magic)
	}
	if h[4] != v2Version {
		return salt, noncePrefix, fmt.Errorf("unsupported v2 version: got %d, want %d", h[4], v2Version)
	}
	if h[5] != v2SuiteAES256GCMHKDFSHA256 {
		return salt, noncePrefix, fmt.Errorf("unsupported v2 suite: got %d, want %d", h[5], v2SuiteAES256GCMHKDFSHA256)
	}
	if h[6] != v2SaltLen {
		return salt, noncePrefix, errors.New("invalid v2 salt length")
	}
	copy(salt[:], h[7:7+v2SaltLen])
	copy(noncePrefix[:], h[7+v2SaltLen:])
	return salt, noncePrefix, nil
}

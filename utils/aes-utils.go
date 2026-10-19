// Package utils preserves the legacy API.
// Deprecated: use packages stream and keys.
package utils

import (
	"github.com/Hangell/cryptox/keys"
	"github.com/Hangell/cryptox/stream"
)

// EncryptLargeFiles delegates to stream.EncryptLargeFiles.
func EncryptLargeFiles(infile, outfile string, key []byte) error {
	return stream.EncryptLargeFiles(infile, outfile, key)
}

// DecryptLargeFiles delegates to stream.DecryptLargeFiles.
func DecryptLargeFiles(infile, outfile string, key []byte) error {
	return stream.DecryptLargeFiles(infile, outfile, key)
}

// ValidateHeader checks the header only, not integrity.
func ValidateHeader(filename string) error { return stream.ValidateHeader(filename) }

// ValidateEncryptedFile checks the header only, not integrity.
//
// Deprecated: use ValidateHeader.
func ValidateEncryptedFile(filename string) error { return stream.ValidateHeader(filename) }

// GenerateKey delegates to keys.GenerateKey.
func GenerateKey(size int) ([]byte, error) { return keys.GenerateKey(size) }

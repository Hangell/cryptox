package keys

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// GenerateKey returns a random AES key of 16, 24, or 32 bytes.
func GenerateKey(size int) ([]byte, error) {
	switch size {
	case 16, 24, 32:
	default:
		return nil, errors.New("key size must be 16, 24, or 32 bytes")
	}

	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

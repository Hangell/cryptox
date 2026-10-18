package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
)

const (
	magic     = "SYM1"
	version   = byte(1)
	algAESGCM = "AESG"
	headerLen = 4 + 1 + 4 + 12
	chunkSize = 64 * 1024
)

// EncryptLargeFiles encrypts a file in legacy v1 format. Use a fresh key per file.
func EncryptLargeFiles(infile, outfile string, key []byte) (err error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return errors.New("key length must be 16, 24, or 32 bytes")
	}

	in, err := os.Open(infile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer in.Close()

	out, err := os.CreateTemp(filepath.Dir(outfile), ".cryptox-*")
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	tmp := out.Name()
	defer func() {
		out.Close()
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}
	if aead.NonceSize() != 12 {
		return errors.New("unexpected GCM nonce size")
	}

	baseNonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, baseNonce[:8]); err != nil {
		return fmt.Errorf("failed to generate random nonce: %w", err)
	}

	hdr := make([]byte, 0, headerLen)
	hdr = append(hdr, magic...)
	hdr = append(hdr, version)
	hdr = append(hdr, algAESGCM...)
	hdr = append(hdr, baseNonce...)
	if _, err = out.Write(hdr); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	buf := make([]byte, chunkSize)
	var counter uint64

	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			nonce := make([]byte, 12)
			copy(nonce, baseNonce[:8])
			if err := checkCounter(counter); err != nil {
				return err
			}
			binary.LittleEndian.PutUint32(nonce[8:], uint32(counter))

			ciphertext := aead.Seal(nil, nonce, buf[:n], nil)

			lenField := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenField, uint32(len(ciphertext)))

			if _, err = out.Write(lenField); err != nil {
				return fmt.Errorf("failed to write chunk length: %w", err)
			}
			if _, err = out.Write(ciphertext); err != nil {
				return fmt.Errorf("failed to write encrypted chunk: %w", err)
			}
			counter++
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("error reading input file: %w", readErr)
		}
	}

	if err = out.Sync(); err != nil {
		return fmt.Errorf("failed to sync output file: %w", err)
	}
	if err = out.Close(); err != nil {
		return fmt.Errorf("failed to close output file: %w", err)
	}
	return os.Rename(tmp, outfile)
}

// DecryptLargeFiles authenticates individual chunks, but cannot detect removed trailing chunks.
func DecryptLargeFiles(infile, outfile string, key []byte) (err error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return errors.New("key length must be 16, 24, or 32 bytes")
	}

	in, err := os.Open(infile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer in.Close()

	out, err := os.CreateTemp(filepath.Dir(outfile), ".cryptox-*")
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	tmp := out.Name()
	defer func() {
		out.Close()
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	if err = decryptV1(in, out, key); err != nil {
		return err
	}

	if err = out.Sync(); err != nil {
		return fmt.Errorf("failed to sync output file: %w", err)
	}
	if err = out.Close(); err != nil {
		return fmt.Errorf("failed to close output file: %w", err)
	}
	return os.Rename(tmp, outfile)
}

// ValidateEncryptedFile checks only the v1 header; it does not verify integrity.
func ValidateEncryptedFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}
	if stat.Size() < headerLen {
		return errors.New("file too short: missing header")
	}

	hdr := make([]byte, headerLen)
	if _, err = io.ReadFull(file, hdr); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	if string(hdr[:4]) != magic {
		return errors.New("invalid file format: magic bytes mismatch")
	}

	if hdr[4] != version {
		return fmt.Errorf("unsupported version: got %d, expected %d", hdr[4], version)
	}

	if string(hdr[5:9]) != algAESGCM {
		return fmt.Errorf("unsupported algorithm: got %s, expected %s", string(hdr[5:9]), algAESGCM)
	}

	if binary.LittleEndian.Uint32(hdr[17:21]) != 0 {
		return errors.New("invalid reserved nonce bytes")
	}
	return nil
}

func checkCounter(counter uint64) error {
	if counter > math.MaxUint32 {
		return errors.New("v1 chunk counter exhausted")
	}
	return nil
}

// decryptV1 may write authenticated prefixes before returning an error.
// Only the file adapter provides transactional publication.
func decryptV1(in io.Reader, out io.Writer, key []byte) (err error) {
	hdr := make([]byte, headerLen)
	if _, err = io.ReadFull(in, hdr); err != nil {
		if err == io.EOF {
			return errors.New("file too short: missing header")
		}
		return fmt.Errorf("failed to read header: %w", err)
	}

	if string(hdr[:4]) != magic {
		return errors.New("invalid file format: magic bytes mismatch")
	}

	if hdr[4] != version {
		return fmt.Errorf("unsupported version: got %d, expected %d", hdr[4], version)
	}

	if string(hdr[5:9]) != algAESGCM {
		return fmt.Errorf("unsupported algorithm: got %s, expected %s", string(hdr[5:9]), algAESGCM)
	}

	baseNonce := make([]byte, 12)
	copy(baseNonce, hdr[9:21])
	if binary.LittleEndian.Uint32(baseNonce[8:]) != 0 {
		return errors.New("invalid reserved nonce bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}
	if aead.NonceSize() != 12 {
		return errors.New("unexpected GCM nonce size")
	}

	var counter uint64

	for {
		lenField := make([]byte, 4)
		n, readErr := io.ReadFull(in, lenField)
		if readErr == io.EOF && n == 0 {
			break
		}
		if readErr != nil {
			return fmt.Errorf("error reading chunk length: %w", readErr)
		}

		chunkLen := binary.LittleEndian.Uint32(lenField)
		if chunkLen < uint32(aead.Overhead()) {
			return errors.New("corrupted file: chunk shorter than authentication tag")
		}
		if chunkLen > uint32(chunkSize+aead.Overhead()) {
			return errors.New("corrupted file: chunk too large")
		}

		ciphertext := make([]byte, chunkLen)
		if _, err = io.ReadFull(in, ciphertext); err != nil {
			if err == io.EOF {
				return errors.New("corrupted file: incomplete chunk data")
			}
			return fmt.Errorf("error reading chunk data: %w", err)
		}

		nonce := make([]byte, 12)
		copy(nonce, baseNonce[:8])
		if err := checkCounter(counter); err != nil {
			return err
		}
		binary.LittleEndian.PutUint32(nonce[8:], uint32(counter))

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("decryption failed at chunk %d: %w", counter, err)
		}

		written, writeErr := out.Write(plaintext)
		if writeErr != nil {
			return fmt.Errorf("failed to write decrypted chunk: %w", writeErr)
		}
		if written != len(plaintext) {
			return fmt.Errorf("failed to write decrypted chunk: %w", io.ErrShortWrite)
		}

		counter++
	}

	return nil
}

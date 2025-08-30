package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	magic     = "SYM1"         // 4 bytes
	version   = byte(1)        // 1 byte
	algAESGCM = "AESG"         // 4 bytes
	headerLen = 4 + 1 + 4 + 12 // magic + ver + alg + baseNonce(12)
	chunkSize = 64 * 1024      // 64KB por chunk
)

// EncryptLargeFiles criptografa arquivos grandes usando AES-GCM em chunks
func EncryptLargeFiles(infile, outfile string, key []byte) (err error) {
	// 1) Valida chave
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

	tmp := outfile + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		out.Close()
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	// 2) Inicializa AEAD (AES-GCM)
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

	// 3) Gera nonce base aleatório (12 bytes): [8 aleatórios | 4 zeros de contador]
	baseNonce := make([]byte, aead.NonceSize()) // 12
	if _, err = io.ReadFull(rand.Reader, baseNonce[:8]); err != nil {
		return fmt.Errorf("failed to generate random nonce: %w", err)
	}
	// baseNonce[8:12] será sobrescrito a cada chunk com o contador

	// 4) Escreve cabeçalho
	hdr := make([]byte, 0, headerLen)
	hdr = append(hdr, magic...)     // "SYM1"
	hdr = append(hdr, version)      // 0x01
	hdr = append(hdr, algAESGCM...) // "AESG"
	hdr = append(hdr, baseNonce...) // 12B
	if _, err = out.Write(hdr); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// 5) Loop de chunks
	buf := make([]byte, chunkSize)
	var counter uint32 = 0

	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			nonce := make([]byte, 12)
			copy(nonce, baseNonce[:8])
			binary.LittleEndian.PutUint32(nonce[8:], counter)

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

	// 6) Finaliza atômico
	if err = out.Sync(); err != nil {
		return fmt.Errorf("failed to sync output file: %w", err)
	}
	if err = out.Close(); err != nil {
		return fmt.Errorf("failed to close output file: %w", err)
	}
	return os.Rename(tmp, outfile)
}

// DecryptLargeFiles descriptografa arquivos grandes criptografados com EncryptLargeFiles
func DecryptLargeFiles(infile, outfile string, key []byte) (err error) {
	// 1) Valida chave
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

	tmp := outfile + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() {
		out.Close()
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	// 2) Lê e valida cabeçalho
	hdr := make([]byte, headerLen)
	if _, err = io.ReadFull(in, hdr); err != nil {
		if err == io.EOF {
			return errors.New("file too short: missing header")
		}
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Valida magic
	if string(hdr[:4]) != magic {
		return errors.New("invalid file format: magic bytes mismatch")
	}

	// Valida versão
	if hdr[4] != version {
		return fmt.Errorf("unsupported version: got %d, expected %d", hdr[4], version)
	}

	// Valida algoritmo
	if string(hdr[5:9]) != algAESGCM {
		return fmt.Errorf("unsupported algorithm: got %s, expected %s", string(hdr[5:9]), algAESGCM)
	}

	// Extrai nonce base
	baseNonce := make([]byte, 12)
	copy(baseNonce, hdr[9:21])

	// 3) Inicializa AEAD (AES-GCM)
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

	// 4) Loop de chunks
	var counter uint32 = 0

	for {
		// Lê tamanho do chunk
		lenField := make([]byte, 4)
		n, readErr := in.Read(lenField)
		if readErr == io.EOF && n == 0 {
			// Fim do arquivo
			break
		}
		if readErr != nil {
			return fmt.Errorf("error reading chunk length: %w", readErr)
		}
		if n < 4 {
			return errors.New("corrupted file: incomplete chunk length")
		}

		chunkLen := binary.LittleEndian.Uint32(lenField)
		if chunkLen == 0 {
			return errors.New("corrupted file: zero chunk length")
		}
		// Proteção contra chunks muito grandes (possível ataque)
		if chunkLen > chunkSize+aead.Overhead() {
			return errors.New("corrupted file: chunk too large")
		}

		// Lê chunk criptografado
		ciphertext := make([]byte, chunkLen)
		if _, err = io.ReadFull(in, ciphertext); err != nil {
			if err == io.EOF {
				return errors.New("corrupted file: incomplete chunk data")
			}
			return fmt.Errorf("error reading chunk data: %w", err)
		}

		// Reconstrói nonce
		nonce := make([]byte, 12)
		copy(nonce, baseNonce[:8])
		binary.LittleEndian.PutUint32(nonce[8:], counter)

		// Descriptografa chunk
		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return fmt.Errorf("decryption failed at chunk %d: %w", counter, err)
		}

		// Escreve chunk descriptografado
		if _, err = out.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write decrypted chunk: %w", err)
		}

		counter++
	}

	// 5) Finaliza atômico
	if err = out.Sync(); err != nil {
		return fmt.Errorf("failed to sync output file: %w", err)
	}
	if err = out.Close(); err != nil {
		return fmt.Errorf("failed to close output file: %w", err)
	}
	return os.Rename(tmp, outfile)
}

// ValidateEncryptedFile verifica se um arquivo tem o formato válido sem descriptografar
func ValidateEncryptedFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Verifica tamanho mínimo
	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file stats: %w", err)
	}
	if stat.Size() < headerLen {
		return errors.New("file too short: missing header")
	}

	// Lê e valida cabeçalho
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

	return nil
}

// GenerateKey gera uma chave aleatória para criptografia
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
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
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

func EncryptLargeFiles(infile, outfile string, key []byte) (err error) {
	// 1) Valida chave
	switch len(key) {
	case 16, 24, 32:
	default:
		return errors.New("key length must be 16, 24, or 32 bytes")
	}

	in, err := os.Open(infile)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := outfile + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
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
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if aead.NonceSize() != 12 {
		return errors.New("unexpected GCM nonce size")
	}

	// 3) Gera nonce base aleatório (12 bytes): [8 aleatórios | 4 zeros de contador]
	baseNonce := make([]byte, aead.NonceSize()) // 12
	if _, err = io.ReadFull(rand.Reader, baseNonce[:8]); err != nil {
		return err
	}
	// baseNonce[8:12] será sobrescrito a cada chunk com o contador

	// 4) Escreve cabeçalho
	hdr := make([]byte, 0, headerLen)
	hdr = append(hdr, magic...)     // "SYM1"
	hdr = append(hdr, version)      // 0x01
	hdr = append(hdr, algAESGCM...) // "AESG"
	hdr = append(hdr, baseNonce...) // 12B
	if _, err = out.Write(hdr); err != nil {
		return err
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
				return err
			}
			if _, err = out.Write(ciphertext); err != nil {
				return err
			}
			counter++
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	// 6) Finaliza atômico
	if err = out.Sync(); err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, outfile)
}

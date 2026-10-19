package stream

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// EncryptFileV2 encrypts infile into outfile in the v2 stream format using a
// 32-byte key. Publication contract (same as v1): output is written to a unique
// temporary file and atomically renamed over outfile on success, replacing any
// existing file; on failure the temporary file is removed and an existing
// outfile is left untouched. The destination directory is not fsynced.
func EncryptFileV2(infile, outfile string, key, aad []byte) (err error) {
	if len(key) != 32 {
		return errors.New("v2 requires a 32-byte key")
	}

	in, err := os.Open(infile)
	if err != nil {
		return fmt.Errorf("v2: open input: %w", err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.CreateTemp(filepath.Dir(outfile), ".cryptox-*")
	if err != nil {
		return fmt.Errorf("v2: create output: %w", err)
	}
	tmp := out.Name()
	defer func() {
		_ = out.Close()
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	enc, err := NewEncryptor(out, key, aad)
	if err != nil {
		return err
	}
	if _, err := io.Copy(enc, in); err != nil {
		return fmt.Errorf("v2: encrypt: %w", err)
	}
	if err := enc.Close(); err != nil {
		return err
	}

	if err = out.Sync(); err != nil {
		return fmt.Errorf("v2: sync output: %w", err)
	}
	if err = out.Close(); err != nil {
		return fmt.Errorf("v2: close output: %w", err)
	}
	return os.Rename(tmp, outfile)
}

// DecryptFileV2 decrypts a v2 file, authenticating the entire stream before
// publishing. The destination is replaced only after the Decryptor returns
// io.EOF, which it does only after the final segment is authenticated; on any
// error the temporary file is removed and an existing outfile is untouched.
func DecryptFileV2(infile, outfile string, key, aad []byte) (err error) {
	if len(key) != 32 {
		return errors.New("v2 requires a 32-byte key")
	}

	in, err := os.Open(infile)
	if err != nil {
		return fmt.Errorf("v2: open input: %w", err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.CreateTemp(filepath.Dir(outfile), ".cryptox-*")
	if err != nil {
		return fmt.Errorf("v2: create output: %w", err)
	}
	tmp := out.Name()
	defer func() {
		_ = out.Close()
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	dec, err := NewDecryptor(in, key, aad)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, dec); err != nil {
		return fmt.Errorf("v2: decrypt: %w", err)
	}

	if err = out.Sync(); err != nil {
		return fmt.Errorf("v2: sync output: %w", err)
	}
	if err = out.Close(); err != nil {
		return fmt.Errorf("v2: close output: %w", err)
	}
	return os.Rename(tmp, outfile)
}

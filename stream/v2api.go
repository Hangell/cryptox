package stream

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// This file exposes the v2 format as explicit io.Reader / io.WriteCloser
// contracts. The security boundary is the final segment: plaintext read or
// written before finalization is segment-authenticated only, not whole-stream
// authenticated.

// Encryptor is an io.WriteCloser that encrypts plaintext into the v2 stream
// format. Close finalizes the stream by writing the authenticated final
// segment; output is only a complete, valid v2 stream after Close succeeds.
//
// Not safe for concurrent use.
type Encryptor struct {
	w       io.Writer
	g       cipher.AEAD
	prefix  [v2NoncePrefixLen]byte
	buf     []byte
	counter uint64
	closed  bool
	err     error
}

// NewEncryptor returns an Encryptor writing to w with a 32-byte key and
// optional associated data. The v2 header is written immediately; on error the
// returned Encryptor is nil and w must not be reused for this stream.
func NewEncryptor(w io.Writer, key, aad []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, errors.New("v2 requires a 32-byte key")
	}
	var salt [v2SaltLen]byte
	var prefix [v2NoncePrefixLen]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return nil, fmt.Errorf("v2: generate salt: %w", err)
	}
	if _, err := io.ReadFull(rand.Reader, prefix[:]); err != nil {
		return nil, fmt.Errorf("v2: generate nonce prefix: %w", err)
	}

	hdr := buildV2Header(salt, prefix)
	derived := v2DeriveKey(key, salt, aad)
	g, err := newV2GCM(derived)
	if err != nil {
		return nil, err
	}
	if err := writeAll(w, hdr[:]); err != nil {
		return nil, fmt.Errorf("v2: write header: %w", err)
	}
	return &Encryptor{
		w:      w,
		g:      g,
		prefix: prefix,
		buf:    make([]byte, 0, v2SegmentSize),
	}, nil
}

// Write encrypts p as part of the stream. It returns the number of bytes
// consumed, which is len(p) unless an error occurred. After an error the
// Encryptor is unusable and the output must be discarded.
func (e *Encryptor) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	if e.closed {
		return 0, errors.New("v2: Write after Close")
	}

	e.buf = append(e.buf, p...)
	for len(e.buf) >= v2SegmentSize {
		if err := e.emit(e.buf[:v2SegmentSize], false); err != nil {
			e.err = err
			return 0, err
		}
		e.buf = e.buf[v2SegmentSize:]
		e.counter++
	}
	return len(p), nil
}

// Close writes the final authenticated segment. It must be called to produce a
// complete stream; without it the output has no authenticated termination and
// any consumer will reject it as truncated. Close is idempotent.
func (e *Encryptor) Close() error {
	if e.err != nil {
		return e.err
	}
	if e.closed {
		return nil
	}
	e.closed = true

	if err := e.emit(e.buf, true); err != nil {
		e.err = err
		return err
	}
	e.buf = nil
	return nil
}

// emit encrypts and writes one segment with the given final flag.
func (e *Encryptor) emit(data []byte, final bool) error {
	if err := checkCounter(e.counter); err != nil {
		return err
	}
	iv := v2SegmentIV(e.prefix, uint32(e.counter), final)
	ct := e.g.Seal(nil, iv[:], data, nil)
	if err := writeAll(e.w, ct); err != nil {
		return fmt.Errorf("v2: write segment: %w", err)
	}
	return nil
}

// Decryptor is an io.Reader that decrypts a v2 stream. Read returns io.EOF only
// after the final segment has been successfully authenticated.
//
// Security contract: plaintext returned before Read returns io.EOF is
// segment-authenticated only. Whole-stream integrity is established solely by
// reading until io.EOF; an error before io.EOF means the stream was truncated,
// modified, or reordered and the plaintext must not be trusted as complete.
//
// Not safe for concurrent use.
type Decryptor struct {
	r       *bufio.Reader
	g       cipher.AEAD
	prefix  [v2NoncePrefixLen]byte
	segBuf  []byte
	pending []byte
	counter uint64
	done    bool
	err     error
}

// NewDecryptor returns a Decryptor reading the v2 stream from r with a 32-byte
// key and the same associated data used at encryption. The header is read and
// validated immediately.
func NewDecryptor(r io.Reader, key, aad []byte) (*Decryptor, error) {
	if len(key) != 32 {
		return nil, errors.New("v2 requires a 32-byte key")
	}
	br := bufio.NewReaderSize(r, v2SegmentSize+v2TagSize)

	hdr := make([]byte, v2HeaderLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		if err == io.EOF {
			return nil, errors.New("v2: truncated header")
		}
		return nil, fmt.Errorf("v2: read header: %w", err)
	}
	salt, prefix, err := parseV2Header(hdr)
	if err != nil {
		return nil, err
	}

	derived := v2DeriveKey(key, salt, aad)
	g, err := newV2GCM(derived)
	if err != nil {
		return nil, err
	}
	return &Decryptor{
		r:      br,
		g:      g,
		prefix: prefix,
		segBuf: make([]byte, v2SegmentSize+v2TagSize),
	}, nil
}

// Read decrypts and returns plaintext. It returns io.EOF only after the final
// authenticated segment has been fully consumed.
func (d *Decryptor) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	for len(d.pending) == 0 && !d.done {
		if err := d.nextSegment(); err != nil {
			d.err = err
			return 0, err
		}
	}
	if d.done && len(d.pending) == 0 {
		return 0, io.EOF
	}
	n := copy(p, d.pending)
	d.pending = d.pending[n:]
	return n, nil
}

// nextSegment reads and authenticates the next segment, populating pending.
func (d *Decryptor) nextSegment() error {
	if err := checkCounter(d.counter); err != nil {
		return err
	}
	n, readErr := io.ReadFull(d.r, d.segBuf)
	var final bool
	switch readErr {
	case nil:
		if _, perr := d.r.Peek(1); perr != nil {
			final = true
		}
	case io.ErrUnexpectedEOF:
		if n < v2TagSize {
			return errors.New("v2: final segment shorter than authentication tag")
		}
		final = true
	case io.EOF:
		return errors.New("v2: truncated stream: missing authenticated final segment")
	default:
		return fmt.Errorf("v2: read segment: %w", readErr)
	}

	plaintext, err := openV2Segment(d.g, d.prefix, uint32(d.counter), final, d.segBuf[:n])
	if err != nil {
		return fmt.Errorf("v2: segment %d: %w", d.counter, err)
	}
	d.pending = plaintext
	if final {
		d.done = true
	}
	d.counter++
	return nil
}

// writeAll writes p to w, handling short writes.
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

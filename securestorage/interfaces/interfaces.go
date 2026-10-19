// Package interfaces defines the transport- and backend-independent contracts
// for secure storage (ARCHITECTURE.md §6.7). Adapters for filesystems,
// databases, or OS keystores implement these contracts; the contracts
// themselves have no knowledge of any concrete storage technology.
//
// Concurrency: a Store must be safe for concurrent use by multiple goroutines.
// Put and Delete use an optional expected version for compare-and-swap: when a
// non-nil expected Version is supplied and does not match the stored version,
// the operation fails with ErrConflict and changes nothing.
package interfaces

import "errors"

// RecordID identifies a record. It must be non-empty.
type RecordID string

// Version is a monotonically increasing record version. Version 0 means "no
// version recorded yet".
type Version uint64

// Record is a stored value with its identifier and version.
type Record struct {
	ID      RecordID
	Version Version
	Data    []byte
}

// Errors returned by Store implementations. Callers can classify failures with
// errors.Is.
var (
	// ErrNotFound indicates the record does not exist.
	ErrNotFound = errors.New("securestorage: record not found")
	// ErrConflict indicates a compare-and-swap version mismatch; nothing was
	// written.
	ErrConflict = errors.New("securestorage: version conflict")
	// ErrInvalidID indicates an empty or malformed record identifier.
	ErrInvalidID = errors.New("securestorage: invalid record id")
	// ErrClosed indicates the store has been closed and no longer accepts
	// operations.
	ErrClosed = errors.New("securestorage: store closed")
)

// Store is the minimal secure-storage contract: read, write with optional CAS,
// logical delete, and enumeration. Implementations may add capabilities; a
// capability a backend does not have must be reported as an error, never
// silently ignored.
type Store interface {
	// Get returns the record for id, or ErrNotFound.
	Get(id RecordID) (Record, error)
	// Put writes data for id. If expected is non-nil and does not equal the
	// stored version, it fails with ErrConflict and changes nothing. The
	// returned Record carries the new version.
	Put(id RecordID, data []byte, expected *Version) (Record, error)
	// Delete logically deletes id. If expected is non-nil and does not match,
	// it fails with ErrConflict and changes nothing. Deletion is logical:
	// physical erasure is not guaranteed (see the spec).
	Delete(id RecordID, expected *Version) error
	// List returns the identifiers of all non-deleted records.
	List() ([]RecordID, error)
}

// Transactional is an optional capability: a Store that can run a function
// atomically. Implementations that do not support transactions simply do not
// implement this interface.
type Transactional interface {
	Store
	// View runs fn against a consistent read-only snapshot.
	View(fn func(Store) error) error
	// Update runs fn atomically: writes performed through the provided Store
	// are committed only if fn returns nil; otherwise they are rolled back.
	Update(fn func(Store) error) error
}

// Closer is an optional capability for stores that hold resources.
type Closer interface {
	Close() error
}

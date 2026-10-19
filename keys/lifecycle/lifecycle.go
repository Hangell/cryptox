// Package lifecycle implements the one-way key lifecycle state machine
// defined in ADR 0005: active -> retired -> revoked. A key in a given state
// may only move forward; revocation is terminal.
//
// The state machine stores no key material. It is metadata only and is safe
// for concurrent use.
package lifecycle

import (
	"errors"
	"fmt"
	"sync"
)

// State is a key lifecycle state.
type State uint8

const (
	// StateActive is a key usable for encryption and decryption.
	StateActive State = iota + 1
	// StateRetired is a key no longer used for new encryption but still used
	// for decrypting or verifying historical data.
	StateRetired
	// StateRevoked is a terminal state; the key must not be used for any new
	// operation. Historical data may be processed only through an explicit
	// revocation-aware path.
	StateRevoked
)

// Errors returned by the package. Callers can classify failures with errors.Is.
var (
	// ErrInvalidState indicates an unknown state value.
	ErrInvalidState = errors.New("lifecycle: invalid state")
	// ErrInvalidTransition indicates a transition not allowed by the
	// one-way state machine.
	ErrInvalidTransition = errors.New("lifecycle: invalid transition")
)

// String returns the state name.
func (s State) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateRetired:
		return "retired"
	case StateRevoked:
		return "revoked"
	default:
		return fmt.Sprintf("invalid(%d)", uint8(s))
	}
}

// valid reports whether s is a known state.
func (s State) valid() bool {
	return s >= StateActive && s <= StateRevoked
}

// CanTransitionTo reports whether s may move to to under the one-way model.
func (s State) CanTransitionTo(to State) bool {
	switch s {
	case StateActive:
		return to == StateRetired || to == StateRevoked
	case StateRetired:
		return to == StateRevoked
	default:
		return false
	}
}

// AllowsEncrypt reports whether new encryption is permitted. Only active keys
// may encrypt.
func (s State) AllowsEncrypt() bool { return s == StateActive }

// AllowsDecrypt reports whether ordinary decryption is permitted. Active and
// retired keys may decrypt; revoked keys require the explicit historical path.
func (s State) AllowsDecrypt() bool { return s == StateActive || s == StateRetired }

// AllowsHistoricalDecrypt reports whether already-captured ciphertext may be
// decrypted through an explicit, revocation-aware path. This is the only way a
// revoked key may be used, and only for data that predates revocation.
func (s State) AllowsHistoricalDecrypt() bool { return s.valid() }

// StateMachine is a concurrency-safe holder for a key lifecycle state.
type StateMachine struct {
	mu    sync.Mutex
	state State
}

// New returns a StateMachine in the active state.
func New() *StateMachine {
	return &StateMachine{state: StateActive}
}

// NewIn returns a StateMachine in the given initial state, rejecting unknown
// states.
func NewIn(s State) (*StateMachine, error) {
	if !s.valid() {
		return nil, ErrInvalidState
	}
	return &StateMachine{state: s}, nil
}

// State returns the current state.
func (m *StateMachine) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Transition moves the state machine to to if and only if the one-way
// transition is valid. It is atomic: concurrent calls cannot interleave.
func (m *StateMachine) Transition(to State) error {
	if !to.valid() {
		return ErrInvalidState
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.state.CanTransitionTo(to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, m.state, to)
	}
	m.state = to
	return nil
}

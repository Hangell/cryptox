package lifecycle

import (
	"errors"
	"sync"
	"testing"
)

func TestTransitions(t *testing.T) {
	valid := []struct {
		from, to State
	}{
		{StateActive, StateRetired},
		{StateActive, StateRevoked},
		{StateRetired, StateRevoked},
	}
	for _, tc := range valid {
		m, err := NewIn(tc.from)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Transition(tc.to); err != nil {
			t.Fatalf("%s -> %s: unexpected error %v", tc.from, tc.to, err)
		}
		if m.State() != tc.to {
			t.Fatalf("%s -> %s: state = %s", tc.from, tc.to, m.State())
		}
	}
}

func TestInvalidTransitions(t *testing.T) {
	invalid := []struct {
		from, to State
	}{
		{StateActive, StateActive},   // no self-transition
		{StateRetired, StateActive},  // no backwards
		{StateRetired, StateRetired}, // no self-transition
		{StateRevoked, StateActive},  // terminal
		{StateRevoked, StateRetired}, // terminal
		{StateRevoked, StateRevoked}, // terminal, no self-transition
	}
	for _, tc := range invalid {
		m, err := NewIn(tc.from)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Transition(tc.to); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("%s -> %s: got %v, want ErrInvalidTransition", tc.from, tc.to, err)
		}
	}
}

func TestUnknownStateRejected(t *testing.T) {
	if _, err := NewIn(State(0)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("NewIn(0): got %v, want ErrInvalidState", err)
	}
	if _, err := NewIn(State(99)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("NewIn(99): got %v, want ErrInvalidState", err)
	}
	m := New()
	if err := m.Transition(State(99)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("Transition(99): got %v, want ErrInvalidState", err)
	}
}

func TestOperationPolicies(t *testing.T) {
	cases := []struct {
		state       State
		encrypt     bool
		decrypt     bool
		histDecrypt bool
	}{
		{StateActive, true, true, true},
		{StateRetired, false, true, true},
		{StateRevoked, false, false, true},
	}
	for _, tc := range cases {
		if got := tc.state.AllowsEncrypt(); got != tc.encrypt {
			t.Fatalf("%s.AllowsEncrypt() = %v", tc.state, got)
		}
		if got := tc.state.AllowsDecrypt(); got != tc.decrypt {
			t.Fatalf("%s.AllowsDecrypt() = %v", tc.state, got)
		}
		if got := tc.state.AllowsHistoricalDecrypt(); got != tc.histDecrypt {
			t.Fatalf("%s.AllowsHistoricalDecrypt() = %v", tc.state, got)
		}
	}
}

func TestConcurrentTransitionAtomic(t *testing.T) {
	m := New()
	const n = 32
	var wg sync.WaitGroup
	var successes int
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Transition(StateRetired); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("active -> retired succeeded %d times, want exactly 1", successes)
	}
	if m.State() != StateRetired {
		t.Fatalf("final state = %s, want retired", m.State())
	}
}

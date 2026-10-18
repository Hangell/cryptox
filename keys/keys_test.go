package keys

import (
	"sync"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	for _, size := range []int{16, 24, 32} {
		key, err := GenerateKey(size)
		if err != nil {
			t.Fatal(err)
		}
		if len(key) != size {
			t.Fatal("incorrect key length")
		}
	}
	for _, size := range []int{-1, 0, 15, 17, 33} {
		if _, err := GenerateKey(size); err == nil {
			t.Fatal("invalid size accepted")
		}
	}
}

// TestGenerateKeyConcurrent exercises GenerateKey from concurrent goroutines and
// checks that every result has the requested length and is unique. It is intended
// to run under the race detector via `make test`.
func TestGenerateKeyConcurrent(t *testing.T) {
	const goroutines = 32
	const perGoroutine = 64

	seen := make(map[[32]byte]struct{}, goroutines*perGoroutine)
	var mu sync.Mutex
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				key, err := GenerateKey(32)
				if err != nil {
					t.Error(err)
					return
				}
				var arr [32]byte
				copy(arr[:], key)
				mu.Lock()
				seen[arr] = struct{}{}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(seen) != goroutines*perGoroutine {
		t.Fatalf("expected %d unique keys, got %d", goroutines*perGoroutine, len(seen))
	}
}

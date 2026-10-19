package envelope

import "testing"

// FuzzOpen ensures the envelope parser never panics and never returns payload
// together with an error for arbitrary input.
func FuzzOpen(f *testing.F) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	seed, err := Seal(key, []byte("fuzz seed plaintext"), []byte("kid"), []byte("aad"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{})
	f.Add([]byte("CXE1"))

	f.Fuzz(func(t *testing.T, data []byte) {
		opened, err := Open(key, data)
		if err != nil && opened != nil {
			t.Fatalf("Open returned a result together with error %v", err)
		}
	})
}

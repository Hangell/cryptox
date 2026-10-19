package aead

import "testing"

// FuzzOpen ensures Open never panics and never returns plaintext together with
// an error for arbitrary, attacker-controlled input.
func FuzzOpen(f *testing.F) {
	key, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	seed, _ := Seal(key, []byte("fuzz seed plaintext"), []byte("aad"))
	f.Add(seed)
	f.Add([]byte{})
	f.Add(make([]byte, 28))

	f.Fuzz(func(t *testing.T, data []byte) {
		pt, err := Open(key, data, []byte("aad"))
		if err != nil && pt != nil {
			t.Fatalf("Open returned plaintext (%d bytes) together with error %v", len(pt), err)
		}
	})
}

// FuzzSealOpen ensures arbitrary plaintext/AAD round-trips through Seal/Open.
func FuzzSealOpen(f *testing.F) {
	key, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte("hello"), []byte("aad"))
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0xff, 0x00, 0x7f}, []byte{0x00})

	f.Fuzz(func(t *testing.T, plaintext, aad []byte) {
		ct, err := Seal(key, plaintext, aad)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Open(key, ct, aad)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(plaintext) {
			t.Fatalf("length mismatch: got %d, want %d", len(got), len(plaintext))
		}
		for i := range got {
			if got[i] != plaintext[i] {
				t.Fatalf("byte %d mismatch", i)
			}
		}
	})
}

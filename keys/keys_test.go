package keys

import "testing"

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

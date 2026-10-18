package keys

import (
	"fmt"
	"testing"
)

// BenchmarkGenerateKey measures random key generation. Run with `make bench`.
// When publishing results, record the Go version, OS, architecture, and the
// benchmark parameters from the `make bench` invocation.
func BenchmarkGenerateKey(b *testing.B) {
	for _, size := range []int{16, 24, 32} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := GenerateKey(size); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

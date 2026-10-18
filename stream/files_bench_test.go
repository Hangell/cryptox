package stream

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The benchmarks below measure the legacy v1 file operations, which are not the
// target secure-streaming format. Run with `make bench`. When publishing results,
// record the Go version, OS, architecture, and input sizes.
func BenchmarkEncryptLargeFiles(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			dir := b.TempDir()
			input := filepath.Join(dir, "input")
			encrypted := filepath.Join(dir, "encrypted")
			key := make([]byte, 32)
			if err := os.WriteFile(input, bytes.Repeat([]byte{0xa5}, size), 0600); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := EncryptLargeFiles(input, encrypted, key); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecryptLargeFiles(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			dir := b.TempDir()
			input := filepath.Join(dir, "input")
			encrypted := filepath.Join(dir, "encrypted")
			output := filepath.Join(dir, "output")
			key := make([]byte, 32)
			if err := os.WriteFile(input, bytes.Repeat([]byte{0xa5}, size), 0600); err != nil {
				b.Fatal(err)
			}
			if err := EncryptLargeFiles(input, encrypted, key); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := DecryptLargeFiles(encrypted, output, key); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

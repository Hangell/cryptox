package cryptox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// currentPackages is the set of Go packages that must exist in this increment,
// documented in ARCHITECTURE.md §4.1. A new package must be added here together
// with its contract, implementation, and tests — never as an empty placeholder.
var currentPackages = []string{"keys", "stream", "utils"}

// targetPackageDirs are directories from the target structure (§4) that are
// intended to become Go packages. They may be absent (expected during Phase 0),
// but when present they must contain Go source files.
var targetPackageDirs = []string{
	"aead", "envelope", "identity", "securestorage", "e2ee", "pki", "compat", "internal",
}

// nonPackageDirs are top-level directories that legitimately contain Go files
// without being libraries listed in §4.1 (examples, generated or fixture data).
var nonPackageDirs = map[string]bool{"docs": true, "examples": true, "testdata": true}

// TestDocumentedPackagesExist verifies that every package documented as current
// actually exists and contains Go source files.
func TestDocumentedPackagesExist(t *testing.T) {
	for _, p := range currentPackages {
		if !dirContainsGo(p) {
			t.Errorf("documented package %q is missing or contains no Go files", p)
		}
	}
}

// TestNoEmptyPlaceholderPackages fails if a directory from the target structure
// exists but contains no Go source files (an empty placeholder package).
func TestNoEmptyPlaceholderPackages(t *testing.T) {
	for _, d := range targetPackageDirs {
		if _, err := os.Stat(d); err != nil {
			if os.IsNotExist(err) {
				continue // not introduced yet: expected and fine
			}
			t.Fatalf("stat %s: %v", d, err)
		}
		if !dirContainsGo(d) {
			t.Errorf("directory %q exists but contains no Go source files (empty placeholder)", d)
		}
	}
}

// TestUndocumentedTopLevelPackages fails if a top-level directory contains Go
// files without being documented in ARCHITECTURE.md §4.1 or listed as a
// non-package directory. This keeps the documented structure and the actual
// tree consistent.
func TestUndocumentedTopLevelPackages(t *testing.T) {
	allowed := map[string]bool{}
	for _, p := range currentPackages {
		allowed[p] = true
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if allowed[e.Name()] || nonPackageDirs[e.Name()] {
			continue
		}
		if dirContainsGo(e.Name()) {
			t.Errorf("top-level directory %q contains Go files but is not documented in ARCHITECTURE.md §4.1", e.Name())
		}
	}
}

// dirContainsGo reports whether dir or any of its subdirectories contains a
// .go file.
func dirContainsGo(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".go") {
			found = true
		}
		return nil
	})
	return found
}

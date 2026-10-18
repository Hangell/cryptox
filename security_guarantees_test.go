package cryptox

import (
	"os"
	"strings"
	"testing"
)

// TestSecurityGuaranteesDocumented verifies that SECURITY.md states both the
// supported guarantees and the explicit non-guarantees required by Phase 0.
// Keeping these checks in sync with the public policy prevents unsupported
// security claims from being silently introduced.
func TestSecurityGuaranteesDocumented(t *testing.T) {
	b, err := os.ReadFile("SECURITY.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)

	for _, want := range []string{
		"## Supported guarantees",
		"## Known limitations",
		"whole-file integrity",
		"replay",
		"erasure of secrets from memory",
		"trusted destination directory",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("SECURITY.md is missing required statement %q", want)
		}
	}
}
